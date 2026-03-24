//! HTTP/2 connection and stream state scaffolding.

const std = @import("std");
const frame = @import("frame.zig");
const types = @import("../types.zig");
const interop_harness = @import("../testing/interop_harness.zig");

/// Stream state for one HTTP/2 stream.
pub const StreamState = enum {
    idle,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

/// Connection state for one HTTP/2 session.
pub const ConnectionState = enum {
    idle,
    preface,
    active,
    draining,
    closed,
};

/// Local and remote HTTP/2 settings snapshots.
pub const Settings = struct {
    /// Maximum concurrent streams permitted by the peer.
    max_concurrent_streams: u32 = std.math.maxInt(u31),
    /// Initial flow-control window.
    initial_window_size: u32 = 65535,
    /// Maximum frame size.
    max_frame_size: u32 = 16384,
};

/// One tracked HTTP/2 stream.
pub const Stream = struct {
    /// Stream identifier.
    id: u31,
    /// Current state.
    state: StreamState,
    /// Send-side flow-control window.
    send_window: i64,
    /// Receive-side flow-control window.
    recv_window: i64,
};

/// Minimal HTTP/2 connection state holder.
pub const Connection = struct {
    /// Allocator used for stream bookkeeping.
    allocator: std.mem.Allocator,
    /// Session state.
    state: ConnectionState,
    /// Locally advertised settings.
    settings_local: Settings,
    /// Peer settings.
    settings_remote: Settings,
    /// Next locally initiated stream identifier.
    next_stream_id: u31,
    /// Connection-level send window.
    connection_window: i64,
    /// Active streams.
    streams: std.ArrayListUnmanaged(Stream),
    /// Last `GOAWAY` stream identifier, if any.
    goaway_last_stream_id: ?u31,

    /// Creates an empty HTTP/2 connection state machine.
    pub fn init(allocator: std.mem.Allocator) Connection {
        return .{
            .allocator = allocator,
            .state = .idle,
            .settings_local = .{},
            .settings_remote = .{},
            .next_stream_id = 1,
            .connection_window = 65535,
            .streams = .{},
            .goaway_last_stream_id = null,
        };
    }

    /// Releases owned stream bookkeeping.
    pub fn deinit(self: *Connection) void {
        self.streams.deinit(self.allocator);
        self.* = undefined;
    }

    /// Marks the client preface as sent.
    pub fn sendClientPreface(self: *Connection) void {
        if (self.state == .idle) {
            self.state = .preface;
        }
    }

    /// Opens the next local stream and returns its identifier.
    pub fn openLocalStream(self: *Connection) !u31 {
        const stream_id = self.next_stream_id;
        self.next_stream_id += 2;
        try self.streams.append(self.allocator, .{
            .id = stream_id,
            .state = .open,
            .send_window = self.settings_remote.initial_window_size,
            .recv_window = self.settings_local.initial_window_size,
        });
        self.state = .active;
        return stream_id;
    }

    /// Applies a remote SETTINGS payload to the connection state.
    pub fn applyRemoteSettings(self: *Connection, settings_payload: []const frame.Setting) void {
        for (settings_payload) |setting| {
            switch (setting.id) {
                .max_concurrent_streams => self.settings_remote.max_concurrent_streams = setting.value,
                .initial_window_size => self.settings_remote.initial_window_size = setting.value,
                .max_frame_size => self.settings_remote.max_frame_size = setting.value,
                else => {},
            }
        }
    }

    /// Updates a stream window by the provided delta.
    pub fn updateStreamWindow(self: *Connection, stream_id: u31, delta: i32) bool {
        for (self.streams.items) |*stream| {
            if (stream.id == stream_id) {
                stream.recv_window += delta;
                return true;
            }
        }
        return false;
    }

    /// Marks a stream as reset or closed by the peer.
    pub fn resetStream(self: *Connection, stream_id: u31) bool {
        for (self.streams.items) |*stream| {
            if (stream.id == stream_id) {
                stream.state = .closed;
                return true;
            }
        }
        return false;
    }

    /// Records a `GOAWAY` frame and moves the connection into draining mode.
    pub fn beginGoAway(self: *Connection, last_stream_id: u31) void {
        self.goaway_last_stream_id = last_stream_id;
        self.state = .draining;
    }
};

/// Error set returned by the local HTTP/2 interop session.
pub const InteropError = error{
    /// The request scheme is not valid for the local secure HTTP/2 flow.
    InvalidScheme,
    /// The request target does not match the session endpoint.
    InvalidTarget,
    /// The request body reader surfaced an unexpected failure.
    BodyReadFailed,
    /// The request body exceeded the local harness buffering limit.
    RequestBodyTooLarge,
    /// Allocation failed while materializing the response.
    OutOfMemory,
};

/// Reusable in-memory HTTP/2 session backed by the shared interop harness.
pub const InteropSession = struct {
    /// Allocator used for owned response data.
    allocator: std.mem.Allocator,
    /// Endpoint served by the local harness session.
    endpoint: interop_harness.Endpoint,
    /// HTTP/2 connection state reused across requests.
    connection: Connection,
    /// Number of requests executed on the session.
    executed_requests: usize,

    /// Initializes an HTTP/2 interop session for the provided loopback endpoint.
    pub fn init(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: types.Port,
    ) InteropSession {
        var connection = Connection.init(allocator);
        connection.sendClientPreface();
        return .{
            .allocator = allocator,
            .endpoint = .{
                .host = host,
                .port = port,
                .transport = .tcp,
                .protocol = .h2,
            },
            .connection = connection,
            .executed_requests = 0,
        };
    }

    /// Releases the reused connection state.
    pub fn deinit(self: *InteropSession) void {
        self.connection.deinit();
        self.* = undefined;
    }

    /// Returns how many requests have executed on the session.
    pub fn requestCount(self: *const InteropSession) usize {
        return self.executed_requests;
    }

    /// Returns the next locally initiated stream identifier.
    pub fn nextStreamId(self: *const InteropSession) u31 {
        return self.connection.next_stream_id;
    }

    /// Executes one request against the shared local interop harness.
    pub fn executeRequest(self: *InteropSession, request: *const types.Request) InteropError!types.Response {
        if (request.uri.scheme != .https) {
            return error.InvalidScheme;
        }
        if (!std.ascii.eqlIgnoreCase(request.uri.host, self.endpoint.host) or
            request.uri.effectivePort().toInt() != self.endpoint.port.toInt())
        {
            return error.InvalidTarget;
        }

        _ = self.connection.openLocalStream() catch |err| return mapAllocatorError(err);
        self.executed_requests += 1;

        const request_body = if (request.body) |body_reader|
            try readBodyAlloc(self.allocator, body_reader, 256 * 1024)
        else
            self.allocator.alloc(u8, 0) catch return error.OutOfMemory;
        defer self.allocator.free(request_body);

        var semantic = interop_harness.buildSemanticResponse(self.allocator, .{
            .method = request.method,
            .path = request.uri.path,
            .query = request.uri.query,
            .negotiated_protocol = .h2,
            .body = request_body,
            .cookie_header = request.headers.get("cookie"),
        }) catch return error.OutOfMemory;
        defer semantic.deinit();

        return semanticToResponse(self.allocator, semantic, .http_2);
    }
};

/// In-memory response body state for local HTTP/2 responses.
const OwnedBody = struct {
    /// Allocator used to destroy the body state.
    allocator: std.mem.Allocator,
    /// Owned response body bytes.
    bytes: []u8,
    /// Current read offset.
    offset: usize,

    /// Reads one chunk from the owned body bytes.
    fn read(ctx: ?*anyopaque, dest: []u8) anyerror!usize {
        const self: *OwnedBody = @ptrCast(@alignCast(ctx.?));
        if (self.offset >= self.bytes.len) {
            return 0;
        }

        const remaining = self.bytes.len - self.offset;
        const to_copy = @min(dest.len, remaining);
        std.mem.copyForwards(u8, dest[0..to_copy], self.bytes[self.offset .. self.offset + to_copy]);
        self.offset += to_copy;
        return to_copy;
    }

    /// Releases the owned body buffer.
    fn close(ctx: ?*anyopaque) void {
        const self: *OwnedBody = @ptrCast(@alignCast(ctx.?));
        self.allocator.free(self.bytes);
        self.allocator.destroy(self);
    }
};

/// Allocates a body state for a decoded response body.
fn makeBodyState(allocator: std.mem.Allocator, bytes: []u8) std.mem.Allocator.Error!*OwnedBody {
    const state = try allocator.create(OwnedBody);
    state.* = .{
        .allocator = allocator,
        .bytes = bytes,
        .offset = 0,
    };
    return state;
}

/// Reads a full request body into memory for the local harness flow.
fn readBodyAlloc(
    allocator: std.mem.Allocator,
    body_reader: types.BodyReader,
    max_bytes: usize,
) InteropError![]u8 {
    var collected = std.ArrayListUnmanaged(u8){};
    errdefer collected.deinit(allocator);

    var buffer: [4096]u8 = undefined;
    while (true) {
        const read_len = body_reader.read(&buffer) catch return error.BodyReadFailed;
        if (read_len == 0) {
            break;
        }
        if (collected.items.len + read_len > max_bytes) {
            return error.RequestBodyTooLarge;
        }
        collected.appendSlice(allocator, buffer[0..read_len]) catch return error.OutOfMemory;
    }

    return collected.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Converts an interop-harness response into the shared HTTP response type.
fn semanticToResponse(
    allocator: std.mem.Allocator,
    semantic: interop_harness.SemanticResponse,
    version: types.Version,
) InteropError!types.Response {
    var response = types.Response.init(allocator, version, semantic.status);
    errdefer response.deinit();

    var iterator = semantic.headers.iterator();
    while (iterator.next()) |header| {
        response.headers.append(header.name, header.value) catch return error.OutOfMemory;
    }

    if (semantic.body.len > 0) {
        const owned_body = allocator.dupe(u8, semantic.body) catch return error.OutOfMemory;
        const state = makeBodyState(allocator, owned_body) catch return error.OutOfMemory;
        response.body = .{
            .ctx = state,
            .read_fn = OwnedBody.read,
            .close_fn = OwnedBody.close,
        };
    }

    return response;
}

/// Maps allocator failures into the interop error surface.
fn mapAllocatorError(_: std.mem.Allocator.Error) InteropError {
    return error.OutOfMemory;
}

test "http2 connection opens client streams on odd identifiers" {
    var conn = Connection.init(std.testing.allocator);
    defer conn.deinit();

    conn.sendClientPreface();
    try std.testing.expectEqual(@as(u31, 1), try conn.openLocalStream());
    try std.testing.expectEqual(@as(u31, 3), try conn.openLocalStream());
}

test "http2 connection tracks settings and goaway state" {
    var conn = Connection.init(std.testing.allocator);
    defer conn.deinit();

    conn.applyRemoteSettings(&.{
        .{ .id = .max_frame_size, .value = 32768 },
        .{ .id = .initial_window_size, .value = 70000 },
    });
    conn.beginGoAway(7);

    try std.testing.expectEqual(@as(u32, 32768), conn.settings_remote.max_frame_size);
    try std.testing.expectEqual(@as(u32, 70000), conn.settings_remote.initial_window_size);
    try std.testing.expectEqual(ConnectionState.draining, conn.state);
}
