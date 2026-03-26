//! Typed HTTP/2 connection and stream state bookkeeping.

const std = @import("std");
const frame = @import("frame.zig");

/// Error set returned while opening a new local stream.
pub const OpenStreamError = std.mem.Allocator.Error || error{
    /// The connection is draining or already closed.
    Draining,
    /// The peer-advertised concurrency limit has been reached.
    StreamLimit,
};

/// Error set returned when a stream lookup fails.
pub const StreamLookupError = error{
    /// The requested stream identifier is not tracked by the connection.
    StreamNotFound,
};

/// Scope of a currently blocked stream.
pub const BlockedReason = enum {
    /// The stream is not blocked.
    none,
    /// The stream hit its stream-local buffering limit.
    stream_buffer,
    /// The stream hit the shared connection buffering limit.
    connection_buffer,
    /// The stream can no longer admit new work because the connection is draining.
    draining,
};

/// Stream state for one HTTP/2 stream.
pub const StreamState = enum {
    /// The stream is queued before headers are committed.
    queued,
    /// The stream is transitioning into the open state.
    opening,
    /// The stream is actively exchanging request and response bytes.
    open,
    /// The local request body is complete but the response is still active.
    half_closed_local,
    /// The remote response body is complete but local cleanup remains.
    half_closed_remote,
    /// The stream is blocked on a stream-local limit.
    blocked_stream,
    /// The stream is blocked on a connection-wide limit.
    blocked_connection,
    /// The peer reset the stream.
    reset,
    /// The stream is fully closed.
    closed,
};

/// Connection state for one HTTP/2 session.
pub const ConnectionState = enum {
    /// No preface has been sent yet.
    idle,
    /// The client preface has been sent.
    preface,
    /// The connection can admit and service streams.
    active,
    /// The connection is draining and must reject new admissions.
    draining,
    /// The connection is permanently closed.
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
    /// Current stream state.
    state: StreamState,
    /// Send-side flow-control window.
    send_window: i64,
    /// Receive-side flow-control window.
    recv_window: i64,
    /// Buffered body bytes currently retained for the caller.
    buffered_body_bytes: usize,
    /// Current blocked reason for the stream.
    blocked_reason: BlockedReason,

    /// Returns true when the stream still counts against active-stream admission.
    pub fn isActive(self: Stream) bool {
        return switch (self.state) {
            .queued,
            .opening,
            .open,
            .half_closed_local,
            .half_closed_remote,
            .blocked_stream,
            .blocked_connection,
            => true,
            .reset,
            .closed,
            => false,
        };
    }
};

/// Minimal typed HTTP/2 connection state holder used by the runtime.
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
    connection_send_window: i64,
    /// Connection-level receive window.
    connection_recv_window: i64,
    /// Active and historical streams.
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
            .connection_send_window = 65535,
            .connection_recv_window = 65535,
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

    /// Returns the number of streams that still count as active.
    pub fn activeStreamCount(self: *const Connection) usize {
        var count: usize = 0;
        for (self.streams.items) |stream| {
            if (stream.isActive()) {
                count += 1;
            }
        }
        return count;
    }

    /// Returns true when the connection may still admit new local streams.
    pub fn isReusable(self: *const Connection) bool {
        return self.state == .preface or self.state == .active;
    }

    /// Opens the next local stream and returns its identifier.
    pub fn openLocalStream(self: *Connection) OpenStreamError!u31 {
        if (self.state == .draining or self.state == .closed) {
            return error.Draining;
        }
        if (self.activeStreamCount() >= self.settings_remote.max_concurrent_streams) {
            return error.StreamLimit;
        }

        const stream_id = self.next_stream_id;
        self.next_stream_id += 2;
        try self.streams.append(self.allocator, .{
            .id = stream_id,
            .state = .opening,
            .send_window = self.settings_remote.initial_window_size,
            .recv_window = self.settings_local.initial_window_size,
            .buffered_body_bytes = 0,
            .blocked_reason = .none,
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

    /// Updates a stream receive window by the provided delta.
    pub fn updateStreamWindow(self: *Connection, stream_id: u31, delta: i32) StreamLookupError!void {
        const stream = try self.findStream(stream_id);
        stream.recv_window += delta;
    }

    /// Sets the state for a tracked stream.
    pub fn setStreamState(
        self: *Connection,
        stream_id: u31,
        state: StreamState,
    ) StreamLookupError!void {
        const stream = try self.findStream(stream_id);
        stream.state = state;
    }

    /// Updates the buffered body bytes retained for the provided stream.
    pub fn setBufferedBodyBytes(
        self: *Connection,
        stream_id: u31,
        buffered_body_bytes: usize,
    ) StreamLookupError!void {
        const stream = try self.findStream(stream_id);
        stream.buffered_body_bytes = buffered_body_bytes;
    }

    /// Marks the stream as blocked by the provided scope.
    pub fn setBlockedReason(
        self: *Connection,
        stream_id: u31,
        blocked_reason: BlockedReason,
    ) StreamLookupError!void {
        const stream = try self.findStream(stream_id);
        stream.blocked_reason = blocked_reason;
        stream.state = switch (blocked_reason) {
            .none => .open,
            .stream_buffer => .blocked_stream,
            .connection_buffer => .blocked_connection,
            .draining => .half_closed_remote,
        };
    }

    /// Clears any blocked state and returns the stream to open processing.
    pub fn clearBlockedReason(self: *Connection, stream_id: u31) StreamLookupError!void {
        const stream = try self.findStream(stream_id);
        stream.blocked_reason = .none;
        if (stream.state == .blocked_stream or stream.state == .blocked_connection) {
            stream.state = .open;
        }
    }

    /// Marks a stream as fully closed after a successful terminal transition.
    pub fn finishStream(self: *Connection, stream_id: u31) StreamLookupError!void {
        const stream = try self.findStream(stream_id);
        stream.state = .closed;
        stream.blocked_reason = .none;
        stream.buffered_body_bytes = 0;
    }

    /// Marks a stream as reset by the peer.
    pub fn resetStream(self: *Connection, stream_id: u31) StreamLookupError!void {
        const stream = try self.findStream(stream_id);
        stream.state = .reset;
        stream.blocked_reason = .none;
    }

    /// Records a `GOAWAY` frame and moves the connection into draining mode.
    pub fn beginGoAway(self: *Connection, last_stream_id: u31) void {
        self.goaway_last_stream_id = last_stream_id;
        if (self.state != .closed) {
            self.state = .draining;
        }
    }

    /// Marks the connection as fully closed.
    pub fn close(self: *Connection) void {
        self.state = .closed;
    }

    /// Returns the tracked stream pointer for the provided identifier.
    fn findStream(self: *Connection, stream_id: u31) StreamLookupError!*Stream {
        for (self.streams.items) |*stream| {
            if (stream.id == stream_id) {
                return stream;
            }
        }
        return error.StreamNotFound;
    }
};

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
    try std.testing.expectEqual(@as(?u31, 7), conn.goaway_last_stream_id);
}

test "http2 connection tracks blocked reasons and buffered bytes per stream" {
    var conn = Connection.init(std.testing.allocator);
    defer conn.deinit();

    conn.sendClientPreface();
    const stream_id = try conn.openLocalStream();
    try conn.setStreamState(stream_id, .open);
    try conn.setBufferedBodyBytes(stream_id, 512);
    try conn.setBlockedReason(stream_id, .connection_buffer);

    try std.testing.expectEqual(@as(usize, 1), conn.activeStreamCount());
    try std.testing.expectEqual(BlockedReason.connection_buffer, conn.streams.items[0].blocked_reason);
    try std.testing.expectEqual(@as(usize, 512), conn.streams.items[0].buffered_body_bytes);

    try conn.clearBlockedReason(stream_id);
    try conn.finishStream(stream_id);
    try std.testing.expectEqual(@as(usize, 0), conn.activeStreamCount());
}
