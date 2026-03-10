//! Experimental HTTP/3 client request flow for local harness interoperability.

const std = @import("std");
const types = @import("../types.zig");
const qpack = @import("qpack.zig");
const quic = @import("quic.zig");
const server = @import("server.zig");

/// Error set returned by the local HTTP/3 client helpers.
pub const Error = quic.Error || qpack.Error || server.Error || error{
    /// HTTP/3 is only supported for HTTPS-style requests in this scaffold.
    InvalidScheme,
    /// The request body reader surfaced an unexpected failure.
    BodyReadFailed,
    /// The request body exceeded the local harness buffering limit.
    RequestBodyTooLarge,
    /// The response omitted the required `:status` pseudo-header.
    MissingStatus,
};

/// Prepared HTTP/3 request metadata and encoded header block.
pub const RequestPlan = struct {
    /// Allocator used for owned buffers.
    allocator: std.mem.Allocator,
    /// QUIC stream identifier used for the request.
    stream_id: u64,
    /// Encoded header block.
    header_block: []u8,
    /// Fully buffered request body.
    body: []u8,

    /// Releases request-owned buffers.
    pub fn deinit(self: *RequestPlan) void {
        self.allocator.free(self.header_block);
        self.allocator.free(self.body);
        self.* = undefined;
    }
};

/// Prepares an HTTP/3 request for the experimental local harness flow.
pub fn prepareRequest(
    allocator: std.mem.Allocator,
    connection: *quic.Connection,
    request: *const types.Request,
) Error!RequestPlan {
    if (request.uri.scheme != .https) {
        return error.InvalidScheme;
    }

    var headers = std.ArrayListUnmanaged(qpack.HeaderField){};
    defer {
        for (headers.items) |*header| {
            header.deinit(allocator);
        }
        headers.deinit(allocator);
    }

    const authority = if (request.uri.port) |port|
        try std.fmt.allocPrint(allocator, "{s}:{d}", .{ request.uri.host, port.toInt() })
    else
        try allocator.dupe(u8, request.uri.host);
    defer allocator.free(authority);

    const path = if (request.uri.query) |query|
        try std.fmt.allocPrint(allocator, "{s}?{s}", .{ request.uri.path, query })
    else
        try allocator.dupe(u8, request.uri.path);
    defer allocator.free(path);

    try appendOwnedHeader(allocator, &headers, ":method", request.method.asBytes());
    try appendOwnedHeader(allocator, &headers, ":scheme", request.uri.scheme.asBytes());
    try appendOwnedHeader(allocator, &headers, ":authority", authority);
    try appendOwnedHeader(allocator, &headers, ":path", path);

    var iter = request.headers.iterator();
    while (iter.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "host")) {
            continue;
        }
        try appendOwnedHeader(allocator, &headers, header.name, header.value);
    }

    const header_block = try qpack.encodeHeaderBlock(allocator, headers.items);
    errdefer allocator.free(header_block);
    const body = if (request.body) |body_reader|
        try readBodyAlloc(allocator, body_reader, 256 * 1024)
    else
        try allocator.alloc(u8, 0);
    errdefer allocator.free(body);

    return .{
        .allocator = allocator,
        .stream_id = try connection.openStream(.bidirectional),
        .header_block = header_block,
        .body = body,
    };
}

/// Encodes a prepared request into HTTP/3 HEADERS and DATA frames.
pub fn encodeRequest(allocator: std.mem.Allocator, plan: RequestPlan) Error![]u8 {
    const headers_frame = try qpack.encodeFrame(allocator, .headers, plan.header_block);
    defer allocator.free(headers_frame);

    var bytes = std.ArrayListUnmanaged(u8){};
    errdefer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, headers_frame);

    if (plan.body.len > 0) {
        const data_frame = try qpack.encodeFrame(allocator, .data, plan.body);
        defer allocator.free(data_frame);
        try bytes.appendSlice(allocator, data_frame);
    }

    return bytes.toOwnedSlice(allocator);
}

/// Executes one local harness request over the experimental QUIC scaffolding.
pub fn executeHarnessRequest(
    allocator: std.mem.Allocator,
    request: *const types.Request,
) Error!types.Response {
    var client_conn = quic.Connection.init(allocator, "client01".*, "server01".*);
    defer client_conn.deinit();
    var server_conn = quic.Connection.init(allocator, "server01".*, "client01".*);
    defer server_conn.deinit();
    client_conn.beginHandshake();
    client_conn.establish();
    server_conn.beginHandshake();
    server_conn.establish();

    var plan = try prepareRequest(allocator, &client_conn, request);
    defer plan.deinit();

    const request_payload = try encodeRequest(allocator, plan);
    defer allocator.free(request_payload);
    const request_packet = try client_conn.protectPacket(allocator, .application, request_payload);
    defer allocator.free(request_packet);

    var harness_server = server.Server.init(allocator, .{
        .host = request.uri.host,
        .port = request.uri.effectivePort(),
    });
    const response_packet = try harness_server.handleDatagram(&server_conn, request_packet);
    defer allocator.free(response_packet);

    return try decodeResponse(allocator, &client_conn, response_packet);
}

/// Decodes a protected HTTP/3 response packet into the shared response type.
pub fn decodeResponse(
    allocator: std.mem.Allocator,
    connection: *quic.Connection,
    packet_bytes: []const u8,
) Error!types.Response {
    var packet = try connection.unprotectPacket(allocator, packet_bytes);
    defer packet.deinit(allocator);

    const frames = try qpack.decodeFrames(allocator, packet.payload);
    defer qpack.freeFrames(allocator, frames);

    var status: ?types.Status = null;
    var response = types.Response.init(allocator, .http_3, .ok);
    errdefer response.deinit();
    var body = std.ArrayListUnmanaged(u8){};
    errdefer body.deinit(allocator);

    for (frames) |frame| {
        switch (frame.frame_type) {
            .headers => {
                const headers = try qpack.decodeHeaderBlock(allocator, frame.payload);
                defer qpack.freeHeaderFields(allocator, headers);

                for (headers) |header| {
                    if (std.mem.eql(u8, header.name, ":status")) {
                        const status_code = std.fmt.parseInt(u16, header.value, 10) catch {
                            return error.InvalidStatus;
                        };
                        status = types.Status.fromInt(status_code);
                        continue;
                    }
                    try response.headers.append(header.name, header.value);
                }
            },
            .data => try body.appendSlice(allocator, frame.payload),
            else => {},
        }
    }

    response.status = status orelse return error.MissingStatus;
    if (body.items.len > 0) {
        const owned_body = try body.toOwnedSlice(allocator);
        response.body = .{
            .ctx = try makeBodyState(allocator, owned_body),
            .read_fn = OwnedBody.read,
            .close_fn = OwnedBody.close,
        };
    }
    _ = connection.acknowledge(.application, packet.number);

    return response;
}

/// In-memory response body state for decoded HTTP/3 responses.
const OwnedBody = struct {
    /// Allocator used to destroy the body state.
    allocator: std.mem.Allocator,
    /// Owned payload bytes.
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
) Error![]u8 {
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
        try collected.appendSlice(allocator, buffer[0..read_len]);
    }

    return collected.toOwnedSlice(allocator);
}

/// Appends one owned header field to the provided list.
fn appendOwnedHeader(
    allocator: std.mem.Allocator,
    headers: *std.ArrayListUnmanaged(qpack.HeaderField),
    name: []const u8,
    value: []const u8,
) Error!void {
    const owned_name = try allocator.dupe(u8, name);
    errdefer allocator.free(owned_name);
    const owned_value = try allocator.dupe(u8, value);
    errdefer allocator.free(owned_value);
    try headers.append(allocator, .{
        .name = owned_name,
        .value = owned_value,
    });
}

test "http3 client prepares a request plan with pseudo-headers" {
    var conn = quic.Connection.init(std.testing.allocator, "client01".*, "server01".*);
    defer conn.deinit();
    conn.beginHandshake();
    conn.establish();

    var request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(4433), "/health", null, null),
    );
    defer request.deinit();
    try request.headers.append("Host", "127.0.0.1");

    var plan = try prepareRequest(std.testing.allocator, &conn, &request);
    defer plan.deinit();

    try std.testing.expectEqual(@as(u64, 0), plan.stream_id);
    try std.testing.expect(plan.header_block.len > 0);
}

test "http3 client executes the local harness health flow" {
    var request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(4433), "/health", null, null),
    );
    defer request.deinit();
    try request.headers.append("Host", "127.0.0.1");

    var response = try executeHarnessRequest(std.testing.allocator, &request);
    defer response.deinit();
    defer if (response.body) |body| body.close();

    try std.testing.expectEqual(types.Status.ok, response.status);
    try std.testing.expectEqual(types.Version.http_3, response.version);
    try std.testing.expectEqualStrings("application/json", response.headers.get("content-type").?);

    var buffer: [128]u8 = undefined;
    const read_len = try response.body.?.read(&buffer);
    try std.testing.expect(std.mem.containsAtLeast(u8, buffer[0..read_len], 1, "\"protocol\":\"h3\""));
}
