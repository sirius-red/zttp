//! Minimal HTTP/2 server-side exchange handling for local interop coverage.

const std = @import("std");
const core = @import("../types.zig");
const shared_frame = @import("../http2/frame.zig");
const shared_hpack = @import("../http2/hpack.zig");
const socket_io = @import("../util/socket_io.zig");
const server_types = @import("types.zig");
const websocket_server = @import("../websocket/server.zig");

/// Cleartext HTTP/2 client connection preface.
pub const client_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Server-side protocol selection outcome.
pub const Negotiation = struct {
    /// Protocol selected for the accepted connection.
    protocol: core.NegotiatedProtocol,
    /// Whether the runtime can serve the selected protocol end to end.
    supported: bool,
};

/// Error set returned by the minimal HTTP/2 server path.
pub const ExchangeError = anyerror;

/// Structured exchange failures surfaced by the minimal HTTP/2 server path.
pub const ExchangeFailure = error{
    /// The connection ended before the expected request bytes arrived.
    UnexpectedEof,
    /// The connection did not start with the HTTP/2 client preface.
    InvalidClientPreface,
    /// The peer did not send the required SETTINGS frame first.
    MissingSettings,
    /// The peer sent malformed HTTP/2 wire data.
    MalformedFrame,
    /// The peer requested an unsupported HTTP/2 exchange shape.
    UnsupportedExchange,
};

/// Decoded HTTP/2 response returned by the test helpers.
pub const DecodedResponse = struct {
    /// Allocator used for the owned headers and body bytes.
    allocator: std.mem.Allocator,
    /// Response status code.
    status: core.Status,
    /// Decoded literal headers from the HEADERS frame.
    headers: []shared_hpack.HeaderField,
    /// Concatenated DATA payload bytes.
    body: []u8,

    /// Releases the owned headers and body bytes.
    pub fn deinit(self: *DecodedResponse) void {
        shared_hpack.freeLiteralHeaders(self.allocator, self.headers);
        self.allocator.free(self.body);
        self.* = undefined;
    }
};

/// Returns the selected protocol for the listener configuration.
pub fn negotiate(config: server_types.ServerConfig, peer_preference: ?core.NegotiatedProtocol) Negotiation {
    if (config.http2_enabled) {
        if (peer_preference) |protocol| {
            if (protocol == .h2) {
                return .{
                    .protocol = .h2,
                    .supported = true,
                };
            }
        }
    }

    return .{
        .protocol = .http_1_1,
        .supported = true,
    };
}

/// Returns true when the bytes start with the HTTP/2 connection preface.
pub fn startsWithClientPreface(bytes: []const u8) bool {
    if (bytes.len < client_preface.len) {
        return false;
    }
    return std.mem.eql(u8, bytes[0..client_preface.len], client_preface);
}

/// Returns a predictable failure category for one HTTP/2 server-side error.
pub fn classifyFailure(err: anyerror) ?server_types.Http2FailureCategory {
    return switch (err) {
        error.InvalidClientPreface,
        error.MissingSettings,
        error.MalformedFrame,
        => .malformed_frame,

        error.UnsupportedExchange => .unsupported_exchange,
        else => null,
    };
}

/// Serves one minimal HTTP/2 request/response exchange on the accepted stream.
pub fn serveConnection(
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    prefix_bytes: []const u8,
    session: server_types.NegotiatedSession,
    limits: server_types.ConnectionLimits,
    handler: server_types.Handler,
    handler_context: ?*anyopaque,
) ExchangeError!void {
    var prefixed = PrefixedStream.init(stream, prefix_bytes);

    var incoming = try readRequest(allocator, &prefixed, session, limits);
    defer incoming.request.deinit();

    try sendServerSettings(stream);

    var writer = try initResponseWriter(allocator, stream, incoming.stream_id);
    defer writer.deinit();

    try handler(handler_context, &incoming.request, &writer);
    try writer.finish();
}

/// Encodes one client request into a deterministic minimal HTTP/2 exchange.
pub fn encodeClientRequest(
    allocator: std.mem.Allocator,
    method: core.Method,
    path: []const u8,
    host: []const u8,
    body: []const u8,
) std.mem.Allocator.Error![]u8 {
    const settings = try shared_frame.encodeSettings(allocator, &.{});
    defer allocator.free(settings);

    const header_fields = [_]shared_hpack.HeaderField{
        .{ .name = ":method", .value = method.asBytes() },
        .{ .name = ":path", .value = path },
        .{ .name = "host", .value = host },
    };
    const header_block = try shared_hpack.encodeLiteralHeaders(allocator, &header_fields);
    defer allocator.free(header_block);

    var bytes = std.ArrayListUnmanaged(u8){};
    errdefer bytes.deinit(allocator);

    try bytes.appendSlice(allocator, client_preface);
    try appendFrame(allocator, &bytes, .{
        .length = @intCast(settings.len),
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, settings);
    try appendFrame(allocator, &bytes, .{
        .length = @intCast(header_block.len),
        .frame_type = .headers,
        .flags = 0x4 | if (body.len == 0) @as(u8, 0x1) else @as(u8, 0),
        .stream_id = 1,
    }, header_block);
    if (body.len > 0) {
        try appendFrame(allocator, &bytes, .{
            .length = @intCast(body.len),
            .frame_type = .data,
            .flags = 0x1,
            .stream_id = 1,
        }, body);
    }

    return bytes.toOwnedSlice(allocator);
}

/// Decodes a minimal HTTP/2 response produced by the local server path.
pub fn decodeServerResponse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) (std.mem.Allocator.Error || ExchangeError)!DecodedResponse {
    var cursor: usize = 0;
    var response_headers: ?[]shared_hpack.HeaderField = null;
    var response_body = std.ArrayListUnmanaged(u8){};
    errdefer response_body.deinit(allocator);

    while (cursor < bytes.len) {
        if (cursor + 9 > bytes.len) {
            return error.MalformedFrame;
        }
        const header = shared_frame.FrameHeader.decode(bytes[cursor .. cursor + 9]) catch return error.MalformedFrame;
        cursor += 9;
        if (cursor + header.length > bytes.len) {
            return error.MalformedFrame;
        }
        const payload = bytes[cursor .. cursor + header.length];
        cursor += header.length;

        switch (header.frame_type) {
            .settings => continue,
            .headers => {
                response_headers = shared_hpack.decodeLiteralHeaders(allocator, payload) catch return error.MalformedFrame;
            },
            .data => try response_body.appendSlice(allocator, payload),
            else => return error.UnsupportedExchange,
        }
    }

    const headers = response_headers orelse return error.UnsupportedExchange;
    const status = parseStatus(headers);

    return .{
        .allocator = allocator,
        .status = status,
        .headers = headers,
        .body = try response_body.toOwnedSlice(allocator),
    };
}

/// Dispatches one server-owned WebSocket endpoint through the HTTP/2 adapter.
pub fn dispatchWebSocketEndpoint(
    endpoint: websocket_server.Endpoint,
    request: *server_types.ServerRequest,
    writer: *server_types.ServerResponseWriter,
) !void {
    try websocket_server.dispatchEndpoint(endpoint, request, writer);
}

/// One parsed incoming HTTP/2 request plus its target stream.
const IncomingRequest = struct {
    /// Decoded request surfaced to handlers.
    request: server_types.ServerRequest,
    /// Stream identifier associated with the request.
    stream_id: u31,
};

/// Prefix-aware stream reader used when protocol dispatch already consumed bytes.
const PrefixedStream = struct {
    /// Underlying accepted stream.
    stream: std.net.Stream,
    /// Already-buffered bytes waiting to be consumed first.
    prefix: []const u8,
    /// Current offset into the buffered prefix.
    offset: usize,

    /// Creates a prefix-aware reader over the accepted stream.
    fn init(stream: std.net.Stream, prefix: []const u8) PrefixedStream {
        return .{
            .stream = stream,
            .prefix = prefix,
            .offset = 0,
        };
    }

    /// Reads exactly `dest.len` bytes from the prefix or stream.
    fn readExact(self: *PrefixedStream, dest: []u8) ExchangeError!void {
        var written: usize = 0;
        while (written < dest.len) {
            const read_len = try self.read(dest[written..]);
            if (read_len == 0) {
                return error.UnexpectedEof;
            }
            written += read_len;
        }
    }

    /// Reads up to `dest.len` bytes from the prefix or stream.
    fn read(self: *PrefixedStream, dest: []u8) ExchangeError!usize {
        if (dest.len == 0) {
            return 0;
        }
        if (self.offset < self.prefix.len) {
            const available = self.prefix.len - self.offset;
            const to_copy = @min(dest.len, available);
            std.mem.copyForwards(u8, dest[0..to_copy], self.prefix[self.offset .. self.offset + to_copy]);
            self.offset += to_copy;
            return to_copy;
        }
        return socket_io.read(self.stream, dest);
    }
};

/// Fully buffered HTTP/2 request body surfaced through the shared body-reader type.
const BufferedBodyState = struct {
    /// Allocator used to destroy the body state.
    allocator: std.mem.Allocator,
    /// Owned body bytes.
    body: []u8,
    /// Current read offset.
    offset: usize,

    /// Reads buffered body bytes into the destination slice.
    fn read(ctx: ?*anyopaque, dest: []u8) anyerror!usize {
        const self: *BufferedBodyState = @ptrCast(@alignCast(ctx.?));
        if (self.offset >= self.body.len or dest.len == 0) {
            return 0;
        }
        const remaining = self.body.len - self.offset;
        const to_copy = @min(dest.len, remaining);
        std.mem.copyForwards(u8, dest[0..to_copy], self.body[self.offset .. self.offset + to_copy]);
        self.offset += to_copy;
        return to_copy;
    }

    /// Releases the owned buffered body bytes.
    fn close(ctx: ?*anyopaque) void {
        const self: *BufferedBodyState = @ptrCast(@alignCast(ctx.?));
        self.allocator.free(self.body);
        self.allocator.destroy(self);
    }
};

/// Protocol-private response writer state for one HTTP/2 response stream.
const ResponseState = struct {
    /// Allocator used to destroy the protocol state.
    allocator: std.mem.Allocator,
    /// Accepted stream that receives the response frames.
    stream: std.net.Stream,
    /// Response stream identifier.
    stream_id: u31,
    /// Whether the response HEADERS frame has already been emitted.
    headers_sent: bool,
};

/// Reads one minimal client request from the accepted HTTP/2 connection.
fn readRequest(
    allocator: std.mem.Allocator,
    prefixed: *PrefixedStream,
    session: server_types.NegotiatedSession,
    limits: server_types.ConnectionLimits,
) ExchangeError!IncomingRequest {
    var preface_bytes: [client_preface.len]u8 = undefined;
    try prefixed.readExact(&preface_bytes);
    if (!startsWithClientPreface(&preface_bytes)) {
        return error.InvalidClientPreface;
    }

    const settings_header = try readFrameHeader(prefixed);
    if (settings_header.frame_type != .settings or settings_header.stream_id != 0) {
        return error.MissingSettings;
    }
    _ = try readFramePayload(allocator, prefixed, settings_header);

    const request_header = try readFrameHeader(prefixed);
    if (request_header.frame_type != .headers or request_header.stream_id == 0) {
        return error.UnsupportedExchange;
    }
    if ((request_header.flags & 0x4) == 0) {
        return error.UnsupportedExchange;
    }

    const request_header_payload = try readFramePayload(allocator, prefixed, request_header);
    defer allocator.free(request_header_payload);

    const literal_headers = shared_hpack.decodeLiteralHeaders(allocator, request_header_payload) catch return error.MalformedFrame;
    defer shared_hpack.freeLiteralHeaders(allocator, literal_headers);

    const method = parseMethod(headerValue(literal_headers, ":method") orelse return error.UnsupportedExchange);
    const path = headerValue(literal_headers, ":path") orelse return error.UnsupportedExchange;
    const host = headerValue(literal_headers, "host") orelse "127.0.0.1";

    var body = std.ArrayListUnmanaged(u8){};
    errdefer body.deinit(allocator);

    var end_stream = (request_header.flags & 0x1) != 0;
    while (!end_stream) {
        const body_header = try readFrameHeader(prefixed);
        if (body_header.stream_id != request_header.stream_id) {
            return error.UnsupportedExchange;
        }
        const payload = try readFramePayload(allocator, prefixed, body_header);
        defer allocator.free(payload);

        switch (body_header.frame_type) {
            .data => {
                if (body.items.len + payload.len > limits.max_body_bytes.toInt()) {
                    return error.UnsupportedExchange;
                }
                try body.appendSlice(allocator, payload);
                end_stream = (body_header.flags & 0x1) != 0;
            },
            else => return error.UnsupportedExchange,
        }
    }

    const owned_host = try allocator.dupe(u8, host);
    errdefer allocator.free(owned_host);
    const owned_path = try allocator.dupe(u8, path);
    errdefer allocator.free(owned_path);

    var request_headers = core.Headers.init(allocator);
    errdefer request_headers.deinit();
    for (literal_headers) |header| {
        if (header.name.len > 0 and header.name[0] == ':') {
            continue;
        }
        try request_headers.append(header.name, header.value);
    }

    const body_reader = try buildBufferedBodyReader(allocator, try body.toOwnedSlice(allocator));

    const secure = session.secure;
    const version = core.Version.http_2;
    const request = server_types.ServerRequest{
        .allocator = allocator,
        .method = method,
        .version = version,
        .uri = core.Uri.init(
            if (secure) .https else .http,
            owned_host,
            null,
            owned_path,
            null,
            null,
        ),
        .headers = request_headers,
        .body = body_reader,
        .peer = session.peer,
        .negotiated_protocol = .h2,
        .secure = secure,
        .identity_token = session.identity_token,
        .session = .{
            .peer = session.peer,
            .identity_token = session.identity_token,
            .advertised_protocols = session.advertised_protocols,
            .negotiated_protocol = .h2,
            .request_version = version,
            .secure = secure,
            .alive = true,
        },
        .owned_host = owned_host,
        .owned_path = owned_path,
        .owned_query = null,
    };

    return .{
        .request = request,
        .stream_id = request_header.stream_id,
    };
}

/// Reads and decodes one HTTP/2 frame header from the prefix-aware stream.
fn readFrameHeader(prefixed: *PrefixedStream) ExchangeError!shared_frame.FrameHeader {
    var bytes: [9]u8 = undefined;
    try prefixed.readExact(&bytes);
    return shared_frame.FrameHeader.decode(&bytes) catch return error.MalformedFrame;
}

/// Reads the full payload bytes for a frame header.
fn readFramePayload(
    allocator: std.mem.Allocator,
    prefixed: *PrefixedStream,
    header: shared_frame.FrameHeader,
) ExchangeError![]u8 {
    const payload = try allocator.alloc(u8, header.length);
    errdefer allocator.free(payload);
    try prefixed.readExact(payload);
    return payload;
}

/// Sends the minimal server SETTINGS and ACK sequence required by the local tests.
fn sendServerSettings(stream: std.net.Stream) !void {
    var header: [9]u8 = undefined;
    (shared_frame.FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }).encode(&header);
    try stream.writeAll(&header);

    (shared_frame.FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = 0x1,
        .stream_id = 0,
    }).encode(&header);
    try stream.writeAll(&header);
}

/// Initializes an HTTP/2 response writer for one response stream.
fn initResponseWriter(
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    stream_id: u31,
) std.mem.Allocator.Error!server_types.ServerResponseWriter {
    const state = try allocator.create(ResponseState);
    state.* = .{
        .allocator = allocator,
        .stream = stream,
        .stream_id = stream_id,
        .headers_sent = false,
    };

    return server_types.ServerResponseWriter.init(
        allocator,
        state,
        writeBodyBytes,
        beginResponse,
        finishResponse,
        destroyResponseState,
    );
}

/// Emits the HEADERS frame for the response.
fn beginResponse(ctx: ?*anyopaque, writer: *server_types.ServerResponseWriter) anyerror!void {
    const state: *ResponseState = @ptrCast(@alignCast(ctx.?));
    if (state.headers_sent) {
        return;
    }

    const encoded = try encodeResponseHeaders(state.allocator, writer);
    defer state.allocator.free(encoded);

    var header: [9]u8 = undefined;
    (shared_frame.FrameHeader{
        .length = @intCast(encoded.len),
        .frame_type = .headers,
        .flags = 0x4,
        .stream_id = state.stream_id,
    }).encode(&header);
    try state.stream.writeAll(&header);
    try state.stream.writeAll(encoded);
    state.headers_sent = true;
}

/// Emits one DATA frame for the provided body chunk.
fn writeBodyBytes(ctx: ?*anyopaque, bytes: []const u8) anyerror!void {
    const state: *ResponseState = @ptrCast(@alignCast(ctx.?));
    if (bytes.len == 0) {
        return;
    }

    var header: [9]u8 = undefined;
    (shared_frame.FrameHeader{
        .length = @intCast(bytes.len),
        .frame_type = .data,
        .flags = 0,
        .stream_id = state.stream_id,
    }).encode(&header);
    try state.stream.writeAll(&header);
    try state.stream.writeAll(bytes);
}

/// Finalizes the response with an empty END_STREAM DATA frame.
fn finishResponse(ctx: ?*anyopaque, _: *server_types.ServerResponseWriter) anyerror!void {
    const state: *ResponseState = @ptrCast(@alignCast(ctx.?));
    var header: [9]u8 = undefined;
    (shared_frame.FrameHeader{
        .length = 0,
        .frame_type = .data,
        .flags = 0x1,
        .stream_id = state.stream_id,
    }).encode(&header);
    try state.stream.writeAll(&header);
}

/// Releases the protocol-private response state.
fn destroyResponseState(ctx: ?*anyopaque) void {
    const state: *ResponseState = @ptrCast(@alignCast(ctx.?));
    state.allocator.destroy(state);
}

/// Encodes the response pseudo-headers and regular headers.
fn encodeResponseHeaders(
    allocator: std.mem.Allocator,
    writer: *const server_types.ServerResponseWriter,
) std.mem.Allocator.Error![]u8 {
    var fields = std.ArrayListUnmanaged(shared_hpack.HeaderField){};
    defer fields.deinit(allocator);

    const status_bytes = try std.fmt.allocPrint(allocator, "{d}", .{writer.status.code()});
    defer allocator.free(status_bytes);
    try fields.append(allocator, .{
        .name = ":status",
        .value = status_bytes,
    });

    var iter = writer.headers.iterator();
    while (iter.next()) |header| {
        try fields.append(allocator, .{
            .name = header.name,
            .value = header.value,
        });
    }

    return shared_hpack.encodeLiteralHeaders(allocator, fields.items);
}

/// Builds a buffered request-body reader from the provided bytes.
fn buildBufferedBodyReader(
    allocator: std.mem.Allocator,
    bytes: []u8,
) std.mem.Allocator.Error!?core.BodyReader {
    if (bytes.len == 0) {
        allocator.free(bytes);
        return null;
    }

    const state = try allocator.create(BufferedBodyState);
    state.* = .{
        .allocator = allocator,
        .body = bytes,
        .offset = 0,
    };

    return .{
        .ctx = state,
        .read_fn = BufferedBodyState.read,
        .close_fn = BufferedBodyState.close,
    };
}

/// Returns the first literal header value for the provided name.
fn headerValue(headers: []const shared_hpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) {
            return header.value;
        }
    }
    return null;
}

/// Parses a shared typed HTTP method from an HTTP/2 pseudo-header value.
fn parseMethod(token: []const u8) core.Method {
    if (std.ascii.eqlIgnoreCase(token, "GET")) return .get;
    if (std.ascii.eqlIgnoreCase(token, "HEAD")) return .head;
    if (std.ascii.eqlIgnoreCase(token, "POST")) return .post;
    if (std.ascii.eqlIgnoreCase(token, "PUT")) return .put;
    if (std.ascii.eqlIgnoreCase(token, "DELETE")) return .delete;
    if (std.ascii.eqlIgnoreCase(token, "CONNECT")) return .connect;
    if (std.ascii.eqlIgnoreCase(token, "OPTIONS")) return .options;
    if (std.ascii.eqlIgnoreCase(token, "TRACE")) return .trace;
    if (std.ascii.eqlIgnoreCase(token, "PATCH")) return .patch;
    return .{ .custom = token };
}

/// Parses the response status pseudo-header from a decoded response.
fn parseStatus(headers: []const shared_hpack.HeaderField) core.Status {
    const status_bytes = headerValue(headers, ":status") orelse return .internal_server_error;
    const code = std.fmt.parseInt(u16, status_bytes, 10) catch return .internal_server_error;
    return core.Status.fromInt(code);
}

/// Appends one frame header and payload to the provided byte list.
fn appendFrame(
    allocator: std.mem.Allocator,
    bytes: *std.ArrayListUnmanaged(u8),
    header: shared_frame.FrameHeader,
    payload: []const u8,
) std.mem.Allocator.Error!void {
    var header_bytes: [9]u8 = undefined;
    header.encode(&header_bytes);
    try bytes.appendSlice(allocator, &header_bytes);
    try bytes.appendSlice(allocator, payload);
}

test "server http2 negotiation falls back to http1 by default" {
    const noop = struct {
        fn handle(_: ?*anyopaque, _: *server_types.ServerRequest, _: *server_types.ServerResponseWriter) !void {}
    };

    const config = server_types.ServerConfig.init(noop.handle);
    const result = negotiate(config, null);

    try std.testing.expectEqual(core.NegotiatedProtocol.http_1_1, result.protocol);
    try std.testing.expect(result.supported);
}

test "server http2 preface matcher recognizes the client magic" {
    try std.testing.expect(startsWithClientPreface(client_preface));
    try std.testing.expect(!startsWithClientPreface("GET / HTTP/1.1\r\n\r\n"));
}

test "server http2 request encoder emits the client preface and settings" {
    const encoded = try encodeClientRequest(
        std.testing.allocator,
        .get,
        "/health",
        "127.0.0.1",
        "",
    );
    defer std.testing.allocator.free(encoded);

    try std.testing.expect(std.mem.startsWith(u8, encoded, client_preface));
    try std.testing.expect(encoded.len > client_preface.len + 9);
}
