//! HTTP/1.1 request parsing and streamed response writing helpers.

const std = @import("std");
const core = @import("../types.zig");
const socket_io = @import("../util/socket_io.zig");
const server_types = @import("types.zig");
const websocket_server = @import("../websocket/server.zig");

/// Error set returned while parsing an HTTP/1.1 request.
pub const ParseError = error{
    /// The peer closed the connection before the full request head arrived.
    UnexpectedEof,
    /// The request head exceeded the configured byte limit.
    HeaderTooLarge,
    /// The request line exceeded the configured byte limit.
    RequestLineTooLarge,
    /// Too many header fields were supplied.
    TooManyHeaders,
    /// The request line was malformed.
    InvalidRequestLine,
    /// A header line was malformed.
    InvalidHeader,
    /// The HTTP version is not supported by this parser.
    UnsupportedVersion,
    /// The `Content-Length` value was invalid.
    InvalidContentLength,
    /// The request body exceeded the configured limit.
    BodyTooLarge,
};

/// Parses one HTTP/1.1 request from the accepted connection.
pub fn readRequest(
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    scheme: core.Scheme,
    peer: std.net.Address,
    negotiated_protocol: core.NegotiatedProtocol,
    limits: server_types.ConnectionLimits,
) (std.mem.Allocator.Error || std.net.Stream.ReadError || ParseError)!server_types.ServerRequest {
    return readRequestPrefixed(
        allocator,
        stream,
        &.{},
        scheme,
        peer,
        negotiated_protocol,
        limits,
    );
}

/// Parses one HTTP/1.1 request, starting from an already-buffered prefix.
pub fn readRequestPrefixed(
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    prefix_bytes: []const u8,
    scheme: core.Scheme,
    peer: std.net.Address,
    negotiated_protocol: core.NegotiatedProtocol,
    limits: server_types.ConnectionLimits,
) (std.mem.Allocator.Error || std.net.Stream.ReadError || ParseError)!server_types.ServerRequest {
    var head_bytes = std.ArrayListUnmanaged(u8){};
    defer head_bytes.deinit(allocator);
    try head_bytes.appendSlice(allocator, prefix_bytes);

    var buffer: [1024]u8 = undefined;
    var header_end: ?usize = std.mem.indexOf(u8, head_bytes.items, "\r\n\r\n");
    while (header_end == null) {
        const read_len = try socket_io.read(stream, &buffer);
        if (read_len == 0) {
            return error.UnexpectedEof;
        }
        try head_bytes.appendSlice(allocator, buffer[0..read_len]);
        if (head_bytes.items.len > limits.max_header_bytes.toInt()) {
            return error.HeaderTooLarge;
        }
        header_end = std.mem.indexOf(u8, head_bytes.items, "\r\n\r\n");
    }

    const header_stop = header_end.?;
    const body_prefix = head_bytes.items[header_stop + 4 ..];
    const request_head = head_bytes.items[0..header_stop];

    var lines = std.mem.splitSequence(u8, request_head, "\r\n");
    const request_line = lines.next() orelse return error.InvalidRequestLine;
    if (request_line.len > limits.max_request_line_bytes.toInt()) {
        return error.RequestLineTooLarge;
    }

    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method_token = parts.next() orelse return error.InvalidRequestLine;
    const target = parts.next() orelse return error.InvalidRequestLine;
    const version_token = parts.next() orelse return error.InvalidRequestLine;
    if (parts.next() != null) {
        return error.InvalidRequestLine;
    }

    const method = parseMethod(method_token);
    const version = parseVersion(version_token) catch return error.UnsupportedVersion;

    var headers = core.Headers.init(allocator);
    errdefer headers.deinit();

    var header_count: usize = 0;
    var content_length: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) {
            continue;
        }
        header_count += 1;
        if (header_count > limits.max_header_count.toInt()) {
            return error.TooManyHeaders;
        }

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHeader;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trimLeft(u8, line[colon + 1 ..], " \t");
        if (name.len == 0) {
            return error.InvalidHeader;
        }
        try headers.append(name, value);

        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            content_length = std.fmt.parseInt(usize, value, 10) catch return error.InvalidContentLength;
            if (content_length > limits.max_body_bytes.toInt()) {
                return error.BodyTooLarge;
            }
        }
    }

    const path_and_query = splitTarget(target);
    const host_header = headers.get("host") orelse "127.0.0.1";
    const host_only = stripHostPort(host_header);

    const owned_host = try allocator.dupe(u8, host_only);
    errdefer allocator.free(owned_host);
    const owned_path = try allocator.dupe(u8, path_and_query.path);
    errdefer allocator.free(owned_path);
    const owned_query = if (path_and_query.query) |query|
        try allocator.dupe(u8, query)
    else
        null;
    errdefer if (owned_query) |query| allocator.free(query);

    const body = if (content_length > 0 or body_prefix.len > 0)
        try buildBodyReader(allocator, stream, body_prefix, content_length)
    else
        null;

    return .{
        .allocator = allocator,
        .method = method,
        .version = version,
        .uri = core.Uri.init(
            scheme,
            owned_host,
            null,
            owned_path,
            owned_query,
            null,
        ),
        .headers = headers,
        .body = body,
        .peer = peer,
        .negotiated_protocol = negotiated_protocol,
        .secure = scheme == .https,
        .identity_token = null,
        .session = .{
            .peer = peer,
            .identity_token = null,
            .negotiated_protocol = negotiated_protocol,
            .request_version = version,
            .secure = scheme == .https,
            .alive = true,
        },
        .owned_host = owned_host,
        .owned_path = owned_path,
        .owned_query = owned_query,
    };
}

/// Creates an HTTP/1.1 response writer for the accepted stream.
pub fn initResponseWriter(
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    version: core.Version,
) std.mem.Allocator.Error!server_types.ServerResponseWriter {
    const state = try allocator.create(ResponseState);
    state.* = .{
        .allocator = allocator,
        .stream = stream,
        .version = version,
        .chunked = false,
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

/// Dispatches one server-owned WebSocket endpoint through the HTTP/1.1 upgrade path.
pub fn dispatchWebSocketEndpoint(
    endpoint: websocket_server.Endpoint,
    request: *server_types.ServerRequest,
    writer: *server_types.ServerResponseWriter,
) !void {
    try websocket_server.dispatchEndpoint(endpoint, request, writer);
}

/// Splits a request target into path and query components.
fn splitTarget(target: []const u8) struct { path: []const u8, query: ?[]const u8 } {
    if (std.mem.indexOfScalar(u8, target, '?')) |query_start| {
        return .{
            .path = if (query_start == 0) "/" else target[0..query_start],
            .query = target[query_start + 1 ..],
        };
    }
    return .{
        .path = if (target.len == 0) "/" else target,
        .query = null,
    };
}

/// Returns the host portion of a host header value.
fn stripHostPort(host_header: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, host_header, ':')) |port_start| {
        return host_header[0..port_start];
    }
    return host_header;
}

/// Parses a request method token into the shared method type.
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

/// Parses an HTTP version token from the request line.
fn parseVersion(token: []const u8) ParseError!core.Version {
    if (std.mem.eql(u8, token, "HTTP/1.0")) return .http_1_0;
    if (std.mem.eql(u8, token, "HTTP/1.1")) return .http_1_1;
    return error.UnsupportedVersion;
}

/// Streaming request body state that preserves already-buffered bytes.
const RequestBodyState = struct {
    /// Allocator used to destroy the state.
    allocator: std.mem.Allocator,
    /// Underlying connection stream.
    stream: std.net.Stream,
    /// Already-buffered body bytes read with the request head.
    prefix: []u8,
    /// Current offset into the buffered prefix.
    prefix_offset: usize,
    /// Remaining body bytes still expected from the peer.
    remaining: usize,

    /// Reads request body bytes into the destination buffer.
    fn read(ctx: ?*anyopaque, dest: []u8) anyerror!usize {
        const self: *RequestBodyState = @ptrCast(@alignCast(ctx.?));
        if (dest.len == 0) {
            return 0;
        }

        if (self.prefix_offset < self.prefix.len) {
            const available = self.prefix.len - self.prefix_offset;
            const to_copy = @min(dest.len, available);
            std.mem.copyForwards(u8, dest[0..to_copy], self.prefix[self.prefix_offset .. self.prefix_offset + to_copy]);
            self.prefix_offset += to_copy;
            return to_copy;
        }

        if (self.remaining == 0) {
            return 0;
        }

        const to_read = @min(dest.len, self.remaining);
        const read_len = try socket_io.read(self.stream, dest[0..to_read]);
        if (read_len == 0) {
            return error.UnexpectedEof;
        }
        self.remaining -= read_len;
        return read_len;
    }

    /// Releases the buffered body state.
    fn close(ctx: ?*anyopaque) void {
        const self: *RequestBodyState = @ptrCast(@alignCast(ctx.?));
        self.allocator.free(self.prefix);
        self.allocator.destroy(self);
    }
};

/// Allocates a streaming body reader for the parsed request.
fn buildBodyReader(
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    body_prefix: []const u8,
    content_length: usize,
) std.mem.Allocator.Error!?core.BodyReader {
    const prefix_len = @min(body_prefix.len, content_length);
    const prefix = try allocator.dupe(u8, body_prefix[0..prefix_len]);
    errdefer allocator.free(prefix);

    const state = try allocator.create(RequestBodyState);
    state.* = .{
        .allocator = allocator,
        .stream = stream,
        .prefix = prefix,
        .prefix_offset = 0,
        .remaining = content_length - prefix_len,
    };

    return .{
        .ctx = state,
        .read_fn = RequestBodyState.read,
        .close_fn = RequestBodyState.close,
    };
}

/// Protocol-private response writer state.
const ResponseState = struct {
    /// Allocator used to destroy the state.
    allocator: std.mem.Allocator,
    /// Accepted connection stream.
    stream: std.net.Stream,
    /// HTTP version used for the status line.
    version: core.Version,
    /// Whether chunked transfer encoding is in use.
    chunked: bool,
    /// Whether the response head has already been emitted.
    headers_sent: bool,
};

/// Emits the HTTP status line and response headers.
fn beginResponse(
    ctx: ?*anyopaque,
    writer: *server_types.ServerResponseWriter,
) anyerror!void {
    const state: *ResponseState = @ptrCast(@alignCast(ctx.?));
    if (state.headers_sent) {
        return;
    }

    const has_content_length = writer.headers.get("content-length") != null;
    const has_transfer_encoding = writer.headers.get("transfer-encoding") != null;
    if (!has_content_length and !has_transfer_encoding) {
        try writer.headers.append("Transfer-Encoding", "chunked");
        state.chunked = true;
    } else if (writer.headers.get("transfer-encoding")) |value| {
        state.chunked = std.ascii.eqlIgnoreCase(value, "chunked");
    }

    if (writer.headers.get("connection") == null) {
        try writer.headers.append("Connection", "close");
    }

    var line_buffer: [256]u8 = undefined;
    const status_line = try std.fmt.bufPrint(
        &line_buffer,
        "{s} {d} {s}\r\n",
        .{
            state.version.asBytes(),
            writer.status.code(),
            reasonPhrase(writer.status),
        },
    );
    try state.stream.writeAll(status_line);

    var iter = writer.headers.iterator();
    while (iter.next()) |header| {
        const header_line = try std.fmt.bufPrint(&line_buffer, "{s}: {s}\r\n", .{ header.name, header.value });
        try state.stream.writeAll(header_line);
    }

    try state.stream.writeAll("\r\n");
    state.headers_sent = true;
}

/// Streams one body chunk through the HTTP/1.1 response encoder.
fn writeBodyBytes(ctx: ?*anyopaque, bytes: []const u8) anyerror!void {
    const state: *ResponseState = @ptrCast(@alignCast(ctx.?));
    if (state.chunked) {
        var prefix_buffer: [32]u8 = undefined;
        const prefix = try std.fmt.bufPrint(&prefix_buffer, "{x}\r\n", .{bytes.len});
        try state.stream.writeAll(prefix);
        try state.stream.writeAll(bytes);
        try state.stream.writeAll("\r\n");
        return;
    }
    try state.stream.writeAll(bytes);
}

/// Finalizes the HTTP/1.1 response.
fn finishResponse(
    ctx: ?*anyopaque,
    writer: *server_types.ServerResponseWriter,
) anyerror!void {
    const state: *ResponseState = @ptrCast(@alignCast(ctx.?));
    if (state.chunked) {
        try state.stream.writeAll("0\r\n");
        if (writer.trailers.entries.items.len > 0) {
            var line_buffer: [256]u8 = undefined;
            var iter = writer.trailers.iterator();
            while (iter.next()) |header| {
                const trailer_line = try std.fmt.bufPrint(&line_buffer, "{s}: {s}\r\n", .{ header.name, header.value });
                try state.stream.writeAll(trailer_line);
            }
        }
        try state.stream.writeAll("\r\n");
    }
}

/// Destroys the protocol-private response state.
fn destroyResponseState(ctx: ?*anyopaque) void {
    const state: *ResponseState = @ptrCast(@alignCast(ctx.?));
    state.allocator.destroy(state);
}

/// Returns the conventional reason phrase for a status code.
fn reasonPhrase(status: core.Status) []const u8 {
    return switch (status) {
        .continue_ => "Continue",
        .switching_protocols => "Switching Protocols",
        .ok => "OK",
        .created => "Created",
        .no_content => "No Content",
        .moved_permanently => "Moved Permanently",
        .found => "Found",
        .see_other => "See Other",
        .temporary_redirect => "Temporary Redirect",
        .permanent_redirect => "Permanent Redirect",
        .bad_request => "Bad Request",
        .unauthorized => "Unauthorized",
        .forbidden => "Forbidden",
        .not_found => "Not Found",
        .method_not_allowed => "Method Not Allowed",
        .request_timeout => "Request Timeout",
        .payload_too_large => "Payload Too Large",
        .uri_too_long => "URI Too Long",
        .request_header_fields_too_large => "Request Header Fields Too Large",
        .internal_server_error => "Internal Server Error",
        .bad_gateway => "Bad Gateway",
        .service_unavailable => "Service Unavailable",
    };
}

test "http1 response writer emits chunked response bodies" {
    var bytes = std.ArrayList(u8).empty;
    defer bytes.deinit(std.testing.allocator);

    const FakeState = struct {
        bytes: *std.ArrayList(u8),
        chunked: bool = false,

        fn write(ctx: ?*anyopaque, payload: []const u8) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            try self.bytes.appendSlice(std.testing.allocator, payload);
        }

        fn begin(ctx: ?*anyopaque, writer: *server_types.ServerResponseWriter) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            _ = writer;
            self.chunked = true;
            try self.bytes.appendSlice(std.testing.allocator, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        }

        fn finish(ctx: ?*anyopaque, writer: *server_types.ServerResponseWriter) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            _ = writer;
            if (self.chunked) {
                try self.bytes.appendSlice(std.testing.allocator, "0\r\n\r\n");
            }
        }
    };

    var state = FakeState{ .bytes = &bytes };
    var writer = server_types.ServerResponseWriter.init(
        std.testing.allocator,
        &state,
        FakeState.write,
        FakeState.begin,
        FakeState.finish,
        null,
    );
    defer writer.deinit();

    try writer.writeAll("hello");
    try writer.finish();

    try std.testing.expect(std.mem.containsAtLeast(u8, bytes.items, 1, "Transfer-Encoding: chunked"));
}
