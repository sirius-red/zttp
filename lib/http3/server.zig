//! In-memory HTTP/3 server and harness flow.

const std = @import("std");
const types = @import("../types.zig");
const interop_harness = @import("../testing/interop_harness.zig");
const qpack = @import("qpack.zig");
const quic = @import("quic.zig");

/// Error set returned by the local HTTP/3 server helpers.
pub const Error = quic.Error || qpack.Error || error{
    /// The request omitted a required pseudo-header.
    MissingPseudoHeader,
    /// The request used an invalid `:status` value.
    InvalidStatus,
};

/// Listener options for the in-memory HTTP/3 harness.
pub const Options = struct {
    /// Host advertised by the harness endpoint.
    host: []const u8 = "127.0.0.1",
    /// UDP port advertised by the harness endpoint.
    port: types.Port = types.Port.init(4433),
};

/// One decoded HTTP/3 request.
pub const DecodedRequest = struct {
    /// HTTP method derived from `:method`.
    method: types.Method,
    /// Path component derived from `:path`.
    path: []u8,
    /// Query component derived from `:path`, if present.
    query: ?[]u8,
    /// Observed `Cookie` header, if present.
    cookie_header: ?[]u8,
    /// Request body bytes.
    body: []u8,

    /// Releases the request-owned buffers.
    pub fn deinit(self: *DecodedRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        if (self.query) |query| {
            allocator.free(query);
        }
        if (self.cookie_header) |cookie_header| {
            allocator.free(cookie_header);
        }
        allocator.free(self.body);
        self.* = undefined;
    }
};

/// In-memory HTTP/3 harness server backed by the shared interop scenarios.
pub const Server = struct {
    /// Allocator used for response encoding.
    allocator: std.mem.Allocator,
    /// Advertised endpoint for the harness.
    listen_endpoint: interop_harness.Endpoint,

    /// Returns a harness server for the provided host and port.
    pub fn init(allocator: std.mem.Allocator, options: Options) Server {
        return .{
            .allocator = allocator,
            .listen_endpoint = .{
                .host = options.host,
                .port = options.port,
                .transport = .udp,
                .protocol = .h3,
            },
        };
    }

    /// Returns the UDP endpoint advertised by the harness.
    pub fn endpoint(self: Server) interop_harness.Endpoint {
        return self.listen_endpoint;
    }

    /// Handles one protected request datagram and returns one protected response datagram.
    pub fn handleDatagram(
        self: *Server,
        connection: *quic.Connection,
        packet_bytes: []const u8,
    ) Error![]u8 {
        var packet = try connection.unprotectPacket(self.allocator, packet_bytes);
        defer packet.deinit(self.allocator);

        var request = try decodeRequest(self.allocator, packet.payload);
        defer request.deinit(self.allocator);

        var response = try interop_harness.buildSemanticResponse(self.allocator, .{
            .method = request.method,
            .path = request.path,
            .query = request.query,
            .negotiated_protocol = .h3,
            .body = request.body,
            .cookie_header = request.cookie_header,
        });
        defer response.deinit();

        const payload = try encodeResponse(self.allocator, response);
        defer self.allocator.free(payload);

        return try connection.protectPacket(self.allocator, .application, payload);
    }
};

/// Returns a harness server for the provided host and port.
pub fn init(allocator: std.mem.Allocator, options: Options) Server {
    return Server.init(allocator, options);
}

/// Decodes request frames into a semantic request.
pub fn decodeRequest(allocator: std.mem.Allocator, bytes: []const u8) Error!DecodedRequest {
    const frames = try qpack.decodeFrames(allocator, bytes);
    defer qpack.freeFrames(allocator, frames);

    var method: ?types.Method = null;
    var path = try allocator.dupe(u8, "/");
    errdefer allocator.free(path);
    var query: ?[]u8 = null;
    errdefer if (query) |value| allocator.free(value);
    var cookie_header: ?[]u8 = null;
    errdefer if (cookie_header) |value| allocator.free(value);
    var body = try allocator.alloc(u8, 0);
    errdefer allocator.free(body);

    for (frames) |frame| {
        switch (frame.frame_type) {
            .headers => {
                const headers = try qpack.decodeHeaderBlock(allocator, frame.payload);
                defer qpack.freeHeaderFields(allocator, headers);

                for (headers) |header| {
                    if (std.mem.eql(u8, header.name, ":method")) {
                        method = parseMethod(header.value);
                        continue;
                    }
                    if (std.mem.eql(u8, header.name, ":path")) {
                        allocator.free(path);
                        if (query) |value| {
                            allocator.free(value);
                            query = null;
                        }
                        const split = try splitPathAndQuery(allocator, header.value);
                        path = split.path;
                        query = split.query;
                        continue;
                    }
                    if (std.ascii.eqlIgnoreCase(header.name, "cookie")) {
                        if (cookie_header) |value| {
                            allocator.free(value);
                        }
                        cookie_header = try allocator.dupe(u8, header.value);
                    }
                }
            },
            .data => {
                allocator.free(body);
                body = try allocator.dupe(u8, frame.payload);
            },
            else => {},
        }
    }

    return .{
        .method = method orelse return error.MissingPseudoHeader,
        .path = path,
        .query = query,
        .cookie_header = cookie_header,
        .body = body,
    };
}

/// Encodes an interop-harness response into HTTP/3 frames.
pub fn encodeResponse(
    allocator: std.mem.Allocator,
    response: interop_harness.SemanticResponse,
) Error![]u8 {
    var headers = std.ArrayListUnmanaged(qpack.HeaderField){};
    defer {
        for (headers.items) |*header| {
            header.deinit(allocator);
        }
        headers.deinit(allocator);
    }

    try appendOwnedHeader(
        allocator,
        &headers,
        ":status",
        try std.fmt.allocPrint(allocator, "{d}", .{response.status.code()}),
        true,
    );
    var iterator = response.headers.iterator();
    while (iterator.next()) |header| {
        try appendOwnedHeader(allocator, &headers, header.name, header.value, false);
    }

    const header_block = try qpack.encodeHeaderBlock(allocator, headers.items);
    defer allocator.free(header_block);
    const header_frame = try qpack.encodeFrame(allocator, .headers, header_block);
    defer allocator.free(header_frame);

    var bytes = std.ArrayListUnmanaged(u8){};
    errdefer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, header_frame);
    if (response.body.len > 0) {
        const data_frame = try qpack.encodeFrame(allocator, .data, response.body);
        defer allocator.free(data_frame);
        try bytes.appendSlice(allocator, data_frame);
    }

    return bytes.toOwnedSlice(allocator);
}

/// Appends one owned header field to the provided list.
fn appendOwnedHeader(
    allocator: std.mem.Allocator,
    headers: *std.ArrayListUnmanaged(qpack.HeaderField),
    name: []const u8,
    value: []const u8,
    value_owned: bool,
) Error!void {
    const owned_name = try allocator.dupe(u8, name);
    errdefer allocator.free(owned_name);
    const owned_value = if (value_owned)
        value
    else
        try allocator.dupe(u8, value);
    errdefer allocator.free(@constCast(owned_value));
    try headers.append(allocator, .{
        .name = owned_name,
        .value = owned_value,
    });
}

/// Splits a `:path` pseudo-header into path and query components.
fn splitPathAndQuery(
    allocator: std.mem.Allocator,
    value: []const u8,
) std.mem.Allocator.Error!struct { path: []u8, query: ?[]u8 } {
    if (std.mem.indexOfScalar(u8, value, '?')) |query_start| {
        return .{
            .path = try allocator.dupe(u8, if (query_start == 0) "/" else value[0..query_start]),
            .query = try allocator.dupe(u8, value[query_start + 1 ..]),
        };
    }
    return .{
        .path = try allocator.dupe(u8, if (value.len == 0) "/" else value),
        .query = null,
    };
}

/// Parses a method token into the shared method type.
fn parseMethod(value: []const u8) types.Method {
    if (std.ascii.eqlIgnoreCase(value, "GET")) return .get;
    if (std.ascii.eqlIgnoreCase(value, "HEAD")) return .head;
    if (std.ascii.eqlIgnoreCase(value, "POST")) return .post;
    if (std.ascii.eqlIgnoreCase(value, "PUT")) return .put;
    if (std.ascii.eqlIgnoreCase(value, "DELETE")) return .delete;
    if (std.ascii.eqlIgnoreCase(value, "CONNECT")) return .connect;
    if (std.ascii.eqlIgnoreCase(value, "OPTIONS")) return .options;
    if (std.ascii.eqlIgnoreCase(value, "TRACE")) return .trace;
    if (std.ascii.eqlIgnoreCase(value, "PATCH")) return .patch;
    return .{ .custom = value };
}

test "http3 server decodes request pseudo-headers and body" {
    var headers = std.ArrayListUnmanaged(qpack.HeaderField){};
    defer {
        for (headers.items) |*header| {
            header.deinit(std.testing.allocator);
        }
        headers.deinit(std.testing.allocator);
    }
    try appendOwnedHeader(std.testing.allocator, &headers, ":method", "POST", false);
    try appendOwnedHeader(std.testing.allocator, &headers, ":path", "/echo?name=value", false);
    try appendOwnedHeader(std.testing.allocator, &headers, "cookie", "a=b", false);

    const header_block = try qpack.encodeHeaderBlock(std.testing.allocator, headers.items);
    defer std.testing.allocator.free(header_block);
    const header_frame = try qpack.encodeFrame(std.testing.allocator, .headers, header_block);
    defer std.testing.allocator.free(header_frame);
    const data_frame = try qpack.encodeFrame(std.testing.allocator, .data, "payload");
    defer std.testing.allocator.free(data_frame);

    var encoded = std.ArrayListUnmanaged(u8){};
    defer encoded.deinit(std.testing.allocator);
    try encoded.appendSlice(std.testing.allocator, header_frame);
    try encoded.appendSlice(std.testing.allocator, data_frame);

    var request = try decodeRequest(std.testing.allocator, encoded.items);
    defer request.deinit(std.testing.allocator);

    try std.testing.expectEqual(types.Method.post, request.method);
    try std.testing.expectEqualStrings("/echo", request.path);
    try std.testing.expectEqualStrings("name=value", request.query.?);
    try std.testing.expectEqualStrings("a=b", request.cookie_header.?);
    try std.testing.expectEqualStrings("payload", request.body);
}

test "http3 server round trips harness health requests" {
    var client_conn = quic.Connection.init(std.testing.allocator, "client01".*, "server01".*);
    defer client_conn.deinit();
    var server_conn = quic.Connection.init(std.testing.allocator, "server01".*, "client01".*);
    defer server_conn.deinit();
    client_conn.beginHandshake();
    client_conn.establish();
    server_conn.beginHandshake();
    server_conn.establish();

    const header_block = try qpack.encodeHeaderBlock(std.testing.allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/health" },
    });
    defer std.testing.allocator.free(header_block);
    const header_frame = try qpack.encodeFrame(std.testing.allocator, .headers, header_block);
    defer std.testing.allocator.free(header_frame);
    const request_packet = try client_conn.protectPacket(std.testing.allocator, .application, header_frame);
    defer std.testing.allocator.free(request_packet);

    var server = Server.init(std.testing.allocator, .{});
    const response_packet = try server.handleDatagram(&server_conn, request_packet);
    defer std.testing.allocator.free(response_packet);

    var decoded = try client_conn.unprotectPacket(std.testing.allocator, response_packet);
    defer decoded.deinit(std.testing.allocator);

    const frames = try qpack.decodeFrames(std.testing.allocator, decoded.payload);
    defer qpack.freeFrames(std.testing.allocator, frames);
    const response_headers = try qpack.decodeHeaderBlock(std.testing.allocator, frames[0].payload);
    defer qpack.freeHeaderFields(std.testing.allocator, response_headers);

    try std.testing.expectEqualStrings("200", response_headers[0].value);
}
