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

/// Connection-scoped HTTP/3 compression state retained by the harness server path.
pub const SessionState = struct {
    /// Connection-scoped QPACK state reused across repeated exchanges.
    qpack_state: qpack.PeerState,
    /// Negotiated maximum dynamic-table capacity for the peer.
    qpack_max_table_capacity: usize,
    /// Negotiated blocked-stream limit for the peer.
    qpack_blocked_streams: usize,

    /// Returns an empty per-session state for the provided QPACK limits.
    pub fn init(
        allocator: std.mem.Allocator,
        qpack_max_table_capacity: usize,
        qpack_blocked_streams: usize,
    ) SessionState {
        return .{
            .qpack_state = qpack.PeerState.init(
                allocator,
                qpack_max_table_capacity,
                qpack_blocked_streams,
            ),
            .qpack_max_table_capacity = qpack_max_table_capacity,
            .qpack_blocked_streams = qpack_blocked_streams,
        };
    }

    /// Releases the retained connection-scoped QPACK state.
    pub fn deinit(self: *SessionState) void {
        self.qpack_state.deinit();
        self.* = undefined;
    }

    /// Applies the currently negotiated QPACK limits to the retained peer state.
    pub fn applyNegotiatedSettings(self: *SessionState) void {
        self.qpack_state.configureLimits(
            self.qpack_max_table_capacity,
            self.qpack_blocked_streams,
        );
    }
};

/// One decoded HTTP/3 request.
pub const DecodedRequest = struct {
    /// HTTP method derived from `:method`.
    method: types.Method,
    /// Path component derived from `:path`.
    path: []u8,
    /// Query component derived from `:path`, if present.
    query: ?[]u8,
    /// Decoded non-pseudo request headers preserved for the handler bridge.
    headers: types.Headers,
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
        self.headers.deinit();
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
        var session_state = SessionState.init(self.allocator, 4 * 1024, 8);
        defer session_state.deinit();
        return self.handleDatagramWithSession(connection, &session_state, packet_bytes);
    }

    /// Handles one protected request datagram while reusing retained session state.
    pub fn handleDatagramWithSession(
        self: *Server,
        connection: *quic.Connection,
        session_state: *SessionState,
        packet_bytes: []const u8,
    ) Error![]u8 {
        var packet = try connection.unprotectPacket(self.allocator, packet_bytes);
        defer packet.deinit(self.allocator);

        var request = try decodeRequestWithSession(self.allocator, session_state, packet.payload);
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

        const payload = try encodeResponseWithSession(self.allocator, session_state, response);
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
    var session_state = SessionState.init(allocator, 4 * 1024, 8);
    defer session_state.deinit();
    return decodeRequestWithSession(allocator, &session_state, bytes);
}

/// Decodes request frames into a semantic request using retained peer state.
pub fn decodeRequestWithSession(
    allocator: std.mem.Allocator,
    session_state: *SessionState,
    bytes: []const u8,
) Error!DecodedRequest {
    return decodeRequestWithPeerState(
        allocator,
        &session_state.qpack_state,
        session_state.qpack_max_table_capacity,
        session_state.qpack_blocked_streams,
        bytes,
    );
}

/// Decodes request frames into a semantic request using retained peer QPACK state.
pub fn decodeRequestWithPeerState(
    allocator: std.mem.Allocator,
    qpack_state: *qpack.PeerState,
    qpack_max_table_capacity: usize,
    qpack_blocked_streams: usize,
    bytes: []const u8,
) Error!DecodedRequest {
    const frames = try qpack.decodeFrames(allocator, bytes);
    defer qpack.freeFrames(allocator, frames);

    var method: ?types.Method = null;
    var path = try allocator.dupe(u8, "/");
    errdefer allocator.free(path);
    var query: ?[]u8 = null;
    errdefer if (query) |value| allocator.free(value);
    var headers = types.Headers.init(allocator);
    errdefer headers.deinit();
    var cookie_header: ?[]u8 = null;
    errdefer if (cookie_header) |value| allocator.free(value);
    var body = try allocator.alloc(u8, 0);
    errdefer allocator.free(body);

    for (frames) |frame| {
        switch (frame.frame_type) {
            .headers => {
                qpack_state.configureLimits(qpack_max_table_capacity, qpack_blocked_streams);
                const decoded_headers = try qpack_state.decodeHeaders(frame.payload);
                defer qpack.freeHeaderFields(allocator, decoded_headers);

                for (decoded_headers) |header| {
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
                        try headers.append(header.name, header.value);
                        continue;
                    }
                    if (header.name.len > 0 and header.name[0] != ':') {
                        try headers.append(header.name, header.value);
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
        .headers = headers,
        .cookie_header = cookie_header,
        .body = body,
    };
}

/// Encodes an interop-harness response into HTTP/3 frames.
pub fn encodeResponse(
    allocator: std.mem.Allocator,
    response: interop_harness.SemanticResponse,
) Error![]u8 {
    var session_state = SessionState.init(allocator, 4 * 1024, 8);
    defer session_state.deinit();
    return encodeResponseWithSession(allocator, &session_state, response);
}

/// Encodes an interop-harness response using retained peer compression state.
pub fn encodeResponseWithSession(
    allocator: std.mem.Allocator,
    session_state: *SessionState,
    response: interop_harness.SemanticResponse,
) Error![]u8 {
    return encodeResponseWithPeerState(
        allocator,
        &session_state.qpack_state,
        session_state.qpack_max_table_capacity,
        session_state.qpack_blocked_streams,
        response,
    );
}

/// Encodes an interop-harness response using retained peer QPACK state.
pub fn encodeResponseWithPeerState(
    allocator: std.mem.Allocator,
    qpack_state: *qpack.PeerState,
    qpack_max_table_capacity: usize,
    qpack_blocked_streams: usize,
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

    qpack_state.configureLimits(qpack_max_table_capacity, qpack_blocked_streams);
    const header_block = try qpack_state.encodeHeaders(headers.items);
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
