//! HTTP/3 client request flow for local harness interoperability.

const builtin = @import("builtin");
const std = @import("std");
const types = @import("../types.zig");
const qpack = @import("qpack.zig");
const quic = @import("quic.zig");
const server = @import("server.zig");

/// Monotonic seed used to derive distinct loopback runtime session identifiers.
var runtime_session_seed = std.atomic.Value(u64).init(0);

/// Error set returned by the local HTTP/3 client helpers.
pub const Error = anyerror;

/// One decoded runtime stream envelope retained long enough to parse a response.
const StreamEnvelope = struct {
    /// Stream identifier associated with the payload.
    stream_id: u64,
    /// Owned payload bytes carried for the stream.
    payload: []u8,

    /// Releases the owned payload buffer.
    fn deinit(self: *StreamEnvelope, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
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

/// Prepares an HTTP/3 request for the local harness flow.
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

/// Executes one local harness request over the QUIC scaffolding.
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
    var harness_session = server.SessionState.init(allocator, 4 * 1024, 8);
    defer harness_session.deinit();
    const response_packet = try harness_server.handleDatagramWithSession(
        &server_conn,
        &harness_session,
        request_packet,
    );
    defer allocator.free(response_packet);

    return try decodeResponse(allocator, &client_conn, response_packet);
}

/// Reusable UDP-backed HTTP/3 client session for local loopback exchanges.
pub const RuntimeSession = struct {
    /// Allocator used for connection and response storage.
    allocator: std.mem.Allocator,
    /// Connected UDP socket for the peer listener.
    socket: std.posix.socket_t,
    /// QUIC transport state retained across repeated exchanges.
    connection: quic.Connection,
    /// Connection-scoped QPACK state retained across repeated exchanges.
    qpack_state: qpack.PeerState,
    /// Local control stream identifier.
    control_stream_id: u64,
    /// Local QPACK encoder stream identifier.
    qpack_encoder_stream_id: u64,
    /// Local QPACK decoder stream identifier.
    qpack_decoder_stream_id: u64,
    /// Negotiated maximum QPACK table capacity.
    qpack_max_table_capacity: usize,
    /// Negotiated maximum blocked-stream count.
    qpack_blocked_stream_limit: usize,
    /// Whether critical control-stream setup completed for the session.
    control_stream_ready: bool,

    /// Connects a new loopback HTTP/3 runtime session.
    pub fn init(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: types.Port,
    ) Error!RuntimeSession {
        const peer = try std.net.Address.parseIp(host, port.toInt());
        const socket = try std.posix.socket(
            peer.any.family,
            std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC,
            std.posix.IPPROTO.UDP,
        );
        errdefer std.posix.close(socket);

        var local = try std.net.Address.parseIp("127.0.0.1", 0);
        try std.posix.bind(socket, &local.any, local.getOsSockLen());
        try std.posix.connect(socket, &peer.any, peer.getOsSockLen());

        var connection = quic.Connection.init(
            allocator,
            deriveClientConnectionId(host, port),
            "server01".*,
        );
        connection.beginHandshake();
        connection.establish();
        const control_stream_id = try connection.openStream(.unidirectional);
        const qpack_encoder_stream_id = try connection.openStream(.unidirectional);
        const qpack_decoder_stream_id = try connection.openStream(.unidirectional);
        var qpack_state = qpack.PeerState.init(allocator, 4 * 1024, 8);
        qpack_state.encoder_stream.stream_id = qpack_encoder_stream_id;
        qpack_state.decoder_stream.stream_id = qpack_decoder_stream_id;

        return .{
            .allocator = allocator,
            .socket = socket,
            .connection = connection,
            .qpack_state = qpack_state,
            .control_stream_id = control_stream_id,
            .qpack_encoder_stream_id = qpack_encoder_stream_id,
            .qpack_decoder_stream_id = qpack_decoder_stream_id,
            .qpack_max_table_capacity = 4 * 1024,
            .qpack_blocked_stream_limit = 8,
            .control_stream_ready = true,
        };
    }

    /// Releases the connected UDP socket and retained session state.
    pub fn deinit(self: *RuntimeSession) void {
        std.posix.close(self.socket);
        self.connection.deinit();
        self.qpack_state.deinit();
        self.* = undefined;
    }

    /// Executes one HTTP/3 request against the connected runtime.
    pub fn executeRequest(self: *RuntimeSession, request: *const types.Request) Error!types.Response {
        try self.applyNegotiatedSettings();
        var plan = try prepareRuntimeRequest(
            self.allocator,
            &self.connection,
            &self.qpack_state,
            request,
        );
        defer plan.deinit();

        const request_payload = try encodeRequest(self.allocator, plan);
        defer self.allocator.free(request_payload);
        const stream_payload = try encodeStreamEnvelope(
            self.allocator,
            plan.stream_id,
            request_payload,
        );
        defer self.allocator.free(stream_payload);
        const request_packet = try self.connection.protectPacket(
            self.allocator,
            .application,
            stream_payload,
        );
        defer self.allocator.free(request_packet);

        _ = try sendConnected(self.socket, request_packet);

        var buffer: [64 * 1024]u8 = undefined;
        const read_len = try recvConnected(self.socket, buffer[0..]);
        return try decodeResponseWithPeerState(
            self.allocator,
            &self.connection,
            &self.qpack_state,
            plan.stream_id,
            buffer[0..read_len],
        );
    }

    /// Applies the negotiated SETTINGS values to the retained QPACK state.
    fn applyNegotiatedSettings(self: *RuntimeSession) Error!void {
        if (!self.control_stream_ready) {
            return error.InvalidControlStreamState;
        }
        self.qpack_state.encoder_stream.stream_id = self.qpack_encoder_stream_id;
        self.qpack_state.decoder_stream.stream_id = self.qpack_decoder_stream_id;
        self.qpack_state.configureLimits(
            self.qpack_max_table_capacity,
            self.qpack_blocked_stream_limit,
        );
    }
};

/// Executes one local loopback request against the real UDP-backed HTTP/3 runtime.
pub fn executeRuntimeRequest(
    allocator: std.mem.Allocator,
    request: *const types.Request,
) Error!types.Response {
    var session = try RuntimeSession.init(allocator, request.uri.host, request.uri.effectivePort());
    defer session.deinit();
    return try session.executeRequest(request);
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

/// Decodes a protected HTTP/3 response packet using connection-scoped QPACK state.
pub fn decodeResponseWithPeerState(
    allocator: std.mem.Allocator,
    connection: *quic.Connection,
    qpack_state: *qpack.PeerState,
    expected_stream_id: u64,
    packet_bytes: []const u8,
) Error!types.Response {
    var packet = try connection.unprotectPacket(allocator, packet_bytes);
    defer packet.deinit(allocator);

    var envelope = try decodeStreamEnvelope(allocator, packet.payload);
    defer envelope.deinit(allocator);
    if (envelope.stream_id != expected_stream_id) {
        return error.InvalidStreamEnvelope;
    }

    const frames = try qpack.decodeFrames(allocator, envelope.payload);
    defer qpack.freeFrames(allocator, frames);

    var status: ?types.Status = null;
    var response = types.Response.init(allocator, .http_3, .ok);
    errdefer response.deinit();
    var body = std.ArrayListUnmanaged(u8){};
    errdefer body.deinit(allocator);

    for (frames) |frame| {
        switch (frame.frame_type) {
            .headers => {
                const headers = try qpack_state.decodeHeaders(frame.payload);
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

/// Prepares an HTTP/3 request while retaining connection-scoped QPACK state.
fn prepareRuntimeRequest(
    allocator: std.mem.Allocator,
    connection: *quic.Connection,
    qpack_state: *qpack.PeerState,
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

    const header_block = try qpack_state.encodeHeaders(headers.items);
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

/// Derives a stable client connection identifier from the loopback target.
fn deriveClientConnectionId(host: []const u8, port: types.Port) quic.ConnectionId {
    var id: quic.ConnectionId = undefined;
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(host);
    const port_bytes = std.mem.toBytes(port.toInt());
    hasher.update(&port_bytes);
    const seed_bytes = std.mem.toBytes(runtime_session_seed.fetchAdd(1, .seq_cst));
    hasher.update(&seed_bytes);
    const hash = std.mem.toBytes(hasher.final());
    std.mem.copyForwards(u8, id[0..], hash[0..id.len]);
    return id;
}

/// Encodes one runtime request payload with its QUIC stream identifier.
fn encodeStreamEnvelope(
    allocator: std.mem.Allocator,
    stream_id: u64,
    payload: []const u8,
) Error![]u8 {
    const encoded_stream_id = try qpack.encodeVarInt(allocator, stream_id);
    defer allocator.free(encoded_stream_id);
    const encoded_payload_len = try qpack.encodeVarInt(allocator, payload.len);
    defer allocator.free(encoded_payload_len);

    var bytes = std.ArrayListUnmanaged(u8){};
    errdefer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, encoded_stream_id);
    try bytes.appendSlice(allocator, encoded_payload_len);
    try bytes.appendSlice(allocator, payload);
    return bytes.toOwnedSlice(allocator);
}

/// Decodes one runtime response envelope into stream metadata plus payload bytes.
fn decodeStreamEnvelope(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) Error!StreamEnvelope {
    var index: usize = 0;
    const stream_id = try qpack.decodeVarInt(bytes, &index);
    const payload_len: usize = @intCast(try qpack.decodeVarInt(bytes, &index));
    if (index + payload_len != bytes.len) {
        return error.InvalidStreamEnvelope;
    }

    return .{
        .stream_id = stream_id,
        .payload = try allocator.dupe(u8, bytes[index..]),
    };
}

/// Sends one datagram on a connected UDP socket.
fn sendConnected(socket: std.posix.socket_t, bytes: []const u8) !usize {
    if (builtin.os.tag == .windows) {
        switch (std.os.windows.ws2_32.send(
            socket,
            bytes.ptr,
            @intCast(bytes.len),
            0,
        )) {
            std.os.windows.ws2_32.SOCKET_ERROR => switch (std.os.windows.ws2_32.WSAGetLastError()) {
                .WSAECONNRESET => return error.ConnectionResetByPeer,
                .WSAEMSGSIZE => return error.MessageTooBig,
                .WSAENETUNREACH, .WSAEHOSTUNREACH => return error.NetworkUnreachable,
                .WSAEWOULDBLOCK => return error.WouldBlock,
                else => |err| return std.os.windows.unexpectedWSAError(err),
            },
            else => |written| return @intCast(written),
        }
    }

    return std.posix.send(socket, bytes, 0);
}

/// Receives one datagram on a connected UDP socket.
fn recvConnected(socket: std.posix.socket_t, buffer: []u8) !usize {
    if (builtin.os.tag == .windows) {
        switch (std.os.windows.ws2_32.recv(
            socket,
            buffer.ptr,
            @intCast(buffer.len),
            0,
        )) {
            std.os.windows.ws2_32.SOCKET_ERROR => switch (std.os.windows.ws2_32.WSAGetLastError()) {
                .WSAECONNRESET => return error.ConnectionResetByPeer,
                .WSAEMSGSIZE => return error.MessageTooBig,
                .WSAENETDOWN => return error.NetworkSubsystemFailed,
                .WSAENOTCONN => return error.SocketNotConnected,
                .WSAEWOULDBLOCK => return error.WouldBlock,
                .WSAETIMEDOUT => return error.ConnectionTimedOut,
                else => |err| return std.os.windows.unexpectedWSAError(err),
            },
            else => |read_len| return @intCast(read_len),
        }
    }

    return std.posix.recv(socket, buffer, 0);
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
