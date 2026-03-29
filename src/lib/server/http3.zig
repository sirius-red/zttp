//! HTTP/3 UDP runtime bridge for the canonical server surfaces.

const builtin = @import("builtin");
const std = @import("std");
const core = @import("../types.zig");
const h3 = @import("../http3/http3.zig");
const h3_qpack = @import("../http3/qpack.zig");
const h3_quic = @import("../http3/quic.zig");
const h3_server = @import("../http3/server.zig");
const server_types = @import("types.zig");

/// Error set returned by the HTTP/3 runtime bridge.
pub const Error = anyerror;

/// One tracked HTTP/3 listener session keyed by the peer connection identifier.
pub const ListenerSession = struct {
    /// QUIC transport state for the peer.
    connection: h3_quic.Connection,
    /// Connection-scoped QPACK state retained across requests.
    qpack_state: h3_qpack.PeerState,
    /// HTTP/3 control-plane state retained across requests.
    control_plane: h3.ControlPlaneState,
    /// Last peer address observed for the session.
    peer: std.net.Address,

    /// Releases the retained session state.
    pub fn deinit(self: *ListenerSession) void {
        self.connection.deinit();
        self.qpack_state.deinit();
        self.* = undefined;
    }
};

/// One remote-connection-id to session mapping retained by the listener.
const SessionRecord = struct {
    /// Peer connection identifier used to match future datagrams.
    remote_connection_id: h3_quic.ConnectionId,
    /// Session state retained for the peer.
    session: ListenerSession,
};

/// Buffer-backed response writer context used by the HTTP/3 bridge.
const ResponseBuffer = struct {
    /// Allocator used for buffered body bytes.
    allocator: std.mem.Allocator,
    /// Buffered response body bytes.
    body: std.ArrayListUnmanaged(u8),

    /// Returns an empty response buffer.
    fn init(allocator: std.mem.Allocator) ResponseBuffer {
        return .{
            .allocator = allocator,
            .body = .{},
        };
    }

    /// Releases buffered response bytes.
    fn deinit(self: *ResponseBuffer) void {
        self.body.deinit(self.allocator);
        self.* = undefined;
    }

    /// Header emission is buffered, so begin is a no-op.
    fn begin(_: ?*anyopaque, _: *server_types.ServerResponseWriter) anyerror!void {}

    /// Writes one buffered body chunk.
    fn writeAll(ctx: ?*anyopaque, bytes: []const u8) anyerror!void {
        const self: *ResponseBuffer = @ptrCast(@alignCast(ctx.?));
        try self.body.appendSlice(self.allocator, bytes);
    }

    /// Response finishing is buffered, so finish is a no-op.
    fn finish(_: ?*anyopaque, _: *server_types.ServerResponseWriter) anyerror!void {}
};

/// Owned body reader state for request payloads bridged into `ServerRequest`.
const RequestBodyState = struct {
    /// Allocator used to destroy the body state.
    allocator: std.mem.Allocator,
    /// Owned request body bytes.
    bytes: []u8,
    /// Current read offset.
    offset: usize,

    /// Creates a request body state by copying the provided bytes.
    fn init(allocator: std.mem.Allocator, bytes: []const u8) !*RequestBodyState {
        const state = try allocator.create(RequestBodyState);
        errdefer allocator.destroy(state);
        state.* = .{
            .allocator = allocator,
            .bytes = try allocator.dupe(u8, bytes),
            .offset = 0,
        };
        return state;
    }

    /// Reads the next body chunk into `dest`.
    fn read(ctx: ?*anyopaque, dest: []u8) anyerror!usize {
        const self: *RequestBodyState = @ptrCast(@alignCast(ctx.?));
        if (self.offset >= self.bytes.len) {
            return 0;
        }

        const remaining = self.bytes.len - self.offset;
        const to_copy = @min(remaining, dest.len);
        std.mem.copyForwards(u8, dest[0..to_copy], self.bytes[self.offset .. self.offset + to_copy]);
        self.offset += to_copy;
        return to_copy;
    }

    /// Releases the copied request body.
    fn close(ctx: ?*anyopaque) void {
        const self: *RequestBodyState = @ptrCast(@alignCast(ctx.?));
        self.allocator.free(self.bytes);
        self.allocator.destroy(self);
    }
};

/// One bound HTTP/3 UDP listener owned by the canonical server runtime.
pub const Runtime = struct {
    /// Allocator used for session and response state.
    allocator: std.mem.Allocator,
    /// Canonical server configuration that owns this runtime.
    config: server_types.ServerConfig,
    /// Bound UDP socket handle.
    socket: ?std.posix.socket_t,
    /// Bound listen address.
    listen_address: std.net.Address,
    /// Optional background serve thread.
    thread: ?std.Thread,
    /// Stop flag observed by the serve loop.
    stop_requested: std.atomic.Value(bool),
    /// Listener-owned session table.
    sessions: std.ArrayListUnmanaged(SessionRecord),
    /// Stable destination connection identifier for new client sessions.
    local_connection_id: h3_quic.ConnectionId,

    /// Binds a UDP listener for the configured HTTP/3 runtime.
    pub fn init(allocator: std.mem.Allocator, config: server_types.ServerConfig) Error!Runtime {
        const http3_config = config.http3 orelse return error.InvalidHttp3Configuration;
        try http3_config.validate();

        var listen_address = try std.net.Address.parseIp(http3_config.listen_host, http3_config.port.toInt());
        const socket = try std.posix.socket(
            listen_address.any.family,
            std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC,
            std.posix.IPPROTO.UDP,
        );
        errdefer std.posix.close(socket);

        try std.posix.bind(socket, &listen_address.any, listen_address.getOsSockLen());
        var bound_len = listen_address.getOsSockLen();
        try std.posix.getsockname(socket, &listen_address.any, &bound_len);

        return .{
            .allocator = allocator,
            .config = config,
            .socket = socket,
            .listen_address = listen_address,
            .thread = null,
            .stop_requested = std.atomic.Value(bool).init(false),
            .sessions = .{},
            .local_connection_id = "server01".*,
        };
    }

    /// Starts the UDP receive loop in a background thread.
    pub fn start(self: *Runtime) Error!void {
        if (self.thread != null) {
            return error.AlreadyStarted;
        }
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    /// Runs the UDP receive loop on the current thread until stopped.
    pub fn serve(self: *Runtime) Error!void {
        var buffer: [64 * 1024]u8 = undefined;
        while (!self.stop_requested.load(.seq_cst)) {
            var peer: std.net.Address = undefined;
            const read_len = recvDatagram(
                self.socket.?,
                buffer[0..],
                &peer,
            ) catch |err| switch (err) {
                error.ConnectionResetByPeer => continue,
                else => return err,
            };
            if (self.stop_requested.load(.seq_cst)) {
                return;
            }
            if (read_len == 0) {
                continue;
            }
            try self.handleDatagram(peer, buffer[0..read_len]);
        }
    }

    /// Returns the bound UDP port.
    pub fn port(self: *const Runtime) u16 {
        return self.listen_address.getPort();
    }

    /// Requests the receive loop to stop and wakes the bound socket.
    pub fn requestStop(self: *Runtime) void {
        if (self.stop_requested.swap(true, .seq_cst)) {
            return;
        }

        const wake_socket = std.posix.socket(
            self.listen_address.any.family,
            std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC,
            std.posix.IPPROTO.UDP,
        ) catch return;
        defer std.posix.close(wake_socket);
        _ = sendDatagramTo(
            wake_socket,
            "wake",
            self.listen_address,
        ) catch {};
    }

    /// Stops the runtime, joins the background thread, and releases session state.
    pub fn deinit(self: *Runtime) void {
        self.requestStop();
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        if (self.socket) |socket| {
            std.posix.close(socket);
            self.socket = null;
        }
        for (self.sessions.items) |*record| {
            record.session.deinit();
        }
        self.sessions.deinit(self.allocator);
        self.* = undefined;
    }

    /// Background serve-loop entrypoint.
    fn run(self: *Runtime) void {
        self.serve() catch {};
    }

    /// Handles one inbound datagram and sends one protected response.
    fn handleDatagram(self: *Runtime, peer: std.net.Address, packet_bytes: []const u8) Error!void {
        const connection_ids = parseConnectionIds(packet_bytes) orelse return;
        if (!std.mem.eql(u8, connection_ids.destination[0..], self.local_connection_id[0..])) {
            return;
        }

        const session = try self.sessionForPeer(connection_ids.source, peer);
        try applyNegotiatedQpackState(session);
        var packet = try session.connection.unprotectPacket(self.allocator, packet_bytes);
        defer packet.deinit(self.allocator);
        if (packet.delivery_state == .duplicate) {
            return;
        }

        var request = try h3_server.decodeRequestWithPeerState(
            self.allocator,
            &session.qpack_state,
            session.control_plane.peer_settings.?.qpack_max_table_capacity,
            session.control_plane.peer_settings.?.qpack_blocked_streams,
            packet.payload,
        );
        defer request.deinit(self.allocator);

        var server_request = try self.buildServerRequest(peer, request);
        defer server_request.deinit();

        var response_buffer = ResponseBuffer.init(self.allocator);
        defer response_buffer.deinit();

        var writer = server_types.ServerResponseWriter.init(
            self.allocator,
            &response_buffer,
            ResponseBuffer.writeAll,
            ResponseBuffer.begin,
            ResponseBuffer.finish,
            null,
        );
        defer writer.deinit();

        try dispatchRequest(self.config, &server_request, &writer);
        try writer.finish();

        const payload = try encodeWriterResponse(
            self.allocator,
            &session.qpack_state,
            session.control_plane.peer_settings.?.qpack_max_table_capacity,
            session.control_plane.peer_settings.?.qpack_blocked_streams,
            &writer,
            response_buffer.body.items,
        );
        defer self.allocator.free(payload);

        const response_packet = try session.connection.protectPacket(
            self.allocator,
            .application,
            payload,
        );
        defer self.allocator.free(response_packet);

        _ = try sendDatagramTo(
            self.socket.?,
            response_packet,
            peer,
        );
        _ = session.connection.acknowledge(.application, packet.number);
    }

    /// Returns the retained session for the peer connection identifier.
    fn sessionForPeer(
        self: *Runtime,
        remote_connection_id: h3_quic.ConnectionId,
        peer: std.net.Address,
    ) Error!*ListenerSession {
        for (self.sessions.items) |*record| {
            if (std.mem.eql(u8, record.remote_connection_id[0..], remote_connection_id[0..])) {
                record.session.peer = peer;
                return &record.session;
            }
        }

        const http3_config = self.config.http3.?;
        if (self.sessions.items.len >= http3_config.session_limits.max_sessions.toInt()) {
            return error.SessionLimitExceeded;
        }

        var connection = h3_quic.Connection.init(self.allocator, self.local_connection_id, remote_connection_id);
        connection.beginHandshake();
        connection.establish();
        const control_stream_id = try connection.openStream(.unidirectional);
        const qpack_encoder_stream_id = try connection.openStream(.unidirectional);
        const qpack_decoder_stream_id = try connection.openStream(.unidirectional);
        var qpack_state = h3_qpack.PeerState.init(
            self.allocator,
            http3_config.qpack_limits.dynamic_table_capacity.toInt(),
            http3_config.qpack_limits.blocked_streams.toInt(),
        );
        qpack_state.encoder_stream.stream_id = qpack_encoder_stream_id;
        qpack_state.decoder_stream.stream_id = qpack_decoder_stream_id;

        try self.sessions.append(self.allocator, .{
            .remote_connection_id = remote_connection_id,
            .session = .{
                .connection = connection,
                .qpack_state = qpack_state,
                .control_plane = .{
                    .local_control_stream_id = control_stream_id,
                    .peer_control_stream_id = 3,
                    .local_settings = .{
                        .qpack_max_table_capacity = http3_config.qpack_limits.dynamic_table_capacity.toInt(),
                        .qpack_blocked_streams = http3_config.qpack_limits.blocked_streams.toInt(),
                    },
                    .peer_settings = .{
                        .qpack_max_table_capacity = http3_config.qpack_limits.dynamic_table_capacity.toInt(),
                        .qpack_blocked_streams = http3_config.qpack_limits.blocked_streams.toInt(),
                    },
                    .critical_stream_status = .ready,
                },
                .peer = peer,
            },
        });
        return &self.sessions.items[self.sessions.items.len - 1].session;
    }

    /// Builds a canonical `ServerRequest` from one decoded HTTP/3 request.
    fn buildServerRequest(
        self: *Runtime,
        peer: std.net.Address,
        request: h3_server.DecodedRequest,
    ) Error!server_types.ServerRequest {
        var headers = core.Headers.init(self.allocator);
        errdefer headers.deinit();

        try headers.append("Host", self.config.http3.?.listen_host);
        var iterator = request.headers.iterator();
        while (iterator.next()) |header| {
            try headers.append(header.name, header.value);
        }
        if (request.cookie_header) |cookie_header| {
            if (headers.get("cookie") != null) {
                // The decoded header collection already preserved the cookie.
            } else {
            try headers.append("Cookie", cookie_header);
            }
        }

        const owned_host = try self.allocator.dupe(u8, self.config.http3.?.listen_host);
        errdefer self.allocator.free(owned_host);
        const owned_path = try self.allocator.dupe(u8, request.path);
        errdefer self.allocator.free(owned_path);
        const owned_query = if (request.query) |query|
            try self.allocator.dupe(u8, query)
        else
            null;
        errdefer if (owned_query) |query| self.allocator.free(query);

        const body = if (request.body.len > 0) blk: {
            const state = try RequestBodyState.init(self.allocator, request.body);
            break :blk core.BodyReader{
                .ctx = state,
                .read_fn = RequestBodyState.read,
                .close_fn = RequestBodyState.close,
            };
        } else null;

        const identity_token = if (self.config.tls) |tls| tls.identity() else null;
        return .{
            .allocator = self.allocator,
            .method = request.method,
            .version = .http_3,
            .uri = core.Uri.init(
                .https,
                owned_host,
                core.Port.init(self.port()),
                owned_path,
                owned_query,
                null,
            ),
            .headers = headers,
            .body = body,
            .peer = peer,
            .negotiated_protocol = .h3,
            .secure = true,
            .identity_token = identity_token,
            .session = .{
                .peer = peer,
                .identity_token = identity_token,
                .negotiated_protocol = .h3,
                .request_version = .http_3,
                .secure = true,
                .alive = true,
            },
            .owned_host = owned_host,
            .owned_path = owned_path,
            .owned_query = owned_query,
        };
    }
};

/// Encodes a buffered writer state into HTTP/3 HEADERS and DATA frames.
fn encodeWriterResponse(
    allocator: std.mem.Allocator,
    qpack_state: *h3_qpack.PeerState,
    qpack_max_table_capacity: usize,
    qpack_blocked_streams: usize,
    writer: *const server_types.ServerResponseWriter,
    body: []const u8,
) Error![]u8 {
    var headers = std.ArrayListUnmanaged(h3_qpack.HeaderField){};
    defer {
        for (headers.items) |*header| {
            header.deinit(allocator);
        }
        headers.deinit(allocator);
    }

    const status_value = try std.fmt.allocPrint(allocator, "{d}", .{writer.status.code()});
    defer allocator.free(status_value);
    try appendOwnedHeader(allocator, &headers, ":status", status_value);

    var iterator = writer.headers.iterator();
    while (iterator.next()) |header| {
        try appendOwnedHeader(allocator, &headers, header.name, header.value);
    }

    qpack_state.configureLimits(qpack_max_table_capacity, qpack_blocked_streams);
    const header_block = try qpack_state.encodeHeaders(headers.items);
    defer allocator.free(header_block);
    const headers_frame = try h3_qpack.encodeFrame(allocator, .headers, header_block);
    defer allocator.free(headers_frame);

    var encoded = std.ArrayListUnmanaged(u8){};
    errdefer encoded.deinit(allocator);
    try encoded.appendSlice(allocator, headers_frame);
    if (body.len > 0) {
        const data_frame = try h3_qpack.encodeFrame(allocator, .data, body);
        defer allocator.free(data_frame);
        try encoded.appendSlice(allocator, data_frame);
    }
    return encoded.toOwnedSlice(allocator);
}

/// Appends one owned header field to the provided list.
fn appendOwnedHeader(
    allocator: std.mem.Allocator,
    headers: *std.ArrayListUnmanaged(h3_qpack.HeaderField),
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

/// Applies the negotiated SETTINGS values to the retained QPACK state.
fn applyNegotiatedQpackState(session: *ListenerSession) Error!void {
    const peer_settings = session.control_plane.peer_settings orelse return error.InvalidHttp3Configuration;
    if (session.qpack_state.encoder_stream.stream_id == null) {
        return error.InvalidHttp3Configuration;
    }
    if (session.qpack_state.decoder_stream.stream_id == null) {
        return error.InvalidHttp3Configuration;
    }
    session.qpack_state.configureLimits(
        peer_settings.qpack_max_table_capacity,
        peer_settings.qpack_blocked_streams,
    );
}

/// Returns the connection identifiers carried by one protected QUIC packet.
fn parseConnectionIds(
    packet_bytes: []const u8,
) ?struct {
    destination: h3_quic.ConnectionId,
    source: h3_quic.ConnectionId,
} {
    if (packet_bytes.len < 26) {
        return null;
    }

    var destination: h3_quic.ConnectionId = undefined;
    var source: h3_quic.ConnectionId = undefined;
    std.mem.copyForwards(u8, destination[0..], packet_bytes[10..18]);
    std.mem.copyForwards(u8, source[0..], packet_bytes[18..26]);
    return .{
        .destination = destination,
        .source = source,
    };
}

/// Dispatches one HTTP/3 request through middleware, routes, or the fallback handler.
fn dispatchRequest(
    config: server_types.ServerConfig,
    request: *server_types.ServerRequest,
    writer: *server_types.ServerResponseWriter,
) !void {
    if (config.router) |router| {
        for (router.middleware) |middleware| {
            const decision = try middleware.handler(middleware.context, request, writer);
            if (decision == .handled) {
                return;
            }
        }

        if (findMatchingRoute(router.routes, request.method, request.uri.path)) |route| {
            try route.handler(route.handler_context, request, writer);
            return;
        }

        if (router.fallback) |fallback| {
            try fallback.handler(fallback.handler_context, request, writer);
            return;
        }

        try writeDefaultNotFound(writer);
        return;
    }

    try config.handler(config.handler_context, request, writer);
}

/// Returns the first exact route match for the provided method and path.
fn findMatchingRoute(
    routes: []const server_types.Route,
    method: core.Method,
    path: []const u8,
) ?server_types.Route {
    for (routes) |route| {
        if (!std.ascii.eqlIgnoreCase(route.method.asBytes(), method.asBytes())) {
            continue;
        }
        if (!std.mem.eql(u8, route.path, path)) {
            continue;
        }
        return route;
    }
    return null;
}

/// Writes the default JSON `404 Not Found` response for an unmapped request.
fn writeDefaultNotFound(writer: *server_types.ServerResponseWriter) !void {
    writer.setStatus(.not_found);
    try writer.appendHeader("Content-Type", "application/json");
    try writer.writeAll("{\"error\":\"not_found\"}");
}

/// Sends one datagram to the provided peer address.
fn sendDatagramTo(
    socket: std.posix.socket_t,
    bytes: []const u8,
    peer: std.net.Address,
) !usize {
    if (builtin.os.tag == .windows) {
        switch (std.os.windows.ws2_32.sendto(
            socket,
            bytes.ptr,
            @intCast(bytes.len),
            0,
            &peer.any,
            @intCast(peer.getOsSockLen()),
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

    return std.posix.sendto(
        socket,
        bytes,
        0,
        &peer.any,
        peer.getOsSockLen(),
    );
}

/// Receives one datagram and writes the peer address into `peer`.
fn recvDatagram(
    socket: std.posix.socket_t,
    buffer: []u8,
    peer: *std.net.Address,
) !usize {
    if (builtin.os.tag == .windows) {
        var peer_len: i32 = @sizeOf(std.net.Address);
        switch (std.os.windows.ws2_32.recvfrom(
            socket,
            buffer.ptr,
            @intCast(buffer.len),
            0,
            &peer.any,
            &peer_len,
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

    var peer_len: std.posix.socklen_t = @sizeOf(std.net.Address);
    return std.posix.recvfrom(
        socket,
        buffer,
        0,
        &peer.any,
        &peer_len,
    );
}
