//! Server-owned WebSocket endpoint registration and handshake helpers.

const std = @import("std");
const core = @import("../types.zig");
const websocket = @import("websocket.zig");
const frame = @import("frame.zig");
const server_types = @import("../server/types.zig");

const default_supported_protocols = [_]core.NegotiatedProtocol{ .http_1_1, .h2, .h3 };

/// Callback invoked after a server-side WebSocket handshake is accepted.
pub const Handler = *const fn (
    ctx: ?*anyopaque,
    session: *Session,
    request: *server_types.ServerRequest,
    writer: *server_types.ServerResponseWriter,
) anyerror!void;

/// Protocol-aware handshake rules for one server endpoint.
pub const HandshakePolicy = struct {
    /// Whether the HTTP/1.1 path requires the `Upgrade: websocket` header.
    require_http1_upgrade: bool,
    /// Whether the HTTP/2 and HTTP/3 paths may use extended CONNECT semantics.
    allow_extended_connect: bool,

    /// Returns the default handshake policy for the first-party server surface.
    pub fn default() HandshakePolicy {
        return .{
            .require_http1_upgrade = true,
            .allow_extended_connect = true,
        };
    }
};

/// Message-size limits applied to one server endpoint.
pub const MessageLimits = struct {
    /// Maximum accepted message size in bytes.
    max_message_bytes: usize,
    /// Maximum accepted frame size in bytes.
    max_frame_bytes: usize,

    /// Returns the default message limits for local interop coverage.
    pub fn default() MessageLimits {
        return .{
            .max_message_bytes = 64 * 1024,
            .max_frame_bytes = 16 * 1024,
        };
    }
};

/// Close behavior applied when the endpoint finishes normally.
pub const ClosePolicy = struct {
    /// Close code emitted for normal endpoint completion.
    normal_code: frame.CloseCode,
    /// Optional normal-close description.
    normal_description: ?[]const u8,

    /// Returns the default deterministic close policy.
    pub fn default() ClosePolicy {
        return .{
            .normal_code = .normal_closure,
            .normal_description = "normal-server-close",
        };
    }
};

/// Server-owned endpoint registration for the first-party WebSocket surface.
pub const Endpoint = struct {
    /// Stable endpoint name for diagnostics.
    name: []const u8,
    /// Exact request path used for the endpoint.
    path: []const u8,
    /// Supported subprotocols in preference order.
    subprotocols: []const []const u8,
    /// Supported transport protocols for the endpoint.
    supported_protocols: []const core.NegotiatedProtocol,
    /// Handshake rules for the endpoint.
    handshake_policy: HandshakePolicy,
    /// Message and frame limits for the endpoint.
    message_limits: MessageLimits,
    /// Deterministic close behavior for successful sessions.
    close_policy: ClosePolicy,
    /// Endpoint callback executed after the handshake succeeds.
    handler: Handler,
    /// Optional endpoint callback context.
    handler_context: ?*anyopaque,

    /// Returns a basic endpoint registration with default policies.
    pub fn init(name: []const u8, path: []const u8, handler: Handler) Endpoint {
        return .{
            .name = name,
            .path = path,
            .subprotocols = &.{},
            .supported_protocols = &default_supported_protocols,
            .handshake_policy = HandshakePolicy.default(),
            .message_limits = MessageLimits.default(),
            .close_policy = ClosePolicy.default(),
            .handler = handler,
            .handler_context = null,
        };
    }

    /// Returns true when the endpoint supports the negotiated protocol.
    pub fn supportsProtocol(self: Endpoint, protocol: core.NegotiatedProtocol) bool {
        for (self.supported_protocols) |supported| {
            if (supported == protocol) {
                return true;
            }
        }
        return false;
    }

    /// Validates the endpoint definition.
    pub fn validate(self: Endpoint) !void {
        if (self.name.len == 0) {
            return error.InvalidWebSocketEndpoint;
        }
        if (self.path.len == 0 or self.path[0] != '/') {
            return error.InvalidWebSocketEndpoint;
        }
        if (self.supported_protocols.len == 0) {
            return error.InvalidWebSocketEndpoint;
        }
        if (self.message_limits.max_message_bytes == 0 or self.message_limits.max_frame_bytes == 0) {
            return error.InvalidWebSocketEndpoint;
        }
    }
};

/// Server-owned session facade layered over the transport-neutral session state.
pub const Session = struct {
    /// Shared transport-neutral session state.
    transport: websocket.Session,
    /// Endpoint path that accepted the session.
    endpoint_path: []const u8,
    /// Negotiated subprotocol, when one was selected.
    subprotocol: ?[]const u8,

    /// Creates a new server-side session facade in the opening state.
    pub fn init(
        endpoint_path: []const u8,
        protocol: core.NegotiatedProtocol,
        support: core.FeatureSupportLevel,
        subprotocol: ?[]const u8,
    ) Session {
        return .{
            .transport = websocket.Session.init(.{
                .protocol = protocol,
                .transport = transportForProtocol(protocol),
                .support = support,
            }),
            .endpoint_path = endpoint_path,
            .subprotocol = subprotocol,
        };
    }

    /// Marks the session as open.
    pub fn markOpen(self: *Session) void {
        self.transport.markOpen();
    }

    /// Starts a deterministic close transition for the session.
    pub fn startClose(self: *Session, reason: frame.CloseReason) void {
        self.transport.startClose(reason);
    }

    /// Marks the session as fully closed.
    pub fn markClosed(self: *Session) void {
        self.transport.markClosed();
    }
};

/// Returns the transport-neutral handshake kind for one protocol.
pub fn transportForProtocol(protocol: core.NegotiatedProtocol) websocket.TransportKind {
    return switch (protocol) {
        .http_1_1 => .http1_upgrade,
        .h2 => .http2_connect,
        .h3 => .http3_connect,
    };
}

/// Returns true when the request looks like a WebSocket handshake for the endpoint.
pub fn isHandshakeRequest(endpoint: Endpoint, request: *const server_types.ServerRequest) bool {
    if (!endpoint.supportsProtocol(request.negotiated_protocol)) {
        return false;
    }
    if (!std.mem.eql(u8, endpoint.path, request.uri.path)) {
        return false;
    }

    return switch (request.negotiated_protocol) {
        .http_1_1 => request.method == .get and isHttp1UpgradeRequest(endpoint, request),
        .h2, .h3 => isExtendedConnectRequest(endpoint, request),
    };
}

/// Accepts the endpoint handshake, runs the endpoint callback, and closes deterministically.
pub fn dispatchEndpoint(
    endpoint: Endpoint,
    request: *server_types.ServerRequest,
    writer: *server_types.ServerResponseWriter,
) !void {
    try endpoint.validate();

    if (!endpoint.supportsProtocol(request.negotiated_protocol)) {
        try writeHandshakeError(writer, "unsupported_protocol");
        return;
    }
    if (!isHandshakeRequest(endpoint, request)) {
        try writeHandshakeError(writer, "invalid_handshake");
        return;
    }

    const subprotocol = selectSubprotocol(endpoint, request.header("Sec-WebSocket-Protocol"));
    var session = Session.init(endpoint.path, request.negotiated_protocol, .supported, subprotocol);

    switch (request.negotiated_protocol) {
        .http_1_1 => {
            writer.setStatus(.switching_protocols);
            try writer.appendHeader("Connection", "Upgrade");
            try writer.appendHeader("Upgrade", "websocket");
        },
        .h2, .h3 => writer.setStatus(.ok),
    }

    if (subprotocol) |selected_subprotocol| {
        try writer.appendHeader("Sec-WebSocket-Protocol", selected_subprotocol);
    }

    session.markOpen();
    try endpoint.handler(endpoint.handler_context, &session, request, writer);
    if (session.transport.state == .open) {
        session.startClose(.{
            .code = endpoint.close_policy.normal_code,
            .description = endpoint.close_policy.normal_description,
        });
    }
    session.markClosed();
}

/// Returns the endpoint subprotocol selected for the request, when one matches.
pub fn selectSubprotocol(endpoint: Endpoint, requested_header: ?[]const u8) ?[]const u8 {
    const header = requested_header orelse return null;
    var tokens = std.mem.splitScalar(u8, header, ',');
    while (tokens.next()) |token| {
        const trimmed = std.mem.trim(u8, token, " \t");
        for (endpoint.subprotocols) |supported| {
            if (std.ascii.eqlIgnoreCase(trimmed, supported)) {
                return supported;
            }
        }
    }
    return null;
}

/// Returns true when an HTTP/1.1 request satisfies the endpoint upgrade policy.
fn isHttp1UpgradeRequest(endpoint: Endpoint, request: *const server_types.ServerRequest) bool {
    if (!endpoint.handshake_policy.require_http1_upgrade) {
        return true;
    }
    const upgrade = request.header("Upgrade") orelse return false;
    return std.ascii.eqlIgnoreCase(upgrade, "websocket");
}

/// Returns true when an HTTP/2 or HTTP/3 request satisfies the endpoint CONNECT policy.
fn isExtendedConnectRequest(endpoint: Endpoint, request: *const server_types.ServerRequest) bool {
    if (!endpoint.handshake_policy.allow_extended_connect) {
        return false;
    }
    if (request.method == .connect) {
        return true;
    }
    return request.method == .get and request.header("Sec-WebSocket-Key") != null;
}

/// Writes a clear bad-request response for an invalid handshake outcome.
fn writeHandshakeError(
    writer: *server_types.ServerResponseWriter,
    reason: []const u8,
) !void {
    writer.setStatus(.bad_request);
    try writer.appendHeader("Content-Type", "application/json");
    var body_buffer: [128]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buffer, "{{\"error\":\"{s}\"}}", .{reason});
    try writer.writeAll(body);
}

/// No-op endpoint handler used by basic tests and placeholder registrations.
pub fn noopHandler(
    _: ?*anyopaque,
    _: *Session,
    _: *server_types.ServerRequest,
    _: *server_types.ServerResponseWriter,
) !void {}

test "server websocket endpoint validates exact paths and supported protocols" {
    var endpoint = Endpoint.init("chat", "/ws/chat", noopHandler);
    try endpoint.validate();
    try std.testing.expect(endpoint.supportsProtocol(.http_1_1));
    try std.testing.expect(endpoint.supportsProtocol(.h2));
}

test "server websocket session facade preserves deterministic close metadata" {
    var session = Session.init("/ws/chat", .h3, .supported, null);

    try std.testing.expectEqual(websocket.SessionState.opening, session.transport.state);
    session.markOpen();
    try std.testing.expectEqual(websocket.SessionState.open, session.transport.state);

    session.startClose(.{
        .code = .normal_closure,
        .description = "server-close",
    });
    try std.testing.expectEqual(frame.CloseCode.normal_closure, session.transport.close_reason.?.code);
    session.markClosed();
    try std.testing.expectEqual(websocket.SessionState.closed, session.transport.state);
}
