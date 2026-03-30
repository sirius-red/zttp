//! Client-owned WebSocket session helpers layered over the transport-neutral model.

const std = @import("std");
const types = @import("../types.zig");
const websocket = @import("websocket.zig");
const frame = @import("frame.zig");

/// Error set returned by first-party client WebSocket helpers.
pub const Error = error{
    /// The requested endpoint path is invalid.
    InvalidPath,
    /// The requested protocol is not supported by the client helper.
    UnsupportedProtocol,
};

/// Re-exported message-kind type.
pub const MessageKind = websocket.MessageKind;
/// Re-exported message type.
pub const Message = websocket.Message;
/// Re-exported transport-kind type.
pub const TransportKind = websocket.TransportKind;
/// Re-exported capability type.
pub const Capability = websocket.Capability;
/// Re-exported session-state type.
pub const SessionState = websocket.SessionState;
/// Re-exported session metadata type.
pub const SessionMetadata = websocket.SessionMetadata;
/// Re-exported close-code type.
pub const CloseCode = frame.CloseCode;
/// Re-exported close-reason type.
pub const CloseReason = frame.CloseReason;

/// Client-owned endpoint configuration for one WebSocket dial.
pub const Endpoint = struct {
    /// Exact endpoint path to dial.
    path: []const u8,
    /// Optional requested subprotocol.
    subprotocol: ?[]const u8,
};

/// Client-owned dial options for one WebSocket session.
pub const DialOptions = struct {
    /// Optional requested subprotocol.
    subprotocol: ?[]const u8,
    /// Capability classification to attach to the session.
    support: types.FeatureSupportLevel,

    /// Returns the default dial options.
    pub fn default() DialOptions {
        return .{
            .subprotocol = null,
            .support = .supported,
        };
    }
};

/// Client-owned unified WebSocket session surface.
pub const Session = struct {
    /// Stable metadata for the session.
    metadata: SessionMetadata,
    /// Current lifecycle state.
    state: SessionState,
    /// Last close reason, when one was recorded.
    close_reason: ?CloseReason,
    /// Exact endpoint path for the session.
    endpoint_path: []const u8,
    /// Negotiated subprotocol when one exists.
    subprotocol: ?[]const u8,

    /// Initializes a session in the opening state.
    pub fn init(metadata: SessionMetadata) Session {
        return .{
            .metadata = metadata,
            .state = .opening,
            .close_reason = null,
            .endpoint_path = "/",
            .subprotocol = null,
        };
    }

    /// Initializes a session for the provided endpoint and options.
    pub fn initForEndpoint(
        endpoint: Endpoint,
        protocol: types.NegotiatedProtocol,
        options: DialOptions,
    ) Error!Session {
        try validatePath(endpoint.path);
        return .{
            .metadata = .{
                .protocol = protocol,
                .transport = transportForProtocol(protocol),
                .support = options.support,
            },
            .state = .opening,
            .close_reason = null,
            .endpoint_path = endpoint.path,
            .subprotocol = options.subprotocol orelse endpoint.subprotocol,
        };
    }

    /// Marks the session as open.
    pub fn markOpen(self: *Session) void {
        self.state = .open;
    }

    /// Starts a structured close transition.
    pub fn startClose(self: *Session, reason: CloseReason) void {
        self.state = .closing;
        self.close_reason = reason;
    }

    /// Finalizes a structured close transition.
    pub fn markClosed(self: *Session) void {
        self.state = .closed;
    }
};

/// Returns the transport kind required by one negotiated protocol.
pub fn transportForProtocol(protocol: types.NegotiatedProtocol) websocket.TransportKind {
    return switch (protocol) {
        .http_1_1 => .http1_upgrade,
        .h2 => .http2_connect,
        .h3 => .http3_connect,
    };
}

/// Creates a client-owned WebSocket session for the provided endpoint.
pub fn connect(
    endpoint: Endpoint,
    protocol: types.NegotiatedProtocol,
    options: DialOptions,
) Error!Session {
    return Session.initForEndpoint(endpoint, protocol, options);
}

/// Validates that the endpoint path is suitable for WebSocket dialing.
pub fn validatePath(path: []const u8) Error!void {
    if (path.len == 0 or path[0] != '/') {
        return error.InvalidPath;
    }
}

test "client websocket session binds endpoint path and protocol transport" {
    var session = try connect(.{
        .path = "/ws/chat",
        .subprotocol = "chat.v1",
    }, .h2, .{
        .subprotocol = null,
        .support = .supported,
    });

    try std.testing.expectEqualStrings("/ws/chat", session.endpoint_path);
    try std.testing.expectEqualStrings("chat.v1", session.subprotocol.?);
    try std.testing.expectEqual(websocket.TransportKind.http2_connect, session.metadata.transport);

    session.markOpen();
    try std.testing.expectEqual(websocket.SessionState.open, session.state);
}

test "client websocket helper rejects invalid endpoint paths" {
    try std.testing.expectError(error.InvalidPath, connect(.{
        .path = "ws/chat",
        .subprotocol = null,
    }, .http_1_1, DialOptions.default()));
}
