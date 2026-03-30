//! Transport-neutral WebSocket session metadata and message semantics.

const std = @import("std");
const types = @import("../types.zig");
const frame = @import("frame.zig");

/// Protocol-specific handshake mode used by one WebSocket session.
pub const TransportKind = enum {
    /// HTTP/1.1 upgrade handshake.
    http1_upgrade,
    /// HTTP/2 extended CONNECT handshake.
    http2_connect,
    /// HTTP/3 extended CONNECT handshake.
    http3_connect,
};

/// Message kind surfaced by the first-party session API.
pub const MessageKind = enum {
    /// UTF-8 text message.
    text,
    /// Binary message.
    binary,
};

/// One first-party WebSocket message.
pub const Message = struct {
    /// Message kind.
    kind: MessageKind,
    /// Message bytes.
    bytes: []const u8,
};

/// Lifecycle state for a session placeholder.
pub const SessionState = enum {
    /// Handshake or session admission is in progress.
    opening,
    /// Session is open for bidirectional messages.
    open,
    /// Session is closing but not finalized.
    closing,
    /// Session is fully closed.
    closed,
};

/// Typed capability entry for one WebSocket protocol pairing.
pub const Capability = struct {
    /// Negotiated protocol being classified.
    protocol: types.NegotiatedProtocol,
    /// Protocol-specific handshake mode.
    transport: TransportKind,
    /// Capability classification for the protocol pairing.
    support: types.FeatureSupportLevel,
    /// Optional diagnostic note for the capability.
    notes: ?[]const u8,
};

/// Typed metadata attached to one first-party session.
pub const SessionMetadata = struct {
    /// Negotiated protocol for the session.
    protocol: types.NegotiatedProtocol,
    /// Protocol-specific handshake mode.
    transport: TransportKind,
    /// Capability classification for the session.
    support: types.FeatureSupportLevel,
};

/// Transport-neutral first-party WebSocket session placeholder.
pub const Session = struct {
    /// Stable metadata for the session.
    metadata: SessionMetadata,
    /// Current lifecycle state.
    state: SessionState,
    /// Last close reason, when one was recorded.
    close_reason: ?frame.CloseReason,

    /// Initializes a session in the opening state.
    pub fn init(metadata: SessionMetadata) Session {
        return .{
            .metadata = metadata,
            .state = .opening,
            .close_reason = null,
        };
    }

    /// Marks the session as open.
    pub fn markOpen(self: *Session) void {
        self.state = .open;
    }

    /// Starts a structured close transition.
    pub fn startClose(self: *Session, reason: frame.CloseReason) void {
        self.state = .closing;
        self.close_reason = reason;
    }

    /// Finalizes a structured close transition.
    pub fn markClosed(self: *Session) void {
        self.state = .closed;
    }
};

/// Re-exported close-reason type for session APIs.
pub const CloseReason = frame.CloseReason;

test "session lifecycle transitions preserve close metadata" {
    var session = Session.init(.{
        .protocol = .h2,
        .transport = .http2_connect,
        .support = .supported,
    });

    try std.testing.expectEqual(SessionState.opening, session.state);
    session.markOpen();
    try std.testing.expectEqual(SessionState.open, session.state);

    session.startClose(.{
        .code = .normal_closure,
        .description = "finished",
    });
    try std.testing.expectEqual(SessionState.closing, session.state);
    try std.testing.expectEqual(frame.CloseCode.normal_closure, session.close_reason.?.code);

    session.markClosed();
    try std.testing.expectEqual(SessionState.closed, session.state);
}

test "capability keeps typed protocol metadata" {
    const capability = Capability{
        .protocol = .http_1_1,
        .transport = .http1_upgrade,
        .support = .supported,
        .notes = null,
    };

    try std.testing.expectEqual(types.NegotiatedProtocol.http_1_1, capability.protocol);
    try std.testing.expectEqual(types.FeatureSupportLevel.supported, capability.support);
}
