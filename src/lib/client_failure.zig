//! Lightweight client failure classification helpers for hardening coverage.

const types = @import("types.zig");
const connection_h2 = @import("http2/connection_h2.zig");

/// Re-exported isolation boundary for client-visible failures.
pub const FailureIsolationScope = types.FailureIsolationScope;

/// Explicit client failure category used by the hardening matrix.
pub const ClientFailureCategory = enum {
    /// Secure negotiation failed before HTTP routing.
    negotiation,
    /// One multiplexed stream failed while the connection remained usable.
    stream,
    /// One shared connection entered a draining or terminal state.
    connection,
    /// One transport session failed at the HTTP/3 runtime layer.
    session,
    /// One WebSocket attempt failed before or during session establishment.
    websocket,
};

/// Explicit client-visible failure classification for hardening diagnostics.
pub const ClientFailureClassification = struct {
    /// Isolation boundary preserved by the failure.
    scope: FailureIsolationScope,
    /// Typed client failure category.
    category: ClientFailureCategory,
    /// Negotiated protocol associated with the failure, when known.
    protocol: ?types.NegotiatedProtocol,
    /// Optional explanatory note for the classification.
    notes: ?[]const u8,
};

/// Classifies one shared HTTP/2 runtime snapshot into an explicit failure outcome.
pub fn classifyH2Snapshot(snapshot: connection_h2.Snapshot) ?ClientFailureClassification {
    const scope = snapshot.last_failure_scope orelse return null;
    return .{
        .scope = scope,
        .category = switch (scope) {
            .stream => .stream,
            .connection => .connection,
            .request => .connection,
            .session => .session,
        },
        .protocol = .h2,
        .notes = snapshot.last_failure_note,
    };
}

/// Classifies one HTTP/3 runtime error into an explicit failure outcome.
pub fn classifyHttp3RuntimeError(err: anyerror) ClientFailureClassification {
    return switch (err) {
        error.InvalidScheme,
        error.BodyReadFailed,
        error.RequestBodyTooLarge,
        => .{
            .scope = .request,
            .category = .session,
            .protocol = .h3,
            .notes = "request could not be prepared for the runtime session",
        },
        error.InvalidStreamEnvelope,
        error.InvalidStatus,
        error.MissingStatus,
        => .{
            .scope = .stream,
            .category = .stream,
            .protocol = .h3,
            .notes = "response decoding failed for one request stream",
        },
        error.InvalidControlStreamState,
        => .{
            .scope = .session,
            .category = .session,
            .protocol = .h3,
            .notes = "connection-scoped control or QPACK state was invalid",
        },
        error.ConnectionResetByPeer,
        error.ConnectionTimedOut,
        error.NetworkSubsystemFailed,
        error.NetworkUnreachable,
        error.SocketNotConnected,
        error.WouldBlock,
        => .{
            .scope = .session,
            .category = .session,
            .protocol = .h3,
            .notes = "UDP or QUIC session transport failed",
        },
        else => .{
            .scope = .session,
            .category = .session,
            .protocol = .h3,
            .notes = "session-level fallback classification",
        },
    };
}
