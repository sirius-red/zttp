//! Typed HTTP/3 control-plane, exchange, and validation state.

const std = @import("std");

/// Whether HTTP/3 support is enabled for this build.
pub const enabled = true;

/// Validation category surfaced by HTTP/3 runtime and interoperability checks.
pub const ValidationCategory = enum {
    /// Listener startup or bind failed.
    startup,
    /// Datagram transport or packet protection failed.
    transport,
    /// Session establishment or stream admission failed.
    session,
    /// QPACK or control-stream validation failed.
    compression,
    /// Route dispatch failed after transport setup succeeded.
    route,
};

/// Validation status for one HTTP/3 outcome.
pub const ValidationStatus = enum {
    /// The checked operation succeeded.
    ok,
    /// The checked operation failed predictably.
    failed,
};

/// Settings exchanged on the HTTP/3 control stream.
pub const Settings = struct {
    /// Maximum bytes admitted for one header section.
    max_field_section_size: usize = 64 * 1024,
    /// Maximum QPACK dynamic-table capacity.
    qpack_max_table_capacity: usize = 4 * 1024,
    /// Maximum blocked streams admitted by QPACK.
    qpack_blocked_streams: usize = 8,
};

/// Whether critical control streams have been established correctly.
pub const CriticalStreamStatus = enum {
    /// Control stream state has not been established yet.
    pending,
    /// Required streams are established and valid.
    ready,
    /// Control stream state is invalid for the connection.
    failed,
};

/// HTTP/3 control-plane state for one QUIC session.
pub const ControlPlaneState = struct {
    /// Local control stream identifier, once created.
    local_control_stream_id: ?u64 = null,
    /// Peer control stream identifier, once observed.
    peer_control_stream_id: ?u64 = null,
    /// Local SETTINGS values sent on the control stream.
    local_settings: Settings = .{},
    /// Peer SETTINGS values received from the control stream.
    peer_settings: ?Settings = null,
    /// Whether critical stream validation has completed.
    critical_stream_status: CriticalStreamStatus = .pending,
};

/// Lifecycle state for one HTTP/3 stream exchange.
pub const StreamExchangeState = enum {
    /// No request bytes have been admitted for the stream yet.
    idle,
    /// Header processing is active for the stream.
    headers_open,
    /// Body bytes are being streamed for the exchange.
    body_streaming,
    /// The exchange completed successfully.
    completed,
    /// The exchange was reset or failed.
    reset,
};

/// One HTTP/3 request or response exchange tracked on a QUIC stream.
pub const StreamExchange = struct {
    /// Stable QUIC stream identifier.
    stream_id: u64,
    /// Current lifecycle state.
    state: StreamExchangeState = .idle,
    /// Number of request headers observed on the exchange.
    request_header_count: usize = 0,
    /// Number of response headers emitted on the exchange.
    response_header_count: usize = 0,
    /// Validation category recorded when the exchange failed.
    failure_category: ?ValidationCategory = null,
};

/// Predictable local validation result for one HTTP/3 operation.
pub const ValidationOutcome = struct {
    /// Validation category for the result.
    category: ValidationCategory,
    /// Whether the operation succeeded.
    status: ValidationStatus,
    /// Human-readable diagnostic message.
    message: []const u8,
    /// Optional route that was being served or requested.
    related_route: ?[]const u8 = null,
};

/// QUIC transport helpers exposed by the HTTP/3 module family.
pub const Quic = @import("quic.zig");
/// QPACK and frame helpers exposed by the HTTP/3 module family.
pub const Qpack = @import("qpack.zig");
/// HTTP/3 client request flow.
pub const Client = @import("client.zig");
/// HTTP/3 server and harness flow.
pub const Server = @import("server.zig");

test {
    _ = enabled;
    _ = ValidationCategory;
    _ = ValidationStatus;
    _ = Settings;
    _ = CriticalStreamStatus;
    _ = ControlPlaneState;
    _ = StreamExchangeState;
    _ = StreamExchange;
    _ = ValidationOutcome;
    _ = Quic;
    _ = Qpack;
    _ = Client;
    _ = Server;
    _ = @import("quic_test.zig");
}

test "http3 validation outcome retains route diagnostics" {
    const outcome = ValidationOutcome{
        .category = .route,
        .status = .failed,
        .message = "not_found",
        .related_route = "/missing",
    };

    try std.testing.expectEqual(ValidationCategory.route, outcome.category);
    try std.testing.expectEqual(ValidationStatus.failed, outcome.status);
    try std.testing.expectEqualStrings("/missing", outcome.related_route.?);
}
