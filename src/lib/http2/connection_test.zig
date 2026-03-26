//! Regression coverage scaffolding for future HTTP/2 client work.

const std = @import("std");
const types = @import("../types.zig");
const interop_harness = @import("../testing/interop_harness.zig");
const connection = @import("connection.zig");

/// HTTP/2 behavior class covered by a regression scenario.
pub const RegressionEvent = enum {
    /// SETTINGS exchange and acknowledgement.
    settings,
    /// HPACK encoding and decoding.
    hpack,
    /// Flow-control window exhaustion and recovery.
    flow_control,
    /// `RST_STREAM` handling.
    rst_stream,
    /// `GOAWAY` handling.
    goaway,
    /// Malformed frame handling.
    malformed_frame,
};

/// Declarative HTTP/2 regression case for the future connection implementation.
pub const RegressionCase = struct {
    /// Stable case name used in test output.
    name: []const u8,
    /// HTTP/2 event exercised by the case.
    event: RegressionEvent,
    /// Route template used by the higher-level interop harness.
    path_template: []const u8,
    /// Whether the case is expected to fail the stream or connection.
    expect_error: bool,
};

const regression_cases = [_]RegressionCase{
    .{
        .name = "settings-ack",
        .event = .settings,
        .path_template = "/health",
        .expect_error = false,
    },
    .{
        .name = "hpack-roundtrip",
        .event = .hpack,
        .path_template = "/echo",
        .expect_error = false,
    },
    .{
        .name = "flow-control-large-stream",
        .event = .flow_control,
        .path_template = "/stream/large",
        .expect_error = false,
    },
    .{
        .name = "rst-stream-aborts-request",
        .event = .rst_stream,
        .path_template = "/stream/chunked",
        .expect_error = true,
    },
    .{
        .name = "goaway-drains-connection",
        .event = .goaway,
        .path_template = "/health",
        .expect_error = true,
    },
    .{
        .name = "malformed-frame-is-rejected",
        .event = .malformed_frame,
        .path_template = "/echo",
        .expect_error = true,
    },
};

test "http2 regression matrix covers required failure modes" {
    try std.testing.expectEqual(@as(usize, 6), regression_cases.len);
    try std.testing.expectEqual(RegressionEvent.rst_stream, regression_cases[3].event);
    try std.testing.expect(regression_cases[3].expect_error);
    try std.testing.expectEqual(RegressionEvent.goaway, regression_cases[4].event);
    try std.testing.expect(regression_cases[4].expect_error);
}

test "http2 regression matrix retains hpack and flow-control coverage" {
    try std.testing.expectEqualStrings("/echo", regression_cases[1].path_template);
    try std.testing.expectEqual(RegressionEvent.flow_control, regression_cases[2].event);
    try std.testing.expectEqualStrings("/stream/large", regression_cases[2].path_template);
}

test "interop routes advertise http2 coverage" {
    const health = interop_harness.scenarioForRoute(.health).?;
    const echo_get = interop_harness.scenarioForRoute(.echo_get).?;
    const stream_large = interop_harness.scenarioForRoute(.stream_large).?;

    try std.testing.expect(health.supportsProtocol(.h2));
    try std.testing.expect(echo_get.supportsProtocol(.h2));
    try std.testing.expect(stream_large.supportsProtocol(.h2));
    try std.testing.expectEqualStrings("h2", types.NegotiatedProtocol.h2.asAlpnBytes());
}

test "http2 typed connection state tracks repeated stream openings" {
    var state = connection.Connection.init(std.testing.allocator);
    defer state.deinit();

    state.sendClientPreface();
    try std.testing.expectEqual(@as(u31, 1), try state.openLocalStream());
    try std.testing.expectEqual(@as(u31, 3), try state.openLocalStream());
    try std.testing.expectEqual(@as(usize, 2), state.activeStreamCount());
    try std.testing.expectEqual(@as(u31, 5), state.next_stream_id);
}

test "http2 typed connection state records blocked scope transitions" {
    var state = connection.Connection.init(std.testing.allocator);
    defer state.deinit();

    state.sendClientPreface();
    const stream_id = try state.openLocalStream();
    try state.setStreamState(stream_id, .open);
    try state.setBlockedReason(stream_id, .stream_buffer);
    try std.testing.expectEqual(connection.BlockedReason.stream_buffer, state.streams.items[0].blocked_reason);
    try std.testing.expectEqual(connection.StreamState.blocked_stream, state.streams.items[0].state);

    try state.clearBlockedReason(stream_id);
    try std.testing.expectEqual(connection.BlockedReason.none, state.streams.items[0].blocked_reason);
    try std.testing.expectEqual(connection.StreamState.open, state.streams.items[0].state);
}
