//! Regression coverage scaffolding for future QUIC transport work.

const std = @import("std");
const quic = @import("quic.zig");
const types = @import("../types.zig");
const fixture_loader = @import("../testing/fixture_loader.zig");
const interop_harness = @import("../testing/interop_harness.zig");

/// QUIC behavior class covered by a regression scenario.
pub const RegressionEvent = enum {
    /// Packet formatting and packet-number-space handling.
    packet,
    /// Loss detection and recovery timer behavior.
    recovery,
    /// Congestion-window growth and backoff behavior.
    congestion,
    /// Stream reset signaling and propagation.
    stream_reset,
};

/// Packet-number space exercised by a regression scenario.
pub const PacketSpace = enum {
    /// Initial packet protection and parsing.
    initial,
    /// Handshake packet lifecycle.
    handshake,
    /// Application-data packet lifecycle.
    application,
};

/// Declarative QUIC regression case for the future HTTP/3 transport.
pub const RegressionCase = struct {
    /// Stable case name used in test output.
    name: []const u8,
    /// QUIC behavior covered by the case.
    event: RegressionEvent,
    /// Packet-number space exercised by the case.
    packet_space: PacketSpace,
    /// Harness path template used by the higher-level HTTP/3 interop flow.
    path_template: []const u8,
    /// Whether the transport is expected to surface an error.
    expect_error: bool,
};

const regression_cases = [_]RegressionCase{
    .{
        .name = "initial-packet-health-probe",
        .event = .packet,
        .packet_space = .initial,
        .path_template = "/health",
        .expect_error = false,
    },
    .{
        .name = "handshake-recovery-retransmits-echo",
        .event = .recovery,
        .packet_space = .handshake,
        .path_template = "/echo",
        .expect_error = false,
    },
    .{
        .name = "application-congestion-large-body",
        .event = .congestion,
        .packet_space = .application,
        .path_template = "/stream/large",
        .expect_error = false,
    },
    .{
        .name = "stream-reset-aborts-chunked-response",
        .event = .stream_reset,
        .packet_space = .application,
        .path_template = "/stream/chunked",
        .expect_error = true,
    },
};

test "quic regression matrix covers packet, recovery, congestion, and reset cases" {
    try std.testing.expectEqual(@as(usize, 4), regression_cases.len);
    try std.testing.expectEqual(RegressionEvent.packet, regression_cases[0].event);
    try std.testing.expectEqual(PacketSpace.initial, regression_cases[0].packet_space);
    try std.testing.expectEqual(RegressionEvent.recovery, regression_cases[1].event);
    try std.testing.expectEqual(PacketSpace.handshake, regression_cases[1].packet_space);
    try std.testing.expectEqual(RegressionEvent.congestion, regression_cases[2].event);
    try std.testing.expectEqual(RegressionEvent.stream_reset, regression_cases[3].event);
    try std.testing.expect(regression_cases[3].expect_error);
}

test "quic regression matrix retains route and packet-space coverage" {
    try std.testing.expectEqualStrings("/health", regression_cases[0].path_template);
    try std.testing.expectEqualStrings("/echo", regression_cases[1].path_template);
    try std.testing.expectEqualStrings("/stream/large", regression_cases[2].path_template);
    try std.testing.expectEqualStrings("/stream/chunked", regression_cases[3].path_template);
    try std.testing.expectEqual(PacketSpace.application, regression_cases[2].packet_space);
    try std.testing.expectEqual(PacketSpace.application, regression_cases[3].packet_space);
}

test "http3 fixture paths stay inside the dedicated fixture group" {
    const loader = fixture_loader.Loader.init();
    const path = try loader.pathFor(std.testing.allocator, "http3/quic/initial-client.bin");
    defer std.testing.allocator.free(path);

    try std.testing.expect(std.mem.startsWith(u8, path, "src/lib/testing/fixtures"));
    try std.testing.expect(
        std.mem.endsWith(u8, path, "http3/quic/initial-client.bin") or
            std.mem.endsWith(u8, path, "http3\\quic\\initial-client.bin"),
    );
}

test "interop routes advertise h3 coverage" {
    const health = interop_harness.scenarioForRoute(.health).?;
    const echo_get = interop_harness.scenarioForRoute(.echo_get).?;
    const echo_post = interop_harness.scenarioForRoute(.echo_post).?;

    try std.testing.expect(health.supportsProtocol(.h3));
    try std.testing.expect(echo_get.supportsProtocol(.h3));
    try std.testing.expect(echo_post.supportsProtocol(.h3));
    try std.testing.expectEqualStrings("h3", types.NegotiatedProtocol.h3.asAlpnBytes());
}

test "quic application packets require a completed handshake" {
    var session = quic.Session.init(std.testing.allocator, "client01".*, "server01".*);
    defer session.deinit();

    try std.testing.expectError(
        error.HandshakeIncomplete,
        session.protectPacket(std.testing.allocator, .application, "blocked"),
    );
}

test "quic disturbed delivery classifies reordered and duplicate packets predictably" {
    var client = quic.Session.init(std.testing.allocator, "client01".*, "server01".*);
    defer client.deinit();
    var server = quic.Session.init(std.testing.allocator, "server01".*, "client01".*);
    defer server.deinit();
    client.beginHandshake();
    client.establish();
    server.beginHandshake();
    server.establish();

    const first = try client.protectPacket(std.testing.allocator, .application, "first");
    defer std.testing.allocator.free(first);
    const second = try client.protectPacket(std.testing.allocator, .application, "second");
    defer std.testing.allocator.free(second);

    var out_of_order = try server.unprotectPacket(std.testing.allocator, second);
    defer out_of_order.deinit(std.testing.allocator);
    try std.testing.expectEqual(quic.PacketDeliveryState.fresh, out_of_order.delivery_state);
    try std.testing.expectEqualStrings("second", out_of_order.payload);

    var reordered = try server.unprotectPacket(std.testing.allocator, first);
    defer reordered.deinit(std.testing.allocator);
    try std.testing.expectEqual(quic.PacketDeliveryState.reordered, reordered.delivery_state);
    try std.testing.expectEqualStrings("first", reordered.payload);

    var duplicate = try server.unprotectPacket(std.testing.allocator, first);
    defer duplicate.deinit(std.testing.allocator);
    try std.testing.expectEqual(quic.PacketDeliveryState.duplicate, duplicate.delivery_state);
}

test "quic retransmission rebuilds a lost payload with a fresh packet number" {
    var client = quic.Session.init(std.testing.allocator, "client01".*, "server01".*);
    defer client.deinit();
    var server = quic.Session.init(std.testing.allocator, "server01".*, "client01".*);
    defer server.deinit();
    client.beginHandshake();
    client.establish();
    server.beginHandshake();
    server.establish();

    const original = try client.protectPacket(std.testing.allocator, .application, "health");
    defer std.testing.allocator.free(original);
    const retransmitted = try client.retransmitLostPacket(std.testing.allocator, .application, 0);
    defer std.testing.allocator.free(retransmitted);

    var packet = try server.unprotectPacket(std.testing.allocator, retransmitted);
    defer packet.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u64, 1), packet.number);
    try std.testing.expectEqualStrings("health", packet.payload);
}

test "quic stream registries preserve session isolation across overlapping stream ids" {
    var session_a = quic.Session.init(std.testing.allocator, "client01".*, "server01".*);
    defer session_a.deinit();
    var session_b = quic.Session.init(std.testing.allocator, "client02".*, "server02".*);
    defer session_b.deinit();
    session_a.beginHandshake();
    session_a.establish();
    session_b.beginHandshake();
    session_b.establish();

    const stream_a = try session_a.openStream(.bidirectional);
    const stream_b = try session_b.openStream(.bidirectional);
    try std.testing.expectEqual(@as(u64, 0), stream_a);
    try std.testing.expectEqual(@as(u64, 0), stream_b);

    try std.testing.expect(session_a.completeStream(stream_a));
    try std.testing.expect(session_b.resetStream(stream_b));

    try std.testing.expectEqual(quic.StreamLifecycle.completed, session_a.streamState(stream_a).?);
    try std.testing.expectEqual(quic.StreamLifecycle.reset, session_b.streamState(stream_b).?);
}
