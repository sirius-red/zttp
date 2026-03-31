//! Entry point for shared local test harness support.

const std = @import("std");
const types = @import("../types.zig");
const server_types = @import("../server/types.zig");

/// Semantic interop harness route catalog.
pub const InteropHarness = @import("interop_harness.zig");
/// Local fixture loading helpers.
pub const FixtureLoader = @import("fixture_loader.zig");
/// Shared smoke scenario planner and runner.
pub const SmokeRunner = @import("smoke_runner.zig");

const default_http3_runtime_routes = [_]InteropHarness.RouteId{
    .health,
    .echo_get,
    .echo_post,
    .stream_large,
};

/// Combined HTTP/3 runtime case derived from the shared route and datagram catalogs.
pub const Http3RuntimeCase = struct {
    /// Stable route identifier for the case.
    route: InteropHarness.RouteId,
    /// Semantic request and response contract for the route.
    scenario: InteropHarness.Scenario,
    /// UDP runtime metadata for the route.
    datagram: InteropHarness.Http3DatagramScenario,
};

/// Shared HTTP/3 runtime helpers for loopback transport and server tests.
pub const Http3Runtime = struct {
    /// Returns the default HTTP/3 runtime routes that require loopback coverage.
    pub fn defaultRoutes() []const InteropHarness.RouteId {
        return &default_http3_runtime_routes;
    }

    /// Returns the merged HTTP/3 runtime case for the provided route, if any.
    pub fn caseForRoute(route: InteropHarness.RouteId) ?Http3RuntimeCase {
        const scenario = InteropHarness.scenarioForRoute(route) orelse return null;
        const datagram = InteropHarness.http3DatagramScenarioForRoute(route) orelse return null;
        return .{
            .route = route,
            .scenario = scenario,
            .datagram = datagram,
        };
    }

    /// Returns the shared runtime expectations used across loopback HTTP/3 scenarios.
    pub fn defaultExpectations() InteropHarness.Http3RuntimeExpectations {
        return caseForRoute(.health).?.datagram.runtime.expectations;
    }

    /// Returns a loopback-friendly HTTP/3 listener config aligned to the shared runtime catalog.
    pub fn defaultListenerConfig() server_types.Http3ListenerConfig {
        const health = caseForRoute(.health).?.datagram;
        const expectations = health.runtime.expectations;

        return .{
            .listen_host = health.endpoint.host,
            .port = health.endpoint.port,
            .max_datagram_size = types.ByteSize.fromBytes(health.max_datagram_size),
            .session_limits = .{
                .max_sessions = expectations.concurrent_sessions_minimum,
                .max_streams_per_session = types.ConnectionCount.init(
                    expectations.overlapping_streams_per_session_minimum.toInt(),
                ),
            },
            .qpack_limits = .{
                .dynamic_table_capacity = if (caseForRoute(.echo_post).?.datagram.runtime.qpack_dynamic_state_required)
                    types.ByteSize.fromKib(4)
                else
                    server_types.Http3QpackLimits.default().dynamic_table_capacity,
                .blocked_streams = types.ConnectionCount.init(
                    expectations.overlapping_streams_per_session_minimum.toInt(),
                ),
            },
        };
    }

    /// Returns the default loopback QUIC runtime fixture paths.
    pub fn loopbackFixturePaths(
        allocator: std.mem.Allocator,
    ) FixtureLoader.LoadError!FixtureLoader.LoopbackQuicRuntimeFixturePaths {
        return try FixtureLoader.Loader.init().loopbackQuicRuntimeFixturePaths(allocator);
    }

    /// Loads the default loopback QUIC runtime fixtures.
    pub fn loadLoopbackFixtures(
        allocator: std.mem.Allocator,
    ) FixtureLoader.LoadError!FixtureLoader.LoopbackQuicRuntimeFixtures {
        return try FixtureLoader.Loader.init().loadLoopbackQuicRuntimeFixtures(allocator);
    }
};

/// Focused readiness scenarios and smoke hooks.
pub const Readiness = struct {
    /// Release-readiness scenario identifier.
    pub const ScenarioId = InteropHarness.ReadinessScenarioId;
    /// Release-readiness scenario definition.
    pub const Scenario = InteropHarness.ReadinessScenario;

    /// Returns the readiness scenarios exposed by the shared harness.
    pub fn defaultScenarios() []const Scenario {
        return InteropHarness.defaultReadinessScenarios();
    }

    /// Returns one readiness scenario by identifier.
    pub fn scenarioForId(id: ScenarioId) ?Scenario {
        return InteropHarness.readinessScenarioForId(id);
    }

    /// Returns the smoke scenarios relevant to readiness orchestration.
    pub fn smokeScenarios() []const SmokeRunner.Scenario {
        return SmokeRunner.defaultScenarios();
    }
};

test {
    _ = InteropHarness;
    _ = FixtureLoader;
    _ = SmokeRunner;
    _ = Http3RuntimeCase;
    _ = Http3Runtime;
    _ = Readiness;
    _ = @import("malformed_input_test.zig");
    _ = @import("http3_interop_test.zig");
}

test "http3 runtime helpers expose shared loopback defaults" {
    const health = Http3Runtime.caseForRoute(.health).?;
    const echo = Http3Runtime.caseForRoute(.echo_post).?;
    const listener = Http3Runtime.defaultListenerConfig();
    const expectations = Http3Runtime.defaultExpectations();

    try @import("std").testing.expectEqual(InteropHarness.RouteId.health, health.route);
    try @import("std").testing.expectEqual(types.NegotiatedProtocol.h3, health.datagram.endpoint.protocol);
    try @import("std").testing.expectEqual(types.Status.ok, health.scenario.success_status);
    try @import("std").testing.expectEqualStrings("127.0.0.1", listener.listen_host);
    try @import("std").testing.expectEqual(@as(u16, 4433), listener.port.toInt());
    try @import("std").testing.expectEqual(@as(usize, 1200), listener.max_datagram_size.toInt());
    try @import("std").testing.expectEqual(@as(usize, 2), listener.session_limits.max_sessions.toInt());
    try @import("std").testing.expectEqual(@as(usize, 2), listener.session_limits.max_streams_per_session.toInt());
    try @import("std").testing.expectEqual(@as(usize, 2), listener.qpack_limits.blocked_streams.toInt());
    try @import("std").testing.expect(echo.datagram.runtime.qpack_dynamic_state_required);
    try @import("std").testing.expectEqual(@as(usize, 10), expectations.sequential_requests_without_restart);
}

test "http3 runtime helpers expose loopback fixture paths" {
    var paths = try Http3Runtime.loopbackFixturePaths(@import("std").testing.allocator);
    defer paths.deinit(@import("std").testing.allocator);

    try @import("std").testing.expect(
        @import("std").mem.endsWith(u8, paths.runtime_health_path, "http3/quic/runtime/health-request.bin") or
            @import("std").mem.endsWith(u8, paths.runtime_health_path, "http3\\quic\\runtime\\health-request.bin"),
    );
    try @import("std").testing.expect(
        @import("std").mem.endsWith(u8, paths.runtime_echo_path, "http3/quic/runtime/echo-request.bin") or
            @import("std").mem.endsWith(u8, paths.runtime_echo_path, "http3\\quic\\runtime\\echo-request.bin"),
    );
}

test "readiness entrypoint exposes the windows loopback scenario" {
    const readiness = Readiness.scenarioForId(.windows_loopback_cli_roundtrip).?;

    try @import("std").testing.expectEqualStrings("windows-cli-loopback-roundtrip", readiness.name);
    try @import("std").testing.expectEqualStrings("request", readiness.request_command.name);
    try @import("std").testing.expect(Readiness.smokeScenarios().len >= 4);
}
