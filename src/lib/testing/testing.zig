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
const default_secure_validation_alpn = [_]types.NegotiatedProtocol{ .h2, .http_1_1 };

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
    /// Evidence status used by the bounded release gates.
    pub const EvidenceStatus = InteropHarness.ReleaseEvidenceStatus;
    /// Platform-scoped readiness evidence bundle.
    pub const PlatformEvidence = InteropHarness.PlatformReadinessEvidence;
    /// Protocol-scoped capability-floor evidence bundle.
    pub const ProtocolEvidence = InteropHarness.ProtocolCapabilityEvidence;

    /// Returns the readiness scenarios exposed by the shared harness.
    pub fn defaultScenarios() []const Scenario {
        return InteropHarness.defaultReadinessScenarios();
    }

    /// Returns one readiness scenario by identifier.
    pub fn scenarioForId(id: ScenarioId) ?Scenario {
        return InteropHarness.readinessScenarioForId(id);
    }

    /// Returns one readiness scenario by blocking platform.
    pub fn scenarioForPlatform(platform: InteropHarness.ReadinessPlatform) ?Scenario {
        return InteropHarness.readinessScenarioForPlatform(platform);
    }

    /// Returns the blocking release platforms for the bounded decision path.
    pub fn blockingPlatforms() []const InteropHarness.ReadinessPlatform {
        return InteropHarness.blockingReadinessPlatforms();
    }

    /// Returns the blocking capability floor for the bounded decision path.
    pub fn blockingCapabilityFloor() []const InteropHarness.CapabilityFeatureId {
        return InteropHarness.blockingCapabilityFeatures();
    }

    /// Returns the protocol-scoped release evidence for the capability floor.
    pub fn protocolEvidenceFor(protocol: types.NegotiatedProtocol) ProtocolEvidence {
        return InteropHarness.protocolCapabilityEvidenceFor(protocol);
    }

    /// Returns the smoke scenarios relevant to readiness orchestration.
    pub fn smokeScenarios() []const SmokeRunner.Scenario {
        return SmokeRunner.defaultScenarios();
    }
};

/// Shared generated-credential metadata for secure smoke and readiness helpers.
pub const SecureValidation = struct {
    /// Owned generated local credential metadata plus typed listener helpers.
    pub const GeneratedCredentialSet = struct {
        /// Owned generated credential paths under `.tmp/local-certs`.
        paths: FixtureLoader.GeneratedLocalCredentialPaths,
        /// Canonical secure endpoint used by the shared validation flow.
        endpoint: types.SecureEndpointMetadata,
        /// Shared trust and identity metadata derived from the generated paths.
        trust: types.TlsTrustMaterial,
        /// Listener metadata derived from the generated paths.
        listener: server_types.SecureListenerMetadata,

        /// Releases the owned generated credential paths.
        pub fn deinit(self: *GeneratedCredentialSet, allocator: std.mem.Allocator) void {
            self.paths.deinit(allocator);
            self.* = undefined;
        }
    };

    /// Returns the default generated-credential metadata for secure validation.
    pub fn generatedCredentialSet(
        allocator: std.mem.Allocator,
    ) FixtureLoader.LoadError!GeneratedCredentialSet {
        var paths = try FixtureLoader.Loader.init().generatedLocalCredentialPaths(allocator);
        errdefer paths.deinit(allocator);

        const endpoint = types.SecureEndpointMetadata{
            .scheme = .https,
            .host = "127.0.0.1",
            .port = types.Port.init(4433),
            .path = "/health",
            .protocol = .http_1_1,
        };
        const trust = types.TlsTrustMaterial{
            .explicit_roots_path = paths.roots_path,
            .certificate_chain_path = paths.certificate_chain_path,
            .private_key_path = paths.private_key_path,
        };

        return .{
            .paths = paths,
            .endpoint = endpoint,
            .trust = trust,
            .listener = .{
                .endpoint = endpoint,
                .trust = trust,
                .alpn_protocols = &default_secure_validation_alpn,
            },
        };
    }
};

test {
    _ = Http3RuntimeCase;
    _ = Http3Runtime;
    _ = Readiness;
    _ = SecureValidation;
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

test "readiness entrypoint exposes blocking platforms and protocol evidence" {
    const linux = Readiness.scenarioForPlatform(.linux).?;
    const h3 = Readiness.protocolEvidenceFor(.h3);

    try @import("std").testing.expectEqualStrings("linux-cli-loopback-roundtrip", linux.name);
    try @import("std").testing.expectEqual(@as(usize, 2), Readiness.blockingPlatforms().len);
    try @import("std").testing.expectEqual(@as(usize, 11), Readiness.blockingCapabilityFloor().len);
    try @import("std").testing.expectEqual(.verified, h3.overallStatus());
}

test "secure validation exposes generated local credential metadata" {
    var generated = try SecureValidation.generatedCredentialSet(@import("std").testing.allocator);
    defer generated.deinit(@import("std").testing.allocator);

    const config = generated.listener.config(noopHandler);

    try @import("std").testing.expectEqual(types.Scheme.https, generated.endpoint.scheme);
    try @import("std").testing.expectEqual(@as(u16, 4433), generated.endpoint.port.toInt());
    try @import("std").testing.expectEqualStrings("/health", generated.endpoint.path);
    try @import("std").testing.expectEqualStrings("127.0.0.1", config.listen_host);
    try @import("std").testing.expectEqualStrings(
        generated.paths.roots_path,
        config.tls.?.explicit_roots_path.?,
    );
}

/// No-op handler used by shared validation tests.
fn noopHandler(_: ?*anyopaque, _: *server_types.ServerRequest, _: *server_types.ServerResponseWriter) !void {}
