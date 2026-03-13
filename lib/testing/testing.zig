//! Entry point for shared local test harness support.

/// Build-time feature flags visible to the testing module family.
pub const BuildOptions = @import("zttp_build_options");
/// Semantic interop harness route catalog.
pub const InteropHarness = @import("interop_harness.zig");
/// Local fixture loading helpers.
pub const FixtureLoader = @import("fixture_loader.zig");
/// Shared smoke scenario planner and runner.
pub const SmokeRunner = @import("smoke_runner.zig");
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
    _ = BuildOptions;
    _ = InteropHarness;
    _ = FixtureLoader;
    _ = SmokeRunner;
    _ = Readiness;
    _ = @import("malformed_input_test.zig");
    if (BuildOptions.http3) {
        _ = @import("http3_interop_test.zig");
    }
}

test "readiness entrypoint exposes the windows loopback scenario" {
    const readiness = Readiness.scenarioForId(.windows_loopback_cli_roundtrip).?;

    try @import("std").testing.expectEqualStrings("windows-loopback-cli-roundtrip", readiness.name);
    try @import("std").testing.expectEqualStrings("request", readiness.request_command.name);
    try @import("std").testing.expect(Readiness.smokeScenarios().len >= 4);
}
