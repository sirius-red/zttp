//! Entry point for shared local test harness support.

/// Build-time feature flags visible to the testing module family.
pub const BuildOptions = @import("zttp_build_options");
/// Semantic interop harness route catalog.
pub const InteropHarness = @import("interop_harness.zig");
/// Local fixture loading helpers.
pub const FixtureLoader = @import("fixture_loader.zig");
/// Shared smoke scenario planner and runner.
pub const SmokeRunner = @import("smoke_runner.zig");

test {
    _ = BuildOptions;
    _ = InteropHarness;
    _ = FixtureLoader;
    _ = SmokeRunner;
}
