//! Executable entrypoint for the readiness smoke runner.

const std = @import("std");
const zttp = @import("zttp");

/// Runs the shared readiness smoke scenario.
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const scenario = zttp.Testing.Readiness.scenarioForId(.windows_loopback_cli_roundtrip).?;
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const platform = zttp.Testing.SmokeRunner.currentReadinessPlatform() orelse {
        try stdout.print("scenario: {s}\nstatus: skipped\nreason: unsupported host platform\n", .{scenario.name});
        try stdout.flush();
        return;
    };
    if (!scenario.supportsPlatform(platform)) {
        try stdout.print("scenario: {s}\nstatus: skipped\nreason: scenario not targeted for this host\n", .{scenario.name});
        try stdout.flush();
        return;
    }

    var round_trip = try zttp.Testing.SmokeRunner.CliRoundTripRunner.init(allocator, .{}).runReadinessScenario(scenario);
    defer round_trip.deinit(allocator);
    try zttp.Testing.SmokeRunner.writeRoundTripSummary(stdout, round_trip);

    const metrics = try zttp.Testing.InteropHarness.captureHardeningMetrics(
        allocator,
        zttp.Testing.FixtureLoader.Loader.init(),
    );
    const hardening_summary = zttp.Testing.SmokeRunner.summarizeHardening(metrics);
    try stdout.print("hardening_summary:\n", .{});
    try zttp.Testing.SmokeRunner.writeHardeningSummary(stdout, hardening_summary);
    try stdout.flush();

    if (round_trip.status == .unexpected_failure) {
        return error.UnexpectedSmokeFailure;
    }
    if (!hardening_summary.passes_reliability_threshold) {
        return error.HardeningCriteriaNotMet;
    }
}
