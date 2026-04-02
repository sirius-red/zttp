//! Executable entrypoint for the readiness smoke runner.

const std = @import("std");
const zttp = @import("zttp");

/// Runs the shared readiness smoke scenario.
pub fn main() !void {
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    const require_all_platforms = try parseRequireAllPlatformsFlag(args[1..]);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const report = try zttp.Testing.SmokeRunner.captureReleaseDecisionReport(allocator);
    try zttp.Testing.SmokeRunner.writeReleaseDecisionSummary(stdout, report);
    try stdout.flush();

    for (report.platforms) |entry| {
        if (entry.round_trip_status == .unexpected_failure) {
            return error.UnexpectedSmokeFailure;
        }
    }
    if (require_all_platforms and report.hasIncompletePlatformEvidence()) {
        return error.MissingPlatformEvidence;
    }
    if (!report.hardening.passes_reliability_threshold) {
        return error.HardeningCriteriaNotMet;
    }
}

/// Parses the optional all-platform enforcement flag.
fn parseRequireAllPlatformsFlag(args: []const []const u8) !bool {
    var require_all_platforms = false;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--require-all-platforms")) {
            require_all_platforms = true;
        } else {
            return error.InvalidArgument;
        }
    }
    return require_all_platforms;
}

test "platform-enforcement flag parser accepts the bounded release option" {
    try std.testing.expect(try parseRequireAllPlatformsFlag(&.{"--require-all-platforms"}));
    try std.testing.expect(!(try parseRequireAllPlatformsFlag(&.{})));
}

test "platform-enforcement flag parser rejects unknown arguments" {
    try std.testing.expectError(error.InvalidArgument, parseRequireAllPlatformsFlag(&.{"--unknown"}));
}
