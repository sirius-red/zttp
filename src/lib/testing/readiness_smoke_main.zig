//! Executable entrypoint for the readiness smoke runner.

const zttp = @import("zttp");

/// Runs the shared readiness smoke scenario.
pub fn main() !void {
    try zttp.Testing.SmokeRunner.main();
}
