//! Executable wrapper for the shared readiness smoke runner.

const smoke_runner = @import("testing/smoke_runner.zig");

/// Entrypoint for the standalone readiness executable wired through `build.zig`.
pub fn main() !void {
    try smoke_runner.main();
}
