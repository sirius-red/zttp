//! Shared smoke scenario planner and callback-based runner.

const std = @import("std");
const interop_harness = @import("interop_harness.zig");

/// Shell command definition for a smoke scenario.
pub const SmokeCommand = struct {
    /// Argument vector used to invoke the command.
    argv: []const []const u8,
    /// Working directory for the command.
    cwd: []const u8 = ".",
};

/// One smoke-test scenario in the local validation flow.
pub const Scenario = struct {
    /// Stable name for reporting.
    name: []const u8,
    /// Human-readable summary of what the scenario validates.
    summary: []const u8,
    /// Command to execute for the scenario.
    command: SmokeCommand,
    /// Optional interop route tied to the scenario.
    route: ?interop_harness.RouteId = null,
};

/// Error returned when the runner is missing an executor.
pub const RunError = error{
    /// No executor was configured for the runner.
    MissingExecutor,
};

/// Callback type used by the smoke runner.
pub const ExecuteFn = *const fn (ctx: ?*anyopaque, scenario: Scenario) anyerror!void;

/// Callback-based runner for build, CLI, and harness smoke scenarios.
pub const Runner = struct {
    /// Executor callback used for each scenario.
    execute_fn: ?ExecuteFn,
    /// Optional callback context.
    ctx: ?*anyopaque,

    /// Creates a runner with the provided executor callback.
    pub fn init(ctx: ?*anyopaque, execute_fn: ExecuteFn) Runner {
        return .{
            .execute_fn = execute_fn,
            .ctx = ctx,
        };
    }

    /// Creates a runner without an executor.
    pub fn initUnchecked() Runner {
        return .{
            .execute_fn = null,
            .ctx = null,
        };
    }

    /// Runs all scenarios in order through the callback executor.
    pub fn runAll(self: Runner, scenarios: []const Scenario) !void {
        const execute_fn = self.execute_fn orelse return error.MissingExecutor;
        for (scenarios) |scenario| {
            try execute_fn(self.ctx, scenario);
        }
    }
};

const default_scenarios = [_]Scenario{
    .{
        .name = "build",
        .summary = "Build the library, CLI, and examples",
        .command = .{ .argv = &.{ "zig", "build" } },
    },
    .{
        .name = "test",
        .summary = "Run the local protocol and integration test suite",
        .command = .{ .argv = &.{ "zig", "build", "test" } },
    },
    .{
        .name = "request-http",
        .summary = "Verify the CLI request path against the loopback harness",
        .command = .{ .argv = &.{ "zig", "build", "run", "--", "request", "http://127.0.0.1:8080/echo" } },
        .route = .echo_get,
    },
    .{
        .name = "request-https",
        .summary = "Verify HTTPS, TLS, and ALPN against the loopback harness",
        .command = .{ .argv = &.{ "zig", "build", "run", "--", "request", "https://127.0.0.1:8443/health" } },
        .route = .health,
    },
    .{
        .name = "server",
        .summary = "Verify the server CLI can bind and answer health probes",
        .command = .{ .argv = &.{ "zig", "build", "run", "--", "server", "--listen", "127.0.0.1", "--port", "8080" } },
        .route = .health,
    },
    .{
        .name = "http3",
        .summary = "Run the opt-in HTTP/3 smoke validation path",
        .command = .{ .argv = &.{ "zig", "build", "test", "-Dhttp3=true" } },
        .route = .health,
    },
};

/// Returns the default smoke scenarios aligned with `quickstart.md`.
pub fn defaultScenarios() []const Scenario {
    return &default_scenarios;
}

/// Returns the first default scenario that targets the provided route, if any.
pub fn scenarioForRoute(route: interop_harness.RouteId) ?Scenario {
    for (default_scenarios) |scenario| {
        if (scenario.route == route) {
            return scenario;
        }
    }
    return null;
}

test "default smoke scenarios cover quickstart commands" {
    try std.testing.expect(defaultScenarios().len >= 4);
    const request_https = scenarioForRoute(.health).?;
    try std.testing.expectEqualStrings("request-https", request_https.name);
}

test "runner dispatches scenarios through callback" {
    const Recorder = struct {
        fn execute(ctx: ?*anyopaque, scenario: Scenario) !void {
            _ = scenario;
            const counter: *usize = @ptrCast(@alignCast(ctx.?));
            counter.* += 1;
        }
    };

    var count: usize = 0;
    const runner = Runner.init(&count, Recorder.execute);
    try runner.runAll(defaultScenarios()[0..2]);
    try std.testing.expectEqual(@as(usize, 2), count);
}
