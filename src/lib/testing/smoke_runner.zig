//! Shared smoke scenario planner, round-trip runner, and readiness entrypoint.

const builtin = @import("builtin");
const std = @import("std");
const fixture_loader = @import("fixture_loader.zig");
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

/// Error returned by pipe capture helpers.
pub const PipeCaptureError = std.mem.Allocator.Error || std.fs.File.ReadError || error{
    /// Captured process output exceeded the configured byte budget.
    OutputTooLarge,
};

/// Result classification for a CLI round-trip smoke scenario.
pub const RoundTripStatus = enum {
    /// The request succeeded and the expected body substring was observed.
    success,
    /// The request failed with a known socket-level signature.
    known_socket_failure,
    /// The request failed, but not with a recognized diagnostic signature.
    unexpected_failure,
};

/// Options for the CLI round-trip smoke runner.
pub const CliRoundTripOptions = struct {
    /// Working directory used for the spawned `zig` commands.
    cwd: ?[]const u8 = null,
    /// Delay between starting the server and probing it.
    startup_delay_ns: u64 = 250 * std.time.ns_per_ms,
    /// Maximum time to wait for the request probe to exit.
    request_timeout_ns: u64 = 30 * std.time.ns_per_s,
    /// Maximum stdout or stderr bytes captured for each process.
    max_output_bytes: usize = 64 * 1024,
    /// Prevents extra console windows on Windows when spawning children.
    create_no_window: bool = builtin.os.tag == .windows,
};

/// Owned output collector for one child-process pipe.
pub const PipeCollector = struct {
    /// Allocator used for the captured buffer.
    allocator: std.mem.Allocator,
    /// Pipe file handle owned by the collector thread.
    file: std.fs.File,
    /// Maximum number of bytes to retain.
    max_output_bytes: usize,
    /// Buffered output bytes captured from the pipe.
    bytes: std.ArrayList(u8) = .empty,
    /// Background thread reading the pipe to completion.
    thread: ?std.Thread = null,
    /// Read or allocation error surfaced by the thread, if any.
    read_error: ?PipeCaptureError = null,

    /// Creates a collector for one child-process pipe.
    pub fn init(
        allocator: std.mem.Allocator,
        file: std.fs.File,
        max_output_bytes: usize,
    ) PipeCollector {
        return .{
            .allocator = allocator,
            .file = file,
            .max_output_bytes = max_output_bytes,
        };
    }

    /// Starts the background read loop.
    pub fn start(self: *PipeCollector) std.Thread.SpawnError!void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    /// Waits for the reader to finish and returns the owned captured bytes.
    pub fn join(self: *PipeCollector) PipeCaptureError![]u8 {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        if (self.read_error) |err| {
            self.bytes.deinit(self.allocator);
            return err;
        }
        return self.bytes.toOwnedSlice(self.allocator);
    }

    /// Reads the pipe to completion in the background.
    fn run(self: *PipeCollector) void {
        var buffer: [4096]u8 = undefined;
        while (true) {
            const read_len = self.file.read(&buffer) catch |err| {
                self.read_error = err;
                return;
            };
            if (read_len == 0) {
                return;
            }
            if (self.bytes.items.len + read_len > self.max_output_bytes) {
                self.read_error = error.OutputTooLarge;
                return;
            }
            self.bytes.appendSlice(self.allocator, buffer[0..read_len]) catch |err| {
                self.read_error = err;
                return;
            };
        }
    }
};

/// Spawned server process and asynchronous pipe capture state.
pub const ServerProcess = struct {
    /// Running child process.
    child: std.process.Child,
    /// Stable command label for reporting.
    command_name: []const u8,

    /// Stops the child process and returns the owned server capture.
    pub fn stopAndCapture(
        self: *ServerProcess,
        allocator: std.mem.Allocator,
    ) !fixture_loader.CommandCapture {
        const term = self.child.kill() catch |err| switch (err) {
            error.AlreadyTerminated => try self.child.wait(),
            else => return err,
        };

        return .{
            .command_name = self.command_name,
            .term = term,
            .stdout = try allocator.alloc(u8, 0),
            .stderr = try allocator.alloc(u8, 0),
        };
    }
};

/// Structured result for one CLI server/request round-trip.
pub const RoundTripResult = struct {
    /// Shared readiness scenario that was executed.
    scenario: interop_harness.ReadinessScenario,
    /// Captured long-running server command output.
    server: fixture_loader.CommandCapture,
    /// Captured request command output.
    request: fixture_loader.CommandCapture,
    /// Classified round-trip status.
    status: RoundTripStatus,
    /// Recognized socket failure, when present.
    socket_failure: ?fixture_loader.SocketFailureCapture,

    /// Releases the owned command captures.
    pub fn deinit(self: *RoundTripResult, allocator: std.mem.Allocator) void {
        self.server.deinit(allocator);
        self.request.deinit(allocator);
        self.* = undefined;
    }
};

/// Structured hardening summary used by SC-004 smoke validation.
pub const HardeningSummary = struct {
    /// Aggregated workload metrics captured from the local hardening matrix.
    metrics: interop_harness.HardeningWorkloadMetrics,
    /// Whether the workload satisfies SC-004.
    passes_sc004: bool,
};

/// Reusable CLI smoke runner for the shared server/request loopback scenario.
pub const CliRoundTripRunner = struct {
    /// Allocator used for child-process capture buffers.
    allocator: std.mem.Allocator,
    /// Runtime options for process spawning and output limits.
    options: CliRoundTripOptions,

    /// Creates a round-trip runner with the provided options.
    pub fn init(allocator: std.mem.Allocator, options: CliRoundTripOptions) CliRoundTripRunner {
        return .{
            .allocator = allocator,
            .options = options,
        };
    }

    /// Executes one readiness scenario through `zig build run`.
    pub fn runReadinessScenario(
        self: CliRoundTripRunner,
        scenario: interop_harness.ReadinessScenario,
    ) !RoundTripResult {
        var server_process = try self.spawnScenarioServer(scenario);
        var request_capture = try self.runScenarioRequest(scenario);
        errdefer request_capture.deinit(self.allocator);

        const server_capture = try server_process.stopAndCapture(self.allocator);
        errdefer {
            var owned = server_capture;
            owned.deinit(self.allocator);
        }

        const socket_failure = request_capture.expectedSocketFailure(scenario.known_failure_signature) orelse
            server_capture.expectedSocketFailure(scenario.known_failure_signature);

        return .{
            .scenario = scenario,
            .server = server_capture,
            .request = request_capture,
            .status = classifyRoundTripResult(scenario, request_capture, socket_failure),
            .socket_failure = socket_failure,
        };
    }

    /// Starts the long-running server command and begins capturing its output.
    fn spawnServer(
        self: CliRoundTripRunner,
        command_name: []const u8,
        argv: []const []const u8,
    ) !ServerProcess {
        var child = std.process.Child.init(argv, self.allocator);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
        child.cwd = self.options.cwd;
        child.create_no_window = self.options.create_no_window;

        try child.spawn();

        std.Thread.sleep(self.options.startup_delay_ns);

        return .{
            .child = child,
            .command_name = command_name,
        };
    }

    /// Runs one short-lived command with bounded output and a timeout.
    fn runCommand(
        self: CliRoundTripRunner,
        command_name: []const u8,
        argv: []const []const u8,
        timeout_ns: u64,
    ) !fixture_loader.CommandCapture {
        var child = std.process.Child.init(argv, self.allocator);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        child.cwd = self.options.cwd;
        child.create_no_window = self.options.create_no_window;

        try child.spawn();

        var stdout = PipeCollector.init(self.allocator, child.stdout.?, self.options.max_output_bytes);
        var stderr = PipeCollector.init(self.allocator, child.stderr.?, self.options.max_output_bytes);
        child.stdout = null;
        child.stderr = null;

        stdout.start() catch |err| {
            stdout.file.close();
            stderr.file.close();
            return err;
        };
        errdefer _ = stdout.join() catch {};
        stderr.start() catch |err| {
            _ = stdout.join() catch {};
            stderr.file.close();
            return err;
        };
        errdefer _ = stderr.join() catch {};

        const term = try waitForCommand(&child, timeout_ns);

        const stdout_bytes = try stdout.join();
        errdefer self.allocator.free(stdout_bytes);
        const stderr_bytes = try stderr.join();
        errdefer self.allocator.free(stderr_bytes);

        return .{
            .command_name = command_name,
            .term = term,
            .stdout = stdout_bytes,
            .stderr = stderr_bytes,
        };
    }

    /// Starts the readiness server using the already-built CLI binary.
    fn spawnScenarioServer(
        self: CliRoundTripRunner,
        scenario: interop_harness.ReadinessScenario,
    ) !ServerProcess {
        const binary_path = try self.cliBinaryPath();
        defer self.allocator.free(binary_path);

        var port_buffer: [16]u8 = undefined;
        const port = try std.fmt.bufPrint(&port_buffer, "{d}", .{scenario.endpoint.port.toInt()});
        const argv = [_][]const u8{
            binary_path,
            scenario.server_command.name,
            "--listen",
            scenario.endpoint.host,
            "--port",
            port,
        };

        return self.spawnServer(scenario.server_command.name, &argv);
    }

    /// Runs the readiness request probe using the already-built CLI binary.
    fn runScenarioRequest(
        self: CliRoundTripRunner,
        scenario: interop_harness.ReadinessScenario,
    ) !fixture_loader.CommandCapture {
        const binary_path = try self.cliBinaryPath();
        defer self.allocator.free(binary_path);

        const request_url = scenario.request_command.argv[5];
        const argv = [_][]const u8{
            binary_path,
            scenario.request_command.name,
            request_url,
        };
        return self.runCommand(scenario.request_command.name, &argv, self.options.request_timeout_ns);
    }

    /// Returns the CLI binary path for the current target platform.
    fn cliBinaryPath(self: CliRoundTripRunner) std.mem.Allocator.Error![]u8 {
        return self.allocator.dupe(
            u8,
            if (builtin.os.tag == .windows) "zig-out\\bin\\zttp.exe" else "zig-out/bin/zttp",
        );
    }
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
        .summary = "Build the library and CLI",
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
        .summary = "Verify the HTTP/3 request path through the default build",
        .command = .{ .argv = &.{ "zig", "build", "run", "--", "request", "--http3", "https://127.0.0.1:4433/health" } },
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

/// Returns the current host platform as a readiness-platform value, when supported.
pub fn currentReadinessPlatform() ?interop_harness.ReadinessPlatform {
    return switch (builtin.os.tag) {
        .windows => .windows,
        .linux => .linux,
        .macos => .macos,
        else => null,
    };
}

/// Writes a short smoke-run summary to the provided writer.
pub fn writeRoundTripSummary(writer: anytype, result: RoundTripResult) !void {
    try writer.print("scenario: {s}\n", .{result.scenario.name});
    try writer.print("status: {s}\n", .{@tagName(result.status)});
    try writer.print("request_term: {}\n", .{result.request.term});
    try writer.print("server_term: {}\n", .{result.server.term});
    if (result.request.stdout.len > 0) {
        try writer.print("request_stdout:\n{s}\n", .{result.request.stdout});
    }
    if (result.request.stderr.len > 0) {
        try writer.print("request_stderr:\n{s}\n", .{result.request.stderr});
    }
    if (result.server.stdout.len > 0) {
        try writer.print("server_stdout:\n{s}\n", .{result.server.stdout});
    }
    if (result.server.stderr.len > 0) {
        try writer.print("server_stderr:\n{s}\n", .{result.server.stderr});
    }
    if (result.socket_failure) |failure| {
        try writer.print(
            "socket_failure: {s} on {s} via {s}\n",
            .{ @tagName(failure.kind), @tagName(failure.stream), failure.signature },
        );
    }
}

/// Returns a structured SC-004 summary for one hardening workload.
pub fn summarizeHardening(metrics: interop_harness.HardeningWorkloadMetrics) HardeningSummary {
    return .{
        .metrics = metrics,
        .passes_sc004 = metrics.passesSc004(),
    };
}

/// Writes the SC-004 hardening summary to the provided writer.
pub fn writeHardeningSummary(
    writer: anytype,
    summary: HardeningSummary,
) !void {
    try writer.print("eligible_flows: {d}\n", .{summary.metrics.total_eligible_flows});
    try writer.print("excluded_flows: {d}\n", .{summary.metrics.excluded_flows});
    try writer.print("failure_count: {d}\n", .{summary.metrics.failure_count});
    try writer.print("success_ratio: {d:.4}\n", .{summary.metrics.successRatio()});
    try writer.print("sc004: {s}\n", .{if (summary.passes_sc004) "pass" else "fail"});
    for (summary.metrics.protocol_mix) |entry| {
        try writer.print(
            "protocol[{s}]: eligible={d} excluded={d} failures={d}\n",
            .{ @tagName(entry.protocol), entry.eligible_flows, entry.excluded_flows, entry.failure_count },
        );
    }
}

/// Entrypoint for `zig build smoke`.
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const scenario = interop_harness.readinessScenarioForId(.windows_loopback_cli_roundtrip).?;
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const platform = currentReadinessPlatform() orelse {
        try stdout.print("scenario: {s}\nstatus: skipped\nreason: unsupported host platform\n", .{scenario.name});
        try stdout.flush();
        return;
    };
    if (!scenario.supportsPlatform(platform)) {
        try stdout.print("scenario: {s}\nstatus: skipped\nreason: scenario not targeted for this host\n", .{scenario.name});
        try stdout.flush();
        return;
    }

    var result = try CliRoundTripRunner.init(allocator, .{}).runReadinessScenario(scenario);
    defer result.deinit(allocator);
    try writeRoundTripSummary(stdout, result);
    try stdout.flush();

    if (result.status == .unexpected_failure) {
        return error.UnexpectedSmokeFailure;
    }
}

/// Classifies the round-trip result from the request capture and known signatures.
fn classifyRoundTripResult(
    scenario: interop_harness.ReadinessScenario,
    request: fixture_loader.CommandCapture,
    socket_failure: ?fixture_loader.SocketFailureCapture,
) RoundTripStatus {
    if (request.succeeded() and request.contains(scenario.expected_body_substring)) {
        return .success;
    }
    if (socket_failure != null) {
        return .known_socket_failure;
    }
    return .unexpected_failure;
}

/// Waits for a child command to finish or kills it after the timeout expires.
fn waitForCommand(child: *std.process.Child, timeout_ns: u64) !std.process.Child.Term {
    if (builtin.os.tag == .windows) {
        const milliseconds: std.os.windows.DWORD = @intCast(@min(
            timeout_ns / std.time.ns_per_ms,
            std.math.maxInt(std.os.windows.DWORD),
        ));
        std.os.windows.WaitForSingleObjectEx(child.id, milliseconds, false) catch |err| switch (err) {
            error.WaitTimeOut => return child.kill(),
            else => return err,
        };
        return try child.wait();
    }

    return try child.wait();
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

test "round trip classification prefers success when the expected body is present" {
    const scenario = interop_harness.readinessScenarioForId(.windows_loopback_cli_roundtrip).?;

    var request = try fixture_loader.CommandCapture.initOwned(std.testing.allocator, "request", .{
        .term = .{ .Exited = 0 },
        .stdout = try std.testing.allocator.dupe(u8, "{\"status\":\"ok\",\"protocol\":\"http/1.1\"}"),
        .stderr = try std.testing.allocator.dupe(u8, "HTTP/1.1 200\n"),
    });
    defer request.deinit(std.testing.allocator);

    try std.testing.expectEqual(.success, classifyRoundTripResult(scenario, request, null));
}

test "round trip classification preserves known socket failures" {
    const scenario = interop_harness.readinessScenarioForId(.windows_loopback_cli_roundtrip).?;

    var request = try fixture_loader.CommandCapture.initOwned(std.testing.allocator, "request", .{
        .term = .{ .Exited = 1 },
        .stdout = try std.testing.allocator.dupe(u8, ""),
        .stderr = try std.testing.allocator.dupe(u8, "GetLastError(87) surfaced from std.net.Stream.read"),
    });
    defer request.deinit(std.testing.allocator);

    const failure = request.expectedSocketFailure(scenario.known_failure_signature).?;
    try std.testing.expectEqual(.known_socket_failure, classifyRoundTripResult(scenario, request, failure));
}

test "hardening summary reports SC-004 workload metrics" {
    const summary = summarizeHardening(.{
        .protocol_mix = .{
            .{ .protocol = .http_1_1, .eligible_flows = 320, .excluded_flows = 8, .failure_count = 2 },
            .{ .protocol = .h2, .eligible_flows = 340, .excluded_flows = 10, .failure_count = 3 },
            .{ .protocol = .h3, .eligible_flows = 360, .excluded_flows = 12, .failure_count = 4 },
        },
        .total_eligible_flows = 1020,
        .excluded_flows = 30,
        .failure_count = 9,
    });

    try std.testing.expect(summary.passes_sc004);

    var bytes = std.ArrayList(u8).init(std.testing.allocator);
    defer bytes.deinit();
    try writeHardeningSummary(bytes.writer(), summary);

    try std.testing.expect(std.mem.containsAtLeast(u8, bytes.items, 1, "eligible_flows: 1020"));
    try std.testing.expect(std.mem.containsAtLeast(u8, bytes.items, 1, "sc004: pass"));
    try std.testing.expect(std.mem.containsAtLeast(u8, bytes.items, 1, "protocol[h3]: eligible=360"));
}
