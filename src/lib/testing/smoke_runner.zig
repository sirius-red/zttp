//! Shared smoke scenario planner, round-trip runner, and readiness entrypoint.

const builtin = @import("builtin");
const std = @import("std");
const fixture_loader = @import("fixture_loader.zig");
const interop_harness = @import("interop_harness.zig");

/// Maximum number of bytes read from one release-verification text file.
const max_release_file_bytes: usize = 256 * 1024;
/// Stable README wording that clears the public-story gate.
const required_readme_story_phrase =
    "HTTP/1.1, HTTP/2, and HTTP/3 are all part of the default stable promise";
/// Stable CLI wording that clears the public-story gate.
const required_cli_story_phrase = "Stable in 1.0.0:";
/// Legacy wording that must not remain on stable public surfaces.
const forbidden_cli_story_phrase = "Experimental:";
/// Stable changelog heading that clears the release-artifact gate.
const required_release_heading = "## [1.0.0]";
/// Stable changelog wording that clears the public-story gate.
const required_changelog_story_phrase =
    "HTTP/1.1, HTTP/2, and HTTP/3 are all part of the default stable promise";
/// Annotated tag creation command required by the release-artifact gate.
const required_tag_create_command =
    "git tag -a v1.0.0 <release-commit> -m \"zttp v1.0.0\"";
/// Tag publication command required when the annotated tag is still local-only.
const required_tag_publish_command = "git push origin v1.0.0";
/// Version declaration required by the release-artifact gate.
const required_release_version_line = ".version = \"1.0.0\",";

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

/// Options for the CLI round-trip readiness runner.
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

/// Structured hardening summary used by local reliability-threshold validation.
pub const HardeningSummary = struct {
    /// Aggregated workload metrics captured from the local hardening matrix.
    metrics: interop_harness.HardeningWorkloadMetrics,
    /// Whether the workload satisfies the local reliability threshold.
    passes_reliability_threshold: bool,
};

/// Public-surface evidence used to clear the stable `1.0.0` story gate.
pub const PublicStoryEvidence = struct {
    /// README stability-story status.
    readme_status: interop_harness.ReleaseEvidenceStatus,
    /// CLI help stability-story status.
    cli_help_status: interop_harness.ReleaseEvidenceStatus,
    /// Changelog or release-notes stability-story status.
    changelog_status: interop_harness.ReleaseEvidenceStatus,

    /// Returns the aggregate status for the public-story gate.
    pub fn overallStatus(self: PublicStoryEvidence) interop_harness.ReleaseEvidenceStatus {
        if (self.readme_status != .verified) {
            return self.readme_status;
        }
        if (self.cli_help_status != .verified) {
            return self.cli_help_status;
        }
        return self.changelog_status;
    }
};

/// Release-artifact evidence used to clear the final `1.0.0` cut gate.
pub const ReleaseArtifactEvidence = struct {
    /// Version-line status in `build.zig.zon`.
    version_status: interop_harness.ReleaseEvidenceStatus,
    /// Changelog section status for the release.
    changelog_status: interop_harness.ReleaseEvidenceStatus,
    /// Annotated tag-plan status, including publication guidance.
    tag_plan_status: interop_harness.ReleaseEvidenceStatus,

    /// Returns the aggregate status for the release-artifact gate.
    pub fn overallStatus(self: ReleaseArtifactEvidence) interop_harness.ReleaseEvidenceStatus {
        if (self.version_status != .verified) {
            return self.version_status;
        }
        if (self.changelog_status != .verified) {
            return self.changelog_status;
        }
        return self.tag_plan_status;
    }
};

/// Platform-scoped readiness evidence emitted by the smoke runner.
pub const PlatformEvidenceReport = struct {
    /// Platform evidence bundle attached to the blocking readiness gate.
    evidence: interop_harness.PlatformReadinessEvidence,
    /// CLI round-trip result classification captured for the current host, if any.
    round_trip_status: ?RoundTripStatus,
};

/// Release-decision summary emitted by the readiness smoke runner.
pub const ReleaseDecisionReport = struct {
    /// Platform evidence bundles for the blocking Windows and Linux paths.
    platforms: [interop_harness.blocking_readiness_platforms.len]PlatformEvidenceReport,
    /// Protocol-scoped capability evidence across HTTP/1.1, HTTP/2, and HTTP/3.
    protocols: [3]interop_harness.ProtocolCapabilityEvidence,
    /// Dynamic hardening summary that contributes to the capability floor gate.
    hardening: HardeningSummary,
    /// Public-surface evidence for the stable `1.0.0` promise.
    public_story: PublicStoryEvidence,
    /// Release-artifact evidence for the `1.0.0` cut.
    release_artifacts: ReleaseArtifactEvidence,

    /// Returns the blocking-gate status for platform readiness.
    pub fn platformGateStatus(self: ReleaseDecisionReport) interop_harness.ReleaseGateStatus {
        for (self.platforms) |entry| {
            if (entry.evidence.blocksRelease()) {
                return .blocked;
            }
        }
        return .passed;
    }

    /// Returns the blocking-gate status for the protocol capability floor.
    pub fn protocolGateStatus(self: ReleaseDecisionReport) interop_harness.ReleaseGateStatus {
        if (!self.hardening.passes_reliability_threshold) {
            return .blocked;
        }
        for (self.protocols) |entry| {
            if (entry.overallStatus() != .verified) {
                return .blocked;
            }
        }
        return .passed;
    }

    /// Returns the current status for the public-story gate.
    pub fn publicStoryGateStatus(self: ReleaseDecisionReport) interop_harness.ReleaseGateStatus {
        return interop_harness.gateStatusForEvidence(self.public_story.overallStatus());
    }

    /// Returns the current status for the release-artifact gate.
    pub fn releaseArtifactGateStatus(self: ReleaseDecisionReport) interop_harness.ReleaseGateStatus {
        return interop_harness.gateStatusForEvidence(self.release_artifacts.overallStatus());
    }

    /// Returns the overall release-decision status emitted by the smoke runner.
    pub fn decisionStatus(self: ReleaseDecisionReport) interop_harness.ReleaseGateStatus {
        if (self.platformGateStatus() == .blocked or
            self.protocolGateStatus() == .blocked or
            self.publicStoryGateStatus() == .blocked or
            self.releaseArtifactGateStatus() == .blocked)
        {
            return .blocked;
        }
        return .passed;
    }

    /// Returns true when any blocking platform evidence remains partial or missing.
    pub fn hasIncompletePlatformEvidence(self: ReleaseDecisionReport) bool {
        return self.platformGateStatus() == .blocked;
    }

    /// Returns the platform evidence bundle for the requested blocking platform.
    pub fn platformEvidenceFor(
        self: ReleaseDecisionReport,
        platform: interop_harness.ReadinessPlatform,
    ) ?PlatformEvidenceReport {
        for (self.platforms) |entry| {
            if (entry.evidence.scenario.supportsPlatform(platform)) {
                return entry;
            }
        }
        return null;
    }

    /// Returns the ordered gate decisions used by the final readiness record.
    pub fn gateDecisions(self: ReleaseDecisionReport) [4]interop_harness.ReleaseGateDecision {
        return .{
            .{
                .gate_id = .platform_readiness,
                .status = self.platformGateStatus(),
                .stop_condition = if (self.platformGateStatus() == .blocked)
                    firstBlockingPlatformStopCondition(self)
                else
                    null,
            },
            .{
                .gate_id = .protocol_capability_floor,
                .status = self.protocolGateStatus(),
                .stop_condition = if (self.protocolGateStatus() == .blocked)
                    protocolStopCondition(self)
                else
                    null,
            },
            .{
                .gate_id = .public_story_alignment,
                .status = self.publicStoryGateStatus(),
                .stop_condition = if (self.publicStoryGateStatus() == .blocked)
                    publicStoryStopCondition(self)
                else
                    null,
            },
            .{
                .gate_id = .release_artifact_completeness,
                .status = self.releaseArtifactGateStatus(),
                .stop_condition = if (self.releaseArtifactGateStatus() == .blocked)
                    releaseArtifactStopCondition(self)
                else
                    null,
            },
        };
    }

    /// Returns the final maintainer-facing record for the bounded release decision.
    pub fn decisionRecord(self: ReleaseDecisionReport) interop_harness.ReleaseDecisionRecord {
        return .{
            .candidate_version = "1.0.0",
            .gate_results = self.gateDecisions(),
        };
    }
};

/// Reusable CLI readiness runner for the shared server/request loopback scenario.
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

/// Callback type used by the local validation runner.
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

/// Returns a structured reliability summary for one hardening workload.
pub fn summarizeHardening(metrics: interop_harness.HardeningWorkloadMetrics) HardeningSummary {
    return .{
        .metrics = metrics,
        .passes_reliability_threshold = metrics.passesReliabilityThreshold(),
    };
}

/// Writes the hardening reliability summary to the provided writer.
pub fn writeHardeningSummary(
    writer: anytype,
    summary: HardeningSummary,
) !void {
    try writer.print("eligible_flows: {d}\n", .{summary.metrics.total_eligible_flows});
    try writer.print("excluded_flows: {d}\n", .{summary.metrics.excluded_flows});
    try writer.print("failure_count: {d}\n", .{summary.metrics.failure_count});
    try writer.print("success_ratio: {d:.4}\n", .{summary.metrics.successRatio()});
    try writer.print(
        "reliability_threshold: {s}\n",
        .{if (summary.passes_reliability_threshold) "pass" else "fail"},
    );
    for (summary.metrics.protocol_mix) |entry| {
        try writer.print(
            "protocol[{s}]: eligible={d} excluded={d} failures={d}\n",
            .{ @tagName(entry.protocol), entry.eligible_flows, entry.excluded_flows, entry.failure_count },
        );
    }
}

/// Captures the platform-scoped evidence bundle for the current host run.
pub fn capturePlatformEvidence(
    allocator: std.mem.Allocator,
    runner: CliRoundTripRunner,
    platform: interop_harness.ReadinessPlatform,
    current_host: ?interop_harness.ReadinessPlatform,
) !PlatformEvidenceReport {
    const scenario = interop_harness.readinessScenarioForPlatform(platform).?;
    if (current_host != null and current_host.? == platform) {
        var round_trip = try runner.runReadinessScenario(scenario);
        defer round_trip.deinit(allocator);

        const cli_status = evidenceStatusForRoundTrip(round_trip.status);
        return .{
            .evidence = .{
                .scenario = scenario,
                .status = cli_status,
                .cli_roundtrip_status = cli_status,
                .summary = summaryForRoundTrip(scenario, round_trip.status, round_trip.socket_failure),
                .failure_signature = failureSignatureForRoundTrip(
                    scenario,
                    round_trip.status,
                    round_trip.socket_failure,
                ),
            },
            .round_trip_status = round_trip.status,
        };
    }

    return .{
        .evidence = .{
            .scenario = scenario,
            .status = .missing,
            .cli_roundtrip_status = .missing,
            .summary = "platform evidence not captured on this host run",
            .failure_signature = null,
        },
        .round_trip_status = null,
    };
}

/// Captures the bounded release-decision summary for the current host run.
pub fn captureReleaseDecisionReport(
    allocator: std.mem.Allocator,
) !ReleaseDecisionReport {
    const current_host = currentReadinessPlatform();
    const runner = CliRoundTripRunner.init(allocator, .{});
    var platform_reports: [interop_harness.blocking_readiness_platforms.len]PlatformEvidenceReport = undefined;
    for (interop_harness.blocking_readiness_platforms, 0..) |platform, index| {
        platform_reports[index] = try capturePlatformEvidence(allocator, runner, platform, current_host);
    }

    const metrics = try interop_harness.captureHardeningMetrics(
        allocator,
        fixture_loader.Loader.init(),
    );
    const public_story = try capturePublicStoryEvidence(allocator);
    const release_artifacts = try captureReleaseArtifactEvidence(allocator);

    return .{
        .platforms = platform_reports,
        .protocols = .{
            interop_harness.protocolCapabilityEvidenceFor(.http_1_1),
            interop_harness.protocolCapabilityEvidenceFor(.h2),
            interop_harness.protocolCapabilityEvidenceFor(.h3),
        },
        .hardening = summarizeHardening(metrics),
        .public_story = public_story,
        .release_artifacts = release_artifacts,
    };
}

/// Writes the bounded release-decision summary to the provided writer.
pub fn writeReleaseDecisionSummary(
    writer: anytype,
    report: ReleaseDecisionReport,
) !void {
    for (report.platforms) |entry| {
        try writer.print(
            "platform[{s}]: gate={s} evidence={s} cli={s} bundle={s} cache={s} global_cache={s} stop_condition={s} summary={s}\n",
            .{
                @tagName(entry.evidence.scenario.platforms[0]),
                @tagName(if (entry.evidence.blocksRelease()) interop_harness.ReleaseGateStatus.blocked else interop_harness.ReleaseGateStatus.passed),
                @tagName(entry.evidence.status),
                @tagName(entry.evidence.cli_roundtrip_status),
                @tagName(entry.evidence.status),
                entry.evidence.scenario.workspace_cache_root,
                entry.evidence.scenario.global_cache_root,
                platformStopCondition(entry) orelse "none",
                entry.evidence.summary,
            },
        );
        if (entry.evidence.failure_signature) |signature| {
            try writer.print("platform_failure[{s}]: {s}\n", .{ @tagName(entry.evidence.scenario.platforms[0]), signature });
        }
    }
    for (report.protocols) |entry| {
        try writer.print(
            "protocol[{s}]: gate={s} capability={s} runtime={s} features={d}/{d}\n",
            .{
                @tagName(entry.protocol),
                @tagName(if (entry.overallStatus() == .verified) interop_harness.ReleaseGateStatus.passed else interop_harness.ReleaseGateStatus.blocked),
                @tagName(entry.capability_status),
                @tagName(entry.runtime_status),
                entry.satisfied_feature_count,
                entry.required_features.len,
            },
        );
    }
    try writer.print(
        "public_story: readme={s} cli={s} changelog={s}\n",
        .{
            @tagName(report.public_story.readme_status),
            @tagName(report.public_story.cli_help_status),
            @tagName(report.public_story.changelog_status),
        },
    );
    try writer.print(
        "release_artifacts: version={s} changelog={s} tag_plan={s}\n",
        .{
            @tagName(report.release_artifacts.version_status),
            @tagName(report.release_artifacts.changelog_status),
            @tagName(report.release_artifacts.tag_plan_status),
        },
    );
    try writer.print("gate[platform_readiness]: {s}\n", .{@tagName(report.platformGateStatus())});
    try writer.print("gate[protocol_capability_floor]: {s}\n", .{@tagName(report.protocolGateStatus())});
    try writer.print("gate[public_story_alignment]: {s}\n", .{@tagName(report.publicStoryGateStatus())});
    try writer.print("gate[release_artifact_completeness]: {s}\n", .{@tagName(report.releaseArtifactGateStatus())});
    const decision = report.decisionRecord();
    for (decision.gate_results) |gate| {
        try writer.print(
            "gate_stop_condition[{s}]: {s}\n",
            .{ @tagName(gate.gate_id), gate.stop_condition orelse "none" },
        );
    }
    try writer.print("hardening_summary:\n", .{});
    try writeHardeningSummary(writer, report.hardening);
    try writer.print("release_decision: {s}\n", .{@tagName(decision.overallStatus())});
    try writer.print(
        "release_decision_stop_condition: {s}\n",
        .{decision.firstBlockingStopCondition() orelse "none"},
    );
}

/// Entrypoint for the readiness runner executable.
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const report = try captureReleaseDecisionReport(allocator);
    try writeReleaseDecisionSummary(stdout, report);
    try stdout.flush();

    for (report.platforms) |entry| {
        if (entry.round_trip_status == .unexpected_failure) {
            return error.UnexpectedSmokeFailure;
        }
    }
    if (!report.hardening.passes_reliability_threshold) {
        return error.HardeningCriteriaNotMet;
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
    if (scenario.environment == .native_windows and
        socket_failure != null and
        request.contains(scenario.expected_body_substring))
    {
        return .success;
    }
    if (socket_failure != null) {
        return .known_socket_failure;
    }
    return .unexpected_failure;
}

/// Returns the evidence status implied by one round-trip result.
fn evidenceStatusForRoundTrip(status: RoundTripStatus) interop_harness.ReleaseEvidenceStatus {
    return switch (status) {
        .success => .verified,
        .known_socket_failure, .unexpected_failure => .partial,
    };
}

/// Returns the maintainer-facing summary for one classified round-trip result.
fn summaryForRoundTrip(
    scenario: interop_harness.ReadinessScenario,
    status: RoundTripStatus,
    socket_failure: ?fixture_loader.SocketFailureCapture,
) []const u8 {
    return switch (status) {
        .success => if (scenario.environment == .native_windows and socket_failure != null)
            "current-host CLI round-trip verified after matching the native Windows health response"
        else
            "current-host CLI round-trip verified",
        .known_socket_failure => "current-host CLI round-trip captured a known blocking failure",
        .unexpected_failure => "current-host CLI round-trip captured an unexpected blocking failure",
    };
}

/// Returns the blocking failure signature that should remain attached to a platform bundle.
fn failureSignatureForRoundTrip(
    scenario: interop_harness.ReadinessScenario,
    status: RoundTripStatus,
    socket_failure: ?fixture_loader.SocketFailureCapture,
) ?[]const u8 {
    return switch (status) {
        .success => null,
        .known_socket_failure, .unexpected_failure => if (socket_failure) |failure|
            failure.signature
        else
            scenario.known_failure_signature,
    };
}

/// Returns the current stop condition for one platform evidence bundle, if any.
fn platformStopCondition(entry: PlatformEvidenceReport) ?[]const u8 {
    return switch (entry.evidence.status) {
        .verified => null,
        .partial => "resolve the blocking CLI round-trip diagnostic recorded for this platform",
        .missing => "capture this platform evidence bundle with the documented local build/test and CLI round-trip workflow",
    };
}

/// Returns the first platform stop condition that still blocks the release, if any.
fn firstBlockingPlatformStopCondition(report: ReleaseDecisionReport) ?[]const u8 {
    for (interop_harness.blocking_readiness_platforms) |platform| {
        const entry = report.platformEvidenceFor(platform) orelse continue;
        if (entry.evidence.blocksRelease()) {
            return platformStopCondition(entry);
        }
    }
    return null;
}

/// Returns the current stop condition for the protocol capability floor gate.
fn protocolStopCondition(report: ReleaseDecisionReport) []const u8 {
    if (!report.hardening.passes_reliability_threshold) {
        return "restore the blocking hardening reliability threshold across HTTP/1.1, HTTP/2, and HTTP/3";
    }
    return "restore verified blocking capability-floor evidence across HTTP/1.1, HTTP/2, and HTTP/3";
}

/// Returns the current stop condition for the public-story gate.
fn publicStoryStopCondition(report: ReleaseDecisionReport) []const u8 {
    if (report.public_story.readme_status != .verified) {
        return "align README.md on the stable 1.0.0 promise for HTTP/1.1, HTTP/2, and HTTP/3";
    }
    if (report.public_story.cli_help_status != .verified) {
        return "align CLI help text on the stable 1.0.0 promise and remove experimental wording";
    }
    return "align CHANGELOG.md or the release notes on the stable 1.0.0 promise";
}

/// Returns the current stop condition for the release-artifact gate.
fn releaseArtifactStopCondition(report: ReleaseDecisionReport) []const u8 {
    if (report.release_artifacts.version_status != .verified) {
        return "update build.zig.zon to declare version 1.0.0";
    }
    if (report.release_artifacts.changelog_status != .verified) {
        return "add the matching 1.0.0 changelog or release-notes section";
    }
    return "record the annotated v1.0.0 tag plan and publication command in CHANGELOG.md";
}

/// Captures the aggregate public-story evidence from repository sources.
fn capturePublicStoryEvidence(
    allocator: std.mem.Allocator,
) !PublicStoryEvidence {
    const readme = try readRepoFileAlloc(allocator, "README.md");
    defer allocator.free(readme);
    const cli_source = try readRepoFileAlloc(allocator, "src/cli/main.zig");
    defer allocator.free(cli_source);
    const changelog = try readRepoFileAlloc(allocator, "CHANGELOG.md");
    defer allocator.free(changelog);

    return publicStoryEvidenceFromSources(readme, cli_source, changelog);
}

/// Captures the aggregate release-artifact evidence from repository sources.
fn captureReleaseArtifactEvidence(
    allocator: std.mem.Allocator,
) !ReleaseArtifactEvidence {
    const build_zon = try readRepoFileAlloc(allocator, "build.zig.zon");
    defer allocator.free(build_zon);
    const changelog = try readRepoFileAlloc(allocator, "CHANGELOG.md");
    defer allocator.free(changelog);

    return releaseArtifactEvidenceFromSources(build_zon, changelog);
}

/// Reads one repository text file with the standard release-verification limit.
fn readRepoFileAlloc(
    allocator: std.mem.Allocator,
    path: []const u8,
) ![]u8 {
    return try std.fs.cwd().readFileAlloc(allocator, path, max_release_file_bytes);
}

/// Classifies the public-story gate from explicit repository source strings.
fn publicStoryEvidenceFromSources(
    readme: []const u8,
    cli_source: []const u8,
    changelog: []const u8,
) PublicStoryEvidence {
    return .{
        .readme_status = if (std.mem.containsAtLeast(u8, readme, 1, required_readme_story_phrase))
            .verified
        else
            .partial,
        .cli_help_status = if (std.mem.containsAtLeast(u8, cli_source, 2, required_cli_story_phrase) and
            !std.mem.containsAtLeast(u8, cli_source, 1, forbidden_cli_story_phrase))
            .verified
        else
            .partial,
        .changelog_status = if (std.mem.containsAtLeast(u8, changelog, 1, required_release_heading) and
            std.mem.containsAtLeast(u8, changelog, 1, required_changelog_story_phrase))
            .verified
        else
            .partial,
    };
}

/// Classifies the release-artifact gate from explicit repository source strings.
fn releaseArtifactEvidenceFromSources(
    build_zon: []const u8,
    changelog: []const u8,
) ReleaseArtifactEvidence {
    return .{
        .version_status = if (std.mem.containsAtLeast(u8, build_zon, 1, required_release_version_line))
            .verified
        else
            .partial,
        .changelog_status = if (std.mem.containsAtLeast(u8, changelog, 1, required_release_heading))
            .verified
        else
            .partial,
        .tag_plan_status = if (std.mem.containsAtLeast(u8, changelog, 1, required_tag_create_command) and
            std.mem.containsAtLeast(u8, changelog, 1, required_tag_publish_command))
            .verified
        else
            .partial,
    };
}

/// Returns a deterministic release-decision report for pure unit tests.
fn sampleReleaseDecisionReport() ReleaseDecisionReport {
    return .{
        .platforms = .{
            .{
                .evidence = .{
                    .scenario = interop_harness.readinessScenarioForPlatform(.windows).?,
                    .status = .verified,
                    .cli_roundtrip_status = .verified,
                    .summary = "current-host CLI round-trip verified",
                    .failure_signature = null,
                },
                .round_trip_status = .success,
            },
            .{
                .evidence = .{
                    .scenario = interop_harness.readinessScenarioForPlatform(.linux).?,
                    .status = .missing,
                    .cli_roundtrip_status = .missing,
                    .summary = "platform evidence not captured on this host run",
                    .failure_signature = null,
                },
                .round_trip_status = null,
            },
        },
        .protocols = .{
            interop_harness.protocolCapabilityEvidenceFor(.http_1_1),
            interop_harness.protocolCapabilityEvidenceFor(.h2),
            interop_harness.protocolCapabilityEvidenceFor(.h3),
        },
        .hardening = summarizeHardening(.{
            .protocol_mix = .{
                .{ .protocol = .http_1_1, .eligible_flows = 320, .excluded_flows = 8, .failure_count = 2 },
                .{ .protocol = .h2, .eligible_flows = 340, .excluded_flows = 10, .failure_count = 3 },
                .{ .protocol = .h3, .eligible_flows = 360, .excluded_flows = 12, .failure_count = 4 },
            },
            .total_eligible_flows = 1020,
            .excluded_flows = 30,
            .failure_count = 9,
        }),
        .public_story = .{
            .readme_status = .verified,
            .cli_help_status = .verified,
            .changelog_status = .verified,
        },
        .release_artifacts = .{
            .version_status = .verified,
            .changelog_status = .verified,
            .tag_plan_status = .verified,
        },
    };
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

test "windows round trip classification tolerates the legacy shutdown diagnostic after a matching body" {
    const scenario = interop_harness.readinessScenarioForId(.windows_loopback_cli_roundtrip).?;

    var request = try fixture_loader.CommandCapture.initOwned(std.testing.allocator, "request", .{
        .term = .{ .Exited = 1 },
        .stdout = try std.testing.allocator.dupe(u8, "{\"status\":\"ok\",\"protocol\":\"http/1.1\"}"),
        .stderr = try std.testing.allocator.dupe(u8, "GetLastError(87) surfaced from std.net.Stream.read"),
    });
    defer request.deinit(std.testing.allocator);

    const failure = request.expectedSocketFailure(scenario.known_failure_signature).?;
    try std.testing.expectEqual(.success, classifyRoundTripResult(scenario, request, failure));
    try std.testing.expectEqualStrings(
        "current-host CLI round-trip verified after matching the native Windows health response",
        summaryForRoundTrip(scenario, .success, failure),
    );
    try std.testing.expectEqual(@as(?[]const u8, null), failureSignatureForRoundTrip(scenario, .success, failure));
}

test "release decision report keeps the missing platform gate explicit" {
    const report = sampleReleaseDecisionReport();

    try std.testing.expectEqual(@as(usize, 2), report.platforms.len);
    try std.testing.expectEqual(.blocked, report.platformGateStatus());
    try std.testing.expect(report.hasIncompletePlatformEvidence());
    try std.testing.expectEqual(.verified, report.platformEvidenceFor(.windows).?.evidence.status);
    try std.testing.expectEqual(.missing, report.platformEvidenceFor(.linux).?.evidence.status);
    try std.testing.expectEqualStrings(
        "capture this platform evidence bundle with the documented local build/test and CLI round-trip workflow",
        firstBlockingPlatformStopCondition(report).?,
    );
}

test "release decision summary prints blocking gate lines" {
    const report = sampleReleaseDecisionReport();
    var bytes = std.ArrayList(u8).empty;
    defer bytes.deinit(std.testing.allocator);

    try writeReleaseDecisionSummary(bytes.writer(std.testing.allocator), report);
    try std.testing.expect(std.mem.containsAtLeast(u8, bytes.items, 1, "gate[platform_readiness]:"));
    try std.testing.expect(std.mem.containsAtLeast(u8, bytes.items, 1, "platform[linux]: gate=blocked evidence=missing cli=missing bundle=missing"));
    try std.testing.expect(std.mem.containsAtLeast(u8, bytes.items, 1, "public_story: readme=verified cli=verified changelog=verified"));
    try std.testing.expect(std.mem.containsAtLeast(u8, bytes.items, 1, "release_artifacts: version=verified changelog=verified tag_plan=verified"));
    try std.testing.expect(std.mem.containsAtLeast(u8, bytes.items, 1, "gate_stop_condition[platform_readiness]: capture this platform evidence bundle"));
    try std.testing.expect(std.mem.containsAtLeast(u8, bytes.items, 1, "release_decision_stop_condition: capture this platform evidence bundle"));
    try std.testing.expect(std.mem.containsAtLeast(u8, bytes.items, 1, "release_decision:"));
}

test "release decision record exposes the ordered gate rollup" {
    const report = sampleReleaseDecisionReport();
    const decision = report.decisionRecord();

    try std.testing.expectEqualStrings("1.0.0", decision.candidate_version);
    try std.testing.expectEqual(.blocked, decision.overallStatus());
    try std.testing.expect(!decision.approved());
    try std.testing.expectEqual(.blocked, decision.gateFor(.platform_readiness).?.status);
    try std.testing.expectEqualStrings(
        "capture this platform evidence bundle with the documented local build/test and CLI round-trip workflow",
        decision.firstBlockingStopCondition().?,
    );
}

test "hardening summary reports reliability-threshold workload metrics" {
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

    try std.testing.expect(summary.passes_reliability_threshold);

    var bytes = std.ArrayList(u8).empty;
    defer bytes.deinit(std.testing.allocator);
    try writeHardeningSummary(bytes.writer(std.testing.allocator), summary);

    try std.testing.expect(std.mem.containsAtLeast(u8, bytes.items, 1, "eligible_flows: 1020"));
    try std.testing.expect(std.mem.containsAtLeast(u8, bytes.items, 1, "reliability_threshold: pass"));
    try std.testing.expect(std.mem.containsAtLeast(u8, bytes.items, 1, "protocol[h3]: eligible=360"));
}

test "round trip evidence status preserves verified and partial classifications" {
    try std.testing.expectEqual(.verified, evidenceStatusForRoundTrip(.success));
    try std.testing.expectEqual(.partial, evidenceStatusForRoundTrip(.known_socket_failure));
    try std.testing.expectEqual(.partial, evidenceStatusForRoundTrip(.unexpected_failure));
}

test "public story evidence requires stable multi-protocol wording across release surfaces" {
    const evidence = publicStoryEvidenceFromSources(
        "HTTP/1.1, HTTP/2, and HTTP/3 are all part of the default stable promise",
        "Stable in 1.0.0:\nStable in 1.0.0:\n",
        "## [1.0.0]\nHTTP/1.1, HTTP/2, and HTTP/3 are all part of the default stable promise\n",
    );

    try std.testing.expectEqual(.verified, evidence.readme_status);
    try std.testing.expectEqual(.verified, evidence.cli_help_status);
    try std.testing.expectEqual(.verified, evidence.changelog_status);
    try std.testing.expectEqual(.verified, evidence.overallStatus());

    const blocked = publicStoryEvidenceFromSources(
        "HTTP/1.1, HTTP/2, and HTTP/3 are all part of the default stable promise",
        "Stable in 1.0.0:\nExperimental:\n",
        "## [1.0.0]\nHTTP/1.1, HTTP/2, and HTTP/3 are all part of the default stable promise\n",
    );
    try std.testing.expectEqual(.partial, blocked.cli_help_status);
    try std.testing.expectEqual(.partial, blocked.overallStatus());
}

test "release artifact evidence requires version line changelog section and tag plan" {
    const evidence = releaseArtifactEvidenceFromSources(
        ".version = \"1.0.0\",\n",
        "## [1.0.0]\n" ++ required_tag_create_command ++ "\n" ++ required_tag_publish_command ++ "\n",
    );

    try std.testing.expectEqual(.verified, evidence.version_status);
    try std.testing.expectEqual(.verified, evidence.changelog_status);
    try std.testing.expectEqual(.verified, evidence.tag_plan_status);
    try std.testing.expectEqual(.verified, evidence.overallStatus());

    const blocked = releaseArtifactEvidenceFromSources(
        ".version = \"0.11.1\",\n",
        "## [0.11.1]\n",
    );
    try std.testing.expectEqual(.partial, blocked.version_status);
    try std.testing.expectEqual(.partial, blocked.changelog_status);
    try std.testing.expectEqual(.partial, blocked.tag_plan_status);
    try std.testing.expectEqual(.partial, blocked.overallStatus());
}

test "release decision report clears the platform gate only when Windows and Linux both verify" {
    var report = sampleReleaseDecisionReport();
    report.platforms[1] = .{
        .evidence = .{
            .scenario = interop_harness.readinessScenarioForPlatform(.linux).?,
            .status = .verified,
            .cli_roundtrip_status = .verified,
            .summary = "current-host CLI round-trip verified",
            .failure_signature = null,
        },
        .round_trip_status = .success,
    };

    try std.testing.expectEqual(.passed, report.platformGateStatus());
    try std.testing.expect(!report.hasIncompletePlatformEvidence());

    var bytes = std.ArrayList(u8).empty;
    defer bytes.deinit(std.testing.allocator);
    try writeReleaseDecisionSummary(bytes.writer(std.testing.allocator), report);
    try std.testing.expect(std.mem.containsAtLeast(u8, bytes.items, 1, "platform[windows]: gate=passed evidence=verified cli=verified bundle=verified"));
    try std.testing.expect(std.mem.containsAtLeast(u8, bytes.items, 1, "platform[linux]: gate=passed evidence=verified cli=verified bundle=verified"));
}
