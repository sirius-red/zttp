//! Client interop regression coverage tied to the shared harness contract.

const std = @import("std");
const interop_harness = @import("interop_harness.zig");
const smoke_runner = @import("smoke_runner.zig");

test "client interop catalog covers required contract routes" {
    const health = interop_harness.scenarioForRoute(.health).?;
    const echo_get = interop_harness.scenarioForRoute(.echo_get).?;
    const redirect = interop_harness.scenarioForRoute(.redirect_count).?;
    const cookie_set = interop_harness.scenarioForRoute(.cookies_set).?;
    const cookie_read = interop_harness.scenarioForRoute(.cookies_read).?;
    const chunked = interop_harness.scenarioForRoute(.stream_chunked).?;
    const large = interop_harness.scenarioForRoute(.stream_large).?;

    try std.testing.expectEqualStrings("/health", health.path_template);
    try std.testing.expectEqualStrings("/echo", echo_get.path_template);
    try std.testing.expectEqualStrings("/redirect/{count}", redirect.path_template);
    try std.testing.expectEqualStrings("/cookies/set", cookie_set.path_template);
    try std.testing.expectEqualStrings("/cookies/read", cookie_read.path_template);
    try std.testing.expectEqualStrings("/stream/chunked", chunked.path_template);
    try std.testing.expectEqualStrings("/stream/large", large.path_template);
}

test "client interop catalog preserves expected response modes" {
    const redirect = interop_harness.scenarioForRoute(.redirect_count).?;
    const cookie_set = interop_harness.scenarioForRoute(.cookies_set).?;
    const chunked = interop_harness.scenarioForRoute(.stream_chunked).?;
    const large = interop_harness.scenarioForRoute(.stream_large).?;

    try std.testing.expectEqual(.redirect, redirect.response_mode);
    try std.testing.expectEqual(.no_content, cookie_set.response_mode);
    try std.testing.expectEqual(.text_stream, chunked.response_mode);
    try std.testing.expectEqual(.binary_stream, large.response_mode);
}

test "smoke scenarios retain request coverage for http and https" {
    const scenarios = smoke_runner.defaultScenarios();
    try std.testing.expect(scenarios.len >= 4);
    try std.testing.expectEqualStrings("request-http", scenarios[2].name);
    try std.testing.expectEqualStrings("request-https", scenarios[3].name);
    try std.testing.expect(scenarios[2].route != null);
    try std.testing.expect(scenarios[3].route != null);
}

test "client interop preserves the windows loopback readiness probe contract" {
    const readiness = interop_harness.readinessScenarioForId(.windows_loopback_cli_roundtrip).?;

    try std.testing.expectEqualStrings("windows-loopback-cli-roundtrip", readiness.name);
    try std.testing.expectEqual(interop_harness.RouteId.health, readiness.route);
    try std.testing.expectEqualStrings("request", readiness.request_command.name);
    try std.testing.expectEqualStrings("http://127.0.0.1:18080/health", readiness.request_command.argv[5]);
    try std.testing.expect(readiness.blocking);
    try std.testing.expect(std.mem.containsAtLeast(
        u8,
        readiness.expected_body_substring,
        1,
        "\"protocol\":\"http/1.1\"",
    ));
}
