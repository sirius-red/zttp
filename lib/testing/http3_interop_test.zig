//! Opt-in HTTP/3 interop regression coverage tied to the shared harness contract.

const std = @import("std");
const http3 = @import("../http3/http3.zig");
const types = @import("../types.zig");
const interop_harness = @import("interop_harness.zig");
const smoke_runner = @import("smoke_runner.zig");

/// Declarative expectation for one HTTP/3 interop route.
pub const RouteExpectation = struct {
    /// Stable route identifier from the shared harness contract.
    route: interop_harness.RouteId,
    /// Path template the HTTP/3 harness must expose.
    path_template: []const u8,
    /// Method expected by the route.
    method: types.Method,
    /// Success status returned by the route.
    success_status: types.Status,
};

const required_routes = [_]RouteExpectation{
    .{
        .route = .health,
        .path_template = "/health",
        .method = .get,
        .success_status = .ok,
    },
    .{
        .route = .echo_get,
        .path_template = "/echo",
        .method = .get,
        .success_status = .ok,
    },
    .{
        .route = .echo_post,
        .path_template = "/echo",
        .method = .post,
        .success_status = .ok,
    },
};

test "http3 interop coverage is opt-in" {
    try std.testing.expect(http3.enabled);
    try std.testing.expectEqual(@as(usize, 3), required_routes.len);
}

test "http3 interop catalog covers health and echo routes" {
    for (required_routes) |expectation| {
        const scenario = interop_harness.scenarioForRoute(expectation.route).?;
        try std.testing.expectEqualStrings(expectation.path_template, scenario.path_template);
        try std.testing.expectEqual(expectation.method, scenario.method);
        try std.testing.expectEqual(expectation.success_status, scenario.success_status);
        try std.testing.expect(scenario.supportsProtocol(.h3));
    }
}

test "http3 interop catalog preserves health and echo semantics" {
    const health = interop_harness.scenarioForRoute(.health).?;
    const echo_get = interop_harness.scenarioForRoute(.echo_get).?;
    const echo_post = interop_harness.scenarioForRoute(.echo_post).?;

    try std.testing.expect(health.tls_supported);
    try std.testing.expectEqual(.json, health.response_mode);
    try std.testing.expectEqual(.json, echo_get.response_mode);
    try std.testing.expectEqual(.json, echo_post.response_mode);
    try std.testing.expectEqualStrings("application/json", health.content_type.?);
    try std.testing.expectEqualStrings("application/json", echo_get.content_type.?);
}

test "http3 smoke scenario points at the health route" {
    const scenario = smoke_runner.scenarioForRoute(.health).?;

    try std.testing.expectEqualStrings("request-https", scenario.name);

    const all = smoke_runner.defaultScenarios();
    try std.testing.expectEqualStrings("http3", all[5].name);
    try std.testing.expectEqual(interop_harness.RouteId.health, all[5].route.?);
    try std.testing.expectEqualStrings("zig", all[5].command.argv[0]);
    try std.testing.expectEqualStrings("test", all[5].command.argv[2]);
    try std.testing.expectEqualStrings("-Dhttp3=true", all[5].command.argv[3]);
}
