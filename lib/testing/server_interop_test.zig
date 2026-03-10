//! Server interop regression coverage tied to the shared harness contract.

const std = @import("std");
const types = @import("../types.zig");
const interop_harness = @import("interop_harness.zig");

/// Declarative expectation for one server interop route.
pub const RouteExpectation = struct {
    /// Stable route identifier from the shared harness contract.
    route: interop_harness.RouteId,
    /// Path template the server must expose.
    path_template: []const u8,
    /// Success status returned by the route.
    success_status: types.Status,
    /// Response mode returned by the route.
    response_mode: interop_harness.ResponseMode,
    /// Whether the route participates in TLS validation.
    tls_supported: bool,
};

const required_routes = [_]RouteExpectation{
    .{
        .route = .health,
        .path_template = "/health",
        .success_status = .ok,
        .response_mode = .json,
        .tls_supported = true,
    },
    .{
        .route = .echo_get,
        .path_template = "/echo",
        .success_status = .ok,
        .response_mode = .json,
        .tls_supported = true,
    },
    .{
        .route = .echo_post,
        .path_template = "/echo",
        .success_status = .ok,
        .response_mode = .json,
        .tls_supported = true,
    },
    .{
        .route = .redirect_count,
        .path_template = "/redirect/{count}",
        .success_status = .found,
        .response_mode = .redirect,
        .tls_supported = true,
    },
    .{
        .route = .cookies_set,
        .path_template = "/cookies/set",
        .success_status = .no_content,
        .response_mode = .no_content,
        .tls_supported = true,
    },
    .{
        .route = .cookies_read,
        .path_template = "/cookies/read",
        .success_status = .ok,
        .response_mode = .json,
        .tls_supported = true,
    },
    .{
        .route = .stream_chunked,
        .path_template = "/stream/chunked",
        .success_status = .ok,
        .response_mode = .text_stream,
        .tls_supported = true,
    },
    .{
        .route = .stream_large,
        .path_template = "/stream/large",
        .success_status = .ok,
        .response_mode = .binary_stream,
        .tls_supported = true,
    },
};

test "server interop catalog covers required contract routes" {
    try std.testing.expectEqual(@as(usize, 8), required_routes.len);

    for (required_routes) |expectation| {
        const scenario = interop_harness.scenarioForRoute(expectation.route).?;
        try std.testing.expectEqualStrings(expectation.path_template, scenario.path_template);
        try std.testing.expectEqual(expectation.success_status, scenario.success_status);
        try std.testing.expectEqual(expectation.response_mode, scenario.response_mode);
    }
}

test "server interop catalog preserves tls and protocol coverage" {
    for (required_routes) |expectation| {
        const scenario = interop_harness.scenarioForRoute(expectation.route).?;
        try std.testing.expectEqual(expectation.tls_supported, scenario.tls_supported);
        try std.testing.expect(scenario.supportsProtocol(.http_1_1));
        try std.testing.expect(scenario.supportsProtocol(.h2));
    }
}

test "server interop catalog retains cookie and streaming semantics" {
    const cookie_set = interop_harness.scenarioForRoute(.cookies_set).?;
    const cookie_read = interop_harness.scenarioForRoute(.cookies_read).?;
    const chunked = interop_harness.scenarioForRoute(.stream_chunked).?;
    const large = interop_harness.scenarioForRoute(.stream_large).?;

    try std.testing.expectEqual(types.Status.no_content, cookie_set.success_status);
    try std.testing.expectEqual(.json, cookie_read.response_mode);
    try std.testing.expectEqual(.text_stream, chunked.response_mode);
    try std.testing.expectEqual(.binary_stream, large.response_mode);
}
