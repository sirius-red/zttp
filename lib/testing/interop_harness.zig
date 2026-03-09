//! Semantic route definitions for the shared local interop harness.

const std = @import("std");
const types = @import("../types.zig");

/// Stable route identifier from the interop harness contract.
pub const RouteId = enum {
    /// `GET /health`
    health,
    /// `GET /echo`
    echo_get,
    /// `POST /echo`
    echo_post,
    /// `GET /redirect/{count}`
    redirect_count,
    /// `GET /cookies/set`
    cookies_set,
    /// `GET /cookies/read`
    cookies_read,
    /// `GET /stream/chunked`
    stream_chunked,
    /// `GET /stream/large`
    stream_large,
};

/// Response behavior expected from a route.
pub const ResponseMode = enum {
    /// JSON object response.
    json,
    /// Empty success response.
    no_content,
    /// Redirect response with a `Location` header.
    redirect,
    /// Chunked or streamed text payload.
    text_stream,
    /// Binary payload suitable for backpressure validation.
    binary_stream,
};

/// Declarative local harness scenario used across client, server, and CLI tests.
pub const Scenario = struct {
    /// Stable route identifier.
    route: RouteId,
    /// Method expected by the route.
    method: types.Method,
    /// Path template from the harness contract.
    path_template: []const u8,
    /// Protocols supported by the route.
    protocols_supported: []const types.NegotiatedProtocol,
    /// Expected success status for the route.
    success_status: types.Status,
    /// Response behavior mode.
    response_mode: ResponseMode,
    /// Content type returned by the route when applicable.
    content_type: ?[]const u8,
    /// Whether the route participates in TLS scenarios.
    tls_supported: bool,
    /// Optional negative-case note for dedicated failure tests.
    negative_case: ?[]const u8,

    /// Returns true when the route supports the protocol.
    pub fn supportsProtocol(self: Scenario, protocol: types.NegotiatedProtocol) bool {
        for (self.protocols_supported) |candidate| {
            if (candidate == protocol) {
                return true;
            }
        }
        return false;
    }
};

const route_protocols = [_]types.NegotiatedProtocol{ .http_1_1, .h2, .h3 };

const default_scenarios = [_]Scenario{
    .{
        .route = .health,
        .method = .get,
        .path_template = "/health",
        .protocols_supported = &route_protocols,
        .success_status = .ok,
        .response_mode = .json,
        .content_type = "application/json",
        .tls_supported = true,
        .negative_case = "advertise mismatched negotiated protocol metadata",
    },
    .{
        .route = .echo_get,
        .method = .get,
        .path_template = "/echo",
        .protocols_supported = &route_protocols,
        .success_status = .ok,
        .response_mode = .json,
        .content_type = "application/json",
        .tls_supported = true,
        .negative_case = "drop X-Echo metadata in the reflected response",
    },
    .{
        .route = .echo_post,
        .method = .post,
        .path_template = "/echo",
        .protocols_supported = &route_protocols,
        .success_status = .ok,
        .response_mode = .json,
        .content_type = "application/json",
        .tls_supported = true,
        .negative_case = "report the wrong body size for echoed payloads",
    },
    .{
        .route = .redirect_count,
        .method = .get,
        .path_template = "/redirect/{count}",
        .protocols_supported = &route_protocols,
        .success_status = .found,
        .response_mode = .redirect,
        .content_type = null,
        .tls_supported = true,
        .negative_case = "omit the Location header on intermediate redirects",
    },
    .{
        .route = .cookies_set,
        .method = .get,
        .path_template = "/cookies/set",
        .protocols_supported = &route_protocols,
        .success_status = .no_content,
        .response_mode = .no_content,
        .content_type = null,
        .tls_supported = true,
        .negative_case = "emit an invalid Set-Cookie header",
    },
    .{
        .route = .cookies_read,
        .method = .get,
        .path_template = "/cookies/read",
        .protocols_supported = &route_protocols,
        .success_status = .ok,
        .response_mode = .json,
        .content_type = "application/json",
        .tls_supported = true,
        .negative_case = "drop cookies that were set earlier in the scenario",
    },
    .{
        .route = .stream_chunked,
        .method = .get,
        .path_template = "/stream/chunked",
        .protocols_supported = &route_protocols,
        .success_status = .ok,
        .response_mode = .text_stream,
        .content_type = "text/plain",
        .tls_supported = true,
        .negative_case = "truncate a chunked response before the terminating chunk",
    },
    .{
        .route = .stream_large,
        .method = .get,
        .path_template = "/stream/large",
        .protocols_supported = &route_protocols,
        .success_status = .ok,
        .response_mode = .binary_stream,
        .content_type = "application/octet-stream",
        .tls_supported = true,
        .negative_case = "close the stream before the declared large body completes",
    },
};

/// Returns the default interop route catalog.
pub fn defaultScenarios() []const Scenario {
    return &default_scenarios;
}

/// Returns the route definition for the provided identifier, or null if absent.
pub fn scenarioForRoute(route: RouteId) ?Scenario {
    for (default_scenarios) |scenario| {
        if (scenario.route == route) {
            return scenario;
        }
    }
    return null;
}

test "route catalog includes contract endpoints" {
    const health = scenarioForRoute(.health).?;
    try std.testing.expectEqualStrings("/health", health.path_template);
    try std.testing.expect(health.supportsProtocol(.h2));

    const redirect = scenarioForRoute(.redirect_count).?;
    try std.testing.expectEqual(types.Status.found, redirect.success_status);
    try std.testing.expectEqual(ResponseMode.redirect, redirect.response_mode);
}
