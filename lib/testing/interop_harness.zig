//! Semantic route definitions for the shared local interop harness.

const std = @import("std");
const types = @import("../types.zig");
const server_types = @import("../server/types.zig");

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

/// Route match result for a concrete request path.
pub const RouteMatch = struct {
    /// Matched route identifier.
    route: RouteId,
    /// Parsed redirect count for `/redirect/{count}`, when applicable.
    redirect_count: ?u32 = null,
};

/// Matches a method and path to one of the shared interop routes.
pub fn matchRoute(method: types.Method, path: []const u8) ?RouteMatch {
    if (method == .get and std.mem.eql(u8, path, "/health")) {
        return .{ .route = .health };
    }
    if (std.mem.eql(u8, path, "/echo")) {
        return .{
            .route = if (method == .post) .echo_post else .echo_get,
        };
    }
    if (method == .get and std.mem.startsWith(u8, path, "/redirect/")) {
        const count_bytes = path["/redirect/".len..];
        const count = std.fmt.parseInt(u32, count_bytes, 10) catch return null;
        return .{
            .route = .redirect_count,
            .redirect_count = count,
        };
    }
    if (method == .get and std.mem.eql(u8, path, "/cookies/set")) {
        return .{ .route = .cookies_set };
    }
    if (method == .get and std.mem.eql(u8, path, "/cookies/read")) {
        return .{ .route = .cookies_read };
    }
    if (method == .get and std.mem.eql(u8, path, "/stream/chunked")) {
        return .{ .route = .stream_chunked };
    }
    if (method == .get and std.mem.eql(u8, path, "/stream/large")) {
        return .{ .route = .stream_large };
    }
    return null;
}

/// Default in-repo handler that serves the interop-harness contract.
pub fn handleServerRequest(
    _: ?*anyopaque,
    request: *server_types.ServerRequest,
    writer: *server_types.ServerResponseWriter,
) !void {
    const route = matchRoute(request.method, request.uri.path) orelse {
        writer.setStatus(.not_found);
        try writer.appendHeader("Content-Type", "application/json");
        try writer.writeAll("{\"error\":\"not_found\"}");
        return;
    };

    switch (route.route) {
        .health => {
            const body = try std.fmt.allocPrint(
                request.allocator,
                "{{\"status\":\"ok\",\"protocol\":\"{s}\"}}",
                .{request.negotiated_protocol.asAlpnBytes()},
            );
            defer request.allocator.free(body);
            try writer.appendHeader("Content-Type", "application/json");
            try writer.writeAll(body);
        },
        .echo_get, .echo_post => {
            const body_bytes = try request.readBodyAlloc(
                request.allocator,
                256 * 1024,
            );
            defer request.allocator.free(body_bytes);

            const body = try std.fmt.allocPrint(
                request.allocator,
                "{{\"method\":\"{s}\",\"path\":\"{s}\",\"protocol\":\"{s}\",\"body_size\":{d}}}",
                .{
                    request.method.asBytes(),
                    request.uri.path,
                    request.negotiated_protocol.asAlpnBytes(),
                    body_bytes.len,
                },
            );
            defer request.allocator.free(body);
            try writer.appendHeader("Content-Type", "application/json");
            try writer.writeAll(body);
        },
        .redirect_count => {
            const count = route.redirect_count.?;
            if (count == 0) {
                try writer.appendHeader("Content-Type", "application/json");
                try writer.writeAll("{\"redirects_followed\":0}");
                return;
            }

            writer.setStatus(.found);
            const location = try std.fmt.allocPrint(request.allocator, "/redirect/{d}", .{count - 1});
            defer request.allocator.free(location);
            try writer.appendHeader("Location", location);
        },
        .cookies_set => {
            const cookie_name = queryValue(request.uri.query, "name") orelse "cookie";
            const cookie_value = queryValue(request.uri.query, "value") orelse "value";
            const header = try std.fmt.allocPrint(
                request.allocator,
                "{s}={s}; Path=/",
                .{ cookie_name, cookie_value },
            );
            defer request.allocator.free(header);
            writer.setStatus(.no_content);
            try writer.appendHeader("Set-Cookie", header);
        },
        .cookies_read => {
            const cookie_header = request.header("cookie") orelse "";
            const body = try std.fmt.allocPrint(
                request.allocator,
                "{{\"cookie_header\":\"{s}\"}}",
                .{cookie_header},
            );
            defer request.allocator.free(body);
            try writer.appendHeader("Content-Type", "application/json");
            try writer.writeAll(body);
        },
        .stream_chunked => {
            try writer.appendHeader("Content-Type", "text/plain");
            try writer.writeAll("chunk-one\n");
            try writer.writeAll("chunk-two\n");
            try writer.writeAll("chunk-three\n");
        },
        .stream_large => {
            try writer.appendHeader("Content-Type", "application/octet-stream");

            var chunk: [4096]u8 = undefined;
            for (&chunk, 0..) |*byte, index| {
                byte.* = @intCast(index % 251);
            }

            var remaining: usize = 64 * 1024;
            while (remaining > 0) {
                const to_write = @min(remaining, chunk.len);
                try writer.writeAll(chunk[0..to_write]);
                remaining -= to_write;
            }
        },
    }
}

/// Returns the first matching query value for the given key.
fn queryValue(query: ?[]const u8, name: []const u8) ?[]const u8 {
    const raw_query = query orelse return null;
    var pairs = std.mem.splitScalar(u8, raw_query, '&');
    while (pairs.next()) |pair| {
        var entry = std.mem.splitScalar(u8, pair, '=');
        const key = entry.next() orelse continue;
        const value = entry.next() orelse continue;
        if (std.mem.eql(u8, key, name)) {
            return value;
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

test "route matcher resolves contract endpoints" {
    try std.testing.expectEqual(RouteId.health, matchRoute(.get, "/health").?.route);
    try std.testing.expectEqual(RouteId.echo_post, matchRoute(.post, "/echo").?.route);
    try std.testing.expectEqual(@as(u32, 3), matchRoute(.get, "/redirect/3").?.redirect_count.?);
}
