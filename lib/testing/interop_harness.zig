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

/// Socket transport used by a harness scenario.
pub const Transport = enum {
    /// TCP listener or client flow.
    tcp,
    /// UDP datagram listener or client flow.
    udp,
};

/// Endpoint metadata attached to a harness scenario.
pub const Endpoint = struct {
    /// Host advertised by the harness.
    host: []const u8,
    /// Port advertised by the harness.
    port: types.Port,
    /// Socket transport used by the scenario.
    transport: Transport,
    /// Application protocol expected on the endpoint.
    protocol: types.NegotiatedProtocol,
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

/// Semantic request shared across TCP and UDP harness implementations.
pub const SemanticRequest = struct {
    /// HTTP method for the request.
    method: types.Method,
    /// Request path without a query suffix.
    path: []const u8,
    /// Optional query string without a leading `?`.
    query: ?[]const u8,
    /// Negotiated application protocol for the route.
    negotiated_protocol: types.NegotiatedProtocol,
    /// Fully buffered request body.
    body: []const u8,
    /// Observed `Cookie` header, if present.
    cookie_header: ?[]const u8,
};

/// Owned response returned by the semantic harness helpers.
pub const SemanticResponse = struct {
    /// Allocator used for headers and body storage.
    allocator: std.mem.Allocator,
    /// Response status code.
    status: types.Status,
    /// Response headers.
    headers: types.Headers,
    /// Fully buffered response body.
    body: []u8,

    /// Releases the owned headers and body bytes.
    pub fn deinit(self: *SemanticResponse) void {
        self.headers.deinit();
        self.allocator.free(self.body);
        self.* = undefined;
    }
};

/// UDP-focused HTTP/3 scenario metadata.
pub const Http3DatagramScenario = struct {
    /// Route served by the datagram scenario.
    route: RouteId,
    /// UDP endpoint used for the scenario.
    endpoint: Endpoint,
    /// Suggested maximum datagram size.
    max_datagram_size: usize,
    /// Maximum buffered application data for the scenario.
    datagram_budget: usize,
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

const default_http3_datagram_scenarios = [_]Http3DatagramScenario{
    .{
        .route = .health,
        .endpoint = .{
            .host = "127.0.0.1",
            .port = types.Port.init(4433),
            .transport = .udp,
            .protocol = .h3,
        },
        .max_datagram_size = 1200,
        .datagram_budget = 16 * 1024,
    },
    .{
        .route = .echo_get,
        .endpoint = .{
            .host = "127.0.0.1",
            .port = types.Port.init(4433),
            .transport = .udp,
            .protocol = .h3,
        },
        .max_datagram_size = 1200,
        .datagram_budget = 16 * 1024,
    },
    .{
        .route = .echo_post,
        .endpoint = .{
            .host = "127.0.0.1",
            .port = types.Port.init(4433),
            .transport = .udp,
            .protocol = .h3,
        },
        .max_datagram_size = 1200,
        .datagram_budget = 64 * 1024,
    },
    .{
        .route = .stream_large,
        .endpoint = .{
            .host = "127.0.0.1",
            .port = types.Port.init(4433),
            .transport = .udp,
            .protocol = .h3,
        },
        .max_datagram_size = 1200,
        .datagram_budget = 96 * 1024,
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

/// Returns the UDP-focused HTTP/3 scenario catalog.
pub fn defaultHttp3DatagramScenarios() []const Http3DatagramScenario {
    return &default_http3_datagram_scenarios;
}

/// Returns the UDP-focused HTTP/3 scenario for the provided route, if any.
pub fn http3DatagramScenarioForRoute(route: RouteId) ?Http3DatagramScenario {
    for (default_http3_datagram_scenarios) |scenario| {
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

/// Builds a semantic response for a shared harness request.
pub fn buildSemanticResponse(
    allocator: std.mem.Allocator,
    request: SemanticRequest,
) !SemanticResponse {
    const route = matchRoute(request.method, request.path) orelse {
        var headers = types.Headers.init(allocator);
        errdefer headers.deinit();
        try headers.append("Content-Type", "application/json");
        return .{
            .allocator = allocator,
            .status = .not_found,
            .headers = headers,
            .body = try allocator.dupe(u8, "{\"error\":\"not_found\"}"),
        };
    };

    var headers = types.Headers.init(allocator);
    errdefer headers.deinit();

    var body = try allocator.alloc(u8, 0);
    errdefer allocator.free(body);
    var status = scenarioForRoute(route.route).?.success_status;

    switch (route.route) {
        .health => {
            allocator.free(body);
            try headers.append("Content-Type", "application/json");
            body = try std.fmt.allocPrint(
                allocator,
                "{{\"status\":\"ok\",\"protocol\":\"{s}\"}}",
                .{request.negotiated_protocol.asAlpnBytes()},
            );
        },
        .echo_get, .echo_post => {
            allocator.free(body);
            try headers.append("Content-Type", "application/json");
            body = try std.fmt.allocPrint(
                allocator,
                "{{\"method\":\"{s}\",\"path\":\"{s}\",\"protocol\":\"{s}\",\"body_size\":{d}}}",
                .{
                    request.method.asBytes(),
                    request.path,
                    request.negotiated_protocol.asAlpnBytes(),
                    request.body.len,
                },
            );
        },
        .redirect_count => {
            const count = route.redirect_count.?;
            if (count == 0) {
                status = .ok;
                allocator.free(body);
                try headers.append("Content-Type", "application/json");
                body = try allocator.dupe(u8, "{\"redirects_followed\":0}");
            } else {
                status = .found;
                const location = try std.fmt.allocPrint(allocator, "/redirect/{d}", .{count - 1});
                defer allocator.free(location);
                try headers.append("Location", location);
            }
        },
        .cookies_set => {
            const cookie_name = queryValue(request.query, "name") orelse "cookie";
            const cookie_value = queryValue(request.query, "value") orelse "value";
            const header = try std.fmt.allocPrint(
                allocator,
                "{s}={s}; Path=/",
                .{ cookie_name, cookie_value },
            );
            defer allocator.free(header);
            status = .no_content;
            try headers.append("Set-Cookie", header);
        },
        .cookies_read => {
            allocator.free(body);
            try headers.append("Content-Type", "application/json");
            body = try std.fmt.allocPrint(
                allocator,
                "{{\"cookie_header\":\"{s}\"}}",
                .{request.cookie_header orelse ""},
            );
        },
        .stream_chunked => {
            allocator.free(body);
            try headers.append("Content-Type", "text/plain");
            body = try allocator.dupe(u8, "chunk-one\nchunk-two\nchunk-three\n");
        },
        .stream_large => {
            allocator.free(body);
            try headers.append("Content-Type", "application/octet-stream");
            body = try allocator.alloc(u8, 64 * 1024);
            for (body, 0..) |*byte, index| {
                byte.* = @intCast(index % 251);
            }
        },
    }

    return .{
        .allocator = allocator,
        .status = status,
        .headers = headers,
        .body = body,
    };
}

/// Default in-repo handler that serves the interop-harness contract.
pub fn handleServerRequest(
    _: ?*anyopaque,
    request: *server_types.ServerRequest,
    writer: *server_types.ServerResponseWriter,
) !void {
    const body_bytes = try request.readBodyAlloc(request.allocator, 256 * 1024);
    defer request.allocator.free(body_bytes);

    var response = try buildSemanticResponse(request.allocator, .{
        .method = request.method,
        .path = request.uri.path,
        .query = request.uri.query,
        .negotiated_protocol = request.negotiated_protocol,
        .body = body_bytes,
        .cookie_header = request.header("cookie"),
    });
    defer response.deinit();

    writer.setStatus(response.status);
    var iterator = response.headers.iterator();
    while (iterator.next()) |header| {
        try writer.appendHeader(header.name, header.value);
    }
    if (response.body.len > 0) {
        try writer.writeAll(response.body);
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

test "semantic responses preserve http3 health and cookie semantics" {
    var response = try buildSemanticResponse(std.testing.allocator, .{
        .method = .get,
        .path = "/health",
        .query = null,
        .negotiated_protocol = .h3,
        .body = "",
        .cookie_header = null,
    });
    defer response.deinit();

    try std.testing.expectEqual(types.Status.ok, response.status);
    try std.testing.expectEqualStrings("application/json", response.headers.get("content-type").?);
    try std.testing.expect(std.mem.containsAtLeast(u8, response.body, 1, "\"protocol\":\"h3\""));

    var cookies = try buildSemanticResponse(std.testing.allocator, .{
        .method = .get,
        .path = "/cookies/read",
        .query = null,
        .negotiated_protocol = .http_1_1,
        .body = "",
        .cookie_header = "session=abc",
    });
    defer cookies.deinit();

    try std.testing.expect(std.mem.containsAtLeast(u8, cookies.body, 1, "session=abc"));
}

test "udp http3 scenarios advertise local health and echo coverage" {
    const scenarios = defaultHttp3DatagramScenarios();

    try std.testing.expectEqual(@as(usize, 4), scenarios.len);
    try std.testing.expectEqual(RouteId.health, scenarios[0].route);
    try std.testing.expectEqual(Transport.udp, scenarios[0].endpoint.transport);
    try std.testing.expectEqual(types.NegotiatedProtocol.h3, scenarios[1].endpoint.protocol);
    try std.testing.expectEqual(@as(usize, 64 * 1024), http3DatagramScenarioForRoute(.echo_post).?.datagram_budget);
}
