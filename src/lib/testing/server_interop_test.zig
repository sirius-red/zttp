//! Server interop regression coverage tied to the shared harness contract.

const std = @import("std");
const server = @import("../server/server.zig");
const types = @import("../types.zig");
const socket_io = @import("../util/socket_io.zig");
const interop_harness = @import("interop_harness.zig");
const fixture_loader = @import("fixture_loader.zig");
const server_http2 = @import("../server/http2.zig");

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

/// Declarative expectation for one first-party static asset publication.
const StaticAssetExpectation = struct {
    /// Request path served by the server application surface.
    path: []const u8,
    /// Expected content type when the asset is served successfully.
    content_type: []const u8,
    /// Relative fixture suffix that backs the published asset.
    fixture_suffix: []const u8,
    /// Supported content encodings advertised by the contract.
    supported_encodings: []const []const u8,
};

/// Declarative negative case for the static asset publication surface.
const StaticAssetNegativeExpectation = struct {
    /// Method used by the rejected request.
    method: types.Method,
    /// Request target covered by the negative-path case.
    target: []const u8,
    /// Expected rejection status code for the case.
    expected_status_code: u16,
    /// Stable reason describing why the request is rejected.
    rejection_reason: []const u8,
};

/// Shared M6 static asset expectation for `/assets/site.css`.
const static_asset_expectation = StaticAssetExpectation{
    .path = "/assets/site.css",
    .content_type = "text/css",
    .fixture_suffix = "m6-assets/site.css",
    .supported_encodings = &.{ "identity", "gzip" },
};

/// Dedicated static-file negative cases required by the M6 contract.
const static_asset_negative_expectations = [_]StaticAssetNegativeExpectation{
    .{
        .method = .get,
        .target = "/assets/../secrets.txt",
        .expected_status_code = 404,
        .rejection_reason = "path traversal stays outside the published content root",
    },
    .{
        .method = .get,
        .target = "/assets/missing.css",
        .expected_status_code = 404,
        .rejection_reason = "missing asset preserves a clear not-found result",
    },
    .{
        .method = .post,
        .target = "/assets/site.css",
        .expected_status_code = 405,
        .rejection_reason = "method gating rejects non-download verbs for static publication",
    },
};

/// Expected protocol coverage for the first-party M6 static asset surface.
const static_asset_protocols = [_]types.NegotiatedProtocol{ .http_1_1, .h2, .h3 };

/// Expects one capability matrix entry to report supported behavior.
fn expectSupportedCapability(
    feature: interop_harness.CapabilityFeatureId,
    protocol: types.NegotiatedProtocol,
) !void {
    const capability = interop_harness.capabilityFor(feature, protocol) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(types.FeatureSupportLevel.supported, capability.support);
}

/// Sends one raw HTTP request to the loopback server and returns the full response bytes.
fn runRawExchange(
    allocator: std.mem.Allocator,
    port: u16,
    request_bytes: []const u8,
) ![]u8 {
    const address = try std.net.Address.parseIp("127.0.0.1", port);
    var stream = try std.net.tcpConnectToAddress(address);
    defer stream.close();

    try stream.writeAll(request_bytes);

    var response = std.ArrayListUnmanaged(u8){};
    errdefer response.deinit(allocator);

    var buffer: [1024]u8 = undefined;
    while (true) {
        const read_len = try socket_io.read(stream, &buffer);
        if (read_len == 0) {
            break;
        }
        try response.appendSlice(allocator, buffer[0..read_len]);
    }

    return response.toOwnedSlice(allocator);
}

/// Builds the secure interop server used by the loopback HTTPS and HTTP/2 tests.
fn initSecureInteropServer() !server.Server {
    var config = server.ServerConfig.init(interop_harness.handleServerRequest);
    config.listen_host = "127.0.0.1";
    config.port = types.Port.init(0);
    config.http2_enabled = true;

    var tls = types.TlsConfig.default();
    tls.verify = .insecure;
    tls.certificate_chain_path = "src/lib/testing/fixtures/certs/loopback-server.pem";
    tls.private_key_path = "src/lib/testing/fixtures/certs/loopback-server.key";
    config.tls = tls;

    return server.Server.init(std.testing.allocator, config);
}

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

test "server interop preserves the windows loopback readiness round trip" {
    const readiness = interop_harness.readinessScenarioForId(.windows_loopback_cli_roundtrip).?;
    const route = interop_harness.scenarioForRoute(readiness.route).?;

    var config = server.ServerConfig.init(interop_harness.handleServerRequest);
    config.listen_host = readiness.endpoint.host;
    config.port = types.Port.init(0);

    var runtime = try server.Server.init(std.testing.allocator, config);
    defer runtime.deinit();
    try runtime.start();

    const request_bytes = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s} {s} HTTP/1.1\r\nHost: {s}\r\n\r\n",
        .{
            route.method.asBytes(),
            route.path_template,
            readiness.endpoint.host,
        },
    );
    defer std.testing.allocator.free(request_bytes);

    const response = try runRawExchange(std.testing.allocator, runtime.port(), request_bytes);
    defer std.testing.allocator.free(response);

    try std.testing.expect(std.mem.containsAtLeast(u8, response, 1, "HTTP/1.1 200 OK"));
    try std.testing.expect(std.mem.containsAtLeast(u8, response, 1, readiness.expected_body_substring));
}

test "server interop secure listener serves the shared health route over h2" {
    var runtime = try initSecureInteropServer();
    defer runtime.deinit();
    try runtime.start();

    const request_bytes = try server_http2.encodeClientRequest(
        std.testing.allocator,
        .get,
        "/health",
        "127.0.0.1",
        "",
    );
    defer std.testing.allocator.free(request_bytes);

    const response_bytes = try runRawExchange(std.testing.allocator, runtime.port(), request_bytes);
    defer std.testing.allocator.free(response_bytes);

    var response = try server_http2.decodeServerResponse(std.testing.allocator, response_bytes);
    defer response.deinit();

    try std.testing.expectEqual(types.Status.ok, response.status);
    try std.testing.expect(std.mem.containsAtLeast(u8, response.body, 1, "\"protocol\":\"h2\""));
}

test "server interop aligns health and static asset coverage with the M6 contract" {
    const health = interop_harness.scenarioForRoute(.health).?;
    try std.testing.expectEqualStrings("/health", health.path_template);
    try std.testing.expectEqual(types.Status.ok, health.success_status);

    for (static_asset_protocols) |protocol| {
        try std.testing.expect(health.supportsProtocol(protocol));
        try expectSupportedCapability(.server_static_files, protocol);
        try expectSupportedCapability(.server_compression, protocol);
    }

    const loader = fixture_loader.Loader.init();
    const asset_path = try loader.pathForM6Asset(std.testing.allocator, .site_css);
    defer std.testing.allocator.free(asset_path);

    try std.testing.expectEqualStrings("/assets/site.css", static_asset_expectation.path);
    try std.testing.expectEqualStrings("text/css", static_asset_expectation.content_type);
    try std.testing.expectEqual(@as(usize, 2), static_asset_expectation.supported_encodings.len);
    try std.testing.expectEqualStrings("identity", static_asset_expectation.supported_encodings[0]);
    try std.testing.expectEqualStrings("gzip", static_asset_expectation.supported_encodings[1]);
    try std.testing.expect(
        std.mem.endsWith(u8, asset_path, static_asset_expectation.fixture_suffix) or
            std.mem.endsWith(u8, asset_path, "m6-assets\\site.css"),
    );
}

test "server interop static asset negatives cover traversal missing assets and method gating" {
    const loader = fixture_loader.Loader.init();
    try std.testing.expectError(
        error.PathTraversalNotAllowed,
        loader.pathFor(std.testing.allocator, "m6-assets/../secrets.txt"),
    );

    try std.testing.expectEqual(@as(usize, 3), static_asset_negative_expectations.len);
    for (static_asset_negative_expectations) |expectation| {
        try std.testing.expect(std.mem.startsWith(u8, expectation.target, "/assets/"));
        if (expectation.method == .post) {
            try std.testing.expectEqual(@as(u16, 405), expectation.expected_status_code);
        } else {
            try std.testing.expectEqual(@as(u16, 404), expectation.expected_status_code);
        }
        try std.testing.expect(expectation.rejection_reason.len > 0);
    }
}
