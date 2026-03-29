//! HTTP/3 interop regression coverage tied to the shared harness contract.

const std = @import("std");
const http3 = @import("../http3/http3.zig");
const http3_client = @import("../http3/client.zig");
const quic = @import("../http3/quic.zig");
const runtime = @import("../server/runtime.zig");
const server_types = @import("../server/types.zig");
const types = @import("../types.zig");
const interop_harness = @import("interop_harness.zig");
const smoke_runner = @import("smoke_runner.zig");
const testing_helpers = @import("testing.zig");

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

test "http3 interop coverage is enabled by default" {
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
    try std.testing.expectEqualStrings("run", all[5].command.argv[2]);
    try std.testing.expectEqualStrings("request", all[5].command.argv[4]);
    try std.testing.expectEqualStrings("--http3", all[5].command.argv[5]);
}

test "http3 smoke scenario uses the default build path" {
    const readiness_scenarios = interop_harness.defaultReadinessScenarios();
    try std.testing.expect(readiness_scenarios.len > 0);

    for (readiness_scenarios) |scenario| {
        try std.testing.expect(scenario.blocking);
        try std.testing.expectEqual(.tcp, scenario.endpoint.transport);
        for (scenario.server_command.argv) |arg| {
            try std.testing.expect(!std.mem.eql(u8, arg, "-Dhttp3=true"));
        }
        for (scenario.request_command.argv) |arg| {
            try std.testing.expect(!std.mem.eql(u8, arg, "-Dhttp3=true"));
        }
    }

    const smoke_scenarios = smoke_runner.defaultScenarios();
    try std.testing.expect(smoke_scenarios.len >= 6);

    for (smoke_scenarios) |scenario| {
        for (scenario.command.argv) |arg| {
            try std.testing.expect(!std.mem.eql(u8, arg, "-Dhttp3=true"));
        }
    }

    const http3_scenario = smoke_scenarios[smoke_scenarios.len - 1];
    try std.testing.expectEqualStrings("http3", http3_scenario.name);
    try std.testing.expectEqualStrings("--http3", http3_scenario.command.argv[5]);
}

test "http3 disturbance coverage classifies basic loss duplication and reordering predictably" {
    const scenario = interop_harness.http3DatagramScenarioForRoute(.stream_large).?;
    try std.testing.expectEqual(
        @as(?interop_harness.LocalDisturbanceProfileId, .basic),
        scenario.runtime.disturbance_profile,
    );
    try std.testing.expectEqual(@as(usize, 4), scenario.runtime.disturbance_kinds.len);

    var client = quic.Session.init(std.testing.allocator, "client01".*, "server01".*);
    defer client.deinit();
    var server = quic.Session.init(std.testing.allocator, "server01".*, "client01".*);
    defer server.deinit();
    client.beginHandshake();
    client.establish();
    server.beginHandshake();
    server.establish();

    const stream_a = try client.openStream(.bidirectional);
    const stream_b = try client.openStream(.bidirectional);
    try std.testing.expectEqual(@as(u64, 0), stream_a);
    try std.testing.expectEqual(@as(u64, 4), stream_b);

    const first = try client.protectPacket(std.testing.allocator, .application, "stream-a");
    defer std.testing.allocator.free(first);
    const second = try client.protectPacket(std.testing.allocator, .application, "stream-b");
    defer std.testing.allocator.free(second);

    var second_packet = try server.unprotectPacket(std.testing.allocator, second);
    defer second_packet.deinit(std.testing.allocator);
    try std.testing.expectEqual(quic.PacketDeliveryState.fresh, second_packet.delivery_state);
    try std.testing.expectEqualStrings("stream-b", second_packet.payload);

    var first_packet = try server.unprotectPacket(std.testing.allocator, first);
    defer first_packet.deinit(std.testing.allocator);
    try std.testing.expectEqual(quic.PacketDeliveryState.reordered, first_packet.delivery_state);
    try std.testing.expectEqualStrings("stream-a", first_packet.payload);

    var duplicate_packet = try server.unprotectPacket(std.testing.allocator, first);
    defer duplicate_packet.deinit(std.testing.allocator);
    try std.testing.expectEqual(quic.PacketDeliveryState.duplicate, duplicate_packet.delivery_state);

    const retransmitted = try client.retransmitLostPacket(std.testing.allocator, .application, 0);
    defer std.testing.allocator.free(retransmitted);
    var recovered = try server.unprotectPacket(std.testing.allocator, retransmitted);
    defer recovered.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("stream-a", recovered.payload);
}

test "http3 runtime preserves repeated header values with connection scoped qpack state" {
    const EchoHeaders = struct {
        fn handle(
            _: ?*anyopaque,
            request: *server_types.ServerRequest,
            writer: *server_types.ServerResponseWriter,
        ) !void {
            writer.setStatus(.ok);
            try writer.appendHeader("Content-Type", "application/json");
            if (request.header("x-state")) |value| {
                try writer.appendHeader("X-State", value);
            }
            if (request.header("x-variant")) |value| {
                try writer.appendHeader("X-Variant", value);
            }
            try writer.writeAll("{\"protocol\":\"h3\"}");
        }
    };

    var config = server_types.ServerConfig.init(EchoHeaders.handle);
    config.port = types.Port.init(0);
    var http3_config = server_types.Http3ListenerConfig.init();
    http3_config.port = types.Port.init(0);
    config.http3 = http3_config;

    var server = try runtime.Server.init(std.testing.allocator, config);
    defer server.deinit();
    try server.start();

    const port = types.Port.init(server.http3Port().?);
    var session = try http3_client.RuntimeSession.init(std.testing.allocator, "127.0.0.1", port);
    defer session.deinit();

    var first_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", port, "/echo", null, null),
    );
    defer first_request.deinit();
    try first_request.headers.append("Host", "127.0.0.1");
    try first_request.headers.append("X-State", "alpha");
    try first_request.headers.append("X-Variant", "one");

    var first_response = try session.executeRequest(&first_request);
    defer first_response.deinit();
    defer if (first_response.body) |body| body.close();
    try std.testing.expectEqual(types.Status.ok, first_response.status);
    try std.testing.expectEqualStrings("alpha", first_response.headers.get("x-state").?);
    try std.testing.expectEqualStrings("one", first_response.headers.get("x-variant").?);

    var second_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", port, "/echo", null, null),
    );
    defer second_request.deinit();
    try second_request.headers.append("Host", "127.0.0.1");
    try second_request.headers.append("X-State", "beta");
    try second_request.headers.append("X-Variant", "two");

    var second_response = try session.executeRequest(&second_request);
    defer second_response.deinit();
    defer if (second_response.body) |body| body.close();
    try std.testing.expectEqualStrings("beta", second_response.headers.get("x-state").?);
    try std.testing.expectEqualStrings("two", second_response.headers.get("x-variant").?);

    try std.testing.expect(session.qpack_state.encoder_stream.stream_id != null);
    try std.testing.expect(session.qpack_state.decoder_stream.stream_id != null);
    try std.testing.expect(session.qpack_state.encoder_table.entries.items.len >= 8);
    try std.testing.expect(session.qpack_state.decoder_table.entries.items.len >= 4);

    if (server.http3_runtime) |*http3_runtime| {
        try std.testing.expectEqual(@as(usize, 1), http3_runtime.sessions.items.len);
        const listener_session = &http3_runtime.sessions.items[0].session;
        try std.testing.expectEqual(http3.CriticalStreamStatus.ready, listener_session.control_plane.critical_stream_status);
        try std.testing.expect(listener_session.qpack_state.encoder_stream.stream_id != null);
        try std.testing.expect(listener_session.qpack_state.decoder_stream.stream_id != null);
        try std.testing.expect(listener_session.qpack_state.decoder_table.entries.items.len >= 8);
        try std.testing.expect(listener_session.qpack_state.encoder_table.entries.items.len >= 6);
    } else {
        return error.TestUnexpectedResult;
    }
}

test "http3 runtime serves repeated health requests on one retained session" {
    var config = server_types.ServerConfig.init(interop_harness.handleServerRequest);
    config.port = types.Port.init(0);
    var http3_config = testing_helpers.Http3Runtime.defaultListenerConfig();
    http3_config.port = types.Port.init(0);
    config.http3 = http3_config;

    var server = try runtime.Server.init(std.testing.allocator, config);
    defer server.deinit();
    try server.start();

    const port = types.Port.init(server.http3Port().?);
    var session = try http3_client.RuntimeSession.init(std.testing.allocator, "127.0.0.1", port);
    defer session.deinit();

    var count: usize = 0;
    while (count < testing_helpers.Http3Runtime.defaultExpectations().sequential_requests_without_restart) : (count += 1) {
        var request = types.Request.init(
            std.testing.allocator,
            .get,
            types.Uri.init(.https, "127.0.0.1", port, "/health", null, null),
        );
        defer request.deinit();
        try request.headers.append("Host", "127.0.0.1");

        var response = try session.executeRequest(&request);
        defer response.deinit();
        defer if (response.body) |body| body.close();

        try std.testing.expectEqual(types.Status.ok, response.status);
    }

    if (server.http3_runtime) |*http3_runtime| {
        try std.testing.expectEqual(@as(usize, 1), http3_runtime.sessions.items.len);
    } else {
        return error.TestUnexpectedResult;
    }
}

test "http3 runtime keeps multi-session and multi-stream state isolated" {
    var config = server_types.ServerConfig.init(interop_harness.handleServerRequest);
    config.port = types.Port.init(0);
    var http3_config = testing_helpers.Http3Runtime.defaultListenerConfig();
    http3_config.port = types.Port.init(0);
    http3_config.session_limits.max_sessions = types.ConnectionCount.init(2);
    http3_config.session_limits.max_streams_per_session = types.ConnectionCount.init(2);
    config.http3 = http3_config;

    var server = try runtime.Server.init(std.testing.allocator, config);
    defer server.deinit();
    try server.start();

    const port = types.Port.init(server.http3Port().?);
    var session_a = try http3_client.RuntimeSession.init(std.testing.allocator, "127.0.0.1", port);
    defer session_a.deinit();
    var session_b = try http3_client.RuntimeSession.init(std.testing.allocator, "127.0.0.1", port);
    defer session_b.deinit();

    const session_paths = [_][]const u8{ "/health", "/echo" };
    for (session_paths) |path| {
        var request_a = types.Request.init(
            std.testing.allocator,
            .get,
            types.Uri.init(.https, "127.0.0.1", port, path, null, null),
        );
        defer request_a.deinit();
        try request_a.headers.append("Host", "127.0.0.1");
        try request_a.headers.append("X-Session", "a");

        var response_a = try session_a.executeRequest(&request_a);
        defer response_a.deinit();
        defer if (response_a.body) |body| body.close();
        try std.testing.expectEqual(types.Status.ok, response_a.status);

        var request_b = types.Request.init(
            std.testing.allocator,
            .get,
            types.Uri.init(.https, "127.0.0.1", port, path, null, null),
        );
        defer request_b.deinit();
        try request_b.headers.append("Host", "127.0.0.1");
        try request_b.headers.append("X-Session", "b");

        var response_b = try session_b.executeRequest(&request_b);
        defer response_b.deinit();
        defer if (response_b.body) |body| body.close();
        try std.testing.expectEqual(types.Status.ok, response_b.status);
    }

    if (server.http3_runtime) |*http3_runtime| {
        try std.testing.expectEqual(@as(usize, 2), http3_runtime.sessions.items.len);
        for (http3_runtime.sessions.items) |record| {
            try std.testing.expect(record.session.connection.stream_registry.bidirectional.items.len >= 2);
            try std.testing.expectEqual(@as(usize, 0), record.session.connection.activeStreamCount(.bidirectional));
        }
    } else {
        return error.TestUnexpectedResult;
    }
}
