//! Regression coverage for the HTTP/1.1 loopback connection path.

const std = @import("std");
const types = @import("../types.zig");
const connection_h1 = @import("connection_h1.zig");
const test_server = @import("test_server.zig");

/// Creates a loopback GET request for the provided path.
fn initLoopbackRequest(port: u16, path: []const u8) !types.Request {
    const uri = types.Uri.init(.http, "127.0.0.1", types.Port.init(port), path, null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    errdefer request.deinit();
    try request.headers.append("Host", "127.0.0.1");
    return request;
}

/// Creates an HTTP/1.1 loopback connection for the provided server port.
fn initLoopbackConnection(port: u16) !connection_h1.ConnectionH1 {
    return connection_h1.ConnectionH1.init(
        std.testing.allocator,
        .{
            .scheme = .http,
            .host = "127.0.0.1",
            .port = types.Port.init(port),
            .target_mode = .origin_form,
            .tunnel = null,
            .proxy_authorization = null,
        },
        connection_h1.Options.default(),
    );
}

test "connection completes the loopback health response" {
    const scenarios = [_]test_server.Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{
                        .response = .{
                            .status = .ok,
                            .reason = "OK",
                            .headers = &.{
                                .{ .name = "Content-Type", .value = "application/json" },
                            },
                            .body = "{\"status\":\"ok\",\"protocol\":\"http/1.1\"}",
                        },
                    },
                },
            },
        },
    };

    var server = try test_server.TestServer.init(&scenarios, test_server.Options.default());
    defer server.deinit();
    try server.start();

    var conn = try initLoopbackConnection(server.port());
    defer conn.deinit();
    try conn.start();

    var request = try initLoopbackRequest(server.port(), "/health");
    defer request.deinit();

    var response_future = connection_h1.ResponseFuture.init();
    try conn.submit(&request, response_future.completion());

    var response = try response_future.wait();
    defer response.deinit();
    defer if (response.body) |body| body.close();

    try std.testing.expectEqual(types.Status.ok, response.status);

    var body = std.ArrayList(u8).empty;
    defer body.deinit(std.testing.allocator);
    var buffer: [64]u8 = undefined;
    while (true) {
        const read_len = try response.body.?.read(&buffer);
        if (read_len == 0) {
            break;
        }
        try body.appendSlice(std.testing.allocator, buffer[0..read_len]);
    }

    try std.testing.expectEqualStrings(
        "{\"status\":\"ok\",\"protocol\":\"http/1.1\"}",
        body.items,
    );
}

test "connection translates a loopback socket close into transport" {
    const scenarios = [_]test_server.Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{ .raw = "" },
                },
            },
        },
    };

    var server = try test_server.TestServer.init(&scenarios, test_server.Options.default());
    defer server.deinit();
    try server.start();

    var conn = try initLoopbackConnection(server.port());
    defer conn.deinit();
    try conn.start();

    var request = try initLoopbackRequest(server.port(), "/health");
    defer request.deinit();

    var response_future = connection_h1.ResponseFuture.init();
    try conn.submit(&request, response_future.completion());

    try std.testing.expectError(error.Transport, response_future.wait());
}
