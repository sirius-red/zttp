//! Regression coverage for the dedicated HTTP/2 runtime.

const std = @import("std");
const types = @import("../types.zig");
const connection_h2 = @import("connection_h2.zig");

/// Polls until the runtime reports stream-scoped backpressure.
fn waitForStreamBackpressure(runtime: *connection_h2.ConnectionH2) !connection_h2.Snapshot {
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        const snapshot = runtime.snapshot();
        if (snapshot.saw_stream_backpressure) {
            return snapshot;
        }
        std.Thread.sleep(std.time.ns_per_ms);
    }
    return error.Timeout;
}

/// Polls until the runtime reports connection-scoped backpressure.
fn waitForConnectionBackpressure(runtime: *connection_h2.ConnectionH2) !connection_h2.Snapshot {
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        const snapshot = runtime.snapshot();
        if (snapshot.saw_connection_backpressure) {
            return snapshot;
        }
        std.Thread.sleep(std.time.ns_per_ms);
    }
    return error.Timeout;
}

/// Polls until the runtime enters the draining state after GOAWAY begins.
fn waitForDraining(runtime: *connection_h2.ConnectionH2) !connection_h2.Snapshot {
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        const snapshot = runtime.snapshot();
        if (snapshot.state == .draining and !snapshot.reusable) {
            return snapshot;
        }
        std.Thread.sleep(std.time.ns_per_ms);
    }
    return error.Timeout;
}

test "connection_h2 runtime tracks concurrent stream identifiers" {
    var runtime = connection_h2.ConnectionH2.init(
        std.testing.allocator,
        "127.0.0.1",
        types.Port.init(18443),
        connection_h2.Options.default(),
    );
    defer runtime.deinit();
    try runtime.start();

    var health_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(18443), "/health", null, null),
    );
    defer health_request.deinit();
    try health_request.headers.append("Host", "127.0.0.1");

    var echo_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(18443), "/echo", null, null),
    );
    defer echo_request.deinit();
    try echo_request.headers.append("Host", "127.0.0.1");

    var health_future = connection_h2.ResponseFuture.init();
    var echo_future = connection_h2.ResponseFuture.init();
    try runtime.submit(&health_request, health_future.completion());
    try runtime.submit(&echo_request, echo_future.completion());

    var health_response = try health_future.wait();
    defer health_response.deinit();
    defer if (health_response.body) |body| body.close();
    var echo_response = try echo_future.wait();
    defer echo_response.deinit();
    defer if (echo_response.body) |body| body.close();

    const snapshot = runtime.snapshot();
    try std.testing.expect(snapshot.max_overlapping_streams >= 2);
    try std.testing.expectEqual(@as(u31, 5), snapshot.next_stream_id);
}

test "connection_h2 runtime records backpressure scopes" {
    var options = connection_h2.Options.default();
    options.max_stream_buffer_bytes = types.ByteSize.fromBytes(512);
    options.max_connection_buffer_bytes = types.ByteSize.fromBytes(768);

    var runtime = connection_h2.ConnectionH2.init(
        std.testing.allocator,
        "127.0.0.1",
        types.Port.init(18443),
        options,
    );
    defer runtime.deinit();
    try runtime.start();

    var large_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(18443), "/stream/large", null, null),
    );
    defer large_request.deinit();
    try large_request.headers.append("Host", "127.0.0.1");

    var second_large_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(18443), "/stream/large", null, null),
    );
    defer second_large_request.deinit();
    try second_large_request.headers.append("Host", "127.0.0.1");

    var large_future = connection_h2.ResponseFuture.init();
    try runtime.submit(&large_request, large_future.completion());

    var large_response = try large_future.wait();
    defer large_response.deinit();
    defer if (large_response.body) |body| body.close();
    _ = try waitForStreamBackpressure(&runtime);

    var second_large_future = connection_h2.ResponseFuture.init();
    try runtime.submit(&second_large_request, second_large_future.completion());
    var second_large_response = try second_large_future.wait();
    defer second_large_response.deinit();
    defer if (second_large_response.body) |body| body.close();

    const snapshot = try waitForConnectionBackpressure(&runtime);
    try std.testing.expect(snapshot.saw_stream_backpressure);
    try std.testing.expect(snapshot.saw_connection_backpressure);
}

test "connection_h2 runtime keeps stream resets scoped" {
    var runtime = connection_h2.ConnectionH2.init(
        std.testing.allocator,
        "127.0.0.1",
        types.Port.init(18443),
        connection_h2.Options.default(),
    );
    defer runtime.deinit();
    try runtime.start();

    var rst_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(18443), "/stream/chunked", "action=rst", null),
    );
    defer rst_request.deinit();
    try rst_request.headers.append("Host", "127.0.0.1");

    var health_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(18443), "/health", null, null),
    );
    defer health_request.deinit();
    try health_request.headers.append("Host", "127.0.0.1");

    var rst_future = connection_h2.ResponseFuture.init();
    var health_future = connection_h2.ResponseFuture.init();
    try runtime.submit(&rst_request, rst_future.completion());
    try runtime.submit(&health_request, health_future.completion());

    var rst_response = try rst_future.wait();
    defer rst_response.deinit();
    defer if (rst_response.body) |body| body.close();
    var buffer: [32]u8 = undefined;
    _ = try rst_response.body.?.read(&buffer);
    try std.testing.expectError(error.Protocol, rst_response.body.?.read(&buffer));

    var health_response = try health_future.wait();
    defer health_response.deinit();
    defer if (health_response.body) |body| body.close();
    try std.testing.expectEqual(types.Status.ok, health_response.status);
}

test "connection_h2 runtime marks goaway as connection-scoped drain" {
    var runtime = connection_h2.ConnectionH2.init(
        std.testing.allocator,
        "127.0.0.1",
        types.Port.init(18443),
        connection_h2.Options.default(),
    );
    defer runtime.deinit();
    try runtime.start();

    var goaway_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(18443), "/stream/chunked", "action=goaway", null),
    );
    defer goaway_request.deinit();
    try goaway_request.headers.append("Host", "127.0.0.1");

    var goaway_future = connection_h2.ResponseFuture.init();
    try runtime.submit(&goaway_request, goaway_future.completion());
    var goaway_response = try goaway_future.wait();
    defer goaway_response.deinit();
    defer if (goaway_response.body) |body| body.close();

    const snapshot = try waitForDraining(&runtime);
    try std.testing.expectEqual(.draining, snapshot.state);
    try std.testing.expect(!snapshot.reusable);
}
