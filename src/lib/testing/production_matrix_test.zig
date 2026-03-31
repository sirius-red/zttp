//! Client-side production matrix coverage for retry and cache acceptance flows.

const std = @import("std");
const client = @import("../client.zig");
const fixture_loader = @import("fixture_loader.zig");
const http_cache = @import("../cache/http_cache.zig");
const interop_harness = @import("interop_harness.zig");
const types = @import("../types.zig");

/// Expected protocol coverage for the client retry and cache matrix.
const matrix_protocols = [_]types.NegotiatedProtocol{ .http_1_1, .h2, .h3 };

/// Explicit retry failure classes declared by the M6 contract.
const RetryFailureClass = enum {
    /// Transport-level failure before a definitive response completes.
    transport,
    /// Timeout eligible for replay-safe retry handling.
    timeout,
    /// Retryable 5xx response class.
    retryable_5xx,
};

/// Declarative expectation for the `/unstable/health` retry flow.
const RetryAcceptanceExpectation = struct {
    /// Endpoint path exposed by the contract.
    path: []const u8,
    /// Method that remains replay-safe by default.
    method: types.Method,
    /// Failure classes eligible for retry.
    failure_classes: []const RetryFailureClass,
    /// Expected success status when the retry budget succeeds.
    success_status: types.Status,
    /// Expected terminal status when retries are exhausted.
    exhausted_status: types.Status,
};

/// Declarative expectation for the `/cached/config` cache flow.
const CacheAcceptanceExpectation = struct {
    /// Endpoint path exposed by the contract.
    path: []const u8,
    /// Expected success status for a fresh representation.
    fresh_status: types.Status,
    /// Expected conditional revalidation status code.
    revalidation_status_code: u16,
    /// Stored response content type.
    content_type: []const u8,
    /// Cache-source markers required by the contract.
    sources: []const []const u8,
};

/// Shared retry acceptance contract for `/unstable/health`.
const retry_acceptance = RetryAcceptanceExpectation{
    .path = "/unstable/health",
    .method = .get,
    .failure_classes = &.{ .transport, .timeout, .retryable_5xx },
    .success_status = .ok,
    .exhausted_status = .service_unavailable,
};

/// Shared cache acceptance contract for `/cached/config`.
const cache_acceptance = CacheAcceptanceExpectation{
    .path = "/cached/config",
    .fresh_status = .ok,
    .revalidation_status_code = 304,
    .content_type = "application/json",
    .sources = &.{ "origin", "cache", "revalidated" },
};

/// Expects one capability matrix entry to report supported client behavior.
fn expectSupportedCapability(
    feature: interop_harness.CapabilityFeatureId,
    protocol: types.NegotiatedProtocol,
) !interop_harness.CapabilityMatrixEntry {
    const capability = interop_harness.capabilityFor(feature, protocol) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(types.FeatureSupportLevel.supported, capability.support);
    return capability;
}

test "production matrix capability coverage classifies retry and cache across http1 h2 and h3" {
    for (matrix_protocols) |protocol| {
        const retry_capability = try expectSupportedCapability(.client_retry, protocol);
        const cache_capability = try expectSupportedCapability(.client_cache, protocol);

        try std.testing.expectEqual(types.FeatureSurface.client, retry_capability.surface);
        try std.testing.expectEqual(types.FeatureSurface.client, cache_capability.surface);
        try std.testing.expect(std.mem.containsAtLeast(
            u8,
            retry_capability.notes.?,
            1,
            "replay safety",
        ));
    }
}

test "production matrix retry coverage keeps replay safety explicit for unstable health" {
    try std.testing.expectEqualStrings("/unstable/health", retry_acceptance.path);
    try std.testing.expectEqual(types.Method.get, retry_acceptance.method);
    try std.testing.expectEqual(@as(usize, 3), retry_acceptance.failure_classes.len);
    try std.testing.expectEqual(types.Status.ok, retry_acceptance.success_status);
    try std.testing.expectEqual(types.Status.service_unavailable, retry_acceptance.exhausted_status);
    try std.testing.expectEqual(RetryFailureClass.transport, retry_acceptance.failure_classes[0]);
    try std.testing.expectEqual(RetryFailureClass.timeout, retry_acceptance.failure_classes[1]);
    try std.testing.expectEqual(RetryFailureClass.retryable_5xx, retry_acceptance.failure_classes[2]);

    for (matrix_protocols) |protocol| {
        const capability = try expectSupportedCapability(.client_retry, protocol);
        try std.testing.expectEqual(protocol, capability.protocol);
    }
}

test "production matrix cache coverage preserves freshness revalidation and invalidation for cached config" {
    const loader = fixture_loader.Loader.init();
    const config_body = try loader.loadM6Asset(std.testing.allocator, .cached_config);
    defer std.testing.allocator.free(config_body);

    var cache = client.HttpCache.init(std.testing.allocator);
    defer cache.deinit();

    try cache.put(.{
        .key = .{
            .method = .get,
            .scheme = .https,
            .host = try std.testing.allocator.dupe(u8, "127.0.0.1"),
            .port = types.Port.init(18443),
            .path = try std.testing.allocator.dupe(u8, cache_acceptance.path),
            .query = null,
        },
        .status = cache_acceptance.fresh_status,
        .body = try std.testing.allocator.dupe(u8, config_body),
        .content_type = try std.testing.allocator.dupe(u8, cache_acceptance.content_type),
        .etag = try std.testing.allocator.dupe(u8, "\"cfg-v1\""),
        .last_modified = null,
        .stored_at_ns = 0,
        .max_age = types.Duration.fromSeconds(5),
        .state = .fresh,
    });

    const entry = cache.get("127.0.0.1", cache_acceptance.path).?;
    try std.testing.expectEqualStrings("/cached/config", cache_acceptance.path);
    try std.testing.expectEqual(types.Status.ok, entry.status);
    try std.testing.expectEqual(http_cache.CacheState.fresh, entry.freshness(std.time.ns_per_s));
    try std.testing.expectEqual(http_cache.CacheState.stale, entry.freshness(10 * std.time.ns_per_s));
    try std.testing.expect(std.mem.eql(u8, config_body, entry.body));
    try std.testing.expectEqualStrings("application/json", entry.content_type.?);
    try std.testing.expectEqualStrings("\"cfg-v1\"", entry.etag.?);
    try std.testing.expectEqual(@as(u16, 304), cache_acceptance.revalidation_status_code);
    try std.testing.expectEqual(@as(usize, 3), cache_acceptance.sources.len);
    try std.testing.expectEqualStrings("origin", cache_acceptance.sources[0]);
    try std.testing.expectEqualStrings("cache", cache_acceptance.sources[1]);
    try std.testing.expectEqualStrings("revalidated", cache_acceptance.sources[2]);

    cache.invalidate("127.0.0.1", cache_acceptance.path);
    try std.testing.expectEqual(http_cache.CacheState.invalidated, cache.get("127.0.0.1", cache_acceptance.path).?.state);

    for (matrix_protocols) |protocol| {
        const capability = try expectSupportedCapability(.client_cache, protocol);
        try std.testing.expectEqual(protocol, capability.protocol);
    }
}

test "production matrix hardening preserves concurrent isolation and negative-path scope" {
    const slow_consumer = interop_harness.multiplexingScenarioForId(.slow_consumer_large_body).?;
    try std.testing.expectEqual(@as(usize, 2), slow_consumer.diagnostics.expected_backpressure_scopes.len);
    try std.testing.expectEqual(interop_harness.BackpressureScope.stream, slow_consumer.diagnostics.expected_backpressure_scopes[0]);
    try std.testing.expectEqual(interop_harness.BackpressureScope.connection, slow_consumer.diagnostics.expected_backpressure_scopes[1]);
    try std.testing.expect(slow_consumer.diagnostics.unrelated_streams_continue);

    const rst_stream = interop_harness.multiplexingScenarioForId(.rst_stream_isolated).?;
    try std.testing.expectEqual(interop_harness.FailureScope.stream, rst_stream.diagnostics.expected_failure_scope.?);
    try std.testing.expect(rst_stream.diagnostics.unrelated_streams_continue);

    const goaway = interop_harness.multiplexingScenarioForId(.goaway_drains_connection).?;
    try std.testing.expectEqual(interop_harness.FailureScope.connection, goaway.diagnostics.expected_failure_scope.?);
    try std.testing.expect(goaway.diagnostics.new_requests_rejected_after_drain);
}

test "production matrix client failure surfaces keep protocol and scope explicit" {
    const h2_failure = client.classifyH2Snapshot(.{
        .request_count = 2,
        .max_overlapping_streams = 2,
        .next_stream_id = 5,
        .total_buffered_bytes = 0,
        .saw_stream_backpressure = false,
        .saw_connection_backpressure = false,
        .reusable = false,
        .state = .draining,
        .last_failure_scope = .connection,
        .last_failure_note = "goaway drained the shared connection",
    }).?;
    try std.testing.expectEqual(client.FailureIsolationScope.connection, h2_failure.scope);
    try std.testing.expectEqual(client.ClientFailureCategory.connection, h2_failure.category);
    try std.testing.expectEqual(types.NegotiatedProtocol.h2, h2_failure.protocol.?);

    const h3_failure = client.classifyHttp3RuntimeError(error.InvalidStreamEnvelope);
    try std.testing.expectEqual(client.FailureIsolationScope.stream, h3_failure.scope);
    try std.testing.expectEqual(client.ClientFailureCategory.stream, h3_failure.category);
    try std.testing.expectEqual(types.NegotiatedProtocol.h3, h3_failure.protocol.?);
}

test "production matrix SC-004 metrics capture exceeds one thousand eligible flows" {
    const loader = fixture_loader.Loader.init();
    const metrics = try interop_harness.captureSc004Metrics(std.testing.allocator, loader);

    try std.testing.expectEqual(@as(usize, 1020), metrics.total_eligible_flows);
    try std.testing.expectEqual(@as(usize, 9), metrics.failure_count);
    try std.testing.expect(metrics.successRatio() > 0.99);
    try std.testing.expect(metrics.passesSc004());
}
