//! Regression coverage scaffolding for future HTTP/1.1 server work.

const std = @import("std");
const types = @import("../types.zig");
const interop_harness = @import("../testing/interop_harness.zig");

/// HTTP/1.1 server behavior class covered by a regression scenario.
pub const RegressionEvent = enum {
    /// Parse the request line and route it correctly.
    request_line,
    /// Parse headers before invoking the handler.
    request_headers,
    /// Stream a request body to the handler.
    request_body,
    /// Emit a chunked or streamed text response.
    chunked_response,
    /// Emit a large binary response without buffering it all at once.
    large_stream,
};

/// Declarative server regression case for the future runtime implementation.
pub const RegressionCase = struct {
    /// Stable case name used in test output.
    name: []const u8,
    /// HTTP/1.1 behavior covered by the case.
    event: RegressionEvent,
    /// Request method expected for the case.
    method: types.Method,
    /// Harness path template exercised by the case.
    path_template: []const u8,
    /// Response mode the server must produce.
    response_mode: interop_harness.ResponseMode,
    /// Whether the response should be stream-friendly.
    streamed_response: bool,
};

const regression_cases = [_]RegressionCase{
    .{
        .name = "parse-health-request-line",
        .event = .request_line,
        .method = .get,
        .path_template = "/health",
        .response_mode = .json,
        .streamed_response = false,
    },
    .{
        .name = "parse-echo-header-reflection",
        .event = .request_headers,
        .method = .get,
        .path_template = "/echo",
        .response_mode = .json,
        .streamed_response = false,
    },
    .{
        .name = "stream-echo-request-body",
        .event = .request_body,
        .method = .post,
        .path_template = "/echo",
        .response_mode = .json,
        .streamed_response = true,
    },
    .{
        .name = "stream-chunked-response",
        .event = .chunked_response,
        .method = .get,
        .path_template = "/stream/chunked",
        .response_mode = .text_stream,
        .streamed_response = true,
    },
    .{
        .name = "stream-large-response",
        .event = .large_stream,
        .method = .get,
        .path_template = "/stream/large",
        .response_mode = .binary_stream,
        .streamed_response = true,
    },
};

test "server regression matrix covers request parsing cases" {
    try std.testing.expectEqual(@as(usize, 5), regression_cases.len);
    try std.testing.expectEqual(RegressionEvent.request_line, regression_cases[0].event);
    try std.testing.expectEqualStrings("/health", regression_cases[0].path_template);
    try std.testing.expectEqual(RegressionEvent.request_headers, regression_cases[1].event);
    try std.testing.expectEqualStrings("/echo", regression_cases[1].path_template);
    try std.testing.expectEqual(RegressionEvent.request_body, regression_cases[2].event);
    try std.testing.expectEqual(types.Method.post, regression_cases[2].method);
}

test "server regression matrix retains streamed response coverage" {
    try std.testing.expectEqual(RegressionEvent.chunked_response, regression_cases[3].event);
    try std.testing.expectEqual(.text_stream, regression_cases[3].response_mode);
    try std.testing.expect(regression_cases[3].streamed_response);

    try std.testing.expectEqual(RegressionEvent.large_stream, regression_cases[4].event);
    try std.testing.expectEqual(.binary_stream, regression_cases[4].response_mode);
    try std.testing.expect(regression_cases[4].streamed_response);
}

test "interop routes preserve http1 server coverage" {
    const health = interop_harness.scenarioForRoute(.health).?;
    const echo_post = interop_harness.scenarioForRoute(.echo_post).?;
    const chunked = interop_harness.scenarioForRoute(.stream_chunked).?;
    const large = interop_harness.scenarioForRoute(.stream_large).?;

    try std.testing.expect(health.supportsProtocol(.http_1_1));
    try std.testing.expectEqual(types.Method.post, echo_post.method);
    try std.testing.expect(chunked.supportsProtocol(.http_1_1));
    try std.testing.expectEqual(.text_stream, chunked.response_mode);
    try std.testing.expect(large.supportsProtocol(.http_1_1));
    try std.testing.expectEqual(.binary_stream, large.response_mode);
}
