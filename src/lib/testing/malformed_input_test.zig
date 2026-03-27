//! Malformed-input and shared-bug cross-check coverage.

const std = @import("std");
const types = @import("../types.zig");
const response_parser = @import("../http1/response_parser.zig");
const http2_frame = @import("../http2/frame.zig");
const qpack = @import("../http3/qpack.zig");
const quic = @import("../http3/quic.zig");
const server_http2 = @import("../server/http2.zig");
const server_types = @import("../server/types.zig");
const interop_harness = @import("interop_harness.zig");
const smoke_runner = @import("smoke_runner.zig");

test "wire-format parser rejects malformed chunked responses independently" {
    const payload =
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "Z\r\n" ++
        "0\r\n\r\n";

    var stream = std.io.fixedBufferStream(payload);
    var reader = stream.reader();
    var buffer: [64]u8 = undefined;

    var parser = response_parser.ResponseParser(@TypeOf(reader)).init(
        std.testing.allocator,
        &reader,
        &buffer,
        response_parser.Limits.default(),
    );

    var response = try parser.readResponse();
    defer response.deinit();
    defer if (response.body) |body| body.close();

    var body_buffer: [8]u8 = undefined;
    try std.testing.expectError(error.InvalidChunkSize, response.body.?.read(&body_buffer));
}

test "smoke scenarios stay anchored to harness routes with explicit negative cases" {
    const scenarios = smoke_runner.defaultScenarios();

    var route_backed_scenarios: usize = 0;
    for (scenarios) |scenario| {
        const route = scenario.route orelse continue;
        route_backed_scenarios += 1;

        const contract = interop_harness.scenarioForRoute(route).?;
        try std.testing.expect(contract.negative_case != null);
        try std.testing.expect(contract.negative_case.?.len > 0);

        if (std.mem.eql(u8, scenario.name, "request-http")) {
            try std.testing.expectEqual(interop_harness.RouteId.echo_get, route);
            try std.testing.expect(contract.supportsProtocol(.http_1_1));
        }
        if (std.mem.eql(u8, scenario.name, "request-https")) {
            try std.testing.expectEqual(interop_harness.RouteId.health, route);
            try std.testing.expect(contract.tls_supported);
            try std.testing.expect(contract.supportsProtocol(.h2));
        }
        if (std.mem.eql(u8, scenario.name, "server")) {
            try std.testing.expectEqualStrings("/health", contract.path_template);
        }
    }

    try std.testing.expectEqual(@as(usize, 4), route_backed_scenarios);
}

test "http2 and http3 wire decoders reject truncated inputs before harness semantics" {
    try std.testing.expectError(
        error.ShortHeader,
        http2_frame.FrameHeader.decode(&.{ 0x00, 0x01, 0x02 }),
    );
    try std.testing.expectError(
        error.InvalidSettingsPayloadLength,
        http2_frame.decodeSettings(std.testing.allocator, &.{ 0x00, 0x01, 0x00, 0x00, 0x00 }),
    );
    try std.testing.expectError(
        error.UnexpectedEof,
        qpack.decodeFrames(std.testing.allocator, &.{ 0x01, 0x05, 'o', 'k' }),
    );
    try std.testing.expectError(
        error.UnexpectedEof,
        qpack.decodeHeaderBlock(std.testing.allocator, &.{ 0x03, 'a' }),
    );
}

test "quic transport rejects malformed packet lengths before http3 request decoding" {
    var sender = quic.Connection.init(std.testing.allocator, "client01".*, "server01".*);
    defer sender.deinit();
    var receiver = quic.Connection.init(std.testing.allocator, "server01".*, "client01".*);
    defer receiver.deinit();

    try std.testing.expectError(
        error.ShortPacket,
        receiver.unprotectPacket(std.testing.allocator, "too-short-packet"),
    );

    const encoded = try sender.protectPacket(std.testing.allocator, .application, "health");
    defer std.testing.allocator.free(encoded);

    var malformed = try std.testing.allocator.dupe(u8, encoded);
    defer std.testing.allocator.free(malformed);
    malformed[26] = 0x00;
    malformed[27] = encoded[27] + 1;

    try std.testing.expectError(
        error.InvalidPacketLength,
        receiver.unprotectPacket(std.testing.allocator, malformed),
    );
}

test "interop harness scenarios keep explicit negative cases for shared-bug cross-checks" {
    const scenarios = interop_harness.defaultScenarios();

    try std.testing.expectEqual(@as(usize, 8), scenarios.len);
    for (scenarios) |scenario| {
        try std.testing.expect(scenario.negative_case != null);
        try std.testing.expect(scenario.negative_case.?.len > 0);
    }
}

test "server http2 failure classification distinguishes malformed from unsupported exchanges" {
    try std.testing.expectEqual(server_types.Http2FailureCategory.malformed_frame, server_http2.classifyFailure(error.InvalidClientPreface).?);
    try std.testing.expectEqual(server_types.Http2FailureCategory.unsupported_exchange, server_http2.classifyFailure(error.UnsupportedExchange).?);
}
