//! Server-side WebSocket interop coverage tied to the shared M6 contract.

const std = @import("std");
const client = @import("../client.zig");
const types = @import("../types.zig");
const websocket = @import("../websocket/websocket.zig");
const websocket_frame = @import("../websocket/frame.zig");
const interop_harness = @import("interop_harness.zig");

/// Expected protocol coverage for the first-party server WebSocket surface.
const websocket_protocols = [_]types.NegotiatedProtocol{ .http_1_1, .h2, .h3 };

/// Shared endpoint path covered by the first-party WebSocket contract.
const websocket_endpoint_path = "/ws/chat";

/// Returns the expected transport-neutral handshake type for one protocol.
fn expectedTransport(protocol: types.NegotiatedProtocol) websocket.TransportKind {
    return switch (protocol) {
        .http_1_1 => .http1_upgrade,
        .h2 => .http2_connect,
        .h3 => .http3_connect,
    };
}

/// Returns the note fragment expected in the capability matrix for one protocol.
fn expectedHandshakeNote(protocol: types.NegotiatedProtocol) []const u8 {
    return switch (protocol) {
        .http_1_1 => "upgrade",
        .h2, .h3 => "CONNECT",
    };
}

/// Expects one server WebSocket capability entry to align with the transport-neutral session model.
fn expectServerWebSocketCapability(protocol: types.NegotiatedProtocol) !void {
    const capability = interop_harness.capabilityFor(.server_websocket, protocol) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(types.FeatureSurface.server, capability.surface);
    try std.testing.expectEqual(types.FeatureSupportLevel.supported, capability.support);
    try std.testing.expect(std.mem.containsAtLeast(u8, capability.notes.?, 1, expectedHandshakeNote(protocol)));
}

/// Expects one client WebSocket capability entry to align with the transport-neutral session model.
fn expectClientWebSocketCapability(protocol: types.NegotiatedProtocol) !void {
    const capability = interop_harness.capabilityFor(.client_websocket, protocol) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(types.FeatureSurface.client, capability.surface);
    try std.testing.expectEqual(types.FeatureSupportLevel.supported, capability.support);
    try std.testing.expect(std.mem.containsAtLeast(u8, capability.notes.?, 1, expectedHandshakeNote(protocol)));
}

test "server websocket interop capability matrix covers handshake modes for http1 h2 and h3" {
    for (websocket_protocols) |protocol| {
        try expectServerWebSocketCapability(protocol);
    }
}

test "server websocket message model stays protocol-neutral" {
    const text_message = websocket.Message{
        .kind = .text,
        .bytes = "hello-from-server",
    };
    const binary_message = websocket.Message{
        .kind = .binary,
        .bytes = &.{ 0x01, 0x02, 0x03, 0x04 },
    };

    try std.testing.expectEqual(websocket.MessageKind.text, text_message.kind);
    try std.testing.expectEqualStrings("hello-from-server", text_message.bytes);
    try std.testing.expectEqual(websocket.MessageKind.binary, binary_message.kind);
    try std.testing.expectEqual(@as(usize, 4), binary_message.bytes.len);
}

test "server websocket sessions preserve deterministic close semantics across protocols" {
    for (websocket_protocols) |protocol| {
        try expectServerWebSocketCapability(protocol);

        var session = websocket.Session.init(.{
            .protocol = protocol,
            .transport = expectedTransport(protocol),
            .support = .supported,
        });

        try std.testing.expectEqual(websocket.SessionState.opening, session.state);
        try std.testing.expectEqual(expectedTransport(protocol), session.metadata.transport);

        session.markOpen();
        try std.testing.expectEqual(websocket.SessionState.open, session.state);

        const close_reason = websocket_frame.CloseReason{
            .code = .normal_closure,
            .description = "deterministic-close",
        };
        session.startClose(close_reason);
        try std.testing.expectEqual(websocket.SessionState.closing, session.state);
        try std.testing.expectEqual(websocket_frame.CloseCode.normal_closure, session.close_reason.?.code);
        try std.testing.expectEqualStrings("deterministic-close", session.close_reason.?.description.?);

        session.markClosed();
        try std.testing.expectEqual(websocket.SessionState.closed, session.state);
    }
}

test "client websocket interop capability matrix covers handshake modes for http1 h2 and h3" {
    try std.testing.expectEqualStrings("/ws/chat", websocket_endpoint_path);

    for (websocket_protocols) |protocol| {
        try expectClientWebSocketCapability(protocol);
    }
}

test "client websocket session model stays unified across http1 h2 and h3" {
    const text_message = client.WebSocket.Message{
        .kind = .text,
        .bytes = "hello-from-client",
    };
    const binary_message = client.WebSocket.Message{
        .kind = .binary,
        .bytes = &.{ 0x0a, 0x0b, 0x0c },
    };

    try std.testing.expectEqual(client.WebSocket.MessageKind.text, text_message.kind);
    try std.testing.expectEqualStrings("hello-from-client", text_message.bytes);
    try std.testing.expectEqual(client.WebSocket.MessageKind.binary, binary_message.kind);
    try std.testing.expectEqual(@as(usize, 3), binary_message.bytes.len);

    for (websocket_protocols) |protocol| {
        try expectClientWebSocketCapability(protocol);

        const metadata: client.WebSocketSessionMetadata = .{
            .protocol = protocol,
            .transport = expectedTransport(protocol),
            .support = .supported,
        };
        var session = client.WebSocketSession.init(metadata);

        try std.testing.expectEqual(websocket.SessionState.opening, session.state);
        try std.testing.expectEqual(expectedTransport(protocol), session.metadata.transport);

        session.markOpen();
        try std.testing.expectEqual(websocket.SessionState.open, session.state);

        const close_reason = websocket_frame.CloseReason{
            .code = .normal_closure,
            .description = "deterministic-close",
        };
        session.startClose(close_reason);
        try std.testing.expectEqual(websocket.SessionState.closing, session.state);
        try std.testing.expectEqual(websocket_frame.CloseCode.normal_closure, session.close_reason.?.code);
        try std.testing.expectEqualStrings("deterministic-close", session.close_reason.?.description.?);

        session.markClosed();
        try std.testing.expectEqual(websocket.SessionState.closed, session.state);
    }
}
