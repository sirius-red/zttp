//! Transport-neutral WebSocket frame and close semantics.

const std = @import("std");

/// WebSocket opcode for one frame.
pub const Opcode = enum(u4) {
    /// Continuation frame.
    continuation = 0x0,
    /// UTF-8 text message frame.
    text = 0x1,
    /// Binary message frame.
    binary = 0x2,
    /// Close control frame.
    close = 0x8,
    /// Ping control frame.
    ping = 0x9,
    /// Pong control frame.
    pong = 0xA,

    /// Returns true when the opcode is a control frame.
    pub fn isControl(self: Opcode) bool {
        return @intFromEnum(self) >= @intFromEnum(Opcode.close);
    }
};

/// Explicit payload length for one frame.
pub const PayloadLength = struct {
    /// Payload size in bytes.
    bytes: usize,

    /// Creates a payload length from bytes.
    pub fn init(bytes: usize) PayloadLength {
        return .{ .bytes = bytes };
    }
};

/// Client masking key for one frame.
pub const MaskingKey = struct {
    /// Four-byte masking key.
    bytes: [4]u8,

    /// Creates a masking key from raw bytes.
    pub fn init(bytes: [4]u8) MaskingKey {
        return .{ .bytes = bytes };
    }
};

/// Transport-neutral frame header.
pub const FrameHeader = struct {
    /// Whether this frame ends the message.
    fin: bool,
    /// Frame opcode.
    opcode: Opcode,
    /// Whether the payload is masked.
    masked: bool,
    /// Explicit payload length.
    payload_length: PayloadLength,
};

/// Standardized WebSocket close code.
pub const CloseCode = enum(u16) {
    /// Normal session shutdown.
    normal_closure = 1000,
    /// Peer is going away.
    going_away = 1001,
    /// Protocol semantics were violated.
    protocol_error = 1002,
    /// Frame payload type is unsupported.
    unsupported_data = 1003,
    /// Payload data was invalid for the message type.
    invalid_payload = 1007,
    /// Policy rejected the message.
    policy_violation = 1008,
    /// Message exceeded the configured limit.
    message_too_big = 1009,
    /// Internal endpoint failure.
    internal_error = 1011,
};

/// Structured close reason for one session shutdown.
pub const CloseReason = struct {
    /// Standardized close code.
    code: CloseCode,
    /// Optional diagnostic reason text.
    description: ?[]const u8,
};

/// One transport-neutral frame plus its payload bytes.
pub const Frame = struct {
    /// Frame header metadata.
    header: FrameHeader,
    /// Optional masking key.
    masking_key: ?MaskingKey,
    /// Frame payload bytes.
    payload: []const u8,

    /// Returns true when the frame is a control frame.
    pub fn isControl(self: Frame) bool {
        return self.header.opcode.isControl();
    }
};

test "opcode marks close and ping frames as control frames" {
    try std.testing.expect(!Opcode.text.isControl());
    try std.testing.expect(Opcode.close.isControl());
    try std.testing.expect(Opcode.ping.isControl());
}

test "frame preserves typed header and payload metadata" {
    const frame = Frame{
        .header = .{
            .fin = true,
            .opcode = .binary,
            .masked = false,
            .payload_length = PayloadLength.init(4),
        },
        .masking_key = null,
        .payload = "pong",
    };

    try std.testing.expectEqual(@as(usize, 4), frame.header.payload_length.bytes);
    try std.testing.expectEqualStrings("pong", frame.payload);
    try std.testing.expect(!frame.isControl());
}
