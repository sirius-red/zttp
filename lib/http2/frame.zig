//! HTTP/2 frame encoding and decoding primitives.

const std = @import("std");

/// Error set returned by frame parsing helpers.
pub const Error = error{
    /// Frame header bytes were truncated.
    ShortHeader,
    /// Frame payload length is invalid for the selected type.
    InvalidPayloadLength,
    /// Settings payload length was not a multiple of six bytes.
    InvalidSettingsPayloadLength,
};

/// HTTP/2 frame type identifier.
pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
    _,
};

/// Fixed 9-byte HTTP/2 frame header.
pub const FrameHeader = struct {
    /// Payload length in bytes.
    length: u24,
    /// Frame type.
    frame_type: FrameType,
    /// Frame flags.
    flags: u8,
    /// Stream identifier without the reserved high bit.
    stream_id: u31,

    /// Encodes the header into the provided 9-byte destination.
    pub fn encode(self: FrameHeader, dest: *[9]u8) void {
        dest[0] = @intCast((self.length >> 16) & 0xff);
        dest[1] = @intCast((self.length >> 8) & 0xff);
        dest[2] = @intCast(self.length & 0xff);
        dest[3] = @intFromEnum(self.frame_type);
        dest[4] = self.flags;
        const stream_id: u32 = self.stream_id;
        dest[5] = @intCast((stream_id >> 24) & 0x7f);
        dest[6] = @intCast((stream_id >> 16) & 0xff);
        dest[7] = @intCast((stream_id >> 8) & 0xff);
        dest[8] = @intCast(stream_id & 0xff);
    }

    /// Decodes a frame header from a 9-byte buffer.
    pub fn decode(bytes: []const u8) Error!FrameHeader {
        if (bytes.len < 9) {
            return error.ShortHeader;
        }

        const length: u24 = (@as(u24, bytes[0]) << 16) | (@as(u24, bytes[1]) << 8) | bytes[2];
        const stream_id: u31 =
            (@as(u31, bytes[5] & 0x7f) << 24) |
            (@as(u31, bytes[6]) << 16) |
            (@as(u31, bytes[7]) << 8) |
            bytes[8];

        return .{
            .length = length,
            .frame_type = @enumFromInt(bytes[3]),
            .flags = bytes[4],
            .stream_id = stream_id,
        };
    }
};

/// HTTP/2 settings identifier.
pub const SettingId = enum(u16) {
    header_table_size = 0x1,
    enable_push = 0x2,
    max_concurrent_streams = 0x3,
    initial_window_size = 0x4,
    max_frame_size = 0x5,
    max_header_list_size = 0x6,
    _,
};

/// One HTTP/2 settings parameter.
pub const Setting = struct {
    /// Setting identifier.
    id: SettingId,
    /// Setting value.
    value: u32,
};

/// Encodes HTTP/2 settings into a byte list.
pub fn encodeSettings(allocator: std.mem.Allocator, settings: []const Setting) std.mem.Allocator.Error![]u8 {
    const bytes = try allocator.alloc(u8, settings.len * 6);
    errdefer allocator.free(bytes);

    for (settings, 0..) |setting, index| {
        const offset = index * 6;
        const setting_id = @intFromEnum(setting.id);
        bytes[offset + 0] = @intCast((setting_id >> 8) & 0xff);
        bytes[offset + 1] = @intCast(setting_id & 0xff);
        bytes[offset + 2] = @intCast((setting.value >> 24) & 0xff);
        bytes[offset + 3] = @intCast((setting.value >> 16) & 0xff);
        bytes[offset + 4] = @intCast((setting.value >> 8) & 0xff);
        bytes[offset + 5] = @intCast(setting.value & 0xff);
    }

    return bytes;
}

/// Decodes HTTP/2 settings from a byte slice.
pub fn decodeSettings(allocator: std.mem.Allocator, bytes: []const u8) (std.mem.Allocator.Error || Error)![]Setting {
    if (bytes.len % 6 != 0) {
        return error.InvalidSettingsPayloadLength;
    }

    const settings = try allocator.alloc(Setting, bytes.len / 6);
    errdefer allocator.free(settings);

    for (settings, 0..) |*setting, index| {
        const offset = index * 6;
        const setting_id = (@as(u16, bytes[offset + 0]) << 8) | bytes[offset + 1];
        const value = (@as(u32, bytes[offset + 2]) << 24) |
            (@as(u32, bytes[offset + 3]) << 16) |
            (@as(u32, bytes[offset + 4]) << 8) |
            bytes[offset + 5];
        setting.* = .{
            .id = @enumFromInt(setting_id),
            .value = value,
        };
    }

    return settings;
}

test "frame header round trips" {
    const header = FrameHeader{
        .length = 42,
        .frame_type = .headers,
        .flags = 0x5,
        .stream_id = 3,
    };
    var encoded: [9]u8 = undefined;
    header.encode(&encoded);

    const decoded = try FrameHeader.decode(&encoded);
    try std.testing.expectEqual(header.length, decoded.length);
    try std.testing.expectEqual(header.frame_type, decoded.frame_type);
    try std.testing.expectEqual(header.flags, decoded.flags);
    try std.testing.expectEqual(header.stream_id, decoded.stream_id);
}

test "settings payload round trips" {
    const payload = try encodeSettings(std.testing.allocator, &.{
        .{ .id = .max_frame_size, .value = 16384 },
        .{ .id = .initial_window_size, .value = 65535 },
    });
    defer std.testing.allocator.free(payload);

    const decoded = try decodeSettings(std.testing.allocator, payload);
    defer std.testing.allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 2), decoded.len);
    try std.testing.expectEqual(SettingId.max_frame_size, decoded[0].id);
    try std.testing.expectEqual(@as(u32, 65535), decoded[1].value);
}
