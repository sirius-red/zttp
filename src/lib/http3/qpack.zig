//! Minimal QPACK and HTTP/3 frame helpers for local interop.

const std = @import("std");

/// Error set returned by QPACK and frame helpers.
pub const Error = std.mem.Allocator.Error || error{
    /// Encoded bytes ended before a complete value was available.
    UnexpectedEof,
    /// The encoded varint exceeded the supported size for this module.
    InvalidVarInt,
    /// A control or instruction stream contained an unsupported instruction.
    MalformedInstruction,
    /// The peer exceeded the configured blocked-stream limit.
    BlockedStreamsExceeded,
};

/// One QPACK header field.
pub const HeaderField = struct {
    /// Header name bytes.
    name: []const u8,
    /// Header value bytes.
    value: []const u8,

    /// Releases owned buffers for a decoded header field.
    pub fn deinit(self: *HeaderField, allocator: std.mem.Allocator) void {
        allocator.free(@constCast(self.name));
        allocator.free(@constCast(self.value));
        self.* = undefined;
    }
};

/// HTTP/3 frame type identifiers used by the local interop flow.
pub const FrameType = enum(u64) {
    /// Body payload bytes.
    data = 0x0,
    /// Encoded header block.
    headers = 0x1,
    /// HTTP/3 settings frame.
    settings = 0x4,
    /// Graceful shutdown marker.
    goaway = 0x7,
    _,
};

/// One decoded HTTP/3 frame.
pub const Frame = struct {
    /// Frame type identifier.
    frame_type: FrameType,
    /// Owned payload bytes.
    payload: []u8,

    /// Releases the owned payload buffer.
    pub fn deinit(self: *Frame, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

/// Minimal dynamic-table bookkeeping for repeated header blocks.
pub const DynamicTable = struct {
    /// Allocator used for owned entries.
    allocator: std.mem.Allocator,
    /// Maximum number of entries retained.
    capacity: usize,
    /// Stored header entries.
    entries: std.ArrayListUnmanaged(HeaderField),

    /// Returns an empty dynamic table.
    pub fn init(allocator: std.mem.Allocator, capacity: usize) DynamicTable {
        return .{
            .allocator = allocator,
            .capacity = capacity,
            .entries = .{},
        };
    }

    /// Releases all stored entries.
    pub fn deinit(self: *DynamicTable) void {
        for (self.entries.items) |*entry| {
            entry.deinit(self.allocator);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Inserts one header field into the table.
    pub fn insert(self: *DynamicTable, name: []const u8, value: []const u8) Error!void {
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);

        try self.entries.append(self.allocator, .{
            .name = owned_name,
            .value = owned_value,
        });

        while (self.entries.items.len > self.capacity) {
            var removed = self.entries.orderedRemove(0);
            removed.deinit(self.allocator);
        }
    }
};

/// Encoder-side control stream state for one QPACK peer.
pub const EncoderStream = struct {
    /// Stable encoder stream identifier, when one exists.
    stream_id: ?u64 = null,
    /// Number of inserts emitted on the stream.
    insert_count: usize = 0,
};

/// Decoder-side control stream state for one QPACK peer.
pub const DecoderStream = struct {
    /// Stable decoder stream identifier, when one exists.
    stream_id: ?u64 = null,
    /// Highest insert count acknowledged by the peer.
    acknowledged_insert_count: usize = 0,
};

/// Connection-scoped QPACK state retained across repeated exchanges.
pub const PeerState = struct {
    /// Encoder-side dynamic table.
    encoder_table: DynamicTable,
    /// Decoder-side dynamic table.
    decoder_table: DynamicTable,
    /// Maximum blocked streams admitted before decode fails.
    blocked_stream_limit: usize,
    /// Number of streams currently blocked on unseen inserts.
    blocked_streams: usize,
    /// Encoder stream state for the peer.
    encoder_stream: EncoderStream,
    /// Decoder stream state for the peer.
    decoder_stream: DecoderStream,

    /// Returns an empty peer state for the provided capacity and stream limit.
    pub fn init(
        allocator: std.mem.Allocator,
        table_capacity: usize,
        blocked_stream_limit: usize,
    ) PeerState {
        return .{
            .encoder_table = DynamicTable.init(allocator, table_capacity),
            .decoder_table = DynamicTable.init(allocator, table_capacity),
            .blocked_stream_limit = blocked_stream_limit,
            .blocked_streams = 0,
            .encoder_stream = .{},
            .decoder_stream = .{},
        };
    }

    /// Releases the retained QPACK state.
    pub fn deinit(self: *PeerState) void {
        self.encoder_table.deinit();
        self.decoder_table.deinit();
        self.* = undefined;
    }

    /// Encodes headers while retaining connection-scoped dynamic-table state.
    pub fn encodeHeaders(self: *PeerState, headers: []const HeaderField) Error![]u8 {
        const encoded = try encodeHeaderBlock(self.encoder_table.allocator, headers);
        for (headers) |header| {
            try self.encoder_table.insert(header.name, header.value);
            self.encoder_stream.insert_count += 1;
        }
        return encoded;
    }

    /// Decodes headers while retaining connection-scoped dynamic-table state.
    pub fn decodeHeaders(self: *PeerState, bytes: []const u8) Error![]HeaderField {
        if (self.blocked_streams >= self.blocked_stream_limit and self.blocked_stream_limit != 0) {
            return error.BlockedStreamsExceeded;
        }
        const headers = try decodeHeaderBlock(self.decoder_table.allocator, bytes);
        errdefer freeHeaderFields(self.decoder_table.allocator, headers);
        for (headers) |header| {
            try self.decoder_table.insert(header.name, header.value);
        }
        return headers;
    }

    /// Applies minimal encoder-stream instructions for local repeated-exchange tests.
    pub fn applyEncoderInstructions(self: *PeerState, bytes: []const u8) Error!void {
        var index: usize = 0;
        while (index < bytes.len) {
            const opcode = bytes[index];
            index += 1;
            switch (opcode) {
                0x01 => {
                    const name_len: usize = @intCast(try decodeVarInt(bytes, &index));
                    if (index + name_len > bytes.len) {
                        return error.MalformedInstruction;
                    }
                    const name = bytes[index .. index + name_len];
                    index += name_len;
                    const value_len: usize = @intCast(try decodeVarInt(bytes, &index));
                    if (index + value_len > bytes.len) {
                        return error.MalformedInstruction;
                    }
                    const value = bytes[index .. index + value_len];
                    index += value_len;
                    try self.decoder_table.insert(name, value);
                },
                0x02 => {
                    const capacity: usize = @intCast(try decodeVarInt(bytes, &index));
                    self.encoder_table.capacity = capacity;
                    self.decoder_table.capacity = capacity;
                },
                else => return error.MalformedInstruction,
            }
        }
    }

    /// Applies minimal decoder-stream instructions for local acknowledgement tests.
    pub fn applyDecoderInstructions(self: *PeerState, bytes: []const u8) Error!void {
        var index: usize = 0;
        while (index < bytes.len) {
            const opcode = bytes[index];
            index += 1;
            switch (opcode) {
                0x03 => {
                    self.decoder_stream.acknowledged_insert_count = @intCast(try decodeVarInt(bytes, &index));
                },
                0x04 => {
                    const blocked_streams: usize = @intCast(try decodeVarInt(bytes, &index));
                    if (blocked_streams > self.blocked_stream_limit) {
                        return error.BlockedStreamsExceeded;
                    }
                    self.blocked_streams = blocked_streams;
                },
                else => return error.MalformedInstruction,
            }
        }
    }
};

/// QPACK encoder backed by the minimal dynamic table.
pub const Encoder = struct {
    /// Dynamic-table state.
    table: DynamicTable,

    /// Returns an encoder with the provided table capacity.
    pub fn init(allocator: std.mem.Allocator, capacity: usize) Encoder {
        return .{
            .table = DynamicTable.init(allocator, capacity),
        };
    }

    /// Releases encoder-owned state.
    pub fn deinit(self: *Encoder) void {
        self.table.deinit();
        self.* = undefined;
    }

    /// Encodes the provided headers into one header block.
    pub fn encodeHeaders(self: *Encoder, headers: []const HeaderField) Error![]u8 {
        const encoded = try encodeHeaderBlock(self.table.allocator, headers);
        for (headers) |header| {
            try self.table.insert(header.name, header.value);
        }
        return encoded;
    }
};

/// QPACK decoder backed by the minimal dynamic table.
pub const Decoder = struct {
    /// Dynamic-table state.
    table: DynamicTable,

    /// Returns a decoder with the provided table capacity.
    pub fn init(allocator: std.mem.Allocator, capacity: usize) Decoder {
        return .{
            .table = DynamicTable.init(allocator, capacity),
        };
    }

    /// Releases decoder-owned state.
    pub fn deinit(self: *Decoder) void {
        self.table.deinit();
        self.* = undefined;
    }

    /// Decodes a header block into owned header fields.
    pub fn decodeHeaders(self: *Decoder, bytes: []const u8) Error![]HeaderField {
        const headers = try decodeHeaderBlock(self.table.allocator, bytes);
        errdefer freeHeaderFields(self.table.allocator, headers);
        for (headers) |header| {
            try self.table.insert(header.name, header.value);
        }
        return headers;
    }
};

/// Encodes one QUIC-style varint into an owned slice.
pub fn encodeVarInt(allocator: std.mem.Allocator, value: u64) Error![]u8 {
    var bytes = std.ArrayListUnmanaged(u8){};
    errdefer bytes.deinit(allocator);
    try appendVarInt(&bytes, allocator, value);
    return bytes.toOwnedSlice(allocator);
}

/// Decodes one QUIC-style varint from `bytes` and advances `index`.
pub fn decodeVarInt(bytes: []const u8, index: *usize) Error!u64 {
    if (index.* >= bytes.len) {
        return error.UnexpectedEof;
    }

    const first = bytes[index.*];
    const prefix = first >> 6;
    const width: usize = switch (prefix) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (index.* + width > bytes.len) {
        return error.UnexpectedEof;
    }

    var value: u64 = first & 0x3f;
    var offset: usize = 1;
    while (offset < width) : (offset += 1) {
        value = (value << 8) | bytes[index.* + offset];
    }
    index.* += width;
    return value;
}

/// Encodes a QPACK header block using simple length-prefixed fields.
pub fn encodeHeaderBlock(
    allocator: std.mem.Allocator,
    headers: []const HeaderField,
) Error![]u8 {
    var bytes = std.ArrayListUnmanaged(u8){};
    errdefer bytes.deinit(allocator);

    for (headers) |header| {
        try appendVarInt(&bytes, allocator, header.name.len);
        try bytes.appendSlice(allocator, header.name);
        try appendVarInt(&bytes, allocator, header.value.len);
        try bytes.appendSlice(allocator, header.value);
    }

    return bytes.toOwnedSlice(allocator);
}

/// Decodes a QPACK header block into owned header fields.
pub fn decodeHeaderBlock(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) Error![]HeaderField {
    var headers = std.ArrayListUnmanaged(HeaderField){};
    errdefer {
        for (headers.items) |*header| {
            header.deinit(allocator);
        }
        headers.deinit(allocator);
    }

    var index: usize = 0;
    while (index < bytes.len) {
        const name_len: usize = @intCast(try decodeVarInt(bytes, &index));
        if (index + name_len > bytes.len) {
            return error.UnexpectedEof;
        }
        const name = try allocator.dupe(u8, bytes[index .. index + name_len]);
        errdefer allocator.free(name);
        index += name_len;

        const value_len: usize = @intCast(try decodeVarInt(bytes, &index));
        if (index + value_len > bytes.len) {
            allocator.free(name);
            return error.UnexpectedEof;
        }
        const value = try allocator.dupe(u8, bytes[index .. index + value_len]);
        index += value_len;

        try headers.append(allocator, .{
            .name = name,
            .value = value,
        });
    }

    return headers.toOwnedSlice(allocator);
}

/// Releases a header-field slice returned by `decodeHeaderBlock`.
pub fn freeHeaderFields(allocator: std.mem.Allocator, headers: []HeaderField) void {
    for (headers) |*header| {
        header.deinit(allocator);
    }
    allocator.free(headers);
}

/// Encodes one HTTP/3 frame into an owned slice.
pub fn encodeFrame(
    allocator: std.mem.Allocator,
    frame_type: FrameType,
    payload: []const u8,
) Error![]u8 {
    var bytes = std.ArrayListUnmanaged(u8){};
    errdefer bytes.deinit(allocator);

    try appendVarInt(&bytes, allocator, @intFromEnum(frame_type));
    try appendVarInt(&bytes, allocator, payload.len);
    try bytes.appendSlice(allocator, payload);

    return bytes.toOwnedSlice(allocator);
}

/// Decodes one HTTP/3 frame from `bytes` and advances `index`.
pub fn decodeFrame(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    index: *usize,
) Error!Frame {
    const frame_type_value = try decodeVarInt(bytes, index);
    const payload_len: usize = @intCast(try decodeVarInt(bytes, index));
    if (index.* + payload_len > bytes.len) {
        return error.UnexpectedEof;
    }

    const payload = try allocator.dupe(u8, bytes[index.* .. index.* + payload_len]);
    index.* += payload_len;

    return .{
        .frame_type = @enumFromInt(frame_type_value),
        .payload = payload,
    };
}

/// Decodes all frames in `bytes` into owned payload slices.
pub fn decodeFrames(allocator: std.mem.Allocator, bytes: []const u8) Error![]Frame {
    var frames = std.ArrayListUnmanaged(Frame){};
    errdefer {
        for (frames.items) |*frame| {
            frame.deinit(allocator);
        }
        frames.deinit(allocator);
    }

    var index: usize = 0;
    while (index < bytes.len) {
        try frames.append(allocator, try decodeFrame(allocator, bytes, &index));
    }

    return frames.toOwnedSlice(allocator);
}

/// Releases a frame slice returned by `decodeFrames`.
pub fn freeFrames(allocator: std.mem.Allocator, frames: []Frame) void {
    for (frames) |*frame| {
        frame.deinit(allocator);
    }
    allocator.free(frames);
}

/// Appends a QUIC varint to the provided byte list.
fn appendVarInt(
    bytes: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    value: u64,
) Error!void {
    if (value <= 63) {
        try bytes.append(allocator, @intCast(value));
        return;
    }
    if (value <= 16_383) {
        try bytes.append(allocator, @intCast(0x40 | ((value >> 8) & 0x3f)));
        try bytes.append(allocator, @intCast(value & 0xff));
        return;
    }
    if (value <= 1_073_741_823) {
        try bytes.append(allocator, @intCast(0x80 | ((value >> 24) & 0x3f)));
        try bytes.append(allocator, @intCast((value >> 16) & 0xff));
        try bytes.append(allocator, @intCast((value >> 8) & 0xff));
        try bytes.append(allocator, @intCast(value & 0xff));
        return;
    }
    if (value <= 4_611_686_018_427_387_903) {
        try bytes.append(allocator, @intCast(0xc0 | ((value >> 56) & 0x3f)));
        try bytes.append(allocator, @intCast((value >> 48) & 0xff));
        try bytes.append(allocator, @intCast((value >> 40) & 0xff));
        try bytes.append(allocator, @intCast((value >> 32) & 0xff));
        try bytes.append(allocator, @intCast((value >> 24) & 0xff));
        try bytes.append(allocator, @intCast((value >> 16) & 0xff));
        try bytes.append(allocator, @intCast((value >> 8) & 0xff));
        try bytes.append(allocator, @intCast(value & 0xff));
        return;
    }
    return error.InvalidVarInt;
}

test "qpack varints round trip across supported widths" {
    const samples = [_]u64{ 42, 1337, 70_000, 5_000_000_000 };

    for (samples) |sample| {
        const encoded = try encodeVarInt(std.testing.allocator, sample);
        defer std.testing.allocator.free(encoded);

        var index: usize = 0;
        const decoded = try decodeVarInt(encoded, &index);
        try std.testing.expectEqual(sample, decoded);
        try std.testing.expectEqual(encoded.len, index);
    }
}

test "qpack encoder and decoder round trip header blocks" {
    var encoder = Encoder.init(std.testing.allocator, 8);
    defer encoder.deinit();
    var decoder = Decoder.init(std.testing.allocator, 8);
    defer decoder.deinit();

    const encoded = try encoder.encodeHeaders(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/health" },
        .{ .name = "content-type", .value = "application/json" },
    });
    defer std.testing.allocator.free(encoded);

    const decoded = try decoder.decodeHeaders(encoded);
    defer freeHeaderFields(std.testing.allocator, decoded);

    try std.testing.expectEqual(@as(usize, 3), decoded.len);
    try std.testing.expectEqualStrings(":path", decoded[1].name);
    try std.testing.expectEqualStrings("application/json", decoded[2].value);
}

test "http3 frames round trip headers and data payloads" {
    const headers = try encodeFrame(std.testing.allocator, .headers, "hdr");
    defer std.testing.allocator.free(headers);
    const data = try encodeFrame(std.testing.allocator, .data, "body");
    defer std.testing.allocator.free(data);

    var bytes = std.ArrayListUnmanaged(u8){};
    defer bytes.deinit(std.testing.allocator);
    try bytes.appendSlice(std.testing.allocator, headers);
    try bytes.appendSlice(std.testing.allocator, data);

    const decoded = try decodeFrames(std.testing.allocator, bytes.items);
    defer freeFrames(std.testing.allocator, decoded);

    try std.testing.expectEqual(@as(usize, 2), decoded.len);
    try std.testing.expectEqual(FrameType.headers, decoded[0].frame_type);
    try std.testing.expectEqualStrings("body", decoded[1].payload);
}

test "qpack peer state retains repeated header blocks" {
    var peer = PeerState.init(std.testing.allocator, 8, 4);
    defer peer.deinit();

    const encoded_first = try peer.encodeHeaders(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/health" },
    });
    defer std.testing.allocator.free(encoded_first);

    const decoded_first = try peer.decodeHeaders(encoded_first);
    defer freeHeaderFields(std.testing.allocator, decoded_first);

    const encoded_second = try peer.encodeHeaders(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/echo" },
        .{ .name = "x-retry", .value = "2" },
    });
    defer std.testing.allocator.free(encoded_second);

    const decoded_second = try peer.decodeHeaders(encoded_second);
    defer freeHeaderFields(std.testing.allocator, decoded_second);

    try std.testing.expectEqual(@as(usize, 5), peer.decoder_table.entries.items.len);
    try std.testing.expectEqualStrings("/echo", decoded_second[1].value);
}

test "qpack peer state rejects malformed instructions" {
    var peer = PeerState.init(std.testing.allocator, 8, 1);
    defer peer.deinit();

    try std.testing.expectError(
        error.MalformedInstruction,
        peer.applyEncoderInstructions(&.{ 0xff, 0x01 }),
    );
    try std.testing.expectError(
        error.BlockedStreamsExceeded,
        peer.applyDecoderInstructions(&.{ 0x04, 0x02 }),
    );
}
