//! Minimal HPACK literal-header helpers for early HTTP/2 integration.

const std = @import("std");

/// One decoded header field.
pub const HeaderField = struct {
    /// Header name bytes.
    name: []const u8,
    /// Header value bytes.
    value: []const u8,

    /// Releases owned buffers for the field.
    pub fn deinit(self: *HeaderField, allocator: std.mem.Allocator) void {
        allocator.free(@constCast(self.name));
        allocator.free(@constCast(self.value));
        self.* = undefined;
    }
};

/// Error set returned while decoding literal headers.
pub const DecodeError = error{
    /// Encoded bytes ended before a full header field was available.
    UnexpectedEof,
};

/// Encodes headers as a simple literal sequence with length-prefixed strings.
pub fn encodeLiteralHeaders(
    allocator: std.mem.Allocator,
    headers: []const HeaderField,
) std.mem.Allocator.Error![]u8 {
    var bytes = std.ArrayListUnmanaged(u8){};
    errdefer bytes.deinit(allocator);

    for (headers) |header| {
        try bytes.append(allocator, @intCast(header.name.len));
        try bytes.appendSlice(allocator, header.name);
        try bytes.append(allocator, @intCast(header.value.len));
        try bytes.appendSlice(allocator, header.value);
    }

    return bytes.toOwnedSlice(allocator);
}

/// Decodes a literal header sequence into owned header fields.
pub fn decodeLiteralHeaders(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) (std.mem.Allocator.Error || DecodeError)![]HeaderField {
    var fields = std.ArrayListUnmanaged(HeaderField){};
    errdefer {
        for (fields.items) |*field| {
            field.deinit(allocator);
        }
        fields.deinit(allocator);
    }

    var index: usize = 0;
    while (index < bytes.len) {
        if (index >= bytes.len) return error.UnexpectedEof;
        const name_len = bytes[index];
        index += 1;
        if (index + name_len > bytes.len) return error.UnexpectedEof;
        const name = try allocator.dupe(u8, bytes[index .. index + name_len]);
        errdefer allocator.free(name);
        index += name_len;

        if (index >= bytes.len) return error.UnexpectedEof;
        const value_len = bytes[index];
        index += 1;
        if (index + value_len > bytes.len) {
            allocator.free(name);
            return error.UnexpectedEof;
        }
        const value = try allocator.dupe(u8, bytes[index .. index + value_len]);
        index += value_len;

        try fields.append(allocator, .{
            .name = name,
            .value = value,
        });
    }

    return fields.toOwnedSlice(allocator);
}

/// Releases an owned header list returned by `decodeLiteralHeaders`.
pub fn freeLiteralHeaders(allocator: std.mem.Allocator, headers: []HeaderField) void {
    for (headers) |*header| {
        header.deinit(allocator);
    }
    allocator.free(headers);
}

test "literal header encoding round trips" {
    const encoded = try encodeLiteralHeaders(std.testing.allocator, &.{
        .{ .name = "content-type", .value = "application/json" },
        .{ .name = "x-test", .value = "1" },
    });
    defer std.testing.allocator.free(encoded);

    const decoded = try decodeLiteralHeaders(std.testing.allocator, encoded);
    defer freeLiteralHeaders(std.testing.allocator, decoded);

    try std.testing.expectEqual(@as(usize, 2), decoded.len);
    try std.testing.expectEqualStrings("content-type", decoded[0].name);
    try std.testing.expectEqualStrings("1", decoded[1].value);
}
