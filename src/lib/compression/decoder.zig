//! Shared decode primitives for higher-level response handling.

const std = @import("std");
const encoding = @import("encoding.zig");

/// Owned decoded-body result.
pub const DecodedBody = struct {
    /// Owned body bytes returned by the decoder.
    bytes: []u8,
    /// Encoding that was inspected.
    content_encoding: encoding.ContentEncoding,
    /// Whether the primitive changed the body representation.
    transformed: bool,

    /// Releases the owned body bytes.
    pub fn deinit(self: *DecodedBody, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

/// Shared body-decoder primitive.
pub const Decoder = struct {
    /// Encoding that the decoder expects to inspect.
    content_encoding: encoding.ContentEncoding,

    /// Creates a decoder for the provided content encoding.
    pub fn init(content_encoding: encoding.ContentEncoding) Decoder {
        return .{ .content_encoding = content_encoding };
    }

    /// Returns an owned decoded-body result.
    pub fn decodeAlloc(
        self: Decoder,
        allocator: std.mem.Allocator,
        bytes: []const u8,
    ) std.mem.Allocator.Error!DecodedBody {
        return .{
            .bytes = try allocator.dupe(u8, bytes),
            .content_encoding = self.content_encoding,
            .transformed = self.content_encoding != .identity,
        };
    }
};

test "decoder preserves identity payload bytes" {
    const decoder = Decoder.init(.identity);
    var decoded = try decoder.decodeAlloc(std.testing.allocator, "hello");
    defer decoded.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("hello", decoded.bytes);
    try std.testing.expect(!decoded.transformed);
}
