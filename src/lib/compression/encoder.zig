//! Shared encode primitives for higher-level response handling.

const std = @import("std");
const encoding = @import("encoding.zig");

/// Owned encoded-body result.
pub const EncodedBody = struct {
    /// Owned body bytes returned by the encoder.
    bytes: []u8,
    /// Encoding selected by the primitive.
    content_encoding: encoding.ContentEncoding,
    /// Whether the primitive changed the body representation.
    transformed: bool,

    /// Releases the owned body bytes.
    pub fn deinit(self: *EncodedBody, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

/// Shared body-encoder primitive.
pub const Encoder = struct {
    /// Encoding that the encoder should report.
    content_encoding: encoding.ContentEncoding,

    /// Creates an encoder for the provided content encoding.
    pub fn init(content_encoding: encoding.ContentEncoding) Encoder {
        return .{ .content_encoding = content_encoding };
    }

    /// Returns an owned encoded-body result.
    pub fn encodeAlloc(
        self: Encoder,
        allocator: std.mem.Allocator,
        bytes: []const u8,
    ) std.mem.Allocator.Error!EncodedBody {
        return .{
            .bytes = try allocator.dupe(u8, bytes),
            .content_encoding = self.content_encoding,
            .transformed = self.content_encoding != .identity,
        };
    }
};

test "encoder preserves identity payload bytes" {
    const encoder_instance = Encoder.init(.identity);
    var encoded = try encoder_instance.encodeAlloc(std.testing.allocator, "hello");
    defer encoded.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("hello", encoded.bytes);
    try std.testing.expect(!encoded.transformed);
}
