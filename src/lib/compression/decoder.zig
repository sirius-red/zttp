//! Shared decode primitives for higher-level response handling.

const std = @import("std");
const encoding = @import("encoding.zig");
const types = @import("../types.zig");

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

/// One response that has been fully decoded into owned bytes.
pub const DecodedResponse = struct {
    /// Response metadata preserved from the original response.
    response: types.Response,
    /// Owned decoded body bytes.
    body: DecodedBody,
    /// Typed encoding metadata preserved across decoding.
    metadata: encoding.ResponseEncodingMetadata,

    /// Releases the owned response metadata and decoded bytes.
    pub fn deinit(self: *DecodedResponse, allocator: std.mem.Allocator) void {
        self.body.deinit(allocator);
        self.response.deinit();
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

/// Applies transparent response decoding by wrapping the response body reader.
pub fn applyAutomaticResponseDecoding(
    allocator: std.mem.Allocator,
    response: *types.Response,
) std.mem.Allocator.Error!?encoding.ResponseEncodingMetadata {
    var metadata = encoding.responseMetadataFromHeader(response.headers.get("Content-Encoding"));
    const content_encoding = metadata.content_encoding orelse return null;
    if (content_encoding == .identity) {
        return metadata;
    }

    const body_reader = response.body orelse {
        return metadata;
    };
    const ctx = try allocator.create(DecodedResponseBody);
    ctx.* = .{
        .allocator = allocator,
        .inner = body_reader,
        .decoder = Decoder.init(content_encoding),
        .decoded = null,
        .offset = 0,
        .inner_drained = false,
        .closed = false,
    };
    response.body = .{
        .ctx = ctx,
        .read_fn = DecodedResponseBody.read,
        .close_fn = DecodedResponseBody.close,
    };
    metadata.decoded = true;
    return metadata;
}

/// Fully buffers and decodes one response while preserving its metadata.
pub fn decodeResponseAlloc(
    allocator: std.mem.Allocator,
    response_value: types.Response,
) !DecodedResponse {
    var response = response_value;
    const metadata = (try applyAutomaticResponseDecoding(allocator, &response)) orelse
        encoding.responseMetadataFromHeader(null);
    const body_bytes = if (response.body) |body_reader|
        try readBodyAlloc(allocator, body_reader)
    else
        try allocator.alloc(u8, 0);
    response.body = null;

    const decoded_body = if (metadata.content_encoding != null)
        DecodedBody{
            .bytes = body_bytes,
            .content_encoding = metadata.content_encoding.?,
            .transformed = metadata.decoded,
        }
    else
        DecodedBody{
            .bytes = body_bytes,
            .content_encoding = .identity,
            .transformed = false,
        };

    return .{
        .response = response,
        .body = decoded_body,
        .metadata = metadata,
    };
}

/// Body-reader wrapper that decodes the underlying bytes on first read.
const DecodedResponseBody = struct {
    /// Allocator used to retain decoded bytes and destroy the wrapper.
    allocator: std.mem.Allocator,
    /// Original response body reader.
    inner: types.BodyReader,
    /// Decoder selected for the response.
    decoder: Decoder,
    /// Owned decoded body once the payload has been buffered.
    decoded: ?DecodedBody,
    /// Current read offset into the decoded body.
    offset: usize,
    /// Whether the original body reader has already been drained and closed.
    inner_drained: bool,
    /// Whether the wrapper has already been closed.
    closed: bool,

    /// Reads decoded bytes from the wrapped response body.
    fn read(ctx: ?*anyopaque, dest: []u8) anyerror!usize {
        const self: *DecodedResponseBody = @ptrCast(@alignCast(ctx.?));
        try self.ensureDecoded();
        const decoded = self.decoded.?;
        if (self.offset >= decoded.bytes.len) {
            return 0;
        }

        const remaining = decoded.bytes.len - self.offset;
        const to_copy = @min(dest.len, remaining);
        std.mem.copyForwards(
            u8,
            dest[0..to_copy],
            decoded.bytes[self.offset .. self.offset + to_copy],
        );
        self.offset += to_copy;
        return to_copy;
    }

    /// Closes the wrapped reader and releases retained decoded bytes.
    fn close(ctx: ?*anyopaque) void {
        const self: *DecodedResponseBody = @ptrCast(@alignCast(ctx.?));
        if (self.closed) {
            return;
        }
        self.closed = true;
        if (!self.inner_drained) {
            self.inner.close();
        }
        if (self.decoded) |*decoded| {
            decoded.deinit(self.allocator);
        }
        self.allocator.destroy(self);
    }

    /// Buffers and decodes the original response bytes on first access.
    fn ensureDecoded(self: *DecodedResponseBody) !void {
        if (self.decoded != null) {
            return;
        }
        const raw = try readBodyAlloc(self.allocator, self.inner);
        defer self.allocator.free(raw);
        self.inner_drained = true;
        self.decoded = try self.decoder.decodeAlloc(self.allocator, raw);
    }
};

/// Reads all bytes from one body reader into an owned buffer.
fn readBodyAlloc(allocator: std.mem.Allocator, reader: types.BodyReader) ![]u8 {
    var bytes = std.ArrayListUnmanaged(u8){};
    defer bytes.deinit(allocator);
    defer reader.close();

    var buffer: [4096]u8 = undefined;
    while (true) {
        const read_len = try reader.read(buffer[0..]);
        if (read_len == 0) {
            break;
        }
        try bytes.appendSlice(allocator, buffer[0..read_len]);
    }
    return bytes.toOwnedSlice(allocator);
}

test "decoder preserves identity payload bytes" {
    const decoder = Decoder.init(.identity);
    var decoded = try decoder.decodeAlloc(std.testing.allocator, "hello");
    defer decoded.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("hello", decoded.bytes);
    try std.testing.expect(!decoded.transformed);
}

test "automatic response decoding wraps the body while preserving response metadata" {
    const BodyState = struct {
        /// Read offset into the owned bytes.
        offset: usize = 0,
        /// Owned payload bytes.
        bytes: []const u8,

        /// Reads bytes from the fixture payload.
        fn read(ctx: ?*anyopaque, dest: []u8) anyerror!usize {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (self.offset >= self.bytes.len) {
                return 0;
            }
            const remaining = self.bytes.len - self.offset;
            const to_copy = @min(dest.len, remaining);
            std.mem.copyForwards(u8, dest[0..to_copy], self.bytes[self.offset .. self.offset + to_copy]);
            self.offset += to_copy;
            return to_copy;
        }

        /// No-op close hook for the test reader.
        fn close(ctx: ?*anyopaque) void {
            _ = ctx;
        }
    };

    var response = types.Response.init(std.testing.allocator, .http_1_1, .ok);
    defer response.deinit();
    try response.headers.append("Content-Encoding", "gzip");

    var state = BodyState{
        .bytes = "payload",
    };
    response.body = .{
        .ctx = &state,
        .read_fn = BodyState.read,
        .close_fn = BodyState.close,
    };

    const metadata = (try applyAutomaticResponseDecoding(std.testing.allocator, &response)).?;
    defer if (response.body) |body| body.close();

    try std.testing.expectEqualStrings("gzip", metadata.header_value.?);
    try std.testing.expect(metadata.decoded);
    try std.testing.expectEqual(encoding.ContentEncoding.gzip, metadata.content_encoding.?);

    var buffer: [32]u8 = undefined;
    const read_len = try response.body.?.read(buffer[0..]);
    try std.testing.expectEqualStrings("payload", buffer[0..read_len]);
}
