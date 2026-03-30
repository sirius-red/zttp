//! Shared content-encoding metadata used by client and server surfaces.

const std = @import("std");
const types = @import("../types.zig");

/// Supported content-encoding token.
pub const ContentEncoding = enum {
    /// Unencoded body bytes.
    identity,
    /// `gzip` body encoding.
    gzip,
    /// `deflate` body encoding.
    deflate,
    /// `br` body encoding.
    br,

    /// Returns the wire token for the encoding.
    pub fn asHeaderValue(self: ContentEncoding) []const u8 {
        return switch (self) {
            .identity => "identity",
            .gzip => "gzip",
            .deflate => "deflate",
            .br => "br",
        };
    }
};

/// Message direction for an encoding policy.
pub const EncodingDirection = enum {
    /// Request-body encoding.
    request,
    /// Response-body encoding.
    response,
};

/// Action selected by one encoding rule.
pub const EncodingDecision = enum {
    /// Apply the encoding.
    apply,
    /// Bypass encoding.
    bypass,
    /// Reject the encoding for this path.
    reject,
};

/// Typed encoding rule shared by client and server planning.
pub const EncodingRule = struct {
    /// Encoding being considered.
    encoding: ContentEncoding,
    /// Direction of the policy.
    direction: EncodingDirection,
    /// Selected action.
    decision: EncodingDecision,
    /// Optional explanatory reason for bypass or reject decisions.
    reason: ?[]const u8,
};

/// Capability classification for one encoding and protocol pairing.
pub const EncodingCapability = struct {
    /// Negotiated protocol being classified.
    protocol: types.NegotiatedProtocol,
    /// Encoding being classified.
    encoding: ContentEncoding,
    /// Support classification for the pairing.
    support: types.FeatureSupportLevel,
    /// Optional explanatory note for the capability.
    notes: ?[]const u8,
};

/// Metadata preserved while one response body is decoded transparently.
pub const ResponseEncodingMetadata = struct {
    /// Original header value surfaced by the response, when present.
    header_value: ?[]const u8,
    /// Parsed content encoding, when the header is recognized.
    content_encoding: ?ContentEncoding,
    /// Whether automatic decoding is active for the response body.
    decoded: bool,
    /// Whether the original response headers remain intact.
    preserves_metadata: bool,
};

/// Parses a content-encoding token into the typed representation.
pub fn parseEncoding(value: []const u8) ?ContentEncoding {
    if (std.ascii.eqlIgnoreCase(value, "identity")) {
        return .identity;
    }
    if (std.ascii.eqlIgnoreCase(value, "gzip")) {
        return .gzip;
    }
    if (std.ascii.eqlIgnoreCase(value, "deflate")) {
        return .deflate;
    }
    if (std.ascii.eqlIgnoreCase(value, "br")) {
        return .br;
    }
    return null;
}

/// Returns typed encoding metadata for one response header value.
pub fn responseMetadataFromHeader(value: ?[]const u8) ResponseEncodingMetadata {
    if (value) |header_value| {
        return .{
            .header_value = header_value,
            .content_encoding = parseEncoding(header_value),
            .decoded = false,
            .preserves_metadata = true,
        };
    }
    return .{
        .header_value = null,
        .content_encoding = null,
        .decoded = false,
        .preserves_metadata = true,
    };
}

test "content encoding round-trips header tokens" {
    try std.testing.expectEqualStrings("gzip", ContentEncoding.gzip.asHeaderValue());
    try std.testing.expectEqual(ContentEncoding.br, parseEncoding("Br").?);
    try std.testing.expect(parseEncoding("compress") == null);
}

test "response metadata preserves the original encoding header" {
    const metadata = responseMetadataFromHeader("gzip");

    try std.testing.expectEqualStrings("gzip", metadata.header_value.?);
    try std.testing.expectEqual(ContentEncoding.gzip, metadata.content_encoding.?);
    try std.testing.expect(!metadata.decoded);
    try std.testing.expect(metadata.preserves_metadata);
}
