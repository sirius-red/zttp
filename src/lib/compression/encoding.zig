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

test "content encoding round-trips header tokens" {
    try std.testing.expectEqualStrings("gzip", ContentEncoding.gzip.asHeaderValue());
    try std.testing.expectEqual(ContentEncoding.br, parseEncoding("Br").?);
    try std.testing.expect(parseEncoding("compress") == null);
}
