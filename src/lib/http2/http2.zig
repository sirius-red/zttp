//! Entry point for HTTP/2 support.

/// Build-time feature flags visible to the HTTP/2 module family.
pub const BuildOptions = @import("zttp_build_options");
/// HTTP/2 frame encoding and decoding primitives.
pub const Frame = @import("frame.zig");
/// Minimal HPACK helpers.
pub const Hpack = @import("hpack.zig");
/// HTTP/2 connection and stream state.
pub const Connection = @import("connection.zig");
