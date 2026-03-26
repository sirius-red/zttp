//! Entry point for HTTP/2 support.

/// HTTP/2 frame encoding and decoding primitives.
pub const Frame = @import("frame.zig");
/// Minimal HPACK helpers.
pub const Hpack = @import("hpack.zig");
/// HTTP/2 connection and stream state.
pub const Connection = @import("connection.zig");
/// Dedicated HTTP/2 runtime for shared-client multiplexing.
pub const ConnectionH2 = @import("connection_h2.zig");
/// Deterministic local HTTP/2 peer fixture.
pub const TestPeer = @import("test_peer.zig");
