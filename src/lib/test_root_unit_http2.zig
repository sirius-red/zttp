//! Unit-test root for HTTP/2 codecs and typed state.

test {
    _ = @import("http2/frame.zig");
    _ = @import("http2/hpack.zig");
    _ = @import("http2/connection.zig");
    _ = @import("http2/connection_test.zig");
    _ = @import("http2/test_peer.zig");
}
