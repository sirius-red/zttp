//! Integration-test root for HTTP/2 loopback runtime behavior.

test {
    _ = @import("http2/connection_h2.zig");
    _ = @import("http2/connection_h2_test.zig");
}
