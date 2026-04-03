//! Integration-test root for HTTP/3 loopback runtime behavior.

test {
    _ = @import("http3/client.zig");
    _ = @import("http3/server.zig");
    _ = @import("testing/http3_interop_test.zig");
}
