//! Integration-test root for server runtime and HTTP/1 loopback flows.

test {
    _ = @import("http1/test_server.zig");
    _ = @import("http1/connection_h1.zig");
    _ = @import("http1/connection_h1_test.zig");
    _ = @import("server/runtime.zig");
    _ = @import("server/server_test.zig");
}
