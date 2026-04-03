//! Integration-test root for the library's loopback, transport, and runtime flows.

test {
    _ = @import("client.zig");
    _ = @import("http1/test_server.zig");
    _ = @import("http1/connection_h1.zig");
    _ = @import("http1/connection_h1_test.zig");
    _ = @import("http2/connection_h2.zig");
    _ = @import("http2/connection_h2_test.zig");
    _ = @import("http3/client.zig");
    _ = @import("http3/server.zig");
    _ = @import("server/runtime.zig");
    _ = @import("server/server_test.zig");
    _ = @import("testing/client_interop_test.zig");
    _ = @import("testing/server_interop_test.zig");
    _ = @import("testing/http3_interop_test.zig");
    _ = @import("testing/websocket_interop_test.zig");
}
