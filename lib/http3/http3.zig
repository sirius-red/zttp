//! Entry point for HTTP/3 support.

/// Whether HTTP/3 support is enabled for this build.
pub const enabled = true;
/// QUIC transport helpers exposed by the HTTP/3 module family.
pub const Quic = @import("quic.zig");
/// QPACK and frame helpers exposed by the HTTP/3 module family.
pub const Qpack = @import("qpack.zig");
/// HTTP/3 client request flow.
pub const Client = @import("client.zig");
/// HTTP/3 server and harness flow.
pub const Server = @import("server.zig");

test {
    _ = enabled;
    _ = Quic;
    _ = Qpack;
    _ = Client;
    _ = Server;
    _ = @import("quic_test.zig");
}
