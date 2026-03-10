//! Entry point for experimental HTTP/3 support.

/// Build-time feature flags visible to the HTTP/3 module family.
pub const BuildOptions = @import("zttp_build_options");
/// Whether experimental HTTP/3 support is enabled for this build.
pub const enabled = BuildOptions.http3;
/// QUIC transport helpers exposed when HTTP/3 support is enabled.
pub const Quic = if (enabled) @import("quic.zig") else struct {};
/// QPACK and frame helpers exposed when HTTP/3 support is enabled.
pub const Qpack = if (enabled) @import("qpack.zig") else struct {};
/// Experimental client request flow exposed when HTTP/3 support is enabled.
pub const Client = if (enabled) @import("client.zig") else struct {};
/// Experimental server and harness flow exposed when HTTP/3 support is enabled.
pub const Server = if (enabled) @import("server.zig") else struct {};

test {
    _ = enabled;
    if (enabled) {
        _ = Quic;
        _ = Qpack;
        _ = Client;
        _ = Server;
        _ = @import("quic_test.zig");
    }
}
