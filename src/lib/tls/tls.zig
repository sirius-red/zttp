//! Entry point for shared TLS support.

/// Build-time feature flags visible to the TLS module family.
pub const BuildOptions = @import("zttp_build_options");
/// TLS configuration helpers.
pub const Config = @import("config.zig");
/// TLS client planning helpers.
pub const Client = @import("client.zig");
/// TLS server planning helpers.
pub const Server = @import("server.zig");

test {
    _ = BuildOptions;
    _ = Config;
    _ = Client;
    _ = Server;
}
