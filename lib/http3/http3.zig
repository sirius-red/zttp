//! Entry point for experimental HTTP/3 support.

/// Build-time feature flags visible to the HTTP/3 module family.
pub const BuildOptions = @import("zttp_build_options");
/// Whether experimental HTTP/3 support is enabled for this build.
pub const enabled = BuildOptions.http3;

test {
    _ = enabled;
    if (enabled) {
        _ = @import("quic_test.zig");
    }
}
