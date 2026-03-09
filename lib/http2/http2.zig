//! Entry point for HTTP/2 support.

/// Build-time feature flags visible to the HTTP/2 module family.
pub const BuildOptions = @import("zttp_build_options");

test {
    _ = BuildOptions;
}
