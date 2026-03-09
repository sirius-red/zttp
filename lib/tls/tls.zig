//! Entry point for shared TLS support.

/// Build-time feature flags visible to the TLS module family.
pub const BuildOptions = @import("zttp_build_options");

test {
    _ = BuildOptions;
}
