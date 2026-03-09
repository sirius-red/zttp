//! Entry point for server support.

/// Build-time feature flags visible to the server module family.
pub const BuildOptions = @import("zttp_build_options");

test {
    _ = BuildOptions;
}
