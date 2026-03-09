//! Entry point for shared local test harness support.

/// Build-time feature flags visible to the testing module family.
pub const BuildOptions = @import("zttp_build_options");

test {
    _ = BuildOptions;
}
