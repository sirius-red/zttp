//! Unit-test root for readiness summaries and malformed-input matrices.

test {
    _ = @import("testing/smoke_runner.zig");
    _ = @import("testing/malformed_input_test.zig");
    _ = @import("testing/production_matrix_test.zig");
}
