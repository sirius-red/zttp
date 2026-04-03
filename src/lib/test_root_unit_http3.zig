//! Unit-test root for HTTP/3, QUIC, and QPACK typed logic.

test {
    _ = @import("http3/qpack.zig");
    _ = @import("http3/quic.zig");
    _ = @import("http3/quic_test.zig");
    _ = @import("http3/http3.zig");
}
