//! Unit-test root for server-side planning, routing, and encoding helpers.

test {
    _ = @import("server/types.zig");
    _ = @import("server/http1.zig");
    _ = @import("server/http2.zig");
    _ = @import("server/app.zig");
    _ = @import("server/static.zig");
    _ = @import("server/compression.zig");
}
