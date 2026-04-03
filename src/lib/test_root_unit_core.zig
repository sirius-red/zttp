//! Unit-test root for core library logic without loopback runtimes.

test {
    _ = @import("http1/request_encoder.zig");
    _ = @import("http1/response_parser.zig");
    _ = @import("tls/config.zig");
    _ = @import("tls/client.zig");
    _ = @import("tls/client_test.zig");
    _ = @import("tls/server.zig");
    _ = @import("websocket/frame.zig");
    _ = @import("websocket/websocket.zig");
    _ = @import("websocket/client.zig");
    _ = @import("websocket/server.zig");
    _ = @import("compression/encoding.zig");
    _ = @import("compression/decoder.zig");
    _ = @import("compression/encoder.zig");
    _ = @import("multipart/form_data.zig");
    _ = @import("cache/http_cache.zig");
    _ = @import("cookies/cookie_jar.zig");
    _ = @import("redirects/redirects.zig");
    _ = @import("proxy/proxy_env.zig");
}
