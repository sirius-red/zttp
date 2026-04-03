//! Unit-test root for the library's pure logic and fixture-planning layers.

test {
    _ = @import("http1/request_encoder.zig");
    _ = @import("http1/response_parser.zig");
    _ = @import("tls/config.zig");
    _ = @import("tls/client.zig");
    _ = @import("tls/client_test.zig");
    _ = @import("tls/server.zig");
    _ = @import("http2/frame.zig");
    _ = @import("http2/hpack.zig");
    _ = @import("http2/connection.zig");
    _ = @import("http2/connection_test.zig");
    _ = @import("http2/test_peer.zig");
    _ = @import("http3/qpack.zig");
    _ = @import("http3/quic.zig");
    _ = @import("http3/quic_test.zig");
    _ = @import("http3/http3.zig");
    _ = @import("server/types.zig");
    _ = @import("server/http1.zig");
    _ = @import("server/http2.zig");
    _ = @import("server/app.zig");
    _ = @import("server/static.zig");
    _ = @import("server/compression.zig");
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
    _ = @import("testing/interop_harness.zig");
    _ = @import("testing/fixture_loader.zig");
    _ = @import("testing/smoke_runner.zig");
    _ = @import("testing/testing.zig");
    _ = @import("testing/malformed_input_test.zig");
    _ = @import("testing/production_matrix_test.zig");
}
