//! Public exports for the zttp module.

const types = @import("types.zig");
const client = @import("client.zig");
const tls = @import("tls/tls.zig");
const http2 = @import("http2/http2.zig");
const server = @import("server/server.zig");
const http3 = @import("http3/http3.zig");
const testing = @import("testing/testing.zig");

/// HTTP method type.
pub const Method = types.Method;
/// HTTP status code type.
pub const Status = types.Status;
/// HTTP version type.
pub const Version = types.Version;
/// URI scheme type.
pub const Scheme = types.Scheme;
/// Port type for URI components.
pub const Port = types.Port;
/// Duration type with explicit units.
pub const Duration = types.Duration;
/// Byte-size type with explicit units.
pub const ByteSize = types.ByteSize;
/// Parsed URI type.
pub const Uri = types.Uri;
/// TLS verification mode.
pub const TlsVerifyMode = types.TlsVerifyMode;
/// TLS root-store selection mode.
pub const TlsRootStoreMode = types.TlsRootStoreMode;
/// Negotiated protocol identifier.
pub const NegotiatedProtocol = types.NegotiatedProtocol;
/// TLS configuration type.
pub const TlsConfig = types.TlsConfig;
/// Shared origin-key type for connection pooling.
pub const OriginKey = types.OriginKey;
/// HTTP header collection type.
pub const Headers = types.Headers;
/// Streaming body reader type.
pub const BodyReader = types.BodyReader;
/// HTTP request type.
pub const Request = types.Request;
/// HTTP response type.
pub const Response = types.Response;
/// HTTP client type.
pub const Client = client.Client;
/// HTTP client configuration options.
pub const ClientOptions = client.Options;
/// TLS module entrypoint.
pub const Tls = tls;
/// HTTP/2 module entrypoint.
pub const Http2 = http2;
/// Server module entrypoint.
pub const Server = server;
/// Experimental HTTP/3 module entrypoint.
pub const Http3 = http3;
/// Shared testing module entrypoint.
pub const Testing = testing;

test {
    _ = @import("http1/test_server.zig");
    _ = @import("http1/request_encoder.zig");
    _ = @import("http1/response_parser.zig");
    _ = @import("http1/connection_h1.zig");
    _ = @import("tls/client_test.zig");
    _ = @import("http2/connection_test.zig");
    _ = @import("cookies/cookie_jar.zig");
    _ = @import("redirects/redirects.zig");
    _ = @import("proxy/proxy_env.zig");
    _ = @import("testing/client_interop_test.zig");
    _ = testing;
}
