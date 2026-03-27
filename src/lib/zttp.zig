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
/// Streaming body writer type for server handlers.
pub const BodyWriter = server.Types.BodyWriter;
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
/// Server listener configuration type.
pub const ServerConfig = server.ServerConfig;
/// Server request type.
pub const ServerRequest = server.ServerRequest;
/// Server response writer type.
pub const ServerResponseWriter = server.ServerResponseWriter;
/// Negotiated session metadata for one accepted server connection.
pub const NegotiatedSession = server.NegotiatedSession;
/// Higher-level exact route definition.
pub const Route = server.Route;
/// Shared request behavior definition.
pub const Middleware = server.Middleware;
/// Shared request behavior decision type.
pub const MiddlewareDecision = server.MiddlewareDecision;
/// Higher-level route catalog surface.
pub const RouteCatalog = server.RouteCatalog;
/// Optional fallback handler for unmatched routes.
pub const FallbackHandler = server.FallbackHandler;
/// Bound server runtime type.
pub const ServerRuntime = server.Server;
/// HTTP/3 module entrypoint.
pub const Http3 = http3;
/// Shared testing module entrypoint.
pub const Testing = testing;

test {
    _ = @import("http1/test_server.zig");
    _ = @import("http1/request_encoder.zig");
    _ = @import("http1/response_parser.zig");
    _ = @import("http1/connection_h1.zig");
    _ = @import("http1/connection_h1_test.zig");
    _ = @import("tls/config.zig");
    _ = @import("tls/client.zig");
    _ = @import("tls/client_test.zig");
    _ = @import("http2/frame.zig");
    _ = @import("http2/hpack.zig");
    _ = @import("http2/connection.zig");
    _ = @import("http2/connection_h2.zig");
    _ = @import("http2/connection_h2_test.zig");
    _ = @import("http2/connection_test.zig");
    _ = @import("http2/test_peer.zig");
    _ = @import("server/server_test.zig");
    _ = @import("cookies/cookie_jar.zig");
    _ = @import("redirects/redirects.zig");
    _ = @import("proxy/proxy_env.zig");
    _ = @import("testing/client_interop_test.zig");
    _ = @import("testing/server_interop_test.zig");
    _ = testing;
}
