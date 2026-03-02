//! Public exports for the zttp module.

const types = @import("types.zig");
const client = @import("client.zig");

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
/// Parsed URI type.
pub const Uri = types.Uri;
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

test {
    _ = @import("http1/test_server.zig");
    _ = @import("http1/request_encoder.zig");
    _ = @import("http1/response_parser.zig");
    _ = @import("http1/connection_h1.zig");
    _ = @import("cookies/cookie_jar.zig");
    _ = @import("redirects/redirects.zig");
    _ = @import("proxy/proxy_env.zig");
}
