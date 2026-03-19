//! Entry point for server support.

/// Server-side public configuration and message types.
pub const Types = @import("types.zig");
/// HTTP/1.1 request parsing and response writing helpers.
pub const Http1 = @import("http1.zig");
/// Minimal HTTP/2 negotiation planning helpers.
pub const Http2 = @import("http2.zig");
/// Bound runtime server implementation.
pub const Runtime = @import("runtime.zig");
/// Public server configuration alias.
pub const ServerConfig = Types.ServerConfig;
/// Public server request alias.
pub const ServerRequest = Types.ServerRequest;
/// Public response writer alias.
pub const ServerResponseWriter = Types.ServerResponseWriter;
/// Public server runtime alias.
pub const Server = Runtime.Server;
