//! Entry point for server support.

const types = @import("../types.zig");
const websocket = @import("../websocket/websocket.zig");

/// Server-side public configuration and message types.
pub const Types = @import("types.zig");
/// HTTP/1.1 request parsing and response writing helpers.
pub const Http1 = @import("http1.zig");
/// Minimal HTTP/2 negotiation planning helpers.
pub const Http2 = @import("http2.zig");
/// HTTP/3 UDP runtime bridge and listener helpers.
pub const Http3 = @import("http3.zig");
/// Bound runtime server implementation.
pub const Runtime = @import("runtime.zig");
/// Public server configuration alias.
pub const ServerConfig = Types.ServerConfig;
/// Public server request alias.
pub const ServerRequest = Types.ServerRequest;
/// Public response writer alias.
pub const ServerResponseWriter = Types.ServerResponseWriter;
/// Public negotiated session metadata alias.
pub const NegotiatedSession = Types.NegotiatedSession;
/// Public route definition alias.
pub const Route = Types.Route;
/// Public shared request behavior alias.
pub const Middleware = Types.Middleware;
/// Public middleware decision alias.
pub const MiddlewareDecision = Types.MiddlewareDecision;
/// Public route catalog alias.
pub const RouteCatalog = Types.RouteCatalog;
/// Public fallback handler alias.
pub const FallbackHandler = Types.FallbackHandler;
/// Public higher-level server feature identifier.
pub const ServerFeature = Types.ServerFeature;
/// Public server feature-policy placeholder.
pub const ServerFeaturePolicy = Types.ServerFeaturePolicy;
/// Public server capability classification entry.
pub const ServerCapability = Types.ServerCapability;
/// Public generic feature-support classification.
pub const FeatureSupportLevel = types.FeatureSupportLevel;
/// Public shared WebSocket module entrypoint.
pub const WebSocket = websocket;
/// Public shared WebSocket session metadata.
pub const WebSocketSessionMetadata = websocket.SessionMetadata;
/// Public shared WebSocket session placeholder.
pub const WebSocketSession = websocket.Session;
/// Public HTTP/3 listener configuration alias.
pub const Http3ListenerConfig = Types.Http3ListenerConfig;
/// Public HTTP/3 session-limit alias.
pub const Http3SessionLimits = Types.Http3SessionLimits;
/// Public HTTP/3 QPACK-limit alias.
pub const Http3QpackLimits = Types.Http3QpackLimits;
/// Public HTTP/3 failure-category alias.
pub const Http3FailureCategory = Types.Http3FailureCategory;
/// Public HTTP/3 runtime alias.
pub const Http3Runtime = Http3.Runtime;
/// Public server runtime alias.
pub const Server = Runtime.Server;
