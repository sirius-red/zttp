//! Public server-side configuration and request/response types.

const std = @import("std");
const core = @import("../types.zig");
const tls_config = @import("../tls/config.zig");
const tls_server = @import("../tls/server.zig");

const default_alpn_protocols = [_]core.NegotiatedProtocol{ .h2, .http_1_1 };

/// Callback invoked for one accepted server request.
pub const Handler = *const fn (
    ctx: ?*anyopaque,
    request: *ServerRequest,
    writer: *ServerResponseWriter,
) anyerror!void;

/// Streaming body writer callback surface exposed to handlers.
pub const BodyWriter = struct {
    /// Opaque callback context.
    ctx: ?*anyopaque,
    /// Function that writes one body chunk.
    write_all_fn: *const fn (ctx: ?*anyopaque, bytes: []const u8) anyerror!void,

    /// Writes all bytes in the provided slice.
    pub fn writeAll(self: BodyWriter, bytes: []const u8) anyerror!void {
        return self.write_all_fn(self.ctx, bytes);
    }
};

/// Response-writer lifecycle state.
pub const WriterState = enum {
    /// No response bytes have been emitted yet.
    idle,
    /// Headers have been emitted but no body bytes were written.
    headers_sent,
    /// Body bytes are being streamed.
    streaming,
    /// The response is complete.
    finished,
};

/// Connection limits and parsing guards for the server runtime.
pub const ConnectionLimits = struct {
    /// Maximum simultaneous connections handled by the runtime.
    max_connections: core.ConnectionCount,
    /// Maximum request-line length in bytes.
    max_request_line_bytes: core.LineLength,
    /// Maximum total request header bytes.
    max_header_bytes: core.ByteSize,
    /// Maximum number of request headers.
    max_header_count: core.HeaderCount,
    /// Maximum request body size buffered through helper methods.
    max_body_bytes: core.ByteSize,

    /// Returns the default limit set for loopback usage.
    pub fn default() ConnectionLimits {
        return .{
            .max_connections = core.ConnectionCount.init(32),
            .max_request_line_bytes = core.LineLength.fromBytes(8 * 1024),
            .max_header_bytes = core.ByteSize.fromKib(32),
            .max_header_count = core.HeaderCount.init(100),
            .max_body_bytes = core.ByteSize.fromKib(256),
        };
    }
};

/// Maximum per-session stream counts admitted by the HTTP/3 runtime.
pub const Http3SessionLimits = struct {
    /// Maximum simultaneous QUIC sessions on one bound listener.
    max_sessions: core.ConnectionCount,
    /// Maximum active request streams admitted on one session.
    max_streams_per_session: core.ConnectionCount,

    /// Returns the default loopback-oriented HTTP/3 session limits.
    pub fn default() Http3SessionLimits {
        return .{
            .max_sessions = core.ConnectionCount.init(8),
            .max_streams_per_session = core.ConnectionCount.init(8),
        };
    }
};

/// QPACK limits surfaced through the HTTP/3 listener configuration.
pub const Http3QpackLimits = struct {
    /// Maximum dynamic-table capacity retained per peer.
    dynamic_table_capacity: core.ByteSize,
    /// Maximum number of blocked streams admitted before decode fails.
    blocked_streams: core.ConnectionCount,

    /// Returns the default local HTTP/3 QPACK limits.
    pub fn default() Http3QpackLimits {
        return .{
            .dynamic_table_capacity = core.ByteSize.fromKib(4),
            .blocked_streams = core.ConnectionCount.init(8),
        };
    }
};

/// Typed HTTP/3 listener configuration owned by the canonical server runtime.
pub const Http3ListenerConfig = struct {
    /// Host or IPv4 literal bound by the UDP listener.
    listen_host: []const u8,
    /// UDP port bound by the listener.
    port: core.Port,
    /// Maximum protected datagram payload size.
    max_datagram_size: core.ByteSize,
    /// Per-listener session and stream admission limits.
    session_limits: Http3SessionLimits,
    /// Per-peer QPACK capacity and blocked-stream limits.
    qpack_limits: Http3QpackLimits,

    /// Returns a loopback-friendly default HTTP/3 listener configuration.
    pub fn init() Http3ListenerConfig {
        return .{
            .listen_host = "127.0.0.1",
            .port = core.Port.init(4433),
            .max_datagram_size = core.ByteSize.fromBytes(1200),
            .session_limits = Http3SessionLimits.default(),
            .qpack_limits = Http3QpackLimits.default(),
        };
    }

    /// Validates the configured datagram and admission limits.
    pub fn validate(self: Http3ListenerConfig) !void {
        if (self.max_datagram_size.toInt() < 256) {
            return error.InvalidHttp3Configuration;
        }
        if (self.session_limits.max_sessions.toInt() == 0) {
            return error.InvalidHttp3Configuration;
        }
        if (self.session_limits.max_streams_per_session.toInt() == 0) {
            return error.InvalidHttp3Configuration;
        }
    }
};

/// Error set returned by server configuration validation.
pub const ConfigError = tls_config.ValidationError || error{
    /// TLS listener mode requires both a certificate chain and private key.
    MissingTlsIdentity,
    /// HTTP/2 requires TLS ALPN advertising in this runtime.
    InvalidHttp2Configuration,
    /// HTTP/3 requires valid listener, datagram, and admission settings.
    InvalidHttp3Configuration,
    /// The higher-level route catalog contains an invalid exact duplicate.
    InvalidRouteCatalog,
};

/// Re-exported TLS listener plan used by secure server configurations.
pub const SecureListenerPlan = tls_server.ListenerPlan;

/// Explicit ALPN negotiation failure surfaced by the secure listener runtime.
pub const NegotiationFailureCategory = enum {
    /// The peer selected or required an unsupported application protocol.
    unsupported_protocol,
    /// The peer sent bytes that could not be routed to a supported protocol path.
    invalid_negotiation_bytes,
};

/// Predictable failure category surfaced by the minimal HTTP/2 server path.
pub const Http2FailureCategory = enum {
    /// The peer sent malformed HTTP/2 wire data.
    malformed_frame,
    /// The peer requested an unsupported HTTP/2 exchange shape.
    unsupported_exchange,
};

/// Distinct failure category surfaced by the HTTP/3 runtime bridge.
pub const Http3FailureCategory = enum {
    /// Listener startup or bind failed before serving requests.
    startup,
    /// Datagram transport or packet protection failed.
    transport,
    /// Session establishment or stream admission failed.
    session,
    /// QPACK or control-stream state was invalid.
    compression,
    /// Route dispatch failed after transport setup succeeded.
    route,
};

/// Typed negotiated session metadata for one accepted server connection.
pub const NegotiatedSession = struct {
    /// Peer address for the accepted socket.
    peer: std.net.Address,
    /// Stable TLS identity token when secure listener mode is active.
    identity_token: ?core.TlsIdentityToken,
    /// Negotiated application protocol for the connection.
    negotiated_protocol: core.NegotiatedProtocol,
    /// Effective request version that will be surfaced to handlers.
    request_version: core.Version,
    /// Whether the connection was accepted in secure-listener mode.
    secure: bool,
    /// Whether the connection is still considered alive.
    alive: bool,
};

/// Result returned by one shared request-behavior callback.
pub const MiddlewareDecision = enum {
    /// Continue into the next middleware or the matched route.
    continue_processing,
    /// Stop processing because the middleware already produced the response.
    handled,
};

/// Shared request behavior applied before route-specific handling.
pub const Middleware = struct {
    /// Stable middleware name used for diagnostics.
    name: []const u8,
    /// Optional opaque middleware context.
    context: ?*anyopaque,
    /// Callback invoked before route dispatch.
    handler: *const fn (
        ctx: ?*anyopaque,
        request: *ServerRequest,
        writer: *ServerResponseWriter,
    ) anyerror!MiddlewareDecision,
};

/// One exact method/path route definition.
pub const Route = struct {
    /// Stable route name used for diagnostics.
    name: []const u8,
    /// Exact HTTP method match for the route.
    method: core.Method,
    /// Exact request path match for the route.
    path: []const u8,
    /// Route-specific handler callback.
    handler: Handler,
    /// Optional route-specific handler context.
    handler_context: ?*anyopaque,
};

/// Optional fallback handler used when no route matches the request.
pub const FallbackHandler = struct {
    /// Fallback callback invoked for unmapped requests.
    handler: Handler,
    /// Optional fallback callback context.
    handler_context: ?*anyopaque,
};

/// Conflict policy used when more than one route matches the same identity.
pub const RouteAmbiguityPolicy = enum {
    /// Reject duplicate exact method/path pairs during validation.
    reject_duplicates,
    /// Allow duplicates and dispatch the first registered route.
    first_registered,
};

/// Typed higher-level routing surface layered over the core runtime handler.
pub const RouteCatalog = struct {
    /// Exact routes available for dispatch.
    routes: []const Route,
    /// Shared request behaviors executed before route dispatch.
    middleware: []const Middleware,
    /// Optional fallback handler for unmatched requests.
    fallback: ?FallbackHandler,
    /// Conflict policy for duplicate route identities.
    ambiguity_policy: RouteAmbiguityPolicy,

    /// Returns an empty route catalog with default validation policy.
    pub fn empty() RouteCatalog {
        return .{
            .routes = &.{},
            .middleware = &.{},
            .fallback = null,
            .ambiguity_policy = .reject_duplicates,
        };
    }

    /// Validates duplicate route identities under the selected policy.
    pub fn validate(self: RouteCatalog) ConfigError!void {
        if (self.ambiguity_policy != .reject_duplicates) {
            return;
        }

        for (self.routes, 0..) |route, index| {
            for (self.routes[index + 1 ..]) |other| {
                if (routeIdentityEquals(route, other)) {
                    return error.InvalidRouteCatalog;
                }
            }
        }
    }
};

/// Public server configuration for the runtime and CLI.
pub const ServerConfig = struct {
    /// Host or IPv4 literal to bind.
    listen_host: []const u8,
    /// TCP port to bind.
    port: core.Port,
    /// Request handler callback.
    handler: Handler,
    /// Optional handler callback context.
    handler_context: ?*anyopaque,
    /// Optional TLS listener configuration.
    tls: ?core.TlsConfig,
    /// ALPN protocols the listener is willing to advertise.
    alpn: []const core.NegotiatedProtocol,
    /// Enables minimal HTTP/2 negotiation planning.
    http2_enabled: bool,
    /// Optional HTTP/3 UDP listener configuration.
    http3: ?Http3ListenerConfig,
    /// Runtime connection and parsing limits.
    connection_limits: ConnectionLimits,
    /// Optional higher-level route catalog layered on top of the core handler.
    router: ?RouteCatalog,

    /// Returns a loopback-friendly default configuration.
    pub fn init(handler: Handler) ServerConfig {
        return .{
            .listen_host = "127.0.0.1",
            .port = core.Port.init(8080),
            .handler = handler,
            .handler_context = null,
            .tls = null,
            .alpn = &default_alpn_protocols,
            .http2_enabled = false,
            .http3 = null,
            .connection_limits = ConnectionLimits.default(),
            .router = null,
        };
    }

    /// Returns the authoritative TLS configuration with routed ALPN ordering applied.
    pub fn effectiveTlsConfig(self: ServerConfig) ?core.TlsConfig {
        if (self.tls) |tls| {
            return tls.withAlpnProtocols(self.alpn);
        }
        return null;
    }

    /// Validates the configuration before binding the listener.
    pub fn validate(self: ServerConfig) ConfigError!void {
        if (self.effectiveTlsConfig()) |tls| {
            try tls_config.validate(tls);
            if (tls.certificate_chain_path == null or tls.private_key_path == null) {
                return error.MissingTlsIdentity;
            }
        }

        if (self.http2_enabled) {
            if (self.tls == null) {
                return error.InvalidHttp2Configuration;
            }
            if (!supportsProtocol(self.alpn, .h2)) {
                return error.InvalidHttp2Configuration;
            }
        }
        if (self.http3) |http3| {
            try http3.validate();
        }
        if (self.router) |router| {
            try router.validate();
        }
    }
};

/// Typed server-side request view exposed to handlers.
pub const ServerRequest = struct {
    /// Allocator used for owned request storage.
    allocator: std.mem.Allocator,
    /// HTTP method from the request line.
    method: core.Method,
    /// Parsed HTTP version.
    version: core.Version,
    /// Parsed request URI.
    uri: core.Uri,
    /// Request headers.
    headers: core.Headers,
    /// Optional streaming request body reader.
    body: ?core.BodyReader,
    /// Peer address for the accepted socket.
    peer: std.net.Address,
    /// Negotiated protocol label for the connection.
    negotiated_protocol: core.NegotiatedProtocol,
    /// Whether the accepted connection ran in secure-listener mode.
    secure: bool,
    /// Stable TLS identity token when secure-listener mode is active.
    identity_token: ?core.TlsIdentityToken,
    /// Negotiated-session metadata for the accepted connection.
    session: NegotiatedSession,
    /// Owned host bytes backing `uri.host`.
    owned_host: []u8,
    /// Owned path bytes backing `uri.path`.
    owned_path: []u8,
    /// Owned query bytes backing `uri.query`, when present.
    owned_query: ?[]u8,

    /// Releases all owned request storage.
    pub fn deinit(self: *ServerRequest) void {
        if (self.body) |body_reader| {
            body_reader.close();
            self.body = null;
        }
        self.headers.deinit();
        self.allocator.free(self.owned_host);
        self.allocator.free(self.owned_path);
        if (self.owned_query) |query| {
            self.allocator.free(query);
            self.owned_query = null;
        }
        self.* = undefined;
    }

    /// Returns the first header value matching the name.
    pub fn header(self: *const ServerRequest, name: []const u8) ?[]const u8 {
        return self.headers.get(name);
    }

    /// Reads the remaining request body into owned memory.
    pub fn readBodyAlloc(
        self: *ServerRequest,
        allocator: std.mem.Allocator,
        max_bytes: usize,
    ) ![]u8 {
        var collected = std.ArrayListUnmanaged(u8){};
        errdefer collected.deinit(allocator);

        if (self.body) |body_reader| {
            var buffer: [4096]u8 = undefined;
            while (true) {
                const read_len = try body_reader.read(&buffer);
                if (read_len == 0) {
                    break;
                }
                if (collected.items.len + read_len > max_bytes) {
                    return error.BodyTooLarge;
                }
                try collected.appendSlice(allocator, buffer[0..read_len]);
            }
        }

        return collected.toOwnedSlice(allocator);
    }
};

/// Typed streaming response sink exposed to handlers.
pub const ServerResponseWriter = struct {
    /// Opaque writer context managed by the protocol layer.
    ctx: ?*anyopaque,
    /// Current response status.
    status: core.Status,
    /// Response headers emitted before the body.
    headers: core.Headers,
    /// Optional trailer headers for chunked responses.
    trailers: core.Headers,
    /// Streaming body writer surface.
    body_writer: BodyWriter,
    /// Current writer state.
    state: WriterState,
    /// Callback that emits response headers.
    begin_fn: *const fn (ctx: ?*anyopaque, writer: *ServerResponseWriter) anyerror!void,
    /// Callback that finalizes the response.
    finish_fn: *const fn (ctx: ?*anyopaque, writer: *ServerResponseWriter) anyerror!void,
    /// Optional callback that destroys the protocol writer context.
    destroy_ctx_fn: ?*const fn (ctx: ?*anyopaque) void,

    /// Initializes a protocol-backed response writer.
    pub fn init(
        allocator: std.mem.Allocator,
        ctx: ?*anyopaque,
        write_all_fn: *const fn (ctx: ?*anyopaque, bytes: []const u8) anyerror!void,
        begin_fn: *const fn (ctx: ?*anyopaque, writer: *ServerResponseWriter) anyerror!void,
        finish_fn: *const fn (ctx: ?*anyopaque, writer: *ServerResponseWriter) anyerror!void,
        destroy_ctx_fn: ?*const fn (ctx: ?*anyopaque) void,
    ) ServerResponseWriter {
        return .{
            .ctx = ctx,
            .status = .ok,
            .headers = core.Headers.init(allocator),
            .trailers = core.Headers.init(allocator),
            .body_writer = .{
                .ctx = ctx,
                .write_all_fn = write_all_fn,
            },
            .state = .idle,
            .begin_fn = begin_fn,
            .finish_fn = finish_fn,
            .destroy_ctx_fn = destroy_ctx_fn,
        };
    }

    /// Releases owned headers and any protocol-owned context.
    pub fn deinit(self: *ServerResponseWriter) void {
        self.headers.deinit();
        self.trailers.deinit();
        if (self.destroy_ctx_fn) |destroy_ctx_fn| {
            destroy_ctx_fn(self.ctx);
        }
        self.* = undefined;
    }

    /// Sets the response status code.
    pub fn setStatus(self: *ServerResponseWriter, status: core.Status) void {
        self.status = status;
    }

    /// Appends a response header before body streaming begins.
    pub fn appendHeader(self: *ServerResponseWriter, name: []const u8, value: []const u8) !void {
        try self.headers.append(name, value);
    }

    /// Appends a trailer header to emit when the response finishes.
    pub fn appendTrailer(self: *ServerResponseWriter, name: []const u8, value: []const u8) !void {
        try self.trailers.append(name, value);
    }

    /// Forces response headers to be emitted immediately.
    pub fn sendHeaders(self: *ServerResponseWriter) anyerror!void {
        if (self.state != .idle) {
            return;
        }
        try self.begin_fn(self.ctx, self);
        self.state = .headers_sent;
    }

    /// Streams one body chunk to the client.
    pub fn writeAll(self: *ServerResponseWriter, bytes: []const u8) anyerror!void {
        if (self.state == .finished) {
            return error.ResponseFinished;
        }
        if (self.state == .idle) {
            try self.sendHeaders();
        }
        try self.body_writer.writeAll(bytes);
        self.state = .streaming;
    }

    /// Finalizes the response.
    pub fn finish(self: *ServerResponseWriter) anyerror!void {
        if (self.state == .finished) {
            return;
        }
        if (self.state == .idle and self.headers.get("content-length") == null and self.headers.get("transfer-encoding") == null) {
            try self.headers.append("Content-Length", "0");
        }
        if (self.state == .idle) {
            try self.sendHeaders();
        }
        try self.finish_fn(self.ctx, self);
        self.state = .finished;
    }
};

/// Returns true when the protocol list contains the expected value.
fn supportsProtocol(
    protocols: []const core.NegotiatedProtocol,
    expected: core.NegotiatedProtocol,
) bool {
    for (protocols) |protocol| {
        if (protocol == expected) {
            return true;
        }
    }
    return false;
}

/// Returns true when two routes target the same exact method/path identity.
fn routeIdentityEquals(a: Route, b: Route) bool {
    return std.ascii.eqlIgnoreCase(a.method.asBytes(), b.method.asBytes()) and
        std.mem.eql(u8, a.path, b.path);
}

test "server config requires a full tls identity for listener mode" {
    const noop = struct {
        fn handle(_: ?*anyopaque, _: *ServerRequest, _: *ServerResponseWriter) !void {}
    };

    var config = ServerConfig.init(noop.handle);
    config.tls = core.TlsConfig.default();
    config.tls.?.certificate_chain_path = "server.pem";

    try std.testing.expectError(error.IncompleteIdentity, config.validate());
}

test "server config rejects http2 without tls alpn" {
    const noop = struct {
        fn handle(_: ?*anyopaque, _: *ServerRequest, _: *ServerResponseWriter) !void {}
    };

    var config = ServerConfig.init(noop.handle);
    config.http2_enabled = true;

    try std.testing.expectError(error.InvalidHttp2Configuration, config.validate());
}

test "route catalog rejects duplicate exact identities by default" {
    const noop = struct {
        fn handle(_: ?*anyopaque, _: *ServerRequest, _: *ServerResponseWriter) !void {}
    };

    const router = RouteCatalog{
        .routes = &.{
            .{
                .name = "health-a",
                .method = .get,
                .path = "/health",
                .handler = noop.handle,
                .handler_context = null,
            },
            .{
                .name = "health-b",
                .method = .get,
                .path = "/health",
                .handler = noop.handle,
                .handler_context = null,
            },
        },
        .middleware = &.{},
        .fallback = null,
        .ambiguity_policy = .reject_duplicates,
    };

    try std.testing.expectError(error.InvalidRouteCatalog, router.validate());
}
