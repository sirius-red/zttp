//! Public server-side configuration and request/response types.

const std = @import("std");
const core = @import("../types.zig");
const tls_config = @import("../tls/config.zig");

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

/// Error set returned by server configuration validation.
pub const ConfigError = tls_config.ValidationError || error{
    /// TLS listener mode requires both a certificate chain and private key.
    MissingTlsIdentity,
    /// HTTP/2 requires TLS ALPN advertising in this runtime.
    InvalidHttp2Configuration,
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
    /// Runtime connection and parsing limits.
    connection_limits: ConnectionLimits,

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
            .connection_limits = ConnectionLimits.default(),
        };
    }

    /// Validates the configuration before binding the listener.
    pub fn validate(self: ServerConfig) ConfigError!void {
        if (self.tls) |tls| {
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
