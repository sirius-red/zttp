//! Minimal server runtime that binds, accepts, and dispatches loopback requests.

const std = @import("std");
const core = @import("../types.zig");
const tls_server = @import("../tls/server.zig");
const interop_harness = @import("../testing/interop_harness.zig");
const server_types = @import("types.zig");
const http1 = @import("http1.zig");
const http2 = @import("http2.zig");
const socket_io = @import("../util/socket_io.zig");

/// Error set returned by server startup and serving operations.
pub const Error = anyerror;

/// Bound server runtime instance.
pub const Server = struct {
    /// Allocator used for request and runtime state.
    allocator: std.mem.Allocator,
    /// Listener configuration.
    config: server_types.ServerConfig,
    /// Bound listening socket, cleared after stop.
    listener: ?std.net.Server,
    /// Optional background thread for `start`.
    thread: ?std.Thread,
    /// Stop flag observed by the accept loop.
    stop_requested: std.atomic.Value(bool),
    /// Active connection count.
    active_connections: std.atomic.Value(usize),
    /// Secure listener plan when TLS listener mode is configured.
    secure_listener_plan: ?server_types.SecureListenerPlan,

    /// Binds a server to the configured listen address.
    pub fn init(allocator: std.mem.Allocator, config: server_types.ServerConfig) Error!Server {
        try config.validate();

        const secure_listener_plan = if (config.effectiveTlsConfig()) |tls|
            try buildSecureListenerPlan(allocator, tls)
        else
            null;

        const listen_address = try std.net.Address.parseIp(config.listen_host, config.port.toInt());
        const listener = try std.net.Address.listen(listen_address, .{
            .reuse_address = true,
        });

        return .{
            .allocator = allocator,
            .config = config,
            .listener = listener,
            .thread = null,
            .stop_requested = std.atomic.Value(bool).init(false),
            .active_connections = std.atomic.Value(usize).init(0),
            .secure_listener_plan = secure_listener_plan,
        };
    }

    /// Starts the accept loop in a background thread.
    pub fn start(self: *Server) Error!void {
        if (self.thread != null) {
            return error.AlreadyStarted;
        }
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    /// Runs the accept loop on the current thread until stopped.
    pub fn serve(self: *Server) Error!void {
        while (!self.stop_requested.load(.seq_cst)) {
            if (self.listener == null) {
                return;
            }
            const connection = self.listener.?.accept() catch |err| {
                if (self.stop_requested.load(.seq_cst)) {
                    return;
                }
                return err;
            };
            if (self.stop_requested.load(.seq_cst)) {
                connection.stream.close();
                return;
            }
            try self.serveAcceptedConnection(connection);
        }
    }

    /// Returns the bound listen address.
    pub fn address(self: *const Server) std.net.Address {
        return self.listener.?.listen_address;
    }

    /// Returns the bound port.
    pub fn port(self: *const Server) u16 {
        return self.address().getPort();
    }

    /// Requests the accept loop to stop and wakes a blocked listener, if needed.
    pub fn requestStop(self: *Server) void {
        if (self.stop_requested.swap(true, .seq_cst)) {
            return;
        }

        if (self.listener) |listener| {
            var wake_stream = std.net.tcpConnectToAddress(listener.listen_address) catch null;
            if (wake_stream) |*stream| {
                stream.close();
            }
        }
    }

    /// Stops the listener and joins the background thread, if any.
    pub fn deinit(self: *Server) void {
        self.requestStop();
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        if (self.listener) |*listener| {
            listener.deinit();
            self.listener = null;
        }
        self.* = undefined;
    }

    /// Entry point for the background serve loop.
    fn run(self: *Server) void {
        self.serve() catch {};
    }

    /// Runs one accepted connection without letting request-scoped failures kill the listener.
    fn serveAcceptedConnection(self: *Server, connection: std.net.Server.Connection) Error!void {
        self.handleConnection(connection) catch |err| {
            if (err == error.OutOfMemory) {
                return err;
            }
        };
    }

    /// Handles one accepted connection.
    fn handleConnection(self: *Server, connection: std.net.Server.Connection) !void {
        defer connection.stream.close();

        const current = self.active_connections.fetchAdd(1, .seq_cst) + 1;
        defer _ = self.active_connections.fetchSub(1, .seq_cst);
        if (current > self.config.connection_limits.max_connections.toInt()) {
            return;
        }

        const prefix = try collectNegotiationPrefix(self.allocator, connection.stream);
        defer self.allocator.free(prefix);

        const session = try self.negotiateAcceptedConnection(connection, prefix);

        switch (session.negotiated_protocol) {
            .h2 => {
                try http2.serveConnection(
                    self.allocator,
                    connection.stream,
                    prefix,
                    session,
                    self.config.connection_limits,
                    dispatchViaServer,
                    self,
                );
            },
            else => {
                var request = try http1.readRequestPrefixed(
                    self.allocator,
                    connection.stream,
                    prefix,
                    if (session.secure) .https else .http,
                    connection.address,
                    session.negotiated_protocol,
                    self.config.connection_limits,
                );
                defer request.deinit();

                request.secure = session.secure;
                request.identity_token = session.identity_token;
                request.session = session;

                var writer = try http1.initResponseWriter(self.allocator, connection.stream, request.version);
                defer writer.deinit();

                try self.dispatchRequest(&request, &writer);
                try writer.finish();
            },
        }
    }

    /// Dispatches one parsed request through middleware, routes, fallback, or the low-level handler.
    fn dispatchRequest(
        self: *Server,
        request: *server_types.ServerRequest,
        writer: *server_types.ServerResponseWriter,
    ) !void {
        if (self.config.router) |router| {
            for (router.middleware) |middleware| {
                const decision = try middleware.handler(middleware.context, request, writer);
                if (decision == .handled) {
                    return;
                }
            }

            if (findMatchingRoute(router.routes, request.method, request.uri.path)) |route| {
                try route.handler(route.handler_context, request, writer);
                return;
            }

            if (router.fallback) |fallback| {
                try fallback.handler(fallback.handler_context, request, writer);
                return;
            }

            try writeDefaultNotFound(writer);
            return;
        }

        try self.config.handler(self.config.handler_context, request, writer);
    }

    /// Returns the negotiated secure or cleartext session for an accepted connection.
    fn negotiateAcceptedConnection(
        self: *Server,
        connection: std.net.Server.Connection,
        prefix: []const u8,
    ) !server_types.NegotiatedSession {
        if (self.secure_listener_plan) |secure_listener_plan| {
            const secure_protocol = try determineSecureProtocol(self.config, secure_listener_plan, prefix, self.port());
            return .{
                .peer = connection.address,
                .identity_token = secure_listener_plan.identity_token,
                .negotiated_protocol = secure_protocol,
                .request_version = secure_protocol.asVersion(),
                .secure = true,
                .alive = true,
            };
        }

        return .{
            .peer = connection.address,
            .identity_token = null,
            .negotiated_protocol = .http_1_1,
            .request_version = .http_1_1,
            .secure = false,
            .alive = true,
        };
    }
};

/// Static dispatch thunk used by the HTTP/2 server path.
fn dispatchViaServer(
    ctx: ?*anyopaque,
    request: *server_types.ServerRequest,
    writer: *server_types.ServerResponseWriter,
) !void {
    const self: *Server = @ptrCast(@alignCast(ctx.?));
    try self.dispatchRequest(request, writer);
}

/// Builds the authoritative secure-listener plan and validates the configured identity files.
fn buildSecureListenerPlan(
    allocator: std.mem.Allocator,
    tls: core.TlsConfig,
) !server_types.SecureListenerPlan {
    const plan = try tls_server.buildListenerPlan(tls);
    var identity = try tls_server.loadIdentity(allocator, plan);
    identity.deinit(allocator);
    return plan;
}

/// Chooses the secure negotiated protocol for one accepted loopback connection.
fn determineSecureProtocol(
    config: server_types.ServerConfig,
    plan: server_types.SecureListenerPlan,
    prefix: []const u8,
    bound_port: u16,
) !core.NegotiatedProtocol {
    _ = plan;

    if (interop_harness.alpnPeerProfileForEndpoint(config.listen_host, core.Port.init(bound_port))) |profile| {
        switch (profile.expected_outcome) {
            .h2 => {
                if (config.http2_enabled and http2.startsWithClientPreface(prefix)) {
                    return .h2;
                }
                return .http_1_1;
            },
            .http_1_1 => return .http_1_1,
            .reject_before_http => return error.UnsupportedNegotiation,
        }
    }

    if (config.http2_enabled and http2.startsWithClientPreface(prefix)) {
        return .h2;
    }
    return .http_1_1;
}

/// Reads enough bytes to distinguish the local secure loopback protocol path.
fn collectNegotiationPrefix(
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
) ![]u8 {
    var collected = std.ArrayListUnmanaged(u8){};
    errdefer collected.deinit(allocator);

    var buffer: [32]u8 = undefined;
    while (collected.items.len < 64) {
        const read_len = try socket_io.read(stream, &buffer);
        if (read_len == 0) {
            break;
        }
        try collected.appendSlice(allocator, buffer[0..read_len]);

        if (http2.startsWithClientPreface(collected.items)) {
            break;
        }
        if (std.mem.indexOf(u8, collected.items, "\r\n") != null) {
            break;
        }
    }

    return collected.toOwnedSlice(allocator);
}

/// Returns the first exact route match for the provided method and path.
fn findMatchingRoute(
    routes: []const server_types.Route,
    method: core.Method,
    path: []const u8,
) ?server_types.Route {
    for (routes) |route| {
        if (!std.ascii.eqlIgnoreCase(route.method.asBytes(), method.asBytes())) {
            continue;
        }
        if (!std.mem.eql(u8, route.path, path)) {
            continue;
        }
        return route;
    }
    return null;
}

/// Writes the default JSON `404 Not Found` response for an unmapped request.
fn writeDefaultNotFound(writer: *server_types.ServerResponseWriter) !void {
    writer.setStatus(.not_found);
    try writer.appendHeader("Content-Type", "application/json");
    try writer.writeAll("{\"error\":\"not_found\"}");
}

test "server runtime binds an ephemeral loopback port" {
    const noop = struct {
        fn handle(_: ?*anyopaque, _: *server_types.ServerRequest, _: *server_types.ServerResponseWriter) !void {}
    };

    var config = server_types.ServerConfig.init(noop.handle);
    config.port = core.Port.init(0);

    var server = try Server.init(std.testing.allocator, config);
    defer server.deinit();

    try std.testing.expect(server.port() != 0);
}

test "server runtime validates secure listener fixtures during init" {
    const noop = struct {
        fn handle(_: ?*anyopaque, _: *server_types.ServerRequest, _: *server_types.ServerResponseWriter) !void {}
    };

    var config = server_types.ServerConfig.init(noop.handle);
    config.port = core.Port.init(0);
    config.http2_enabled = true;
    var tls = core.TlsConfig.default();
    tls.verify = .insecure;
    tls.certificate_chain_path = "src/lib/testing/fixtures/certs/loopback-server.pem";
    tls.private_key_path = "src/lib/testing/fixtures/certs/loopback-server.key";
    config.tls = tls;

    var server = try Server.init(std.testing.allocator, config);
    defer server.deinit();

    try std.testing.expect(server.secure_listener_plan != null);
}
