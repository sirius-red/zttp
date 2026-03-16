//! Minimal server runtime that binds, accepts, and dispatches loopback requests.

const std = @import("std");
const core = @import("../types.zig");
const server_types = @import("types.zig");
const http1 = @import("http1.zig");
const http2 = @import("http2.zig");

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

    /// Binds a server to the configured listen address.
    pub fn init(allocator: std.mem.Allocator, config: server_types.ServerConfig) Error!Server {
        try config.validate();

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
        if (self.config.tls != null) {
            return error.TlsServerUnsupported;
        }

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

        const negotiated = http2.negotiate(self.config, null);
        _ = negotiated;

        var request = try http1.readRequest(
            self.allocator,
            connection.stream,
            if (self.config.tls != null) .https else .http,
            connection.address,
            .http_1_1,
            self.config.connection_limits,
        );
        defer request.deinit();

        var writer = try http1.initResponseWriter(self.allocator, connection.stream, request.version);
        defer writer.deinit();

        try self.config.handler(self.config.handler_context, &request, &writer);
        try writer.finish();
    }
};

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
