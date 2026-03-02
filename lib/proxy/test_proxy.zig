//! Minimal CONNECT proxy harness for integration tests.

const std = @import("std");

/// Proxy response used when rejecting a CONNECT request.
pub const RejectResponse = struct {
    /// Status code to return.
    status: u16,
    /// Reason phrase to return.
    reason: []const u8,
};

/// Proxy behavior mode.
pub const Mode = union(enum) {
    /// Accept CONNECT requests and tunnel bytes.
    tunnel: void,
    /// Reject CONNECT requests with a response.
    reject: RejectResponse,
};

/// Proxy configuration options.
pub const Options = struct {
    /// Address to listen on.
    listen_address: std.net.Address,
    /// Maximum request header bytes to read.
    max_request_bytes: usize,
    /// Optional substring expected in the CONNECT request.
    expect_connect_contains: ?[]const u8,
    /// Enable socket address reuse.
    reuse_address: bool,

    /// Returns default options for localhost on an ephemeral port.
    pub fn default() Options {
        return .{
            .listen_address = std.net.Address.parseIp("127.0.0.1", 0) catch unreachable,
            .max_request_bytes = 32 * 1024,
            .expect_connect_contains = null,
            .reuse_address = true,
        };
    }
};

/// Error set returned by `start`.
pub const StartError = error{AlreadyStarted} || std.Thread.SpawnError;

/// CONNECT request data parsed from a proxy client.
const ConnectRequest = struct {
    /// Allocator used for stored buffers.
    allocator: std.mem.Allocator,
    /// Parsed target host.
    host: []u8,
    /// Parsed target port.
    port: u16,
    /// Extra bytes after the CONNECT headers.
    extra: []u8,

    /// Releases stored buffers.
    fn deinit(self: *ConnectRequest) void {
        self.allocator.free(self.host);
        if (self.extra.len > 0) {
            self.allocator.free(self.extra);
        }
        self.* = undefined;
    }
};

/// Error set returned by CONNECT request parsing.
const ReadConnectError = std.mem.Allocator.Error || std.net.Stream.ReadError || error{
    EndOfStream,
    InvalidRequest,
    LimitExceeded,
    MissingExpectedBytes,
};

/// Target host and port parsed from CONNECT request lines.
const ConnectTarget = struct {
    /// Target host bytes.
    host: []const u8,
    /// Target port number.
    port: u16,
};

/// HTTP proxy harness that supports CONNECT for tests.
pub const TestProxy = struct {
    /// Allocator used for request parsing buffers.
    allocator: std.mem.Allocator,
    /// Listening server socket.
    server: std.net.Server,
    /// Behavior mode for CONNECT handling.
    mode: Mode,
    /// Configuration options for the proxy.
    options: Options,
    /// Background thread running the accept loop.
    thread: ?std.Thread,

    /// Creates a proxy bound to the provided address.
    pub fn init(allocator: std.mem.Allocator, mode: Mode, options: Options) !TestProxy {
        const server = try std.net.Address.listen(options.listen_address, .{
            .reuse_address = options.reuse_address,
        });

        return .{
            .allocator = allocator,
            .server = server,
            .mode = mode,
            .options = options,
            .thread = null,
        };
    }

    /// Starts the accept loop in a background thread.
    pub fn start(self: *TestProxy) StartError!void {
        if (self.thread != null) {
            return error.AlreadyStarted;
        }
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    /// Returns the listening address.
    pub fn address(self: *const TestProxy) std.net.Address {
        return self.server.listen_address;
    }

    /// Returns the port assigned to the proxy.
    pub fn port(self: *const TestProxy) u16 {
        return self.server.listen_address.getPort();
    }

    /// Joins the background thread and closes the listening socket.
    pub fn deinit(self: *TestProxy) void {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        self.server.deinit();
    }

    /// Runs the accept loop for incoming proxy connections.
    fn run(self: *TestProxy) void {
        while (true) {
            const connection = self.server.accept() catch return;
            handleConnection(self, connection) catch {};
        }
    }

    /// Handles a single proxy connection.
    fn handleConnection(self: *TestProxy, connection: std.net.Server.Connection) !void {
        defer connection.stream.close();

        var request = try readConnectRequest(
            self.allocator,
            connection.stream,
            self.options.max_request_bytes,
            self.options.expect_connect_contains,
        );
        defer request.deinit();

        switch (self.mode) {
            .reject => |response| {
                try writeResponse(connection.stream, response.status, response.reason);
                return;
            },
            .tunnel => {},
        }

        var upstream = std.net.tcpConnectToHost(self.allocator, request.host, request.port) catch {
            try writeResponse(connection.stream, 502, "Bad Gateway");
            return;
        };
        defer upstream.close();

        try writeResponse(connection.stream, 200, "Connection Established");

        if (request.extra.len > 0) {
            try upstream.writeAll(request.extra);
        }

        var forward = try std.Thread.spawn(.{}, copyStream, .{ connection.stream, upstream });
        copyStream(upstream, connection.stream);
        forward.join();
    }

    /// Reads and parses a CONNECT request.
    fn readConnectRequest(
        allocator: std.mem.Allocator,
        stream: std.net.Stream,
        max_bytes: usize,
        expect_contains: ?[]const u8,
    ) ReadConnectError!ConnectRequest {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();

        var temp: [1024]u8 = undefined;
        var header_end: ?usize = null;

        while (header_end == null) {
            const read_len = try stream.read(&temp);
            if (read_len == 0) {
                return error.EndOfStream;
            }
            try buffer.appendSlice(temp[0..read_len]);
            if (buffer.items.len > max_bytes) {
                return error.LimitExceeded;
            }
            if (std.mem.indexOf(u8, buffer.items, "\r\n\r\n")) |index| {
                header_end = index + 4;
            }
        }

        const header_bytes = buffer.items[0..header_end.?];
        if (expect_contains) |needle| {
            if (!std.mem.containsAtLeast(u8, header_bytes, 1, needle)) {
                return error.MissingExpectedBytes;
            }
        }

        const line_end = std.mem.indexOf(u8, header_bytes, "\r\n") orelse return error.InvalidRequest;
        const request_line = header_bytes[0..line_end];

        var parts = std.mem.splitScalar(u8, request_line, ' ');
        const method = parts.next() orelse return error.InvalidRequest;
        const target = parts.next() orelse return error.InvalidRequest;
        _ = parts.next() orelse return error.InvalidRequest;

        if (!std.mem.eql(u8, method, "CONNECT")) {
            return error.InvalidRequest;
        }

        const parsed = parseConnectTarget(target) orelse return error.InvalidRequest;
        const host_copy = try allocator.dupe(u8, parsed.host);
        errdefer allocator.free(host_copy);

        const extra = buffer.items[header_end.?..];
        var extra_copy: []u8 = &[_]u8{};
        if (extra.len > 0) {
            extra_copy = try allocator.dupe(u8, extra);
        }

        return .{
            .allocator = allocator,
            .host = host_copy,
            .port = parsed.port,
            .extra = extra_copy,
        };
    }

    /// Parses the CONNECT target host and port.
    fn parseConnectTarget(value: []const u8) ?ConnectTarget {
        if (value.len == 0) {
            return null;
        }

        if (value[0] == '[') {
            const closing = std.mem.indexOfScalar(u8, value, ']') orelse return null;
            const host = value[1..closing];
            if (host.len == 0) {
                return null;
            }
            if (closing + 1 >= value.len or value[closing + 1] != ':') {
                return null;
            }
            const port_str = value[closing + 2 ..];
            const port_value = std.fmt.parseInt(u16, port_str, 10) catch return null;
            return .{ .host = host, .port = port_value };
        }

        const colon = std.mem.lastIndexOfScalar(u8, value, ':') orelse return null;
        if (colon == 0 or colon == value.len - 1) {
            return null;
        }
        const host = value[0..colon];
        const port_str = value[colon + 1 ..];
        const port_value = std.fmt.parseInt(u16, port_str, 10) catch return null;
        return .{ .host = host, .port = port_value };
    }

    /// Writes a simple HTTP response to the stream.
    fn writeResponse(stream: std.net.Stream, status: u16, reason: []const u8) !void {
        var line_buffer: [256]u8 = undefined;
        const line = try std.fmt.bufPrint(&line_buffer, "HTTP/1.1 {d} {s}\r\n\r\n", .{ status, reason });
        try stream.writeAll(line);
    }

    /// Forwards bytes from src to dst until EOF or error.
    fn copyStream(src: std.net.Stream, dst: std.net.Stream) void {
        var buffer: [4096]u8 = undefined;
        while (true) {
            const read_len = src.read(&buffer) catch return;
            if (read_len == 0) {
                return;
            }
            dst.writeAll(buffer[0..read_len]) catch return;
        }
    }
};
