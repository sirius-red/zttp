//! Minimal HTTP/1.1 test server harness for local integration tests.

const std = @import("std");
const types = @import("../types.zig");
const socket_io = @import("../util/socket_io.zig");

/// Header name/value pair for response construction.
pub const Header = struct {
    /// Header name.
    name: []const u8,
    /// Header value.
    value: []const u8,
};

/// Structured HTTP response definition for canned responses.
pub const Response = struct {
    /// HTTP version to emit on the status line.
    version: types.Version = .http_1_1,
    /// HTTP status code to emit.
    status: types.Status = .ok,
    /// Reason phrase to emit with the status line.
    reason: []const u8 = "OK",
    /// Response headers to emit before the body.
    headers: []const Header = &.{},
    /// Response body bytes.
    body: []const u8 = "",
};

/// Response payload variant for a scenario step.
pub const ResponsePayload = union(enum) {
    /// Build a response from structured fields.
    response: Response,
    /// Send raw bytes exactly as provided.
    raw: []const u8,
};

/// Single request/response step within a connection.
pub const Step = struct {
    /// Response payload for this step.
    payload: ResponsePayload,
    /// Read and discard a request before sending the response.
    read_request: bool = true,
    /// Optional substring expected in the request headers.
    expect_request_contains: ?[]const u8 = null,
    /// Delay before sending the response payload.
    delay_before_ns: u64 = 0,
    /// Close the connection after sending the response.
    close_after: bool = true,
};

/// Scenario describing responses for one connection.
pub const Scenario = struct {
    /// Steps to execute in sequence for the connection.
    steps: []const Step,
};

/// Server configuration options.
pub const Options = struct {
    /// Address to listen on.
    listen_address: std.net.Address,
    /// Maximum request header bytes to read per step.
    max_request_bytes: usize,
    /// Enable socket address reuse.
    reuse_address: bool,

    /// Returns default options for localhost on an ephemeral port.
    pub fn default() Options {
        return .{
            .listen_address = std.net.Address.parseIp("127.0.0.1", 0) catch unreachable,
            .max_request_bytes = 32 * 1024,
            .reuse_address = true,
        };
    }
};

/// Error set returned by `start`.
pub const StartError = error{AlreadyStarted} || std.Thread.SpawnError;

/// Error set returned by request header reads.
pub const ReadRequestError = std.net.Stream.ReadError || error{
    LimitExceeded,
    EndOfStream,
    MissingExpectedBytes,
};

/// Error set returned by response writes.
pub const WriteResponseError = std.net.Stream.WriteError || std.fmt.BufPrintError;

/// HTTP/1.1 test server harness.
pub const TestServer = struct {
    /// Listening server socket.
    server: std.net.Server,
    /// Scenarios served in order.
    scenarios: []const Scenario,
    /// Configuration options for the server.
    options: Options,
    /// Background thread running the accept loop.
    thread: ?std.Thread,

    /// Creates a test server bound to the provided address.
    pub fn init(scenarios: []const Scenario, options: Options) !TestServer {
        const server = try std.net.Address.listen(options.listen_address, .{
            .reuse_address = options.reuse_address,
        });

        return .{
            .server = server,
            .scenarios = scenarios,
            .options = options,
            .thread = null,
        };
    }

    /// Starts the accept loop in a background thread.
    pub fn start(self: *TestServer) StartError!void {
        if (self.thread != null) {
            return error.AlreadyStarted;
        }

        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    /// Returns the listening address.
    pub fn address(self: *const TestServer) std.net.Address {
        return self.server.listen_address;
    }

    /// Returns the port assigned to the server.
    pub fn port(self: *const TestServer) u16 {
        return self.server.listen_address.getPort();
    }

    /// Joins the background thread and closes the listening socket.
    pub fn deinit(self: *TestServer) void {
        self.server.deinit();
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
    }

    /// Runs the accept loop for each configured scenario.
    fn run(self: *TestServer) void {
        var index: usize = 0;
        while (index < self.scenarios.len) : (index += 1) {
            const connection = self.server.accept() catch return;
            handleConnection(self, connection, self.scenarios[index]) catch {};
        }
    }

    /// Handles a single connection according to the scenario steps.
    fn handleConnection(
        self: *TestServer,
        connection: std.net.Server.Connection,
        scenario: Scenario,
    ) !void {
        defer connection.stream.close();

        for (scenario.steps) |step| {
            if (step.read_request) {
                try readRequestHeaders(
                    connection.stream,
                    self.options.max_request_bytes,
                    step.expect_request_contains,
                );
            }

            if (step.delay_before_ns > 0) {
                std.Thread.sleep(step.delay_before_ns);
            }

            try sendPayload(connection.stream, step.payload, step.close_after);

            if (step.close_after) {
                break;
            }
        }
    }

    /// Sends the configured response payload to the stream.
    fn sendPayload(
        stream: std.net.Stream,
        payload: ResponsePayload,
        close_after: bool,
    ) !void {
        switch (payload) {
            .response => |response| try writeResponse(stream, response, close_after),
            .raw => |bytes| try stream.writeAll(bytes),
        }
    }

    /// Reads request headers until the header terminator is reached.
    fn readRequestHeaders(
        stream: std.net.Stream,
        max_bytes: usize,
        expect_contains: ?[]const u8,
    ) ReadRequestError!void {
        var buffer: [1024]u8 = undefined;
        var total: usize = 0;
        var state: u8 = 0;
        var match_index: usize = 0;
        var found = expect_contains == null;

        while (true) {
            const read_len = try socket_io.read(stream, &buffer);
            if (read_len == 0) {
                return error.EndOfStream;
            }

            total += read_len;
            if (total > max_bytes) {
                return error.LimitExceeded;
            }

            for (buffer[0..read_len]) |byte| {
                if (!found) {
                    const needle = expect_contains.?;
                    if (byte == needle[match_index]) {
                        match_index += 1;
                        if (match_index == needle.len) {
                            found = true;
                        }
                    } else {
                        match_index = if (byte == needle[0]) 1 else 0;
                    }
                }

                switch (state) {
                    0 => state = if (byte == '\r') 1 else 0,
                    1 => state = if (byte == '\n') 2 else if (byte == '\r') 1 else 0,
                    2 => state = if (byte == '\r') 3 else 0,
                    3 => {
                        if (byte == '\n') {
                            if (!found) {
                                return error.MissingExpectedBytes;
                            }
                            return;
                        }
                        state = 0;
                    },
                    else => state = 0,
                }
            }
        }
    }

    /// Writes a structured response to the stream.
    fn writeResponse(
        stream: std.net.Stream,
        response: Response,
        close_after: bool,
    ) WriteResponseError!void {
        var line_buffer: [256]u8 = undefined;

        const status_line = try std.fmt.bufPrint(
            &line_buffer,
            "{s} {d} {s}\r\n",
            .{ response.version.asBytes(), response.status.code(), response.reason },
        );
        try stream.writeAll(status_line);

        var has_content_length = false;
        var has_transfer_encoding = false;
        var has_connection = false;

        for (response.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
                has_content_length = true;
            } else if (std.ascii.eqlIgnoreCase(header.name, "transfer-encoding")) {
                has_transfer_encoding = true;
            } else if (std.ascii.eqlIgnoreCase(header.name, "connection")) {
                has_connection = true;
            }

            const header_line = try std.fmt.bufPrint(
                &line_buffer,
                "{s}: {s}\r\n",
                .{ header.name, header.value },
            );
            try stream.writeAll(header_line);
        }

        if (!has_content_length and !has_transfer_encoding) {
            const length_line = try std.fmt.bufPrint(
                &line_buffer,
                "Content-Length: {d}\r\n",
                .{response.body.len},
            );
            try stream.writeAll(length_line);
        }

        if (close_after and !has_connection) {
            try stream.writeAll("Connection: close\r\n");
        }

        try stream.writeAll("\r\n");

        if (response.body.len > 0) {
            try stream.writeAll(response.body);
        }
    }
};

test "test server emits canned response" {
    const scenarios = [_]Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{
                        .response = .{
                            .status = .ok,
                            .reason = "OK",
                            .headers = &.{
                                .{ .name = "Content-Type", .value = "text/plain" },
                            },
                            .body = "hello",
                        },
                    },
                },
            },
        },
    };

    var server = try TestServer.init(&scenarios, Options.default());
    defer server.deinit();
    try server.start();

    var stream = try std.net.tcpConnectToAddress(server.address());
    defer stream.close();

    try stream.writeAll("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");

    var response = std.ArrayList(u8).empty;
    defer response.deinit(std.testing.allocator);
    var buffer: [256]u8 = undefined;
    while (true) {
        const read_len = try socket_io.read(stream, &buffer);
        if (read_len == 0) {
            break;
        }
        try response.appendSlice(std.testing.allocator, buffer[0..read_len]);
    }

    try std.testing.expect(std.mem.containsAtLeast(u8, response.items, 1, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.containsAtLeast(u8, response.items, 1, "Content-Length: 5\r\n"));
    try std.testing.expect(std.mem.containsAtLeast(u8, response.items, 1, "\r\nhello"));
}

test "test server emits raw response" {
    const raw_response = "HTTP/1.1 200 OK\n\n";
    const scenarios = [_]Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{ .raw = raw_response },
                    .read_request = false,
                },
            },
        },
    };

    var server = try TestServer.init(&scenarios, Options.default());
    defer server.deinit();
    try server.start();

    var stream = try std.net.tcpConnectToAddress(server.address());
    defer stream.close();

    var response = std.ArrayList(u8).empty;
    defer response.deinit(std.testing.allocator);
    var buffer: [64]u8 = undefined;
    while (true) {
        const read_len = try socket_io.read(stream, &buffer);
        if (read_len == 0) {
            break;
        }
        try response.appendSlice(std.testing.allocator, buffer[0..read_len]);
    }
    try std.testing.expectEqualStrings(raw_response, response.items);
}
