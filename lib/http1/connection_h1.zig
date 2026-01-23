//! HTTP/1.1 connection thread and request execution.

const std = @import("std");
const builtin = @import("builtin");
const types = @import("../types.zig");
const mailbox = @import("../util/mailbox.zig");
const future = @import("../util/future.zig");
const body_pipe = @import("../util/body_pipe.zig");
const request_encoder = @import("request_encoder.zig");
const response_parser = @import("response_parser.zig");

/// HTTP/1.1 connection implementation backed by a dedicated thread.
pub const ConnectionH1 = struct {
    /// Allocator used for per-request allocations.
    allocator: std.mem.Allocator,
    /// Origin this connection is bound to.
    origin: Origin,
    /// Runtime configuration options.
    options: Options,
    /// Mailbox used for command dispatch.
    mailbox: Mailbox,
    /// Background thread handling requests.
    thread: ?std.Thread,
    /// Active TCP stream or null when disconnected.
    stream: ?std.net.Stream,

    /// Error set returned by connection operations.
    pub const Error = error{
        /// Operation exceeded a timeout.
        Timeout,
        /// URI is invalid or unsupported.
        InvalidUri,
        /// Transport failure (DNS/TCP).
        Transport,
        /// Protocol violation or malformed data.
        Protocol,
        /// Configured limit was exceeded.
        LimitExceeded,
        /// Operation was canceled.
        Canceled,
        /// Allocation failed.
        OutOfMemory,
    };

    /// Future type for HTTP/1.1 responses.
    pub const ResponseFuture = future.RequestFuture(types.Response, Error);

    /// Connection origin information.
    pub const Origin = struct {
        /// Scheme associated with the origin.
        scheme: types.Scheme,
        /// Hostname or IP literal for the origin.
        host: []const u8,
        /// Port for the origin.
        port: types.Port,
    };

    /// Connection configuration options.
    pub const Options = struct {
        /// Connection timeout in nanoseconds.
        connect_timeout_ns: ?u64,
        /// Write timeout in nanoseconds.
        write_timeout_ns: ?u64,
        /// Read timeout in nanoseconds.
        read_timeout_ns: ?u64,
        /// Total request timeout in nanoseconds.
        request_timeout_ns: ?u64,
        /// Maximum total header bytes.
        max_header_bytes: usize,
        /// Maximum number of header fields.
        max_header_count: usize,
        /// Maximum length of the status line in bytes.
        max_status_line_bytes: usize,
        /// Maximum total response body bytes, or null for unlimited.
        max_body_bytes: ?usize,
        /// Maximum chunk size in bytes.
        max_chunk_size: usize,
        /// Buffer size for socket reads.
        io_buffer_bytes: usize,
        /// Buffer size for response body streaming.
        body_buffer_bytes: usize,

        /// Returns default connection options.
        pub fn default() Options {
            const limits = response_parser.Limits.default();
            return .{
                .connect_timeout_ns = null,
                .write_timeout_ns = null,
                .read_timeout_ns = null,
                .request_timeout_ns = null,
                .max_header_bytes = limits.max_header_bytes,
                .max_header_count = limits.max_header_count,
                .max_status_line_bytes = limits.max_status_line_bytes,
                .max_body_bytes = limits.max_body_bytes,
                .max_chunk_size = limits.max_chunk_size,
                .io_buffer_bytes = 16 * 1024,
                .body_buffer_bytes = 64 * 1024,
            };
        }
    };

    /// Error set returned by `start`.
    pub const StartError = error{AlreadyStarted} || std.Thread.SpawnError;
    /// Error set returned by `submit`.
    pub const SubmitError = Mailbox.SendError || error{NotStarted};

    /// Initializes a connection without starting the background thread.
    pub fn init(allocator: std.mem.Allocator, origin: Origin, options: Options) ConnectionH1 {
        return .{
            .allocator = allocator,
            .origin = origin,
            .options = options,
            .mailbox = Mailbox.init(allocator),
            .thread = null,
            .stream = null,
        };
    }

    /// Starts the background thread to service requests.
    pub fn start(self: *ConnectionH1) StartError!void {
        if (self.thread != null) {
            return error.AlreadyStarted;
        }
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    /// Submits a request for execution.
    pub fn submit(
        self: *ConnectionH1,
        request: *const types.Request,
        completion: ResponseFuture.Completion,
    ) SubmitError!void {
        if (self.thread == null) {
            return error.NotStarted;
        }
        try self.mailbox.send(.{ .request = .{ .request = request, .completion = completion } });
    }

    /// Stops the connection thread and releases resources.
    pub fn deinit(self: *ConnectionH1) void {
        self.mailbox.close();
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        self.mailbox.deinit();
        self.closeStream();
    }

    /// Command mailbox type.
    const Mailbox = mailbox.Mailbox(Command);

    /// Command payloads handled by the connection thread.
    const Command = union(enum) {
        /// Execute a request.
        request: RequestCommand,
        /// Shutdown command.
        shutdown: void,
    };

    /// Request command payload.
    const RequestCommand = struct {
        /// Request to execute.
        request: *const types.Request,
        /// Completion handle for the response.
        completion: ResponseFuture.Completion,
    };

    /// Runs the connection loop until the mailbox is closed.
    fn run(self: *ConnectionH1) void {
        defer self.closeStream();
        while (true) {
            const cmd = self.mailbox.recv() catch return;
            switch (cmd) {
                .request => |req| self.handleRequest(req),
                .shutdown => return,
            }
        }
    }

    /// Executes the request command and completes the future.
    fn handleRequest(self: *ConnectionH1, cmd: RequestCommand) void {
        var completion = cmd.completion;
        const request_start = std.time.nanoTimestamp();
        var attempts: u8 = 0;
        while (true) {
            const had_stream = self.stream != null;
            const response_info = self.execute(cmd.request, request_start) catch |err| {
                if (attempts == 0 and had_stream and isRetryableRequest(cmd.request) and err == error.Transport) {
                    attempts += 1;
                    self.closeStream();
                    continue;
                }
                _ = completion.finish(err);
                self.closeStream();
                return;
            };

            var response = response_info.response;
            const keep_alive = shouldKeepAlive(cmd.request, response);
            if (response_info.body) |body_reader| {
                const pipe = body_pipe.BodyPipe.init(self.allocator, self.options.body_buffer_bytes) catch |err| {
                    response.deinit();
                    _ = completion.finish(mapPipeInitError(err));
                    body_reader.close();
                    self.closeStream();
                    return;
                };

                response.body = .{
                    .ctx = pipe,
                    .read_fn = body_pipe.BodyPipe.read,
                    .close_fn = body_pipe.BodyPipe.closeReader,
                };

                if (!completion.finish(response)) {
                    response.deinit();
                    body_reader.close();
                    pipe.closeWriter(error.Canceled);
                    pipe.closeReaderHandle();
                    self.closeStream();
                    return;
                }

                self.forwardBody(body_reader, pipe);
                if (!keep_alive) {
                    self.closeStream();
                }
                return;
            }

            if (!completion.finish(response)) {
                response.deinit();
                self.closeStream();
                return;
            }

            if (!keep_alive) {
                self.closeStream();
            }
            return;
        }
    }

    /// Returns true when the request can be retried safely.
    fn isRetryableRequest(request: *const types.Request) bool {
        if (request.body != null) {
            return false;
        }
        return isIdempotentMethod(request.method);
    }

    /// Returns true when the method is idempotent.
    fn isIdempotentMethod(method: types.Method) bool {
        return switch (method) {
            .get,
            .head,
            .put,
            .delete,
            .options,
            .trace,
            => true,
            else => false,
        };
    }

    /// Returns true when the connection should be kept alive after the response.
    fn shouldKeepAlive(request: *const types.Request, response: types.Response) bool {
        if (response.version == .http_1_0) {
            return false;
        }
        if (headerHasToken(&request.headers, "connection", "close")) {
            return false;
        }
        if (headerHasToken(&response.headers, "connection", "close")) {
            return false;
        }
        return true;
    }

    /// Returns true when the header contains the provided token.
    fn headerHasToken(headers: *const types.Headers, name: []const u8, token: []const u8) bool {
        if (headers.get(name)) |value| {
            return hasToken(value, token);
        }
        return false;
    }

    /// Returns true when the value contains the provided comma-separated token.
    fn hasToken(value: []const u8, token: []const u8) bool {
        var index: usize = 0;
        while (index < value.len) {
            while (index < value.len and (value[index] == ' ' or value[index] == '\t' or value[index] == ',')) {
                index += 1;
            }
            if (index >= value.len) {
                return false;
            }
            var end = index;
            while (end < value.len and value[end] != ',') {
                end += 1;
            }
            const part = std.mem.trim(u8, value[index..end], " \t");
            if (part.len != 0 and std.ascii.eqlIgnoreCase(part, token)) {
                return true;
            }
            index = if (end < value.len) end + 1 else end;
        }
        return false;
    }

    /// Executes the request and returns the parsed response.
    fn execute(self: *ConnectionH1, request: *const types.Request, request_start: i128) Error!ResponseInfo {
        try self.validateRequest(request);
        try self.ensureConnected(request_start);
        try self.sendRequest(request, request_start);
        return self.readResponse(request_start);
    }

    /// Parsed response and optional body reader for forwarding.
    const ResponseInfo = struct {
        /// Parsed response headers and metadata.
        response: types.Response,
        /// Body reader sourced from the socket.
        body: ?types.BodyReader,
    };

    /// Validates the request against the connection origin.
    fn validateRequest(self: *ConnectionH1, request: *const types.Request) Error!void {
        if (request.uri.scheme != self.origin.scheme) {
            return error.InvalidUri;
        }
        if (request.uri.scheme != .http) {
            return error.InvalidUri;
        }
        if (request.uri.host.len == 0) {
            return error.InvalidUri;
        }
        if (!std.ascii.eqlIgnoreCase(request.uri.host, self.origin.host)) {
            return error.InvalidUri;
        }
        if (request.uri.effectivePort().toInt() != self.origin.port.toInt()) {
            return error.InvalidUri;
        }
    }

    /// Ensures a TCP connection is established.
    fn ensureConnected(self: *ConnectionH1, request_start: i128) Error!void {
        if (self.stream != null) {
            return;
        }

        try self.checkRequestTimeout(request_start);

        const connect_start = std.time.nanoTimestamp();
        const stream = std.net.tcpConnectToHost(self.allocator, self.origin.host, self.origin.port.toInt()) catch {
            return error.Transport;
        };

        if (self.options.connect_timeout_ns) |timeout| {
            const elapsed = std.time.nanoTimestamp() - connect_start;
            if (elapsed > @as(i128, @intCast(timeout))) {
                stream.close();
                return error.Timeout;
            }
        }

        if (self.options.read_timeout_ns != null or self.options.write_timeout_ns != null) {
            self.applySocketTimeouts(stream) catch return error.Transport;
        }

        self.stream = stream;
    }

    /// Writes the request to the socket.
    fn sendRequest(self: *ConnectionH1, request: *const types.Request, request_start: i128) Error!void {
        try self.checkRequestTimeout(request_start);

        var stream = self.stream.?;
        var writer = StreamWriter.init(&stream);
        var encoder = request_encoder.RequestEncoder(StreamWriter).init(&writer);

        var body_writer = encoder.writeRequest(request) catch |err| return mapEncoderError(err);

        if (request.body) |body_reader| {
            defer body_reader.close();
            var buffer: [8192]u8 = undefined;
            while (true) {
                const read_len = body_reader.read(&buffer) catch |err| return mapBodyReadError(err);
                if (read_len == 0) {
                    break;
                }
                body_writer.writeAll(buffer[0..read_len]) catch |err| return mapEncoderError(err);
            }
        }

        body_writer.flush() catch |err| return mapEncoderError(err);
    }

    /// Reads and parses the response from the socket.
    fn readResponse(self: *ConnectionH1, request_start: i128) Error!ResponseInfo {
        try self.checkRequestTimeout(request_start);

        var stream = self.stream.?;
        const limits = self.buildParserLimits();

        const buffer = self.allocator.alloc(u8, self.options.io_buffer_bytes) catch |err| return mapAllocatorError(err);
        defer self.allocator.free(buffer);

        var reader = StreamReader.init(&stream);
        var parser = response_parser.ResponseParser(StreamReader).init(
            self.allocator,
            &reader,
            buffer,
            limits,
        );

        var response = parser.readResponse() catch |err| return mapParserError(err);
        const body_reader = response.body;
        response.body = null;

        return .{
            .response = response,
            .body = body_reader,
        };
    }

    /// Forwards the response body into the provided pipe.
    fn forwardBody(self: *ConnectionH1, body_reader: types.BodyReader, pipe: *body_pipe.BodyPipe) void {
        _ = self;
        defer body_reader.close();

        var buffer: [8192]u8 = undefined;
        while (true) {
            const read_len = body_reader.read(&buffer) catch |err| {
                pipe.closeWriter(mapBodyReadError(err));
                return;
            };
            if (read_len == 0) {
                pipe.closeWriter(null);
                return;
            }
            pipe.writeAll(buffer[0..read_len]) catch {
                pipe.closeWriter(error.Canceled);
                return;
            };
        }
    }

    /// Applies socket timeouts based on configured options.
    fn applySocketTimeouts(self: *ConnectionH1, stream: std.net.Stream) std.posix.SetSockOptError!void {
        if (self.options.read_timeout_ns) |timeout| {
            try setSocketTimeout(stream, std.posix.SO.RCVTIMEO, timeout);
        }
        if (self.options.write_timeout_ns) |timeout| {
            try setSocketTimeout(stream, std.posix.SO.SNDTIMEO, timeout);
        }
    }

    /// Sets a socket timeout option on the provided stream.
    fn setSocketTimeout(stream: std.net.Stream, opt: u32, timeout_ns: u64) std.posix.SetSockOptError!void {
        const socket: std.posix.socket_t = stream.handle;
        if (builtin.os.tag == .windows) {
            var millis = std.math.cast(u32, timeout_ns / std.time.ns_per_ms) orelse std.math.maxInt(u32);
            if (millis == 0 and timeout_ns > 0) {
                millis = 1;
            }
            try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, opt, std.mem.asBytes(&millis));
            return;
        }

        var tv = std.posix.timeval{
            .tv_sec = @intCast(timeout_ns / std.time.ns_per_s),
            .tv_usec = @intCast((timeout_ns % std.time.ns_per_s) / std.time.ns_per_us),
        };
        try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, opt, std.mem.asBytes(&tv));
    }

    /// Builds parser limits from connection options.
    fn buildParserLimits(self: *ConnectionH1) response_parser.Limits {
        return .{
            .max_status_line_bytes = self.options.max_status_line_bytes,
            .max_header_bytes = self.options.max_header_bytes,
            .max_header_count = self.options.max_header_count,
            .max_header_line_bytes = response_parser.Limits.default().max_header_line_bytes,
            .max_body_bytes = self.options.max_body_bytes,
            .max_chunk_size = self.options.max_chunk_size,
        };
    }

    /// Checks the total request timeout if configured.
    fn checkRequestTimeout(self: *ConnectionH1, request_start: i128) Error!void {
        if (self.options.request_timeout_ns) |timeout| {
            const elapsed = std.time.nanoTimestamp() - request_start;
            if (elapsed > @as(i128, @intCast(timeout))) {
                return error.Timeout;
            }
        }
    }

    /// Closes the active stream if present.
    fn closeStream(self: *ConnectionH1) void {
        if (self.stream) |stream| {
            stream.close();
            self.stream = null;
        }
    }

    /// Maps allocator errors into connection errors.
    fn mapAllocatorError(_: std.mem.Allocator.Error) Error {
        return error.OutOfMemory;
    }

    /// Maps pipe initialization errors into connection errors.
    fn mapPipeInitError(err: body_pipe.BodyPipe.InitError) Error {
        return switch (err) {
            error.InvalidCapacity => error.LimitExceeded,
            error.OutOfMemory => error.OutOfMemory,
        };
    }

    /// Maps request encoder errors into connection errors.
    fn mapEncoderError(err: request_encoder.RequestEncoder(StreamWriter).Error) Error {
        return switch (err) {
            error.InvalidRequestTarget => error.InvalidUri,
            error.BodyTooLarge => error.LimitExceeded,
            error.MissingContentLength,
            error.AmbiguousLength,
            error.DuplicateContentLength,
            error.InvalidMethod,
            error.InvalidVersion,
            error.InvalidHeaderName,
            error.InvalidHeaderValue,
            error.UnsupportedTransferEncoding,
            error.BodyLengthMismatch,
            error.NoSpaceLeft,
            => error.Protocol,
            error.BodyClosed => error.Canceled,
            error.WouldBlock,
            => error.Timeout,
            else => error.Transport,
        };
    }

    /// Maps response parser errors into connection errors.
    fn mapParserError(err: response_parser.ResponseParser(StreamReader).Error) Error {
        return switch (err) {
            error.HeaderTooLarge,
            error.HeaderCountExceeded,
            error.LineTooLong,
            error.BodyTooLarge,
            => error.LimitExceeded,
            error.ConnectionTimedOut,
            error.WouldBlock,
            => error.Timeout,
            error.UnexpectedEof,
            error.ConnectionResetByPeer,
            => error.Transport,
            error.OutOfMemory => error.OutOfMemory,
            else => error.Protocol,
        };
    }

    /// Maps body reader errors into connection errors.
    fn mapBodyReadError(err: anyerror) Error {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.HeaderTooLarge,
            error.HeaderCountExceeded,
            error.LineTooLong,
            error.BodyTooLarge,
            => error.LimitExceeded,
            error.ConnectionTimedOut,
            error.WouldBlock,
            => error.Timeout,
            error.Canceled => error.Canceled,
            else => error.Protocol,
        };
    }

    /// Reader wrapper for raw stream reads.
    const StreamReader = struct {
        /// Stream handle for reading.
        stream: *std.net.Stream,

        /// Error set returned by stream reads.
        pub const Error = std.net.Stream.ReadError;

        /// Initializes a reader for the provided stream.
        pub fn init(stream: *std.net.Stream) StreamReader {
            return .{ .stream = stream };
        }

        /// Reads bytes from the underlying stream.
        pub fn read(self: *StreamReader, dest: []u8) StreamReader.Error!usize {
            return self.stream.read(dest);
        }
    };

    /// Writer wrapper for raw stream writes.
    const StreamWriter = struct {
        /// Stream handle for writing.
        stream: *std.net.Stream,

        /// Error set returned by stream writes.
        pub const Error = std.net.Stream.WriteError;

        /// Initializes a writer for the provided stream.
        pub fn init(stream: *std.net.Stream) StreamWriter {
            return .{ .stream = stream };
        }

        /// Writes all bytes to the underlying stream.
        pub fn writeAll(self: *StreamWriter, bytes: []const u8) StreamWriter.Error!void {
            try self.stream.writeAll(bytes);
        }

        /// Writes a single byte to the underlying stream.
        pub fn writeByte(self: *StreamWriter, byte: u8) StreamWriter.Error!void {
            var buf: [1]u8 = .{byte};
            try self.stream.writeAll(&buf);
        }
    };
};

test "connection executes a request and streams the response body" {
    const test_server = @import("test_server.zig");

    const scenarios = [_]test_server.Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{
                        .response = .{
                            .status = .ok,
                            .reason = "OK",
                            .body = "hello",
                        },
                    },
                },
            },
        },
    };

    var server = try test_server.TestServer.init(&scenarios, test_server.Options.default());
    defer server.deinit();
    try server.start();

    var conn = ConnectionH1.init(
        std.testing.allocator,
        .{
            .scheme = .http,
            .host = "127.0.0.1",
            .port = types.Port.init(server.port()),
        },
        ConnectionH1.Options.default(),
    );
    defer conn.deinit();
    try conn.start();

    const uri = types.Uri.init(.http, "127.0.0.1", types.Port.init(server.port()), "/", null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();
    try request.headers.append("Host", "127.0.0.1");

    var response_future = ConnectionH1.ResponseFuture.init();
    try conn.submit(&request, response_future.completion());

    var response = try response_future.wait();
    defer response.deinit();
    defer if (response.body) |body| body.close();

    try std.testing.expectEqual(types.Status.ok, response.status);

    var buf: [8]u8 = undefined;
    const read_len = try response.body.?.read(&buf);
    try std.testing.expectEqual(@as(usize, 5), read_len);
    try std.testing.expectEqualStrings("hello", buf[0..read_len]);
    const eof = try response.body.?.read(&buf);
    try std.testing.expectEqual(@as(usize, 0), eof);
}
