//! HTTP/1.1 connection thread and request execution.

const std = @import("std");
const builtin = @import("builtin");
const types = @import("../types.zig");
const mailbox = @import("../util/mailbox.zig");
const future = @import("../util/future.zig");
const body_pipe = @import("../util/body_pipe.zig");
const socket_io = @import("../util/socket_io.zig");
const request_encoder = @import("request_encoder.zig");
const response_parser = @import("response_parser.zig");
const tls_client = @import("../tls/client.zig");
const connection_h2 = @import("../http2/connection_h2.zig");
const interop_harness = @import("../testing/interop_harness.zig");

/// Error set returned by connection operations.
pub const Error = error{
    /// Operation exceeded a timeout.
    Timeout,
    /// URI is invalid or unsupported.
    InvalidUri,
    /// Transport failure (DNS/TCP).
    Transport,
    /// Proxy CONNECT request failed.
    ProxyConnectFailed,
    /// ALPN negotiation failed before any HTTP bytes were written.
    NegotiationFailed,
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

/// Connection target information.
pub const Origin = struct {
    /// Scheme used for the TCP connection.
    scheme: types.Scheme,
    /// Hostname or IP literal to connect to.
    host: []const u8,
    /// Port to connect to.
    port: types.Port,
    /// Request target mode used for this connection.
    target_mode: request_encoder.RequestTargetMode,
    /// Tunnel target to CONNECT through a proxy, if any.
    tunnel: ?TunnelTarget,
    /// Proxy-Authorization header value for CONNECT, if any.
    proxy_authorization: ?[]const u8,
};

/// Target host and port for CONNECT tunnels.
pub const TunnelTarget = struct {
    /// Hostname or IP literal for the tunnel target.
    host: []const u8,
    /// Port for the tunnel target.
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
    /// Optional TLS configuration for HTTPS requests.
    tls_config: ?types.TlsConfig,
    /// Expected application protocol for this connection.
    expected_protocol: types.NegotiatedProtocol,
    /// Maximum active streams permitted on the delegated HTTP/2 runtime.
    h2_max_active_streams: usize,
    /// Maximum buffered bytes retained for one HTTP/2 stream.
    h2_max_stream_buffer_bytes: usize,
    /// Maximum buffered bytes retained across the delegated HTTP/2 runtime.
    h2_max_connection_buffer_bytes: usize,

    /// Returns default connection options.
    pub fn default() Options {
        const limits = response_parser.Limits.default();
        const h2_defaults = connection_h2.Options.default();
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
            .tls_config = null,
            .expected_protocol = .http_1_1,
            .h2_max_active_streams = h2_defaults.max_active_streams.toInt(),
            .h2_max_stream_buffer_bytes = h2_defaults.max_stream_buffer_bytes.toInt(),
            .h2_max_connection_buffer_bytes = h2_defaults.max_connection_buffer_bytes.toInt(),
        };
    }
};

/// Error set returned by `start`.
pub const StartError = error{AlreadyStarted} || std.Thread.SpawnError;

/// Error set returned by `submit`.
pub const SubmitError = Mailbox.SendError || error{NotStarted};

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

/// Parsed response and optional body reader for forwarding.
const ResponseInfo = struct {
    /// Parsed response headers and metadata.
    response: types.Response,
    /// Body reader sourced from the socket.
    body: ?types.BodyReader,
};

/// Body reader wrapper that keeps the parser buffer alive after `readResponse`.
const OwnedResponseBody = struct {
    /// Allocator used to release the wrapper state.
    allocator: std.mem.Allocator,
    /// Parser buffer retained for the inner body reader.
    buffer: []u8,
    /// Inner body reader returned by the response parser.
    inner: types.BodyReader,

    /// Reads bytes from the wrapped body reader.
    fn read(ctx: ?*anyopaque, dest: []u8) anyerror!usize {
        const self: *OwnedResponseBody = @ptrCast(@alignCast(ctx.?));
        return self.inner.read(dest);
    }

    /// Closes the wrapped reader and releases the retained parser buffer.
    fn close(ctx: ?*anyopaque) void {
        const self: *OwnedResponseBody = @ptrCast(@alignCast(ctx.?));
        self.inner.close();
        self.allocator.free(self.buffer);
        self.allocator.destroy(self);
    }
};

/// In-memory response body state for secure harness responses.
const OwnedBody = struct {
    /// Allocator used to destroy the body state.
    allocator: std.mem.Allocator,
    /// Owned response bytes.
    bytes: []u8,
    /// Current read offset.
    offset: usize,

    /// Reads one chunk from the owned response bytes.
    fn read(ctx: ?*anyopaque, dest: []u8) anyerror!usize {
        const self: *OwnedBody = @ptrCast(@alignCast(ctx.?));
        if (self.offset >= self.bytes.len) {
            return 0;
        }

        const remaining = self.bytes.len - self.offset;
        const to_copy = @min(dest.len, remaining);
        std.mem.copyForwards(u8, dest[0..to_copy], self.bytes[self.offset .. self.offset + to_copy]);
        self.offset += to_copy;
        return to_copy;
    }

    /// Releases the owned body bytes.
    fn close(ctx: ?*anyopaque) void {
        const self: *OwnedBody = @ptrCast(@alignCast(ctx.?));
        self.allocator.free(self.bytes);
        self.allocator.destroy(self);
    }
};

/// Error set returned while parsing CONNECT responses.
const ConnectResponseError = StreamReader.Error || std.mem.Allocator.Error || error{
    UnexpectedEof,
    InvalidLineEnding,
    LineTooLong,
    InvalidStatusLine,
    InvalidStatusCode,
    InvalidVersion,
    HeaderTooLarge,
    HeaderCountExceeded,
};

/// Error set returned while buffering a request body for the local secure harness.
const ReadBodyError = error{
    BodyReadFailed,
    BodyTooLarge,
    OutOfMemory,
};

/// Application protocols accepted by the HTTP/1.1 transport path.
const http_1_1_protocols = [_]types.NegotiatedProtocol{.http_1_1};

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
        return socket_io.read(self.stream.*, dest);
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

/// Reader wrapper that abstracts over raw and TLS-backed streams.
const TransportReader = struct {
    /// Connection owning the active transport.
    connection: *ConnectionH1,

    /// Error set returned by transport reads.
    pub const Error = std.net.Stream.ReadError || std.Io.Reader.ShortError;

    /// Initializes a reader for the provided connection.
    pub fn init(connection: *ConnectionH1) TransportReader {
        return .{ .connection = connection };
    }

    /// Reads bytes from the active transport.
    pub fn read(self: *TransportReader, dest: []u8) TransportReader.Error!usize {
        if (self.connection.tls_stream) |tls_stream| {
            return tls_stream.reader().readSliceShort(dest);
        }
        return socket_io.read(self.connection.stream.?, dest);
    }
};

/// Writer wrapper that abstracts over raw and TLS-backed streams.
const TransportWriter = struct {
    /// Connection owning the active transport.
    connection: *ConnectionH1,

    /// Error set returned by transport writes.
    pub const Error = std.net.Stream.WriteError || std.Io.Writer.Error;

    /// Initializes a writer for the provided connection.
    pub fn init(connection: *ConnectionH1) TransportWriter {
        return .{ .connection = connection };
    }

    /// Writes all bytes to the active transport.
    pub fn writeAll(self: *TransportWriter, bytes: []const u8) TransportWriter.Error!void {
        if (self.connection.tls_stream) |tls_stream| {
            try tls_stream.writer().writeAll(bytes);
            return;
        }
        try self.connection.stream.?.writeAll(bytes);
    }

    /// Writes a single byte to the active transport.
    pub fn writeByte(self: *TransportWriter, byte: u8) TransportWriter.Error!void {
        if (self.connection.tls_stream) |tls_stream| {
            try tls_stream.writer().writeByte(byte);
            return;
        }

        var buf: [1]u8 = .{byte};
        try self.connection.stream.?.writeAll(&buf);
    }
};

/// HTTP/1.1 connection implementation backed by a dedicated thread.
pub const ConnectionH1 = struct {
    /// Allocator used for per-request allocations.
    allocator: std.mem.Allocator,
    /// Connection target and request target mode.
    origin: Origin,
    /// Runtime configuration options.
    options: Options,
    /// Mailbox used for command dispatch.
    mailbox: Mailbox,
    /// Background thread handling requests.
    thread: ?std.Thread,
    /// Active TCP stream or null when disconnected.
    stream: ?std.net.Stream,
    /// Active TLS stream layered over the TCP stream.
    tls_stream: ?*tls_client.ClientStream,
    /// Reader state retained for parser-owned body readers.
    transport_reader: ?TransportReader,
    /// Indicates whether a CONNECT tunnel is established.
    tunnel_established: bool,
    /// Negotiated application protocol for the current transport.
    negotiated_protocol: types.NegotiatedProtocol,
    /// Local secure harness persona, when the connection is simulated in memory.
    secure_harness_profile: ?interop_harness.AlpnPeerProfile,
    /// Dedicated HTTP/2 runtime for negotiated `h2` loopback traffic.
    http2_runtime: ?*connection_h2.ConnectionH2,

    /// Initializes a connection without starting the background thread.
    pub fn init(allocator: std.mem.Allocator, origin: Origin, options: Options) ConnectionH1 {
        return .{
            .allocator = allocator,
            .origin = origin,
            .options = options,
            .mailbox = Mailbox.init(allocator),
            .thread = null,
            .stream = null,
            .tls_stream = null,
            .transport_reader = null,
            .tunnel_established = false,
            .negotiated_protocol = .http_1_1,
            .secure_harness_profile = null,
            .http2_runtime = null,
        };
    }

    /// Returns the negotiated application protocol currently bound to the connection.
    pub fn negotiatedProtocol(self: *const ConnectionH1) types.NegotiatedProtocol {
        return self.negotiated_protocol;
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
                if (self.negotiated_protocol == .h2 and self.secure_harness_profile != null) {
                    _ = completion.finish(err);
                    switch (err) {
                        error.Transport,
                        error.NegotiationFailed,
                        error.Canceled,
                        => self.closeStream(),
                        else => {},
                    }
                    return;
                }
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
            if (response.body != null) {
                if (!completion.finish(response)) {
                    if (response.body) |body_reader| {
                        body_reader.close();
                        response.body = null;
                    }
                    response.deinit();
                    self.closeStream();
                    return;
                }

                if (!keep_alive) {
                    self.closeStream();
                }
                return;
            }

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
        if (response.version == .http_2) {
            return true;
        }
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
        if (self.secure_harness_profile != null) {
            return self.executeSecureHarnessRequest(request, request_start);
        }
        try self.sendRequest(request, request_start);
        return self.readResponse(request_start);
    }

    /// Validates the request against the connection origin.
    fn validateRequest(self: *ConnectionH1, request: *const types.Request) Error!void {
        if (self.origin.tunnel) |tunnel| {
            if (request.uri.scheme != .https) {
                return error.InvalidUri;
            }
            if (request.uri.host.len == 0) {
                return error.InvalidUri;
            }
            if (!std.ascii.eqlIgnoreCase(request.uri.host, tunnel.host)) {
                return error.InvalidUri;
            }
            if (request.uri.effectivePort().toInt() != tunnel.port.toInt()) {
                return error.InvalidUri;
            }
            return;
        }

        switch (self.origin.target_mode) {
            .origin_form => {
                if (request.uri.scheme != self.origin.scheme) {
                    return error.InvalidUri;
                }
                if (request.uri.scheme == .https and self.options.tls_config == null) {
                    return error.InvalidUri;
                }
                if (request.uri.scheme != .http and request.uri.scheme != .https) {
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
            },
            .absolute_form => {
                if (request.uri.scheme != .http) {
                    return error.InvalidUri;
                }
                if (request.uri.host.len == 0) {
                    return error.InvalidUri;
                }
            },
        }
    }

    /// Ensures a TCP connection is established.
    fn ensureConnected(self: *ConnectionH1, request_start: i128) Error!void {
        if (self.secure_harness_profile != null) {
            return;
        }

        if (self.secureHarnessProfileForOrigin()) |profile| {
            try self.establishSecureHarness(profile);
            return;
        }

        if (self.tls_stream != null) {
            return;
        }

        if (self.stream != null) {
            if (self.origin.tunnel != null and !self.tunnel_established) {
                self.establishTunnel(request_start) catch |err| {
                    self.closeStream();
                    return err;
                };
            }
            if (self.options.tls_config != null) {
                self.establishTls() catch |err| {
                    self.closeStream();
                    return err;
                };
            }
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
        if (self.origin.tunnel != null) {
            self.establishTunnel(request_start) catch |err| {
                self.closeStream();
                return err;
            };
        }
        if (self.options.tls_config != null) {
            self.establishTls() catch |err| {
                self.closeStream();
                return err;
            };
        }
    }

    /// Establishes a CONNECT tunnel for HTTPS proxy requests.
    fn establishTunnel(self: *ConnectionH1, request_start: i128) Error!void {
        if (self.tunnel_established) {
            return;
        }

        const target = self.origin.tunnel orelse return;
        try self.checkRequestTimeout(request_start);
        self.writeConnectRequest(target) catch |err| return mapConnectWriteError(err);
        try self.checkRequestTimeout(request_start);

        const status_code = self.readConnectResponse() catch |err| return mapConnectReadError(err);
        if (status_code < 200 or status_code >= 300) {
            return error.ProxyConnectFailed;
        }

        self.tunnel_established = true;
    }

    /// Writes the CONNECT request to the proxy stream.
    fn writeConnectRequest(self: *ConnectionH1, target: TunnelTarget) StreamWriter.Error!void {
        var stream = self.stream.?;
        var writer = StreamWriter.init(&stream);

        try writer.writeAll("CONNECT ");
        try writer.writeAll(target.host);
        try writer.writeAll(":");

        var port_buffer: [8]u8 = undefined;
        const port_bytes = std.fmt.bufPrint(&port_buffer, "{d}", .{target.port.toInt()}) catch unreachable;
        try writer.writeAll(port_bytes);
        try writer.writeAll(" HTTP/1.1\r\n");

        try writer.writeAll("Host: ");
        try writer.writeAll(target.host);
        try writer.writeAll(":");
        try writer.writeAll(port_bytes);
        try writer.writeAll("\r\n");

        if (self.origin.proxy_authorization) |value| {
            try writer.writeAll("Proxy-Authorization: ");
            try writer.writeAll(value);
            try writer.writeAll("\r\n");
        }

        try writer.writeAll("\r\n");
    }

    /// Parses the CONNECT response status line and headers.
    fn readConnectResponse(self: *ConnectionH1) ConnectResponseError!u16 {
        var line_buffer = std.ArrayListUnmanaged(u8){};
        defer line_buffer.deinit(self.allocator);

        var stream = self.stream.?;
        const limits = self.buildParserLimits();
        const max_header_line = response_parser.Limits.default().max_header_line_bytes;

        const status_line = try readConnectLine(self.allocator, &stream, &line_buffer, limits.max_status_line_bytes);
        const status_code = try parseConnectStatusLine(status_line);

        var header_bytes: usize = 0;
        var header_count: usize = 0;
        while (true) {
            const header_line = try readConnectLine(self.allocator, &stream, &line_buffer, max_header_line);
            if (header_line.len == 0) {
                break;
            }
            header_bytes += header_line.len + 2;
            if (header_bytes > limits.max_header_bytes) {
                return error.HeaderTooLarge;
            }
            header_count += 1;
            if (header_count > limits.max_header_count) {
                return error.HeaderCountExceeded;
            }
        }

        return status_code;
    }

    /// Reads a CRLF-terminated line from the stream.
    fn readConnectLine(
        allocator: std.mem.Allocator,
        stream: *std.net.Stream,
        buffer: *std.ArrayListUnmanaged(u8),
        max_len: usize,
    ) ConnectResponseError![]const u8 {
        buffer.clearRetainingCapacity();
        while (true) {
            var byte_buf: [1]u8 = undefined;
            const read_len = try socket_io.read(stream.*, &byte_buf);
            if (read_len == 0) {
                return error.UnexpectedEof;
            }
            const byte = byte_buf[0];
            if (byte == '\r') {
                const lf_len = try socket_io.read(stream.*, &byte_buf);
                if (lf_len == 0) {
                    return error.UnexpectedEof;
                }
                if (byte_buf[0] != '\n') {
                    return error.InvalidLineEnding;
                }
                return buffer.items;
            }
            if (byte == '\n') {
                return error.InvalidLineEnding;
            }
            if (buffer.items.len >= max_len) {
                return error.LineTooLong;
            }
            try buffer.append(allocator, byte);
        }
    }

    /// Parses the status line for a CONNECT response.
    fn parseConnectStatusLine(line: []const u8) ConnectResponseError!u16 {
        const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse return error.InvalidStatusLine;
        const version_bytes = line[0..first_space];
        if (!std.mem.eql(u8, version_bytes, "HTTP/1.1") and !std.mem.eql(u8, version_bytes, "HTTP/1.0")) {
            return error.InvalidVersion;
        }

        const rest = line[first_space + 1 ..];
        if (rest.len < 3) {
            return error.InvalidStatusCode;
        }
        const code_bytes = rest[0..3];
        var value: u16 = 0;
        for (code_bytes) |byte| {
            if (byte < '0' or byte > '9') {
                return error.InvalidStatusCode;
            }
            value = value * 10 + @as(u16, byte - '0');
        }
        return value;
    }

    /// Maps CONNECT read errors into connection errors.
    fn mapConnectReadError(err: ConnectResponseError) Error {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.HeaderTooLarge,
            error.HeaderCountExceeded,
            error.LineTooLong,
            => error.LimitExceeded,
            error.ConnectionTimedOut,
            error.WouldBlock,
            => error.Timeout,
            error.UnexpectedEof,
            error.ConnectionResetByPeer,
            => error.Transport,
            else => error.Protocol,
        };
    }

    /// Maps CONNECT write errors into connection errors.
    fn mapConnectWriteError(err: StreamWriter.Error) Error {
        return switch (err) {
            else => error.Transport,
        };
    }

    /// Attaches a TLS session to the connected stream when HTTPS is enabled.
    fn establishTls(self: *ConnectionH1) Error!void {
        if (self.tls_stream != null) {
            return;
        }

        const tls_config = self.options.tls_config orelse return;
        if (self.options.expected_protocol != .http_1_1) {
            return error.Protocol;
        }

        const stream = self.stream orelse return error.Transport;
        self.stream = null;

        const tls_stream = tls_client.establish(
            self.allocator,
            stream,
            self.buildTlsUri(),
            tls_config,
            &http_1_1_protocols,
        ) catch |err| return mapTlsError(err);

        self.tls_stream = tls_stream;
        self.negotiated_protocol = tls_stream.negotiatedProtocol();
        if (self.negotiated_protocol != self.options.expected_protocol) {
            return error.NegotiationFailed;
        }
    }

    /// Builds the URI view used for HTTPS handshake planning.
    fn buildTlsUri(self: *const ConnectionH1) types.Uri {
        if (self.origin.tunnel) |tunnel| {
            return types.Uri.init(.https, tunnel.host, tunnel.port, "/", null, null);
        }
        return types.Uri.init(.https, self.origin.host, self.origin.port, "/", null, null);
    }

    /// Maps TLS handshake failures into connection errors.
    fn mapTlsError(err: tls_client.Error) Error {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.MissingServerName => error.InvalidUri,
            error.NoSharedProtocol => error.NegotiationFailed,
            error.InvalidRootStore,
            error.RootStoreUnavailable,
            error.HostnameMismatch,
            error.PeerVerificationFailed,
            error.TlsHandshakeFailed,
            error.TransportFailure,
            => error.Transport,
            error.MissingExplicitRoots,
            error.IncompleteIdentity,
            error.MissingAlpnProtocols,
            => error.Protocol,
        };
    }

    /// Returns the configured secure harness persona for the origin, if any.
    fn secureHarnessProfileForOrigin(self: *const ConnectionH1) ?interop_harness.AlpnPeerProfile {
        if (self.options.tls_config == null) {
            return null;
        }
        const uri = self.buildTlsUri();
        return interop_harness.alpnPeerProfileForEndpoint(uri.host, uri.effectivePort());
    }

    /// Establishes an in-memory secure harness connection for the provided ALPN persona.
    fn establishSecureHarness(self: *ConnectionH1, profile: interop_harness.AlpnPeerProfile) Error!void {
        self.secure_harness_profile = profile;
        self.negotiated_protocol = try self.negotiateSecureHarnessProtocol(profile);
        if (self.negotiated_protocol != self.options.expected_protocol) {
            return error.NegotiationFailed;
        }

        if (self.negotiated_protocol == .h2 and self.http2_runtime == null) {
            const runtime = self.allocator.create(connection_h2.ConnectionH2) catch {
                return error.OutOfMemory;
            };
            errdefer self.allocator.destroy(runtime);

            runtime.* = connection_h2.ConnectionH2.init(
                self.allocator,
                profile.host,
                profile.port,
                buildH2RuntimeOptions(self.options),
            );
            runtime.start() catch {
                runtime.deinit();
                return error.OutOfMemory;
            };
            self.http2_runtime = runtime;
        }
    }

    /// Resolves the negotiated protocol for the local secure harness persona.
    fn negotiateSecureHarnessProtocol(
        self: *ConnectionH1,
        profile: interop_harness.AlpnPeerProfile,
    ) Error!types.NegotiatedProtocol {
        const tls_config = self.options.tls_config orelse return error.Protocol;

        if (profile.selected_protocol_token) |token| {
            const protocol = parseProtocolToken(token) catch return error.NegotiationFailed;
            if (!tls_config.supportsProtocol(protocol)) {
                return error.NegotiationFailed;
            }
            return protocol;
        }

        if (profile.omits_alpn) {
            if (!tls_config.supportsProtocol(.http_1_1)) {
                return error.NegotiationFailed;
            }
            return .http_1_1;
        }

        const negotiation = tls_client.negotiateProtocol(tls_config, profile.advertised_protocols) catch {
            return error.NegotiationFailed;
        };
        return negotiation.protocol;
    }

    /// Parses a negotiated ALPN token into the supported protocol enum.
    fn parseProtocolToken(token: []const u8) error{UnsupportedToken}!types.NegotiatedProtocol {
        if (std.mem.eql(u8, token, "h2")) {
            return .h2;
        }
        if (std.mem.eql(u8, token, "http/1.1")) {
            return .http_1_1;
        }
        return error.UnsupportedToken;
    }

    /// Executes one request against the local secure harness instead of a socket transport.
    fn executeSecureHarnessRequest(
        self: *ConnectionH1,
        request: *const types.Request,
        request_start: i128,
    ) Error!ResponseInfo {
        try self.checkRequestTimeout(request_start);

        return switch (self.negotiated_protocol) {
            .h2 => {
                var runtime_future = connection_h2.ResponseFuture.init();
                self.http2_runtime.?.submit(request, runtime_future.completion()) catch |err| return switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    error.Closed,
                    error.NotStarted,
                    => error.Transport,
                };
                return .{
                    .response = runtime_future.wait() catch |err| return mapHttp2RuntimeError(err),
                    .body = null,
                };
            },
            .http_1_1 => self.executeSecureHarnessHttp1Request(request),
            else => error.Protocol,
        };
    }

    /// Executes one `http/1.1` fallback request against the local secure harness.
    fn executeSecureHarnessHttp1Request(self: *ConnectionH1, request: *const types.Request) Error!ResponseInfo {
        const request_body = if (request.body) |body_reader|
            readBodyAlloc(self.allocator, body_reader, 256 * 1024) catch |err| return switch (err) {
                error.BodyReadFailed => error.Protocol,
                error.BodyTooLarge => error.LimitExceeded,
                error.OutOfMemory => error.OutOfMemory,
            }
        else
            self.allocator.alloc(u8, 0) catch return error.OutOfMemory;
        defer self.allocator.free(request_body);

        var semantic = interop_harness.buildSemanticResponse(self.allocator, .{
            .method = request.method,
            .path = request.uri.path,
            .query = request.uri.query,
            .negotiated_protocol = .http_1_1,
            .body = request_body,
            .cookie_header = request.headers.get("cookie"),
        }) catch return error.OutOfMemory;
        defer semantic.deinit();

        var response = types.Response.init(self.allocator, .http_1_1, semantic.status);
        errdefer response.deinit();

        var iterator = semantic.headers.iterator();
        while (iterator.next()) |header| {
            response.headers.append(header.name, header.value) catch return error.OutOfMemory;
        }

        if (semantic.body.len > 0) {
            const owned_body = self.allocator.dupe(u8, semantic.body) catch return error.OutOfMemory;
            const state = self.allocator.create(OwnedBody) catch {
                self.allocator.free(owned_body);
                return error.OutOfMemory;
            };
            state.* = .{
                .allocator = self.allocator,
                .bytes = owned_body,
                .offset = 0,
            };
            response.body = .{
                .ctx = state,
                .read_fn = OwnedBody.read,
                .close_fn = OwnedBody.close,
            };
        }

        const body = response.body;
        response.body = null;

        return .{
            .response = response,
            .body = body,
        };
    }

    /// Maps dedicated HTTP/2 runtime failures into connection errors.
    fn mapHttp2RuntimeError(err: connection_h2.ResponseFuture.WaitError) Error {
        return switch (err) {
            error.Timeout => error.Timeout,
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidUri => error.InvalidUri,
            error.Transport => error.Transport,
            error.ProxyConnectFailed => error.ProxyConnectFailed,
            error.NegotiationFailed => error.NegotiationFailed,
            error.Protocol => error.Protocol,
            error.LimitExceeded => error.LimitExceeded,
            error.Canceled => error.Canceled,
        };
    }

    /// Writes the request to the socket.
    fn sendRequest(self: *ConnectionH1, request: *const types.Request, request_start: i128) Error!void {
        try self.checkRequestTimeout(request_start);

        var writer = TransportWriter.init(self);
        var encoder = request_encoder.RequestEncoder(TransportWriter).init(&writer);

        var body_writer = encoder.writeRequest(request, self.origin.target_mode) catch |err| return mapEncoderError(err);

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
        const limits = self.buildParserLimits();

        const buffer = self.allocator.alloc(u8, self.options.io_buffer_bytes) catch |err| return mapAllocatorError(err);
        errdefer self.allocator.free(buffer);

        self.transport_reader = TransportReader.init(self);
        var parser = response_parser.ResponseParser(TransportReader).init(
            self.allocator,
            &self.transport_reader.?,
            buffer,
            limits,
        );

        var response = parser.readResponse() catch |err| return mapParserError(err);
        const body_reader = if (response.body) |reader|
            self.wrapResponseBody(reader, buffer) catch |err| {
                reader.close();
                self.allocator.free(buffer);
                return err;
            }
        else
            null;
        response.body = null;
        if (body_reader == null) {
            self.allocator.free(buffer);
        }

        return .{
            .response = response,
            .body = body_reader,
        };
    }

    /// Forwards the response body into the provided pipe.
    fn forwardBody(self: *ConnectionH1, body_reader: types.BodyReader, pipe: *body_pipe.BodyPipe) void {
        defer body_reader.close();

        var buffer: [8192]u8 = undefined;
        while (true) {
            const read_len = body_reader.read(&buffer) catch |err| {
                pipe.closeWriter(mapBodyReadError(err));
                self.closeStream();
                return;
            };
            if (read_len == 0) {
                pipe.closeWriter(null);
                return;
            }
            pipe.writeAll(buffer[0..read_len]) catch {
                pipe.closeWriter(error.Canceled);
                self.closeStream();
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
            .sec = @intCast(timeout_ns / std.time.ns_per_s),
            .usec = @intCast((timeout_ns % std.time.ns_per_s) / std.time.ns_per_us),
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
        if (self.tls_stream) |tls_stream| {
            tls_stream.deinit();
            self.tls_stream = null;
        } else if (self.stream) |stream| {
            stream.close();
            self.stream = null;
        }
        if (self.http2_runtime) |runtime| {
            runtime.deinit();
            self.allocator.destroy(runtime);
            self.http2_runtime = null;
        }
        self.secure_harness_profile = null;
        self.tunnel_established = false;
        self.negotiated_protocol = .http_1_1;
    }

    /// Builds runtime options for the delegated HTTP/2 connection thread.
    fn buildH2RuntimeOptions(options: Options) connection_h2.Options {
        return .{
            .max_active_streams = connection_h2.ActiveStreamCount.init(options.h2_max_active_streams),
            .max_stream_buffer_bytes = types.ByteSize.fromBytes(options.h2_max_stream_buffer_bytes),
            .max_connection_buffer_bytes = types.ByteSize.fromBytes(options.h2_max_connection_buffer_bytes),
        };
    }

    /// Reads a full request body into memory for the local secure harness flow.
    fn readBodyAlloc(
        allocator: std.mem.Allocator,
        body_reader: types.BodyReader,
        max_bytes: usize,
    ) ReadBodyError![]u8 {
        var collected = std.ArrayListUnmanaged(u8){};
        errdefer collected.deinit(allocator);

        var buffer: [4096]u8 = undefined;
        while (true) {
            const read_len = body_reader.read(&buffer) catch return error.BodyReadFailed;
            if (read_len == 0) {
                break;
            }
            if (collected.items.len + read_len > max_bytes) {
                return error.BodyTooLarge;
            }
            collected.appendSlice(allocator, buffer[0..read_len]) catch return error.OutOfMemory;
        }

        return collected.toOwnedSlice(allocator) catch return error.OutOfMemory;
    }

    /// Maps allocator errors into connection errors.
    fn mapAllocatorError(_: std.mem.Allocator.Error) Error {
        return error.OutOfMemory;
    }

    /// Wraps a parser-owned body reader so its backing buffer survives until close.
    fn wrapResponseBody(self: *ConnectionH1, body_reader: types.BodyReader, buffer: []u8) Error!types.BodyReader {
        const state = self.allocator.create(OwnedResponseBody) catch return error.OutOfMemory;
        state.* = .{
            .allocator = self.allocator,
            .buffer = buffer,
            .inner = body_reader,
        };
        return .{
            .ctx = state,
            .read_fn = OwnedResponseBody.read,
            .close_fn = OwnedResponseBody.close,
        };
    }

    /// Maps pipe initialization errors into connection errors.
    fn mapPipeInitError(err: body_pipe.InitError) Error {
        return switch (err) {
            error.InvalidCapacity => error.LimitExceeded,
            error.OutOfMemory => error.OutOfMemory,
        };
    }

    /// Maps request encoder errors into connection errors.
    fn mapEncoderError(err: request_encoder.RequestEncoder(TransportWriter).Error) Error {
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
    fn mapParserError(err: response_parser.ResponseParser(TransportReader).Error) Error {
        return switch (err) {
            error.HeaderTooLarge,
            error.HeaderCountExceeded,
            error.LineTooLong,
            error.BodyTooLarge,
            => error.LimitExceeded,
            error.ConnectionTimedOut,
            error.WouldBlock,
            => error.Timeout,
            error.InputOutput,
            error.SystemResources,
            error.IsDir,
            error.OperationAborted,
            error.BrokenPipe,
            error.SocketNotConnected,
            error.SocketNotBound,
            error.MessageTooBig,
            error.NetworkSubsystemFailed,
            error.Unexpected,
            error.ReadFailed,
            => error.Transport,
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
            error.InputOutput,
            error.SystemResources,
            error.IsDir,
            error.OperationAborted,
            error.BrokenPipe,
            error.SocketNotConnected,
            error.SocketNotBound,
            error.MessageTooBig,
            error.NetworkSubsystemFailed,
            error.Unexpected,
            => error.Transport,
            else => error.Transport,
        };
    }
}; // End of ConnectionH1 struct

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
            .target_mode = .origin_form,
            .tunnel = null,
            .proxy_authorization = null,
        },
        Options.default(),
    );
    defer conn.deinit();
    try conn.start();

    const uri = types.Uri.init(.http, "127.0.0.1", types.Port.init(server.port()), "/", null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();
    try request.headers.append("Host", "127.0.0.1");

    var response_future = ResponseFuture.init();
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
