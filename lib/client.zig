//! HTTP client implementation.

const std = @import("std");
const types = @import("types.zig");
const mailbox = @import("util/mailbox.zig");
const future = @import("util/future.zig");
const connection_h1 = @import("http1/connection_h1.zig");

/// Mailbox type for internal command queues.
pub const Mailbox = mailbox.Mailbox;
/// Request future type for completion signaling.
pub const RequestFuture = future.RequestFuture;

/// HTTP client entry point.
pub const Client = struct {
    /// Allocator used for client-owned allocations.
    allocator: std.mem.Allocator,
    /// Configuration options for the client.
    options: Options,

    /// Typed client errors.
    pub const Error = error{
        /// Operation exceeded a timeout.
        Timeout,
        /// URI is invalid or unsupported.
        InvalidUri,
        /// Transport failure (DNS/TCP/TLS).
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

    /// Cancellation token shared across operations.
    pub const CancellationToken = struct {
        /// Cancellation flag.
        flag: std.atomic.Value(bool),

        /// Initializes a token in the not-canceled state.
        pub fn init() CancellationToken {
            return .{ .flag = std.atomic.Value(bool).init(false) };
        }

        /// Marks the token as canceled.
        pub fn cancel(self: *CancellationToken) void {
            self.flag.store(true, .seq_cst);
        }

        /// Returns true if the token has been canceled.
        pub fn isCanceled(self: *const CancellationToken) bool {
            return self.flag.load(.seq_cst);
        }
    };

    /// Duration expressed in nanoseconds.
    pub const Duration = struct {
        /// Duration value in nanoseconds.
        nanoseconds: u64,

        /// Creates a duration from nanoseconds.
        pub fn fromNanos(nanoseconds: u64) Duration {
            return .{ .nanoseconds = nanoseconds };
        }

        /// Creates a duration from milliseconds.
        pub fn fromMillis(milliseconds: u64) Duration {
            return .{ .nanoseconds = milliseconds * std.time.ns_per_ms };
        }

        /// Creates a duration from seconds.
        pub fn fromSeconds(seconds: u64) Duration {
            return .{ .nanoseconds = seconds * std.time.ns_per_s };
        }

        /// Returns the duration in nanoseconds.
        pub fn toNanos(self: Duration) u64 {
            return self.nanoseconds;
        }
    };

    /// Size in bytes with an explicit unit.
    pub const ByteSize = struct {
        /// Size in bytes.
        bytes: usize,

        /// Creates a size from bytes.
        pub fn fromBytes(bytes: usize) ByteSize {
            return .{ .bytes = bytes };
        }

        /// Creates a size from kibibytes (1024 bytes).
        pub fn fromKib(kibibytes: usize) ByteSize {
            return .{ .bytes = kibibytes * 1024 };
        }

        /// Returns the size in bytes.
        pub fn toInt(self: ByteSize) usize {
            return self.bytes;
        }
    };

    /// Header field count with an explicit unit.
    pub const HeaderCount = struct {
        /// Number of header fields.
        count: usize,

        /// Creates a header count from the provided value.
        pub fn init(count: usize) HeaderCount {
            return .{ .count = count };
        }

        /// Returns the header count.
        pub fn toInt(self: HeaderCount) usize {
            return self.count;
        }
    };

    /// Line length expressed in bytes.
    pub const LineLength = struct {
        /// Line length in bytes.
        bytes: usize,

        /// Creates a line length from bytes.
        pub fn fromBytes(bytes: usize) LineLength {
            return .{ .bytes = bytes };
        }

        /// Returns the line length in bytes.
        pub fn toInt(self: LineLength) usize {
            return self.bytes;
        }
    };

    /// Limits applied to protocol parsing and buffering.
    pub const Limits = struct {
        /// Maximum total header bytes allowed.
        max_header_bytes: ByteSize,
        /// Maximum number of header fields allowed.
        max_header_count: HeaderCount,
        /// Maximum length of a response status line.
        max_response_line_bytes: LineLength,

        /// Returns the default limits.
        pub fn default() Limits {
            return .{
                .max_header_bytes = ByteSize.fromKib(32),
                .max_header_count = HeaderCount.init(100),
                .max_response_line_bytes = LineLength.fromBytes(8 * 1024),
            };
        }
    };

    /// Timeout configuration for client operations.
    pub const Timeouts = struct {
        /// Maximum time to establish a connection.
        connect: ?Duration,
        /// Maximum time to write request bytes.
        write: ?Duration,
        /// Maximum time to read response bytes.
        read: ?Duration,
        /// Maximum total time for a request, including redirects.
        request: ?Duration,

        /// Returns the default timeouts.
        pub fn default() Timeouts {
            return .{
                .connect = Duration.fromSeconds(10),
                .write = Duration.fromSeconds(30),
                .read = Duration.fromSeconds(30),
                .request = Duration.fromSeconds(120),
            };
        }
    };

    /// Redirect handling mode.
    pub const RedirectMode = enum {
        /// Do not follow redirects.
        disabled,
        /// Follow redirects according to policy.
        follow,
    };

    /// Redirect handling configuration.
    pub const RedirectPolicy = struct {
        /// Redirect handling mode.
        mode: RedirectMode,
        /// Maximum number of redirects to follow when enabled.
        max_hops: u8,

        /// Returns the default redirect policy.
        pub fn default() RedirectPolicy {
            return .{
                .mode = .follow,
                .max_hops = 10,
            };
        }
    };

    /// Proxy selection mode.
    pub const ProxyMode = enum {
        /// Connect directly without a proxy.
        direct,
        /// Use system proxy discovery.
        system,
        /// Use the manual proxy endpoint.
        manual,
    };

    /// Manual proxy endpoint configuration.
    pub const Proxy = struct {
        /// Proxy scheme.
        scheme: types.Scheme,
        /// Proxy hostname or IP literal.
        host: []const u8,
        /// Proxy port.
        port: types.Port,
    };

    /// Proxy configuration.
    pub const ProxyConfig = struct {
        /// Proxy selection mode.
        mode: ProxyMode,
        /// Manual proxy endpoint when mode is manual.
        manual: ?Proxy,

        /// Returns default proxy configuration.
        pub fn default() ProxyConfig {
            return .{
                .mode = .system,
                .manual = null,
            };
        }
    };

    /// Placeholder type for the cookie jar implementation.
    pub const CookieJar = struct {};

    /// TLS certificate verification mode.
    pub const TlsVerifyMode = enum {
        /// Verify certificates and hostnames.
        verify,
        /// Do not verify certificates.
        insecure,
    };

    /// TLS configuration.
    pub const TlsConfig = struct {
        /// Certificate verification mode.
        verify: TlsVerifyMode,

        /// Returns the default TLS configuration.
        pub fn default() TlsConfig {
            return .{
                .verify = .verify,
            };
        }
    };

    /// Client configuration options.
    pub const Options = struct {
        /// Timeout configuration.
        timeouts: Timeouts,
        /// Limit configuration.
        limits: Limits,
        /// Redirect policy configuration.
        redirect_policy: RedirectPolicy,
        /// Proxy configuration.
        proxy: ProxyConfig,
        /// Cookie jar pointer, or null to disable cookies.
        cookie_jar: ?*CookieJar,
        /// TLS configuration.
        tls: TlsConfig,

        /// Returns default client options.
        pub fn default() Options {
            return .{
                .timeouts = Timeouts.default(),
                .limits = Limits.default(),
                .redirect_policy = RedirectPolicy.default(),
                .proxy = ProxyConfig.default(),
                .cookie_jar = null,
                .tls = TlsConfig.default(),
            };
        }
    };

    /// Future type for response completion.
    pub const ResponseFuture = RequestFuture(types.Response, Error);

    /// Handle for awaiting a client request response.
    pub const RequestHandle = struct {
        /// Internal request state backing the handle.
        state: *RequestState,

        /// Blocks until the request completes.
        pub fn wait(self: *RequestHandle) ResponseFuture.WaitError!types.Response {
            return self.state.wait();
        }

        /// Blocks until completion or the timeout elapses.
        pub fn timedWait(self: *RequestHandle, timeout_ns: u64) ResponseFuture.WaitError!types.Response {
            return self.state.timedWait(timeout_ns);
        }

        /// Cancels the request and releases owned resources.
        pub fn cancel(self: *RequestHandle) bool {
            return self.state.cancel();
        }

        /// Releases resources owned by the handle.
        pub fn deinit(self: *RequestHandle) void {
            self.state.deinit();
            self.state = undefined;
        }
    };

    /// Creates a client with the provided allocator and options.
    pub fn init(allocator: std.mem.Allocator, options: Options) Client {
        return .{
            .allocator = allocator,
            .options = options,
        };
    }

    /// Submits a request using a dedicated HTTP/1.1 connection.
    /// The request must remain valid until the returned handle completes.
    /// If the response includes a body, the caller must close it to release the connection.
    pub fn request(self: *Client, request_value: *const types.Request) Error!RequestHandle {
        const origin = try self.buildOrigin(request_value);
        const conn = try self.allocator.create(connection_h1.ConnectionH1);
        conn.* = connection_h1.ConnectionH1.init(self.allocator, origin, self.buildConnectionOptions());

        const state = self.allocator.create(RequestState) catch {
            conn.deinit();
            self.allocator.destroy(conn);
            return error.OutOfMemory;
        };
        state.* = RequestState.init(self.allocator, conn);

        var cleanup = true;
        errdefer if (cleanup) {
            conn.deinit();
            self.allocator.destroy(conn);
            self.allocator.destroy(state);
        };

        conn.start() catch return error.OutOfMemory;
        conn.submit(request_value, state.future.completion()) catch |err| return mapSubmitError(err);
        cleanup = false;

        return .{ .state = state };
    }

    /// Releases resources owned by the client.
    pub fn deinit(self: *Client) void {
        _ = self;
    }

    /// Internal state for an in-flight request.
    const RequestState = struct {
        /// Allocator for request state and owned allocations.
        allocator: std.mem.Allocator,
        /// Connection used for this request, or null after ownership transfer.
        connection: ?*connection_h1.ConnectionH1,
        /// Future holding the response result.
        future: ResponseFuture,
        /// Indicates the response has been finalized.
        completed: bool,

        /// Initializes a request state with the provided connection.
        fn init(
            allocator: std.mem.Allocator,
            connection: *connection_h1.ConnectionH1,
        ) RequestState {
            return .{
                .allocator = allocator,
                .connection = connection,
                .future = ResponseFuture.init(),
                .completed = false,
            };
        }

        /// Waits for completion and attaches response cleanup hooks.
        fn wait(self: *RequestState) ResponseFuture.WaitError!types.Response {
            const response = self.future.wait() catch |err| {
                self.shutdownConnection();
                return err;
            };
            return self.finalizeResponse(response);
        }

        /// Waits up to the timeout and attaches response cleanup hooks.
        fn timedWait(self: *RequestState, timeout_ns: u64) ResponseFuture.WaitError!types.Response {
            const response = self.future.timedWait(timeout_ns) catch |err| switch (err) {
                error.Timeout => return error.Timeout,
                else => {
                    self.shutdownConnection();
                    return err;
                },
            };
            return self.finalizeResponse(response);
        }

        /// Cancels the future and closes the connection.
        fn cancel(self: *RequestState) bool {
            const canceled = self.future.cancel();
            self.shutdownConnection();
            return canceled;
        }

        /// Releases request resources.
        fn deinit(self: *RequestState) void {
            if (!self.completed) {
                _ = self.future.cancel();
            }
            self.shutdownConnection();
            self.allocator.destroy(self);
        }

        /// Finalizes the response and wires body cleanup if needed.
        fn finalizeResponse(self: *RequestState, response_value: types.Response) ResponseFuture.WaitError!types.Response {
            var response = response_value;
            if (response.body) |body_reader| {
                const connection = self.connection orelse {
                    body_reader.close();
                    response.deinit();
                    return error.Canceled;
                };
                const ctx = self.allocator.create(ResponseBody) catch {
                    body_reader.close();
                    response.deinit();
                    self.shutdownConnection();
                    return error.OutOfMemory;
                };
                ctx.* = .{
                    .allocator = self.allocator,
                    .connection = connection,
                    .inner = body_reader,
                    .closed = false,
                };

                response.body = .{
                    .ctx = ctx,
                    .read_fn = ResponseBody.read,
                    .close_fn = ResponseBody.close,
                };
                self.connection = null;
            } else {
                self.shutdownConnection();
            }

            self.completed = true;
            return response;
        }

        /// Closes and frees the underlying connection, if present.
        fn shutdownConnection(self: *RequestState) void {
            if (self.connection) |connection| {
                connection.deinit();
                self.allocator.destroy(connection);
                self.connection = null;
            }
        }
    };

    /// Response body wrapper that cleans up the connection on close.
    const ResponseBody = struct {
        /// Allocator used for wrapper cleanup.
        allocator: std.mem.Allocator,
        /// Connection to release when the body is closed.
        connection: *connection_h1.ConnectionH1,
        /// Inner body reader provided by the connection.
        inner: types.BodyReader,
        /// Indicates whether the wrapper has been closed.
        closed: bool,

        /// Reads bytes from the inner body reader.
        fn read(ctx: ?*anyopaque, dest: []u8) anyerror!usize {
            const self: *ResponseBody = @ptrCast(@alignCast(ctx.?));
            return self.inner.read(dest);
        }

        /// Closes the body reader and releases connection resources.
        fn close(ctx: ?*anyopaque) void {
            const self: *ResponseBody = @ptrCast(@alignCast(ctx.?));
            if (self.closed) {
                return;
            }
            self.closed = true;
            self.inner.close();
            self.connection.deinit();
            self.allocator.destroy(self.connection);
            self.allocator.destroy(self);
        }
    };

    /// Builds a connection origin from the request URI.
    fn buildOrigin(self: *Client, request_value: *const types.Request) Error!connection_h1.ConnectionH1.Origin {
        _ = self;
        if (request_value.uri.scheme != .http) {
            return error.InvalidUri;
        }
        if (request_value.uri.host.len == 0) {
            return error.InvalidUri;
        }
        const port = request_value.uri.effectivePort();
        return .{
            .scheme = request_value.uri.scheme,
            .host = request_value.uri.host,
            .port = port,
        };
    }

    /// Maps client options into connection options.
    fn buildConnectionOptions(self: *Client) connection_h1.ConnectionH1.Options {
        var options = connection_h1.ConnectionH1.Options.default();
        options.connect_timeout_ns = if (self.options.timeouts.connect) |timeout|
            timeout.toNanos()
        else
            null;
        options.write_timeout_ns = if (self.options.timeouts.write) |timeout|
            timeout.toNanos()
        else
            null;
        options.read_timeout_ns = if (self.options.timeouts.read) |timeout|
            timeout.toNanos()
        else
            null;
        options.request_timeout_ns = if (self.options.timeouts.request) |timeout|
            timeout.toNanos()
        else
            null;
        options.max_header_bytes = self.options.limits.max_header_bytes.toInt();
        options.max_header_count = self.options.limits.max_header_count.toInt();
        options.max_status_line_bytes = self.options.limits.max_response_line_bytes.toInt();
        return options;
    }

    /// Maps connection submit errors into client errors.
    fn mapSubmitError(err: connection_h1.ConnectionH1.SubmitError) Error {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.Closed,
            error.NotStarted,
            => error.Transport,
        };
    }
};

test "client option defaults" {
    const options = Client.Options.default();

    var client = Client.init(std.testing.allocator, options);
    defer client.deinit();

    try std.testing.expect(options.timeouts.connect != null);
    try std.testing.expect(options.timeouts.write != null);
    try std.testing.expect(options.timeouts.read != null);
    try std.testing.expect(options.timeouts.request != null);

    try std.testing.expectEqual(
        @as(u64, 10 * std.time.ns_per_s),
        options.timeouts.connect.?.toNanos(),
    );
    try std.testing.expectEqual(
        @as(u64, 30 * std.time.ns_per_s),
        options.timeouts.write.?.toNanos(),
    );
    try std.testing.expectEqual(
        @as(u64, 30 * std.time.ns_per_s),
        options.timeouts.read.?.toNanos(),
    );
    try std.testing.expectEqual(
        @as(u64, 120 * std.time.ns_per_s),
        options.timeouts.request.?.toNanos(),
    );

    try std.testing.expectEqual(@as(usize, 32 * 1024), options.limits.max_header_bytes.toInt());
    try std.testing.expectEqual(@as(usize, 100), options.limits.max_header_count.toInt());
    try std.testing.expectEqual(
        @as(usize, 8 * 1024),
        options.limits.max_response_line_bytes.toInt(),
    );

    try std.testing.expectEqual(Client.RedirectMode.follow, options.redirect_policy.mode);
    try std.testing.expectEqual(@as(u8, 10), options.redirect_policy.max_hops);

    try std.testing.expectEqual(Client.ProxyMode.system, options.proxy.mode);
    try std.testing.expect(options.proxy.manual == null);

    try std.testing.expect(options.cookie_jar == null);
    try std.testing.expectEqual(Client.TlsVerifyMode.verify, options.tls.verify);
}

test "client request executes against local server" {
    const test_server = @import("http1/test_server.zig");

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

    var client = Client.init(std.testing.allocator, Client.Options.default());
    defer client.deinit();

    const uri = types.Uri.init(.http, "127.0.0.1", types.Port.init(server.port()), "/", null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();
    try request.headers.append("Host", "127.0.0.1");

    var handle = try client.request(&request);
    defer handle.deinit();

    var response = try handle.wait();
    defer response.deinit();
    defer if (response.body) |body| body.close();

    try std.testing.expectEqual(types.Status.ok, response.status);

    var buffer: [8]u8 = undefined;
    const read_len = try response.body.?.read(&buffer);
    try std.testing.expectEqual(@as(usize, 5), read_len);
    try std.testing.expectEqualStrings("hello", buffer[0..read_len]);
    const eof = try response.body.?.read(&buffer);
    try std.testing.expectEqual(@as(usize, 0), eof);
}
