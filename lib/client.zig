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
    /// Connection pool keyed by origin.
    pool: ConnectionPool,

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

    /// Connection count with an explicit unit.
    pub const ConnectionCount = struct {
        /// Number of connections.
        count: usize,

        /// Creates a connection count from the provided value.
        pub fn init(count: usize) ConnectionCount {
            return .{ .count = count };
        }

        /// Returns the connection count.
        pub fn toInt(self: ConnectionCount) usize {
            return self.count;
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

    /// Connection pooling configuration.
    pub const PoolOptions = struct {
        /// Maximum number of connections per origin.
        max_connections: ConnectionCount,
        /// Idle timeout before a connection is discarded.
        idle_timeout: Duration,

        /// Returns default pool options.
        pub fn default() PoolOptions {
            return .{
                .max_connections = ConnectionCount.init(8),
                .idle_timeout = Duration.fromSeconds(30),
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

    /// Identity token for TLS configuration matching.
    pub const TlsConfigId = struct {
        /// Opaque identifier value.
        value: u64,

        /// Creates a TLS config identity from the provided value.
        pub fn init(value: u64) TlsConfigId {
            return .{ .value = value };
        }

        /// Returns the identifier value.
        pub fn toInt(self: TlsConfigId) u64 {
            return self.value;
        }
    };

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

        /// Returns a stable identity token for pooling decisions.
        pub fn identity(self: TlsConfig) TlsConfigId {
            var hasher = std.hash.Wyhash.init(0);
            const verify_byte: u8 = @intFromEnum(self.verify);
            hasher.update(&[_]u8{verify_byte});
            return TlsConfigId.init(hasher.final());
        }

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
        /// Connection pool configuration.
        pool: PoolOptions,
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
                .pool = PoolOptions.default(),
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

    /// Internal connection pool keyed by origin.
    const ConnectionPool = struct {
        /// Allocator used for pool bookkeeping.
        allocator: std.mem.Allocator,
        /// Pool configuration options.
        options: PoolOptions,
        /// Mutex guarding pool state.
        mutex: std.Thread.Mutex,
        /// Map of origin keys to pool entries.
        origins: OriginMap,

        /// Map type for origin entries.
        const OriginMap = std.HashMapUnmanaged(
            OriginKey,
            OriginEntry,
            OriginKeyContext,
            std.hash_map.default_max_load_percentage,
        );

        /// Origin key used for pooling decisions.
        const OriginKey = struct {
            /// Scheme for the origin.
            scheme: types.Scheme,
            /// Hostname for the origin.
            host: []const u8,
            /// Port for the origin.
            port: types.Port,
            /// TLS configuration identity.
            tls_id: TlsConfigId,
        };

        /// Hashing context for origin keys.
        const OriginKeyContext = struct {
            /// Hashes the origin key for the pool map.
            pub fn hash(_: @This(), key: OriginKey) u64 {
                var hasher = std.hash.Wyhash.init(0);
                const scheme_byte: u8 = @intFromEnum(key.scheme);
                hasher.update(&[_]u8{scheme_byte});

                const port_bytes = std.mem.toBytes(key.port.toInt());
                hasher.update(&port_bytes);

                const tls_bytes = std.mem.toBytes(key.tls_id.toInt());
                hasher.update(&tls_bytes);

                for (key.host) |byte| {
                    const lower = std.ascii.toLower(byte);
                    hasher.update(&[_]u8{lower});
                }

                return hasher.final();
            }

            /// Returns true when origin keys are equivalent.
            pub fn eql(_: @This(), a: OriginKey, b: OriginKey) bool {
                return a.scheme == b.scheme and
                    a.port.toInt() == b.port.toInt() and
                    a.tls_id.toInt() == b.tls_id.toInt() and
                    std.ascii.eqlIgnoreCase(a.host, b.host);
            }
        };

        /// Idle connection tracked by the pool.
        const IdleConnection = struct {
            /// Connection pointer.
            connection: *connection_h1.ConnectionH1,
            /// Timestamp of when the connection became idle.
            last_used_ns: i128,
        };

        /// Per-origin connection tracking state.
        const OriginEntry = struct {
            /// Idle connections ready for reuse.
            idle: std.ArrayListUnmanaged(IdleConnection),
            /// Total connections tracked for the origin.
            total: usize,

            /// Initializes an empty origin entry.
            fn init() OriginEntry {
                return .{
                    .idle = .{},
                    .total = 0,
                };
            }

            /// Releases idle connections and storage.
            fn deinit(self: *OriginEntry, allocator: std.mem.Allocator) void {
                for (self.idle.items) |idle| {
                    idle.connection.deinit();
                    allocator.destroy(idle.connection);
                }
                self.idle.deinit(allocator);
                self.total = 0;
            }
        };

        /// Lease returned while a connection is checked out.
        const Lease = struct {
            /// Origin key for this lease.
            origin: OriginKey,
            /// Connection pointer.
            connection: *connection_h1.ConnectionH1,
        };

        /// Creates a connection pool with the provided options.
        fn init(allocator: std.mem.Allocator, options: PoolOptions) ConnectionPool {
            return .{
                .allocator = allocator,
                .options = options,
                .mutex = .{},
                .origins = .{},
            };
        }

        /// Releases idle connections and pool storage.
        fn deinit(self: *ConnectionPool) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            var iter = self.origins.iterator();
            while (iter.next()) |entry| {
                entry.value_ptr.deinit(self.allocator);
                self.allocator.free(@constCast(entry.key_ptr.host));
            }
            self.origins.deinit(self.allocator);
        }

        /// Checks out a connection for the origin.
        fn checkout(
            self: *ConnectionPool,
            origin: OriginKey,
            options: connection_h1.ConnectionH1.Options,
        ) Error!Lease {
            self.mutex.lock();

            var entry = self.origins.getEntryContext(origin, OriginKeyContext{}) orelse blk: {
                const owned_key = try self.allocateKey(origin);
                try self.origins.putContext(
                    self.allocator,
                    owned_key,
                    OriginEntry.init(),
                    OriginKeyContext{},
                );
                break :blk self.origins.getEntryContext(owned_key, OriginKeyContext{}).?;
            };

            const now = std.time.nanoTimestamp();
            self.pruneIdle(entry.value_ptr, now);

            if (entry.value_ptr.idle.items.len > 0) {
                const idle = entry.value_ptr.idle.pop();
                const lease = Lease{
                    .origin = entry.key_ptr.*,
                    .connection = idle.connection,
                };
                self.mutex.unlock();
                return lease;
            }

            if (entry.value_ptr.total >= self.options.max_connections.toInt()) {
                self.mutex.unlock();
                return error.LimitExceeded;
            }

            entry.value_ptr.total += 1;
            const key = entry.key_ptr.*;
            self.mutex.unlock();

            const connection = self.createConnection(key, options) catch |err| {
                self.rollbackReservation(key);
                return err;
            };

            return .{
                .origin = key,
                .connection = connection,
            };
        }

        /// Releases a checked-out connection back into the idle pool.
        fn release(self: *ConnectionPool, lease: Lease) void {
            var connection_to_destroy: ?*connection_h1.ConnectionH1 = null;

            self.mutex.lock();
            if (self.origins.getEntryContext(lease.origin, OriginKeyContext{})) |entry| {
                const idle_entry = IdleConnection{
                    .connection = lease.connection,
                    .last_used_ns = std.time.nanoTimestamp(),
                };
                entry.value_ptr.idle.append(self.allocator, idle_entry) catch {
                    if (entry.value_ptr.total > 0) {
                        entry.value_ptr.total -= 1;
                    }
                    connection_to_destroy = lease.connection;
                    self.pruneOriginIfEmpty(entry.key_ptr, entry.value_ptr);
                };
            } else {
                connection_to_destroy = lease.connection;
            }
            self.mutex.unlock();

            if (connection_to_destroy) |connection| {
                connection.deinit();
                self.allocator.destroy(connection);
            }
        }

        /// Discards a checked-out connection and updates pool counts.
        fn discard(self: *ConnectionPool, lease: Lease) void {
            self.mutex.lock();
            if (self.origins.getEntryContext(lease.origin, OriginKeyContext{})) |entry| {
                if (entry.value_ptr.total > 0) {
                    entry.value_ptr.total -= 1;
                }
                self.pruneOriginIfEmpty(entry.key_ptr, entry.value_ptr);
            }
            self.mutex.unlock();

            lease.connection.deinit();
            self.allocator.destroy(lease.connection);
        }

        /// Creates a new connection for the given origin.
        fn createConnection(
            self: *ConnectionPool,
            origin: OriginKey,
            options: connection_h1.ConnectionH1.Options,
        ) Error!*connection_h1.ConnectionH1 {
            const conn = self.allocator.create(connection_h1.ConnectionH1) catch {
                return error.OutOfMemory;
            };
            conn.* = connection_h1.ConnectionH1.init(
                self.allocator,
                .{
                    .scheme = origin.scheme,
                    .host = origin.host,
                    .port = origin.port,
                },
                options,
            );

            conn.start() catch {
                conn.deinit();
                self.allocator.destroy(conn);
                return error.OutOfMemory;
            };

            return conn;
        }

        /// Removes idle connections that have exceeded the idle timeout.
        fn pruneIdle(self: *ConnectionPool, entry: *OriginEntry, now: i128) void {
            const timeout_ns = self.options.idle_timeout.toNanos();
            if (timeout_ns == 0) {
                return;
            }

            var index: usize = 0;
            while (index < entry.idle.items.len) {
                const idle = entry.idle.items[index];
                const elapsed = now - idle.last_used_ns;
                if (elapsed > @as(i128, @intCast(timeout_ns))) {
                    _ = entry.idle.swapRemove(index);
                    if (entry.total > 0) {
                        entry.total -= 1;
                    }
                    idle.connection.deinit();
                    self.allocator.destroy(idle.connection);
                    continue;
                }
                index += 1;
            }
        }

        /// Removes an origin entry when no connections remain.
        fn pruneOriginIfEmpty(
            self: *ConnectionPool,
            key_ptr: *OriginKey,
            entry: *OriginEntry,
        ) void {
            if (entry.total != 0 or entry.idle.items.len != 0) {
                return;
            }
            const host = key_ptr.host;
            entry.deinit(self.allocator);
            self.origins.removeByPtr(key_ptr);
            self.allocator.free(@constCast(host));
        }

        /// Allocates a stable host copy for a new origin key.
        fn allocateKey(self: *ConnectionPool, key: OriginKey) Error!OriginKey {
            const host_copy = self.allocator.dupe(u8, key.host) catch {
                return error.OutOfMemory;
            };
            return .{
                .scheme = key.scheme,
                .host = host_copy,
                .port = key.port,
                .tls_id = key.tls_id,
            };
        }

        /// Rolls back a reserved connection slot after failure.
        fn rollbackReservation(self: *ConnectionPool, key: OriginKey) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.origins.getEntryContext(key, OriginKeyContext{})) |entry| {
                if (entry.value_ptr.total > 0) {
                    entry.value_ptr.total -= 1;
                }
                self.pruneOriginIfEmpty(entry.key_ptr, entry.value_ptr);
            }
        }
    };

    /// Creates a client with the provided allocator and options.
    pub fn init(allocator: std.mem.Allocator, options: Options) Client {
        return .{
            .allocator = allocator,
            .options = options,
            .pool = ConnectionPool.init(allocator, options.pool),
        };
    }

    /// Submits a request using a pooled HTTP/1.1 connection.
    /// The request must remain valid until the returned handle completes.
    /// If the response includes a body, the caller must close it to release the connection.
    pub fn request(self: *Client, request_value: *const types.Request) Error!RequestHandle {
        const origin = try self.buildOriginKey(request_value);
        const connection_options = self.buildConnectionOptions();
        var lease = try self.pool.checkout(origin, connection_options);

        var cleanup = true;
        errdefer if (cleanup) self.pool.discard(lease);

        const state = self.allocator.create(RequestState) catch {
            return error.OutOfMemory;
        };
        errdefer self.allocator.destroy(state);
        state.* = RequestState.init(self.allocator, &self.pool, lease);

        lease.connection.submit(request_value, state.future.completion()) catch |err| {
            return mapSubmitError(err);
        };

        cleanup = false;
        return .{ .state = state };
    }

    /// Releases resources owned by the client.
    pub fn deinit(self: *Client) void {
        self.pool.deinit();
    }

    /// Internal state for an in-flight request.
    const RequestState = struct {
        /// Allocator for request state and owned allocations.
        allocator: std.mem.Allocator,
        /// Pool used to return or discard connections.
        pool: *ConnectionPool,
        /// Lease for the checked-out connection.
        lease: ?ConnectionPool.Lease,
        /// Future holding the response result.
        future: ResponseFuture,
        /// Indicates the response has been finalized.
        completed: bool,

        /// Initializes a request state with the provided lease.
        fn init(
            allocator: std.mem.Allocator,
            pool: *ConnectionPool,
            lease: ConnectionPool.Lease,
        ) RequestState {
            return .{
                .allocator = allocator,
                .pool = pool,
                .lease = lease,
                .future = ResponseFuture.init(),
                .completed = false,
            };
        }

        /// Waits for completion and attaches response cleanup hooks.
        fn wait(self: *RequestState) ResponseFuture.WaitError!types.Response {
            const response = self.future.wait() catch |err| {
                self.discardLease();
                return err;
            };
            return self.finalizeResponse(response);
        }

        /// Waits up to the timeout and attaches response cleanup hooks.
        fn timedWait(self: *RequestState, timeout_ns: u64) ResponseFuture.WaitError!types.Response {
            const response = self.future.timedWait(timeout_ns) catch |err| switch (err) {
                error.Timeout => return error.Timeout,
                else => {
                    self.discardLease();
                    return err;
                },
            };
            return self.finalizeResponse(response);
        }

        /// Cancels the future and closes the connection.
        fn cancel(self: *RequestState) bool {
            const canceled = self.future.cancel();
            self.discardLease();
            return canceled;
        }

        /// Releases request resources.
        fn deinit(self: *RequestState) void {
            if (!self.completed) {
                _ = self.future.cancel();
            }
            self.discardLease();
            self.allocator.destroy(self);
        }

        /// Finalizes the response and wires body cleanup if needed.
        fn finalizeResponse(self: *RequestState, response_value: types.Response) ResponseFuture.WaitError!types.Response {
            var response = response_value;
            if (response.body) |body_reader| {
                const lease = self.takeLease() orelse {
                    body_reader.close();
                    response.deinit();
                    return error.Canceled;
                };
                const ctx = self.allocator.create(ResponseBody) catch {
                    body_reader.close();
                    response.deinit();
                    self.pool.discard(lease);
                    return error.OutOfMemory;
                };
                ctx.* = .{
                    .allocator = self.allocator,
                    .pool = self.pool,
                    .lease = lease,
                    .inner = body_reader,
                    .closed = false,
                };

                response.body = .{
                    .ctx = ctx,
                    .read_fn = ResponseBody.read,
                    .close_fn = ResponseBody.close,
                };
            } else {
                self.releaseLease();
            }

            self.completed = true;
            return response;
        }

        /// Releases the lease back to the pool, if present.
        fn releaseLease(self: *RequestState) void {
            if (self.lease) |lease| {
                self.pool.release(lease);
                self.lease = null;
            }
        }

        /// Discards the lease and closes the connection, if present.
        fn discardLease(self: *RequestState) void {
            if (self.lease) |lease| {
                self.pool.discard(lease);
                self.lease = null;
            }
        }

        /// Takes ownership of the lease, if present.
        fn takeLease(self: *RequestState) ?ConnectionPool.Lease {
            if (self.lease) |lease| {
                self.lease = null;
                return lease;
            }
            return null;
        }
    };

    /// Response body wrapper that returns the connection on close.
    const ResponseBody = struct {
        /// Allocator used for wrapper cleanup.
        allocator: std.mem.Allocator,
        /// Pool used to return the connection.
        pool: *ConnectionPool,
        /// Lease to return when the body is closed.
        lease: ConnectionPool.Lease,
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
            self.pool.release(self.lease);
            self.allocator.destroy(self);
        }
    };

    /// Builds a pool origin key from the request URI.
    fn buildOriginKey(self: *Client, request_value: *const types.Request) Error!ConnectionPool.OriginKey {
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
            .tls_id = self.options.tls.identity(),
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

    try std.testing.expectEqual(@as(usize, 8), options.pool.max_connections.toInt());
    try std.testing.expectEqual(
        @as(u64, 30 * std.time.ns_per_s),
        options.pool.idle_timeout.toNanos(),
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

test "client reuses keep-alive connection" {
    const test_server = @import("http1/test_server.zig");

    const scenarios = [_]test_server.Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{
                        .response = .{
                            .status = .ok,
                            .reason = "OK",
                            .body = "one",
                        },
                    },
                    .close_after = false,
                },
                .{
                    .payload = .{
                        .response = .{
                            .status = .ok,
                            .reason = "OK",
                            .body = "two",
                        },
                    },
                    .close_after = true,
                },
            },
        },
    };

    var server = try test_server.TestServer.init(&scenarios, test_server.Options.default());
    defer server.deinit();
    try server.start();

    var options = Client.Options.default();
    options.pool.max_connections = Client.ConnectionCount.init(1);
    options.pool.idle_timeout = Client.Duration.fromSeconds(2);
    options.timeouts.read = Client.Duration.fromMillis(500);
    options.timeouts.request = Client.Duration.fromSeconds(2);

    var client = Client.init(std.testing.allocator, options);
    defer client.deinit();

    const uri = types.Uri.init(.http, "127.0.0.1", types.Port.init(server.port()), "/", null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();
    try request.headers.append("Host", "127.0.0.1");

    {
        var handle = try client.request(&request);
        defer handle.deinit();

        var response = try handle.wait();
        defer response.deinit();
        defer if (response.body) |body| body.close();

        var buffer: [8]u8 = undefined;
        const read_len = try response.body.?.read(&buffer);
        try std.testing.expectEqualStrings("one", buffer[0..read_len]);
        const eof = try response.body.?.read(&buffer);
        try std.testing.expectEqual(@as(usize, 0), eof);
    }

    {
        var handle = try client.request(&request);
        defer handle.deinit();

        var response = try handle.wait();
        defer response.deinit();
        defer if (response.body) |body| body.close();

        var buffer: [8]u8 = undefined;
        const read_len = try response.body.?.read(&buffer);
        try std.testing.expectEqualStrings("two", buffer[0..read_len]);
        const eof = try response.body.?.read(&buffer);
        try std.testing.expectEqual(@as(usize, 0), eof);
    }
}
