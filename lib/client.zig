//! HTTP client implementation.

const std = @import("std");
const types = @import("types.zig");
const mailbox = @import("util/mailbox.zig");
const future = @import("util/future.zig");
const connection_h1 = @import("http1/connection_h1.zig");
const request_encoder = @import("http1/request_encoder.zig");
const redirects = @import("redirects/redirects.zig");
const cookies = @import("cookies/cookie_jar.zig");
const proxy_env = @import("proxy/proxy_env.zig");

/// Typed client errors.
pub const Error = error{
    /// Operation exceeded a timeout.
    Timeout,
    /// Client configuration is invalid.
    InvalidConfig,
    /// Proxy CONNECT request failed.
    ProxyConnectFailed,
    /// Redirect limit was exceeded.
    RedirectLimitExceeded,
    /// Redirect loop was detected.
    RedirectLoop,
    /// Redirect response was missing a location header.
    RedirectMissingLocation,
    /// Redirect response contained an invalid location value.
    RedirectInvalidLocation,
    /// Redirect location used an unsupported scheme.
    RedirectUnsupportedScheme,
    /// Redirect requires a repeatable body that is not available.
    RedirectBodyNotRepeatable,
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

/// Duration expressed in nanoseconds.
pub const Duration = types.Duration;
/// Size in bytes with an explicit unit.
pub const ByteSize = types.ByteSize;
/// Header field count with an explicit unit.
pub const HeaderCount = types.HeaderCount;
/// Line length expressed in bytes.
pub const LineLength = types.LineLength;
/// Connection count with an explicit unit.
pub const ConnectionCount = types.ConnectionCount;
/// TLS identity token used in pool matching.
pub const TlsIdentityToken = types.TlsIdentityToken;
/// TLS certificate verification mode.
pub const TlsVerifyMode = types.TlsVerifyMode;
/// Root store selection mode for TLS verification.
pub const TlsRootStoreMode = types.TlsRootStoreMode;
/// TLS configuration.
pub const TlsConfig = types.TlsConfig;
/// Shared origin key used for pool lookups.
const OriginKey = types.OriginKey;

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
    /// Idle timeout before a connection is discarded, or null to disable expiry.
    /// A timeout of zero discards idle connections immediately.
    idle_timeout: ?Duration,

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

/// Basic proxy authentication credentials.
pub const ProxyBasicAuth = struct {
    /// Username for proxy authentication.
    username: []const u8,
    /// Password for proxy authentication.
    password: []const u8,
};

/// Proxy authentication configuration.
pub const ProxyAuth = union(enum) {
    /// Basic authentication credentials.
    basic: ProxyBasicAuth,
};

/// Manual proxy endpoint configuration.
pub const Proxy = struct {
    /// Proxy scheme.
    scheme: types.Scheme,
    /// Proxy hostname or IP literal.
    host: []const u8,
    /// Proxy port.
    port: types.Port,
    /// Optional proxy authentication settings.
    auth: ?ProxyAuth,
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

/// Thread-safe cookie jar implementation.
pub const CookieJar = cookies.CookieJar;

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

/// Per-request configuration overrides.
pub const RequestOptions = struct {
    /// Proxy configuration override, or null to use client defaults.
    proxy: ?ProxyConfig,

    /// Returns default request options.
    pub fn default() RequestOptions {
        return .{
            .proxy = null,
        };
    }
};

/// Future type for response completion.
pub const ResponseFuture = future.RequestFuture(types.Response, Error);

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

/// Prepared request pointer with optional owned storage.
const PreparedRequest = struct {
    /// Request pointer to submit.
    request: *const types.Request,
    /// Owned request storage, if a copy was created.
    owned: ?*types.Request,
};

/// Map type for origin entries.
const OriginMap = std.HashMapUnmanaged(
    OriginKey,
    OriginEntry,
    OriginKeyContext,
    std.hash_map.default_max_load_percentage,
);

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

        const protocol_byte: u8 = @intFromEnum(key.negotiated_protocol);
        hasher.update(&[_]u8{protocol_byte});

        const mode_byte: u8 = @intFromEnum(key.target_mode);
        hasher.update(&[_]u8{mode_byte});

        const tunnel_flag: u8 = if (key.tunnel != null) 1 else 0;
        hasher.update(&[_]u8{tunnel_flag});
        if (key.tunnel) |tunnel| {
            const tunnel_port = std.mem.toBytes(tunnel.port.toInt());
            hasher.update(&tunnel_port);
            for (tunnel.host) |byte| {
                const lower = std.ascii.toLower(byte);
                hasher.update(&[_]u8{lower});
            }
        }

        const auth_flag: u8 = if (key.proxy_authorization != null) 1 else 0;
        hasher.update(&[_]u8{auth_flag});
        if (key.proxy_authorization) |auth| {
            hasher.update(auth);
        }

        for (key.host) |byte| {
            const lower = std.ascii.toLower(byte);
            hasher.update(&[_]u8{lower});
        }

        return hasher.final();
    }

    /// Returns true when origin keys are equivalent.
    pub fn eql(_: @This(), a: OriginKey, b: OriginKey) bool {
        if (a.scheme != b.scheme or
            a.port.toInt() != b.port.toInt() or
            a.tls_id.toInt() != b.tls_id.toInt() or
            a.negotiated_protocol != b.negotiated_protocol or
            a.target_mode != b.target_mode)
        {
            return false;
        }
        if (!std.ascii.eqlIgnoreCase(a.host, b.host)) {
            return false;
        }
        if ((a.tunnel == null) != (b.tunnel == null)) {
            return false;
        }
        if (a.tunnel) |a_tunnel| {
            const b_tunnel = b.tunnel.?;
            if (a_tunnel.port.toInt() != b_tunnel.port.toInt()) {
                return false;
            }
            if (!std.ascii.eqlIgnoreCase(a_tunnel.host, b_tunnel.host)) {
                return false;
            }
        }
        if ((a.proxy_authorization == null) != (b.proxy_authorization == null)) {
            return false;
        }
        if (a.proxy_authorization) |auth_a| {
            const auth_b = b.proxy_authorization.?;
            if (!std.mem.eql(u8, auth_a, auth_b)) {
                return false;
            }
        }
        return true;
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
            const host = entry.key_ptr.host;
            const tunnel_host = if (entry.key_ptr.tunnel) |tunnel| tunnel.host else null;
            const proxy_auth = entry.key_ptr.proxy_authorization;
            self.allocator.free(@constCast(host));
            if (tunnel_host) |value| {
                self.allocator.free(@constCast(value));
            }
            if (proxy_auth) |value| {
                self.allocator.free(@constCast(value));
            }
        }
        self.origins.deinit(self.allocator);
    }

    /// Checks out a connection for the origin.
    fn checkout(
        self: *ConnectionPool,
        origin: OriginKey,
        options: connection_h1.Options,
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
            const idle = entry.value_ptr.idle.pop().?;
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
        const idle_timeout = self.options.idle_timeout;

        self.mutex.lock();
        if (self.origins.getEntryContext(lease.origin, OriginKeyContext{})) |entry| {
            if (idle_timeout) |timeout| {
                if (timeout.toNanos() == 0) {
                    if (entry.value_ptr.total > 0) {
                        entry.value_ptr.total -= 1;
                    }
                    connection_to_destroy = lease.connection;
                    self.pruneOriginIfEmpty(entry.key_ptr, entry.value_ptr);
                    self.mutex.unlock();
                    if (connection_to_destroy) |connection| {
                        connection.deinit();
                        self.allocator.destroy(connection);
                    }
                    return;
                }
            }

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
        options: connection_h1.Options,
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
                .target_mode = mapConnectionTargetMode(origin.target_mode),
                .tunnel = if (origin.tunnel) |tunnel|
                    .{ .host = tunnel.host, .port = tunnel.port }
                else
                    null,
                .proxy_authorization = origin.proxy_authorization,
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
        const timeout = self.options.idle_timeout orelse return;
        const timeout_ns = timeout.toNanos();

        var index: usize = 0;
        while (index < entry.idle.items.len) {
            const idle = entry.idle.items[index];
            const elapsed = now - idle.last_used_ns;
            if (elapsed >= @as(i128, @intCast(timeout_ns))) {
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
        const tunnel_host = if (key_ptr.tunnel) |tunnel| tunnel.host else null;
        const proxy_auth = key_ptr.proxy_authorization;
        entry.deinit(self.allocator);
        self.origins.removeByPtr(key_ptr);
        self.allocator.free(@constCast(host));
        if (tunnel_host) |value| {
            self.allocator.free(@constCast(value));
        }
        if (proxy_auth) |value| {
            self.allocator.free(@constCast(value));
        }
    }

    /// Allocates a stable host copy for a new origin key.
    fn allocateKey(self: *ConnectionPool, key: OriginKey) Error!OriginKey {
        const host_copy = self.allocator.dupe(u8, key.host) catch {
            return error.OutOfMemory;
        };
        errdefer self.allocator.free(host_copy);

        var tunnel_copy: ?types.TunnelTarget = null;
        if (key.tunnel) |tunnel| {
            const tunnel_host = self.allocator.dupe(u8, tunnel.host) catch {
                return error.OutOfMemory;
            };
            tunnel_copy = .{
                .host = tunnel_host,
                .port = tunnel.port,
            };
        }
        errdefer if (tunnel_copy) |tunnel| self.allocator.free(@constCast(tunnel.host));

        var proxy_auth_copy: ?[]const u8 = null;
        if (key.proxy_authorization) |value| {
            const auth = self.allocator.dupe(u8, value) catch {
                return error.OutOfMemory;
            };
            proxy_auth_copy = auth;
        }
        errdefer if (proxy_auth_copy) |value| self.allocator.free(@constCast(value));

        return .{
            .scheme = key.scheme,
            .host = host_copy,
            .port = key.port,
            .tls_id = key.tls_id,
            .negotiated_protocol = key.negotiated_protocol,
            .target_mode = key.target_mode,
            .tunnel = tunnel_copy,
            .proxy_authorization = proxy_auth_copy,
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

/// Internal state for an in-flight request.
const RequestState = struct {
    /// Allocator for request state and owned allocations.
    allocator: std.mem.Allocator,
    /// Mutex guarding mutable request state.
    mutex: std.Thread.Mutex,
    /// Client owning the request.
    client: *Client,
    /// Original request pointer.
    request: *const types.Request,
    /// Owned request storage, if a copy was created.
    owned_request: ?*types.Request,
    /// Indicates whether redirects should be followed.
    follow_redirects: bool,
    /// Per-request override options.
    request_options: RequestOptions,
    /// Timestamp used for overall timeout tracking.
    start_ns: i128,
    /// Cancellation token for the request.
    cancel_token: CancellationToken,
    /// Pool used to return or discard connections.
    pool: *ConnectionPool,
    /// Lease for the checked-out connection.
    lease: ?Lease,
    /// Future holding the response result.
    future: connection_h1.ResponseFuture,
    /// Indicates the response has been finalized.
    completed: bool,

    /// Initializes a request state with the provided lease.
    fn init(
        allocator: std.mem.Allocator,
        client: *Client,
        request_value: *const types.Request,
        owned_request: ?*types.Request,
        follow_redirects: bool,
        request_options: RequestOptions,
        lease: Lease,
    ) RequestState {
        return .{
            .allocator = allocator,
            .mutex = .{},
            .client = client,
            .request = request_value,
            .owned_request = owned_request,
            .follow_redirects = follow_redirects,
            .request_options = request_options,
            .start_ns = std.time.nanoTimestamp(),
            .cancel_token = CancellationToken.init(),
            .pool = &client.pool,
            .lease = lease,
            .future = connection_h1.ResponseFuture.init(),
            .completed = false,
        };
    }

    /// Waits for completion and attaches response cleanup hooks.
    fn wait(self: *RequestState) ResponseFuture.WaitError!types.Response {
        return self.waitInternal(null);
    }

    /// Waits up to the timeout and attaches response cleanup hooks.
    fn timedWait(self: *RequestState, timeout_ns: u64) ResponseFuture.WaitError!types.Response {
        const deadline = std.time.nanoTimestamp() + @as(i128, @intCast(timeout_ns));
        return self.waitInternal(deadline);
    }

    /// Waits for completion, applying redirect logic when enabled.
    fn waitInternal(self: *RequestState, deadline: ?i128) ResponseFuture.WaitError!types.Response {
        var effective_deadline = deadline;
        if (self.client.options.timeouts.request) |timeout| {
            const request_deadline = self.start_ns + @as(i128, @intCast(timeout.toNanos()));
            if (effective_deadline == null or request_deadline < effective_deadline.?) {
                effective_deadline = request_deadline;
            }
        }

        if (!self.follow_redirects) {
            const response = try self.waitForCurrentResponse(effective_deadline);
            return self.finalizeResponse(self.request.uri, response);
        }

        return self.waitWithRedirects(effective_deadline);
    }

    /// Executes redirect handling while waiting for a final response.
    fn waitWithRedirects(self: *RequestState, deadline: ?i128) ResponseFuture.WaitError!types.Response {
        const base_headers = &self.request.headers;
        const version = self.request.version;
        var current_method = self.request.method;
        var current_uri = self.request.uri;
        var body_present = self.request.body != null;
        var current_owned: ?redirects.OwnedUri = null;
        defer if (current_owned) |*owned| owned.deinit();

        var visited = std.ArrayList([]u8){};
        defer {
            for (visited.items) |key| {
                self.allocator.free(key);
            }
            visited.deinit(self.allocator);
        }

        self.appendRedirectKey(&visited, current_uri) catch |err| {
            _ = self.cancel();
            return err;
        };

        var hops: u8 = 0;
        var owned_request: ?*types.Request = null;

        while (true) {
            if (self.cancel_token.isCanceled()) {
                self.discardLease();
                return error.Canceled;
            }

            var response = self.waitForCurrentResponse(deadline) catch |err| {
                self.cleanupOwnedRequest(owned_request);
                owned_request = null;
                return err;
            };

            self.cleanupOwnedRequest(owned_request);
            owned_request = null;

            if (!redirects.isRedirectStatus(response.status)) {
                return self.finalizeResponse(current_uri, response);
            }

            try self.storeCookies(current_uri, &response);

            const location = response.headers.get("Location") orelse {
                self.abandonRedirectResponse(&response);
                return error.RedirectMissingLocation;
            };

            if (hops >= self.client.options.redirect_policy.max_hops) {
                self.abandonRedirectResponse(&response);
                return error.RedirectLimitExceeded;
            }

            const rewrite = redirects.rewriteMethod(response.status, current_method);
            if (rewrite.keep_body and body_present) {
                self.abandonRedirectResponse(&response);
                return error.RedirectBodyNotRepeatable;
            }
            if (!rewrite.keep_body) {
                body_present = false;
            }

            var resolved = redirects.resolveLocation(self.allocator, current_uri, location) catch |err| {
                self.abandonRedirectResponse(&response);
                return mapRedirectError(err);
            };
            var resolved_committed = false;
            defer if (!resolved_committed) resolved.deinit();

            const next_uri = resolved.asUri();
            const same_origin = isSameOrigin(current_uri, next_uri);
            self.appendRedirectKey(&visited, next_uri) catch |err| {
                self.abandonRedirectResponse(&response);
                return err;
            };

            hops += 1;
            self.abandonRedirectResponse(&response);

            current_method = rewrite.method;
            if (current_owned) |*owned| {
                owned.deinit();
            }
            current_owned = resolved;
            current_uri = current_owned.?.asUri();
            resolved_committed = true;

            owned_request = try buildRedirectRequest(
                self.allocator,
                current_method,
                current_uri,
                version,
                base_headers,
                same_origin,
            );
            owned_request = try self.applyCookiesToOwnedRequest(owned_request.?);
            const proxy_config = self.request_options.proxy orelse self.client.options.proxy;
            var proxy_endpoint = try self.client.resolveProxyConfig(current_uri, proxy_config);
            errdefer if (proxy_endpoint) |*proxy_value| proxy_value.deinit();

            const proxy_auth_header = try self.client.prepareProxyAuthHeader(
                owned_request.?,
                proxy_config,
                proxy_endpoint != null,
            );
            defer if (proxy_auth_header) |value| self.allocator.free(value);

            owned_request = try self.applyProxyAuthToOwnedRequest(
                owned_request.?,
                proxy_config,
                proxy_endpoint != null,
            );

            self.submitRedirectRequest(owned_request.?, proxy_endpoint, proxy_auth_header) catch |err| {
                self.cleanupOwnedRequest(owned_request);
                owned_request = null;
                return err;
            };
            proxy_endpoint = null;
        }
    }

    /// Waits for the current response future using the provided deadline.
    fn waitForCurrentResponse(self: *RequestState, deadline: ?i128) ResponseFuture.WaitError!types.Response {
        if (deadline) |limit| {
            const remaining = remainingTimeout(limit) orelse {
                self.discardLease();
                return error.Timeout;
            };
            const response = self.future.timedWait(remaining) catch |err| {
                self.discardLease();
                return mapConnectionWaitError(err);
            };
            return response;
        }

        const response = self.future.wait() catch |err| {
            self.discardLease();
            return mapConnectionWaitError(err);
        };
        return response;
    }

    /// Computes remaining nanoseconds until the deadline, or null if expired.
    fn remainingTimeout(deadline: i128) ?u64 {
        const now = std.time.nanoTimestamp();
        if (now >= deadline) {
            return null;
        }
        return @as(u64, @intCast(deadline - now));
    }

    /// Cancels the future and closes the connection.
    fn cancel(self: *RequestState) bool {
        self.cancel_token.cancel();

        self.mutex.lock();
        const canceled = self.future.cancel();
        self.mutex.unlock();

        self.discardLease();
        return canceled;
    }

    /// Releases request resources.
    fn deinit(self: *RequestState) void {
        if (!self.completed) {
            _ = self.cancel();
        }
        if (self.owned_request) |owned| {
            owned.deinit();
            self.allocator.destroy(owned);
            self.owned_request = null;
        }
        self.allocator.destroy(self);
    }

    /// Finalizes the response and wires body cleanup if needed.
    fn finalizeResponse(
        self: *RequestState,
        request_uri: types.Uri,
        response_value: types.Response,
    ) ResponseFuture.WaitError!types.Response {
        var response = response_value;
        try self.storeCookies(request_uri, &response);
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

    /// Stores cookies from the response when a jar is configured.
    fn storeCookies(self: *RequestState, uri: types.Uri, response: *types.Response) ResponseFuture.WaitError!void {
        const jar = self.client.options.cookie_jar orelse return;
        const now = cookies.Timestamp.now();
        jar.storeFromResponse(uri, &response.headers, now) catch |err| {
            if (response.body) |body_reader| {
                body_reader.close();
                response.body = null;
            }
            response.deinit();
            self.discardLease();
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
            };
        };
    }

    /// Applies cookies to an owned request, replacing it if needed.
    fn applyCookiesToOwnedRequest(
        self: *RequestState,
        request_value: *types.Request,
    ) ResponseFuture.WaitError!*types.Request {
        const jar = self.client.options.cookie_jar orelse return request_value;
        const now = cookies.Timestamp.now();
        const header_value = jar.buildCookieHeader(self.allocator, request_value.uri, now) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
        };

        if (header_value == null) {
            return request_value;
        }
        defer self.allocator.free(header_value.?);

        const updated = try buildRequestWithCookies(self.allocator, request_value, header_value.?);
        request_value.deinit();
        self.allocator.destroy(request_value);
        return updated;
    }

    /// Applies proxy authorization to an owned request when configured.
    fn applyProxyAuthToOwnedRequest(
        self: *RequestState,
        request_value: *types.Request,
        proxy_config: ProxyConfig,
        proxy_enabled: bool,
    ) ResponseFuture.WaitError!*types.Request {
        if (!proxy_enabled) {
            return request_value;
        }

        if (request_value.uri.scheme == .https) {
            if (request_value.headers.get("Proxy-Authorization") == null) {
                return request_value;
            }
            const updated = try buildRequestWithExtras(
                self.allocator,
                request_value,
                null,
                null,
                true,
            );
            request_value.deinit();
            self.allocator.destroy(request_value);
            return updated;
        }

        if (proxy_config.mode != .manual) {
            return request_value;
        }
        const manual = proxy_config.manual orelse return error.InvalidConfig;
        const auth = manual.auth orelse return request_value;
        if (request_value.headers.get("Proxy-Authorization") != null) {
            return request_value;
        }

        const header_value = self.client.buildProxyAuthorizationHeader(self.allocator, auth) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidConfig,
        };
        defer self.allocator.free(header_value);

        request_value.headers.append("Proxy-Authorization", header_value) catch {
            return error.OutOfMemory;
        };
        return request_value;
    }

    /// Cleans up a redirect response before following the next hop.
    fn abandonRedirectResponse(self: *RequestState, response: *types.Response) void {
        if (response.body) |body_reader| {
            body_reader.close();
            response.body = null;
            response.deinit();
            self.discardLease();
            return;
        }
        response.deinit();
        self.releaseLease();
    }

    /// Releases an owned redirect request.
    fn cleanupOwnedRequest(self: *RequestState, owned: ?*types.Request) void {
        if (owned) |request_value| {
            request_value.deinit();
            self.allocator.destroy(request_value);
        }
    }

    /// Adds a redirect key to the visited list for loop detection.
    fn appendRedirectKey(
        self: *RequestState,
        visited: *std.ArrayList([]u8),
        uri: types.Uri,
    ) Error!void {
        const key = redirects.uriKey(self.allocator, uri) catch {
            return error.OutOfMemory;
        };

        if (isRedirectVisited(visited, key)) {
            self.allocator.free(key);
            return error.RedirectLoop;
        }

        visited.append(self.allocator, key) catch |err| {
            self.allocator.free(key);
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
            };
        };
    }

    /// Returns true when the redirect key has been seen already.
    fn isRedirectVisited(visited: *const std.ArrayList([]u8), key: []const u8) bool {
        for (visited.items) |entry| {
            if (std.mem.eql(u8, entry, key)) {
                return true;
            }
        }
        return false;
    }

    /// Submits a follow-up request for a redirect hop.
    fn submitRedirectRequest(
        self: *RequestState,
        request_value: *const types.Request,
        proxy_endpoint: ?proxy_env.ProxyEndpoint,
        proxy_auth_header: ?[]const u8,
    ) Error!void {
        var proxy_value = proxy_endpoint;
        defer if (proxy_value) |*value| value.deinit();

        const origin = try self.client.buildOriginKey(request_value, proxy_value, proxy_auth_header);
        const connection_options = self.client.buildConnectionOptions();
        var lease = try self.pool.checkout(origin, connection_options);

        self.mutex.lock();
        if (self.cancel_token.isCanceled()) {
            self.mutex.unlock();
            self.pool.discard(lease);
            return error.Canceled;
        }

        self.future = connection_h1.ResponseFuture.init();
        self.lease = lease;

        lease.connection.submit(request_value, self.future.completion()) catch |err| {
            self.lease = null;
            self.mutex.unlock();
            self.pool.discard(lease);
            return mapSubmitError(err);
        };

        self.mutex.unlock();
    }

    /// Releases the lease back to the pool, if present.
    fn releaseLease(self: *RequestState) void {
        var lease: ?Lease = null;
        self.mutex.lock();
        if (self.lease) |current| {
            lease = current;
            self.lease = null;
        }
        self.mutex.unlock();

        if (lease) |current| {
            self.pool.release(current);
        }
    }

    /// Discards the lease and closes the connection, if present.
    fn discardLease(self: *RequestState) void {
        var lease: ?Lease = null;
        self.mutex.lock();
        if (self.lease) |current| {
            lease = current;
            self.lease = null;
        }
        self.mutex.unlock();

        if (lease) |current| {
            self.pool.discard(current);
        }
    }

    /// Takes ownership of the lease, if present.
    fn takeLease(self: *RequestState) ?Lease {
        var lease: ?Lease = null;
        self.mutex.lock();
        if (self.lease) |current| {
            lease = current;
            self.lease = null;
        }
        self.mutex.unlock();
        return lease;
    }
};

/// Response body wrapper that returns the connection on close.
const ResponseBody = struct {
    /// Allocator used for wrapper cleanup.
    allocator: std.mem.Allocator,
    /// Pool used to return the connection.
    pool: *ConnectionPool,
    /// Lease to return when the body is closed.
    lease: Lease,
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

/// Maps connection submit errors into client errors.
fn mapSubmitError(err: connection_h1.SubmitError) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Closed,
        error.NotStarted,
        => error.Transport,
    };
}

/// Maps connection wait errors into client-visible errors.
fn mapConnectionWaitError(err: connection_h1.ResponseFuture.WaitError) ResponseFuture.WaitError {
    return switch (err) {
        error.Timeout => error.Timeout,
        error.InvalidUri => error.InvalidUri,
        error.Transport => error.Transport,
        error.ProxyConnectFailed => error.ProxyConnectFailed,
        error.Protocol => error.Protocol,
        error.LimitExceeded => error.LimitExceeded,
        error.Canceled => error.Canceled,
        error.OutOfMemory => error.OutOfMemory,
    };
}

/// HTTP client entry point.
pub const Client = struct {
    /// Allocator used for client-owned allocations.
    allocator: std.mem.Allocator,
    /// Configuration options for the client.
    options: Options,
    /// Connection pool keyed by origin.
    pool: ConnectionPool,

    /// Typed client errors.
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
        return self.requestWithOptions(request_value, RequestOptions.default());
    }

    /// Submits a request with per-request overrides.
    pub fn requestWithOptions(
        self: *Client,
        request_value: *const types.Request,
        request_options: RequestOptions,
    ) Error!RequestHandle {
        const follow_redirects = self.options.redirect_policy.mode == .follow;
        return self.requestInternal(request_value, follow_redirects, request_options);
    }

    /// Submits a request with explicit redirect handling behavior.
    fn requestInternal(
        self: *Client,
        request_value: *const types.Request,
        follow_redirects: bool,
        request_options: RequestOptions,
    ) Error!RequestHandle {
        try self.validateOptions();
        const proxy_config = request_options.proxy orelse self.options.proxy;
        try self.validateProxyConfig(proxy_config);

        var proxy_endpoint = try self.resolveProxyConfig(request_value.uri, proxy_config);
        errdefer if (proxy_endpoint) |*proxy_value| proxy_value.deinit();
        const proxy_enabled = proxy_endpoint != null;

        const proxy_auth_header = try self.prepareProxyAuthHeader(request_value, proxy_config, proxy_enabled);
        defer if (proxy_auth_header) |value| self.allocator.free(value);

        const prepared = try self.prepareRequest(request_value, proxy_config, proxy_enabled);
        var cleanup_prepared = true;
        errdefer if (cleanup_prepared) self.cleanupPreparedRequest(prepared);

        const origin = try self.buildOriginKey(prepared.request, proxy_endpoint, proxy_auth_header);
        const connection_options = self.buildConnectionOptions();
        var lease = try self.pool.checkout(origin, connection_options);
        if (proxy_endpoint) |*proxy_value| {
            proxy_value.deinit();
        }
        proxy_endpoint = null;

        var cleanup = true;
        errdefer if (cleanup) self.pool.discard(lease);

        const state = self.allocator.create(RequestState) catch {
            return error.OutOfMemory;
        };
        errdefer self.allocator.destroy(state);
        state.* = RequestState.init(
            self.allocator,
            self,
            prepared.request,
            prepared.owned,
            follow_redirects,
            request_options,
            lease,
        );

        lease.connection.submit(prepared.request, state.future.completion()) catch |err| {
            return mapSubmitError(err);
        };

        cleanup = false;
        cleanup_prepared = false;
        return .{ .state = state };
    }

    /// Prepares a request for submission, applying cookies and proxy auth when needed.
    fn prepareRequest(
        self: *Client,
        request_value: *const types.Request,
        proxy_config: ProxyConfig,
        proxy_enabled: bool,
    ) Error!PreparedRequest {
        var cookie_header: ?[]u8 = null;
        if (self.options.cookie_jar) |jar| {
            const now = cookies.Timestamp.now();
            cookie_header = try jar.buildCookieHeader(self.allocator, request_value.uri, now);
        }
        defer if (cookie_header) |value| self.allocator.free(value);

        const wants_proxy_header = proxy_enabled and request_value.uri.scheme == .http;
        const needs_proxy_header = wants_proxy_header and
            proxy_config.mode == .manual and
            proxy_config.manual != null and
            proxy_config.manual.?.auth != null and
            request_value.headers.get("Proxy-Authorization") == null;

        var proxy_header: ?[]u8 = null;
        if (needs_proxy_header) {
            proxy_header = try self.buildProxyAuthorizationHeader(self.allocator, proxy_config.manual.?.auth.?);
        }
        defer if (proxy_header) |value| self.allocator.free(value);

        const strip_proxy_authorization = proxy_enabled and
            request_value.uri.scheme == .https and
            request_value.headers.get("Proxy-Authorization") != null;

        if (cookie_header == null and proxy_header == null and !strip_proxy_authorization) {
            return .{ .request = request_value, .owned = null };
        }

        const owned = try buildRequestWithExtras(
            self.allocator,
            request_value,
            if (cookie_header) |value| value else null,
            if (proxy_header) |value| value else null,
            strip_proxy_authorization,
        );
        return .{ .request = owned, .owned = owned };
    }

    /// Releases any owned request created during preparation.
    fn cleanupPreparedRequest(self: *Client, prepared: PreparedRequest) void {
        if (prepared.owned) |owned| {
            owned.deinit();
            self.allocator.destroy(owned);
        }
    }

    /// Releases resources owned by the client.
    pub fn deinit(self: *Client) void {
        self.pool.deinit();
    }

    /// Builds a pool origin key from the request URI and optional proxy endpoint.
    fn buildOriginKey(
        self: *Client,
        request_value: *const types.Request,
        proxy_endpoint: ?proxy_env.ProxyEndpoint,
        proxy_auth_header: ?[]const u8,
    ) Error!OriginKey {
        if (request_value.uri.host.len == 0) {
            return error.InvalidUri;
        }

        if (proxy_endpoint) |proxy_value| {
            if (proxy_value.scheme != .http) {
                return error.InvalidConfig;
            }
            if (request_value.uri.scheme == .http) {
                return .{
                    .scheme = proxy_value.scheme,
                    .host = proxy_value.host,
                    .port = proxy_value.port,
                    .tls_id = self.options.tls.identity(),
                    .negotiated_protocol = .http_1_1,
                    .target_mode = .absolute_form,
                    .tunnel = null,
                    .proxy_authorization = null,
                };
            }

            if (request_value.uri.scheme != .https) {
                return error.InvalidUri;
            }
            const tunnel_host = request_value.uri.host;
            if (tunnel_host.len == 0) {
                return error.InvalidUri;
            }
            return .{
                .scheme = proxy_value.scheme,
                    .host = proxy_value.host,
                    .port = proxy_value.port,
                    .tls_id = self.options.tls.identity(),
                    .negotiated_protocol = .http_1_1,
                    .target_mode = .origin_form,
                    .tunnel = .{
                        .host = tunnel_host,
                    .port = request_value.uri.effectivePort(),
                },
                .proxy_authorization = proxy_auth_header,
            };
        }

        if (request_value.uri.scheme != .http) {
            return error.InvalidUri;
        }
        const port = request_value.uri.effectivePort();
        return .{
            .scheme = request_value.uri.scheme,
            .host = request_value.uri.host,
            .port = port,
            .tls_id = self.options.tls.identity(),
            .negotiated_protocol = .http_1_1,
            .target_mode = .origin_form,
            .tunnel = null,
            .proxy_authorization = null,
        };
    }

    /// Resolves the proxy endpoint for a request URI.
    fn resolveProxy(
        self: *Client,
        uri: types.Uri,
        request_options: RequestOptions,
    ) Error!?proxy_env.ProxyEndpoint {
        const config = request_options.proxy orelse self.options.proxy;
        return self.resolveProxyConfig(uri, config);
    }

    /// Resolves the proxy endpoint for a URI and proxy config.
    fn resolveProxyConfig(
        self: *Client,
        uri: types.Uri,
        config: ProxyConfig,
    ) Error!?proxy_env.ProxyEndpoint {
        var resolved = switch (config.mode) {
            .direct => null,
            .manual => blk: {
                const manual = config.manual orelse return error.InvalidConfig;
                break :blk try buildManualProxyEndpoint(self.allocator, manual);
            },
            .system => blk: {
                var env = proxy_env.loadEnv(self.allocator) catch |err| {
                    return mapEnvError(err);
                };
                defer env.deinit();
                const resolved = proxy_env.selectProxyFromEnv(
                    self.allocator,
                    uri,
                    env.http_proxy,
                    env.https_proxy,
                    env.no_proxy,
                ) catch |err| {
                    return mapResolveError(err);
                };
                break :blk resolved;
            },
        };
        if (resolved) |*proxy_value| {
            if (proxy_value.scheme != .http) {
                proxy_value.deinit();
                return error.InvalidConfig;
            }
        }
        return resolved;
    }

    /// Builds an owned proxy endpoint from manual configuration.
    fn buildManualProxyEndpoint(
        allocator: std.mem.Allocator,
        manual: Proxy,
    ) Error!proxy_env.ProxyEndpoint {
        if (manual.host.len == 0) {
            return error.InvalidConfig;
        }
        if (manual.scheme != .http) {
            return error.InvalidConfig;
        }
        const host_copy = lowerCaseCopy(allocator, manual.host) catch {
            return error.OutOfMemory;
        };
        return .{
            .allocator = allocator,
            .scheme = manual.scheme,
            .host = host_copy,
            .port = manual.port,
        };
    }

    /// Prepares a Proxy-Authorization header value for CONNECT if needed.
    fn prepareProxyAuthHeader(
        self: *Client,
        request_value: *const types.Request,
        proxy_config: ProxyConfig,
        proxy_enabled: bool,
    ) Error!?[]u8 {
        if (!proxy_enabled) {
            return null;
        }
        if (request_value.uri.scheme != .https) {
            return null;
        }
        if (request_value.headers.get("Proxy-Authorization")) |value| {
            return self.allocator.dupe(u8, value) catch {
                return error.OutOfMemory;
            };
        }
        if (proxy_config.mode != .manual) {
            return null;
        }
        const manual = proxy_config.manual orelse return error.InvalidConfig;
        const auth = manual.auth orelse return null;
        return try self.buildProxyAuthorizationHeader(self.allocator, auth);
    }

    /// Builds a Proxy-Authorization header value for the provided auth config.
    fn buildProxyAuthorizationHeader(
        self: *Client,
        allocator: std.mem.Allocator,
        auth: ProxyAuth,
    ) Error![]u8 {
        _ = self;
        return switch (auth) {
            .basic => |basic| buildBasicProxyHeader(allocator, basic),
        };
    }

    /// Builds a Basic proxy authentication header value.
    fn buildBasicProxyHeader(
        allocator: std.mem.Allocator,
        basic: ProxyBasicAuth,
    ) Error![]u8 {
        const raw = std.fmt.allocPrint(allocator, "{s}:{s}", .{ basic.username, basic.password }) catch {
            return error.OutOfMemory;
        };
        defer allocator.free(raw);

        const encoded_len = std.base64.standard.Encoder.calcSize(raw.len);
        const encoded = allocator.alloc(u8, encoded_len) catch {
            return error.OutOfMemory;
        };
        defer allocator.free(encoded);

        _ = std.base64.standard.Encoder.encode(encoded, raw);
        return std.fmt.allocPrint(allocator, "Basic {s}", .{encoded}) catch {
            return error.OutOfMemory;
        };
    }

    /// Returns a lowercased copy of the provided host value.
    fn lowerCaseCopy(allocator: std.mem.Allocator, value: []const u8) std.mem.Allocator.Error![]u8 {
        const copy = try allocator.dupe(u8, value);
        for (copy) |*byte| {
            byte.* = std.ascii.toLower(byte.*);
        }
        return copy;
    }

    /// Maps environment resolution errors into client errors.
    fn mapEnvError(err: proxy_env.EnvError) Error {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidConfig,
        };
    }

    /// Maps proxy parsing errors into client errors.
    fn mapResolveError(err: proxy_env.ResolveError) Error {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidProxy,
            error.UnsupportedScheme,
            error.InvalidNoProxyEntry,
            => error.InvalidConfig,
        };
    }

    /// Maps client options into connection options.
    fn buildConnectionOptions(self: *Client) connection_h1.Options {
        var options = connection_h1.Options.default();
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

    /// Validates client options before issuing requests.
    fn validateOptions(self: *const Client) Error!void {
        if (self.options.pool.max_connections.toInt() == 0) {
            return error.InvalidConfig;
        }
        try self.validateTlsConfig(self.options.tls);
        try self.validateProxyConfig(self.options.proxy);
    }

    /// Validates shared TLS configuration values.
    fn validateTlsConfig(_: *const Client, config: TlsConfig) Error!void {
        if (config.root_store_mode == .explicit and config.explicit_roots_path == null) {
            return error.InvalidConfig;
        }
        if ((config.certificate_chain_path == null) != (config.private_key_path == null)) {
            return error.InvalidConfig;
        }
        if (config.alpn_protocols.len == 0) {
            return error.InvalidConfig;
        }
    }

    /// Validates proxy configuration values.
    fn validateProxyConfig(_: *const Client, config: ProxyConfig) Error!void {
        if (config.mode != .manual) {
            return;
        }
        const manual = config.manual orelse return error.InvalidConfig;
        if (manual.host.len == 0) {
            return error.InvalidConfig;
        }
        if (manual.scheme != .http) {
            return error.InvalidConfig;
        }
    }
};

/// Maps the shared target-mode type into the HTTP/1.1 encoder mode.
fn mapConnectionTargetMode(mode: types.ConnectionTargetMode) request_encoder.RequestTargetMode {
    return switch (mode) {
        .origin_form => .origin_form,
        .absolute_form => .absolute_form,
    };
}

/// Builds a request copy with optional Cookie and Proxy-Authorization headers.
fn buildRequestWithExtras(
    allocator: std.mem.Allocator,
    request_value: *const types.Request,
    cookie_value: ?[]const u8,
    proxy_auth_value: ?[]const u8,
    strip_proxy_authorization: bool,
) Error!*types.Request {
    const request_copy = allocator.create(types.Request) catch {
        return error.OutOfMemory;
    };
    errdefer allocator.destroy(request_copy);

    request_copy.* = types.Request.init(allocator, request_value.method, request_value.uri);
    errdefer request_copy.deinit();

    request_copy.version = request_value.version;
    request_copy.body = request_value.body;

    var existing = std.ArrayListUnmanaged(u8){};
    defer existing.deinit(allocator);
    var add_proxy_auth = proxy_auth_value != null and !strip_proxy_authorization;

    var iter = request_value.headers.iterator();
    while (iter.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "cookie")) {
            if (existing.items.len > 0) {
                try existing.appendSlice(allocator, "; ");
            }
            try existing.appendSlice(allocator, header.value);
            continue;
        }
        if (std.ascii.eqlIgnoreCase(header.name, "proxy-authorization")) {
            add_proxy_auth = false;
            if (strip_proxy_authorization) {
                continue;
            }
        }
        try request_copy.headers.append(header.name, header.value);
    }

    if (cookie_value) |value| {
        var combined = std.ArrayListUnmanaged(u8){};
        defer combined.deinit(allocator);

        if (existing.items.len > 0) {
            try combined.appendSlice(allocator, existing.items);
        }
        if (existing.items.len > 0 and value.len > 0) {
            try combined.appendSlice(allocator, "; ");
        }
        if (value.len > 0) {
            try combined.appendSlice(allocator, value);
        }

        if (combined.items.len > 0) {
            try request_copy.headers.append("Cookie", combined.items);
        }
    } else if (existing.items.len > 0) {
        try request_copy.headers.append("Cookie", existing.items);
    }

    if (add_proxy_auth) {
        const auth_value = proxy_auth_value.?;
        try request_copy.headers.append("Proxy-Authorization", auth_value);
    }

    return request_copy;
}

/// Builds a request copy with an updated Cookie header.
fn buildRequestWithCookies(
    allocator: std.mem.Allocator,
    request_value: *const types.Request,
    cookie_value: []const u8,
) Error!*types.Request {
    return buildRequestWithExtras(allocator, request_value, cookie_value, null, false);
}

/// Returns true when a header should be omitted on redirect follow-ups.
fn shouldSkipRedirectHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding");
}

/// Returns true when a header should be omitted for cross-origin redirects.
fn shouldSkipCrossOriginHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "authorization") or
        std.ascii.eqlIgnoreCase(name, "proxy-authorization") or
        std.ascii.eqlIgnoreCase(name, "cookie");
}

/// Copies request headers for a redirect follow-up.
fn copyRedirectHeaders(
    source: *const types.Headers,
    dest: *types.Headers,
    same_origin: bool,
) Error!void {
    var iter = source.iterator();
    while (iter.next()) |header| {
        if (shouldSkipRedirectHeader(header.name)) {
            continue;
        }
        if (!same_origin and shouldSkipCrossOriginHeader(header.name)) {
            continue;
        }
        try dest.append(header.name, header.value);
    }
}

/// Appends a Host header derived from the URI.
fn appendHostHeader(headers: *types.Headers, uri: types.Uri) Error!void {
    if (uri.port) |port| {
        const value = std.fmt.allocPrint(
            headers.allocator,
            "{s}:{d}",
            .{ uri.host, port.toInt() },
        ) catch return error.OutOfMemory;
        defer headers.allocator.free(value);
        try headers.append("Host", value);
        return;
    }
    try headers.append("Host", uri.host);
}

/// Returns true when two URIs share the same origin.
fn isSameOrigin(a: types.Uri, b: types.Uri) bool {
    return a.scheme == b.scheme and
        a.effectivePort().toInt() == b.effectivePort().toInt() and
        std.ascii.eqlIgnoreCase(a.host, b.host);
}

/// Builds a new request for a redirect hop.
fn buildRedirectRequest(
    allocator: std.mem.Allocator,
    method: types.Method,
    uri: types.Uri,
    version: types.Version,
    base_headers: *const types.Headers,
    same_origin: bool,
) Error!*types.Request {
    const request_value = allocator.create(types.Request) catch {
        return error.OutOfMemory;
    };
    errdefer allocator.destroy(request_value);

    request_value.* = types.Request.init(allocator, method, uri);
    errdefer request_value.deinit();

    request_value.version = version;
    request_value.body = null;

    try copyRedirectHeaders(base_headers, &request_value.headers, same_origin);
    try appendHostHeader(&request_value.headers, uri);

    return request_value;
}

/// Maps redirect helper errors into client errors.
fn mapRedirectError(err: redirects.RedirectError) Error {
    return switch (err) {
        error.MissingLocation => error.RedirectMissingLocation,
        error.InvalidLocation => error.RedirectInvalidLocation,
        error.UnsupportedScheme => error.RedirectUnsupportedScheme,
        error.OutOfMemory => error.OutOfMemory,
    };
}

/// Body reader state for tests requiring a one-shot payload.
const TestBodyState = struct {
    /// Payload bytes.
    data: []const u8,
    /// Read offset into the payload.
    offset: usize,

    /// Reads from the payload buffer.
    fn read(ctx: ?*anyopaque, dest: []u8) anyerror!usize {
        const self: *TestBodyState = @ptrCast(@alignCast(ctx.?));
        if (self.offset >= self.data.len) {
            return 0;
        }
        const remaining = self.data.len - self.offset;
        const to_copy = @min(dest.len, remaining);
        std.mem.copyForwards(u8, dest[0..to_copy], self.data[self.offset .. self.offset + to_copy]);
        self.offset += to_copy;
        return to_copy;
    }

    /// Closes the body reader.
    fn close(ctx: ?*anyopaque) void {
        _ = ctx;
    }
};

test "client option defaults" {
    const options = Options.default();

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
    try std.testing.expect(options.pool.idle_timeout != null);
    try std.testing.expectEqual(
        @as(u64, 30 * std.time.ns_per_s),
        options.pool.idle_timeout.?.toNanos(),
    );

    try std.testing.expectEqual(RedirectMode.follow, options.redirect_policy.mode);
    try std.testing.expectEqual(@as(u8, 10), options.redirect_policy.max_hops);

    try std.testing.expectEqual(ProxyMode.system, options.proxy.mode);
    try std.testing.expect(options.proxy.manual == null);

    try std.testing.expect(options.cookie_jar == null);
    try std.testing.expectEqual(TlsVerifyMode.verify, options.tls.verify);
}

test "request options override proxy selection" {
    var options = Options.default();
    options.proxy = .{
        .mode = .direct,
        .manual = null,
    };

    var client = Client.init(std.testing.allocator, options);
    defer client.deinit();

    const uri = types.Uri.init(.http, "example.com", types.Port.init(80), "/", null, null);
    const request_options = RequestOptions{
        .proxy = .{
            .mode = .manual,
            .manual = .{
                .scheme = .http,
                .host = "proxy.local",
                .port = types.Port.init(8080),
                .auth = null,
            },
        },
    };

    var resolved = try client.resolveProxy(uri, request_options);
    defer if (resolved) |*value| value.deinit();

    try std.testing.expect(resolved != null);
    try std.testing.expectEqual(types.Scheme.http, resolved.?.scheme);
    try std.testing.expectEqualStrings("proxy.local", resolved.?.host);
    try std.testing.expectEqual(@as(u16, 8080), resolved.?.port.toInt());
}

test "request options can disable manual proxy" {
    var options = Options.default();
    options.proxy = .{
        .mode = .manual,
        .manual = .{
            .scheme = .http,
            .host = "proxy.local",
            .port = types.Port.init(8080),
            .auth = null,
        },
    };

    var client = Client.init(std.testing.allocator, options);
    defer client.deinit();

    const uri = types.Uri.init(.http, "example.com", types.Port.init(80), "/", null, null);
    const request_options = RequestOptions{
        .proxy = .{
            .mode = .direct,
            .manual = null,
        },
    };

    const resolved = try client.resolveProxy(uri, request_options);
    if (resolved) |*value| {
        value.deinit();
    }

    try std.testing.expect(resolved == null);
}

test "client rejects zero max connections" {
    var options = Options.default();
    options.pool.max_connections = ConnectionCount.init(0);

    var client = Client.init(std.testing.allocator, options);
    defer client.deinit();

    const uri = types.Uri.init(.http, "127.0.0.1", types.Port.init(80), "/", null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();
    try request.headers.append("Host", "127.0.0.1");

    try std.testing.expectError(error.InvalidConfig, client.request(&request));
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

    var client = Client.init(std.testing.allocator, Options.default());
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

test "client sends absolute-form request through proxy" {
    const test_server = @import("http1/test_server.zig");

    const expected_request =
        "GET http://example.com/resource HTTP/1.1\r\n" ++
        "host: example.com\r\n" ++
        "proxy-authorization: Basic dXNlcjpwYXNz";

    const scenarios = [_]test_server.Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{
                        .response = .{
                            .status = .ok,
                            .reason = "OK",
                            .body = "via-proxy",
                        },
                    },
                    .expect_request_contains = expected_request,
                },
            },
        },
    };

    var server = try test_server.TestServer.init(&scenarios, test_server.Options.default());
    defer server.deinit();
    try server.start();

    var options = Options.default();
    options.proxy = .{
        .mode = .manual,
        .manual = .{
            .scheme = .http,
            .host = "127.0.0.1",
            .port = types.Port.init(server.port()),
            .auth = .{
                .basic = .{
                    .username = "user",
                    .password = "pass",
                },
            },
        },
    };

    var client = Client.init(std.testing.allocator, options);
    defer client.deinit();

    const uri = types.Uri.init(.http, "example.com", null, "/resource", null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();
    try request.headers.append("Host", "example.com");

    var handle = try client.request(&request);
    defer handle.deinit();

    var response = try handle.wait();
    defer response.deinit();
    defer if (response.body) |body| body.close();

    var buffer: [16]u8 = undefined;
    const read_len = try response.body.?.read(&buffer);
    try std.testing.expectEqualStrings("via-proxy", buffer[0..read_len]);
}

test "client establishes CONNECT tunnel through proxy" {
    const test_server = @import("http1/test_server.zig");
    const test_proxy = @import("proxy/test_proxy.zig");

    const scenarios = [_]test_server.Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{
                        .response = .{
                            .status = .ok,
                            .reason = "OK",
                            .body = "tunnel",
                        },
                    },
                },
            },
        },
    };

    var server = try test_server.TestServer.init(&scenarios, test_server.Options.default());
    defer server.deinit();
    try server.start();

    var proxy_options = test_proxy.Options.default();
    proxy_options.expect_connect_contains = "Proxy-Authorization: Basic dXNlcjpwYXNz";

    var proxy = try test_proxy.TestProxy.init(
        std.testing.allocator,
        .{ .tunnel = {} },
        proxy_options,
    );
    defer proxy.deinit();
    try proxy.start();

    var options = Options.default();
    options.proxy = .{
        .mode = .manual,
        .manual = .{
            .scheme = .http,
            .host = "127.0.0.1",
            .port = types.Port.init(proxy.port()),
            .auth = .{
                .basic = .{
                    .username = "user",
                    .password = "pass",
                },
            },
        },
    };

    var client = Client.init(std.testing.allocator, options);
    defer client.deinit();

    const uri = types.Uri.init(.https, "127.0.0.1", types.Port.init(server.port()), "/", null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();

    var host_buffer: [32]u8 = undefined;
    const host_value = try std.fmt.bufPrint(&host_buffer, "127.0.0.1:{d}", .{server.port()});
    try request.headers.append("Host", host_value);

    var handle = try client.request(&request);
    defer handle.deinit();

    var response = try handle.wait();
    defer response.deinit();
    defer if (response.body) |body| body.close();

    var buffer: [8]u8 = undefined;
    const read_len = try response.body.?.read(&buffer);
    try std.testing.expectEqualStrings("tunnel", buffer[0..read_len]);
}

test "client surfaces CONNECT failure" {
    const test_proxy = @import("proxy/test_proxy.zig");

    var proxy = try test_proxy.TestProxy.init(
        std.testing.allocator,
        .{ .reject = .{ .status = 502, .reason = "Bad Gateway" } },
        test_proxy.Options.default(),
    );
    defer proxy.deinit();
    try proxy.start();

    var options = Options.default();
    options.proxy = .{
        .mode = .manual,
        .manual = .{
            .scheme = .http,
            .host = "127.0.0.1",
            .port = types.Port.init(proxy.port()),
            .auth = null,
        },
    };

    var client = Client.init(std.testing.allocator, options);
    defer client.deinit();

    const uri = types.Uri.init(.https, "example.com", types.Port.init(443), "/", null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();
    try request.headers.append("Host", "example.com");

    var handle = try client.request(&request);
    defer handle.deinit();

    try std.testing.expectError(error.ProxyConnectFailed, handle.wait());
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

    var options = Options.default();
    options.pool.max_connections = ConnectionCount.init(1);
    options.pool.idle_timeout = Duration.fromSeconds(2);
    options.timeouts.read = Duration.fromMillis(500);
    options.timeouts.request = Duration.fromSeconds(2);

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

test "client expires idle connection after timeout" {
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
                            .body = "reuse",
                        },
                    },
                    .close_after = true,
                },
            },
        },
        .{
            .steps = &.{
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

    var options = Options.default();
    options.pool.max_connections = ConnectionCount.init(1);
    options.pool.idle_timeout = Duration.fromMillis(20);
    options.timeouts.read = Duration.fromMillis(500);
    options.timeouts.request = Duration.fromSeconds(2);

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

    std.Thread.sleep(50 * std.time.ns_per_ms);

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

test "client reads chunked response body" {
    const test_server = @import("http1/test_server.zig");

    const raw_response =
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "4\r\nWiki\r\n" ++
        "5\r\npedia\r\n" ++
        "0\r\n\r\n";

    const scenarios = [_]test_server.Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{ .raw = raw_response },
                },
            },
        },
    };

    var server = try test_server.TestServer.init(&scenarios, test_server.Options.default());
    defer server.deinit();
    try server.start();

    var client = Client.init(std.testing.allocator, Options.default());
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

    var collected = std.ArrayList(u8).init(std.testing.allocator);
    defer collected.deinit();

    var buffer: [16]u8 = undefined;
    while (true) {
        const read_len = try response.body.?.read(&buffer);
        if (read_len == 0) {
            break;
        }
        try collected.appendSlice(buffer[0..read_len]);
    }

    try std.testing.expectEqualStrings("Wikipedia", collected.items);
}

test "client streams large response body" {
    const test_server = @import("http1/test_server.zig");

    const body_len = 128 * 1024;
    const expected = try std.testing.allocator.alloc(u8, body_len);
    defer std.testing.allocator.free(expected);
    for (expected, 0..) |*byte, index| {
        byte.* = @intCast(index % 251);
    }

    const scenarios = [_]test_server.Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{
                        .response = .{
                            .status = .ok,
                            .reason = "OK",
                            .body = expected,
                        },
                    },
                },
            },
        },
    };

    var server = try test_server.TestServer.init(&scenarios, test_server.Options.default());
    defer server.deinit();
    try server.start();

    var client = Client.init(std.testing.allocator, Options.default());
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

    var offset: usize = 0;
    var buffer: [4096]u8 = undefined;
    while (true) {
        const read_len = try response.body.?.read(&buffer);
        if (read_len == 0) {
            break;
        }
        try std.testing.expectEqualSlices(u8, expected[offset .. offset + read_len], buffer[0..read_len]);
        offset += read_len;
    }

    try std.testing.expectEqual(body_len, offset);
}

test "client rejects malformed response" {
    const test_server = @import("http1/test_server.zig");

    const raw_response = "HTTP/1.1 200 OK\n\n";
    const scenarios = [_]test_server.Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{ .raw = raw_response },
                },
            },
        },
    };

    var server = try test_server.TestServer.init(&scenarios, test_server.Options.default());
    defer server.deinit();
    try server.start();

    var client = Client.init(std.testing.allocator, Options.default());
    defer client.deinit();

    const uri = types.Uri.init(.http, "127.0.0.1", types.Port.init(server.port()), "/", null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();
    try request.headers.append("Host", "127.0.0.1");

    var handle = try client.request(&request);
    defer handle.deinit();

    try std.testing.expectError(error.Protocol, handle.wait());
}

test "client times out waiting for response" {
    const test_server = @import("http1/test_server.zig");

    const scenarios = [_]test_server.Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{
                        .response = .{
                            .status = .ok,
                            .reason = "OK",
                            .body = "late",
                        },
                    },
                    .delay_before_ns = 100 * std.time.ns_per_ms,
                },
            },
        },
    };

    var server = try test_server.TestServer.init(&scenarios, test_server.Options.default());
    defer server.deinit();
    try server.start();

    var options = Options.default();
    options.timeouts.read = Duration.fromMillis(20);
    options.timeouts.request = Duration.fromSeconds(1);

    var client = Client.init(std.testing.allocator, options);
    defer client.deinit();

    const uri = types.Uri.init(.http, "127.0.0.1", types.Port.init(server.port()), "/", null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();
    try request.headers.append("Host", "127.0.0.1");

    var handle = try client.request(&request);
    defer handle.deinit();

    try std.testing.expectError(error.Timeout, handle.wait());
}

test "client can cancel in-flight request" {
    const test_server = @import("http1/test_server.zig");

    const scenarios = [_]test_server.Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{
                        .response = .{
                            .status = .ok,
                            .reason = "OK",
                            .body = "later",
                        },
                    },
                    .delay_before_ns = 200 * std.time.ns_per_ms,
                },
            },
        },
    };

    var server = try test_server.TestServer.init(&scenarios, test_server.Options.default());
    defer server.deinit();
    try server.start();

    var options = Options.default();
    options.timeouts.request = Duration.fromSeconds(1);

    var client = Client.init(std.testing.allocator, options);
    defer client.deinit();

    const uri = types.Uri.init(.http, "127.0.0.1", types.Port.init(server.port()), "/", null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();
    try request.headers.append("Host", "127.0.0.1");

    var handle = try client.request(&request);
    defer handle.deinit();

    try std.testing.expect(handle.cancel());
    try std.testing.expectError(error.Canceled, handle.wait());
}

test "client follows redirect responses" {
    const test_server = @import("http1/test_server.zig");

    const scenarios = [_]test_server.Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{
                        .response = .{
                            .status = .found,
                            .reason = "Found",
                            .headers = &.{
                                .{ .name = "Location", .value = "/next" },
                            },
                        },
                    },
                    .close_after = false,
                },
                .{
                    .payload = .{
                        .response = .{
                            .status = .ok,
                            .reason = "OK",
                            .body = "final",
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

    var client = Client.init(std.testing.allocator, Options.default());
    defer client.deinit();

    const uri = types.Uri.init(.http, "127.0.0.1", types.Port.init(server.port()), "/start", null, null);
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
    try std.testing.expectEqualStrings("final", buffer[0..read_len]);
    const eof = try response.body.?.read(&buffer);
    try std.testing.expectEqual(@as(usize, 0), eof);
}

test "client applies cookies during redirects" {
    const test_server = @import("http1/test_server.zig");

    const scenarios = [_]test_server.Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{
                        .response = .{
                            .status = .found,
                            .reason = "Found",
                            .headers = &.{
                                .{ .name = "Location", .value = "/next" },
                                .{ .name = "Set-Cookie", .value = "session=abc; Path=/" },
                            },
                        },
                    },
                    .close_after = false,
                },
                .{
                    .payload = .{
                        .response = .{
                            .status = .ok,
                            .reason = "OK",
                            .body = "ok",
                        },
                    },
                    .expect_request_contains = "Cookie: session=abc",
                    .close_after = true,
                },
            },
        },
    };

    var server = try test_server.TestServer.init(&scenarios, test_server.Options.default());
    defer server.deinit();
    try server.start();

    var jar = cookies.CookieJar.init(std.testing.allocator, cookies.Options.default());
    defer jar.deinit();

    var options = Options.default();
    options.cookie_jar = &jar;

    var client = Client.init(std.testing.allocator, options);
    defer client.deinit();

    const uri = types.Uri.init(.http, "127.0.0.1", types.Port.init(server.port()), "/start", null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();
    try request.headers.append("Host", "127.0.0.1");

    var handle = try client.request(&request);
    defer handle.deinit();

    var response = try handle.wait();
    defer response.deinit();
    defer if (response.body) |body| body.close();

    try std.testing.expectEqual(types.Status.ok, response.status);

    var buffer: [4]u8 = undefined;
    const read_len = try response.body.?.read(&buffer);
    try std.testing.expectEqualStrings("ok", buffer[0..read_len]);
}

test "client detects redirect loops" {
    const test_server = @import("http1/test_server.zig");

    const scenarios = [_]test_server.Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{
                        .response = .{
                            .status = .found,
                            .reason = "Found",
                            .headers = &.{
                                .{ .name = "Location", .value = "/loop" },
                            },
                        },
                    },
                },
            },
        },
    };

    var server = try test_server.TestServer.init(&scenarios, test_server.Options.default());
    defer server.deinit();
    try server.start();

    var client = Client.init(std.testing.allocator, Options.default());
    defer client.deinit();

    const uri = types.Uri.init(.http, "127.0.0.1", types.Port.init(server.port()), "/loop", null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();
    try request.headers.append("Host", "127.0.0.1");

    var handle = try client.request(&request);
    defer handle.deinit();

    try std.testing.expectError(error.RedirectLoop, handle.wait());
}

test "client enforces redirect hop limit" {
    const test_server = @import("http1/test_server.zig");

    const scenarios = [_]test_server.Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{
                        .response = .{
                            .status = .found,
                            .reason = "Found",
                            .headers = &.{
                                .{ .name = "Location", .value = "/first" },
                            },
                        },
                    },
                    .close_after = false,
                },
                .{
                    .payload = .{
                        .response = .{
                            .status = .found,
                            .reason = "Found",
                            .headers = &.{
                                .{ .name = "Location", .value = "/second" },
                            },
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

    var options = Options.default();
    options.redirect_policy.max_hops = 1;

    var client = Client.init(std.testing.allocator, options);
    defer client.deinit();

    const uri = types.Uri.init(.http, "127.0.0.1", types.Port.init(server.port()), "/start", null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();
    try request.headers.append("Host", "127.0.0.1");

    var handle = try client.request(&request);
    defer handle.deinit();

    try std.testing.expectError(error.RedirectLimitExceeded, handle.wait());
}

test "redirect header carry-over drops sensitive headers on cross-origin" {
    var base = types.Headers.init(std.testing.allocator);
    defer base.deinit();
    try base.append("Authorization", "secret");
    try base.append("Proxy-Authorization", "proxy");
    try base.append("Cookie", "a=b");
    try base.append("Accept", "text/plain");
    try base.append("Host", "example.com");
    try base.append("Content-Length", "5");

    var dest = types.Headers.init(std.testing.allocator);
    defer dest.deinit();

    try copyRedirectHeaders(&base, &dest, false);

    try std.testing.expect(dest.get("Authorization") == null);
    try std.testing.expect(dest.get("Proxy-Authorization") == null);
    try std.testing.expect(dest.get("Cookie") == null);
    try std.testing.expect(dest.get("Host") == null);
    try std.testing.expect(dest.get("Content-Length") == null);
    try std.testing.expectEqualStrings("text/plain", dest.get("Accept").?);
}

test "client rejects redirect when body is not repeatable" {
    const test_server = @import("http1/test_server.zig");

    const scenarios = [_]test_server.Scenario{
        .{
            .steps = &.{
                .{
                    .payload = .{
                        .response = .{
                            .status = .temporary_redirect,
                            .reason = "Temporary Redirect",
                            .headers = &.{
                                .{ .name = "Location", .value = "/next" },
                            },
                        },
                    },
                },
            },
        },
    };

    var server = try test_server.TestServer.init(&scenarios, test_server.Options.default());
    defer server.deinit();
    try server.start();

    var client = Client.init(std.testing.allocator, Options.default());
    defer client.deinit();

    const uri = types.Uri.init(.http, "127.0.0.1", types.Port.init(server.port()), "/start", null, null);
    var request = types.Request.init(std.testing.allocator, .post, uri);
    defer request.deinit();
    try request.headers.append("Host", "127.0.0.1");
    try request.headers.append("Content-Length", "7");

    var body_state = TestBodyState{
        .data = "payload",
        .offset = 0,
    };
    request.body = .{
        .ctx = &body_state,
        .read_fn = TestBodyState.read,
        .close_fn = TestBodyState.close,
    };

    var handle = try client.request(&request);
    defer handle.deinit();

    try std.testing.expectError(error.RedirectBodyNotRepeatable, handle.wait());
}
