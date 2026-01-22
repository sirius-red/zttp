//! HTTP client implementation.

const std = @import("std");
const types = @import("types.zig");
const mailbox = @import("util/mailbox.zig");
const future = @import("util/future.zig");

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

    /// Creates a client with the provided allocator and options.
    pub fn init(allocator: std.mem.Allocator, options: Options) Client {
        return .{
            .allocator = allocator,
            .options = options,
        };
    }

    /// Releases resources owned by the client.
    pub fn deinit(self: *Client) void {
        _ = self;
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
