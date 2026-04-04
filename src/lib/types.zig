//! Core public types for the zttp module.

const std = @import("std");

/// Represents an HTTP method.
pub const Method = union(enum) {
    /// GET request method.
    get,
    /// HEAD request method.
    head,
    /// POST request method.
    post,
    /// PUT request method.
    put,
    /// DELETE request method.
    delete,
    /// CONNECT request method.
    connect,
    /// OPTIONS request method.
    options,
    /// TRACE request method.
    trace,
    /// PATCH request method.
    patch,
    /// Custom extension method token.
    custom: []const u8,

    /// Returns the wire name for the method.
    pub fn asBytes(self: Method) []const u8 {
        return switch (self) {
            .get => "GET",
            .head => "HEAD",
            .post => "POST",
            .put => "PUT",
            .delete => "DELETE",
            .connect => "CONNECT",
            .options => "OPTIONS",
            .trace => "TRACE",
            .patch => "PATCH",
            .custom => |name| name,
        };
    }
};

/// Represents an HTTP version.
pub const Version = enum {
    /// HTTP/1.0.
    http_1_0,
    /// HTTP/1.1.
    http_1_1,
    /// HTTP/2.
    http_2,
    /// HTTP/3.
    http_3,

    /// Returns the wire name for the version.
    pub fn asBytes(self: Version) []const u8 {
        return switch (self) {
            .http_1_0 => "HTTP/1.0",
            .http_1_1 => "HTTP/1.1",
            .http_2 => "HTTP/2",
            .http_3 => "HTTP/3",
        };
    }
};

/// Represents a URI scheme.
pub const Scheme = enum {
    /// Plain-text HTTP.
    http,
    /// HTTP over TLS.
    https,

    /// Returns the default port for the scheme.
    pub fn defaultPort(self: Scheme) Port {
        return switch (self) {
            .http => Port.init(80),
            .https => Port.init(443),
        };
    }

    /// Returns the wire name for the scheme.
    pub fn asBytes(self: Scheme) []const u8 {
        return switch (self) {
            .http => "http",
            .https => "https",
        };
    }
};

/// Represents a TCP/UDP port value.
pub const Port = struct {
    /// Numeric port value.
    value: u16,

    /// Creates a port from a numeric value.
    pub fn init(value: u16) Port {
        return .{ .value = value };
    }

    /// Returns the numeric port value.
    pub fn toInt(self: Port) u16 {
        return self.value;
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

    /// Creates a size from kibibytes.
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

/// Represents a non-owning, parsed URI.
pub const Uri = struct {
    /// Scheme component.
    scheme: Scheme,
    /// Hostname or IP literal.
    host: []const u8,
    /// Explicit port if provided.
    port: ?Port,
    /// Absolute path, starting with '/'.
    path: []const u8,
    /// Query component without leading '?'.
    query: ?[]const u8,
    /// Fragment component without leading '#'.
    fragment: ?[]const u8,

    /// Creates a URI from its components without allocation.
    pub fn init(
        scheme: Scheme,
        host: []const u8,
        port: ?Port,
        path: []const u8,
        query: ?[]const u8,
        fragment: ?[]const u8,
    ) Uri {
        return .{
            .scheme = scheme,
            .host = host,
            .port = port,
            .path = path,
            .query = query,
            .fragment = fragment,
        };
    }

    /// Returns the port used for connections, falling back to the scheme default.
    pub fn effectivePort(self: Uri) Port {
        return self.port orelse self.scheme.defaultPort();
    }
};

/// Identity token for TLS configuration matching.
pub const TlsIdentityToken = struct {
    /// Opaque identifier value.
    value: u64,

    /// Creates an identity token from the provided value.
    pub fn init(value: u64) TlsIdentityToken {
        return .{ .value = value };
    }

    /// Returns the raw identity value.
    pub fn toInt(self: TlsIdentityToken) u64 {
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

/// Root store selection mode for TLS verification.
pub const TlsRootStoreMode = enum {
    /// Use the platform or process default roots.
    system,
    /// Use explicit local roots provided by path.
    explicit,
};

/// Negotiated application protocol for a connection.
pub const NegotiatedProtocol = enum {
    /// HTTP/1.1 or equivalent ALPN fallback.
    http_1_1,
    /// HTTP/2 negotiated through ALPN.
    h2,
    /// HTTP/3 negotiated through QUIC transport.
    h3,

    /// Returns the ALPN token for the protocol.
    pub fn asAlpnBytes(self: NegotiatedProtocol) []const u8 {
        return switch (self) {
            .http_1_1 => "http/1.1",
            .h2 => "h2",
            .h3 => "h3",
        };
    }

    /// Returns the closest HTTP version label for the protocol.
    pub fn asVersion(self: NegotiatedProtocol) Version {
        return switch (self) {
            .http_1_1 => .http_1_1,
            .h2 => .http_2,
            .h3 => .http_3,
        };
    }
};

/// Support classification for one feature and protocol pairing.
pub const FeatureSupportLevel = enum {
    /// The full first-party feature is available on the negotiated protocol.
    supported,
    /// The feature is available with documented protocol-specific limits.
    degraded,
    /// The feature must fail clearly on the negotiated protocol.
    unsupported,
};

/// Higher-level surface that owns a protocol capability.
pub const FeatureSurface = enum {
    /// The capability is owned by a server-facing library surface.
    server,
    /// The capability is owned by a client-facing library surface.
    client,
    /// The capability is shared as a transport-neutral library primitive.
    shared,
    /// The capability is owned by hardening and verification coverage.
    hardening,
};

/// One typed feature/protocol classification entry.
pub const ProtocolFeatureCapability = struct {
    /// Stable feature name surfaced by a capability matrix.
    feature_name: []const u8,
    /// Higher-level surface that owns the capability.
    surface: FeatureSurface,
    /// Negotiated protocol being classified.
    protocol: NegotiatedProtocol,
    /// Classification for the feature/protocol pairing.
    support: FeatureSupportLevel,
    /// Optional explanatory note for downgraded or unsupported entries.
    notes: ?[]const u8,
};

/// Isolation boundary for one request, stream, connection, or session failure.
pub const FailureIsolationScope = enum {
    /// Failure is contained to one request.
    request,
    /// Failure is contained to one multiplexed stream.
    stream,
    /// Failure applies to one shared connection.
    connection,
    /// Failure applies to one transport session.
    session,
};

/// Request target format used for connection pooling decisions.
pub const ConnectionTargetMode = enum {
    /// Origin-form request target.
    origin_form,
    /// Absolute-form request target.
    absolute_form,
};

/// Target host and port for CONNECT tunnels.
pub const TunnelTarget = struct {
    /// Hostname or IP literal for the tunnel target.
    host: []const u8,
    /// Port for the tunnel target.
    port: Port,
};

/// Shared secure-endpoint metadata for local validation and runtime helpers.
pub const SecureEndpointMetadata = struct {
    /// URI scheme used by the endpoint.
    scheme: Scheme,
    /// Hostname or IP literal used by the endpoint.
    host: []const u8,
    /// Port exposed by the endpoint.
    port: Port,
    /// Absolute request path used by validation probes.
    path: []const u8,
    /// Expected application protocol for the endpoint.
    protocol: NegotiatedProtocol,
};

/// Shared TLS trust and identity material used by secure validation helpers.
pub const TlsTrustMaterial = struct {
    /// Optional path to an explicit trust bundle.
    explicit_roots_path: ?[]const u8,
    /// Optional path to the server or mutual-TLS certificate chain.
    certificate_chain_path: ?[]const u8,
    /// Optional path to the matching private key.
    private_key_path: ?[]const u8,

    /// Returns true when an explicit trust bundle is configured.
    pub fn hasExplicitRoots(self: TlsTrustMaterial) bool {
        return self.explicit_roots_path != null;
    }

    /// Returns true when both server-identity paths are configured.
    pub fn hasIdentity(self: TlsTrustMaterial) bool {
        return self.certificate_chain_path != null and self.private_key_path != null;
    }
};

const default_alpn_protocols = [_]NegotiatedProtocol{ .h2, .http_1_1 };

/// Shared TLS configuration for client and server flows.
pub const TlsConfig = struct {
    /// Certificate verification mode.
    verify: TlsVerifyMode,
    /// Root store selection mode.
    root_store_mode: TlsRootStoreMode,
    /// Optional path to an explicit trust store bundle.
    explicit_roots_path: ?[]const u8,
    /// Optional path to a certificate chain for local listeners or mutual TLS.
    certificate_chain_path: ?[]const u8,
    /// Optional path to the matching private key.
    private_key_path: ?[]const u8,
    /// Ordered list of ALPN protocols to advertise.
    alpn_protocols: []const NegotiatedProtocol,
    /// Optional override token to force pool identity separation.
    identity_token: ?TlsIdentityToken,

    /// Returns true when the configuration advertises the provided protocol.
    pub fn supportsProtocol(self: TlsConfig, protocol: NegotiatedProtocol) bool {
        for (self.alpn_protocols) |candidate| {
            if (candidate == protocol) {
                return true;
            }
        }
        return false;
    }

    /// Returns a stable identity token for pooling decisions.
    pub fn identity(self: TlsConfig) TlsIdentityToken {
        if (self.identity_token) |identity_token| {
            return identity_token;
        }

        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&[_]u8{@intFromEnum(self.verify)});
        hasher.update(&[_]u8{@intFromEnum(self.root_store_mode)});

        if (self.explicit_roots_path) |path| {
            hasher.update(path);
        }
        if (self.certificate_chain_path) |path| {
            hasher.update(path);
        }
        if (self.private_key_path) |path| {
            hasher.update(path);
        }
        for (self.alpn_protocols) |protocol| {
            hasher.update(protocol.asAlpnBytes());
        }

        return TlsIdentityToken.init(hasher.final());
    }

    /// Returns a copy of the TLS config constrained to the provided ALPN offers.
    pub fn withAlpnProtocols(self: TlsConfig, protocols: []const NegotiatedProtocol) TlsConfig {
        var copy = self;
        copy.alpn_protocols = protocols;
        return copy;
    }

    /// Returns the default TLS configuration.
    pub fn default() TlsConfig {
        return .{
            .verify = .verify,
            .root_store_mode = .system,
            .explicit_roots_path = null,
            .certificate_chain_path = null,
            .private_key_path = null,
            .alpn_protocols = &default_alpn_protocols,
            .identity_token = null,
        };
    }
};

/// Planned transport protocol and ALPN offer set for one request route.
pub const ProtocolPlan = struct {
    /// Application protocol the selected transport path must handle.
    expected_protocol: NegotiatedProtocol,
    /// Ordered ALPN protocols the client may advertise on this route.
    offered_protocols: []const NegotiatedProtocol,

    /// Returns true when the route advertises the provided protocol.
    pub fn supportsOfferedProtocol(self: ProtocolPlan, protocol: NegotiatedProtocol) bool {
        for (self.offered_protocols) |candidate| {
            if (candidate == protocol) {
                return true;
            }
        }
        return false;
    }

    /// Applies the route's ALPN offer set to a shared TLS configuration.
    pub fn routedTlsConfig(self: ProtocolPlan, tls_config: TlsConfig) TlsConfig {
        return tls_config.withAlpnProtocols(self.offered_protocols);
    }
};

/// Connection-pool identity shared across protocol modules.
pub const OriginKey = struct {
    /// Scheme used for the socket connection.
    scheme: Scheme,
    /// Hostname or IP literal used for the connection.
    host: []const u8,
    /// Port used for the connection.
    port: Port,
    /// TLS configuration identity.
    tls_id: TlsIdentityToken,
    /// Negotiated or expected application protocol.
    negotiated_protocol: NegotiatedProtocol,
    /// Request target mode used on the connection.
    target_mode: ConnectionTargetMode,
    /// Optional tunnel target when using proxy CONNECT.
    tunnel: ?TunnelTarget,
    /// Optional proxy authorization header value for CONNECT.
    proxy_authorization: ?[]const u8,
};

/// Represents an HTTP status code.
pub const Status = enum(u16) {
    /// 100 Continue.
    continue_ = 100,
    /// 101 Switching Protocols.
    switching_protocols = 101,
    /// 200 OK.
    ok = 200,
    /// 201 Created.
    created = 201,
    /// 204 No Content.
    no_content = 204,
    /// 301 Moved Permanently.
    moved_permanently = 301,
    /// 302 Found.
    found = 302,
    /// 303 See Other.
    see_other = 303,
    /// 304 Not Modified.
    not_modified = 304,
    /// 307 Temporary Redirect.
    temporary_redirect = 307,
    /// 308 Permanent Redirect.
    permanent_redirect = 308,
    /// 400 Bad Request.
    bad_request = 400,
    /// 401 Unauthorized.
    unauthorized = 401,
    /// 403 Forbidden.
    forbidden = 403,
    /// 404 Not Found.
    not_found = 404,
    /// 405 Method Not Allowed.
    method_not_allowed = 405,
    /// 408 Request Timeout.
    request_timeout = 408,
    /// 413 Payload Too Large.
    payload_too_large = 413,
    /// 414 URI Too Long.
    uri_too_long = 414,
    /// 431 Request Header Fields Too Large.
    request_header_fields_too_large = 431,
    /// 500 Internal Server Error.
    internal_server_error = 500,
    /// 502 Bad Gateway.
    bad_gateway = 502,
    /// 503 Service Unavailable.
    service_unavailable = 503,

    /// Creates a status from its numeric code.
    pub fn fromInt(value: u16) Status {
        return @enumFromInt(value);
    }

    /// Returns the numeric status code.
    pub fn code(self: Status) u16 {
        return @intFromEnum(self);
    }
};

/// Represents a single header field.
pub const Header = struct {
    /// Header name.
    name: []const u8,
    /// Header value.
    value: []const u8,
};

/// Iterates over header fields.
pub const HeadersIterator = struct {
    /// Header collection being iterated.
    headers: *const Headers,
    /// Current iteration index.
    index: usize,

    /// Returns the next header or null when done.
    pub fn next(self: *HeadersIterator) ?Header {
        if (self.index >= self.headers.entries.items.len) {
            return null;
        }
        const header = self.headers.entries.items[self.index];
        self.index += 1;
        return header;
    }
};

/// Collection of HTTP header fields.
pub const Headers = struct {
    /// Allocator used for header storage.
    allocator: std.mem.Allocator,
    /// Header entries in insertion order.
    entries: std.ArrayListUnmanaged(Header),

    /// Initializes an empty header collection.
    pub fn init(allocator: std.mem.Allocator) Headers {
        return .{
            .allocator = allocator,
            .entries = .{},
        };
    }

    /// Releases all header storage.
    pub fn deinit(self: *Headers) void {
        for (self.entries.items) |header| {
            self.allocator.free(@constCast(header.name));
            self.allocator.free(@constCast(header.value));
        }
        self.entries.deinit(self.allocator);
    }

    /// Appends a header field, copying the name and value.
    pub fn append(self: *Headers, name: []const u8, value: []const u8) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);
        try self.entries.append(self.allocator, .{
            .name = name_copy,
            .value = value_copy,
        });
    }

    /// Returns the first header value matching the name, case-insensitively.
    pub fn get(self: *const Headers, name: []const u8) ?[]const u8 {
        for (self.entries.items) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                return header.value;
            }
        }
        return null;
    }

    /// Returns an iterator over header fields in insertion order.
    pub fn iterator(self: *const Headers) HeadersIterator {
        return .{
            .headers = self,
            .index = 0,
        };
    }
};

/// Error set returned by body reader implementations.
pub const BodyReaderReadError = anyerror;

/// Streaming request/response body reader.
pub const BodyReader = struct {
    /// Opaque reader context.
    ctx: ?*anyopaque,
    /// Reads up to `dest.len` bytes into `dest`.
    read_fn: *const fn (ctx: ?*anyopaque, dest: []u8) BodyReaderReadError!usize,
    /// Optional close hook.
    close_fn: ?*const fn (ctx: ?*anyopaque) void,

    /// Reads bytes into `dest`, returning the number of bytes read.
    pub fn read(self: BodyReader, dest: []u8) BodyReaderReadError!usize {
        return self.read_fn(self.ctx, dest);
    }

    /// Closes the reader if a close hook is present.
    pub fn close(self: BodyReader) void {
        if (self.close_fn) |close_fn| {
            close_fn(self.ctx);
        }
    }
};

/// HTTP request message.
pub const Request = struct {
    /// HTTP method.
    method: Method,
    /// Target URI.
    uri: Uri,
    /// HTTP version to use.
    version: Version,
    /// Request headers.
    headers: Headers,
    /// Optional request body reader.
    body: ?BodyReader,

    /// Initializes a request with empty headers and no body.
    pub fn init(allocator: std.mem.Allocator, method: Method, uri: Uri) Request {
        return .{
            .method = method,
            .uri = uri,
            .version = .http_1_1,
            .headers = Headers.init(allocator),
            .body = null,
        };
    }

    /// Releases owned resources.
    pub fn deinit(self: *Request) void {
        self.headers.deinit();
    }
};

/// HTTP response message.
pub const Response = struct {
    /// HTTP version received.
    version: Version,
    /// Response status code.
    status: Status,
    /// Response headers.
    headers: Headers,
    /// Optional response body reader.
    body: ?BodyReader,

    /// Initializes a response with empty headers and no body.
    pub fn init(allocator: std.mem.Allocator, version: Version, status: Status) Response {
        return .{
            .version = version,
            .status = status,
            .headers = Headers.init(allocator),
            .body = null,
        };
    }

    /// Releases owned resources.
    pub fn deinit(self: *Response) void {
        self.headers.deinit();
    }
};

test "tls config default identity is stable" {
    const config = TlsConfig.default();
    try std.testing.expect(config.supportsProtocol(.h2));
    try std.testing.expect(config.supportsProtocol(.http_1_1));
    try std.testing.expectEqual(config.identity().toInt(), TlsConfig.default().identity().toInt());
}

test "tls trust material reports configured roots and identity" {
    const trust = TlsTrustMaterial{
        .explicit_roots_path = "roots.pem",
        .certificate_chain_path = "server.pem",
        .private_key_path = "server.key",
    };

    try std.testing.expect(trust.hasExplicitRoots());
    try std.testing.expect(trust.hasIdentity());
}

test "protocol plan narrows routed tls identity to the offered alpn set" {
    const routed = ProtocolPlan{
        .expected_protocol = .http_1_1,
        .offered_protocols = &.{.http_1_1},
    };
    const tls_config = routed.routedTlsConfig(TlsConfig.default());

    try std.testing.expectEqual(@as(usize, 1), tls_config.alpn_protocols.len);
    try std.testing.expectEqual(NegotiatedProtocol.http_1_1, tls_config.alpn_protocols[0]);
    try std.testing.expect(routed.supportsOfferedProtocol(.http_1_1));
    try std.testing.expect(!routed.supportsOfferedProtocol(.h2));
    try std.testing.expect(tls_config.identity().toInt() != TlsConfig.default().identity().toInt());
}

test "negotiated protocol exposes ALPN token" {
    try std.testing.expectEqualStrings("h2", NegotiatedProtocol.h2.asAlpnBytes());
    try std.testing.expectEqual(Version.http_3, NegotiatedProtocol.h3.asVersion());
}

test "protocol feature capability keeps typed support metadata" {
    const capability = ProtocolFeatureCapability{
        .feature_name = "server.websocket",
        .surface = .server,
        .protocol = .h2,
        .support = .degraded,
        .notes = "extended CONNECT semantics apply",
    };

    try std.testing.expectEqual(FeatureSurface.server, capability.surface);
    try std.testing.expectEqual(FeatureSupportLevel.degraded, capability.support);
    try std.testing.expectEqual(NegotiatedProtocol.h2, capability.protocol);
}
