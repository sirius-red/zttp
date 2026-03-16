//! Proxy environment discovery and NO_PROXY matching helpers.

const std = @import("std");
const types = @import("../types.zig");

/// Proxy endpoint resolved from configuration.
pub const ProxyEndpoint = struct {
    /// Allocator used to manage stored buffers.
    allocator: std.mem.Allocator,
    /// Proxy scheme.
    scheme: types.Scheme,
    /// Proxy host in lowercase.
    host: []u8,
    /// Proxy port.
    port: types.Port,

    /// Releases owned buffers.
    pub fn deinit(self: *ProxyEndpoint) void {
        self.allocator.free(self.host);
        self.* = undefined;
    }
};

/// Error set returned by proxy resolution helpers.
pub const ResolveError = std.mem.Allocator.Error || error{
    /// Proxy value could not be parsed.
    InvalidProxy,
    /// Proxy scheme is not supported.
    UnsupportedScheme,
    /// NO_PROXY entry is invalid.
    InvalidNoProxyEntry,
};

/// Owned proxy environment values.
pub const EnvValues = struct {
    /// Allocator used for stored values.
    allocator: std.mem.Allocator,
    /// HTTP proxy variable value, if any.
    http_proxy: ?[]u8,
    /// HTTPS proxy variable value, if any.
    https_proxy: ?[]u8,
    /// NO_PROXY variable value, if any.
    no_proxy: ?[]u8,

    /// Releases owned environment values.
    pub fn deinit(self: *EnvValues) void {
        if (self.http_proxy) |value| {
            self.allocator.free(value);
        }
        if (self.https_proxy) |value| {
            self.allocator.free(value);
        }
        if (self.no_proxy) |value| {
            self.allocator.free(value);
        }
        self.* = undefined;
    }
};

/// Error set returned by environment discovery.
pub const EnvError = std.process.GetEnvVarOwnedError;

/// Loads proxy-related environment variables.
/// Uppercase variables take precedence over lowercase variants.
pub fn loadEnv(allocator: std.mem.Allocator) EnvError!EnvValues {
    const http_proxy = try readEnvVarWithFallback(allocator, "HTTP_PROXY", "http_proxy");
    const https_proxy = try readEnvVarWithFallback(allocator, "HTTPS_PROXY", "https_proxy");
    const no_proxy = try readEnvVarWithFallback(allocator, "NO_PROXY", "no_proxy");

    return .{
        .allocator = allocator,
        .http_proxy = http_proxy,
        .https_proxy = https_proxy,
        .no_proxy = no_proxy,
    };
}

/// Resolves a proxy endpoint for the request URI using environment values.
/// Proxy values without an explicit scheme default to `http`.
pub fn selectProxyFromEnv(
    allocator: std.mem.Allocator,
    uri: types.Uri,
    http_proxy: ?[]const u8,
    https_proxy: ?[]const u8,
    no_proxy: ?[]const u8,
) ResolveError!?ProxyEndpoint {
    if (no_proxy) |list| {
        if (matchesNoProxy(uri, list)) {
            return null;
        }
    }

    const proxy_value = switch (uri.scheme) {
        .http => http_proxy,
        .https => https_proxy orelse http_proxy,
    } orelse return null;

    return @as(?ProxyEndpoint, try parseProxy(allocator, proxy_value, .http));
}

/// Returns true when the NO_PROXY list excludes the URI.
pub fn matchesNoProxy(uri: types.Uri, list: []const u8) bool {
    var iter = std.mem.splitScalar(u8, list, ',');
    while (iter.next()) |raw| {
        const entry = trimWhitespace(raw);
        if (entry.len == 0) {
            continue;
        }
        if (std.mem.eql(u8, entry, "*")) {
            return true;
        }
        const parsed = parseNoProxyEntry(entry) orelse continue;
        if (parsed.port) |port| {
            if (uri.effectivePort().toInt() != port) {
                continue;
            }
        }
        if (hostMatchesNoProxy(uri.host, parsed)) {
            return true;
        }
    }
    return false;
}

/// Reads an environment variable, falling back to a secondary key.
fn readEnvVarWithFallback(
    allocator: std.mem.Allocator,
    primary: []const u8,
    fallback: []const u8,
) EnvError!?[]u8 {
    if (try readEnvVar(allocator, primary)) |value| {
        return value;
    }
    return try readEnvVar(allocator, fallback);
}

/// Reads an environment variable or returns null if not set or empty.
fn readEnvVar(allocator: std.mem.Allocator, key: []const u8) EnvError!?[]u8 {
    const value = std.process.getEnvVarOwned(allocator, key) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        else => return err,
    };
    if (value.len == 0) {
        allocator.free(value);
        return null;
    }
    return value;
}

/// Parses a proxy value into a typed endpoint.
fn parseProxy(
    allocator: std.mem.Allocator,
    raw_value: []const u8,
    default_scheme: types.Scheme,
) ResolveError!ProxyEndpoint {
    const trimmed = trimWhitespace(raw_value);
    if (trimmed.len == 0) {
        return error.InvalidProxy;
    }

    var scheme = default_scheme;
    var rest = trimmed;
    if (std.mem.indexOf(u8, trimmed, "://")) |sep| {
        const scheme_bytes = trimmed[0..sep];
        if (std.ascii.eqlIgnoreCase(scheme_bytes, "http")) {
            scheme = .http;
        } else if (std.ascii.eqlIgnoreCase(scheme_bytes, "https")) {
            scheme = .https;
        } else {
            return error.UnsupportedScheme;
        }
        rest = trimmed[sep + 3 ..];
    }

    if (scheme != .http and scheme != .https) {
        return error.UnsupportedScheme;
    }

    const authority = trimAuthority(rest) orelse return error.InvalidProxy;
    const parsed = parseAuthority(authority) orelse return error.InvalidProxy;

    const port = parsed.port orelse scheme.defaultPort();
    const host_copy = try lowerCaseCopy(allocator, parsed.host);
    errdefer allocator.free(host_copy);

    return .{
        .allocator = allocator,
        .scheme = scheme,
        .host = host_copy,
        .port = port,
    };
}

/// Host and port components parsed from an authority string.
const Authority = struct {
    /// Parsed host component.
    host: []const u8,
    /// Parsed port component if present.
    port: ?types.Port,
};

/// Match mode for NO_PROXY entries.
const NoProxyMatchMode = enum {
    /// Matches exact host or subdomains.
    exact_or_subdomain,
    /// Matches subdomains only.
    subdomain_only,
};

/// Parsed NO_PROXY entry data.
const NoProxyEntry = struct {
    /// Entry host value.
    host: []const u8,
    /// Optional port value.
    port: ?u16,
    /// Match mode for host comparisons.
    mode: NoProxyMatchMode,
};

/// Extracts the authority portion from a proxy string.
fn trimAuthority(value: []const u8) ?[]const u8 {
    var end = value.len;
    for (value, 0..) |byte, idx| {
        if (byte == '/' or byte == '?' or byte == '#') {
            end = idx;
            break;
        }
    }
    const authority = value[0..end];
    return if (authority.len == 0) null else authority;
}

/// Parses an authority into host and optional port.
fn parseAuthority(value: []const u8) ?Authority {
    if (value.len == 0) {
        return null;
    }
    if (std.mem.indexOfScalar(u8, value, '@') != null) {
        return null;
    }

    if (value[0] == '[') {
        const closing = std.mem.indexOfScalar(u8, value, ']') orelse return null;
        const host = value[1..closing];
        if (host.len == 0) {
            return null;
        }
        if (closing + 1 == value.len) {
            return .{ .host = host, .port = null };
        }
        if (value[closing + 1] != ':') {
            return null;
        }
        const port_str = value[closing + 2 ..];
        const port = parsePort(port_str) orelse return null;
        return .{ .host = host, .port = port };
    }

    if (std.mem.lastIndexOfScalar(u8, value, ':')) |colon| {
        if (std.mem.indexOfScalar(u8, value[0..colon], ':') != null) {
            return null;
        }
        const host = value[0..colon];
        const port_str = value[colon + 1 ..];
        if (host.len == 0) {
            return null;
        }
        const port = parsePort(port_str) orelse return null;
        return .{ .host = host, .port = port };
    }

    return .{ .host = value, .port = null };
}

/// Parses a port from decimal bytes.
fn parsePort(value: []const u8) ?types.Port {
    if (value.len == 0) {
        return null;
    }
    const parsed = std.fmt.parseInt(u16, value, 10) catch return null;
    return types.Port.init(parsed);
}

/// Parses a NO_PROXY entry.
fn parseNoProxyEntry(value: []const u8) ?NoProxyEntry {
    var host_value = value;
    var port: ?u16 = null;

    if (std.mem.lastIndexOfScalar(u8, value, ':')) |colon| {
        if (std.mem.indexOfScalar(u8, value[0..colon], ':') == null) {
            const port_str = value[colon + 1 ..];
            const parsed = std.fmt.parseInt(u16, port_str, 10) catch null;
            if (parsed != null) {
                port = parsed;
                host_value = value[0..colon];
            }
        }
    }

    if (host_value.len == 0) {
        return null;
    }

    var mode: NoProxyMatchMode = .exact_or_subdomain;
    if (host_value[0] == '.') {
        host_value = host_value[1..];
        mode = .subdomain_only;
    }

    if (host_value.len == 0) {
        return null;
    }

    return .{
        .host = host_value,
        .port = port,
        .mode = mode,
    };
}

/// Returns true when the host matches the NO_PROXY entry.
fn hostMatchesNoProxy(host: []const u8, entry: NoProxyEntry) bool {
    if (entry.mode == .subdomain_only) {
        if (host.len <= entry.host.len) {
            return false;
        }
        if (!std.ascii.eqlIgnoreCase(host[host.len - entry.host.len ..], entry.host)) {
            return false;
        }
        return host[host.len - entry.host.len - 1] == '.';
    }

    if (std.ascii.eqlIgnoreCase(host, entry.host)) {
        return true;
    }
    if (host.len <= entry.host.len) {
        return false;
    }
    if (!std.ascii.eqlIgnoreCase(host[host.len - entry.host.len ..], entry.host)) {
        return false;
    }
    return host[host.len - entry.host.len - 1] == '.';
}

/// Returns a trimmed view of leading and trailing whitespace.
fn trimWhitespace(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t");
}

/// Returns a lowercased copy of the provided value.
fn lowerCaseCopy(allocator: std.mem.Allocator, value: []const u8) std.mem.Allocator.Error![]u8 {
    const copy = try allocator.dupe(u8, value);
    for (copy) |*byte| {
        byte.* = std.ascii.toLower(byte.*);
    }
    return copy;
}

test "no_proxy matches hosts and ports" {
    const uri = types.Uri.init(.http, "api.example.com", types.Port.init(80), "/", null, null);
    try std.testing.expect(matchesNoProxy(uri, "example.com"));
    try std.testing.expect(matchesNoProxy(uri, ".example.com"));

    const root = types.Uri.init(.http, "example.com", types.Port.init(80), "/", null, null);
    try std.testing.expect(matchesNoProxy(root, "example.com"));
    try std.testing.expect(!matchesNoProxy(root, ".example.com"));

    const port_uri = types.Uri.init(.http, "example.com", types.Port.init(8080), "/", null, null);
    try std.testing.expect(matchesNoProxy(port_uri, "example.com:8080"));
    try std.testing.expect(!matchesNoProxy(port_uri, "example.com:80"));
}

test "no_proxy wildcard" {
    const uri = types.Uri.init(.http, "example.com", types.Port.init(80), "/", null, null);
    try std.testing.expect(matchesNoProxy(uri, "*"));
}

test "select proxy from env respects no_proxy" {
    const uri = types.Uri.init(.http, "example.com", types.Port.init(80), "/", null, null);
    var proxy = try selectProxyFromEnv(
        std.testing.allocator,
        uri,
        "http://proxy.local:3128",
        null,
        "example.com",
    );
    if (proxy) |*value| {
        value.deinit();
    }
    try std.testing.expect(proxy == null);
}

test "select proxy from env parses default scheme" {
    const uri = types.Uri.init(.http, "example.com", types.Port.init(80), "/", null, null);
    var proxy = (try selectProxyFromEnv(
        std.testing.allocator,
        uri,
        "proxy.local:8080",
        null,
        null,
    )).?;
    defer proxy.deinit();

    try std.testing.expectEqual(types.Scheme.http, proxy.scheme);
    try std.testing.expectEqualStrings("proxy.local", proxy.host);
    try std.testing.expectEqual(@as(u16, 8080), proxy.port.toInt());
}

test "select proxy from env parses https proxy" {
    const uri = types.Uri.init(.https, "example.com", types.Port.init(443), "/", null, null);
    var proxy = (try selectProxyFromEnv(
        std.testing.allocator,
        uri,
        null,
        "https://proxy.local:8443/path",
        null,
    )).?;
    defer proxy.deinit();

    try std.testing.expectEqual(types.Scheme.https, proxy.scheme);
    try std.testing.expectEqualStrings("proxy.local", proxy.host);
    try std.testing.expectEqual(@as(u16, 8443), proxy.port.toInt());
}

test "select proxy from env falls back to http proxy for https targets" {
    const uri = types.Uri.init(.https, "example.com", types.Port.init(443), "/", null, null);
    var proxy = (try selectProxyFromEnv(
        std.testing.allocator,
        uri,
        "http://proxy.local:3128",
        null,
        null,
    )).?;
    defer proxy.deinit();

    try std.testing.expectEqual(types.Scheme.http, proxy.scheme);
    try std.testing.expectEqualStrings("proxy.local", proxy.host);
    try std.testing.expectEqual(@as(u16, 3128), proxy.port.toInt());
}

test "select proxy from env defaults https proxy to http scheme" {
    const uri = types.Uri.init(.https, "example.com", types.Port.init(443), "/", null, null);
    var proxy = (try selectProxyFromEnv(
        std.testing.allocator,
        uri,
        null,
        "proxy.local:8080",
        null,
    )).?;
    defer proxy.deinit();

    try std.testing.expectEqual(types.Scheme.http, proxy.scheme);
    try std.testing.expectEqualStrings("proxy.local", proxy.host);
    try std.testing.expectEqual(@as(u16, 8080), proxy.port.toInt());
}
