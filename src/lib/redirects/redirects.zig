//! Redirect resolution and method rewrite helpers.

const std = @import("std");
const types = @import("../types.zig");

/// Error set returned by redirect helpers.
pub const RedirectError = std.mem.Allocator.Error || error{
    /// Redirect location header was missing or empty.
    MissingLocation,
    /// Redirect location could not be parsed.
    InvalidLocation,
    /// Redirect scheme is not supported.
    UnsupportedScheme,
};

/// Result of a redirect method rewrite decision.
pub const MethodRewrite = struct {
    /// Method to use for the next request.
    method: types.Method,
    /// Indicates whether the request body may be reused.
    keep_body: bool,
};

/// URI with owned backing storage for components.
pub const OwnedUri = struct {
    /// Allocator used to manage stored buffers.
    allocator: std.mem.Allocator,
    /// Scheme component.
    scheme: types.Scheme,
    /// Host component.
    host: []u8,
    /// Optional port component.
    port: ?types.Port,
    /// Path component.
    path: []u8,
    /// Optional query component.
    query: ?[]u8,
    /// Optional fragment component.
    fragment: ?[]u8,

    /// Releases owned buffers.
    pub fn deinit(self: *OwnedUri) void {
        self.allocator.free(self.host);
        self.allocator.free(self.path);
        if (self.query) |query| {
            self.allocator.free(query);
        }
        if (self.fragment) |fragment| {
            self.allocator.free(fragment);
        }
        self.* = undefined;
    }

    /// Returns a non-owning URI view for the stored components.
    pub fn asUri(self: *const OwnedUri) types.Uri {
        return types.Uri.init(
            self.scheme,
            self.host,
            self.port,
            self.path,
            self.query,
            self.fragment,
        );
    }
};

/// Returns true when the status code represents a redirect.
pub fn isRedirectStatus(status: types.Status) bool {
    return switch (status) {
        .moved_permanently,
        .found,
        .see_other,
        .temporary_redirect,
        .permanent_redirect,
        => true,
        else => false,
    };
}

/// Determines the method to use for a redirect response.
pub fn rewriteMethod(status: types.Status, method: types.Method) MethodRewrite {
    return switch (status) {
        .moved_permanently,
        .found,
        => switch (method) {
            .get, .head => .{ .method = method, .keep_body = true },
            else => .{ .method = .get, .keep_body = false },
        },
        .see_other => switch (method) {
            .head => .{ .method = .head, .keep_body = false },
            else => .{ .method = .get, .keep_body = false },
        },
        .temporary_redirect,
        .permanent_redirect,
        => .{ .method = method, .keep_body = true },
        else => .{ .method = method, .keep_body = true },
    };
}

/// Resolves a Location header value against the base URI.
pub fn resolveLocation(
    allocator: std.mem.Allocator,
    base: types.Uri,
    location: []const u8,
) RedirectError!OwnedUri {
    if (location.len == 0) {
        return error.MissingLocation;
    }

    if (std.mem.startsWith(u8, location, "http://") or std.mem.startsWith(u8, location, "https://")) {
        return parseAbsolute(allocator, location);
    }

    if (std.mem.startsWith(u8, location, "//")) {
        return parseAuthorityRelative(allocator, base, location[2..]);
    }

    if (location[0] == '/') {
        return buildRelative(allocator, base, location);
    }

    if (location[0] == '?') {
        return buildQueryRelative(allocator, base, location[1..]);
    }

    return buildPathRelative(allocator, base, location);
}

/// Builds a stable redirect key for loop detection.
pub fn uriKey(allocator: std.mem.Allocator, uri: types.Uri) std.mem.Allocator.Error![]u8 {
    const port = uri.effectivePort().toInt();
    const host_len = uri.host.len;
    const query_len: usize = if (uri.query) |query| query.len else 0;
    const query_extra: usize = if (uri.query != null) 1 else 0;
    const path = if (uri.path.len == 0) "/" else uri.path;
    const scheme_bytes = uri.scheme.asBytes();

    const length: usize = scheme_bytes.len + 3 + host_len + 1 + 5 + path.len + query_extra + query_len;
    var buffer = try allocator.alloc(u8, length);

    var index: usize = 0;
    std.mem.copyForwards(u8, buffer[index .. index + scheme_bytes.len], scheme_bytes);
    index += scheme_bytes.len;
    buffer[index] = ':';
    buffer[index + 1] = '/';
    buffer[index + 2] = '/';
    index += 3;

    for (uri.host) |byte| {
        buffer[index] = std.ascii.toLower(byte);
        index += 1;
    }

    buffer[index] = ':';
    index += 1;

    var port_buf: [5]u8 = undefined;
    const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch unreachable;
    std.mem.copyForwards(u8, buffer[index .. index + port_str.len], port_str);
    index += port_str.len;

    std.mem.copyForwards(u8, buffer[index .. index + path.len], path);
    index += path.len;

    if (uri.query) |query| {
        buffer[index] = '?';
        index += 1;
        std.mem.copyForwards(u8, buffer[index .. index + query.len], query);
        index += query.len;
    }

    return buffer[0..index];
}

/// Parses an absolute URI (http/https only).
fn parseAbsolute(allocator: std.mem.Allocator, location: []const u8) RedirectError!OwnedUri {
    const scheme_sep = std.mem.indexOf(u8, location, "://") orelse return error.InvalidLocation;
    const scheme_bytes = location[0..scheme_sep];
    const scheme = if (std.ascii.eqlIgnoreCase(scheme_bytes, "http"))
        types.Scheme.http
    else if (std.ascii.eqlIgnoreCase(scheme_bytes, "https"))
        return error.UnsupportedScheme
    else
        return error.UnsupportedScheme;

    const rest = location[scheme_sep + 3 ..];
    return parseAuthorityAndPath(allocator, scheme, rest);
}

/// Parses a scheme-relative URI and applies the base scheme.
fn parseAuthorityRelative(
    allocator: std.mem.Allocator,
    base: types.Uri,
    location: []const u8,
) RedirectError!OwnedUri {
    return parseAuthorityAndPath(allocator, base.scheme, location);
}

/// Parses the authority and optional path/query from a URI tail.
fn parseAuthorityAndPath(
    allocator: std.mem.Allocator,
    scheme: types.Scheme,
    tail: []const u8,
) RedirectError!OwnedUri {
    var authority_end: usize = tail.len;
    var index: usize = 0;
    while (index < tail.len) : (index += 1) {
        const byte = tail[index];
        if (byte == '/' or byte == '?' or byte == '#') {
            authority_end = index;
            break;
        }
    }

    const authority = tail[0..authority_end];
    const authority_info = try parseAuthority(authority);

    const remainder = tail[authority_end..];
    const path_query = splitPathQuery(remainder);

    return buildOwnedUri(
        allocator,
        scheme,
        authority_info.host,
        authority_info.port,
        path_query.path,
        path_query.query,
        null,
    );
}

/// Builds a URI from an absolute-path redirect.
fn buildRelative(
    allocator: std.mem.Allocator,
    base: types.Uri,
    location: []const u8,
) RedirectError!OwnedUri {
    const path_query = splitPathQuery(location);
    return buildOwnedUri(
        allocator,
        base.scheme,
        base.host,
        base.port,
        path_query.path,
        path_query.query,
        null,
    );
}

/// Builds a URI from a query-only redirect.
fn buildQueryRelative(
    allocator: std.mem.Allocator,
    base: types.Uri,
    query: []const u8,
) RedirectError!OwnedUri {
    const path = if (base.path.len == 0) "/" else base.path;
    return buildOwnedUri(
        allocator,
        base.scheme,
        base.host,
        base.port,
        path,
        query,
        null,
    );
}

/// Builds a URI from a relative-path redirect.
fn buildPathRelative(
    allocator: std.mem.Allocator,
    base: types.Uri,
    location: []const u8,
) RedirectError!OwnedUri {
    const base_path = if (base.path.len == 0) "/" else base.path;
    const merged = try joinRelativePath(allocator, base_path, location);
    defer allocator.free(merged);

    const path_query = splitPathQuery(merged);
    return buildOwnedUri(
        allocator,
        base.scheme,
        base.host,
        base.port,
        path_query.path,
        path_query.query,
        null,
    );
}

/// Parsed authority components.
const Authority = struct {
    /// Host component.
    host: []const u8,
    /// Optional port.
    port: ?types.Port,
};

/// Parses an authority string into host and optional port.
fn parseAuthority(authority: []const u8) RedirectError!Authority {
    if (authority.len == 0) {
        return error.InvalidLocation;
    }
    if (authority[0] == '[') {
        return error.InvalidLocation;
    }
    if (std.mem.indexOfScalar(u8, authority, '@') != null) {
        return error.InvalidLocation;
    }

    var host = authority;
    var port: ?types.Port = null;

    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        if (colon == 0) {
            return error.InvalidLocation;
        }
        const port_bytes = authority[colon + 1 ..];
        if (port_bytes.len == 0) {
            return error.InvalidLocation;
        }
        const port_value = std.fmt.parseInt(u16, port_bytes, 10) catch return error.InvalidLocation;
        host = authority[0..colon];
        port = types.Port.init(port_value);
    }

    if (host.len == 0) {
        return error.InvalidLocation;
    }

    return .{
        .host = host,
        .port = port,
    };
}

/// Result of splitting a path and query.
const PathQuery = struct {
    /// Path component, defaulting to "/".
    path: []const u8,
    /// Optional query component.
    query: ?[]const u8,
};

/// Splits a path into path and query components, dropping fragments.
fn splitPathQuery(value: []const u8) PathQuery {
    var trimmed = value;
    if (std.mem.indexOfScalar(u8, trimmed, '#')) |hash| {
        trimmed = trimmed[0..hash];
    }

    var path = trimmed;
    var query: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, trimmed, '?')) |question| {
        path = trimmed[0..question];
        query = trimmed[question + 1 ..];
    }

    if (path.len == 0) {
        path = "/";
    }

    return .{
        .path = path,
        .query = query,
    };
}

/// Builds an owned URI from string slices.
fn buildOwnedUri(
    allocator: std.mem.Allocator,
    scheme: types.Scheme,
    host: []const u8,
    port: ?types.Port,
    path: []const u8,
    query: ?[]const u8,
    fragment: ?[]const u8,
) RedirectError!OwnedUri {
    const host_copy = try allocator.dupe(u8, host);
    errdefer allocator.free(host_copy);
    const path_copy = try allocator.dupe(u8, path);
    errdefer allocator.free(path_copy);

    var query_copy: ?[]u8 = null;
    if (query) |value| {
        query_copy = try allocator.dupe(u8, value);
    }
    errdefer if (query_copy) |buffer| allocator.free(buffer);

    var fragment_copy: ?[]u8 = null;
    if (fragment) |value| {
        fragment_copy = try allocator.dupe(u8, value);
    }
    errdefer if (fragment_copy) |buffer| allocator.free(buffer);

    return .{
        .allocator = allocator,
        .scheme = scheme,
        .host = host_copy,
        .port = port,
        .path = path_copy,
        .query = query_copy,
        .fragment = fragment_copy,
    };
}

/// Joins a base path with a relative path.
fn joinRelativePath(
    allocator: std.mem.Allocator,
    base_path: []const u8,
    relative: []const u8,
) std.mem.Allocator.Error![]u8 {
    var base_dir = base_path;
    if (std.mem.lastIndexOfScalar(u8, base_path, '/')) |slash| {
        base_dir = base_path[0 .. slash + 1];
    }
    const combined = try std.mem.concat(allocator, u8, &.{ base_dir, relative });
    defer allocator.free(combined);
    return normalizePath(allocator, combined);
}

/// Normalizes path segments by handling "." and "..".
fn normalizePath(allocator: std.mem.Allocator, path: []const u8) std.mem.Allocator.Error![]u8 {
    const absolute = path.len > 0 and path[0] == '/';
    var segments = std.ArrayListUnmanaged([]const u8){};
    defer segments.deinit(allocator);

    var iter = std.mem.splitScalar(u8, path, '/');
    while (iter.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".")) {
            continue;
        }
        if (std.mem.eql(u8, segment, "..")) {
            if (segments.items.len > 0) {
                _ = segments.pop();
            }
            continue;
        }
        try segments.append(allocator, segment);
    }

    if (segments.items.len == 0) {
        return if (absolute)
            allocator.dupe(u8, "/")
        else
            allocator.dupe(u8, "");
    }

    var total_len: usize = if (absolute) 1 else 0;
    for (segments.items) |segment| {
        total_len += segment.len;
    }
    total_len += segments.items.len - 1;

    var buffer = try allocator.alloc(u8, total_len);
    var index: usize = 0;
    if (absolute) {
        buffer[index] = '/';
        index += 1;
    }

    for (segments.items, 0..) |segment, idx| {
        if (idx > 0) {
            buffer[index] = '/';
            index += 1;
        }
        std.mem.copyForwards(u8, buffer[index .. index + segment.len], segment);
        index += segment.len;
    }

    return buffer;
}

test "rewrite method rules" {
    try std.testing.expectEqual(.get, rewriteMethod(.moved_permanently, .get).method);
    try std.testing.expect(rewriteMethod(.moved_permanently, .get).keep_body);
    try std.testing.expectEqual(.get, rewriteMethod(.moved_permanently, .post).method);
    try std.testing.expect(!rewriteMethod(.moved_permanently, .post).keep_body);
    try std.testing.expectEqual(.get, rewriteMethod(.see_other, .post).method);
    try std.testing.expect(!rewriteMethod(.see_other, .post).keep_body);
    try std.testing.expectEqual(.head, rewriteMethod(.see_other, .head).method);
    try std.testing.expect(!rewriteMethod(.see_other, .head).keep_body);
    try std.testing.expectEqual(.put, rewriteMethod(.temporary_redirect, .put).method);
    try std.testing.expect(rewriteMethod(.temporary_redirect, .put).keep_body);
}

test "resolve relative location" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const base = types.Uri.init(.http, "example.com", types.Port.init(80), "/docs/index", null, null);
    var resolved = try resolveLocation(allocator, base, "next");
    defer resolved.deinit();

    const uri = resolved.asUri();
    try std.testing.expectEqualStrings("example.com", uri.host);
    try std.testing.expectEqualStrings("/docs/next", uri.path);
    try std.testing.expect(uri.query == null);
}

test "resolve absolute location" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var resolved = try resolveLocation(allocator, types.Uri.init(.http, "x", null, "/", null, null), "http://example.com/path?x=1");
    defer resolved.deinit();

    const uri = resolved.asUri();
    try std.testing.expectEqual(types.Scheme.http, uri.scheme);
    try std.testing.expectEqualStrings("example.com", uri.host);
    try std.testing.expectEqualStrings("/path", uri.path);
    try std.testing.expectEqualStrings("x=1", uri.query.?);
}
