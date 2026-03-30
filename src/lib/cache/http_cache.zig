//! Typed in-memory HTTP cache foundations for M6.

const std = @import("std");
const types = @import("../types.zig");

/// Freshness classification for one stored cache entry.
pub const CacheState = enum {
    /// Entry is fresh and reusable without revalidation.
    fresh,
    /// Entry is stale and requires revalidation.
    stale,
    /// Entry is actively being revalidated.
    revalidating,
    /// Entry has been invalidated and must not be reused.
    invalidated,
};

/// Source marker surfaced by one cache-aware client result.
pub const CacheSource = enum {
    /// Response came from the origin request path.
    origin,
    /// Response was served directly from cache.
    cache,
    /// Response came from a cache revalidation path.
    revalidated,
};

/// Cache action selected by one lookup.
pub const LookupAction = enum {
    /// No matching entry is available.
    miss,
    /// A fresh cached entry may be served immediately.
    serve_cached,
    /// A stale cached entry should be revalidated.
    revalidate,
    /// An entry exists but must not be reused.
    unusable,
};

/// Typed outcome returned by one cache lookup.
pub const LookupResult = struct {
    /// Selected cache action.
    action: LookupAction,
    /// Matching cache entry, when one exists.
    entry: ?*const CacheEntry,
    /// Source marker associated with the lookup action.
    source: ?CacheSource,
};

/// Typed cache key for one request identity.
pub const CacheKey = struct {
    /// Request method.
    method: types.Method,
    /// Request scheme.
    scheme: types.Scheme,
    /// Request host.
    host: []u8,
    /// Effective port.
    port: types.Port,
    /// Request path.
    path: []u8,
    /// Optional query string.
    query: ?[]u8,

    /// Returns true when the key matches the provided request identity.
    pub fn matches(
        self: CacheKey,
        method: types.Method,
        scheme: types.Scheme,
        host: []const u8,
        port: types.Port,
        path: []const u8,
        query: ?[]const u8,
    ) bool {
        if (!methodEql(self.method, method)) {
            return false;
        }
        if (self.scheme != scheme or self.port.toInt() != port.toInt()) {
            return false;
        }
        if (!std.ascii.eqlIgnoreCase(self.host, host)) {
            return false;
        }
        if (!std.mem.eql(u8, self.path, path)) {
            return false;
        }
        if (self.query == null and query == null) {
            return true;
        }
        if (self.query == null or query == null) {
            return false;
        }
        return std.mem.eql(u8, self.query.?, query.?);
    }

    /// Releases the owned key bytes.
    pub fn deinit(self: *CacheKey, allocator: std.mem.Allocator) void {
        allocator.free(self.host);
        allocator.free(self.path);
        if (self.query) |query| {
            allocator.free(query);
        }
        self.* = undefined;
    }
};

/// Stored response metadata and body bytes for one cache entry.
pub const CacheEntry = struct {
    /// Typed request identity for the entry.
    key: CacheKey,
    /// Stored response status.
    status: types.Status,
    /// Stored response body bytes.
    body: []u8,
    /// Stored content type, when known.
    content_type: ?[]u8,
    /// Stored entity tag, when known.
    etag: ?[]u8,
    /// Stored last-modified value, when known.
    last_modified: ?[]u8,
    /// Time when the entry was stored.
    stored_at_ns: i128,
    /// Freshness lifetime for the entry, when known.
    max_age: ?types.Duration,
    /// Current cache state.
    state: CacheState,

    /// Returns the entry freshness at the provided timestamp.
    pub fn freshness(self: CacheEntry, now_ns: i128) CacheState {
        if (self.state == .invalidated) {
            return .invalidated;
        }
        if (self.state == .revalidating) {
            return .revalidating;
        }
        const max_age = self.max_age orelse return .stale;
        if (now_ns - self.stored_at_ns <= @as(i128, @intCast(max_age.toNanos()))) {
            return .fresh;
        }
        return .stale;
    }

    /// Returns true when the entry has validators for conditional revalidation.
    pub fn canRevalidate(self: CacheEntry) bool {
        return self.etag != null or self.last_modified != null;
    }

    /// Releases the owned entry bytes.
    pub fn deinit(self: *CacheEntry, allocator: std.mem.Allocator) void {
        self.key.deinit(allocator);
        allocator.free(self.body);
        if (self.content_type) |value| allocator.free(value);
        if (self.etag) |value| allocator.free(value);
        if (self.last_modified) |value| allocator.free(value);
        self.* = undefined;
    }
};

/// Typed in-memory HTTP cache store.
pub const HttpCache = struct {
    /// Allocator used for entries.
    allocator: std.mem.Allocator,
    /// Stored entries in insertion order.
    entries: std.ArrayListUnmanaged(CacheEntry),

    /// Initializes an empty cache store.
    pub fn init(allocator: std.mem.Allocator) HttpCache {
        return .{
            .allocator = allocator,
            .entries = .{},
        };
    }

    /// Releases all stored entries.
    pub fn deinit(self: *HttpCache) void {
        for (self.entries.items) |*entry| {
            entry.deinit(self.allocator);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Stores an owned copy of the entry.
    pub fn put(self: *HttpCache, entry: CacheEntry) !void {
        if (self.findEntryMut(
            entry.key.method,
            entry.key.scheme,
            entry.key.host,
            entry.key.port,
            entry.key.path,
            entry.key.query,
        )) |existing| {
            existing.deinit(self.allocator);
            existing.* = entry;
            return;
        }
        try self.entries.append(self.allocator, entry);
    }

    /// Returns the first entry matching the provided host and path.
    pub fn get(self: *const HttpCache, host: []const u8, path: []const u8) ?*const CacheEntry {
        for (self.entries.items) |*entry| {
            if (std.ascii.eqlIgnoreCase(entry.key.host, host) and std.mem.eql(u8, entry.key.path, path)) {
                return entry;
            }
        }
        return null;
    }

    /// Returns the first entry matching the provided full request identity.
    pub fn getForRequest(
        self: *const HttpCache,
        method: types.Method,
        scheme: types.Scheme,
        host: []const u8,
        port: types.Port,
        path: []const u8,
        query: ?[]const u8,
    ) ?*const CacheEntry {
        return self.findEntry(method, scheme, host, port, path, query);
    }

    /// Returns the mutable entry matching the provided full request identity.
    pub fn getForRequestMut(
        self: *HttpCache,
        method: types.Method,
        scheme: types.Scheme,
        host: []const u8,
        port: types.Port,
        path: []const u8,
        query: ?[]const u8,
    ) ?*CacheEntry {
        return self.findEntryMut(method, scheme, host, port, path, query);
    }

    /// Returns the cache action appropriate for the provided request identity.
    pub fn lookup(
        self: *const HttpCache,
        method: types.Method,
        scheme: types.Scheme,
        host: []const u8,
        port: types.Port,
        path: []const u8,
        query: ?[]const u8,
        now_ns: i128,
    ) LookupResult {
        const entry = self.findEntry(method, scheme, host, port, path, query) orelse {
            return .{
                .action = .miss,
                .entry = null,
                .source = null,
            };
        };

        return switch (entry.freshness(now_ns)) {
            .fresh => .{
                .action = .serve_cached,
                .entry = entry,
                .source = .cache,
            },
            .stale => .{
                .action = if (entry.canRevalidate()) .revalidate else .unusable,
                .entry = entry,
                .source = if (entry.canRevalidate()) .revalidated else null,
            },
            .revalidating, .invalidated => .{
                .action = .unusable,
                .entry = entry,
                .source = null,
            },
        };
    }

    /// Invalidates the first entry matching the provided host and path.
    pub fn invalidate(self: *HttpCache, host: []const u8, path: []const u8) void {
        for (self.entries.items) |*entry| {
            if (std.ascii.eqlIgnoreCase(entry.key.host, host) and std.mem.eql(u8, entry.key.path, path)) {
                entry.state = .invalidated;
                return;
            }
        }
    }

    /// Invalidates the entry matching the provided full request identity.
    pub fn invalidateRequest(
        self: *HttpCache,
        method: types.Method,
        scheme: types.Scheme,
        host: []const u8,
        port: types.Port,
        path: []const u8,
        query: ?[]const u8,
    ) void {
        if (self.findEntryMut(method, scheme, host, port, path, query)) |entry| {
            entry.state = .invalidated;
        }
    }

    /// Marks the matching entry as revalidating when one exists.
    pub fn beginRevalidation(
        self: *HttpCache,
        method: types.Method,
        scheme: types.Scheme,
        host: []const u8,
        port: types.Port,
        path: []const u8,
        query: ?[]const u8,
    ) bool {
        if (self.findEntryMut(method, scheme, host, port, path, query)) |entry| {
            entry.state = .revalidating;
            return true;
        }
        return false;
    }

    /// Marks the matching entry as fresh after successful revalidation.
    pub fn finishRevalidation(
        self: *HttpCache,
        method: types.Method,
        scheme: types.Scheme,
        host: []const u8,
        port: types.Port,
        path: []const u8,
        query: ?[]const u8,
        stored_at_ns: i128,
        max_age: ?types.Duration,
    ) bool {
        if (self.findEntryMut(method, scheme, host, port, path, query)) |entry| {
            entry.stored_at_ns = stored_at_ns;
            entry.max_age = max_age;
            entry.state = .fresh;
            return true;
        }
        return false;
    }

    /// Returns the first entry matching the full request identity.
    fn findEntry(
        self: *const HttpCache,
        method: types.Method,
        scheme: types.Scheme,
        host: []const u8,
        port: types.Port,
        path: []const u8,
        query: ?[]const u8,
    ) ?*const CacheEntry {
        for (self.entries.items) |*entry| {
            if (entry.key.matches(method, scheme, host, port, path, query)) {
                return entry;
            }
        }
        return null;
    }

    /// Returns the mutable entry matching the full request identity.
    fn findEntryMut(
        self: *HttpCache,
        method: types.Method,
        scheme: types.Scheme,
        host: []const u8,
        port: types.Port,
        path: []const u8,
        query: ?[]const u8,
    ) ?*CacheEntry {
        for (self.entries.items) |*entry| {
            if (entry.key.matches(method, scheme, host, port, path, query)) {
                return entry;
            }
        }
        return null;
    }
};

/// Returns true when two HTTP methods should be treated as equivalent cache keys.
fn methodEql(a: types.Method, b: types.Method) bool {
    const a_tag = std.meta.activeTag(a);
    const b_tag = std.meta.activeTag(b);
    if (a_tag != b_tag) {
        return false;
    }
    return switch (a) {
        .custom => |a_name| switch (b) {
            .custom => |b_name| std.ascii.eqlIgnoreCase(a_name, b_name),
            else => false,
        },
        else => true,
    };
}

test "http cache stores freshness metadata and invalidation state" {
    var cache = HttpCache.init(std.testing.allocator);
    defer cache.deinit();

    try cache.put(.{
        .key = .{
            .method = .get,
            .scheme = .https,
            .host = try std.testing.allocator.dupe(u8, "example.com"),
            .port = types.Port.init(443),
            .path = try std.testing.allocator.dupe(u8, "/config"),
            .query = null,
        },
        .status = .ok,
        .body = try std.testing.allocator.dupe(u8, "{}"),
        .content_type = try std.testing.allocator.dupe(u8, "application/json"),
        .etag = try std.testing.allocator.dupe(u8, "\"abc\""),
        .last_modified = null,
        .stored_at_ns = 0,
        .max_age = types.Duration.fromSeconds(5),
        .state = .fresh,
    });

    const entry = cache.get("example.com", "/config").?;
    try std.testing.expectEqual(CacheState.fresh, entry.freshness(std.time.ns_per_s));

    cache.invalidate("example.com", "/config");
    try std.testing.expectEqual(CacheState.invalidated, cache.get("example.com", "/config").?.state);
}

test "http cache lookup distinguishes fresh stale and revalidating entries" {
    var cache = HttpCache.init(std.testing.allocator);
    defer cache.deinit();

    try cache.put(.{
        .key = .{
            .method = .get,
            .scheme = .https,
            .host = try std.testing.allocator.dupe(u8, "example.com"),
            .port = types.Port.init(443),
            .path = try std.testing.allocator.dupe(u8, "/cached"),
            .query = null,
        },
        .status = .ok,
        .body = try std.testing.allocator.dupe(u8, "cached"),
        .content_type = null,
        .etag = try std.testing.allocator.dupe(u8, "\"etag-1\""),
        .last_modified = null,
        .stored_at_ns = 0,
        .max_age = types.Duration.fromSeconds(1),
        .state = .fresh,
    });

    const fresh = cache.lookup(.get, .https, "example.com", types.Port.init(443), "/cached", null, 0);
    try std.testing.expectEqual(LookupAction.serve_cached, fresh.action);
    try std.testing.expectEqual(CacheSource.cache, fresh.source.?);

    const stale = cache.lookup(.get, .https, "example.com", types.Port.init(443), "/cached", null, 5 * std.time.ns_per_s);
    try std.testing.expectEqual(LookupAction.revalidate, stale.action);
    try std.testing.expect(stale.entry.?.canRevalidate());

    try std.testing.expect(cache.beginRevalidation(.get, .https, "example.com", types.Port.init(443), "/cached", null));
    const revalidating = cache.lookup(.get, .https, "example.com", types.Port.init(443), "/cached", null, 5 * std.time.ns_per_s);
    try std.testing.expectEqual(LookupAction.unusable, revalidating.action);

    try std.testing.expect(cache.finishRevalidation(.get, .https, "example.com", types.Port.init(443), "/cached", null, 10, types.Duration.fromSeconds(3)));
    const refreshed = cache.lookup(.get, .https, "example.com", types.Port.init(443), "/cached", null, std.time.ns_per_s);
    try std.testing.expectEqual(LookupAction.serve_cached, refreshed.action);
}
