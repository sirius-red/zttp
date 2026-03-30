//! Typed in-memory HTTP cache foundations for M6.

const std = @import("std");
const types = @import("../types.zig");

/// Freshness classification for one stored cache entry.
pub const CacheState = enum {
    /// Entry is fresh and reusable without revalidation.
    fresh,
    /// Entry is stale and requires revalidation.
    stale,
    /// Entry has been invalidated and must not be reused.
    invalidated,
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
        const max_age = self.max_age orelse return .stale;
        if (now_ns - self.stored_at_ns <= @as(i128, @intCast(max_age.toNanos()))) {
            return .fresh;
        }
        return .stale;
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

    /// Invalidates the first entry matching the provided host and path.
    pub fn invalidate(self: *HttpCache, host: []const u8, path: []const u8) void {
        for (self.entries.items) |*entry| {
            if (std.ascii.eqlIgnoreCase(entry.key.host, host) and std.mem.eql(u8, entry.key.path, path)) {
                entry.state = .invalidated;
                return;
            }
        }
    }
};

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
