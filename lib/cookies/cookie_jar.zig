//! In-memory cookie jar and RFC6265 helpers.

const std = @import("std");
const types = @import("../types.zig");

/// Thread-safe in-memory cookie jar.
pub const CookieJar = struct {
    /// Allocator used for cookie storage.
    allocator: std.mem.Allocator,
    /// Jar configuration options.
    options: Options,
    /// Mutex guarding cookie state.
    mutex: std.Thread.Mutex,
    /// Stored cookies.
    entries: std.ArrayListUnmanaged(Cookie),
    /// Monotonic counter for creation ordering.
    next_id: u64,

    /// Error set returned by cookie jar operations.
    pub const Error = std.mem.Allocator.Error;

    /// Cookie jar configuration options.
    pub const Options = struct {
        /// Maximum number of cookies to retain.
        max_entries: usize,

        /// Returns default cookie jar options.
        pub fn default() Options {
            return .{ .max_entries = 256 };
        }
    };

    /// Timestamp in seconds since the Unix epoch.
    pub const Timestamp = struct {
        /// Seconds since 1970-01-01T00:00:00Z.
        seconds: i64,

        /// Creates a timestamp from seconds.
        pub fn fromSeconds(seconds: i64) Timestamp {
            return .{ .seconds = seconds };
        }

        /// Returns the timestamp in seconds.
        pub fn toSeconds(self: Timestamp) i64 {
            return self.seconds;
        }

        /// Returns the current wall-clock timestamp.
        pub fn now() Timestamp {
            return .{ .seconds = std.time.timestamp() };
        }
    };

    /// SameSite attribute value.
    pub const SameSite = enum {
        /// No SameSite attribute was provided.
        unspecified,
        /// SameSite=Lax.
        lax,
        /// SameSite=Strict.
        strict,
        /// SameSite=None.
        none,
    };

    /// Initializes a cookie jar with the provided allocator and options.
    pub fn init(allocator: std.mem.Allocator, options: Options) CookieJar {
        return .{
            .allocator = allocator,
            .options = options,
            .mutex = .{},
            .entries = .{},
            .next_id = 0,
        };
    }

    /// Releases all cookie storage.
    pub fn deinit(self: *CookieJar) void {
        self.mutex.lock();
        for (self.entries.items) |*cookie| {
            cookie.deinit(self.allocator);
        }
        self.entries.deinit(self.allocator);
        self.mutex.unlock();
    }

    /// Stores cookies from response headers.
    pub fn storeFromResponse(
        self: *CookieJar,
        uri: types.Uri,
        headers: *const types.Headers,
        now: Timestamp,
    ) Error!void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var iter = headers.iterator();
        while (iter.next()) |header| {
            if (!std.ascii.eqlIgnoreCase(header.name, "set-cookie")) {
                continue;
            }

            const parsed = parseSetCookie(header.value, uri, now) orelse continue;

            if (isExpired(parsed, now)) {
                self.removeCookieLocked(parsed);
                continue;
            }

            try self.upsertCookieLocked(parsed);
        }

        self.pruneExpiredLocked(now);
        self.evictIfNeededLocked();
    }

    /// Builds a Cookie header value for the request URI.
    /// Returns null when no cookies match.
    pub fn buildCookieHeader(
        self: *CookieJar,
        allocator: std.mem.Allocator,
        uri: types.Uri,
        now: Timestamp,
    ) Error!?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.pruneExpiredLocked(now);

        var matches = std.ArrayListUnmanaged(*Cookie){};
        defer matches.deinit(allocator);

        const request_path = normalizePath(uri.path);
        for (self.entries.items) |*cookie| {
            if (!cookieMatches(cookie, uri, request_path, now)) {
                continue;
            }
            try matches.append(allocator, cookie);
        }

        if (matches.items.len == 0) {
            return null;
        }

        std.sort.insertion(*Cookie, matches.items, {}, cookieLessThan);

        var buffer = std.ArrayListUnmanaged(u8){};
        defer buffer.deinit(allocator);

        var first = true;
        for (matches.items) |cookie| {
            if (!first) {
                try buffer.appendSlice(allocator, "; ");
            }
            first = false;
            try buffer.appendSlice(allocator, cookie.name);
            try buffer.append(allocator, '=');
            try buffer.appendSlice(allocator, cookie.value);
        }

        const slice = try buffer.toOwnedSlice(allocator);
        return slice;
    }

    /// Removes expired cookies based on the provided timestamp.
    fn pruneExpiredLocked(self: *CookieJar, now: Timestamp) void {
        var index: usize = 0;
        while (index < self.entries.items.len) {
            const cookie = self.entries.items[index];
            if (!isExpiredCookie(cookie, now)) {
                index += 1;
                continue;
            }
            self.removeIndexLocked(index);
        }
    }

    /// Inserts or updates a cookie in the jar.
    fn upsertCookieLocked(self: *CookieJar, parsed: ParsedCookie) Error!void {
        if (self.options.max_entries == 0) {
            return;
        }

        if (self.findCookieIndex(parsed)) |index| {
            self.entries.items[index].deinit(self.allocator);
            self.entries.items[index] = try cookieFromParsed(self.allocator, parsed, self.next_id);
            self.next_id += 1;
            return;
        }

        try self.entries.append(
            self.allocator,
            try cookieFromParsed(self.allocator, parsed, self.next_id),
        );
        self.next_id += 1;
    }

    /// Removes a matching cookie based on the parsed key.
    fn removeCookieLocked(self: *CookieJar, parsed: ParsedCookie) void {
        if (self.findCookieIndex(parsed)) |index| {
            self.removeIndexLocked(index);
        }
    }

    /// Removes a cookie at the provided index.
    fn removeIndexLocked(self: *CookieJar, index: usize) void {
        var cookie = self.entries.items[index];
        cookie.deinit(self.allocator);
        _ = self.entries.swapRemove(index);
    }

    /// Returns the index of a cookie matching the parsed key.
    fn findCookieIndex(self: *CookieJar, parsed: ParsedCookie) ?usize {
        for (self.entries.items, 0..) |cookie, idx| {
            if (cookieKeyEquals(cookie, parsed)) {
                return idx;
            }
        }
        return null;
    }

    /// Evicts cookies when exceeding the maximum entry count.
    fn evictIfNeededLocked(self: *CookieJar) void {
        if (self.options.max_entries == 0) {
            while (self.entries.items.len > 0) {
                self.removeIndexLocked(self.entries.items.len - 1);
            }
            return;
        }

        while (self.entries.items.len > self.options.max_entries) {
            var oldest_index: usize = 0;
            var oldest_id = self.entries.items[0].created_id;
            for (self.entries.items, 0..) |cookie, idx| {
                if (cookie.created_id < oldest_id) {
                    oldest_id = cookie.created_id;
                    oldest_index = idx;
                }
            }
            self.removeIndexLocked(oldest_index);
        }
    }
};

/// Stored cookie record.
const Cookie = struct {
    /// Cookie name.
    name: []u8,
    /// Cookie value.
    value: []u8,
    /// Cookie domain in lowercase.
    domain: []u8,
    /// Cookie path.
    path: []u8,
    /// Indicates the cookie is host-only.
    host_only: bool,
    /// Indicates the cookie requires a secure scheme.
    secure: bool,
    /// Indicates the cookie should be hidden from scripts.
    http_only: bool,
    /// SameSite attribute value.
    same_site: CookieJar.SameSite,
    /// Expiration timestamp.
    expires: ?CookieJar.Timestamp,
    /// Creation order used for eviction and sorting.
    created_id: u64,

    /// Releases cookie storage.
    fn deinit(self: *Cookie, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
        allocator.free(self.domain);
        allocator.free(self.path);
        self.* = undefined;
    }
};

/// Parsed cookie attributes before allocation.
const ParsedCookie = struct {
    /// Cookie name.
    name: []const u8,
    /// Cookie value.
    value: []const u8,
    /// Cookie domain.
    domain: []const u8,
    /// Cookie path.
    path: []const u8,
    /// Indicates the cookie is host-only.
    host_only: bool,
    /// Indicates the cookie requires a secure scheme.
    secure: bool,
    /// Indicates the cookie should be hidden from scripts.
    http_only: bool,
    /// SameSite attribute value.
    same_site: CookieJar.SameSite,
    /// Expiration timestamp.
    expires: ?CookieJar.Timestamp,
};

/// Returns true when the parsed cookie is expired.
fn isExpired(parsed: ParsedCookie, now: CookieJar.Timestamp) bool {
    if (parsed.expires) |expires| {
        return expires.toSeconds() <= now.toSeconds();
    }
    return false;
}

/// Returns true when the stored cookie is expired.
fn isExpiredCookie(cookie: Cookie, now: CookieJar.Timestamp) bool {
    if (cookie.expires) |expires| {
        return expires.toSeconds() <= now.toSeconds();
    }
    return false;
}

/// Creates an allocated cookie record from parsed data.
fn cookieFromParsed(
    allocator: std.mem.Allocator,
    parsed: ParsedCookie,
    created_id: u64,
) std.mem.Allocator.Error!Cookie {
    const name = try allocator.dupe(u8, parsed.name);
    errdefer allocator.free(name);
    const value = try allocator.dupe(u8, parsed.value);
    errdefer allocator.free(value);
    const domain = try lowerCaseCopy(allocator, parsed.domain);
    errdefer allocator.free(domain);
    const path = try allocator.dupe(u8, parsed.path);
    errdefer allocator.free(path);

    return .{
        .name = name,
        .value = value,
        .domain = domain,
        .path = path,
        .host_only = parsed.host_only,
        .secure = parsed.secure,
        .http_only = parsed.http_only,
        .same_site = parsed.same_site,
        .expires = parsed.expires,
        .created_id = created_id,
    };
}

/// Returns true when the cookie key matches the parsed cookie.
fn cookieKeyEquals(cookie: Cookie, parsed: ParsedCookie) bool {
    return std.mem.eql(u8, cookie.name, parsed.name) and
        std.mem.eql(u8, cookie.path, parsed.path) and
        std.ascii.eqlIgnoreCase(cookie.domain, parsed.domain);
}

/// Returns true when a cookie matches the request URI.
fn cookieMatches(
    cookie: *const Cookie,
    uri: types.Uri,
    request_path: []const u8,
    now: CookieJar.Timestamp,
) bool {
    if (cookie.secure and uri.scheme != .https) {
        return false;
    }
    if (isExpiredCookie(cookie.*, now)) {
        return false;
    }
    if (!domainMatches(cookie, uri.host)) {
        return false;
    }
    return pathMatches(request_path, cookie.path);
}

/// Returns true when the cookie domain matches the host.
fn domainMatches(cookie: *const Cookie, host: []const u8) bool {
    if (cookie.host_only) {
        return std.ascii.eqlIgnoreCase(host, cookie.domain);
    }
    return domainMatch(host, cookie.domain);
}

/// Returns true when the request path matches the cookie path.
fn pathMatches(request_path: []const u8, cookie_path: []const u8) bool {
    if (std.mem.eql(u8, cookie_path, "/")) {
        return true;
    }
    if (!std.mem.startsWith(u8, request_path, cookie_path)) {
        return false;
    }
    if (request_path.len == cookie_path.len) {
        return true;
    }
    if (cookie_path[cookie_path.len - 1] == '/') {
        return true;
    }
    return request_path[cookie_path.len] == '/';
}

/// Returns true when the host matches the cookie domain.
fn domainMatch(host: []const u8, domain: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(host, domain)) {
        return true;
    }
    if (host.len <= domain.len) {
        return false;
    }
    const offset = host.len - domain.len;
    if (!std.ascii.eqlIgnoreCase(host[offset..], domain)) {
        return false;
    }
    return host[offset - 1] == '.';
}

/// Returns true when the host looks like an IP address.
fn isIpAddress(host: []const u8) bool {
    if (std.mem.indexOfScalar(u8, host, ':') != null) {
        return true;
    }

    var saw_dot = false;
    for (host) |byte| {
        if (byte == '.') {
            saw_dot = true;
            continue;
        }
        if (byte < '0' or byte > '9') {
            return false;
        }
    }
    return saw_dot;
}

/// Returns a trimmed view of leading and trailing whitespace.
fn trimWhitespace(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t");
}

/// Returns a path suitable for cookie matching.
fn normalizePath(path: []const u8) []const u8 {
    if (path.len == 0) {
        return "/";
    }
    if (path[0] != '/') {
        return "/";
    }
    return path;
}

/// Returns the default cookie path for a request path.
fn defaultCookiePath(path: []const u8) []const u8 {
    const normalized = normalizePath(path);
    if (std.mem.eql(u8, normalized, "/")) {
        return "/";
    }
    if (std.mem.lastIndexOfScalar(u8, normalized, '/')) |slash| {
        if (slash == 0) {
            return "/";
        }
        return normalized[0..slash];
    }
    return "/";
}

/// Returns true when the cookie name uses allowed bytes.
fn validCookieName(name: []const u8) bool {
    if (name.len == 0) {
        return false;
    }
    for (name) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == ';' or byte == '=' or byte == ',') {
            return false;
        }
    }
    return true;
}

/// Returns true when the cookie value uses allowed bytes.
fn validCookieValue(value: []const u8) bool {
    for (value) |byte| {
        if (byte < 0x20 or byte == 0x7f or byte == ';') {
            return false;
        }
    }
    return true;
}

/// Parses a Set-Cookie header value.
fn parseSetCookie(
    value: []const u8,
    uri: types.Uri,
    now: CookieJar.Timestamp,
) ?ParsedCookie {
    var parts = std.mem.splitScalar(u8, value, ';');
    const first = parts.next() orelse return null;
    const name_value = trimWhitespace(first);
    const eq_index = std.mem.indexOfScalar(u8, name_value, '=') orelse return null;

    const raw_name = trimWhitespace(name_value[0..eq_index]);
    const raw_value = trimWhitespace(name_value[eq_index + 1 ..]);

    if (!validCookieName(raw_name) or !validCookieValue(raw_value)) {
        return null;
    }

    var domain_attr: ?[]const u8 = null;
    var path_attr: ?[]const u8 = null;
    var max_age: ?i64 = null;
    var expires: ?CookieJar.Timestamp = null;
    var secure = false;
    var http_only = false;
    var same_site = CookieJar.SameSite.unspecified;

    while (parts.next()) |raw_attr| {
        const attr = trimWhitespace(raw_attr);
        if (attr.len == 0) {
            continue;
        }

        if (std.mem.indexOfScalar(u8, attr, '=')) |attr_eq| {
            const key = trimWhitespace(attr[0..attr_eq]);
            const attr_value = trimWhitespace(attr[attr_eq + 1 ..]);

            if (std.ascii.eqlIgnoreCase(key, "domain")) {
                domain_attr = trimLeadingDot(attr_value);
            } else if (std.ascii.eqlIgnoreCase(key, "path")) {
                path_attr = attr_value;
            } else if (std.ascii.eqlIgnoreCase(key, "max-age")) {
                max_age = std.fmt.parseInt(i64, attr_value, 10) catch null;
            } else if (std.ascii.eqlIgnoreCase(key, "expires")) {
                expires = parseHttpDate(attr_value);
            } else if (std.ascii.eqlIgnoreCase(key, "samesite")) {
                same_site = parseSameSite(attr_value);
            }
        } else {
            if (std.ascii.eqlIgnoreCase(attr, "secure")) {
                secure = true;
            } else if (std.ascii.eqlIgnoreCase(attr, "httponly")) {
                http_only = true;
            }
        }
    }

    var domain = uri.host;
    var host_only = true;
    if (domain_attr) |attr_domain| {
        if (attr_domain.len == 0) {
            return null;
        }
        if (isIpAddress(uri.host)) {
            return null;
        }
        if (!domainMatch(uri.host, attr_domain)) {
            return null;
        }
        domain = attr_domain;
        host_only = false;
    }

    var path = defaultCookiePath(uri.path);
    if (path_attr) |attr_path| {
        if (attr_path.len > 0 and attr_path[0] == '/') {
            path = attr_path;
        }
    }

    var final_expires = expires;
    if (max_age) |delta| {
        if (delta <= 0) {
            final_expires = CookieJar.Timestamp.fromSeconds(now.toSeconds() - 1);
        } else {
            final_expires = CookieJar.Timestamp.fromSeconds(now.toSeconds() + delta);
        }
    }

    return .{
        .name = raw_name,
        .value = raw_value,
        .domain = domain,
        .path = path,
        .host_only = host_only,
        .secure = secure,
        .http_only = http_only,
        .same_site = same_site,
        .expires = final_expires,
    };
}

/// Removes a leading dot from a domain value.
fn trimLeadingDot(value: []const u8) []const u8 {
    if (value.len > 0 and value[0] == '.') {
        return value[1..];
    }
    return value;
}

/// Parses a SameSite attribute value.
fn parseSameSite(value: []const u8) CookieJar.SameSite {
    if (std.ascii.eqlIgnoreCase(value, "lax")) {
        return .lax;
    }
    if (std.ascii.eqlIgnoreCase(value, "strict")) {
        return .strict;
    }
    if (std.ascii.eqlIgnoreCase(value, "none")) {
        return .none;
    }
    return .unspecified;
}

/// Returns a lowercased copy of the provided value.
fn lowerCaseCopy(allocator: std.mem.Allocator, value: []const u8) std.mem.Allocator.Error![]u8 {
    const copy = try allocator.dupe(u8, value);
    for (copy) |*byte| {
        byte.* = std.ascii.toLower(byte.*);
    }
    return copy;
}

/// Returns true when the left cookie should sort before the right cookie.
fn cookieLessThan(_: void, left: *Cookie, right: *Cookie) bool {
    if (left.path.len != right.path.len) {
        return left.path.len > right.path.len;
    }
    return left.created_id < right.created_id;
}

/// Parses an HTTP-date for the Expires attribute.
fn parseHttpDate(value: []const u8) ?CookieJar.Timestamp {
    var trimmed = trimWhitespace(value);
    if (std.mem.indexOfScalar(u8, trimmed, ',')) |comma| {
        trimmed = trimWhitespace(trimmed[comma + 1 ..]);
    }

    var iter = std.mem.tokenizeScalar(u8, trimmed, ' ');
    const day_str = iter.next() orelse return null;
    const month_str = iter.next() orelse return null;
    const year_str = iter.next() orelse return null;
    const time_str = iter.next() orelse return null;
    const zone_str = iter.next() orelse return null;

    if (!std.ascii.eqlIgnoreCase(zone_str, "GMT")) {
        return null;
    }

    const day = std.fmt.parseInt(i32, day_str, 10) catch return null;
    const month = parseMonth(month_str) orelse return null;
    const year = std.fmt.parseInt(i32, year_str, 10) catch return null;

    var time_iter = std.mem.splitScalar(u8, time_str, ':');
    const hour_str = time_iter.next() orelse return null;
    const min_str = time_iter.next() orelse return null;
    const sec_str = time_iter.next() orelse return null;
    if (time_iter.next() != null) {
        return null;
    }

    const hour = std.fmt.parseInt(i32, hour_str, 10) catch return null;
    const minute = std.fmt.parseInt(i32, min_str, 10) catch return null;
    const second = std.fmt.parseInt(i32, sec_str, 10) catch return null;

    const seconds = unixSecondsFromDate(year, month, day, hour, minute, second) orelse return null;
    return CookieJar.Timestamp.fromSeconds(seconds);
}

/// Parses a month abbreviation into a 1-based month number.
fn parseMonth(value: []const u8) ?i32 {
    if (std.ascii.eqlIgnoreCase(value, "jan")) return 1;
    if (std.ascii.eqlIgnoreCase(value, "feb")) return 2;
    if (std.ascii.eqlIgnoreCase(value, "mar")) return 3;
    if (std.ascii.eqlIgnoreCase(value, "apr")) return 4;
    if (std.ascii.eqlIgnoreCase(value, "may")) return 5;
    if (std.ascii.eqlIgnoreCase(value, "jun")) return 6;
    if (std.ascii.eqlIgnoreCase(value, "jul")) return 7;
    if (std.ascii.eqlIgnoreCase(value, "aug")) return 8;
    if (std.ascii.eqlIgnoreCase(value, "sep")) return 9;
    if (std.ascii.eqlIgnoreCase(value, "oct")) return 10;
    if (std.ascii.eqlIgnoreCase(value, "nov")) return 11;
    if (std.ascii.eqlIgnoreCase(value, "dec")) return 12;
    return null;
}

/// Converts a UTC date/time into seconds since the Unix epoch.
fn unixSecondsFromDate(
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    minute: i32,
    second: i32,
) ?i64 {
    if (month < 1 or month > 12) {
        return null;
    }
    if (hour < 0 or hour > 23) {
        return null;
    }
    if (minute < 0 or minute > 59) {
        return null;
    }
    if (second < 0 or second > 60) {
        return null;
    }

    const max_day = daysInMonth(year, month);
    if (day < 1 or day > max_day) {
        return null;
    }

    const days = daysFromCivil(year, month, day);
    const total = days * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + @as(i64, second);
    return total;
}

/// Returns the number of days in the month for the provided year.
fn daysInMonth(year: i32, month: i32) i32 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 0,
    };
}

/// Returns true when the year is a leap year.
fn isLeapYear(year: i32) bool {
    if (@mod(year, 4) != 0) return false;
    if (@mod(year, 100) != 0) return true;
    return @mod(year, 400) == 0;
}

/// Returns days since 1970-01-01 for a civil date.
fn daysFromCivil(year: i32, month: i32, day: i32) i64 {
    var y = @as(i64, year);
    const m = @as(i64, month);
    const d = @as(i64, day);

    y -= if (m <= 2) 1 else 0;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const m_adj = m + @as(i64, if (m > 2) -3 else 9);
    const doy = @divFloor(153 * m_adj + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

test "cookie jar matches host-only cookies" {
    var jar = CookieJar.init(std.testing.allocator, CookieJar.Options.default());
    defer jar.deinit();

    var headers = types.Headers.init(std.testing.allocator);
    defer headers.deinit();

    try headers.append("Set-Cookie", "a=1");

    const uri = types.Uri.init(.http, "example.com", types.Port.init(80), "/", null, null);
    const now = CookieJar.Timestamp.fromSeconds(1000);

    try jar.storeFromResponse(uri, &headers, now);

    const header = try jar.buildCookieHeader(std.testing.allocator, uri, now);
    defer if (header) |value| std.testing.allocator.free(value);
    try std.testing.expect(header != null);

    const sub_uri = types.Uri.init(.http, "sub.example.com", types.Port.init(80), "/", null, null);
    const sub_header = try jar.buildCookieHeader(std.testing.allocator, sub_uri, now);
    defer if (sub_header) |value| std.testing.allocator.free(value);
    try std.testing.expect(sub_header == null);
}

test "cookie jar respects domain attribute" {
    var jar = CookieJar.init(std.testing.allocator, CookieJar.Options.default());
    defer jar.deinit();

    var headers = types.Headers.init(std.testing.allocator);
    defer headers.deinit();

    try headers.append("Set-Cookie", "a=1; Domain=example.com");

    const uri = types.Uri.init(.http, "www.example.com", types.Port.init(80), "/", null, null);
    const now = CookieJar.Timestamp.fromSeconds(2000);

    try jar.storeFromResponse(uri, &headers, now);

    const sub_uri = types.Uri.init(.http, "api.example.com", types.Port.init(80), "/", null, null);
    const sub_header = try jar.buildCookieHeader(std.testing.allocator, sub_uri, now);
    defer if (sub_header) |value| std.testing.allocator.free(value);
    try std.testing.expect(sub_header != null);

    const bad_uri = types.Uri.init(.http, "evil.com", types.Port.init(80), "/", null, null);
    const bad_header = try jar.buildCookieHeader(std.testing.allocator, bad_uri, now);
    defer if (bad_header) |value| std.testing.allocator.free(value);
    try std.testing.expect(bad_header == null);
}

test "cookie jar respects path matching" {
    var jar = CookieJar.init(std.testing.allocator, CookieJar.Options.default());
    defer jar.deinit();

    var headers = types.Headers.init(std.testing.allocator);
    defer headers.deinit();

    try headers.append("Set-Cookie", "a=1; Path=/docs");

    const uri = types.Uri.init(.http, "example.com", types.Port.init(80), "/docs/index", null, null);
    const now = CookieJar.Timestamp.fromSeconds(3000);

    try jar.storeFromResponse(uri, &headers, now);

    const ok_uri = types.Uri.init(.http, "example.com", types.Port.init(80), "/docs/guide", null, null);
    const ok_header = try jar.buildCookieHeader(std.testing.allocator, ok_uri, now);
    defer if (ok_header) |value| std.testing.allocator.free(value);
    try std.testing.expect(ok_header != null);

    const bad_uri = types.Uri.init(.http, "example.com", types.Port.init(80), "/other", null, null);
    const bad_header = try jar.buildCookieHeader(std.testing.allocator, bad_uri, now);
    defer if (bad_header) |value| std.testing.allocator.free(value);
    try std.testing.expect(bad_header == null);
}

test "cookie jar expires cookies via max-age" {
    var jar = CookieJar.init(std.testing.allocator, CookieJar.Options.default());
    defer jar.deinit();

    var headers = types.Headers.init(std.testing.allocator);
    defer headers.deinit();

    try headers.append("Set-Cookie", "a=1; Max-Age=1");

    const uri = types.Uri.init(.http, "example.com", types.Port.init(80), "/", null, null);
    const now = CookieJar.Timestamp.fromSeconds(4000);

    try jar.storeFromResponse(uri, &headers, now);

    const later = CookieJar.Timestamp.fromSeconds(4002);
    const header = try jar.buildCookieHeader(std.testing.allocator, uri, later);
    defer if (header) |value| std.testing.allocator.free(value);
    try std.testing.expect(header == null);
}

test "cookie jar evicts oldest entries" {
    var options = CookieJar.Options.default();
    options.max_entries = 1;

    var jar = CookieJar.init(std.testing.allocator, options);
    defer jar.deinit();

    const uri = types.Uri.init(.http, "example.com", types.Port.init(80), "/", null, null);
    const now = CookieJar.Timestamp.fromSeconds(5000);

    {
        var headers = types.Headers.init(std.testing.allocator);
        defer headers.deinit();
        try headers.append("Set-Cookie", "a=1");
        try jar.storeFromResponse(uri, &headers, now);
    }

    {
        var headers = types.Headers.init(std.testing.allocator);
        defer headers.deinit();
        try headers.append("Set-Cookie", "b=2");
        try jar.storeFromResponse(uri, &headers, now);
    }

    const header = try jar.buildCookieHeader(std.testing.allocator, uri, now);
    defer if (header) |value| std.testing.allocator.free(value);
    try std.testing.expect(header != null);
    try std.testing.expectEqualStrings("b=2", header.?);
}
