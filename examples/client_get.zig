//! Minimal zttp client example.

const std = @import("std");
const zttp = @import("zttp");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const url = if (args.len > 1) args[1] else "http://example.com/";
    const parsed = try parseUrl(url);

    var client = zttp.Client.init(allocator, zttp.ClientOptions.default());
    defer client.deinit();

    const uri = zttp.Uri.init(parsed.scheme, parsed.host, parsed.port, parsed.path, parsed.query, null);
    var request = zttp.Request.init(allocator, zttp.Method.get, uri);
    defer request.deinit();

    try appendHostHeader(&request, parsed);

    var handle = try client.request(&request);
    defer handle.deinit();

    var response = try handle.wait();
    defer response.deinit();
    defer if (response.body) |body| body.close();

    var buffer: [256]u8 = undefined;
    const output = try std.fmt.bufPrint(
        &buffer,
        "requested {s}\nstatus: {d}\nprotocol: {s}\n",
        .{ url, response.status.code(), response.version.asBytes() },
    );
    try std.fs.File.stdout().writeAll(output);
}

/// Parsed URL components for the example request.
const ParsedUrl = struct {
    /// URL scheme.
    scheme: zttp.Scheme,
    /// Hostname or IP literal.
    host: []const u8,
    /// Explicit port if present.
    port: ?zttp.Port,
    /// Absolute path beginning with `/`.
    path: []const u8,
    /// Optional query string without leading `?`.
    query: ?[]const u8,
};

/// Error set returned by the example URL parser.
const ParseUrlError = error{
    EmptyUrl,
    InvalidUrl,
    UnsupportedScheme,
    MissingHost,
    InvalidPort,
    UnsupportedIpv6,
};

/// Parses a basic `http://` or `https://` URL.
fn parseUrl(url: []const u8) ParseUrlError!ParsedUrl {
    if (url.len == 0) {
        return error.EmptyUrl;
    }

    const scheme_sep = std.mem.indexOf(u8, url, "://") orelse return error.InvalidUrl;
    const scheme_bytes = url[0..scheme_sep];
    const scheme = if (std.ascii.eqlIgnoreCase(scheme_bytes, "http"))
        zttp.Scheme.http
    else if (std.ascii.eqlIgnoreCase(scheme_bytes, "https"))
        zttp.Scheme.https
    else
        return error.UnsupportedScheme;

    const rest = url[scheme_sep + 3 ..];
    if (rest.len == 0) {
        return error.MissingHost;
    }
    if (rest[0] == '[') {
        return error.UnsupportedIpv6;
    }

    var authority_end: usize = rest.len;
    for (rest, 0..) |byte, index| {
        if (byte == '/' or byte == '?' or byte == '#') {
            authority_end = index;
            break;
        }
    }

    const authority = rest[0..authority_end];
    if (authority.len == 0) {
        return error.MissingHost;
    }

    var host = authority;
    var port: ?zttp.Port = null;
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        if (colon == 0) return error.MissingHost;
        const port_value = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch return error.InvalidPort;
        host = authority[0..colon];
        port = zttp.Port.init(port_value);
    }

    var path: []const u8 = "/";
    var query: ?[]const u8 = null;
    if (authority_end < rest.len) {
        const suffix = rest[authority_end..];
        if (suffix.len > 0 and suffix[0] == '/') {
            var path_end = suffix.len;
            if (std.mem.indexOfAny(u8, suffix, "?#")) |delimiter| {
                path_end = delimiter;
            }
            path = suffix[0..path_end];
            if (path_end < suffix.len and suffix[path_end] == '?') {
                query = suffix[path_end + 1 ..];
            }
        } else if (suffix.len > 0 and suffix[0] == '?') {
            query = suffix[1..];
        }
    }

    return .{
        .scheme = scheme,
        .host = host,
        .port = port,
        .path = path,
        .query = query,
    };
}

/// Adds the required Host header to the example request.
fn appendHostHeader(request: *zttp.Request, parsed: ParsedUrl) !void {
    if (parsed.port) |port| {
        if (port.toInt() != parsed.scheme.defaultPort().toInt()) {
            var buffer: [256]u8 = undefined;
            const value = try std.fmt.bufPrint(&buffer, "{s}:{d}", .{ parsed.host, port.toInt() });
            try request.headers.append("Host", value);
            return;
        }
    }
    try request.headers.append("Host", parsed.host);
}
