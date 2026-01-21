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

/// Represents an HTTP status code.
pub const Status = enum(u16) {
    /// 100 Continue.
    continue_ = 100,
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

/// Collection of HTTP header fields.
pub const Headers = struct {
    /// Allocator used for header storage.
    allocator: std.mem.Allocator,
    /// Header entries in insertion order.
    entries: std.ArrayListUnmanaged(Header),

    /// Represents a single header field.
    pub const Header = struct {
        /// Header name.
        name: []const u8,
        /// Header value.
        value: []const u8,
    };

    /// Iterates over header fields.
    pub const Iterator = struct {
        /// Header collection being iterated.
        headers: *const Headers,
        /// Current iteration index.
        index: usize,

        /// Returns the next header or null when done.
        pub fn next(self: *Iterator) ?Header {
            if (self.index >= self.headers.entries.items.len) {
                return null;
            }
            const header = self.headers.entries.items[self.index];
            self.index += 1;
            return header;
        }
    };

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
    pub fn iterator(self: *const Headers) Iterator {
        return .{
            .headers = self,
            .index = 0,
        };
    }
};

/// Streaming request/response body reader.
pub const BodyReader = struct {
    /// Error set returned by reader implementations.
    pub const ReadError = anyerror;

    /// Opaque reader context.
    ctx: ?*anyopaque,
    /// Reads up to `dest.len` bytes into `dest`.
    read_fn: *const fn (ctx: ?*anyopaque, dest: []u8) ReadError!usize,
    /// Optional close hook.
    close_fn: ?*const fn (ctx: ?*anyopaque) void,

    /// Reads bytes into `dest`, returning the number of bytes read.
    pub fn read(self: BodyReader, dest: []u8) ReadError!usize {
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
