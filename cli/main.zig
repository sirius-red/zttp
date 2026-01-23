//! Command-line interface for the zttp library.

const std = @import("std");
const zttp = @import("zttp");

/// General help text for the CLI.
const help_text =
    \\zttp - Zig HTTP client/server
    \\
    \\Usage:
    \\  zttp <command> [options]
    \\
    \\Commands:
    \\  request   HTTP client request
    \\  server    HTTP server harness (stub)
    \\
    \\Flags:
    \\  -h, --help  Show help
    \\
;

/// Help text for the request subcommand.
const request_help =
    \\zttp request - HTTP client request
    \\
    \\Usage:
    \\  zttp request [options] <url>
    \\
    \\Options:
    \\  -h, --help  Show help
    \\
    \\Notes:
    \\  Only http:// URLs are supported in this build.
    \\
;

/// Help text for the server subcommand.
const server_help =
    \\zttp server - HTTP server harness (stub)
    \\
    \\Usage:
    \\  zttp server [options]
    \\
    \\Options:
    \\  -h, --help  Show help
    \\
;

/// CLI application wrapper.
const Cli = struct {
    /// Allocator used for argument parsing.
    allocator: std.mem.Allocator,
    /// Writer for standard output.
    out: std.fs.File.Writer,
    /// Writer for standard error.
    err: std.fs.File.Writer,

    /// Executes the CLI with the provided argument list.
    pub fn run(self: *Cli, args: []const []const u8) !void {
        if (args.len <= 1 or hasHelpFlag(args[1..])) {
            try self.printHelp();
            return;
        }

        const command = args[1];
        if (std.mem.eql(u8, command, "request")) {
            try self.handleRequest(args[2..]);
            return;
        }

        if (std.mem.eql(u8, command, "server")) {
            try self.handleServer(args[2..]);
            return;
        }

        try self.err.print("zttp: unknown command '{s}'\n", .{command});
        return error.InvalidArguments;
    }

    /// Prints the general help text.
    fn printHelp(self: *Cli) !void {
        try self.out.writeAll(help_text);
    }

    /// Prints the help text for the request subcommand.
    fn printRequestHelp(self: *Cli) !void {
        try self.out.writeAll(request_help);
    }

    /// Prints the help text for the server subcommand.
    fn printServerHelp(self: *Cli) !void {
        try self.out.writeAll(server_help);
    }

    /// Handles the request subcommand.
    fn handleRequest(self: *Cli, args: []const []const u8) !void {
        if (args.len == 0 or hasHelpFlag(args)) {
            try self.printRequestHelp();
            return;
        }

        if (args.len != 1) {
            try self.err.writeAll("zttp request: expected a single URL argument\n");
            return error.InvalidArguments;
        }

        const parsed = parseUrl(args[0]) catch |err| {
            try self.err.print("zttp request: {s}\n", .{@errorName(err)});
            return error.InvalidArguments;
        };

        var client = zttp.Client.init(self.allocator, zttp.Client.Options.default());
        defer client.deinit();

        const uri = zttp.Uri.init(
            parsed.scheme,
            parsed.host,
            parsed.port,
            parsed.path,
            parsed.query,
            null,
        );

        var request = zttp.Request.init(self.allocator, zttp.Method.get, uri);
        defer request.deinit();
        try self.addHostHeader(&request, parsed);

        var handle = try client.request(&request);
        defer handle.deinit();

        var response = try handle.wait();
        defer response.deinit();

        try self.err.print("{s} {d}\n", .{ response.version.asBytes(), response.status.code() });

        if (response.body) |body_reader| {
            defer body_reader.close();
            try self.writeBody(body_reader);
        }
    }

    /// Handles the server subcommand.
    fn handleServer(self: *Cli, args: []const []const u8) !void {
        if (args.len == 0 or hasHelpFlag(args)) {
            try self.printServerHelp();
            return;
        }

        _ = zttp.Version.http_1_1;
        _ = zttp.Status.ok;

        try self.err.writeAll("zttp server: not implemented\n");
        return error.NotImplemented;
    }

    /// Returns true when any argument is a help flag.
    fn hasHelpFlag(args: []const []const u8) bool {
        for (args) |arg| {
            if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
                return true;
            }
        }
        return false;
    }

    /// Parsed URL components for the request command.
    const ParsedUrl = struct {
        /// URL scheme.
        scheme: zttp.Scheme,
        /// Hostname or IP literal without brackets.
        host: []const u8,
        /// Explicit port if provided.
        port: ?zttp.Port,
        /// Absolute path beginning with '/'.
        path: []const u8,
        /// Optional query string without leading '?'.
        query: ?[]const u8,
    };

    /// Error set returned by URL parsing.
    const ParseUrlError = error{
        /// URL input was empty.
        EmptyUrl,
        /// URL was missing required components.
        InvalidUrl,
        /// URL scheme is not supported.
        UnsupportedScheme,
        /// URL did not include a host component.
        MissingHost,
        /// URL port was invalid.
        InvalidPort,
        /// IPv6 literals are not supported yet.
        UnsupportedIpv6,
    };

    /// Parses an http:// URL into components.
    fn parseUrl(url: []const u8) ParseUrlError!ParsedUrl {
        if (url.len == 0) {
            return error.EmptyUrl;
        }

        const scheme_sep = std.mem.indexOf(u8, url, "://") orelse return error.InvalidUrl;
        const scheme_bytes = url[0..scheme_sep];
        const scheme = if (std.ascii.eqlIgnoreCase(scheme_bytes, "http"))
            zttp.Scheme.http
        else if (std.ascii.eqlIgnoreCase(scheme_bytes, "https"))
            return error.UnsupportedScheme
        else
            return error.UnsupportedScheme;

        var rest = url[scheme_sep + 3 ..];
        if (rest.len == 0) {
            return error.MissingHost;
        }
        if (rest[0] == '[') {
            return error.UnsupportedIpv6;
        }

        var authority_end: usize = rest.len;
        var index: usize = 0;
        while (index < rest.len) : (index += 1) {
            const byte = rest[index];
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
            if (colon == 0) {
                return error.MissingHost;
            }
            const port_bytes = authority[colon + 1 ..];
            if (port_bytes.len == 0) {
                return error.InvalidPort;
            }
            const port_value = std.fmt.parseInt(u16, port_bytes, 10) catch return error.InvalidPort;
            host = authority[0..colon];
            port = zttp.Port.init(port_value);
        }

        var path: []const u8 = "/";
        var query: ?[]const u8 = null;

        if (authority_end < rest.len) {
            const suffix = rest[authority_end..];
            if (suffix.len > 0 and suffix[0] == '/') {
                var path_end: usize = suffix.len;
                if (std.mem.indexOfAny(u8, suffix, "?#")) |delimiter| {
                    path_end = delimiter;
                }
                path = if (path_end == 0) "/" else suffix[0..path_end];
                if (path_end < suffix.len and suffix[path_end] == '?') {
                    const query_start = path_end + 1;
                    const query_tail = suffix[query_start..];
                    if (std.mem.indexOfScalar(u8, query_tail, '#')) |hash| {
                        query = query_tail[0..hash];
                    } else {
                        query = query_tail;
                    }
                }
            } else if (suffix.len > 0 and suffix[0] == '?') {
                const query_tail = suffix[1..];
                if (std.mem.indexOfScalar(u8, query_tail, '#')) |hash| {
                    query = query_tail[0..hash];
                } else {
                    query = query_tail;
                }
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

    /// Adds the required Host header to the request.
    fn addHostHeader(self: *Cli, request: *zttp.Request, parsed: ParsedUrl) !void {
        const default_port = parsed.scheme.defaultPort().toInt();
        if (parsed.port) |port| {
            if (port.toInt() != default_port) {
                const host_value = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{
                    parsed.host,
                    port.toInt(),
                });
                defer self.allocator.free(host_value);
                try request.headers.append("Host", host_value);
                return;
            }
        }

        try request.headers.append("Host", parsed.host);
    }

    /// Writes the response body to stdout.
    fn writeBody(self: *Cli, body_reader: zttp.BodyReader) !void {
        var buffer: [8192]u8 = undefined;
        while (true) {
            const read_len = try body_reader.read(&buffer);
            if (read_len == 0) {
                return;
            }
            try self.out.writeAll(buffer[0..read_len]);
        }
    }
};

pub fn main() void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = std.process.argsAlloc(allocator) catch {
        std.io.getStdErr().writer().writeAll("zttp: failed to read arguments\n") catch {};
        return;
    };
    defer std.process.argsFree(allocator, args);

    var cli = Cli{
        .allocator = allocator,
        .out = std.io.getStdOut().writer(),
        .err = std.io.getStdErr().writer(),
    };

    cli.run(args) catch |err| {
        cli.err.print("zttp: {s}\n", .{@errorName(err)}) catch {};
        if (err == error.InvalidArguments) {
            cli.printHelp() catch {};
        }
    };
}
