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
    \\  -X, --method <token>    HTTP method (default: GET, or POST when -d is used)
    \\  -H, --header <h:v>      Add a header (repeatable)
    \\  -d, --data <bytes>      Request body (sets Content-Length if missing)
    \\      --tls-insecure      Disable TLS certificate verification
    \\      --tls-ca <path>     Use an explicit trust bundle for HTTPS
    \\      --tls-cert <path>   Present a certificate chain for local HTTPS tests
    \\      --tls-key <path>    Present the matching private key for --tls-cert
    \\  -h, --help              Show help
    \\
    \\Notes:
    \\  http:// and https:// URLs are accepted.
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
    /// Standard output handle.
    out: std.fs.File,
    /// Standard error handle.
    err: std.fs.File,

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

        try self.printErr("zttp: unknown command '{s}'\n", .{command});
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

        var request_args = self.parseRequestArgs(args) catch |err| {
            try self.printErr("zttp request: {s}\n", .{@errorName(err)});
            return error.InvalidArguments;
        };
        defer request_args.deinit(self.allocator);

        const parsed = parseUrl(request_args.url) catch |err| {
            try self.printErr("zttp request: {s}\n", .{@errorName(err)});
            return error.InvalidArguments;
        };

        var client_options = zttp.ClientOptions.default();
        try self.applyTlsOptions(&client_options, request_args);

        var client = zttp.Client.init(self.allocator, client_options);
        defer client.deinit();

        const uri = zttp.Uri.init(
            parsed.scheme,
            parsed.host,
            parsed.port,
            parsed.path,
            parsed.query,
            null,
        );

        const method = self.selectMethod(request_args);
        var request = zttp.Request.init(self.allocator, method, uri);
        defer request.deinit();
        try self.applyHeaders(&request, request_args);
        try self.addHostHeader(&request, parsed);

        var body = DataBody.init(request_args.data);
        if (request_args.data) |data| {
            if (request.headers.get("content-length") == null and request.headers.get("transfer-encoding") == null) {
                var len_buffer: [32]u8 = undefined;
                const len_value = try std.fmt.bufPrint(&len_buffer, "{d}", .{data.len});
                try request.headers.append("Content-Length", len_value);
            }

            request.body = .{
                .ctx = &body,
                .read_fn = DataBody.read,
                .close_fn = DataBody.close,
            };
        }

        var handle = try client.request(&request);
        defer handle.deinit();

        var response = try handle.wait();
        defer response.deinit();

        try self.printErr("{s} {d}\n", .{ response.version.asBytes(), response.status.code() });
        try self.printErr("protocol: {s}\n", .{response.version.asBytes()});

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

    /// Writes a formatted message to standard error.
    fn printErr(self: *Cli, comptime format: []const u8, args: anytype) !void {
        const message = try std.fmt.allocPrint(self.allocator, format, args);
        defer self.allocator.free(message);
        try self.err.writeAll(message);
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
            zttp.Scheme.https
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
        if (request.headers.get("host") != null) {
            return;
        }

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

    /// Header name/value pair parsed from CLI arguments.
    const HeaderArg = struct {
        /// Header name.
        name: []const u8,
        /// Header value.
        value: []const u8,
    };

    /// Parsed arguments for the request command.
    const RequestArgs = struct {
        /// HTTP method override, if provided.
        method: ?[]const u8,
        /// Request body data, if provided.
        data: ?[]const u8,
        /// Disable TLS verification for local testing.
        tls_insecure: bool,
        /// Explicit CA bundle path for HTTPS requests.
        tls_ca: ?[]const u8,
        /// Certificate chain path for local client identity tests.
        tls_cert: ?[]const u8,
        /// Private key path for the client identity.
        tls_key: ?[]const u8,
        /// Target URL argument.
        url: []const u8,
        /// Header list parsed from flags.
        headers: std.ArrayListUnmanaged(HeaderArg),

        /// Releases any allocated header storage.
        fn deinit(self: *RequestArgs, allocator: std.mem.Allocator) void {
            self.headers.deinit(allocator);
        }
    };

    /// Error set returned by argument parsing.
    const RequestArgsError = error{
        /// Memory allocation failed while collecting arguments.
        OutOfMemory,
        /// A required URL argument was missing.
        MissingUrl,
        /// A flag value was missing.
        MissingFlagValue,
        /// An unknown flag was provided.
        UnknownFlag,
        /// The URL argument was provided more than once.
        DuplicateUrl,
        /// The method flag was provided more than once.
        DuplicateMethod,
        /// The data flag was provided more than once.
        DuplicateData,
        /// The CA bundle flag was provided more than once.
        DuplicateTlsCa,
        /// The certificate flag was provided more than once.
        DuplicateTlsCert,
        /// The key flag was provided more than once.
        DuplicateTlsKey,
        /// A header argument was invalid.
        InvalidHeader,
    };

    /// Parses request subcommand arguments into structured values.
    fn parseRequestArgs(self: *Cli, args: []const []const u8) RequestArgsError!RequestArgs {
        var headers = std.ArrayListUnmanaged(HeaderArg){};
        errdefer headers.deinit(self.allocator);

        var method: ?[]const u8 = null;
        var data: ?[]const u8 = null;
        var tls_insecure = false;
        var tls_ca: ?[]const u8 = null;
        var tls_cert: ?[]const u8 = null;
        var tls_key: ?[]const u8 = null;
        var url: ?[]const u8 = null;

        var index: usize = 0;
        while (index < args.len) {
            const arg = args[index];
            if (std.mem.eql(u8, arg, "-X") or std.mem.eql(u8, arg, "--method")) {
                if (method != null) {
                    return error.DuplicateMethod;
                }
                const value = try requireValue(args, &index);
                method = value;
                continue;
            }
            if (std.mem.eql(u8, arg, "-H") or std.mem.eql(u8, arg, "--header")) {
                const value = try requireValue(args, &index);
                const header = parseHeaderArg(value) catch return error.InvalidHeader;
                try headers.append(self.allocator, header);
                continue;
            }
            if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--data")) {
                if (data != null) {
                    return error.DuplicateData;
                }
                const value = try requireValue(args, &index);
                data = value;
                continue;
            }
            if (std.mem.eql(u8, arg, "--tls-insecure")) {
                tls_insecure = true;
                index += 1;
                continue;
            }
            if (std.mem.eql(u8, arg, "--tls-ca")) {
                if (tls_ca != null) {
                    return error.DuplicateTlsCa;
                }
                tls_ca = try requireValue(args, &index);
                continue;
            }
            if (std.mem.eql(u8, arg, "--tls-cert")) {
                if (tls_cert != null) {
                    return error.DuplicateTlsCert;
                }
                tls_cert = try requireValue(args, &index);
                continue;
            }
            if (std.mem.eql(u8, arg, "--tls-key")) {
                if (tls_key != null) {
                    return error.DuplicateTlsKey;
                }
                tls_key = try requireValue(args, &index);
                continue;
            }
            if (std.mem.eql(u8, arg, "--")) {
                index += 1;
                if (index >= args.len) {
                    return error.MissingUrl;
                }
                if (url != null) {
                    return error.DuplicateUrl;
                }
                url = args[index];
                index += 1;
                continue;
            }
            if (arg.len > 0 and arg[0] == '-') {
                return error.UnknownFlag;
            }
            if (url != null) {
                return error.DuplicateUrl;
            }
            url = arg;
            index += 1;
        }

        if (url == null) {
            return error.MissingUrl;
        }

        return .{
            .method = method,
            .data = data,
            .tls_insecure = tls_insecure,
            .tls_ca = tls_ca,
            .tls_cert = tls_cert,
            .tls_key = tls_key,
            .url = url.?,
            .headers = headers,
        };
    }

    /// Requires a value after a flag and advances the index.
    fn requireValue(args: []const []const u8, index: *usize) RequestArgsError![]const u8 {
        if (index.* + 1 >= args.len) {
            return error.MissingFlagValue;
        }
        const value = args[index.* + 1];
        index.* += 2;
        return value;
    }

    /// Parses a header argument into name/value slices.
    fn parseHeaderArg(arg: []const u8) !HeaderArg {
        const colon = std.mem.indexOfScalar(u8, arg, ':') orelse return error.InvalidHeader;
        if (colon == 0) {
            return error.InvalidHeader;
        }
        const name = std.mem.trim(u8, arg[0..colon], " \t");
        const value = std.mem.trimLeft(u8, arg[colon + 1 ..], " \t");
        if (name.len == 0) {
            return error.InvalidHeader;
        }
        return .{
            .name = name,
            .value = value,
        };
    }

    /// Selects the HTTP method for the request.
    fn selectMethod(self: *Cli, args: RequestArgs) zttp.Method {
        _ = self;
        if (args.method) |method| {
            return parseMethod(method);
        }
        if (args.data != null) {
            return .post;
        }
        return .get;
    }

    /// Parses a method token into a typed method.
    fn parseMethod(value: []const u8) zttp.Method {
        if (std.ascii.eqlIgnoreCase(value, "GET")) return .get;
        if (std.ascii.eqlIgnoreCase(value, "HEAD")) return .head;
        if (std.ascii.eqlIgnoreCase(value, "POST")) return .post;
        if (std.ascii.eqlIgnoreCase(value, "PUT")) return .put;
        if (std.ascii.eqlIgnoreCase(value, "DELETE")) return .delete;
        if (std.ascii.eqlIgnoreCase(value, "CONNECT")) return .connect;
        if (std.ascii.eqlIgnoreCase(value, "OPTIONS")) return .options;
        if (std.ascii.eqlIgnoreCase(value, "TRACE")) return .trace;
        if (std.ascii.eqlIgnoreCase(value, "PATCH")) return .patch;
        return .{ .custom = value };
    }

    /// Applies CLI headers to the request.
    fn applyHeaders(self: *Cli, request: *zttp.Request, args: RequestArgs) !void {
        _ = self;
        for (args.headers.items) |header| {
            try request.headers.append(header.name, header.value);
        }
    }

    /// Applies TLS-related CLI flags to the client options.
    fn applyTlsOptions(self: *Cli, options: *zttp.ClientOptions, args: RequestArgs) !void {
        _ = self;
        if (args.tls_insecure) {
            options.tls.verify = .insecure;
        }
        if (args.tls_ca) |path| {
            options.tls.root_store_mode = .explicit;
            options.tls.explicit_roots_path = path;
        }
        if (args.tls_cert) |path| {
            options.tls.certificate_chain_path = path;
        }
        if (args.tls_key) |path| {
            options.tls.private_key_path = path;
        }
    }

    /// Body reader backed by static CLI data.
    const DataBody = struct {
        /// Body bytes to stream.
        data: ?[]const u8,
        /// Current read offset.
        offset: usize,

        /// Initializes the body reader with optional data.
        fn init(data: ?[]const u8) DataBody {
            return .{
                .data = data,
                .offset = 0,
            };
        }

        /// Reads bytes into `dest`.
        fn read(ctx: ?*anyopaque, dest: []u8) anyerror!usize {
            const self: *DataBody = @ptrCast(@alignCast(ctx.?));
            const payload = self.data orelse return 0;
            if (self.offset >= payload.len) {
                return 0;
            }
            const remaining = payload.len - self.offset;
            const to_copy = @min(dest.len, remaining);
            std.mem.copyForwards(u8, dest[0..to_copy], payload[self.offset .. self.offset + to_copy]);
            self.offset += to_copy;
            return to_copy;
        }

        /// Releases any resources held by the body reader.
        fn close(ctx: ?*anyopaque) void {
            _ = ctx;
        }
    };

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
        std.fs.File.stderr().writeAll("zttp: failed to read arguments\n") catch {};
        return;
    };
    defer std.process.argsFree(allocator, args);

    var cli = Cli{
        .allocator = allocator,
        .out = std.fs.File.stdout(),
        .err = std.fs.File.stderr(),
    };

    cli.run(args) catch |err| {
        cli.printErr("zttp: {s}\n", .{@errorName(err)}) catch {};
        if (err == error.InvalidArguments) {
            cli.printHelp() catch {};
        }
    };
}
