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
    \\  request   HTTP client request (stub)
    \\  server    HTTP server harness (stub)
    \\
    \\Flags:
    \\  -h, --help  Show help
    \\
;

/// Help text for the request subcommand.
const request_help =
    \\zttp request - HTTP client request (stub)
    \\
    \\Usage:
    \\  zttp request [options] <url>
    \\
    \\Options:
    \\  -h, --help  Show help
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

        _ = zttp.Client.Options.default();
        _ = zttp.Method.get;

        try self.err.writeAll("zttp request: not implemented\n");
        return error.NotImplemented;
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
