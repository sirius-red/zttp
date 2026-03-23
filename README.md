# ZTTP

Pure Zig (0.15.2+) HTTP client/server library.

## Installation

ZTTP is distributed as a Zig package and exports the `zttp` module.

Fetch it into your consumer project:

```shell
zig fetch --save=zttp git+https://github.com/sirius-red/zttp.git
```

Then wire the dependency into your `build.zig`:

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zttp_dep = b.dependency("zttp", .{
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "your-app",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zttp", .module = zttp_dep.module("zttp") },
            },
        }),
    });

    b.installArtifact(exe);
}
```

## How To Use

Minimal GET request

```zig
const std = @import("std");
const zttp = @import("zttp");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = zttp.Client.init(allocator, zttp.ClientOptions.default());
    defer client.deinit();

    const uri = zttp.Uri.init(.http, "example.com", null, "/", null, null);
    var request = zttp.Request.init(allocator, .get, uri);
    defer request.deinit();
    try request.headers.append("Host", "example.com");

    var handle = try client.request(&request);
    defer handle.deinit();

    var response = try handle.wait();
    defer response.deinit();
    defer if (response.body) |body| body.close();

    var buffer: [64]u8 = undefined;
    const line = try std.fmt.bufPrint(
        &buffer,
        "status={d} version={s}\n",
        .{ response.status.code(), response.version.asBytes() },
    );
    try std.fs.File.stdout().writeAll(line);
}
```

## Roadmap

ZTTP is progressing in phases. The short version is: the HTTP/1.1 client path is the most mature part of the project today, server support exists in basic form, and HTTP/2 and HTTP/3 are still moving toward full end-to-end support.

Current progress:

- [X] Core library structure, public API, examples, tests, and CLI entrypoints are in place.
- [X] HTTP/1.1 client support is working, including streaming request/response bodies.
- [X] Redirects, cookies, proxy support, pooling, timeouts, and cancellation are already part of the client path.
- [X] A basic HTTP/1.1 server runtime exists and is already useful as a local integration harness.
- [X] Internal groundwork for HTTP/2 and HTTP/3 already exists, including HPACK, QPACK, QUIC, and local harness coverage.

What is next:

- [ ] Finish the remaining TLS and ALPN behavior needed for the client path to be considered complete end to end.
- [ ] Deliver full public HTTP/2 client support, not just low-level protocol pieces.
- [ ] Expand server support with real TLS listener support and minimal end-to-end HTTP/2 serving.
- [ ] Move HTTP/3 beyond local harness flows into real networked runtime support where practical.

Longer-term goals:

- [ ] Add higher-level server features on top of the core runtime, including routing, middleware, static files, and compression.
- [ ] Add higher-level client conveniences such as multipart/form-data helpers, retries, caching, and automatic decompression.
- [ ] Add WebSocket support.
- [ ] Bring HTTP/2 and HTTP/3 interoperability and production hardening closer to the maturity of the current HTTP/1.1 path.

## Build and Test

```shell
zig build
zig build test
zig build smoke
```
