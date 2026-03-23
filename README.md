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

## Build and Test

```shell
zig build
zig build test
zig build smoke
```
