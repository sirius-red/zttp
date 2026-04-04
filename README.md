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

## HTTPS ALPN Auto-Selection

For HTTPS requests, `zttp` plans ALPN automatically instead of asking callers to
pick `h2` or `http/1.1` per request.

- `h2` is advertised only when the client can actually route the request onto
  the current HTTP/2 path.
- Peers that support only `http/1.1`, or omit ALPN entirely, stay on the
  HTTP/1.1 compatibility path.
- Peers that negotiate an unsupported protocol fail before HTTP request bytes
  are written; the client surfaces this as a negotiation error instead of a
  silent downgrade.
- Verification for this feature is local-first: `zig build test` covers the
  dual-ALPN, `http1_only`, omitted-ALPN, and unsupported-protocol personas in
  `src/lib/testing/interop_harness.zig`, including the CLI-oriented readiness
  round-trip coverage.

## Secure Validation Workflow

Use the repository-owned credential generators to validate the secure listener
from a clean checkout without committing local secrets.

Prepare `.tmp/` cache roots before running the local suite:

```powershell
New-Item -ItemType Directory -Force .tmp, .tmp\zig-cache-win, .tmp\zig-global-win | Out-Null
```

```sh
mkdir -p .tmp .tmp/zig-cache-linux .tmp/zig-global-linux
```

Generate local credentials under `.tmp/local-certs`:

```powershell
scripts\powershell\generate-local-test-certs.ps1 -OutDir .tmp\local-certs
```

```sh
scripts/bash/generate-local-test-certs.sh .tmp/local-certs
```

Run the canonical local verification suite with `.tmp/` cache paths:

```powershell
zig build test --cache-dir .tmp\zig-cache-win --global-cache-dir .tmp\zig-global-win
```

```sh
zig build test --cache-dir .tmp/zig-cache-linux --global-cache-dir .tmp/zig-global-linux
```

Start one secure listener on the library-owned server surface:

```powershell
zig build run -- server --listen 127.0.0.1 --port 4433 --tls-cert .tmp/local-certs/loopback-server.pem --tls-key .tmp/local-certs/loopback-server.key --http2
```

Probe the same endpoint with the generated trust bundle:

```powershell
zig build run -- request --tls-ca .tmp/local-certs/roots.pem https://127.0.0.1:4433/health
zig build run -- request --tls-ca .tmp/local-certs/roots.pem https://127.0.0.1:4433/echo
```

## Secure Capability Status

Supported behavior:

- Secure requests depend on the peer's live TLS and ALPN result, not on a
  predefined endpoint catalog.
- The default secure listener advertises `h2` and `http/1.1` on one endpoint
  when both protocols are enabled.
- Invalid or unsupported negotiated protocol tokens fail explicitly before a
  success response is reported.

Compatibility fallback behavior:

- Peers that support only `http/1.1`, or omit ALPN entirely, stay on the
  HTTP/1.1 compatibility path.
- Additional trust roots remain opt-in through `--tls-ca` or the typed
  `TlsConfig` fields; untrusted secure peers fail by default.

Known limitations:

- The clean-checkout secure flow is for local validation only and expects the
  generated artifacts under `.tmp/local-certs`.
- The published secure CLI walkthrough validates `/health` and `/echo` on the
  shared listener; broader route coverage remains anchored in the interop and
  loopback harness tests.
- Broader interoperability hardening beyond the current local verification
  matrix remains follow-up work after the `1.0.0` capability floor.

## Roadmap

ZTTP is progressing toward a `1.0.0` release with one public stability story:
HTTP/1.1, HTTP/2, and HTTP/3 are all part of the default stable promise for
the currently verified routing, middleware, static-file, compression,
WebSocket, decompression, multipart, retry, cache, and hardening surfaces.
Broader parity work beyond that capability floor remains follow-up scope after
the release cut, not an HTTP/3 downgrade.

Current progress:

- [X] Core library structure, public API, examples, tests, and CLI entrypoints are in place.
- [X] HTTP/1.1 client support is working, including streaming request/response bodies.
- [X] Redirects, cookies, proxy support, pooling, timeouts, and cancellation are already part of the client path.
- [X] A basic HTTP/1.1 server runtime exists and is already useful as a local integration harness.
- [X] HTTP/2 and HTTP/3 participate in the stable `1.0.0` capability floor, backed by HPACK, QPACK, QUIC, real runtime coverage, and local harness evidence.

Follow-up work after the `1.0.0` capability floor:

- [ ] Continue hardening TLS and ALPN behavior around broader client and server interoperability edges.
- [ ] Deliver full public HTTP/2 client support, not just low-level protocol pieces.
- [X] Expand server support with loopback secure-listener semantics, ALPN dispatch, and minimal end-to-end HTTP/2 serving.
- [X] Add first higher-level server ergonomics on top of the core runtime, including exact routing, shared middleware, and fallback handling.
- [X] Move HTTP/3 beyond local harness flows into real networked runtime support where practical.

Longer-term follow-up after `1.0.0`:

- [X] Expand higher-level server features further with static files, compression, and broader framework conveniences.
- [X] Add higher-level client conveniences such as multipart/form-data helpers, retries, caching, and automatic decompression.
- [X] Add WebSocket support.
- [X] Bring HTTP/2 and HTTP/3 interoperability and production hardening closer to the maturity of the current HTTP/1.1 path.

## Build and Test

`zig build test` is the canonical verification command. It is responsible for
running the full library and CLI test suites from the build graph. Internally,
the library suite is split into dedicated unit and integration roots so local
logic checks do not share the same entrypoint as loopback/runtime coverage.
Within this repository, keep Zig cache directories under `.tmp/` when running
the local suite.

```shell
zig build test
```

Use `zig build` only when you want a build-only check without running the test
suite.
