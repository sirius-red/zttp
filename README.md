# zttp

Pure-Zig HTTP tooling for Zig 0.15.2+, with a library-first client/server stack,
local-first protocol tests, and a thin `zttp` CLI.

## Current Scope

- HTTP/1.1 client and server flows for loopback and local harness use
- HTTPS client support with TLS verification controls and ALPN negotiation
- HTTP/2 framing, HPACK, connection scaffolding, and local interop coverage
- Experimental HTTP/3 client/server harnesses backed by in-repo QUIC and QPACK
- Shared local harnesses for redirects, cookies, streaming, and protocol checks

HTTP/3 remains opt-in behind `-Dhttp3=true`.

## Build And Test

```powershell
zig build
zig build test
zig build test -Dhttp3=true
```

## CLI

The repository installs a `zttp` executable through `zig build`.

### Request Command

```powershell
zig build run -- request http://127.0.0.1:8080/echo
zig build run -- request --tls-insecure https://127.0.0.1:8443/health
```

Supported request flags include:

- `-X`, `--method`
- `-H`, `--header`
- `-d`, `--data`
- `--tls-insecure`
- `--tls-ca <path>`
- `--tls-cert <path>`
- `--tls-key <path>`
- `--http3` when built with `-Dhttp3=true`

### Server Command

```powershell
zig build run -- server --listen 127.0.0.1 --port 8080
```

Supported server flags include:

- `--listen <addr>`
- `--port <number>`
- `--tls-cert <path>`
- `--tls-key <path>`
- `--http2`
- `--http3` when built with `-Dhttp3=true`

## Example Program

The runnable example stays thin and uses the public library API:

```powershell
zig build
zig-out\\bin\\zttp-client-get https://127.0.0.1:8443/health
```

## Validation Flow

The authoritative local verification steps live in
`.specify/specs/main/quickstart.md`. The short version is:

1. Run `zig build` and `zig build test`.
2. Start `zttp server` on loopback and issue a local `zttp request`.
3. Run `zig build test -Dhttp3=true` for the experimental transport path.
