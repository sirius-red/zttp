# Local Test Fixtures

This directory is reserved for local-only fixtures used by protocol and CLI
tests.

## Intended layout

- `certs/`: loopback certificates, keys, and trust roots for TLS and ALPN tests
- `http/`: raw request and response payload fixtures for HTTP/1.1 and HTTP/2
- `http3/`: UDP or QUIC payload samples used by opt-in HTTP/3 harness tests

## Rules

- Keep fixtures deterministic and suitable for `zig build test`
- Do not require external network access or third-party services
- Avoid storing secrets that are not meant for local development
