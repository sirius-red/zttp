# Local Test Fixtures

This directory is reserved for local-only fixtures used by protocol and CLI
tests.

## ALPN loopback personas

- `dual_alpn`
  - Port: `18443`
  - Advertises: `h2`, `http/1.1`
  - Expected client outcome: successful `h2`
- `http1_only`
  - Port: `19443`
  - Advertises: `http/1.1`
  - Expected client outcome: successful `http/1.1`
- `omits_alpn`
  - Port: `20443`
  - Advertises: no ALPN result
  - Expected client outcome: fallback to `http/1.1`
- `unsupported_protocol`
  - Port: `21443`
  - Returns selected token: `spdy/3`
  - Expected client outcome: reject before HTTP handling

These personas must stay aligned with the local contract in
`.specify/specs/feat/alpn-auto-protocol-selection/contracts/alpn-loopback.openapi.yaml`
and the typed metadata in `src/lib/testing/interop_harness.zig`.

## Intended layout

- `certs/`: loopback certificates, keys, and trust roots for TLS and ALPN tests
- `http/`: raw request and response payload fixtures for HTTP/1.1 and HTTP/2
- `http3/`: UDP or QUIC payload samples used by HTTP/3 harness tests

## Rules

- Keep fixtures deterministic and suitable for `zig build test`
- Do not require external network access or third-party services
- Avoid storing secrets that are not meant for local development
- Reuse loopback certificates and trust roots across ALPN personas whenever the
  negotiated-protocol behavior, not certificate variance, is the thing under
  test
- Keep unsupported-protocol fixtures limited to local negative testing; they
  must never become fallback candidates
