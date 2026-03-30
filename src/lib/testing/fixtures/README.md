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
- `m6-assets/`: local static files and cached payload samples used by the M6
  server and client convenience tests
- `m6-peers/`: repository-owned peer descriptors for loopback and multi-process
  hardening personas
- `m6-profiles/`: protocol capability and production-matrix profile metadata

## M6 inventory

- `m6-assets/site.css`
  - Intended for static file publication and compression eligibility checks
- `m6-assets/upload.bin`
  - Intended for multipart upload fixture coverage
- `m6-assets/cached-config.json`
  - Intended for cache freshness and revalidation coverage
- `m6-peers/server-app.json`
  - Intended for the local first-party server application persona
- `m6-peers/h2-peer.json`
  - Intended for the controlled multi-process HTTP/2 persona
- `m6-peers/h3-peer.json`
  - Intended for the controlled multi-process HTTP/3 persona
- `m6-profiles/http1-baseline.json`
  - Intended for HTTP/1.1 capability and fallback classification
- `m6-profiles/h2-multiplexed.json`
  - Intended for HTTP/2 multiplexing and WebSocket capability classification
- `m6-profiles/h3-quic.json`
  - Intended for HTTP/3 runtime and disturbance classification

## Rules

- Keep fixtures deterministic and suitable for `zig build test`
- Do not require external network access or third-party services
- Avoid storing secrets that are not meant for local development
- Reuse loopback certificates and trust roots across ALPN personas whenever the
  negotiated-protocol behavior, not certificate variance, is the thing under
  test
- Keep unsupported-protocol fixtures limited to local negative testing; they
  must never become fallback candidates
