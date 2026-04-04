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

These personas must stay aligned with the typed metadata in
`src/lib/testing/interop_harness.zig`.

## Generated local credentials

Clean-checkout secure validation does not rely on committed secret material.
Generate the local credential set under `.tmp/local-certs` with one of the
first-party commands below before running the published secure server/request
 walkthrough:

- `scripts/powershell/generate-local-test-certs.ps1 -OutDir .tmp/local-certs`
- `scripts/bash/generate-local-test-certs.sh .tmp/local-certs`

Expected generated outputs:

- `.tmp/local-certs/loopback-server.pem`
- `.tmp/local-certs/loopback-server.key`
- `.tmp/local-certs/roots.pem`

The published secure CLI walkthrough uses the generated trust bundle for
`/health` and `/echo`, while the broader validation contract lives in
`.specify/specs/fix/audit-gap-remediation/contracts/secure-runtime.openapi.yaml`.

## Intended layout

- `certs/`: loopback certificates, keys, and trust roots for TLS and ALPN tests
- `http/`: raw request and response payload fixtures for HTTP/1.1 and HTTP/2
- `http3/`: UDP or QUIC payload samples used by HTTP/3 harness tests
- `higher-level-assets/`: local static files and cached payload samples used by
  the higher-level server and client convenience tests
- `interop-peers/`: repository-owned peer descriptors for loopback and
  multi-process hardening personas
- `interop-profiles/`: protocol capability and production-matrix profile
  metadata

## Fixture inventory

- `higher-level-assets/site.css`
  - Intended for static file publication and compression eligibility checks
- `higher-level-assets/upload.bin`
  - Intended for multipart upload fixture coverage
- `higher-level-assets/cached-config.json`
  - Intended for cache freshness and revalidation coverage
- `interop-peers/server-app.json`
  - Intended for the local first-party server application persona
- `interop-peers/h2-peer.json`
  - Intended for the controlled multi-process HTTP/2 persona
- `interop-peers/h3-peer.json`
  - Intended for the controlled multi-process HTTP/3 persona
- `interop-profiles/http1-baseline.json`
  - Intended for HTTP/1.1 capability and fallback classification
- `interop-profiles/h2-multiplexed.json`
  - Intended for HTTP/2 multiplexing and WebSocket capability classification
- `interop-profiles/h3-quic.json`
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
- Keep generated local credentials ephemeral under `.tmp/local-certs`; do not
  replace the committed fixture inventory with local-only artifacts
