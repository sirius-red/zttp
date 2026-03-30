# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.0] - 2026-03-30

### Added

- Added first-party client conveniences for automatic response decoding, typed multipart/form-data submission, replay-safe retry policies, cache-aware request flows with revalidation, and protocol-aware WebSocket session helpers across HTTP/1.1, HTTP/2, and HTTP/3.

## [0.9.0] - 2026-03-29

### Added

- Added the real UDP-backed HTTP/3 runtime path for the library and CLI, including retained session state and hardened stream isolation for repeated and concurrent loopback exchanges.

## [0.8.0] - 2026-03-27

### Added

- Added secure server runtime routing with TLS, ALPN-driven protocol dispatch, and minimal end-to-end HTTP/2 serving.

## [0.7.0] - 2026-03-26

### Added

- Added multiplexed HTTP/2 client streams with basic flow control, backpressure, GOAWAY handling, and failure isolation on a shared connection.

## [0.6.0] - 2026-03-24

### Added

- Added HTTPS ALPN auto-selection that routes dual-ALPN peers over HTTP/2 while preserving HTTP/1.1 fallback and negotiation failure diagnostics.

## [0.5.0] - 2026-03-15

### Added

- Enabled experimental HTTP/3 support by default.

## [0.4.1] - 2026-03-14

### Fixed

- Hardened the loopback server interop runtime.

## [0.4.0] - 2026-03-10

### Added

- Added a minimal server runtime and CLI harness.

## [0.3.0] - 2026-03-10

### Fixed

- Established TLS for the HTTP/1.1 transport, making the HTTPS client path materially real.

## [0.2.8] - 2026-03-02

### Fixed

- Switched CLI stdio handling to file handles.

## [0.2.7] - 2026-03-02

### Changed

- Hoisted public helper types to module scope.

## [0.2.6] - 2026-01-23

### Added

- Added HTTPS CONNECT tunneling through proxies.

## [0.2.5] - 2026-01-23

### Added

- Routed HTTP requests through proxies.

## [0.2.4] - 2026-01-23

### Added

- Added proxy environment discovery and per-request overrides.

## [0.2.3] - 2026-01-23

### Added

- Applied cookies across redirect hops.

## [0.2.2] - 2026-01-23

### Added

- Added cookie jar support and client cookie hooks.

## [0.2.1] - 2026-01-23

### Fixed

- Stopped forwarding sensitive headers on cross-origin redirects.

## [0.2.0] - 2026-01-23

### Added

- Added redirect following with loop detection and hop limits.

## [0.1.3] - 2026-01-23

### Changed

- Tightened client pool validation and option handling.

## [0.1.2] - 2026-01-23

### Added

- Added keep-alive connection pooling.

## [0.1.1] - 2026-01-23

### Added

- Added CLI request flags for method, headers, and body.

## [0.1.0] - 2026-01-23

### Added

- Added the first user-facing end-to-end HTTP/1.1 request flow via `Client.request` and the CLI request command.
