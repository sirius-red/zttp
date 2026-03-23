# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
