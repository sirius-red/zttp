//! Regression coverage scaffolding for future TLS client work.

const std = @import("std");
const types = @import("../types.zig");
const fixture_loader = @import("../testing/fixture_loader.zig");
const interop_harness = @import("../testing/interop_harness.zig");

/// Expected outcome for a planned TLS regression scenario.
pub const HandshakeExpectation = union(enum) {
    /// The handshake should succeed and negotiate the protocol.
    success: types.NegotiatedProtocol,
    /// The handshake should fail with a named verification category.
    tls_error: []const u8,
};

/// Declarative TLS regression case for loopback handshake coverage.
pub const HandshakeCase = struct {
    /// Stable scenario name used in test output.
    name: []const u8,
    /// Fixture path under `src/lib/testing/fixtures/certs/`.
    certificate_fixture: []const u8,
    /// Hostname used for validation.
    server_name: []const u8,
    /// Expected test outcome.
    expectation: HandshakeExpectation,
};

const regression_cases = [_]HandshakeCase{
    .{
        .name = "trusted-local-cert",
        .certificate_fixture = "loopback/server.pem",
        .server_name = "127.0.0.1",
        .expectation = .{ .success = .h2 },
    },
    .{
        .name = "invalid-chain",
        .certificate_fixture = "invalid-chain/server.pem",
        .server_name = "127.0.0.1",
        .expectation = .{ .tls_error = "invalid-chain" },
    },
    .{
        .name = "hostname-mismatch",
        .certificate_fixture = "loopback/server.pem",
        .server_name = "wrong.host.local",
        .expectation = .{ .tls_error = "hostname-mismatch" },
    },
};

test "tls regression matrix covers success and failure cases" {
    try std.testing.expectEqual(@as(usize, 3), regression_cases.len);
    try std.testing.expectEqualStrings("trusted-local-cert", regression_cases[0].name);
    try std.testing.expectEqual(types.NegotiatedProtocol.h2, regression_cases[0].expectation.success);
    try std.testing.expectEqualStrings("invalid-chain", regression_cases[1].expectation.tls_error);
    try std.testing.expectEqualStrings("hostname-mismatch", regression_cases[2].expectation.tls_error);
}

test "tls config identity changes with verification and alpn policy" {
    var strict = types.TlsConfig.default();
    var insecure = types.TlsConfig.default();
    insecure.verify = .insecure;

    var explicit_roots = types.TlsConfig.default();
    explicit_roots.root_store_mode = .explicit;
    explicit_roots.explicit_roots_path = "src/lib/testing/fixtures/certs/roots.pem";

    var h1_only = types.TlsConfig.default();
    h1_only.alpn_protocols = &.{.http_1_1};

    try std.testing.expect(strict.identity().toInt() != insecure.identity().toInt());
    try std.testing.expect(strict.identity().toInt() != explicit_roots.identity().toInt());
    try std.testing.expect(strict.identity().toInt() != h1_only.identity().toInt());
}

test "tls fixture paths stay inside the cert fixture root" {
    const loader = fixture_loader.Loader.init();
    const path = try loader.pathFor(std.testing.allocator, "certs/loopback/server.pem");
    defer std.testing.allocator.free(path);

    try std.testing.expect(std.mem.startsWith(u8, path, "src/lib/testing/fixtures"));
    try std.testing.expect(
        std.mem.endsWith(u8, path, "certs/loopback/server.pem") or
            std.mem.endsWith(u8, path, "certs\\loopback/server.pem"),
    );
}

test "health route remains available for tls and alpn coverage" {
    const health = interop_harness.scenarioForRoute(.health).?;
    try std.testing.expect(health.tls_supported);
    try std.testing.expect(health.supportsProtocol(.h2));
}
