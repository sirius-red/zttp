//! TLS client planning helpers for future HTTPS transport integration.

const std = @import("std");
const types = @import("../types.zig");
const config = @import("config.zig");

/// Error set returned by TLS planning helpers.
pub const Error = config.ValidationError || error{
    /// HTTPS planning requires a host name or IP literal.
    MissingServerName,
    /// No overlap exists between configured and offered ALPN protocols.
    NoSharedProtocol,
    /// Live TLS transport is not wired into HTTP/1.1 yet.
    TransportNotIntegrated,
};

/// Static handshake plan derived from a URI and TLS config.
pub const HandshakePlan = struct {
    /// Server name used for SNI and host verification.
    server_name: []const u8,
    /// Destination port for the TLS session.
    port: types.Port,
    /// Configured verification mode.
    verify_mode: types.TlsVerifyMode,
    /// ALPN protocols to advertise in order.
    alpn_protocols: []const types.NegotiatedProtocol,
    /// Optional explicit root bundle path.
    explicit_roots_path: ?[]const u8,
};

/// Planned outcome of ALPN selection.
pub const NegotiationResult = struct {
    /// Selected application protocol.
    protocol: types.NegotiatedProtocol,
    /// Whether certificate verification is expected to be enforced.
    verified: bool,
};

/// Builds a static TLS handshake plan from the request URI and config.
pub fn buildHandshakePlan(uri: types.Uri, tls_config: types.TlsConfig) Error!HandshakePlan {
    try config.validate(tls_config);
    if (uri.host.len == 0) {
        return error.MissingServerName;
    }

    return .{
        .server_name = uri.host,
        .port = uri.effectivePort(),
        .verify_mode = tls_config.verify,
        .alpn_protocols = tls_config.alpn_protocols,
        .explicit_roots_path = tls_config.explicit_roots_path,
    };
}

/// Chooses the best shared ALPN protocol between the config and the peer offer.
pub fn negotiateProtocol(
    tls_config: types.TlsConfig,
    offered_protocols: []const types.NegotiatedProtocol,
) Error!NegotiationResult {
    try config.validate(tls_config);

    for (tls_config.alpn_protocols) |preferred| {
        for (offered_protocols) |offered| {
            if (preferred == offered) {
                return .{
                    .protocol = preferred,
                    .verified = tls_config.verify == .verify,
                };
            }
        }
    }
    return error.NoSharedProtocol;
}

/// Placeholder for the future live TLS client transport handshake.
pub fn establish(
    uri: types.Uri,
    tls_config: types.TlsConfig,
    offered_protocols: []const types.NegotiatedProtocol,
) Error!NegotiationResult {
    _ = try buildHandshakePlan(uri, tls_config);
    _ = offered_protocols;
    return error.TransportNotIntegrated;
}

test "tls handshake planning preserves host and port" {
    const uri = types.Uri.init(.https, "example.com", null, "/", null, null);
    const plan = try buildHandshakePlan(uri, types.TlsConfig.default());

    try std.testing.expectEqualStrings("example.com", plan.server_name);
    try std.testing.expectEqual(@as(u16, 443), plan.port.toInt());
}

test "tls alpn negotiation honors config order" {
    var tls_config = types.TlsConfig.default();
    tls_config.alpn_protocols = &.{ .http_1_1, .h2 };

    const result = try negotiateProtocol(tls_config, &.{ .h2, .http_1_1 });
    try std.testing.expectEqual(types.NegotiatedProtocol.http_1_1, result.protocol);
    try std.testing.expect(result.verified);
}
