//! TLS listener planning and ALPN negotiation helpers for server mode.

const std = @import("std");
const core = @import("../types.zig");
const config = @import("config.zig");

/// Error set returned by TLS server planning helpers.
pub const Error = config.ValidationError || error{
    /// TLS listener mode requires a certificate chain path.
    MissingCertificateChain,
    /// TLS listener mode requires a private key path.
    MissingPrivateKey,
    /// No shared ALPN protocol could be selected for the peer.
    NoSharedProtocol,
};

/// Static TLS listener plan derived from a shared TLS configuration.
pub const ListenerPlan = struct {
    /// Path to the certificate chain used for the listener.
    certificate_chain_path: []const u8,
    /// Path to the private key used for the listener.
    private_key_path: []const u8,
    /// ALPN protocols the listener will advertise.
    alpn_protocols: []const core.NegotiatedProtocol,
    /// Stable TLS identity token for the listener.
    identity_token: core.TlsIdentityToken,
};

/// Outcome of server-side protocol negotiation.
pub const NegotiationResult = struct {
    /// Protocol selected for the accepted connection.
    protocol: core.NegotiatedProtocol,
    /// Stable TLS identity for the listener.
    identity_token: core.TlsIdentityToken,
};

/// Builds a listener plan from the shared TLS configuration.
pub fn buildListenerPlan(tls: core.TlsConfig) Error!ListenerPlan {
    try config.validate(tls);
    const certificate_chain_path = tls.certificate_chain_path orelse return error.MissingCertificateChain;
    const private_key_path = tls.private_key_path orelse return error.MissingPrivateKey;

    return .{
        .certificate_chain_path = certificate_chain_path,
        .private_key_path = private_key_path,
        .alpn_protocols = tls.alpn_protocols,
        .identity_token = tls.identity(),
    };
}

/// Negotiates ALPN between the listener plan and the peer offer.
pub fn negotiateProtocol(
    plan: ListenerPlan,
    offered_protocols: []const core.NegotiatedProtocol,
) Error!NegotiationResult {
    for (plan.alpn_protocols) |preferred| {
        for (offered_protocols) |offered| {
            if (preferred == offered) {
                return .{
                    .protocol = preferred,
                    .identity_token = plan.identity_token,
                };
            }
        }
    }

    if (containsProtocol(plan.alpn_protocols, .http_1_1)) {
        return .{
            .protocol = .http_1_1,
            .identity_token = plan.identity_token,
        };
    }

    return error.NoSharedProtocol;
}

/// Returns true when the protocol appears in the list.
fn containsProtocol(protocols: []const core.NegotiatedProtocol, expected: core.NegotiatedProtocol) bool {
    for (protocols) |protocol| {
        if (protocol == expected) {
            return true;
        }
    }
    return false;
}

test "tls server planning requires certificate and key material" {
    var tls = core.TlsConfig.default();
    tls.verify = .insecure;

    try std.testing.expectError(error.MissingCertificateChain, buildListenerPlan(tls));
}

test "tls server negotiation honors advertised protocol order" {
    var tls = core.TlsConfig.default();
    tls.verify = .insecure;
    tls.certificate_chain_path = "server.pem";
    tls.private_key_path = "server.key";
    tls.alpn_protocols = &.{ .h2, .http_1_1 };

    const plan = try buildListenerPlan(tls);
    const result = try negotiateProtocol(plan, &.{ .http_1_1, .h2 });

    try std.testing.expectEqual(core.NegotiatedProtocol.h2, result.protocol);
}
