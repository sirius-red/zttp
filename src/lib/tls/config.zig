//! TLS configuration validation and identity helpers.

const std = @import("std");
const types = @import("../types.zig");

/// Error set returned by TLS configuration validation.
pub const ValidationError = error{
    /// An explicit root store was requested without a bundle path.
    MissingExplicitRoots,
    /// A certificate chain was provided without a private key, or vice versa.
    IncompleteIdentity,
    /// No ALPN protocols were configured.
    MissingAlpnProtocols,
};

/// Validates a shared TLS configuration for client or server use.
pub fn validate(config: types.TlsConfig) ValidationError!void {
    if (config.root_store_mode == .explicit and config.explicit_roots_path == null) {
        return error.MissingExplicitRoots;
    }
    if ((config.certificate_chain_path == null) != (config.private_key_path == null)) {
        return error.IncompleteIdentity;
    }
    if (config.alpn_protocols.len == 0) {
        return error.MissingAlpnProtocols;
    }
}

/// Returns the stable identity token for a TLS configuration.
pub fn identityToken(config: types.TlsConfig) ValidationError!types.TlsIdentityToken {
    try validate(config);
    return config.identity();
}

/// Returns the preferred ALPN protocol from the configuration.
pub fn preferredProtocol(config: types.TlsConfig) ValidationError!types.NegotiatedProtocol {
    try validate(config);
    return config.alpn_protocols[0];
}

/// Returns true when the configuration supports the provided ALPN protocol.
pub fn supportsProtocol(config: types.TlsConfig, protocol: types.NegotiatedProtocol) bool {
    return config.supportsProtocol(protocol);
}

/// Applies shared trust and identity metadata to a TLS configuration copy.
pub fn withTrustMaterial(
    config: types.TlsConfig,
    trust: types.TlsTrustMaterial,
) types.TlsConfig {
    var copy = config;
    copy.explicit_roots_path = trust.explicit_roots_path;
    copy.certificate_chain_path = trust.certificate_chain_path;
    copy.private_key_path = trust.private_key_path;
    if (trust.hasExplicitRoots()) {
        copy.root_store_mode = .explicit;
    }
    return copy;
}

test "tls config validation requires explicit roots when requested" {
    var config = types.TlsConfig.default();
    config.root_store_mode = .explicit;

    try std.testing.expectError(error.MissingExplicitRoots, validate(config));
}

test "tls config preferred protocol follows alpn order" {
    var config = types.TlsConfig.default();
    config.alpn_protocols = &.{ .http_1_1, .h2 };

    try std.testing.expectEqual(types.NegotiatedProtocol.http_1_1, try preferredProtocol(config));
}

test "tls config applies trust material metadata" {
    const trust = types.TlsTrustMaterial{
        .explicit_roots_path = "roots.pem",
        .certificate_chain_path = "server.pem",
        .private_key_path = "server.key",
    };
    const config = withTrustMaterial(types.TlsConfig.default(), trust);

    try std.testing.expectEqual(types.TlsRootStoreMode.explicit, config.root_store_mode);
    try std.testing.expectEqualStrings("roots.pem", config.explicit_roots_path.?);
    try std.testing.expectEqualStrings("server.pem", config.certificate_chain_path.?);
    try std.testing.expectEqualStrings("server.key", config.private_key_path.?);
}
