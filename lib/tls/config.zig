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
