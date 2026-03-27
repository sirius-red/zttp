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
    /// The listener certificate chain could not be opened or read.
    InvalidCertificateChain,
    /// The listener private key could not be opened or read.
    InvalidPrivateKey,
    /// Allocation failed while loading listener identity bytes.
    OutOfMemory,
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

/// Owned listener identity bytes loaded from the configured fixture paths.
pub const LoadedIdentity = struct {
    /// Owned certificate chain bytes.
    certificate_chain: []u8,
    /// Owned private-key bytes.
    private_key: []u8,
    /// Stable TLS identity token for the listener plan.
    identity_token: core.TlsIdentityToken,

    /// Releases the owned identity bytes.
    pub fn deinit(self: *LoadedIdentity, allocator: std.mem.Allocator) void {
        allocator.free(self.certificate_chain);
        allocator.free(self.private_key);
        self.* = undefined;
    }
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

/// Loads the configured certificate chain and private key for a listener plan.
pub fn loadIdentity(
    allocator: std.mem.Allocator,
    plan: ListenerPlan,
) Error!LoadedIdentity {
    const certificate_chain = try loadFile(allocator, plan.certificate_chain_path, error.InvalidCertificateChain);
    errdefer allocator.free(certificate_chain);

    const private_key = try loadFile(allocator, plan.private_key_path, error.InvalidPrivateKey);
    errdefer allocator.free(private_key);

    return .{
        .certificate_chain = certificate_chain,
        .private_key = private_key,
        .identity_token = plan.identity_token,
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

/// Loads one identity file and maps failures into the provided server-side error.
fn loadFile(
    allocator: std.mem.Allocator,
    path: []const u8,
    comptime mapped_error: anyerror,
) (std.mem.Allocator.Error || Error)![]u8 {
    if (std.fs.path.isAbsolute(path)) {
        var file = std.fs.openFileAbsolute(path, .{}) catch return mapped_error;
        defer file.close();
        return file.readToEndAlloc(allocator, std.math.maxInt(usize)) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => mapped_error,
        };
    }
    return std.fs.cwd().readFileAlloc(allocator, path, std.math.maxInt(usize)) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => mapped_error,
    };
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

test "tls server loads loopback identity fixtures from a listener plan" {
    var tls = core.TlsConfig.default();
    tls.verify = .insecure;
    tls.certificate_chain_path = "src/lib/testing/fixtures/certs/loopback-server.pem";
    tls.private_key_path = "src/lib/testing/fixtures/certs/loopback-server.key";

    const plan = try buildListenerPlan(tls);
    var identity = try loadIdentity(std.testing.allocator, plan);
    defer identity.deinit(std.testing.allocator);

    try std.testing.expect(identity.certificate_chain.len > 0);
    try std.testing.expect(identity.private_key.len > 0);
    try std.testing.expectEqual(plan.identity_token.toInt(), identity.identity_token.toInt());
}
