//! TLS client handshake planning, trust loading, and stream attachment helpers.

const std = @import("std");
const types = @import("../types.zig");
const config = @import("config.zig");

const default_plaintext_buffer_bytes = 16 * 1024;

/// Error set returned by TLS client helpers.
pub const Error = config.ValidationError || error{
    /// HTTPS planning requires a host name or IP literal.
    MissingServerName,
    /// No shared ALPN protocol could be selected.
    NoSharedProtocol,
    /// The configured explicit trust store could not be opened or parsed.
    InvalidRootStore,
    /// The system trust store could not be loaded.
    RootStoreUnavailable,
    /// The server certificate does not match the requested host.
    HostnameMismatch,
    /// Certificate or trust validation failed.
    PeerVerificationFailed,
    /// TLS handshake negotiation failed after the transport connected.
    TlsHandshakeFailed,
    /// The transport failed while establishing the TLS session.
    TransportFailure,
    /// Allocation failed while preparing the TLS session.
    OutOfMemory,
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
    /// Stable TLS identity used for pooling decisions.
    identity_token: types.TlsIdentityToken,
    /// Whether the peer must be verified during the handshake.
    peer_verification_required: bool,
};

/// Planned outcome of ALPN selection and peer-verification policy.
pub const NegotiationResult = struct {
    /// Selected application protocol.
    protocol: types.NegotiatedProtocol,
    /// Whether peer verification is enabled for the session.
    verified: bool,
};

/// Prepared TLS state that can later attach to a connected stream.
pub const PreparedHandshake = struct {
    /// Allocator used for owned buffers and trust material.
    allocator: std.mem.Allocator,
    /// Owned handshake plan copied from the request inputs.
    plan: HandshakePlan,
    /// Negotiated ALPN and verification policy.
    negotiation: NegotiationResult,
    /// Optional loaded CA bundle for strict verification.
    ca_bundle: ?std.crypto.Certificate.Bundle,
    /// Plaintext buffer consumed by `std.crypto.tls.Client`.
    tls_read_buffer: []u8,
    /// Plaintext write buffer consumed by `std.crypto.tls.Client`.
    tls_write_buffer: []u8,
    /// Encrypted socket read buffer used by `std.net.Stream.Reader`.
    socket_read_buffer: []u8,
    /// Encrypted socket write buffer used by `std.net.Stream.Writer`.
    socket_write_buffer: []u8,

    /// Releases all prepared buffers and trust material.
    pub fn deinit(self: *PreparedHandshake) void {
        freeOwnedPlan(self.allocator, &self.plan);
        if (self.ca_bundle) |*bundle| {
            bundle.deinit(self.allocator);
            self.ca_bundle = null;
        }
        freeBuffer(self.allocator, self.tls_read_buffer);
        freeBuffer(self.allocator, self.tls_write_buffer);
        freeBuffer(self.allocator, self.socket_read_buffer);
        freeBuffer(self.allocator, self.socket_write_buffer);
        self.tls_read_buffer = &.{};
        self.tls_write_buffer = &.{};
        self.socket_read_buffer = &.{};
        self.socket_write_buffer = &.{};
    }

    /// Attaches the prepared TLS state to a connected stream and runs the handshake.
    pub fn attach(self: *PreparedHandshake, stream: std.net.Stream) Error!*ClientStream {
        const tls_stream = self.allocator.create(ClientStream) catch return error.OutOfMemory;
        errdefer self.allocator.destroy(tls_stream);
        errdefer stream.close();

        tls_stream.* = .{
            .allocator = self.allocator,
            .plan = self.plan,
            .session = self.negotiation,
            .ca_bundle = self.ca_bundle,
            .stream = stream,
            .stream_reader = undefined,
            .stream_writer = undefined,
            .tls_client = undefined,
            .tls_read_buffer = self.tls_read_buffer,
            .tls_write_buffer = self.tls_write_buffer,
            .socket_read_buffer = self.socket_read_buffer,
            .socket_write_buffer = self.socket_write_buffer,
        };
        tls_stream.stream_writer = stream.writer(tls_stream.socket_write_buffer);
        tls_stream.stream_reader = stream.reader(tls_stream.socket_read_buffer);
        tls_stream.tls_client = tlsInit(tls_stream) catch |err| {
            tls_stream.stream.close();
            return err;
        };

        self.plan = .{
            .server_name = &.{},
            .port = types.Port.init(0),
            .verify_mode = .insecure,
            .alpn_protocols = &.{},
            .explicit_roots_path = null,
            .identity_token = types.TlsIdentityToken.init(0),
            .peer_verification_required = false,
        };
        self.ca_bundle = null;
        self.tls_read_buffer = &.{};
        self.tls_write_buffer = &.{};
        self.socket_read_buffer = &.{};
        self.socket_write_buffer = &.{};

        return tls_stream;
    }
};

/// Live TLS client stream backed by a connected socket.
pub const ClientStream = struct {
    /// Allocator used for the owned buffers and self-allocation.
    allocator: std.mem.Allocator,
    /// Owned handshake plan for later inspection.
    plan: HandshakePlan,
    /// Final negotiated protocol and verification state.
    session: NegotiationResult,
    /// Optional CA bundle used during handshake establishment.
    ca_bundle: ?std.crypto.Certificate.Bundle,
    /// Underlying connected network stream.
    stream: std.net.Stream,
    /// Encrypted socket reader referenced by the TLS client.
    stream_reader: std.net.Stream.Reader,
    /// Encrypted socket writer referenced by the TLS client.
    stream_writer: std.net.Stream.Writer,
    /// Active TLS client state.
    tls_client: std.crypto.tls.Client,
    /// Plaintext buffer consumed by the TLS client reader.
    tls_read_buffer: []u8,
    /// Plaintext buffer consumed by the TLS client writer.
    tls_write_buffer: []u8,
    /// Socket read buffer referenced by `stream_reader`.
    socket_read_buffer: []u8,
    /// Socket write buffer referenced by `stream_writer`.
    socket_write_buffer: []u8,

    /// Releases the TLS client stream, closes the socket, and destroys self.
    pub fn deinit(self: *ClientStream) void {
        const allocator = self.allocator;
        freeOwnedPlan(allocator, &self.plan);
        if (self.ca_bundle) |*bundle| {
            bundle.deinit(allocator);
            self.ca_bundle = null;
        }
        self.stream.close();
        freeBuffer(allocator, self.tls_read_buffer);
        freeBuffer(allocator, self.tls_write_buffer);
        freeBuffer(allocator, self.socket_read_buffer);
        freeBuffer(allocator, self.socket_write_buffer);
        allocator.destroy(self);
    }

    /// Returns the decrypted TLS reader for application bytes.
    pub fn reader(self: *ClientStream) *std.Io.Reader {
        return &self.tls_client.reader;
    }

    /// Returns the encrypted TLS writer for application bytes.
    pub fn writer(self: *ClientStream) *std.Io.Writer {
        return &self.tls_client.writer;
    }

    /// Returns the negotiated application protocol.
    pub fn negotiatedProtocol(self: *const ClientStream) types.NegotiatedProtocol {
        return self.session.protocol;
    }

    /// Returns true when peer verification was enforced successfully.
    pub fn peerVerified(self: *const ClientStream) bool {
        return self.session.verified;
    }
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
        .identity_token = tls_config.identity(),
        .peer_verification_required = tls_config.verify == .verify,
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

    if (tls_config.supportsProtocol(.http_1_1)) {
        if (offered_protocols.len == 0 or containsProtocol(offered_protocols, .http_1_1)) {
            return .{
                .protocol = .http_1_1,
                .verified = tls_config.verify == .verify,
            };
        }
    }

    return error.NoSharedProtocol;
}

/// Prepares trust material, owned buffers, and ALPN state before attaching to a socket.
pub fn prepare(
    allocator: std.mem.Allocator,
    uri: types.Uri,
    tls_config: types.TlsConfig,
    offered_protocols: []const types.NegotiatedProtocol,
) Error!PreparedHandshake {
    var plan = try clonePlan(allocator, try buildHandshakePlan(uri, tls_config));
    errdefer freeOwnedPlan(allocator, &plan);

    const negotiation = try negotiateProtocol(tls_config, offered_protocols);
    var ca_bundle = try loadCaBundle(allocator, tls_config);
    errdefer if (ca_bundle) |*bundle| bundle.deinit(allocator);

    const tls_read_buffer = allocator.alloc(u8, default_plaintext_buffer_bytes) catch return error.OutOfMemory;
    errdefer allocator.free(tls_read_buffer);
    const tls_write_buffer = allocator.alloc(u8, std.crypto.tls.Client.min_buffer_len) catch return error.OutOfMemory;
    errdefer allocator.free(tls_write_buffer);
    const socket_read_buffer = allocator.alloc(u8, std.crypto.tls.Client.min_buffer_len) catch return error.OutOfMemory;
    errdefer allocator.free(socket_read_buffer);
    const socket_write_buffer = allocator.alloc(u8, std.crypto.tls.Client.min_buffer_len) catch return error.OutOfMemory;
    errdefer allocator.free(socket_write_buffer);

    return .{
        .allocator = allocator,
        .plan = plan,
        .negotiation = negotiation,
        .ca_bundle = ca_bundle,
        .tls_read_buffer = tls_read_buffer,
        .tls_write_buffer = tls_write_buffer,
        .socket_read_buffer = socket_read_buffer,
        .socket_write_buffer = socket_write_buffer,
    };
}

/// Establishes a TLS client over a connected stream using the provided plan inputs.
pub fn establish(
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    uri: types.Uri,
    tls_config: types.TlsConfig,
    offered_protocols: []const types.NegotiatedProtocol,
) Error!*ClientStream {
    var prepared = try prepare(allocator, uri, tls_config, offered_protocols);
    errdefer prepared.deinit();
    return prepared.attach(stream);
}

/// Returns true when the provided protocol is present in the list.
fn containsProtocol(
    protocols: []const types.NegotiatedProtocol,
    expected: types.NegotiatedProtocol,
) bool {
    for (protocols) |protocol| {
        if (protocol == expected) {
            return true;
        }
    }
    return false;
}

/// Clones borrowed handshake-plan slices into allocator-owned storage.
fn clonePlan(allocator: std.mem.Allocator, plan: HandshakePlan) Error!HandshakePlan {
    const server_name = allocator.dupe(u8, plan.server_name) catch return error.OutOfMemory;
    errdefer allocator.free(server_name);

    const alpn_protocols = allocator.dupe(types.NegotiatedProtocol, plan.alpn_protocols) catch {
        return error.OutOfMemory;
    };
    errdefer allocator.free(alpn_protocols);

    const explicit_roots_path = if (plan.explicit_roots_path) |path|
        allocator.dupe(u8, path) catch return error.OutOfMemory
    else
        null;
    errdefer if (explicit_roots_path) |path| allocator.free(path);

    return .{
        .server_name = server_name,
        .port = plan.port,
        .verify_mode = plan.verify_mode,
        .alpn_protocols = alpn_protocols,
        .explicit_roots_path = explicit_roots_path,
        .identity_token = plan.identity_token,
        .peer_verification_required = plan.peer_verification_required,
    };
}

/// Releases the allocator-owned contents of a handshake plan.
fn freeOwnedPlan(allocator: std.mem.Allocator, plan: *HandshakePlan) void {
    freeBuffer(allocator, plan.server_name);
    if (plan.explicit_roots_path) |path| {
        freeBuffer(allocator, path);
        plan.explicit_roots_path = null;
    }
    allocator.free(plan.alpn_protocols);
    plan.server_name = &.{};
    plan.alpn_protocols = &.{};
}

/// Frees an allocator-owned buffer when it is non-empty.
fn freeBuffer(allocator: std.mem.Allocator, buffer: []const u8) void {
    if (buffer.len == 0) {
        return;
    }
    allocator.free(@constCast(buffer));
}

/// Loads the trust material needed for peer verification.
fn loadCaBundle(
    allocator: std.mem.Allocator,
    tls_config: types.TlsConfig,
) Error!?std.crypto.Certificate.Bundle {
    if (tls_config.verify != .verify) {
        return null;
    }

    var bundle: std.crypto.Certificate.Bundle = .{};
    errdefer bundle.deinit(allocator);

    switch (tls_config.root_store_mode) {
        .system => bundle.rescan(allocator) catch return error.RootStoreUnavailable,
        .explicit => {
            const path = tls_config.explicit_roots_path.?;
            if (std.fs.path.isAbsolute(path)) {
                var file = std.fs.openFileAbsolute(path, .{}) catch return error.InvalidRootStore;
                defer file.close();
                bundle.addCertsFromFile(allocator, file) catch return error.InvalidRootStore;
            } else {
                var file = std.fs.cwd().openFile(path, .{}) catch return error.InvalidRootStore;
                defer file.close();
                bundle.addCertsFromFile(allocator, file) catch return error.InvalidRootStore;
            }
        },
    }

    return bundle;
}

/// Initializes the Zig TLS client over the prepared socket reader and writer.
fn tlsInit(tls_stream: *ClientStream) Error!std.crypto.tls.Client {
    if (tls_stream.plan.peer_verification_required) {
        return std.crypto.tls.Client.init(
            tls_stream.stream_reader.interface(),
            &tls_stream.stream_writer.interface,
            .{
                .host = .{ .explicit = tls_stream.plan.server_name },
                .ca = .{ .bundle = tls_stream.ca_bundle.? },
                .allow_truncation_attacks = true,
                .read_buffer = tls_stream.tls_read_buffer,
                .write_buffer = tls_stream.tls_write_buffer,
            },
        ) catch |err| return mapTlsInitError(err);
    }

    return std.crypto.tls.Client.init(
        tls_stream.stream_reader.interface(),
        &tls_stream.stream_writer.interface,
        .{
            .host = .no_verification,
            .ca = .no_verification,
            .allow_truncation_attacks = true,
            .read_buffer = tls_stream.tls_read_buffer,
            .write_buffer = tls_stream.tls_write_buffer,
        },
    ) catch |err| return mapTlsInitError(err);
}

/// Maps Zig TLS handshake failures into the module error surface.
fn mapTlsInitError(err: anyerror) Error {
    return switch (err) {
        error.ReadFailed,
        error.WriteFailed,
        error.TlsConnectionTruncated,
        => error.TransportFailure,

        error.CertificateHostMismatch => error.HostnameMismatch,

        error.TlsCertificateNotVerified,
        error.CertificateFieldHasInvalidLength,
        error.CertificatePublicKeyInvalid,
        error.CertificateExpired,
        error.CertificateFieldHasWrongDataType,
        error.CertificateIssuerMismatch,
        error.CertificateNotYetValid,
        error.CertificateSignatureAlgorithmMismatch,
        error.CertificateSignatureAlgorithmUnsupported,
        error.CertificateSignatureInvalid,
        error.CertificateSignatureInvalidLength,
        error.CertificateSignatureNamedCurveUnsupported,
        error.CertificateSignatureUnsupportedBitCount,
        error.UnsupportedCertificateVersion,
        error.CertificateTimeInvalid,
        error.CertificateHasUnrecognizedObjectId,
        error.CertificateHasInvalidBitString,
        error.InvalidEncoding,
        error.SignatureVerificationFailed,
        error.InvalidSignature,
        error.WeakPublicKey,
        => error.PeerVerificationFailed,

        else => error.TlsHandshakeFailed,
    };
}

test "tls handshake planning preserves host, port, and verification policy" {
    const uri = types.Uri.init(.https, "example.com", null, "/", null, null);
    const plan = try buildHandshakePlan(uri, types.TlsConfig.default());

    try std.testing.expectEqualStrings("example.com", plan.server_name);
    try std.testing.expectEqual(@as(u16, 443), plan.port.toInt());
    try std.testing.expect(plan.peer_verification_required);
    try std.testing.expectEqual(
        types.TlsConfig.default().identity().toInt(),
        plan.identity_token.toInt(),
    );
}

test "tls alpn negotiation honors config order" {
    var tls_config = types.TlsConfig.default();
    tls_config.alpn_protocols = &.{ .http_1_1, .h2 };

    const result = try negotiateProtocol(tls_config, &.{ .h2, .http_1_1 });
    try std.testing.expectEqual(types.NegotiatedProtocol.http_1_1, result.protocol);
    try std.testing.expect(result.verified);
}

test "tls alpn negotiation falls back to http/1.1 when the peer omits alpn" {
    const result = try negotiateProtocol(types.TlsConfig.default(), &.{});

    try std.testing.expectEqual(types.NegotiatedProtocol.http_1_1, result.protocol);
    try std.testing.expect(result.verified);
}

test "prepared handshake owns copied plan data without roots in insecure mode" {
    var tls_config = types.TlsConfig.default();
    tls_config.verify = .insecure;

    var prepared = try prepare(
        std.testing.allocator,
        types.Uri.init(.https, "loopback.local", null, "/", null, null),
        tls_config,
        &.{.h2},
    );
    defer prepared.deinit();

    try std.testing.expectEqualStrings("loopback.local", prepared.plan.server_name);
    try std.testing.expectEqual(types.NegotiatedProtocol.h2, prepared.negotiation.protocol);
    try std.testing.expect(!prepared.negotiation.verified);
    try std.testing.expect(prepared.ca_bundle == null);
    try std.testing.expect(prepared.plan.server_name.ptr != "loopback.local".ptr);
}

test "prepared handshake rejects a missing explicit root store" {
    var tls_config = types.TlsConfig.default();
    tls_config.root_store_mode = .explicit;
    tls_config.explicit_roots_path = "src/lib/testing/fixtures/certs/roots.pem";

    try std.testing.expectError(
        error.InvalidRootStore,
        prepare(
            std.testing.allocator,
            types.Uri.init(.https, "127.0.0.1", null, "/", null, null),
            tls_config,
            &.{.http_1_1},
        ),
    );
}
