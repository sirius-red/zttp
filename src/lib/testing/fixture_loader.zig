//! Local fixture loading helpers for protocol, certificate, and smoke tests.

const std = @import("std");

/// Logical fixture groups under `src/lib/testing/fixtures/`.
pub const FixtureGroup = enum {
    /// Root certificate bundles and keys.
    certs,
    /// HTTP/1.1 and HTTP/2 fixture payloads.
    http,
    /// HTTP/3 and QUIC fixture payloads.
    http3,
    /// Higher-level server/client asset fixtures.
    higher_level_assets,
    /// Peer descriptors for local interop loopback and multi-process profiles.
    interop_peers,
    /// Capability and protocol profile metadata for local interop coverage.
    interop_profiles,

    /// Returns the relative directory name for the fixture group.
    pub fn dirName(self: FixtureGroup) []const u8 {
        return @tagName(self);
    }
};

/// Stable higher-level asset fixture identifier.
pub const HigherLevelAssetFixtureId = enum {
    /// Static stylesheet used by server publication coverage.
    site_css,
    /// Binary upload payload used by multipart coverage.
    upload_bin,
    /// Cached JSON payload used by revalidation coverage.
    cached_config,

    /// Returns the fixture path relative to the root fixture directory.
    pub fn relativePath(self: HigherLevelAssetFixtureId) []const u8 {
        return switch (self) {
            .site_css => "higher-level-assets/site.css",
            .upload_bin => "higher-level-assets/upload.bin",
            .cached_config => "higher-level-assets/cached-config.json",
        };
    }
};

/// Stable interop peer descriptor identifier.
pub const InteropPeerFixtureId = enum {
    /// Loopback first-party server application persona.
    server_app,
    /// Controlled multi-process HTTP/2 peer persona.
    h2_peer,
    /// Controlled multi-process HTTP/3 peer persona.
    h3_peer,

    /// Returns the fixture path relative to the root fixture directory.
    pub fn relativePath(self: InteropPeerFixtureId) []const u8 {
        return switch (self) {
            .server_app => "interop-peers/server-app.json",
            .h2_peer => "interop-peers/h2-peer.json",
            .h3_peer => "interop-peers/h3-peer.json",
        };
    }
};

/// Stable interop protocol profile identifier.
pub const InteropProtocolProfileId = enum {
    /// HTTP/1.1 baseline profile.
    http1_baseline,
    /// HTTP/2 multiplexing profile.
    h2_multiplexed,
    /// HTTP/3 QUIC runtime profile.
    h3_quic,

    /// Returns the fixture path relative to the root fixture directory.
    pub fn relativePath(self: InteropProtocolProfileId) []const u8 {
        return switch (self) {
            .http1_baseline => "interop-profiles/http1-baseline.json",
            .h2_multiplexed => "interop-profiles/h2-multiplexed.json",
            .h3_quic => "interop-profiles/h3-quic.json",
        };
    }
};

/// Errors returned by fixture path validation.
pub const PathError = error{
    /// Fixture path must not be empty.
    EmptyPath,
    /// Fixture path must be relative to the fixture root.
    AbsolutePathNotAllowed,
    /// Fixture path must not contain parent traversal.
    PathTraversalNotAllowed,
};

/// Errors returned while loading fixture contents.
pub const LoadError = PathError || std.mem.Allocator.Error || std.fs.File.OpenError || std.fs.File.ReadError;

/// Output stream source for a captured process message.
pub const OutputStream = enum {
    /// Standard output stream.
    stdout,
    /// Standard error stream.
    stderr,
};

/// Typed socket failure category extracted from command output.
pub const SocketFailureKind = enum {
    /// Windows `GetLastError(87)` surfaced from a socket read path.
    windows_invalid_parameter,
    /// Connection reset while reading or writing the socket.
    connection_reset,
    /// Peer closed the socket while the process still expected to write.
    broken_pipe,
    /// A custom signature supplied by the caller matched the capture.
    known_signature,
};

/// Typed socket failure extracted from captured command output.
pub const SocketFailureCapture = struct {
    /// Failure kind derived from the output text.
    kind: SocketFailureKind,
    /// Stream that contained the matching text.
    stream: OutputStream,
    /// Stable matching substring that identified the failure.
    signature: []const u8,
};

/// Owned stdout/stderr capture for one command invocation.
pub const CommandCapture = struct {
    /// Stable command label for reporting.
    command_name: []const u8,
    /// Process termination record.
    term: std.process.Child.Term,
    /// Bytes captured from standard output.
    stdout: []u8,
    /// Bytes captured from standard error.
    stderr: []u8,

    /// Creates an owned command capture from one child-process result.
    pub fn initOwned(
        allocator: std.mem.Allocator,
        command_name: []const u8,
        result: std.process.Child.RunResult,
    ) std.mem.Allocator.Error!CommandCapture {
        _ = allocator;
        return .{
            .command_name = command_name,
            .term = result.term,
            .stdout = result.stdout,
            .stderr = result.stderr,
        };
    }

    /// Releases captured stdout and stderr bytes.
    pub fn deinit(self: *CommandCapture, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
        self.* = undefined;
    }

    /// Returns true when the process exited with code zero.
    pub fn succeeded(self: CommandCapture) bool {
        return switch (self.term) {
            .Exited => |code| code == 0,
            else => false,
        };
    }

    /// Returns true when either output stream contains the provided substring.
    pub fn contains(self: CommandCapture, needle: []const u8) bool {
        return std.mem.indexOf(u8, self.stdout, needle) != null or
            std.mem.indexOf(u8, self.stderr, needle) != null;
    }

    /// Returns the first typed socket failure found in the capture, if any.
    pub fn socketFailure(self: CommandCapture) ?SocketFailureCapture {
        return detectSocketFailure(self.stdout, self.stderr);
    }

    /// Returns a typed socket failure, also considering an expected custom signature.
    pub fn expectedSocketFailure(
        self: CommandCapture,
        known_signature: ?[]const u8,
    ) ?SocketFailureCapture {
        return detectExpectedSocketFailure(self.stdout, self.stderr, known_signature);
    }
};

/// Owned loopback identity fixture paths for server-mode validation.
pub const LoopbackIdentityPaths = struct {
    /// Path to the loopback certificate chain fixture.
    certificate_chain_path: []u8,
    /// Path to the loopback private key fixture.
    private_key_path: []u8,

    /// Releases the owned fixture paths.
    pub fn deinit(self: *LoopbackIdentityPaths, allocator: std.mem.Allocator) void {
        allocator.free(self.certificate_chain_path);
        allocator.free(self.private_key_path);
        self.* = undefined;
    }
};

/// Owned loopback identity fixture contents for server-mode validation.
pub const LoopbackIdentity = struct {
    /// Certificate chain fixture bytes.
    certificate_chain: []u8,
    /// Private key fixture bytes.
    private_key: []u8,

    /// Releases the owned fixture contents.
    pub fn deinit(self: *LoopbackIdentity, allocator: std.mem.Allocator) void {
        allocator.free(self.certificate_chain);
        allocator.free(self.private_key);
        self.* = undefined;
    }
};

/// Owned generated local credential paths for clean-checkout secure validation.
pub const GeneratedLocalCredentialPaths = struct {
    /// Path to the generated certificate chain.
    certificate_chain_path: []u8,
    /// Path to the generated private key.
    private_key_path: []u8,
    /// Path to the generated trust bundle.
    roots_path: []u8,

    /// Releases the owned generated-credential paths.
    pub fn deinit(self: *GeneratedLocalCredentialPaths, allocator: std.mem.Allocator) void {
        allocator.free(self.certificate_chain_path);
        allocator.free(self.private_key_path);
        allocator.free(self.roots_path);
        self.* = undefined;
    }
};

/// Owned generated local credential contents for clean-checkout secure validation.
pub const GeneratedLocalCredentials = struct {
    /// Generated certificate chain bytes.
    certificate_chain: []u8,
    /// Generated private key bytes.
    private_key: []u8,
    /// Generated trust bundle bytes.
    roots: []u8,

    /// Releases the owned generated credential contents.
    pub fn deinit(self: *GeneratedLocalCredentials, allocator: std.mem.Allocator) void {
        allocator.free(self.certificate_chain);
        allocator.free(self.private_key);
        allocator.free(self.roots);
        self.* = undefined;
    }
};

/// Stable QUIC fixture identifier used by local HTTP/3 runtime scenarios.
pub const QuicRuntimeFixtureId = enum {
    /// Client-side Initial packet fixture for loopback session setup.
    initial_client,
    /// Server-side Initial packet fixture for loopback session setup.
    initial_server,
    /// Health-probe request fixture for runtime smoke coverage.
    runtime_health,
    /// Echo request fixture for runtime QPACK state coverage.
    runtime_echo,
    /// Large-stream fixture for disturbance and recovery coverage.
    runtime_stream_large,

    /// Returns the fixture path relative to the HTTP/3 fixture root.
    pub fn relativePath(self: QuicRuntimeFixtureId) []const u8 {
        return switch (self) {
            .initial_client => "http3/quic/runtime/initial-client.bin",
            .initial_server => "http3/quic/runtime/initial-server.bin",
            .runtime_health => "http3/quic/runtime/health-request.bin",
            .runtime_echo => "http3/quic/runtime/echo-request.bin",
            .runtime_stream_large => "http3/quic/runtime/stream-large.bin",
        };
    }
};

/// Owned loopback QUIC fixture paths used by runtime-oriented HTTP/3 tests.
pub const LoopbackQuicRuntimeFixturePaths = struct {
    /// Path to the client Initial fixture.
    initial_client_path: []u8,
    /// Path to the server Initial fixture.
    initial_server_path: []u8,
    /// Path to the health-probe runtime fixture.
    runtime_health_path: []u8,
    /// Path to the echo runtime fixture.
    runtime_echo_path: []u8,
    /// Path to the large-stream runtime fixture.
    runtime_stream_large_path: []u8,

    /// Releases the owned fixture paths.
    pub fn deinit(self: *LoopbackQuicRuntimeFixturePaths, allocator: std.mem.Allocator) void {
        allocator.free(self.initial_client_path);
        allocator.free(self.initial_server_path);
        allocator.free(self.runtime_health_path);
        allocator.free(self.runtime_echo_path);
        allocator.free(self.runtime_stream_large_path);
        self.* = undefined;
    }
};

/// Owned loopback QUIC fixture contents used by runtime-oriented HTTP/3 tests.
pub const LoopbackQuicRuntimeFixtures = struct {
    /// Client-side Initial packet fixture bytes.
    initial_client: []u8,
    /// Server-side Initial packet fixture bytes.
    initial_server: []u8,
    /// Health-probe runtime fixture bytes.
    runtime_health: []u8,
    /// Echo runtime fixture bytes.
    runtime_echo: []u8,
    /// Large-stream runtime fixture bytes.
    runtime_stream_large: []u8,

    /// Releases the owned fixture contents.
    pub fn deinit(self: *LoopbackQuicRuntimeFixtures, allocator: std.mem.Allocator) void {
        allocator.free(self.initial_client);
        allocator.free(self.initial_server);
        allocator.free(self.runtime_health);
        allocator.free(self.runtime_echo);
        allocator.free(self.runtime_stream_large);
        self.* = undefined;
    }
};

/// Reusable loader for local fixture files.
pub const Loader = struct {
    /// Root path for all fixture files.
    base_path: []const u8,

    /// Creates a loader rooted at the repository fixture directory.
    pub fn init() Loader {
        return .{ .base_path = "src/lib/testing/fixtures" };
    }

    /// Creates a loader rooted at the provided base path.
    pub fn initWithBasePath(base_path: []const u8) Loader {
        return .{ .base_path = base_path };
    }

    /// Loads a fixture relative to the fixture root.
    pub fn load(self: Loader, allocator: std.mem.Allocator, relative_path: []const u8) LoadError![]u8 {
        const full_path = try self.pathFor(allocator, relative_path);
        defer allocator.free(full_path);

        return try std.fs.cwd().readFileAlloc(allocator, full_path, std.math.maxInt(usize));
    }

    /// Loads a fixture from a well-known fixture group.
    pub fn loadFromGroup(
        self: Loader,
        allocator: std.mem.Allocator,
        group: FixtureGroup,
        relative_path: []const u8,
    ) LoadError![]u8 {
        const group_path = try std.fs.path.join(allocator, &.{ group.dirName(), relative_path });
        defer allocator.free(group_path);

        return try self.load(allocator, group_path);
    }

    /// Loads a certificate or key fixture.
    pub fn loadCertificate(self: Loader, allocator: std.mem.Allocator, relative_path: []const u8) LoadError![]u8 {
        return try self.loadFromGroup(allocator, .certs, relative_path);
    }

    /// Loads an HTTP fixture payload.
    pub fn loadHttpFixture(self: Loader, allocator: std.mem.Allocator, relative_path: []const u8) LoadError![]u8 {
        return try self.loadFromGroup(allocator, .http, relative_path);
    }

    /// Loads an HTTP/3 fixture payload.
    pub fn loadHttp3Fixture(self: Loader, allocator: std.mem.Allocator, relative_path: []const u8) LoadError![]u8 {
        return try self.loadFromGroup(allocator, .http3, relative_path);
    }

    /// Returns the full path for one named higher-level asset fixture.
    pub fn pathForHigherLevelAsset(
        self: Loader,
        allocator: std.mem.Allocator,
        fixture: HigherLevelAssetFixtureId,
    ) LoadError![]u8 {
        return try self.pathFor(allocator, fixture.relativePath());
    }

    /// Returns the full path for one named interop peer fixture.
    pub fn pathForInteropPeer(
        self: Loader,
        allocator: std.mem.Allocator,
        fixture: InteropPeerFixtureId,
    ) LoadError![]u8 {
        return try self.pathFor(allocator, fixture.relativePath());
    }

    /// Returns the full path for one named interop protocol profile fixture.
    pub fn pathForInteropProtocolProfile(
        self: Loader,
        allocator: std.mem.Allocator,
        fixture: InteropProtocolProfileId,
    ) LoadError![]u8 {
        return try self.pathFor(allocator, fixture.relativePath());
    }

    /// Loads one named higher-level asset fixture.
    pub fn loadHigherLevelAsset(
        self: Loader,
        allocator: std.mem.Allocator,
        fixture: HigherLevelAssetFixtureId,
    ) LoadError![]u8 {
        return try self.load(allocator, fixture.relativePath());
    }

    /// Loads one named interop peer fixture.
    pub fn loadInteropPeer(
        self: Loader,
        allocator: std.mem.Allocator,
        fixture: InteropPeerFixtureId,
    ) LoadError![]u8 {
        return try self.load(allocator, fixture.relativePath());
    }

    /// Loads one named interop protocol profile fixture.
    pub fn loadInteropProtocolProfile(
        self: Loader,
        allocator: std.mem.Allocator,
        fixture: InteropProtocolProfileId,
    ) LoadError![]u8 {
        return try self.load(allocator, fixture.relativePath());
    }

    /// Returns the full path for one named QUIC runtime fixture.
    pub fn pathForQuicRuntimeFixture(
        self: Loader,
        allocator: std.mem.Allocator,
        fixture: QuicRuntimeFixtureId,
    ) LoadError![]u8 {
        return try self.pathFor(allocator, fixture.relativePath());
    }

    /// Returns the default loopback QUIC runtime fixture paths.
    pub fn loopbackQuicRuntimeFixturePaths(
        self: Loader,
        allocator: std.mem.Allocator,
    ) LoadError!LoopbackQuicRuntimeFixturePaths {
        return .{
            .initial_client_path = try self.pathForQuicRuntimeFixture(allocator, .initial_client),
            .initial_server_path = try self.pathForQuicRuntimeFixture(allocator, .initial_server),
            .runtime_health_path = try self.pathForQuicRuntimeFixture(allocator, .runtime_health),
            .runtime_echo_path = try self.pathForQuicRuntimeFixture(allocator, .runtime_echo),
            .runtime_stream_large_path = try self.pathForQuicRuntimeFixture(allocator, .runtime_stream_large),
        };
    }

    /// Loads one named QUIC runtime fixture.
    pub fn loadQuicRuntimeFixture(
        self: Loader,
        allocator: std.mem.Allocator,
        fixture: QuicRuntimeFixtureId,
    ) LoadError![]u8 {
        return try self.load(allocator, fixture.relativePath());
    }

    /// Loads the default loopback QUIC runtime fixtures.
    pub fn loadLoopbackQuicRuntimeFixtures(
        self: Loader,
        allocator: std.mem.Allocator,
    ) LoadError!LoopbackQuicRuntimeFixtures {
        return .{
            .initial_client = try self.loadQuicRuntimeFixture(allocator, .initial_client),
            .initial_server = try self.loadQuicRuntimeFixture(allocator, .initial_server),
            .runtime_health = try self.loadQuicRuntimeFixture(allocator, .runtime_health),
            .runtime_echo = try self.loadQuicRuntimeFixture(allocator, .runtime_echo),
            .runtime_stream_large = try self.loadQuicRuntimeFixture(allocator, .runtime_stream_large),
        };
    }

    /// Returns the default loopback certificate and private-key fixture paths.
    pub fn loopbackIdentityPaths(
        self: Loader,
        allocator: std.mem.Allocator,
    ) LoadError!LoopbackIdentityPaths {
        return .{
            .certificate_chain_path = try self.pathFor(allocator, "certs/loopback-server.pem"),
            .private_key_path = try self.pathFor(allocator, "certs/loopback-server.key"),
        };
    }

    /// Loads the default loopback certificate and private-key fixtures.
    pub fn loadLoopbackIdentity(
        self: Loader,
        allocator: std.mem.Allocator,
    ) LoadError!LoopbackIdentity {
        return .{
            .certificate_chain = try self.loadCertificate(allocator, "loopback-server.pem"),
            .private_key = try self.loadCertificate(allocator, "loopback-server.key"),
        };
    }

    /// Returns the generated local credential paths under `.tmp/local-certs`.
    pub fn generatedLocalCredentialPaths(
        self: Loader,
        allocator: std.mem.Allocator,
    ) LoadError!GeneratedLocalCredentialPaths {
        _ = self;
        return .{
            .certificate_chain_path = try std.fs.path.join(allocator, &.{ ".tmp", "local-certs", "loopback-server.pem" }),
            .private_key_path = try std.fs.path.join(allocator, &.{ ".tmp", "local-certs", "loopback-server.key" }),
            .roots_path = try std.fs.path.join(allocator, &.{ ".tmp", "local-certs", "roots.pem" }),
        };
    }

    /// Loads the generated local credentials from `.tmp/local-certs`.
    pub fn loadGeneratedLocalCredentials(
        self: Loader,
        allocator: std.mem.Allocator,
    ) LoadError!GeneratedLocalCredentials {
        var paths = try self.generatedLocalCredentialPaths(allocator);
        defer paths.deinit(allocator);

        return .{
            .certificate_chain = try std.fs.cwd().readFileAlloc(allocator, paths.certificate_chain_path, std.math.maxInt(usize)),
            .private_key = try std.fs.cwd().readFileAlloc(allocator, paths.private_key_path, std.math.maxInt(usize)),
            .roots = try std.fs.cwd().readFileAlloc(allocator, paths.roots_path, std.math.maxInt(usize)),
        };
    }

    /// Builds an absolute or repository-relative path to a fixture.
    pub fn pathFor(self: Loader, allocator: std.mem.Allocator, relative_path: []const u8) LoadError![]u8 {
        try validateRelativePath(relative_path);
        return try std.fs.path.join(allocator, &.{ self.base_path, relative_path });
    }
};

/// Validates that a fixture path stays inside the fixture root.
fn validateRelativePath(relative_path: []const u8) PathError!void {
    if (relative_path.len == 0) {
        return error.EmptyPath;
    }
    if (std.fs.path.isAbsolute(relative_path)) {
        return error.AbsolutePathNotAllowed;
    }

    var iter = std.mem.tokenizeAny(u8, relative_path, "/\\");
    while (iter.next()) |segment| {
        if (std.mem.eql(u8, segment, "..")) {
            return error.PathTraversalNotAllowed;
        }
    }
}

/// Returns the first typed socket failure found in stdout or stderr.
pub fn detectSocketFailure(stdout: []const u8, stderr: []const u8) ?SocketFailureCapture {
    return detectExpectedSocketFailure(stdout, stderr, null);
}

/// Returns the first typed socket failure, also honoring a caller-supplied signature.
pub fn detectExpectedSocketFailure(
    stdout: []const u8,
    stderr: []const u8,
    known_signature: ?[]const u8,
) ?SocketFailureCapture {
    if (findSocketFailureInStream(.stderr, stderr, known_signature)) |failure| {
        return failure;
    }
    if (findSocketFailureInStream(.stdout, stdout, known_signature)) |failure| {
        return failure;
    }
    return null;
}

/// Returns the first typed socket failure in one stream, if any.
fn findSocketFailureInStream(
    stream: OutputStream,
    bytes: []const u8,
    known_signature: ?[]const u8,
) ?SocketFailureCapture {
    const patterns = [_]struct {
        kind: SocketFailureKind,
        signature: []const u8,
    }{
        .{ .kind = .windows_invalid_parameter, .signature = "GetLastError(87)" },
        .{ .kind = .connection_reset, .signature = "ConnectionResetByPeer" },
        .{ .kind = .broken_pipe, .signature = "BrokenPipe" },
    };

    for (patterns) |pattern| {
        if (std.mem.indexOf(u8, bytes, pattern.signature) != null) {
            return .{
                .kind = pattern.kind,
                .stream = stream,
                .signature = pattern.signature,
            };
        }
    }

    if (known_signature) |signature| {
        if (std.mem.indexOf(u8, bytes, signature) != null) {
            return .{
                .kind = .known_signature,
                .stream = stream,
                .signature = signature,
            };
        }
    }

    return null;
}

test "fixture loader rejects traversal" {
    const loader = Loader.init();
    try std.testing.expectError(
        error.PathTraversalNotAllowed,
        loader.pathFor(std.testing.allocator, "../secrets/key.pem"),
    );
}

test "fixture loader joins grouped paths" {
    const loader = Loader.initWithBasePath("fixtures");
    const full_path = try loader.pathFor(std.testing.allocator, "certs/loopback.pem");
    defer std.testing.allocator.free(full_path);

    try std.testing.expect(std.mem.startsWith(u8, full_path, "fixtures"));
    try std.testing.expect(
        std.mem.endsWith(u8, full_path, "certs/loopback.pem") or
            std.mem.endsWith(u8, full_path, "certs\\loopback.pem"),
    );
}

test "fixture loader resolves loopback identity fixture paths" {
    const loader = Loader.init();
    var paths = try loader.loopbackIdentityPaths(std.testing.allocator);
    defer paths.deinit(std.testing.allocator);

    try std.testing.expect(
        std.mem.endsWith(u8, paths.certificate_chain_path, "certs/loopback-server.pem") or
            std.mem.endsWith(u8, paths.certificate_chain_path, "certs\\loopback-server.pem"),
    );
    try std.testing.expect(
        std.mem.endsWith(u8, paths.private_key_path, "certs/loopback-server.key") or
            std.mem.endsWith(u8, paths.private_key_path, "certs\\loopback-server.key"),
    );
}

test "fixture loader resolves generated local credential paths" {
    const loader = Loader.init();
    var paths = try loader.generatedLocalCredentialPaths(std.testing.allocator);
    defer paths.deinit(std.testing.allocator);

    try std.testing.expect(
        std.mem.endsWith(u8, paths.certificate_chain_path, ".tmp/local-certs/loopback-server.pem") or
            std.mem.endsWith(u8, paths.certificate_chain_path, ".tmp\\local-certs\\loopback-server.pem") or
            std.mem.endsWith(u8, paths.certificate_chain_path, ".tmp\\local-certs/loopback-server.pem"),
    );
    try std.testing.expect(
        std.mem.endsWith(u8, paths.private_key_path, ".tmp/local-certs/loopback-server.key") or
            std.mem.endsWith(u8, paths.private_key_path, ".tmp\\local-certs\\loopback-server.key") or
            std.mem.endsWith(u8, paths.private_key_path, ".tmp\\local-certs/loopback-server.key"),
    );
    try std.testing.expect(
        std.mem.endsWith(u8, paths.roots_path, ".tmp/local-certs/roots.pem") or
            std.mem.endsWith(u8, paths.roots_path, ".tmp\\local-certs\\roots.pem") or
            std.mem.endsWith(u8, paths.roots_path, ".tmp\\local-certs/roots.pem"),
    );
}

test "fixture loader resolves loopback quic runtime fixture paths" {
    const loader = Loader.init();
    var paths = try loader.loopbackQuicRuntimeFixturePaths(std.testing.allocator);
    defer paths.deinit(std.testing.allocator);

    try std.testing.expect(
        std.mem.endsWith(u8, paths.initial_client_path, "http3/quic/runtime/initial-client.bin") or
            std.mem.endsWith(u8, paths.initial_client_path, "http3\\quic\\runtime\\initial-client.bin"),
    );
    try std.testing.expect(
        std.mem.endsWith(u8, paths.runtime_stream_large_path, "http3/quic/runtime/stream-large.bin") or
            std.mem.endsWith(u8, paths.runtime_stream_large_path, "http3\\quic\\runtime\\stream-large.bin"),
    );
}

test "fixture loader resolves higher-level asset fixture paths" {
    const loader = Loader.init();

    const asset = try loader.pathForHigherLevelAsset(std.testing.allocator, .site_css);
    defer std.testing.allocator.free(asset);
    try std.testing.expect(
        std.mem.endsWith(u8, asset, "higher-level-assets/site.css") or
            std.mem.endsWith(u8, asset, "higher-level-assets\\site.css"),
    );

    const peer = try loader.pathForInteropPeer(std.testing.allocator, .h2_peer);
    defer std.testing.allocator.free(peer);
    try std.testing.expect(
        std.mem.endsWith(u8, peer, "interop-peers/h2-peer.json") or
            std.mem.endsWith(u8, peer, "interop-peers\\h2-peer.json"),
    );

    const profile = try loader.pathForInteropProtocolProfile(std.testing.allocator, .h3_quic);
    defer std.testing.allocator.free(profile);
    try std.testing.expect(
        std.mem.endsWith(u8, profile, "interop-profiles/h3-quic.json") or
            std.mem.endsWith(u8, profile, "interop-profiles\\h3-quic.json"),
    );
}

test "fixture loader reads higher-level asset peer and profile metadata fixtures" {
    const loader = Loader.init();

    const asset = try loader.loadHigherLevelAsset(std.testing.allocator, .cached_config);
    defer std.testing.allocator.free(asset);
    try std.testing.expect(std.mem.containsAtLeast(u8, asset, 1, "\"version\""));

    const peer = try loader.loadInteropPeer(std.testing.allocator, .server_app);
    defer std.testing.allocator.free(peer);
    try std.testing.expect(std.mem.containsAtLeast(u8, peer, 1, "\"network_mode\": \"loopback\""));
    try std.testing.expect(std.mem.containsAtLeast(u8, peer, 1, "\"server_routing\""));

    const profile = try loader.loadInteropProtocolProfile(std.testing.allocator, .h2_multiplexed);
    defer std.testing.allocator.free(profile);
    try std.testing.expect(std.mem.containsAtLeast(u8, profile, 1, "\"eligible_flows\": 340"));
    try std.testing.expect(std.mem.containsAtLeast(u8, profile, 1, "\"hardening_matrix\""));
}

test "fixture loader loads quic runtime fixtures from a custom base path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("http3/quic/runtime");
    try tmp.dir.writeFile(.{ .sub_path = "http3/quic/runtime/initial-client.bin", .data = "client-initial" });
    try tmp.dir.writeFile(.{ .sub_path = "http3/quic/runtime/initial-server.bin", .data = "server-initial" });
    try tmp.dir.writeFile(.{ .sub_path = "http3/quic/runtime/health-request.bin", .data = "health" });
    try tmp.dir.writeFile(.{ .sub_path = "http3/quic/runtime/echo-request.bin", .data = "echo" });
    try tmp.dir.writeFile(.{ .sub_path = "http3/quic/runtime/stream-large.bin", .data = "large-stream" });

    const base_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base_path);

    const loader = Loader.initWithBasePath(base_path);
    var fixtures = try loader.loadLoopbackQuicRuntimeFixtures(std.testing.allocator);
    defer fixtures.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("client-initial", fixtures.initial_client);
    try std.testing.expectEqualStrings("server-initial", fixtures.initial_server);
    try std.testing.expectEqualStrings("health", fixtures.runtime_health);
    try std.testing.expectEqualStrings("echo", fixtures.runtime_echo);
    try std.testing.expectEqualStrings("large-stream", fixtures.runtime_stream_large);
}

test "socket failure capture detects windows loopback signature" {
    const failure = detectSocketFailure(
        "",
        "server read failed: GetLastError(87) surfaced from std.net.Stream.read",
    ).?;

    try std.testing.expectEqual(SocketFailureKind.windows_invalid_parameter, failure.kind);
    try std.testing.expectEqual(OutputStream.stderr, failure.stream);
}

test "command capture matches caller-provided socket signature" {
    var capture = try CommandCapture.initOwned(std.testing.allocator, "request", .{
        .term = .{ .Exited = 1 },
        .stdout = try std.testing.allocator.dupe(u8, ""),
        .stderr = try std.testing.allocator.dupe(u8, "std.net.Stream.read failed during loopback probe"),
    });
    defer capture.deinit(std.testing.allocator);

    const failure = capture.expectedSocketFailure("std.net.Stream.read").?;
    try std.testing.expectEqual(SocketFailureKind.known_signature, failure.kind);
    try std.testing.expectEqualStrings("std.net.Stream.read", failure.signature);
}

test "generated secure-validation artifacts stay in first-party repository paths" {
    try std.fs.cwd().access("scripts/powershell/generate-local-test-certs.ps1", .{});
    try std.fs.cwd().access("scripts/bash/generate-local-test-certs.sh", .{});
    try std.fs.cwd().access("src/lib/testing/fixtures/README.md", .{});
    try std.fs.cwd().access(".specify/specs/fix/audit-gap-remediation/contracts/secure-runtime.openapi.yaml", .{});
    try std.fs.cwd().access(".specify/specs/fix/audit-gap-remediation/quickstart.md", .{});
}

test "fixture documentation and secure contract reference generated local credentials" {
    const fixture_readme = try std.fs.cwd().readFileAlloc(
        std.testing.allocator,
        "src/lib/testing/fixtures/README.md",
        128 * 1024,
    );
    defer std.testing.allocator.free(fixture_readme);
    try std.testing.expect(std.mem.containsAtLeast(
        u8,
        fixture_readme,
        1,
        "scripts/powershell/generate-local-test-certs.ps1",
    ));
    try std.testing.expect(std.mem.containsAtLeast(
        u8,
        fixture_readme,
        1,
        ".tmp/local-certs/loopback-server.pem",
    ));
    try std.testing.expect(std.mem.containsAtLeast(
        u8,
        fixture_readme,
        1,
        ".tmp/local-certs/roots.pem",
    ));

    const contract = try std.fs.cwd().readFileAlloc(
        std.testing.allocator,
        ".specify/specs/fix/audit-gap-remediation/contracts/secure-runtime.openapi.yaml",
        128 * 1024,
    );
    defer std.testing.allocator.free(contract);
    try std.testing.expect(std.mem.containsAtLeast(u8, contract, 1, "/health"));
    try std.testing.expect(std.mem.containsAtLeast(u8, contract, 1, "/echo"));
    try std.testing.expect(std.mem.containsAtLeast(u8, contract, 1, ".tmp/local-certs/roots.pem"));
    try std.testing.expect(std.mem.containsAtLeast(
        u8,
        contract,
        1,
        "scripts/bash/generate-local-test-certs.sh",
    ));
}
