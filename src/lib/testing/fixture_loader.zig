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

    /// Returns the relative directory name for the fixture group.
    pub fn dirName(self: FixtureGroup) []const u8 {
        return @tagName(self);
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
