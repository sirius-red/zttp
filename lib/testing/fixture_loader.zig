//! Local fixture loading helpers for protocol, certificate, and smoke tests.

const std = @import("std");

/// Logical fixture groups under `lib/testing/fixtures/`.
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

/// Reusable loader for local fixture files.
pub const Loader = struct {
    /// Root path for all fixture files.
    base_path: []const u8,

    /// Creates a loader rooted at the repository fixture directory.
    pub fn init() Loader {
        return .{ .base_path = "lib/testing/fixtures" };
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

    try std.testing.expectEqualStrings("fixtures/certs/loopback.pem", full_path);
}
