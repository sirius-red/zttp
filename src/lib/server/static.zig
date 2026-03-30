//! Static-file publication helpers for the first-party server application surface.

const std = @import("std");
const core = @import("../types.zig");
const server_types = @import("types.zig");

const default_allowed_methods = [_]core.Method{ .get, .head };
const default_index_files = [_][]const u8{"index.html"};

/// ETag strategy used by one static publication.
pub const EtagMode = enum {
    /// Do not emit an ETag for the asset.
    none,
    /// Emit a weak hash derived from the asset bytes.
    weak_content_hash,
};

/// Content-type override applied by file suffix.
pub const ContentTypeOverride = struct {
    /// File suffix matched against the resolved asset path.
    suffix: []const u8,
    /// Content type emitted when the suffix matches.
    content_type: []const u8,
};

/// One resolved asset owned temporarily during request handling.
pub const ResolvedAsset = struct {
    /// Full filesystem path to the asset.
    full_path: []u8,
    /// Owned asset bytes.
    bytes: []u8,
    /// Content type emitted for the asset.
    content_type: []const u8,
    /// Optional cache-control header value.
    cache_control: ?[]const u8,
    /// Optional ETag emitted for the asset.
    etag: ?[]u8,

    /// Releases all owned asset state.
    pub fn deinit(self: *ResolvedAsset, allocator: std.mem.Allocator) void {
        allocator.free(self.full_path);
        allocator.free(self.bytes);
        if (self.etag) |etag| {
            allocator.free(etag);
        }
        self.* = undefined;
    }
};

/// Result returned when a static publication inspects a request.
pub const ServeOutcome = enum {
    /// The request path does not target this publication.
    not_handled,
    /// The publication produced a complete response.
    served,
};

/// Static asset publication owned by the higher-level server surface.
pub const Publication = struct {
    /// Stable publication name for diagnostics.
    name: []const u8,
    /// Request-path prefix served by the publication.
    mount_path: []const u8,
    /// Filesystem root that confines the publication.
    content_root: []const u8,
    /// Default index files for mount-root requests.
    index_files: []const []const u8,
    /// ETag strategy used for emitted assets.
    etag_mode: EtagMode,
    /// Optional cache-control header applied to served assets.
    cache_control: ?[]const u8,
    /// HTTP methods allowed for this publication.
    allowed_methods: []const core.Method,
    /// Optional content-type overrides by suffix.
    content_type_overrides: []const ContentTypeOverride,

    /// Returns a basic publication with default method and index behavior.
    pub fn init(name: []const u8, mount_path: []const u8, content_root: []const u8) Publication {
        return .{
            .name = name,
            .mount_path = mount_path,
            .content_root = content_root,
            .index_files = &default_index_files,
            .etag_mode = .weak_content_hash,
            .cache_control = null,
            .allowed_methods = &default_allowed_methods,
            .content_type_overrides = &.{},
        };
    }

    /// Validates the publication configuration.
    pub fn validate(self: Publication) !void {
        if (self.name.len == 0) {
            return error.InvalidStaticPublication;
        }
        if (self.mount_path.len == 0 or self.mount_path[0] != '/') {
            return error.InvalidStaticPublication;
        }
        if (self.content_root.len == 0) {
            return error.InvalidStaticPublication;
        }
        if (self.allowed_methods.len == 0) {
            return error.InvalidStaticPublication;
        }
    }

    /// Returns true when the request path targets the publication mount.
    pub fn matchesPath(self: Publication, path: []const u8) bool {
        if (!std.mem.startsWith(u8, path, self.mount_path)) {
            return false;
        }
        if (path.len == self.mount_path.len) {
            return true;
        }
        return path[self.mount_path.len] == '/';
    }

    /// Serves the asset for the request or reports that the publication is not relevant.
    pub fn serve(
        self: Publication,
        allocator: std.mem.Allocator,
        request: *server_types.ServerRequest,
        writer: *server_types.ServerResponseWriter,
    ) !ServeOutcome {
        try self.validate();
        if (!self.matchesPath(request.uri.path)) {
            return .not_handled;
        }

        if (!methodAllowed(self.allowed_methods, request.method)) {
            writer.setStatus(.method_not_allowed);
            try writer.appendHeader("Allow", "GET, HEAD");
            try writer.appendHeader("Content-Type", "application/json");
            try writer.writeAll("{\"error\":\"method_not_allowed\"}");
            return .served;
        }

        var resolved = self.resolveAsset(allocator, request.uri.path) catch |err| switch (err) {
            error.PathTraversalDetected, error.FileNotFound => {
                writer.setStatus(.not_found);
                try writer.appendHeader("Content-Type", "application/json");
                try writer.writeAll("{\"error\":\"not_found\"}");
                return .served;
            },
            else => return err,
        };
        defer resolved.deinit(allocator);

        writer.setStatus(.ok);
        try writer.appendHeader("Content-Type", resolved.content_type);
        if (resolved.cache_control) |cache_control| {
            try writer.appendHeader("Cache-Control", cache_control);
        }
        if (resolved.etag) |etag| {
            try writer.appendHeader("ETag", etag);
        }

        if (request.method != .head) {
            try writer.writeAll(resolved.bytes);
        }
        return .served;
    }

    /// Resolves an asset for the provided request path and loads its bytes.
    pub fn resolveAsset(
        self: Publication,
        allocator: std.mem.Allocator,
        request_path: []const u8,
    ) !ResolvedAsset {
        const relative_path = try self.relativeAssetPath(allocator, request_path);
        defer allocator.free(relative_path);

        const full_path = try std.fs.path.join(allocator, &.{ self.content_root, relative_path });
        errdefer allocator.free(full_path);
        const bytes = std.fs.cwd().readFileAlloc(allocator, full_path, std.math.maxInt(usize)) catch |err| switch (err) {
            error.FileNotFound => return error.FileNotFound,
            else => return err,
        };
        errdefer allocator.free(bytes);

        return .{
            .full_path = full_path,
            .bytes = bytes,
            .content_type = self.contentTypeForPath(full_path),
            .cache_control = self.cache_control,
            .etag = try self.buildEtag(allocator, bytes),
        };
    }

    /// Returns the relative asset path within the confined content root.
    pub fn relativeAssetPath(
        self: Publication,
        allocator: std.mem.Allocator,
        request_path: []const u8,
    ) ![]u8 {
        if (!self.matchesPath(request_path)) {
            return error.PathTraversalDetected;
        }

        const suffix = if (request_path.len == self.mount_path.len)
            ""
        else
            request_path[self.mount_path.len + 1 ..];

        if (suffix.len == 0) {
            return try allocator.dupe(u8, self.index_files[0]);
        }

        var builder = std.ArrayListUnmanaged(u8){};
        errdefer builder.deinit(allocator);
        var has_segment = false;
        var segments = std.mem.tokenizeAny(u8, suffix, "/\\");
        while (segments.next()) |segment| {
            if (segment.len == 0 or std.mem.eql(u8, segment, ".")) {
                continue;
            }
            if (std.mem.eql(u8, segment, "..")) {
                return error.PathTraversalDetected;
            }
            if (has_segment) {
                try builder.append(allocator, std.fs.path.sep);
            }
            has_segment = true;
            try builder.appendSlice(allocator, segment);
        }
        if (!has_segment) {
            return try allocator.dupe(u8, self.index_files[0]);
        }
        return builder.toOwnedSlice(allocator);
    }

    /// Returns the content type selected for the resolved asset path.
    pub fn contentTypeForPath(self: Publication, asset_path: []const u8) []const u8 {
        for (self.content_type_overrides) |override| {
            if (std.mem.endsWith(u8, asset_path, override.suffix)) {
                return override.content_type;
            }
        }
        if (std.mem.endsWith(u8, asset_path, ".css")) {
            return "text/css";
        }
        if (std.mem.endsWith(u8, asset_path, ".json")) {
            return "application/json";
        }
        if (std.mem.endsWith(u8, asset_path, ".html")) {
            return "text/html";
        }
        return "application/octet-stream";
    }

    /// Builds the configured ETag value for the asset bytes.
    pub fn buildEtag(self: Publication, allocator: std.mem.Allocator, bytes: []const u8) !?[]u8 {
        return switch (self.etag_mode) {
            .none => null,
            .weak_content_hash => blk: {
                var hasher = std.hash.Wyhash.init(0);
                hasher.update(bytes);
                break :blk try std.fmt.allocPrint(allocator, "W/\"{x}\"", .{hasher.final()});
            },
        };
    }
};

/// Returns true when the allowed-method list contains the request method.
fn methodAllowed(allowed_methods: []const core.Method, method: core.Method) bool {
    for (allowed_methods) |allowed| {
        if (std.ascii.eqlIgnoreCase(allowed.asBytes(), method.asBytes())) {
            return true;
        }
    }
    return false;
}

test "static publication validates path confinement and default metadata" {
    const publication = Publication.init("assets", "/assets", "src/lib/testing/fixtures/m6-assets");

    try publication.validate();
    try std.testing.expect(publication.matchesPath("/assets/site.css"));
    try std.testing.expectEqualStrings("text/css", publication.contentTypeForPath("site.css"));
}

test "static publication rejects traversal while resolving the asset path" {
    const publication = Publication.init("assets", "/assets", "fixtures");

    try std.testing.expectError(
        error.PathTraversalDetected,
        publication.relativeAssetPath(std.testing.allocator, "/assets/../secrets.txt"),
    );
}
