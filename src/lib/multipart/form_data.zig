//! Typed multipart form-data payload foundations.

const std = @import("std");

/// Replayability classification for one multipart payload.
pub const Replayability = enum {
    /// The payload can be safely replayed from owned bytes.
    replayable,
    /// The payload depends on one-shot external state.
    one_shot,
};

/// Explicit multipart boundary token.
pub const Boundary = struct {
    /// Boundary value without the leading `--`.
    value: []const u8,

    /// Creates a boundary wrapper from a stable value.
    pub fn init(value: []const u8) Boundary {
        return .{ .value = value };
    }
};

/// Named text field part.
pub const FieldPart = struct {
    /// Field name.
    name: []u8,
    /// Field value.
    value: []u8,
};

/// Named file part with owned bytes.
pub const FilePart = struct {
    /// Form field name.
    name: []u8,
    /// Uploaded file name.
    filename: []u8,
    /// File content type.
    content_type: []u8,
    /// Owned file bytes.
    bytes: []u8,
};

/// Typed multipart part.
pub const Part = union(enum) {
    /// Named text field.
    field: FieldPart,
    /// Named file part.
    file: FilePart,

    /// Releases the owned bytes for the part.
    pub fn deinit(self: *Part, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .field => |field| {
                allocator.free(field.name);
                allocator.free(field.value);
            },
            .file => |file| {
                allocator.free(file.name);
                allocator.free(file.filename);
                allocator.free(file.content_type);
                allocator.free(file.bytes);
            },
        }
        self.* = undefined;
    }
};

/// Typed multipart payload with owned parts.
pub const FormData = struct {
    /// Allocator used for the owned parts.
    allocator: std.mem.Allocator,
    /// Explicit boundary token.
    boundary: Boundary,
    /// Replayability classification for the payload.
    replayability: Replayability,
    /// Owned multipart parts.
    parts: std.ArrayListUnmanaged(Part),

    /// Initializes an empty multipart payload.
    pub fn init(allocator: std.mem.Allocator, boundary: Boundary) FormData {
        return .{
            .allocator = allocator,
            .boundary = boundary,
            .replayability = .replayable,
            .parts = .{},
        };
    }

    /// Releases all owned parts.
    pub fn deinit(self: *FormData) void {
        for (self.parts.items) |*part| {
            part.deinit(self.allocator);
        }
        self.parts.deinit(self.allocator);
        self.* = undefined;
    }

    /// Appends an owned text field to the payload.
    pub fn appendField(self: *FormData, name: []const u8, value: []const u8) !void {
        try self.parts.append(self.allocator, .{
            .field = .{
                .name = try self.allocator.dupe(u8, name),
                .value = try self.allocator.dupe(u8, value),
            },
        });
    }

    /// Appends an owned file part to the payload.
    pub fn appendFile(
        self: *FormData,
        name: []const u8,
        filename: []const u8,
        content_type: []const u8,
        bytes: []const u8,
    ) !void {
        try self.parts.append(self.allocator, .{
            .file = .{
                .name = try self.allocator.dupe(u8, name),
                .filename = try self.allocator.dupe(u8, filename),
                .content_type = try self.allocator.dupe(u8, content_type),
                .bytes = try self.allocator.dupe(u8, bytes),
            },
        });
    }

    /// Returns a typed multipart content-type header value.
    pub fn contentTypeAlloc(self: FormData, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "multipart/form-data; boundary={s}",
            .{self.boundary.value},
        );
    }
};

test "form data stores owned field and file parts" {
    var form = FormData.init(std.testing.allocator, Boundary.init("boundary-123"));
    defer form.deinit();

    try form.appendField("name", "alice");
    try form.appendFile("avatar", "a.png", "image/png", "png");

    try std.testing.expectEqual(@as(usize, 2), form.parts.items.len);
    try std.testing.expectEqual(Replayability.replayable, form.replayability);

    const content_type = try form.contentTypeAlloc(std.testing.allocator);
    defer std.testing.allocator.free(content_type);
    try std.testing.expect(std.mem.containsAtLeast(u8, content_type, 1, "boundary-123"));
}
