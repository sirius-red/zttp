//! Typed multipart form-data payload foundations.

const std = @import("std");

/// Replayability classification for one multipart payload.
pub const Replayability = enum {
    /// The payload can be safely replayed from owned bytes.
    replayable,
    /// The payload depends on one-shot external state.
    one_shot,
};

/// Content-length strategy used when serializing a multipart payload.
pub const ContentLengthMode = enum {
    /// The payload can be serialized to a fully known byte sequence.
    known,
    /// The payload must be streamed until EOF and is not replay-safe.
    stream_until_eof,
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
    /// Content-length strategy used when encoding the payload.
    content_length_mode: ContentLengthMode,
    /// Replayability classification for the payload.
    replayability: Replayability,
    /// Owned multipart parts.
    parts: std.ArrayListUnmanaged(Part),

    /// Initializes an empty multipart payload.
    pub fn init(allocator: std.mem.Allocator, boundary: Boundary) FormData {
        return .{
            .allocator = allocator,
            .boundary = boundary,
            .content_length_mode = .known,
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
        self.refreshReplayability();
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
        self.refreshReplayability();
    }

    /// Updates the serialization mode used for the payload.
    pub fn setContentLengthMode(self: *FormData, mode: ContentLengthMode) void {
        self.content_length_mode = mode;
        self.refreshReplayability();
    }

    /// Marks the payload as explicitly one-shot.
    pub fn markOneShot(self: *FormData) void {
        self.replayability = .one_shot;
    }

    /// Returns a typed multipart content-type header value.
    pub fn contentTypeAlloc(self: FormData, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "multipart/form-data; boundary={s}",
            .{self.boundary.value},
        );
    }

    /// Serializes the multipart payload into one owned byte buffer.
    pub fn renderAlloc(self: FormData, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        var bytes = std.ArrayListUnmanaged(u8){};
        errdefer bytes.deinit(allocator);

        for (self.parts.items) |part| {
            try bytes.writer(allocator).print("--{s}\r\n", .{self.boundary.value});

            switch (part) {
                .field => |field| {
                    try bytes.writer(allocator).print(
                        "Content-Disposition: form-data; name=\"{s}\"\r\n\r\n{s}\r\n",
                        .{ field.name, field.value },
                    );
                },
                .file => |file| {
                    try bytes.writer(allocator).print(
                        "Content-Disposition: form-data; name=\"{s}\"; filename=\"{s}\"\r\n",
                        .{ file.name, file.filename },
                    );
                    try bytes.writer(allocator).print(
                        "Content-Type: {s}\r\n\r\n",
                        .{file.content_type},
                    );
                    try bytes.appendSlice(allocator, file.bytes);
                    try bytes.appendSlice(allocator, "\r\n");
                },
            }
        }

        try bytes.writer(allocator).print("--{s}--\r\n", .{self.boundary.value});
        return bytes.toOwnedSlice(allocator);
    }

    /// Refreshes the replayability classification from the current payload state.
    fn refreshReplayability(self: *FormData) void {
        if (self.replayability == .one_shot) {
            return;
        }
        self.replayability = switch (self.content_length_mode) {
            .known => .replayable,
            .stream_until_eof => .one_shot,
        };
    }
};

/// Typed builder for multipart payload construction.
pub const Builder = struct {
    /// Mutable form under construction.
    form: FormData,

    /// Initializes a builder with an empty payload.
    pub fn init(allocator: std.mem.Allocator, boundary: Boundary) Builder {
        return .{
            .form = FormData.init(allocator, boundary),
        };
    }

    /// Releases all builder-owned parts.
    pub fn deinit(self: *Builder) void {
        self.form.deinit();
        self.* = undefined;
    }

    /// Appends a text field to the in-progress payload.
    pub fn addField(self: *Builder, name: []const u8, value: []const u8) !void {
        try self.form.appendField(name, value);
    }

    /// Appends a file part to the in-progress payload.
    pub fn addFile(
        self: *Builder,
        name: []const u8,
        filename: []const u8,
        content_type: []const u8,
        bytes: []const u8,
    ) !void {
        try self.form.appendFile(name, filename, content_type, bytes);
    }

    /// Sets the payload serialization mode.
    pub fn setContentLengthMode(self: *Builder, mode: ContentLengthMode) void {
        self.form.setContentLengthMode(mode);
    }

    /// Marks the payload as explicitly one-shot.
    pub fn markOneShot(self: *Builder) void {
        self.form.markOneShot();
    }

    /// Returns the current replayability classification.
    pub fn replayability(self: *const Builder) Replayability {
        return self.form.replayability;
    }

    /// Transfers ownership of the built form to the caller.
    pub fn finish(self: *Builder) FormData {
        const form = self.form;
        self.* = undefined;
        return form;
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

test "multipart builder renders payload bytes and one-shot classification explicitly" {
    var builder = Builder.init(std.testing.allocator, Boundary.init("boundary-456"));
    try builder.addField("name", "alice");
    try builder.addFile("avatar", "a.png", "image/png", "png");
    builder.setContentLengthMode(.stream_until_eof);

    var form = builder.finish();
    defer form.deinit();

    const rendered = try form.renderAlloc(std.testing.allocator);
    defer std.testing.allocator.free(rendered);

    try std.testing.expectEqual(Replayability.one_shot, form.replayability);
    try std.testing.expect(std.mem.containsAtLeast(u8, rendered, 1, "Content-Disposition: form-data; name=\"name\""));
    try std.testing.expect(std.mem.containsAtLeast(u8, rendered, 1, "filename=\"a.png\""));
    try std.testing.expect(std.mem.containsAtLeast(u8, rendered, 1, "Content-Type: image/png"));
}
