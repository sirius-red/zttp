//! HTTP/1.1 request encoder and body writer.

const std = @import("std");
const types = @import("../types.zig");

/// Request target format used for the request line.
pub const RequestTargetMode = enum {
    /// Origin-form request target (path + optional query).
    origin_form,
    /// Absolute-form request target (scheme + authority + path).
    absolute_form,
};

/// Creates an HTTP/1.1 request encoder for the provided writer type.
pub fn RequestEncoder(comptime WriterType: type) type {
    return struct {
        const Self = @This();

        /// Error set returned by request encoding operations.
        pub const Error = WriterType.Error || std.fmt.BufPrintError || error{
            InvalidMethod,
            InvalidVersion,
            InvalidRequestTarget,
            InvalidHeaderName,
            InvalidHeaderValue,
            UnsupportedTransferEncoding,
            MissingContentLength,
            AmbiguousLength,
            DuplicateContentLength,
            BodyTooLarge,
            BodyLengthMismatch,
            BodyClosed,
        };

        /// Encoder output writer.
        writer: *WriterType,

        /// Creates a new encoder for the provided writer.
        pub fn init(writer: *WriterType) Self {
            return .{ .writer = writer };
        }

        /// Streaming body writer for request payloads.
        pub const BodyWriter = struct {
            /// Underlying writer for body bytes.
            writer: *WriterType,
            /// Body transfer mode.
            mode: BodyMode,
            /// Remaining bytes for content-length mode.
            remaining: usize,
            /// Indicates the body has been finalized.
            finalized: bool,

            /// Writes the provided bytes to the request body.
            pub fn writeAll(self: *BodyWriter, bytes: []const u8) Error!void {
                if (self.finalized) {
                    return error.BodyClosed;
                }

                switch (self.mode) {
                    .none => return error.BodyTooLarge,
                    .content_length => {
                        if (bytes.len > self.remaining) {
                            return error.BodyTooLarge;
                        }
                        if (bytes.len == 0) {
                            return;
                        }
                        try self.writer.writeAll(bytes);
                        self.remaining -= bytes.len;
                    },
                    .chunked => try writeChunk(self, bytes),
                }
            }

            /// Flushes the body writer and finalizes chunked encoding if used.
            pub fn flush(self: *BodyWriter) Error!void {
                if (self.finalized) {
                    return;
                }

                switch (self.mode) {
                    .none => {},
                    .content_length => {
                        if (self.remaining != 0) {
                            return error.BodyLengthMismatch;
                        }
                    },
                    .chunked => {
                        try self.writer.writeAll("0\r\n\r\n");
                    },
                }

                self.finalized = true;
            }

            /// Writes a single chunk in chunked transfer encoding.
            fn writeChunk(self: *BodyWriter, bytes: []const u8) Error!void {
                if (bytes.len == 0) {
                    return;
                }

                var header_buf: [32]u8 = undefined;
                const header = try std.fmt.bufPrint(&header_buf, "{x}\r\n", .{bytes.len});
                try self.writer.writeAll(header);
                try self.writer.writeAll(bytes);
                try self.writer.writeAll("\r\n");
            }
        };

        /// Encodes the request line and headers, returning a body writer.
        pub fn writeRequest(
            self: *Self,
            request: *const types.Request,
            target_mode: RequestTargetMode,
        ) Error!BodyWriter {
            try validateMethod(request.method);
            try validateVersion(request.version);
            try validateRequestTarget(request.uri, target_mode);

            try self.writer.writeAll(request.method.asBytes());
            try self.writer.writeByte(' ');
            try writeRequestTarget(self.writer, request.uri, target_mode);
            try self.writer.writeByte(' ');
            try self.writer.writeAll(request.version.asBytes());
            try self.writer.writeAll("\r\n");

            const header_info = try analyzeHeaders(&request.headers);

            var iter = request.headers.iterator();
            while (iter.next()) |header| {
                try writeHeader(self.writer, header);
            }

            try self.writer.writeAll("\r\n");

            if (request.body != null and header_info.mode == .none) {
                return error.MissingContentLength;
            }

            return .{
                .writer = self.writer,
                .mode = header_info.mode,
                .remaining = header_info.content_length,
                .finalized = false,
            };
        }

        /// Body transfer mode for encoded requests.
        const BodyMode = enum {
            /// No body is allowed.
            none,
            /// Content-Length is enforced.
            content_length,
            /// Chunked transfer encoding is used.
            chunked,
        };

        /// Parsed header metadata.
        const HeaderInfo = struct {
            /// Selected body mode.
            mode: BodyMode,
            /// Parsed content length when present.
            content_length: usize,
        };

        /// Parses headers to determine transfer mode and validate bytes.
        fn analyzeHeaders(headers: *const types.Headers) Error!HeaderInfo {
            var content_length: ?usize = null;
            var saw_transfer_encoding = false;
            var chunked = false;

            var iter = headers.iterator();
            while (iter.next()) |header| {
                try validateHeaderName(header.name);
                try validateHeaderValue(header.value);

                if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
                    const parsed = try parseContentLength(header.value);
                    if (content_length) |existing| {
                        if (existing != parsed) {
                            return error.DuplicateContentLength;
                        }
                    } else {
                        content_length = parsed;
                    }
                } else if (std.ascii.eqlIgnoreCase(header.name, "transfer-encoding")) {
                    if (saw_transfer_encoding) {
                        return error.UnsupportedTransferEncoding;
                    }
                    saw_transfer_encoding = true;
                    chunked = try parseTransferEncoding(header.value);
                }
            }

            if (chunked) {
                if (content_length != null) {
                    return error.AmbiguousLength;
                }
                return .{
                    .mode = .chunked,
                    .content_length = 0,
                };
            }

            if (content_length) |length| {
                return .{
                    .mode = .content_length,
                    .content_length = length,
                };
            }

            return .{
                .mode = .none,
                .content_length = 0,
            };
        }

        /// Writes the request target using the selected mode.
        fn writeRequestTarget(
            writer: *WriterType,
            uri: types.Uri,
            target_mode: RequestTargetMode,
        ) Error!void {
            switch (target_mode) {
                .origin_form => try writeOriginTarget(writer, uri),
                .absolute_form => try writeAbsoluteTarget(writer, uri),
            }
        }

        /// Writes an origin-form request target.
        fn writeOriginTarget(writer: *WriterType, uri: types.Uri) Error!void {
            try writer.writeAll(uri.path);
            if (uri.query) |query| {
                try writer.writeByte('?');
                try writer.writeAll(query);
            }
        }

        /// Writes an absolute-form request target.
        fn writeAbsoluteTarget(writer: *WriterType, uri: types.Uri) Error!void {
            try writer.writeAll(uri.scheme.asBytes());
            try writer.writeAll("://");
            try writer.writeAll(uri.host);
            if (uri.port) |port| {
                var port_buffer: [8]u8 = undefined;
                const port_bytes = try std.fmt.bufPrint(&port_buffer, ":{d}", .{port.toInt()});
                try writer.writeAll(port_bytes);
            }
            try writer.writeAll(uri.path);
            if (uri.query) |query| {
                try writer.writeByte('?');
                try writer.writeAll(query);
            }
        }

        /// Writes a header line with canonicalized name.
        fn writeHeader(writer: *WriterType, header: types.Headers.Header) Error!void {
            try writeHeaderName(writer, header.name);
            try writer.writeAll(": ");
            try writer.writeAll(header.value);
            try writer.writeAll("\r\n");
        }

        /// Writes a header name using lowercase ASCII.
        fn writeHeaderName(writer: *WriterType, name: []const u8) Error!void {
            for (name) |byte| {
                try writer.writeByte(std.ascii.toLower(byte));
            }
        }

        /// Parses a Content-Length header value into a byte count.
        fn parseContentLength(value: []const u8) Error!usize {
            const trimmed = std.mem.trim(u8, value, " \t");
            if (trimmed.len == 0) {
                return error.InvalidHeaderValue;
            }

            var total: usize = 0;
            for (trimmed) |byte| {
                if (byte < '0' or byte > '9') {
                    return error.InvalidHeaderValue;
                }
                const digit = byte - '0';
                const shifted = std.math.mul(usize, total, 10) catch return error.InvalidHeaderValue;
                total = std.math.add(usize, shifted, digit) catch return error.InvalidHeaderValue;
            }

            return total;
        }

        /// Parses Transfer-Encoding and returns true for chunked.
        fn parseTransferEncoding(value: []const u8) Error!bool {
            const trimmed = std.mem.trim(u8, value, " \t");
            if (trimmed.len == 0) {
                return error.InvalidHeaderValue;
            }
            if (std.mem.indexOfScalar(u8, trimmed, ',')) |_| {
                return error.UnsupportedTransferEncoding;
            }
            if (std.ascii.eqlIgnoreCase(trimmed, "chunked")) {
                return true;
            }
            return error.UnsupportedTransferEncoding;
        }

        /// Validates that the method bytes are legal tokens.
        fn validateMethod(method: types.Method) Error!void {
            const bytes = method.asBytes();
            if (bytes.len == 0) {
                return error.InvalidMethod;
            }
            for (bytes) |byte| {
                if (!isTokenChar(byte)) {
                    return error.InvalidMethod;
                }
            }
        }

        /// Validates that the HTTP version is supported by the encoder.
        fn validateVersion(version: types.Version) Error!void {
            switch (version) {
                .http_1_0, .http_1_1 => {},
                else => return error.InvalidVersion,
            }
        }

        /// Validates the request target for invalid bytes.
        fn validateRequestTarget(uri: types.Uri, target_mode: RequestTargetMode) Error!void {
            switch (target_mode) {
                .origin_form => try validateOriginTarget(uri),
                .absolute_form => try validateAbsoluteTarget(uri),
            }
        }

        /// Validates an origin-form request target.
        fn validateOriginTarget(uri: types.Uri) Error!void {
            if (uri.path.len == 0 or uri.path[0] != '/') {
                return error.InvalidRequestTarget;
            }
            try validateTargetBytes(uri.path);
            if (uri.query) |query| {
                try validateTargetBytes(query);
            }
        }

        /// Validates an absolute-form request target.
        fn validateAbsoluteTarget(uri: types.Uri) Error!void {
            if (uri.scheme != .http and uri.scheme != .https) {
                return error.InvalidRequestTarget;
            }
            if (uri.host.len == 0) {
                return error.InvalidRequestTarget;
            }
            if (uri.path.len == 0 or uri.path[0] != '/') {
                return error.InvalidRequestTarget;
            }
            try validateAuthorityBytes(uri.host);
            try validateTargetBytes(uri.path);
            if (uri.query) |query| {
                try validateTargetBytes(query);
            }
        }

        /// Validates a header name for RFC token compliance.
        fn validateHeaderName(name: []const u8) Error!void {
            if (name.len == 0) {
                return error.InvalidHeaderName;
            }
            for (name) |byte| {
                if (!isTokenChar(byte)) {
                    return error.InvalidHeaderName;
                }
            }
        }

        /// Validates a header value for invalid bytes.
        fn validateHeaderValue(value: []const u8) Error!void {
            for (value) |byte| {
                if (byte == '\r' or byte == '\n' or byte == 0) {
                    return error.InvalidHeaderValue;
                }
                if (byte < 0x20 and byte != '\t') {
                    return error.InvalidHeaderValue;
                }
                if (byte == 0x7f) {
                    return error.InvalidHeaderValue;
                }
            }
        }

        /// Validates request target bytes for control or space characters.
        fn validateTargetBytes(bytes: []const u8) Error!void {
            for (bytes) |byte| {
                if (byte <= 0x20 or byte == 0x7f) {
                    return error.InvalidRequestTarget;
                }
            }
        }

        /// Validates authority bytes for invalid delimiter characters.
        fn validateAuthorityBytes(bytes: []const u8) Error!void {
            for (bytes) |byte| {
                if (byte <= 0x20 or byte == 0x7f) {
                    return error.InvalidRequestTarget;
                }
                if (byte == '/' or byte == '?' or byte == '#' or byte == '@') {
                    return error.InvalidRequestTarget;
                }
            }
        }

        /// Returns true if the byte is a valid token character.
        fn isTokenChar(byte: u8) bool {
            return switch (byte) {
                '0'...'9',
                'A'...'Z',
                'a'...'z',
                '!',
                '#',
                '$',
                '%',
                '&',
                '\'',
                '*',
                '+',
                '-',
                '.',
                '^',
                '_',
                '`',
                '|',
                '~',
                => true,
                else => false,
            };
        }
    };
}

test "request encoder writes content-length body" {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(std.testing.allocator);

    const uri = types.Uri.init(.http, "example.com", null, "/path", "a=1", null);
    var request = types.Request.init(std.testing.allocator, .post, uri);
    defer request.deinit();

    try request.headers.append("Host", "example.com");
    try request.headers.append("Content-Length", "5");

    var writer = list.writer(std.testing.allocator);
    var encoder = RequestEncoder(@TypeOf(writer)).init(&writer);
    var body = try encoder.writeRequest(&request, .origin_form);
    try body.writeAll("hello");
    try body.flush();

    const expected =
        "POST /path?a=1 HTTP/1.1\r\n" ++
        "host: example.com\r\n" ++
        "content-length: 5\r\n" ++
        "\r\n" ++
        "hello";
    try std.testing.expectEqualStrings(expected, list.items);
}

test "request encoder writes absolute-form request target" {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(std.testing.allocator);

    const uri = types.Uri.init(.http, "example.com", types.Port.init(8080), "/proxy", "x=1", null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();

    try request.headers.append("Host", "example.com");

    var writer = list.writer(std.testing.allocator);
    var encoder = RequestEncoder(@TypeOf(writer)).init(&writer);
    _ = try encoder.writeRequest(&request, .absolute_form);

    const expected =
        "GET http://example.com:8080/proxy?x=1 HTTP/1.1\r\n" ++
        "host: example.com\r\n" ++
        "\r\n";
    try std.testing.expectEqualStrings(expected, list.items);
}

test "request encoder writes chunked body" {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(std.testing.allocator);

    const uri = types.Uri.init(.http, "example.com", null, "/", null, null);
    var request = types.Request.init(std.testing.allocator, .post, uri);
    defer request.deinit();

    try request.headers.append("Host", "example.com");
    try request.headers.append("Transfer-Encoding", "chunked");

    var writer = list.writer(std.testing.allocator);
    var encoder = RequestEncoder(@TypeOf(writer)).init(&writer);
    var body = try encoder.writeRequest(&request, .origin_form);
    try body.writeAll("hi");
    try body.flush();

    const expected =
        "POST / HTTP/1.1\r\n" ++
        "host: example.com\r\n" ++
        "transfer-encoding: chunked\r\n" ++
        "\r\n" ++
        "2\r\nhi\r\n0\r\n\r\n";
    try std.testing.expectEqualStrings(expected, list.items);
}

test "request encoder rejects invalid header name" {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(std.testing.allocator);

    const uri = types.Uri.init(.http, "example.com", null, "/", null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();

    try request.headers.append("Bad Header", "value");

    var writer = list.writer(std.testing.allocator);
    var encoder = RequestEncoder(@TypeOf(writer)).init(&writer);
    try std.testing.expectError(error.InvalidHeaderName, encoder.writeRequest(&request, .origin_form));
}

test "request encoder rejects invalid header value" {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(std.testing.allocator);

    const uri = types.Uri.init(.http, "example.com", null, "/", null, null);
    var request = types.Request.init(std.testing.allocator, .get, uri);
    defer request.deinit();

    try request.headers.append("Host", "example.com");
    try request.headers.append("X-Test", "ok\r\nbad");

    var writer = list.writer(std.testing.allocator);
    var encoder = RequestEncoder(@TypeOf(writer)).init(&writer);
    try std.testing.expectError(error.InvalidHeaderValue, encoder.writeRequest(&request, .origin_form));
}

test "request encoder rejects unsupported transfer encoding" {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(std.testing.allocator);

    const uri = types.Uri.init(.http, "example.com", null, "/", null, null);
    var request = types.Request.init(std.testing.allocator, .post, uri);
    defer request.deinit();

    try request.headers.append("Transfer-Encoding", "gzip");

    var writer = list.writer(std.testing.allocator);
    var encoder = RequestEncoder(@TypeOf(writer)).init(&writer);
    try std.testing.expectError(error.UnsupportedTransferEncoding, encoder.writeRequest(&request, .origin_form));
}

test "request encoder enforces content length" {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(std.testing.allocator);

    const uri = types.Uri.init(.http, "example.com", null, "/", null, null);
    var request = types.Request.init(std.testing.allocator, .post, uri);
    defer request.deinit();

    try request.headers.append("Content-Length", "2");

    var writer = list.writer(std.testing.allocator);
    var encoder = RequestEncoder(@TypeOf(writer)).init(&writer);
    var body = try encoder.writeRequest(&request, .origin_form);
    try std.testing.expectError(error.BodyTooLarge, body.writeAll("abc"));
}

test "request encoder rejects missing content length for body" {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(std.testing.allocator);

    const uri = types.Uri.init(.http, "example.com", null, "/", null, null);
    var request = types.Request.init(std.testing.allocator, .post, uri);
    defer request.deinit();

    const reader = types.BodyReader{
        .ctx = null,
        .read_fn = readNoop,
        .close_fn = null,
    };
    request.body = reader;

    var writer = list.writer(std.testing.allocator);
    var encoder = RequestEncoder(@TypeOf(writer)).init(&writer);
    try std.testing.expectError(error.MissingContentLength, encoder.writeRequest(&request, .origin_form));
}

/// Returns end-of-stream without producing data.
fn readNoop(_: ?*anyopaque, _: []u8) types.BodyReader.ReadError!usize {
    return 0;
}
