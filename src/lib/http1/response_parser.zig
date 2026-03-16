//! HTTP/1.1 response parser and body reader.

const std = @import("std");
const types = @import("../types.zig");

/// Limits applied to HTTP/1.1 response parsing.
pub const Limits = struct {
    /// Maximum length of the status line in bytes.
    max_status_line_bytes: usize,
    /// Maximum total header bytes.
    max_header_bytes: usize,
    /// Maximum number of header fields.
    max_header_count: usize,
    /// Maximum length of a single header line in bytes.
    max_header_line_bytes: usize,
    /// Maximum total body bytes, or null for unlimited.
    max_body_bytes: ?usize,
    /// Maximum allowed chunk size in bytes.
    max_chunk_size: usize,

    /// Returns default limits tuned for early HTTP/1.1 parsing.
    pub fn default() Limits {
        return .{
            .max_status_line_bytes = 8 * 1024,
            .max_header_bytes = 32 * 1024,
            .max_header_count = 100,
            .max_header_line_bytes = 8 * 1024,
            .max_body_bytes = null,
            .max_chunk_size = 8 * 1024 * 1024,
        };
    }
};

/// Parsed status line components.
pub const StatusLine = struct {
    /// Parsed HTTP version.
    version: types.Version,
    /// Parsed status code.
    status: types.Status,
};

/// Parsed header name and value slices.
pub const HeaderLine = struct {
    /// Header name bytes.
    name: []const u8,
    /// Header value bytes.
    value: []const u8,
};

/// Body transfer mode for response payloads.
pub const BodyMode = enum {
    /// Response has no body.
    none,
    /// Content-Length delimited body.
    content_length,
    /// Chunked transfer encoding body.
    chunked,
    /// Body ends at connection close.
    close,
};

/// Returns the numeric value of a hexadecimal digit or null.
fn hexValue(byte: u8) ?usize {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => 10 + (byte - 'a'),
        'A'...'F' => 10 + (byte - 'A'),
        else => null,
    };
}

pub fn ParserError(comptime ReaderType: type) type {
    return ReaderType.Error || std.mem.Allocator.Error || error{
        UnexpectedEof,
        InvalidLineEnding,
        LineTooLong,
        InvalidStatusLine,
        InvalidVersion,
        InvalidStatusCode,
        InvalidHeaderName,
        InvalidHeaderValue,
        HeaderTooLarge,
        HeaderCountExceeded,
        UnsupportedTransferEncoding,
        DuplicateContentLength,
        AmbiguousLength,
        InvalidChunkSize,
        InvalidChunkTerminator,
        BodyTooLarge,
        BodyLengthMismatch,
    };
}

pub fn BufferedReaderReadError(comptime ReaderType: type) type {
    return ReaderType.Error || std.mem.Allocator.Error || error{
        EndOfStream,
        InvalidLineEnding,
        LineTooLong,
    };
}

pub fn ParserBufferedReader(comptime ReaderType: type) type {
    return struct {
        reader: *ReaderType,
        buffer: []u8,
        start: usize,
        end: usize,

        pub fn init(
            reader: *ReaderType,
            buffer: []u8,
            start: usize,
            end: usize,
        ) @This() {
            return .{
                .reader = reader,
                .buffer = buffer,
                .start = start,
                .end = end,
            };
        }

        pub fn readByte(self: *@This()) BufferedReaderReadError(ReaderType)!u8 {
            if (self.start == self.end) {
                try self.fill();
            }
            const byte = self.buffer[self.start];
            self.start += 1;
            return byte;
        }

        pub fn read(self: *@This(), dest: []u8) BufferedReaderReadError(ReaderType)!usize {
            if (dest.len == 0) {
                return 0;
            }
            if (self.start < self.end) {
                const available = self.end - self.start;
                const to_copy = @min(dest.len, available);
                @memcpy(dest[0..to_copy], self.buffer[self.start..][0..to_copy]);
                self.start += to_copy;
                return to_copy;
            }

            const read_len = try self.reader.read(dest);
            if (read_len == 0) {
                return error.EndOfStream;
            }
            return read_len;
        }

        pub fn readLine(
            self: *@This(),
            allocator: std.mem.Allocator,
            line_buffer: *std.ArrayListUnmanaged(u8),
            max_len: usize,
        ) BufferedReaderReadError(ReaderType)![]const u8 {
            line_buffer.clearRetainingCapacity();
            var saw_cr = false;
            while (true) {
                const byte = try self.readByte();
                if (saw_cr) {
                    if (byte != '\n') {
                        return error.InvalidLineEnding;
                    }
                    return line_buffer.items;
                }
                if (byte == '\r') {
                    saw_cr = true;
                    continue;
                }
                if (byte == '\n') {
                    return error.InvalidLineEnding;
                }
                try line_buffer.append(allocator, byte);
                if (line_buffer.items.len > max_len) {
                    return error.LineTooLong;
                }
            }
        }

        fn fill(self: *@This()) BufferedReaderReadError(ReaderType)!void {
            self.start = 0;
            self.end = 0;
            const read_len = try self.reader.read(self.buffer);
            if (read_len == 0) {
                return error.EndOfStream;
            }
            self.end = read_len;
        }
    };
}

pub fn mapParserReadError(comptime ReaderType: type, err: BufferedReaderReadError(ReaderType)) ParserError(ReaderType) {
    if (ReaderType.Error == error{}) {
        return switch (err) {
            error.EndOfStream => error.UnexpectedEof,
            error.InvalidLineEnding => error.InvalidLineEnding,
            error.LineTooLong => error.LineTooLong,
            error.OutOfMemory => error.OutOfMemory,
        };
    }

    return switch (err) {
        error.EndOfStream => error.UnexpectedEof,
        error.InvalidLineEnding => error.InvalidLineEnding,
        error.LineTooLong => error.LineTooLong,
        error.OutOfMemory => error.OutOfMemory,
        else => |other| other,
    };
}

const SlowReaderError = error{};

pub fn ParserBodyState(comptime ReaderType: type) type {
    return struct {
        const Self = @This();
        const BufferedReader = ParserBufferedReader(ReaderType);
        const Error = ParserError(ReaderType);

        allocator: std.mem.Allocator,
        buffered: BufferedReader,
        mode: BodyMode,
        remaining: usize,
        chunk_remaining: usize,
        total_read: usize,
        max_body_bytes: ?usize,
        max_chunk_size: usize,
        line_buffer: std.ArrayListUnmanaged(u8),
        done: bool,

        pub fn readBody(ctx: ?*anyopaque, dest: []u8) anyerror!usize {
            const state: *Self = @ptrCast(@alignCast(ctx.?));
            return state.read(dest);
        }

        pub fn closeBody(ctx: ?*anyopaque) void {
            const state: *Self = @ptrCast(@alignCast(ctx.?));
            state.line_buffer.deinit(state.allocator);
            state.allocator.destroy(state);
        }

        fn read(self: *Self, dest: []u8) Error!usize {
            switch (self.mode) {
                .none => return 0,
                .content_length => return self.readContentLength(dest),
                .chunked => return self.readChunked(dest),
                .close => return self.readUntilClose(dest),
            }
        }

        fn readContentLength(self: *Self, dest: []u8) Error!usize {
            if (self.remaining == 0) {
                return 0;
            }
            const to_read = @min(dest.len, self.remaining);
            const read_len = self.buffered.read(dest[0..to_read]) catch |err| {
                return mapParserReadError(ReaderType, err);
            };
            if (read_len == 0) {
                return error.UnexpectedEof;
            }
            self.remaining -= read_len;
            try self.trackBody(read_len);
            return read_len;
        }

        fn readUntilClose(self: *Self, dest: []u8) Error!usize {
            const read_len = self.buffered.read(dest) catch |err| switch (err) {
                error.EndOfStream => return 0,
                else => return mapParserReadError(ReaderType, err),
            };
            if (read_len == 0) {
                return 0;
            }
            try self.trackBody(read_len);
            return read_len;
        }

        fn readChunked(self: *Self, dest: []u8) Error!usize {
            if (self.done) {
                return 0;
            }
            if (dest.len == 0) {
                return 0;
            }
            if (self.chunk_remaining == 0) {
                const next_size = try self.readChunkSize();
                if (next_size == 0) {
                    try self.readTrailers();
                    self.done = true;
                    return 0;
                }
                self.chunk_remaining = next_size;
            }

            const to_read = @min(dest.len, self.chunk_remaining);
            const read_len = self.buffered.read(dest[0..to_read]) catch |err| {
                return mapParserReadError(ReaderType, err);
            };
            if (read_len == 0) {
                return error.UnexpectedEof;
            }
            self.chunk_remaining -= read_len;
            try self.trackBody(read_len);

            if (self.chunk_remaining == 0) {
                try self.readChunkTerminator();
            }

            return read_len;
        }

        fn readChunkSize(self: *Self) Error!usize {
            const line = self.buffered.readLine(
                self.allocator,
                &self.line_buffer,
                self.max_chunk_size,
            ) catch |err| {
                return mapParserReadError(ReaderType, err);
            };

            const trimmed = std.mem.trim(u8, line, " \t");
            if (trimmed.len == 0) {
                return error.InvalidChunkSize;
            }

            var idx: usize = 0;
            var size: usize = 0;
            while (idx < trimmed.len) : (idx += 1) {
                const byte = trimmed[idx];
                const digit = hexValue(byte) orelse break;
                size = (std.math.mul(usize, size, 16) catch return error.InvalidChunkSize) + digit;
                if (size > self.max_chunk_size) {
                    return error.BodyTooLarge;
                }
            }

            if (idx == 0) {
                return error.InvalidChunkSize;
            }

            if (idx < trimmed.len) {
                const next = trimmed[idx];
                if (next != ';' and next != ' ' and next != '\t') {
                    return error.InvalidChunkSize;
                }
            }

            return size;
        }

        fn readChunkTerminator(self: *Self) Error!void {
            const cr = try self.readExactByte();
            const lf = try self.readExactByte();
            if (cr != '\r' or lf != '\n') {
                return error.InvalidChunkTerminator;
            }
        }

        fn readTrailers(self: *Self) Error!void {
            while (true) {
                const line = self.buffered.readLine(
                    self.allocator,
                    &self.line_buffer,
                    self.max_chunk_size,
                ) catch |err| {
                    return mapParserReadError(ReaderType, err);
                };
                if (line.len == 0) {
                    return;
                }
            }
        }

        fn readExactByte(self: *Self) Error!u8 {
            return self.buffered.readByte() catch |err| {
                return mapParserReadError(ReaderType, err);
            };
        }

        fn trackBody(self: *Self, amount: usize) Error!void {
            self.total_read += amount;
            if (self.max_body_bytes) |limit| {
                if (self.total_read > limit) {
                    return error.BodyTooLarge;
                }
            }
        }
    };
}

/// Creates an HTTP/1.1 response parser for the provided reader type.
pub fn ResponseParser(comptime ReaderType: type) type {
    return struct {
        const Self = @This();

        /// Error set returned by parsing operations.
        pub const Error = ParserError(ReaderType);
        const BufferedReader = ParserBufferedReader(ReaderType);
        const BodyState = ParserBodyState(ReaderType);

        /// Allocator used for header storage and parser state.
        allocator: std.mem.Allocator,
        /// Source reader for response bytes.
        reader: *ReaderType,
        /// Buffer used for incremental reads.
        buffer: []u8,
        /// Current parser limits.
        limits: Limits,
        /// Offset to the first unread byte in the buffer.
        start: usize,
        /// Offset past the last buffered byte.
        end: usize,

        /// Creates a response parser using the provided reader and buffer.
        pub fn init(
            allocator: std.mem.Allocator,
            reader: *ReaderType,
            buffer: []u8,
            limits: Limits,
        ) Self {
            return .{
                .allocator = allocator,
                .reader = reader,
                .buffer = buffer,
                .limits = limits,
                .start = 0,
                .end = 0,
            };
        }

        /// Parses a single HTTP/1.1 response from the reader.
        pub fn readResponse(self: *Self) Error!types.Response {
            var line_buffer = std.ArrayListUnmanaged(u8){};
            defer line_buffer.deinit(self.allocator);

            var buffered = BufferedReader.init(self.reader, self.buffer, self.start, self.end);

            const status_line = try self.readLine(
                &buffered,
                &line_buffer,
                self.limits.max_status_line_bytes,
            );
            const status_info = try parseStatusLine(status_line);

            var response = types.Response.init(self.allocator, status_info.version, status_info.status);
            errdefer response.deinit();

            var header_bytes: usize = 0;
            var header_count: usize = 0;
            var content_length: ?usize = null;
            var saw_transfer_encoding = false;
            var chunked = false;

            while (true) {
                const header_line = try self.readLine(
                    &buffered,
                    &line_buffer,
                    self.limits.max_header_line_bytes,
                );
                if (header_line.len == 0) {
                    break;
                }

                header_bytes += header_line.len + 2;
                if (header_bytes > self.limits.max_header_bytes) {
                    return error.HeaderTooLarge;
                }

                header_count += 1;
                if (header_count > self.limits.max_header_count) {
                    return error.HeaderCountExceeded;
                }

                const header = try parseHeaderLine(header_line);
                try validateHeaderName(header.name);
                try validateHeaderValue(header.value);
                try response.headers.append(header.name, header.value);

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

            if (chunked and content_length != null) {
                return error.AmbiguousLength;
            }

            const body_mode = selectBodyMode(status_info.status, chunked, content_length);
            if (body_mode == .content_length and content_length != null) {
                if (self.limits.max_body_bytes) |max_body| {
                    if (content_length.? > max_body) {
                        return error.BodyTooLarge;
                    }
                }
            }

            response.body = try self.makeBodyReader(
                &buffered,
                body_mode,
                content_length,
            );

            self.start = buffered.start;
            self.end = buffered.end;

            return response;
        }

        /// Parses a CRLF-terminated line using the provided buffer.
        fn readLine(
            self: *Self,
            buffered: *BufferedReader,
            line_buffer: *std.ArrayListUnmanaged(u8),
            max_len: usize,
        ) Error![]const u8 {
            const line = buffered.readLine(self.allocator, line_buffer, max_len) catch |err| {
                return mapParserReadError(ReaderType, err);
            };
            return line;
        }

        /// Creates a body reader based on the selected mode.
        fn makeBodyReader(
            self: *Self,
            buffered: *BufferedReader,
            mode: BodyMode,
            content_length: ?usize,
        ) Error!?types.BodyReader {
            if (mode == .none) {
                return null;
            }

            const state = try self.allocator.create(BodyState);
            state.* = BodyState{
                .allocator = self.allocator,
                .buffered = buffered.*,
                .mode = mode,
                .remaining = content_length orelse 0,
                .chunk_remaining = 0,
                .total_read = 0,
                .max_body_bytes = self.limits.max_body_bytes,
                .max_chunk_size = self.limits.max_chunk_size,
                .line_buffer = .{},
                .done = false,
            };

            return .{
                .ctx = state,
                .read_fn = BodyState.readBody,
                .close_fn = BodyState.closeBody,
            };
        }

        /// Parse the HTTP status line into version and status.
        fn parseStatusLine(line: []const u8) Error!StatusLine {
            const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse return error.InvalidStatusLine;
            const version_bytes = line[0..first_space];
            const version = parseVersion(version_bytes) catch return error.InvalidVersion;

            const rest = line[first_space + 1 ..];
            if (rest.len < 3) {
                return error.InvalidStatusCode;
            }
            const code_bytes = rest[0..3];
            const status_code = parseStatusCode(code_bytes) catch return error.InvalidStatusCode;

            return .{
                .version = version,
                .status = @enumFromInt(status_code),
            };
        }

        /// Parses the HTTP version token.
        fn parseVersion(bytes: []const u8) Error!types.Version {
            if (std.mem.eql(u8, bytes, "HTTP/1.1")) {
                return .http_1_1;
            }
            if (std.mem.eql(u8, bytes, "HTTP/1.0")) {
                return .http_1_0;
            }
            return error.InvalidVersion;
        }

        /// Parses a three-digit status code.
        fn parseStatusCode(bytes: []const u8) Error!u16 {
            if (bytes.len != 3) {
                return error.InvalidStatusCode;
            }
            var value: u16 = 0;
            for (bytes) |byte| {
                if (byte < '0' or byte > '9') {
                    return error.InvalidStatusCode;
                }
                value = value * 10 + @as(u16, byte - '0');
            }
            return value;
        }

        /// Parses a header line into name and value.
        fn parseHeaderLine(line: []const u8) Error!HeaderLine {
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHeaderName;
            if (colon == 0) {
                return error.InvalidHeaderName;
            }
            const name = line[0..colon];
            const value_raw = line[colon + 1 ..];
            const value = std.mem.trim(u8, value_raw, " \t");
            return .{
                .name = name,
                .value = value,
            };
        }

        /// Validates a header name for token compliance.
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

        /// Determines the body mode based on status and headers.
        fn selectBodyMode(
            status: types.Status,
            chunked: bool,
            content_length: ?usize,
        ) BodyMode {
            const code = status.code();
            if ((code >= 100 and code < 200) or code == 204 or code == 304) {
                return .none;
            }
            if (chunked) {
                return .chunked;
            }
            if (content_length != null) {
                return .content_length;
            }
            return .close;
        }

        /// Returns true when the byte is a valid token character.
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

/// Reader that returns data in fixed-size chunks for testing.
const SlowReader = struct {
    /// Source payload bytes.
    data: []const u8,
    /// Current read position.
    index: usize,
    /// Maximum bytes returned per read call.
    max_chunk: usize,

    /// Error set for SlowReader reads.
    pub const Error = SlowReaderError;

    /// Creates a slow reader for the provided data.
    pub fn init(data: []const u8, max_chunk: usize) SlowReader {
        return .{
            .data = data,
            .index = 0,
            .max_chunk = max_chunk,
        };
    }

    /// Reads up to `dest.len` bytes with a fixed chunk limit.
    pub fn read(self: *SlowReader, dest: []u8) Error!usize {
        if (self.index >= self.data.len) {
            return 0;
        }
        const remaining = self.data.len - self.index;
        const to_read = @min(dest.len, @min(self.max_chunk, remaining));
        @memcpy(dest[0..to_read], self.data[self.index..][0..to_read]);
        self.index += to_read;
        return to_read;
    }
};

test "response parser handles content-length" {
    const payload =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: 5\r\n" ++
        "Connection: close\r\n" ++
        "\r\n" ++
        "Hello";

    var stream = std.io.fixedBufferStream(payload);
    var reader = stream.reader();
    var buffer: [64]u8 = undefined;

    var parser = ResponseParser(@TypeOf(reader)).init(
        std.testing.allocator,
        &reader,
        &buffer,
        Limits.default(),
    );

    var response = try parser.readResponse();
    defer response.deinit();
    defer if (response.body) |body| body.close();

    try std.testing.expectEqual(types.Version.http_1_1, response.version);
    try std.testing.expectEqual(types.Status.ok, response.status);
    try std.testing.expectEqualStrings("5", response.headers.get("content-length").?);

    var body_buf: [8]u8 = undefined;
    const read_len = try response.body.?.read(body_buf[0..]);
    try std.testing.expectEqual(@as(usize, 5), read_len);
    try std.testing.expectEqualStrings("Hello", body_buf[0..read_len]);
    const eof = try response.body.?.read(body_buf[0..]);
    try std.testing.expectEqual(@as(usize, 0), eof);
}

test "response parser handles chunked with split boundaries" {
    const payload =
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "4\r\nWiki\r\n" ++
        "5\r\npedia\r\n" ++
        "0\r\n" ++
        "\r\n";

    var reader = SlowReader.init(payload, 1);
    var buffer: [16]u8 = undefined;

    var parser = ResponseParser(SlowReader).init(
        std.testing.allocator,
        &reader,
        &buffer,
        Limits.default(),
    );

    var response = try parser.readResponse();
    defer response.deinit();
    defer if (response.body) |body| body.close();

    var out: [16]u8 = undefined;
    var total: usize = 0;
    while (true) {
        const n = try response.body.?.read(out[total..]);
        if (n == 0) {
            break;
        }
        total += n;
    }
    try std.testing.expectEqualStrings("Wikipedia", out[0..total]);
}

test "response parser rejects malformed chunk size" {
    const payload =
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "Z\r\n" ++
        "0\r\n\r\n";

    var stream = std.io.fixedBufferStream(payload);
    var reader = stream.reader();
    var buffer: [32]u8 = undefined;

    var parser = ResponseParser(@TypeOf(reader)).init(
        std.testing.allocator,
        &reader,
        &buffer,
        Limits.default(),
    );

    var response = try parser.readResponse();
    defer response.deinit();
    defer if (response.body) |body| body.close();

    var body_buf: [4]u8 = undefined;
    try std.testing.expectError(error.InvalidChunkSize, response.body.?.read(&body_buf));
}

test "response parser enforces header size limit" {
    const payload =
        "HTTP/1.1 200 OK\r\n" ++
        "X-Test: 1234\r\n" ++
        "\r\n";

    var stream = std.io.fixedBufferStream(payload);
    var reader = stream.reader();
    var buffer: [64]u8 = undefined;
    var limits = Limits.default();
    limits.max_header_bytes = 8;

    var parser = ResponseParser(@TypeOf(reader)).init(
        std.testing.allocator,
        &reader,
        &buffer,
        limits,
    );

    try std.testing.expectError(error.HeaderTooLarge, parser.readResponse());
}

test "response parser rejects invalid line ending" {
    const payload = "HTTP/1.1 200 OK\n";

    var stream = std.io.fixedBufferStream(payload);
    var reader = stream.reader();
    var buffer: [16]u8 = undefined;

    var parser = ResponseParser(@TypeOf(reader)).init(
        std.testing.allocator,
        &reader,
        &buffer,
        Limits.default(),
    );

    try std.testing.expectError(error.InvalidLineEnding, parser.readResponse());
}
