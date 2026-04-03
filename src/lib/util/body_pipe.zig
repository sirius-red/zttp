//! Bounded in-memory pipe for streaming response bodies between threads.

const std = @import("std");

/// Error set returned by `init`.
pub const InitError = std.mem.Allocator.Error || error{InvalidCapacity};
/// Error set returned by `writeAll`.
pub const WriteError = error{ReaderClosed};

/// Provides a bounded byte pipe with one writer and one reader.
pub const BodyPipe = struct {
    /// Allocator used for buffer storage and object lifetime.
    allocator: std.mem.Allocator,
    /// Ring buffer storage for queued bytes.
    buffer: []u8,
    /// Mutex guarding buffer state.
    mutex: std.Thread.Mutex,
    /// Condition variable used to signal readers and writers.
    cond: std.Thread.Condition,
    /// Index of the next byte to read.
    head: usize,
    /// Number of bytes currently buffered.
    len: usize,
    /// Indicates the writer has closed the pipe.
    writer_closed: bool,
    /// Indicates the reader has closed the pipe.
    reader_closed: bool,
    /// Stored error to surface to the reader after draining.
    pending_error: ?anyerror,
    /// Reference count for runtime-slot, reader, and writer lifetimes.
    ref_count: std.atomic.Value(u8),

    /// Allocates a new pipe with the requested capacity in bytes.
    pub fn init(allocator: std.mem.Allocator, capacity: usize) InitError!*BodyPipe {
        if (capacity == 0) {
            return error.InvalidCapacity;
        }

        const pipe = try allocator.create(BodyPipe);
        errdefer allocator.destroy(pipe);

        const buffer = try allocator.alloc(u8, capacity);
        pipe.* = .{
            .allocator = allocator,
            .buffer = buffer,
            .mutex = .{},
            .cond = .{},
            .head = 0,
            .len = 0,
            .writer_closed = false,
            .reader_closed = false,
            .pending_error = null,
            .ref_count = std.atomic.Value(u8).init(3),
        };

        return pipe;
    }

    /// Writes all bytes into the pipe, blocking when the buffer is full.
    pub fn writeAll(self: *BodyPipe, bytes: []const u8) WriteError!void {
        if (bytes.len == 0) {
            return;
        }

        var offset: usize = 0;
        while (offset < bytes.len) {
            self.mutex.lock();
            while (self.len == self.buffer.len) {
                if (self.reader_closed) {
                    self.mutex.unlock();
                    return error.ReaderClosed;
                }
                self.cond.wait(&self.mutex);
            }

            if (self.reader_closed) {
                self.mutex.unlock();
                return error.ReaderClosed;
            }

            const available = self.buffer.len - self.len;
            const to_write = @min(available, bytes.len - offset);
            const tail = (self.head + self.len) % self.buffer.len;
            const first = @min(to_write, self.buffer.len - tail);

            std.mem.copyForwards(u8, self.buffer[tail .. tail + first], bytes[offset .. offset + first]);
            if (first < to_write) {
                const second = to_write - first;
                std.mem.copyForwards(u8, self.buffer[0..second], bytes[offset + first .. offset + to_write]);
            }

            self.len += to_write;
            offset += to_write;
            self.cond.signal();
            self.mutex.unlock();
        }
    }

    /// Writes as many bytes as fit without blocking and returns the count written.
    pub fn writeSome(self: *BodyPipe, bytes: []const u8) WriteError!usize {
        if (bytes.len == 0) {
            return 0;
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.reader_closed) {
            return error.ReaderClosed;
        }

        const available = self.buffer.len - self.len;
        if (available == 0) {
            return 0;
        }

        const to_write = @min(available, bytes.len);
        const tail = (self.head + self.len) % self.buffer.len;
        const first = @min(to_write, self.buffer.len - tail);

        std.mem.copyForwards(u8, self.buffer[tail .. tail + first], bytes[0..first]);
        if (first < to_write) {
            const second = to_write - first;
            std.mem.copyForwards(u8, self.buffer[0..second], bytes[first .. first + second]);
        }

        self.len += to_write;
        self.cond.signal();
        return to_write;
    }

    /// Returns the number of bytes that can be queued immediately without blocking.
    pub fn availableCapacity(self: *BodyPipe) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.buffer.len - self.len;
    }

    /// Returns true when the reader side has already been closed.
    pub fn isReaderClosed(self: *BodyPipe) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.reader_closed;
    }

    /// Closes the writer side, optionally providing an error for the reader.
    pub fn closeWriter(self: *BodyPipe, err: ?anyerror) void {
        var release = false;
        self.mutex.lock();
        if (!self.writer_closed) {
            self.writer_closed = true;
            if (err != null and self.pending_error == null) {
                self.pending_error = err;
            }
            release = true;
            self.cond.broadcast();
        }
        self.mutex.unlock();

        if (release) {
            self.releaseRef();
        }
    }

    /// Reads bytes from the pipe into `dest`.
    pub fn read(ctx: ?*anyopaque, dest: []u8) anyerror!usize {
        const self: *BodyPipe = @ptrCast(@alignCast(ctx.?));
        return self.readInto(dest);
    }

    /// Closes the reader side and releases its reference.
    pub fn closeReader(ctx: ?*anyopaque) void {
        const self: *BodyPipe = @ptrCast(@alignCast(ctx.?));
        self.closeReaderInternal();
    }

    /// Closes the reader side using a direct pointer.
    pub fn closeReaderHandle(self: *BodyPipe) void {
        self.closeReaderInternal();
    }

    /// Releases the runtime slot reference retained by stream bookkeeping.
    pub fn closeRuntimeHandle(self: *BodyPipe) void {
        self.releaseRef();
    }

    /// Reads buffered data, waiting for writer activity as needed.
    fn readInto(self: *BodyPipe, dest: []u8) anyerror!usize {
        if (dest.len == 0) {
            return 0;
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        while (self.len == 0) {
            if (self.pending_error) |err| {
                return err;
            }
            if (self.writer_closed) {
                return 0;
            }
            self.cond.wait(&self.mutex);
        }

        const to_read = @min(dest.len, self.len);
        const first = @min(to_read, self.buffer.len - self.head);
        std.mem.copyForwards(u8, dest[0..first], self.buffer[self.head .. self.head + first]);
        if (first < to_read) {
            const second = to_read - first;
            std.mem.copyForwards(u8, dest[first .. first + second], self.buffer[0..second]);
        }

        self.head = (self.head + to_read) % self.buffer.len;
        self.len -= to_read;
        self.cond.signal();

        return to_read;
    }

    /// Marks the reader side as closed and releases its reference.
    fn closeReaderInternal(self: *BodyPipe) void {
        var release = false;
        self.mutex.lock();
        if (!self.reader_closed) {
            self.reader_closed = true;
            release = true;
            self.cond.broadcast();
        }
        self.mutex.unlock();

        if (release) {
            self.releaseRef();
        }
    }

    /// Releases a reference and frees resources when both sides close.
    fn releaseRef(self: *BodyPipe) void {
        if (self.ref_count.fetchSub(1, .acq_rel) == 1) {
            self.allocator.free(self.buffer);
            self.allocator.destroy(self);
        }
    }
};
