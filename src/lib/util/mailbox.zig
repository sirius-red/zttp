//! Thread-safe mailbox for passing values between threads.

const std = @import("std");

/// Error set returned by `send`.
pub const MailboxSendError = error{Closed} || std.mem.Allocator.Error;
/// Error set returned by `recv`.
pub const MailboxRecvError = error{Closed};
/// Error set returned by `timedRecv`.
pub const MailboxTimedRecvError = error{ Closed, Timeout };

/// Provides a thread-safe FIFO mailbox for values of type `T`.
pub fn Mailbox(comptime T: type) type {
    return struct {
        const Self = @This();

        /// Error set returned by `send`.
        pub const SendError = MailboxSendError;
        /// Error set returned by `recv`.
        pub const RecvError = MailboxRecvError;
        /// Error set returned by `timedRecv`.
        pub const TimedRecvError = MailboxTimedRecvError;

        /// Allocator used for queue storage.
        allocator: std.mem.Allocator,
        /// Mutex guarding mailbox state.
        mutex: std.Thread.Mutex,
        /// Condition variable for waiting receivers.
        cond: std.Thread.Condition,
        /// FIFO storage for enqueued items.
        queue: std.ArrayListUnmanaged(T),
        /// Index of the next item to dequeue.
        head: usize,
        /// Indicates the mailbox has been closed.
        closed: bool,

        /// Initializes an empty mailbox.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .mutex = .{},
                .cond = .{},
                .queue = .{},
                .head = 0,
                .closed = false,
            };
        }

        /// Releases mailbox storage.
        pub fn deinit(self: *Self) void {
            self.close();
            self.queue.deinit(self.allocator);
        }

        /// Adds an item to the mailbox.
        pub fn send(self: *Self, item: T) MailboxSendError!void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.closed) {
                return error.Closed;
            }

            try self.queue.append(self.allocator, item);
            self.cond.signal();
        }

        /// Receives the next item, blocking until one is available or the mailbox is closed.
        pub fn recv(self: *Self) MailboxRecvError!T {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (self.lenLocked() == 0) {
                if (self.closed) {
                    return error.Closed;
                }
                self.cond.wait(&self.mutex);
            }

            return self.popLocked();
        }

        /// Receives the next item or returns `error.Timeout` after `timeout_ns` nanoseconds.
        pub fn timedRecv(self: *Self, timeout_ns: u64) MailboxTimedRecvError!T {
            const deadline = std.time.nanoTimestamp() + @as(i128, @intCast(timeout_ns));

            self.mutex.lock();
            defer self.mutex.unlock();

            while (self.lenLocked() == 0) {
                if (self.closed) {
                    return error.Closed;
                }

                const now = std.time.nanoTimestamp();
                if (now >= deadline) {
                    return error.Timeout;
                }

                const remaining = @as(u64, @intCast(deadline - now));
                self.cond.timedWait(&self.mutex, remaining) catch |err| switch (err) {
                    error.Timeout => return error.Timeout,
                };
            }

            return self.popLocked();
        }

        /// Closes the mailbox and wakes all waiting receivers.
        pub fn close(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.closed) {
                return;
            }

            self.closed = true;
            self.cond.broadcast();
        }

        /// Returns the number of queued items.
        pub fn len(self: *Self) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.lenLocked();
        }

        /// Removes the next item from the queue.
        fn popLocked(self: *Self) T {
            const item = self.queue.items[self.head];
            self.head += 1;

            if (self.head == self.queue.items.len) {
                self.queue.items.len = 0;
                self.head = 0;
                return item;
            }

            if (self.head >= 64 and self.head * 2 >= self.queue.items.len) {
                const remaining = self.queue.items.len - self.head;
                std.mem.copyForwards(T, self.queue.items[0..remaining], self.queue.items[self.head..]);
                self.queue.items.len = remaining;
                self.head = 0;
            }

            return item;
        }

        /// Returns the number of queued items. Caller must hold the mutex.
        fn lenLocked(self: *Self) usize {
            return self.queue.items.len - self.head;
        }
    };
}

test "mailbox concurrent send and receive" {
    const MailboxU32 = Mailbox(u32);
    var mailbox = MailboxU32.init(std.testing.allocator);
    defer mailbox.deinit();

    const producer_count = 4;
    const items_per = 500;

    var threads: [producer_count]std.Thread = undefined;
    var index: usize = 0;
    while (index < producer_count) : (index += 1) {
        const start = @as(u32, @intCast(index * items_per));
        threads[index] = try std.Thread.spawn(.{}, struct {
            /// Sends a fixed number of items to the mailbox.
            fn run(ctx: *MailboxU32, first: u32, count: usize) void {
                var sent: usize = 0;
                while (sent < count) : (sent += 1) {
                    const value = first + @as(u32, @intCast(sent));
                    ctx.send(value) catch unreachable;
                }
            }
        }.run, .{ &mailbox, start, items_per });
    }

    var received: usize = 0;
    while (received < producer_count * items_per) : (received += 1) {
        _ = try mailbox.recv();
    }

    for (threads) |thread| {
        thread.join();
    }
}
