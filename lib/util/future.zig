//! Request future and completion primitives.

const std = @import("std");

/// Creates a request future type for payload `T` and error set `E`.
pub fn RequestFuture(comptime T: type, comptime E: type) type {
    return struct {
        const Self = @This();

        /// Error set returned by `wait` and `timedWait`.
        pub const WaitError = E || error{Canceled, Timeout};

        /// Completion handle that can resolve the future.
        pub const Completion = struct {
            /// Future being completed.
            future: *Self,

            /// Completes the future with the provided result.
            pub fn finish(self: *Completion, result: E!T) bool {
                return self.future.complete(result);
            }

            /// Cancels the future.
            pub fn cancel(self: *Completion) bool {
                return self.future.cancel();
            }
        };

        /// Internal state of the future.
        const State = union(enum) {
            /// Waiting for completion.
            pending,
            /// Completed successfully with a value.
            ok: T,
            /// Completed with an error.
            err: E,
            /// Canceled by the caller.
            canceled,
        };

        /// Mutex guarding state transitions.
        mutex: std.Thread.Mutex,
        /// Condition variable for waiters.
        cond: std.Thread.Condition,
        /// Current future state.
        state: State,

        /// Initializes a new pending future.
        pub fn init() Self {
            return .{
                .mutex = .{},
                .cond = .{},
                .state = .pending,
            };
        }

        /// Returns a completion handle tied to this future.
        pub fn completion(self: *Self) Completion {
            return .{ .future = self };
        }

        /// Marks the future as completed with the provided result.
        pub fn complete(self: *Self, result: E!T) bool {
            self.mutex.lock();
            defer self.mutex.unlock();

            switch (self.state) {
                .pending => {},
                else => return false,
            }

            if (result) |value| {
                self.state = .{ .ok = value };
            } else |err| {
                self.state = .{ .err = err };
            }

            self.cond.broadcast();
            return true;
        }

        /// Marks the future as canceled.
        pub fn cancel(self: *Self) bool {
            self.mutex.lock();
            defer self.mutex.unlock();

            switch (self.state) {
                .pending => {},
                else => return false,
            }

            self.state = .canceled;
            self.cond.broadcast();
            return true;
        }

        /// Blocks until the future completes.
        pub fn wait(self: *Self) WaitError!T {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (true) {
                switch (self.state) {
                    .pending => self.cond.wait(&self.mutex),
                    .ok => |value| return value,
                    .err => |err| return err,
                    .canceled => return error.Canceled,
                }
            }
        }

        /// Blocks until completion or the timeout elapses.
        pub fn timedWait(self: *Self, timeout_ns: u64) WaitError!T {
            const deadline = std.time.nanoTimestamp() + @as(i128, @intCast(timeout_ns));

            self.mutex.lock();
            defer self.mutex.unlock();

            while (true) {
                switch (self.state) {
                    .pending => {
                        const now = std.time.nanoTimestamp();
                        if (now >= deadline) {
                            return error.Timeout;
                        }
                        const remaining = @as(u64, @intCast(deadline - now));
                        self.cond.timedWait(&self.mutex, remaining) catch |err| switch (err) {
                            error.Timeout => return error.Timeout,
                        };
                    },
                    .ok => |value| return value,
                    .err => |err| return err,
                    .canceled => return error.Canceled,
                }
            }
        }
    };
}

test "request future completes" {
    const Future = RequestFuture(u32, error{Failure});
    var future = Future.init();

    var thread = try std.Thread.spawn(.{}, struct {
        /// Completes the future with a value.
        fn run(ctx: *Future) void {
            _ = ctx.complete(42);
        }
    }.run, .{&future});

    const value = try future.wait();
    try std.testing.expectEqual(@as(u32, 42), value);
    thread.join();
}

test "request future cancellation" {
    const Future = RequestFuture(u8, error{Failure});
    var future = Future.init();
    var completion = future.completion();

    _ = completion.cancel();
    try std.testing.expectError(error.Canceled, future.wait());
}

test "request future timed wait times out" {
    const Future = RequestFuture(u8, error{Failure});
    var future = Future.init();

    try std.testing.expectError(
        error.Timeout,
        future.timedWait(5 * std.time.ns_per_ms),
    );
}
