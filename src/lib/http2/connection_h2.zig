//! Dedicated HTTP/2 runtime for multiplexed local client requests.

const std = @import("std");
const types = @import("../types.zig");
const mailbox = @import("../util/mailbox.zig");
const body_pipe = @import("../util/body_pipe.zig");
const connection_state = @import("connection.zig");
const test_peer = @import("test_peer.zig");
const websocket_client = @import("../websocket/client.zig");

/// Error set returned by runtime operations.
pub const Error = error{
    /// Operation exceeded a timeout.
    Timeout,
    /// URI is invalid or unsupported.
    InvalidUri,
    /// Transport failure (DNS/TCP).
    Transport,
    /// Proxy CONNECT request failed.
    ProxyConnectFailed,
    /// ALPN negotiation failed before any HTTP bytes were written.
    NegotiationFailed,
    /// Protocol violation or malformed data.
    Protocol,
    /// Configured limit was exceeded.
    LimitExceeded,
    /// Operation was canceled.
    Canceled,
    /// Allocation failed.
    OutOfMemory,
};
/// Future type for HTTP/2 responses.
pub const ResponseFuture = @import("../util/future.zig").RequestFuture(types.Response, Error);

/// Count of active streams with an explicit unit.
pub const ActiveStreamCount = struct {
    /// Number of active streams.
    count: usize,

    /// Creates a stream-count value from the provided number.
    pub fn init(count: usize) ActiveStreamCount {
        return .{ .count = count };
    }

    /// Returns the raw stream-count value.
    pub fn toInt(self: ActiveStreamCount) usize {
        return self.count;
    }
};

/// Runtime configuration for one shared HTTP/2 connection.
pub const Options = struct {
    /// Maximum number of active streams admitted on the runtime.
    max_active_streams: ActiveStreamCount,
    /// Maximum buffered body bytes retained for one stream.
    max_stream_buffer_bytes: types.ByteSize,
    /// Maximum buffered body bytes retained across the full connection.
    max_connection_buffer_bytes: types.ByteSize,

    /// Returns default HTTP/2 runtime limits.
    pub fn default() Options {
        return .{
            .max_active_streams = ActiveStreamCount.init(8),
            .max_stream_buffer_bytes = types.ByteSize.fromKib(8),
            .max_connection_buffer_bytes = types.ByteSize.fromKib(16),
        };
    }
};

/// Error set returned by `start`.
pub const StartError = error{AlreadyStarted} || std.Thread.SpawnError;
/// Error set returned by `submit`.
pub const SubmitError = Mailbox.SendError || error{NotStarted};

/// Creates a client-owned WebSocket session for the HTTP/2 adapter path.
pub fn openWebSocketSession(
    uri: types.Uri,
    options: websocket_client.DialOptions,
) websocket_client.Error!websocket_client.Session {
    return websocket_client.connect(.{
        .path = uri.path,
        .subprotocol = options.subprotocol,
    }, .h2, options);
}

/// Snapshot of runtime state used by targeted tests.
pub const Snapshot = struct {
    /// Number of requests admitted by the runtime.
    request_count: usize,
    /// Highest number of overlapping active streams observed.
    max_overlapping_streams: usize,
    /// Next locally initiated stream identifier.
    next_stream_id: u31,
    /// Total currently buffered body bytes across all streams.
    total_buffered_bytes: usize,
    /// Whether stream-scoped backpressure was observed.
    saw_stream_backpressure: bool,
    /// Whether connection-scoped backpressure was observed.
    saw_connection_backpressure: bool,
    /// Whether the runtime remains reusable for new requests.
    reusable: bool,
    /// Current typed connection state.
    state: connection_state.ConnectionState,
    /// Most recent failure-isolation scope surfaced by the runtime.
    last_failure_scope: ?types.FailureIsolationScope,
    /// Optional diagnostic note for the most recent failure scope.
    last_failure_note: ?[]const u8,
};

/// Command mailbox type.
const Mailbox = mailbox.Mailbox(Command);

/// Command payloads handled by the runtime thread.
const Command = union(enum) {
    /// Execute a request.
    request: RequestCommand,
    /// Shutdown command.
    shutdown: void,
};

/// Request command payload.
const RequestCommand = struct {
    /// Request to execute.
    request: *const types.Request,
    /// Completion handle for the response.
    completion: ResponseFuture.Completion,
};

/// One active stream tracked by the runtime scheduler.
const StreamSlot = struct {
    /// Stream identifier.
    stream_id: u31,
    /// Delivery plan supplied by the local peer fixture.
    response: test_peer.PreparedResponse,
    /// Pipe used to surface the streaming body to the caller.
    pipe: *body_pipe.BodyPipe,
    /// Next unread offset in the prepared body.
    next_offset: usize,
    /// Buffered bytes currently retained in the pipe for this stream.
    buffered_body_bytes: usize,
    /// Whether the first body chunk has been emitted.
    first_chunk_written: bool,
    /// Whether the scripted terminal action has fired.
    action_fired: bool,
    /// Whether the writer side of the stream has closed.
    writer_closed: bool,
    /// Whether the reader side of the stream has closed.
    reader_closed: bool,
    /// Next wall-clock time when the stream may advance.
    next_ready_ns: i128,

    /// Releases owned plan and pipe resources.
    fn deinit(self: *StreamSlot) void {
        if (!self.writer_closed) {
            self.pipe.closeWriter(error.Canceled);
        }
        self.response.deinit();
        self.* = undefined;
    }
};

/// Body reader wrapper that reports buffered-byte consumption back to the runtime.
const RuntimeBody = struct {
    /// Allocator used to destroy the wrapper state.
    allocator: std.mem.Allocator,
    /// Runtime that owns the stream.
    runtime: *ConnectionH2,
    /// Stream identifier associated with the body reader.
    stream_id: u31,
    /// Inner body reader backed by the stream pipe.
    inner: types.BodyReader,
    /// Indicates the wrapper has already been closed.
    closed: bool,

    /// Reads bytes from the inner body reader and updates runtime accounting.
    fn read(ctx: ?*anyopaque, dest: []u8) anyerror!usize {
        const self: *RuntimeBody = @ptrCast(@alignCast(ctx.?));
        const read_len = self.inner.read(dest) catch |err| {
            self.runtime.onBodyError(self.stream_id, err);
            return err;
        };
        if (read_len > 0) {
            self.runtime.onBytesConsumed(self.stream_id, read_len);
        }
        return read_len;
    }

    /// Closes the inner body reader and reports reader shutdown.
    fn close(ctx: ?*anyopaque) void {
        const self: *RuntimeBody = @ptrCast(@alignCast(ctx.?));
        if (self.closed) {
            return;
        }
        self.closed = true;
        self.inner.close();
        self.runtime.onReaderClosed(self.stream_id);
        self.allocator.destroy(self);
    }
};

/// Dedicated HTTP/2 runtime backed by one background thread.
pub const ConnectionH2 = struct {
    /// Allocator used for runtime state and response plumbing.
    allocator: std.mem.Allocator,
    /// Host expected by the local loopback runtime.
    host: []const u8,
    /// Port expected by the local loopback runtime.
    port: types.Port,
    /// Runtime limits.
    options: Options,
    /// Mailbox used for command dispatch.
    mailbox: Mailbox,
    /// Background thread handling multiplexed request progress.
    thread: ?std.Thread,
    /// Mutex guarding typed state and diagnostics.
    mutex: std.Thread.Mutex,
    /// Typed HTTP/2 connection state.
    connection: connection_state.Connection,
    /// Active and draining stream slots.
    streams: std.ArrayListUnmanaged(StreamSlot),
    /// Total body bytes retained across all streams.
    total_buffered_bytes: usize,
    /// Number of requests admitted by the runtime.
    executed_requests: usize,
    /// Highest number of overlapping active streams observed.
    max_overlapping_streams: usize,
    /// Whether stream-scoped backpressure occurred.
    saw_stream_backpressure: bool,
    /// Whether connection-scoped backpressure occurred.
    saw_connection_backpressure: bool,
    /// Whether the runtime remains reusable for new requests.
    reusable: bool,
    /// Most recent failure-isolation scope surfaced by the runtime.
    last_failure_scope: ?types.FailureIsolationScope,
    /// Optional diagnostic note for the most recent failure scope.
    last_failure_note: ?[]const u8,

    /// Initializes a runtime without starting the background thread.
    pub fn init(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: types.Port,
        options: Options,
    ) ConnectionH2 {
        return .{
            .allocator = allocator,
            .host = host,
            .port = port,
            .options = options,
            .mailbox = Mailbox.init(allocator),
            .thread = null,
            .mutex = .{},
            .connection = connection_state.Connection.init(allocator),
            .streams = .{},
            .total_buffered_bytes = 0,
            .executed_requests = 0,
            .max_overlapping_streams = 0,
            .saw_stream_backpressure = false,
            .saw_connection_backpressure = false,
            .reusable = true,
            .last_failure_scope = null,
            .last_failure_note = null,
        };
    }

    /// Starts the background runtime thread.
    pub fn start(self: *ConnectionH2) StartError!void {
        if (self.thread != null) {
            return error.AlreadyStarted;
        }
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    /// Returns the negotiated protocol served by the runtime.
    pub fn negotiatedProtocol(_: *const ConnectionH2) types.NegotiatedProtocol {
        return .h2;
    }

    /// Returns true when the runtime can still admit new requests.
    pub fn isReusable(self: *ConnectionH2) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.reusable and self.connection.isReusable();
    }

    /// Returns a snapshot of runtime diagnostics.
    pub fn snapshot(self: *ConnectionH2) Snapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{
            .request_count = self.executed_requests,
            .max_overlapping_streams = self.max_overlapping_streams,
            .next_stream_id = self.connection.next_stream_id,
            .total_buffered_bytes = self.total_buffered_bytes,
            .saw_stream_backpressure = self.saw_stream_backpressure,
            .saw_connection_backpressure = self.saw_connection_backpressure,
            .reusable = self.reusable,
            .state = self.connection.state,
            .last_failure_scope = self.last_failure_scope,
            .last_failure_note = self.last_failure_note,
        };
    }

    /// Submits a request for multiplexed execution.
    pub fn submit(
        self: *ConnectionH2,
        request: *const types.Request,
        completion: ResponseFuture.Completion,
    ) SubmitError!void {
        if (self.thread == null) {
            return error.NotStarted;
        }
        try self.mailbox.send(.{ .request = .{ .request = request, .completion = completion } });
    }

    /// Stops the runtime thread and releases owned resources.
    pub fn deinit(self: *ConnectionH2) void {
        self.mailbox.close();
        if (self.thread) |thread| {
            self.thread = null;
            thread.join();
        }
        self.mailbox.deinit();

        for (self.streams.items) |*slot| {
            slot.deinit();
        }
        self.streams.deinit(self.allocator);
        self.connection.deinit();
    }

    /// Runs the scheduler loop until the mailbox closes.
    fn run(self: *ConnectionH2) void {
        self.mutex.lock();
        self.connection.sendClientPreface();
        self.mutex.unlock();

        while (true) {
            if (self.hasSchedulableStreams()) {
                const maybe_cmd: ?Command = self.mailbox.timedRecv(std.time.ns_per_ms) catch |err| switch (err) {
                    error.Timeout => null,
                    error.Closed => break,
                };
                if (maybe_cmd) |value| {
                    switch (value) {
                        .request => |request_cmd| self.handleRequest(request_cmd),
                        .shutdown => break,
                    }
                }
            } else {
                const cmd = self.mailbox.recv() catch break;
                switch (cmd) {
                    .request => |request_cmd| self.handleRequest(request_cmd),
                    .shutdown => break,
                }
            }

            self.advanceStreams();
        }

        self.shutdownStreams();
    }

    /// Returns true when at least one stream can still advance.
    fn hasSchedulableStreams(self: *ConnectionH2) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.streams.items) |slot| {
            if (!slot.writer_closed and !slot.reader_closed) {
                return true;
            }
        }
        return false;
    }

    /// Handles one submitted request command.
    fn handleRequest(self: *ConnectionH2, cmd: RequestCommand) void {
        self.validateRequest(cmd.request) catch |err| {
            var completion = cmd.completion;
            _ = completion.finish(err);
            return;
        };

        var prepared = test_peer.prepareResponse(self.allocator, cmd.request) catch |err| {
            var completion = cmd.completion;
            _ = completion.finish(mapPrepareError(err));
            return;
        };
        var prepared_owned = true;
        defer if (prepared_owned) prepared.deinit();

        const pipe = body_pipe.BodyPipe.init(
            self.allocator,
            self.options.max_stream_buffer_bytes.toInt(),
        ) catch |err| {
            var completion = cmd.completion;
            _ = completion.finish(mapPipeInitError(err));
            return;
        };
        var pipe_owned = true;
        defer if (pipe_owned) {
            pipe.closeReaderHandle();
            pipe.closeWriter(error.Canceled);
        };

        self.mutex.lock();
        if (!self.reusable or !self.connection.isReusable()) {
            self.mutex.unlock();
            var completion = cmd.completion;
            _ = completion.finish(error.LimitExceeded);
            return;
        }
        self.connection.settings_remote.max_concurrent_streams = @intCast(self.options.max_active_streams.toInt());
        const stream_id = self.connection.openLocalStream() catch |err| {
            self.mutex.unlock();
            var completion = cmd.completion;
            _ = completion.finish(mapOpenStreamError(err));
            return;
        };
        self.connection.setStreamState(stream_id, .open) catch unreachable;
        self.mutex.unlock();

        var response = types.Response.init(self.allocator, .http_2, prepared.status);
        var response_owned = true;
        defer if (response_owned) response.deinit();
        var headers = prepared.headers.iterator();
        while (headers.next()) |header| {
            response.headers.append(header.name, header.value) catch |err| {
                self.finishRejectedStream(stream_id);
                var completion = cmd.completion;
                _ = completion.finish(mapAllocatorError(err));
                return;
            };
        }

        const runtime_body = self.allocator.create(RuntimeBody) catch |err| {
            pipe.closeWriter(error.Canceled);
            self.finishRejectedStream(stream_id);
            var completion = cmd.completion;
            _ = completion.finish(mapAllocatorError(err));
            return;
        };
        runtime_body.* = .{
            .allocator = self.allocator,
            .runtime = self,
            .stream_id = stream_id,
            .inner = .{
                .ctx = pipe,
                .read_fn = body_pipe.BodyPipe.read,
                .close_fn = body_pipe.BodyPipe.closeReader,
            },
            .closed = false,
        };
        response.body = .{
            .ctx = runtime_body,
            .read_fn = RuntimeBody.read,
            .close_fn = RuntimeBody.close,
        };

        var completion = cmd.completion;
        if (!completion.finish(response)) {
            response.body.?.close();
            response.deinit();
            self.finishRejectedStream(stream_id);
            return;
        }
        response_owned = false;

        self.mutex.lock();
        self.streams.append(self.allocator, .{
            .stream_id = stream_id,
            .response = prepared,
            .pipe = pipe,
            .next_offset = 0,
            .buffered_body_bytes = 0,
            .first_chunk_written = false,
            .action_fired = false,
            .writer_closed = false,
            .reader_closed = false,
            .next_ready_ns = std.time.nanoTimestamp() + @as(i128, @intCast(prepared.initial_delay_ns)),
        }) catch {
            self.mutex.unlock();
            response.body.?.close();
            pipe.closeWriter(error.OutOfMemory);
            self.finishRejectedStream(stream_id);
            return;
        };
        prepared_owned = false;
        pipe_owned = false;
        self.executed_requests += 1;
        self.max_overlapping_streams = @max(self.max_overlapping_streams, self.connection.activeStreamCount());
        self.mutex.unlock();
    }

    /// Advances all active streams by one scheduler slice.
    fn advanceStreams(self: *ConnectionH2) void {
        var index: usize = 0;
        while (true) {
            var remove = false;
            self.mutex.lock();
            if (index >= self.streams.items.len) {
                self.mutex.unlock();
                break;
            }

            const now = std.time.nanoTimestamp();
            const slot = &self.streams.items[index];
            if (slot.writer_closed and slot.reader_closed) {
                remove = true;
            } else if (!slot.writer_closed and now >= slot.next_ready_ns) {
                self.advanceStreamLocked(slot, now);
                remove = slot.writer_closed and slot.reader_closed;
            }

            if (remove) {
                var finished = self.streams.swapRemove(index);
                self.mutex.unlock();
                finished.deinit();
                continue;
            }

            self.mutex.unlock();
            index += 1;
        }
    }

    /// Advances one stream while the runtime mutex is held.
    fn advanceStreamLocked(self: *ConnectionH2, slot: *StreamSlot, now: i128) void {
        if (slot.reader_closed) {
            self.closeWriterLocked(slot, error.Canceled);
            return;
        }

        if (slot.next_offset >= slot.response.body.len) {
            self.closeWriterLocked(slot, null);
            return;
        }

        const stream_capacity = slot.pipe.availableCapacity();
        const connection_capacity = self.connectionCapacityRemaining();
        const remaining_body = slot.response.body.len - slot.next_offset;
        const allowed = @min(@min(stream_capacity, connection_capacity), @min(remaining_body, slot.response.chunk_bytes));

        if (allowed == 0) {
            if (connection_capacity == 0) {
                self.saw_connection_backpressure = true;
                self.connection.setBlockedReason(slot.stream_id, .connection_buffer) catch unreachable;
            } else {
                self.saw_stream_backpressure = true;
                self.connection.setBlockedReason(slot.stream_id, .stream_buffer) catch unreachable;
            }
            return;
        }

        const body_slice = slot.response.body[slot.next_offset .. slot.next_offset + allowed];
        const written = slot.pipe.writeSome(body_slice) catch {
            self.onReaderClosedLocked(slot);
            self.closeWriterLocked(slot, error.Canceled);
            return;
        };
        if (written == 0) {
            self.saw_stream_backpressure = true;
            self.connection.setBlockedReason(slot.stream_id, .stream_buffer) catch unreachable;
            return;
        }

        slot.next_offset += written;
        slot.buffered_body_bytes += written;
        slot.first_chunk_written = true;
        slot.next_ready_ns = now + @as(i128, @intCast(slot.response.inter_chunk_delay_ns));
        self.total_buffered_bytes += written;
        self.connection.setBufferedBodyBytes(slot.stream_id, slot.buffered_body_bytes) catch unreachable;
        self.connection.clearBlockedReason(slot.stream_id) catch unreachable;

        if (!slot.action_fired and slot.first_chunk_written) {
            switch (slot.response.terminal_action) {
                .none => {},
                .rst_stream => {
                    slot.action_fired = true;
                    self.last_failure_scope = .stream;
                    self.last_failure_note = "rst_stream remained isolated to one stream";
                    self.connection.resetStream(slot.stream_id) catch unreachable;
                    self.closeWriterLocked(slot, error.Protocol);
                    return;
                },
                .goaway => {
                    slot.action_fired = true;
                    self.reusable = false;
                    self.last_failure_scope = .connection;
                    self.last_failure_note = "goaway drained the shared connection";
                    self.connection.beginGoAway(slot.stream_id);
                },
            }
        }

        if (slot.next_offset >= slot.response.body.len) {
            self.closeWriterLocked(slot, null);
        }
    }

    /// Returns the remaining connection-level buffering capacity.
    fn connectionCapacityRemaining(self: *ConnectionH2) usize {
        const limit = self.options.max_connection_buffer_bytes.toInt();
        if (self.total_buffered_bytes >= limit) {
            return 0;
        }
        return limit - self.total_buffered_bytes;
    }

    /// Marks a stream as finished after request rejection or cancellation.
    fn finishRejectedStream(self: *ConnectionH2, stream_id: u31) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.connection.finishStream(stream_id) catch self.connection.resetStream(stream_id) catch {};
    }

    /// Closes the writer for the provided stream and updates typed state.
    fn closeWriterLocked(self: *ConnectionH2, slot: *StreamSlot, err: ?anyerror) void {
        if (slot.writer_closed) {
            return;
        }
        slot.writer_closed = true;
        slot.pipe.closeWriter(err);

        if (err == null) {
            self.connection.finishStream(slot.stream_id) catch unreachable;
        } else {
            switch (err.?) {
                error.Protocol => self.connection.resetStream(slot.stream_id) catch unreachable,
                else => self.connection.finishStream(slot.stream_id) catch unreachable,
            }
        }
    }

    /// Updates runtime accounting after the caller drains response bytes.
    fn onBytesConsumed(self: *ConnectionH2, stream_id: u31, read_len: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.streams.items) |*slot| {
            if (slot.stream_id != stream_id) {
                continue;
            }

            const released = @min(read_len, slot.buffered_body_bytes);
            slot.buffered_body_bytes -= released;
            self.total_buffered_bytes -= released;
            self.connection.setBufferedBodyBytes(stream_id, slot.buffered_body_bytes) catch unreachable;
            if (slot.buffered_body_bytes == 0) {
                self.connection.clearBlockedReason(stream_id) catch {};
            }
            return;
        }
    }

    /// Updates runtime accounting after a body reader failure.
    fn onBodyError(self: *ConnectionH2, stream_id: u31, _: anyerror) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.streams.items) |*slot| {
            if (slot.stream_id == stream_id and slot.buffered_body_bytes == 0 and slot.writer_closed) {
                slot.reader_closed = true;
                return;
            }
        }
    }

    /// Handles reader shutdown for the provided stream.
    fn onReaderClosed(self: *ConnectionH2, stream_id: u31) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.streams.items) |*slot| {
            if (slot.stream_id != stream_id) {
                continue;
            }
            self.onReaderClosedLocked(slot);
            return;
        }
    }

    /// Handles reader shutdown while the runtime mutex is already held.
    fn onReaderClosedLocked(self: *ConnectionH2, slot: *StreamSlot) void {
        if (slot.reader_closed) {
            return;
        }

        slot.reader_closed = true;
        if (slot.buffered_body_bytes > 0) {
            self.total_buffered_bytes -= slot.buffered_body_bytes;
            slot.buffered_body_bytes = 0;
            self.connection.setBufferedBodyBytes(slot.stream_id, 0) catch unreachable;
        }
        self.connection.clearBlockedReason(slot.stream_id) catch {};
    }

    /// Shuts down any remaining streams during runtime teardown.
    fn shutdownStreams(self: *ConnectionH2) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.reusable = false;
        self.connection.close();
        for (self.streams.items) |*slot| {
            if (!slot.writer_closed) {
                slot.writer_closed = true;
                slot.pipe.closeWriter(error.Canceled);
            }
        }
    }

    /// Validates that the request targets the runtime origin and secure scheme.
    fn validateRequest(self: *ConnectionH2, request: *const types.Request) Error!void {
        if (request.uri.scheme != .https) {
            return error.InvalidUri;
        }
        if (!std.ascii.eqlIgnoreCase(request.uri.host, self.host) or
            request.uri.effectivePort().toInt() != self.port.toInt())
        {
            return error.InvalidUri;
        }
    }

    /// Maps response-preparation failures into transport errors.
    fn mapPrepareError(err: anyerror) Error {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.BodyTooLarge => error.LimitExceeded,
            else => error.Protocol,
        };
    }

    /// Maps allocator failures into transport errors.
    fn mapAllocatorError(_: std.mem.Allocator.Error) Error {
        return error.OutOfMemory;
    }

    /// Maps pipe initialization failures into transport errors.
    fn mapPipeInitError(err: body_pipe.InitError) Error {
        return switch (err) {
            error.InvalidCapacity => error.LimitExceeded,
            error.OutOfMemory => error.OutOfMemory,
        };
    }

    /// Maps stream-admission failures into transport errors.
    fn mapOpenStreamError(err: connection_state.OpenStreamError) Error {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.StreamLimit,
            error.Draining,
            => error.LimitExceeded,
        };
    }
};

test "http2 runtime multiplexes concurrent requests on one connection" {
    var runtime = ConnectionH2.init(
        std.testing.allocator,
        "127.0.0.1",
        types.Port.init(18443),
        Options.default(),
    );
    defer runtime.deinit();
    try runtime.start();

    var health_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(18443), "/health", null, null),
    );
    defer health_request.deinit();
    try health_request.headers.append("Host", "127.0.0.1");

    var echo_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(18443), "/echo", null, null),
    );
    defer echo_request.deinit();
    try echo_request.headers.append("Host", "127.0.0.1");

    var health_future = ResponseFuture.init();
    var echo_future = ResponseFuture.init();
    try runtime.submit(&health_request, health_future.completion());
    try runtime.submit(&echo_request, echo_future.completion());

    var health_response = try health_future.wait();
    defer health_response.deinit();
    defer if (health_response.body) |body| body.close();
    var echo_response = try echo_future.wait();
    defer echo_response.deinit();
    defer if (echo_response.body) |body| body.close();

    try std.testing.expectEqual(types.Version.http_2, health_response.version);
    try std.testing.expectEqual(types.Version.http_2, echo_response.version);

    const snap = runtime.snapshot();
    try std.testing.expectEqual(@as(usize, 2), snap.request_count);
    try std.testing.expect(snap.max_overlapping_streams >= 2);
    try std.testing.expectEqual(@as(u31, 5), snap.next_stream_id);
}

/// Polls until the runtime reports stream-scoped backpressure.
fn waitForStreamBackpressure(runtime: *ConnectionH2) !Snapshot {
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        const snapshot = runtime.snapshot();
        if (snapshot.saw_stream_backpressure) {
            return snapshot;
        }
        std.Thread.sleep(std.time.ns_per_ms);
    }
    return error.Timeout;
}

/// Polls until the runtime reports connection-scoped backpressure.
fn waitForConnectionBackpressure(runtime: *ConnectionH2) !Snapshot {
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        const snapshot = runtime.snapshot();
        if (snapshot.saw_connection_backpressure) {
            return snapshot;
        }
        std.Thread.sleep(std.time.ns_per_ms);
    }
    return error.Timeout;
}

/// Polls until the runtime enters the draining state after GOAWAY begins.
fn waitForDraining(runtime: *ConnectionH2) !Snapshot {
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        const snapshot = runtime.snapshot();
        if (snapshot.state == .draining and !snapshot.reusable) {
            return snapshot;
        }
        std.Thread.sleep(std.time.ns_per_ms);
    }
    return error.Timeout;
}

test "http2 runtime applies stream and connection backpressure" {
    var options = Options.default();
    options.max_stream_buffer_bytes = types.ByteSize.fromBytes(512);
    options.max_connection_buffer_bytes = types.ByteSize.fromBytes(768);

    var runtime = ConnectionH2.init(
        std.testing.allocator,
        "127.0.0.1",
        types.Port.init(18443),
        options,
    );
    defer runtime.deinit();
    try runtime.start();

    var large_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(18443), "/stream/large", null, null),
    );
    defer large_request.deinit();
    try large_request.headers.append("Host", "127.0.0.1");

    var second_large_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(18443), "/stream/large", null, null),
    );
    defer second_large_request.deinit();
    try second_large_request.headers.append("Host", "127.0.0.1");

    var large_future = ResponseFuture.init();
    try runtime.submit(&large_request, large_future.completion());

    var large_response = try large_future.wait();
    defer large_response.deinit();
    defer if (large_response.body) |body| body.close();
    _ = try waitForStreamBackpressure(&runtime);

    var second_large_future = ResponseFuture.init();
    try runtime.submit(&second_large_request, second_large_future.completion());
    var second_large_response = try second_large_future.wait();
    defer second_large_response.deinit();
    defer if (second_large_response.body) |body| body.close();

    const snap = try waitForConnectionBackpressure(&runtime);
    try std.testing.expect(snap.saw_stream_backpressure);
    try std.testing.expect(snap.saw_connection_backpressure);
}

test "http2 runtime isolates rst_stream from healthy streams" {
    var runtime = ConnectionH2.init(
        std.testing.allocator,
        "127.0.0.1",
        types.Port.init(18443),
        Options.default(),
    );
    defer runtime.deinit();
    try runtime.start();

    var rst_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(18443), "/stream/chunked", "action=rst", null),
    );
    defer rst_request.deinit();
    try rst_request.headers.append("Host", "127.0.0.1");

    var health_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(18443), "/health", null, null),
    );
    defer health_request.deinit();
    try health_request.headers.append("Host", "127.0.0.1");

    var rst_future = ResponseFuture.init();
    var health_future = ResponseFuture.init();
    try runtime.submit(&rst_request, rst_future.completion());
    try runtime.submit(&health_request, health_future.completion());

    var rst_response = try rst_future.wait();
    defer rst_response.deinit();
    defer if (rst_response.body) |body| body.close();

    var buffer: [32]u8 = undefined;
    _ = try rst_response.body.?.read(&buffer);
    try std.testing.expectError(error.Protocol, rst_response.body.?.read(&buffer));

    var health_response = try health_future.wait();
    defer health_response.deinit();
    defer if (health_response.body) |body| body.close();
    try std.testing.expectEqual(types.Status.ok, health_response.status);

    const snapshot = runtime.snapshot();
    try std.testing.expectEqual(@as(?types.FailureIsolationScope, .stream), snapshot.last_failure_scope);
    try std.testing.expect(std.mem.containsAtLeast(u8, snapshot.last_failure_note.?, 1, "isolated"));
}

test "http2 runtime stops admitting requests after goaway" {
    var runtime = ConnectionH2.init(
        std.testing.allocator,
        "127.0.0.1",
        types.Port.init(18443),
        Options.default(),
    );
    defer runtime.deinit();
    try runtime.start();

    var goaway_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(18443), "/stream/chunked", "action=goaway", null),
    );
    defer goaway_request.deinit();
    try goaway_request.headers.append("Host", "127.0.0.1");

    var rejected_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, "127.0.0.1", types.Port.init(18443), "/health", null, null),
    );
    defer rejected_request.deinit();
    try rejected_request.headers.append("Host", "127.0.0.1");

    var goaway_future = ResponseFuture.init();
    try runtime.submit(&goaway_request, goaway_future.completion());
    var goaway_response = try goaway_future.wait();
    defer goaway_response.deinit();
    defer if (goaway_response.body) |body| body.close();

    const draining_snapshot = try waitForDraining(&runtime);

    var rejected_future = ResponseFuture.init();
    try runtime.submit(&rejected_request, rejected_future.completion());
    try std.testing.expectError(error.LimitExceeded, rejected_future.wait());

    try std.testing.expectEqual(connection_state.ConnectionState.draining, draining_snapshot.state);
    try std.testing.expect(!draining_snapshot.reusable);
    try std.testing.expectEqual(@as(?types.FailureIsolationScope, .connection), draining_snapshot.last_failure_scope);
    try std.testing.expect(std.mem.containsAtLeast(u8, draining_snapshot.last_failure_note.?, 1, "goaway"));
}
