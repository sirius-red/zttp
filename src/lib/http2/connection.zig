//! HTTP/2 connection and stream state scaffolding.

const std = @import("std");
const frame = @import("frame.zig");

/// Stream state for one HTTP/2 stream.
pub const StreamState = enum {
    idle,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

/// Connection state for one HTTP/2 session.
pub const ConnectionState = enum {
    idle,
    preface,
    active,
    draining,
    closed,
};

/// Local and remote HTTP/2 settings snapshots.
pub const Settings = struct {
    /// Maximum concurrent streams permitted by the peer.
    max_concurrent_streams: u32 = std.math.maxInt(u31),
    /// Initial flow-control window.
    initial_window_size: u32 = 65535,
    /// Maximum frame size.
    max_frame_size: u32 = 16384,
};

/// One tracked HTTP/2 stream.
pub const Stream = struct {
    /// Stream identifier.
    id: u31,
    /// Current state.
    state: StreamState,
    /// Send-side flow-control window.
    send_window: i64,
    /// Receive-side flow-control window.
    recv_window: i64,
};

/// Minimal HTTP/2 connection state holder.
pub const Connection = struct {
    /// Allocator used for stream bookkeeping.
    allocator: std.mem.Allocator,
    /// Session state.
    state: ConnectionState,
    /// Locally advertised settings.
    settings_local: Settings,
    /// Peer settings.
    settings_remote: Settings,
    /// Next locally initiated stream identifier.
    next_stream_id: u31,
    /// Connection-level send window.
    connection_window: i64,
    /// Active streams.
    streams: std.ArrayListUnmanaged(Stream),
    /// Last `GOAWAY` stream identifier, if any.
    goaway_last_stream_id: ?u31,

    /// Creates an empty HTTP/2 connection state machine.
    pub fn init(allocator: std.mem.Allocator) Connection {
        return .{
            .allocator = allocator,
            .state = .idle,
            .settings_local = .{},
            .settings_remote = .{},
            .next_stream_id = 1,
            .connection_window = 65535,
            .streams = .{},
            .goaway_last_stream_id = null,
        };
    }

    /// Releases owned stream bookkeeping.
    pub fn deinit(self: *Connection) void {
        self.streams.deinit(self.allocator);
        self.* = undefined;
    }

    /// Marks the client preface as sent.
    pub fn sendClientPreface(self: *Connection) void {
        if (self.state == .idle) {
            self.state = .preface;
        }
    }

    /// Opens the next local stream and returns its identifier.
    pub fn openLocalStream(self: *Connection) !u31 {
        const stream_id = self.next_stream_id;
        self.next_stream_id += 2;
        try self.streams.append(self.allocator, .{
            .id = stream_id,
            .state = .open,
            .send_window = self.settings_remote.initial_window_size,
            .recv_window = self.settings_local.initial_window_size,
        });
        self.state = .active;
        return stream_id;
    }

    /// Applies a remote SETTINGS payload to the connection state.
    pub fn applyRemoteSettings(self: *Connection, settings_payload: []const frame.Setting) void {
        for (settings_payload) |setting| {
            switch (setting.id) {
                .max_concurrent_streams => self.settings_remote.max_concurrent_streams = setting.value,
                .initial_window_size => self.settings_remote.initial_window_size = setting.value,
                .max_frame_size => self.settings_remote.max_frame_size = setting.value,
                else => {},
            }
        }
    }

    /// Updates a stream window by the provided delta.
    pub fn updateStreamWindow(self: *Connection, stream_id: u31, delta: i32) bool {
        for (self.streams.items) |*stream| {
            if (stream.id == stream_id) {
                stream.recv_window += delta;
                return true;
            }
        }
        return false;
    }

    /// Marks a stream as reset or closed by the peer.
    pub fn resetStream(self: *Connection, stream_id: u31) bool {
        for (self.streams.items) |*stream| {
            if (stream.id == stream_id) {
                stream.state = .closed;
                return true;
            }
        }
        return false;
    }

    /// Records a `GOAWAY` frame and moves the connection into draining mode.
    pub fn beginGoAway(self: *Connection, last_stream_id: u31) void {
        self.goaway_last_stream_id = last_stream_id;
        self.state = .draining;
    }
};

test "http2 connection opens client streams on odd identifiers" {
    var conn = Connection.init(std.testing.allocator);
    defer conn.deinit();

    conn.sendClientPreface();
    try std.testing.expectEqual(@as(u31, 1), try conn.openLocalStream());
    try std.testing.expectEqual(@as(u31, 3), try conn.openLocalStream());
}

test "http2 connection tracks settings and goaway state" {
    var conn = Connection.init(std.testing.allocator);
    defer conn.deinit();

    conn.applyRemoteSettings(&.{
        .{ .id = .max_frame_size, .value = 32768 },
        .{ .id = .initial_window_size, .value = 70000 },
    });
    conn.beginGoAway(7);

    try std.testing.expectEqual(@as(u32, 32768), conn.settings_remote.max_frame_size);
    try std.testing.expectEqual(@as(u32, 70000), conn.settings_remote.initial_window_size);
    try std.testing.expectEqual(ConnectionState.draining, conn.state);
}
