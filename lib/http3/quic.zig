//! Minimal QUIC transport scaffolding for the experimental HTTP/3 path.

const std = @import("std");

/// Fixed-width connection identifier used by the in-repo QUIC scaffolding.
pub const ConnectionId = [8]u8;

/// Error set returned by QUIC transport helpers.
pub const Error = std.mem.Allocator.Error || error{
    /// Encoded bytes did not contain a full packet header.
    ShortPacket,
    /// Encoded bytes declared an invalid payload length.
    InvalidPacketLength,
    /// Encoded bytes targeted a different connection identifier.
    ConnectionIdMismatch,
};

/// Lifecycle state for one QUIC connection.
pub const ConnectionState = enum {
    /// Initial transport state before any handshake progress.
    initial,
    /// Handshake packets are in flight.
    handshake,
    /// Application data can flow.
    established,
    /// Connection close has started.
    draining,
    /// Connection is fully closed.
    closed,
};

/// Packet-number space used by a QUIC packet.
pub const PacketNumberSpace = enum(u8) {
    /// Initial packets.
    initial = 0,
    /// Handshake packets.
    handshake = 1,
    /// Application-data packets.
    application = 2,
};

/// High-level stream family supported by the local transport scaffolding.
pub const StreamKind = enum {
    /// Bidirectional application stream.
    bidirectional,
    /// Unidirectional control or encoder stream.
    unidirectional,
};

/// Close-state marker kept alongside the connection state.
pub const CloseState = enum {
    /// The connection is open.
    open,
    /// The connection is draining after a close signal.
    draining,
    /// The connection is closed.
    closed,
};

/// Per-space packet-number bookkeeping.
pub const PacketSpaceState = struct {
    /// Next packet number to emit in this space.
    next_packet_number: u64 = 0,
    /// Largest packet number received in this space.
    largest_received: ?u64 = null,
};

/// One packet tracked for basic recovery accounting.
pub const SentPacket = struct {
    /// Packet number in its space.
    number: u64,
    /// Packet-number space.
    space: PacketNumberSpace,
    /// Bytes counted as in flight.
    bytes_in_flight: usize,
    /// Whether the packet was ack-eliciting.
    ack_eliciting: bool,
};

/// Minimal recovery state used by the HTTP/3 scaffolding.
pub const RecoveryState = struct {
    /// Outstanding ack-eliciting packets.
    outstanding: std.ArrayListUnmanaged(SentPacket),
    /// Largest acknowledged packet number.
    largest_acked: ?u64,
    /// Number of packets marked lost.
    loss_count: usize,
    /// Number of packets acknowledged.
    ack_count: usize,

    /// Returns an empty recovery state.
    pub fn init() RecoveryState {
        return .{
            .outstanding = .{},
            .largest_acked = null,
            .loss_count = 0,
            .ack_count = 0,
        };
    }

    /// Releases packet tracking storage.
    pub fn deinit(self: *RecoveryState, allocator: std.mem.Allocator) void {
        self.outstanding.deinit(allocator);
        self.* = undefined;
    }

    /// Records a newly transmitted packet.
    pub fn onPacketSent(
        self: *RecoveryState,
        allocator: std.mem.Allocator,
        packet: SentPacket,
    ) std.mem.Allocator.Error!void {
        if (packet.ack_eliciting) {
            try self.outstanding.append(allocator, packet);
        }
    }

    /// Marks a tracked packet as acknowledged.
    pub fn onAck(self: *RecoveryState, number: u64, space: PacketNumberSpace) ?SentPacket {
        for (self.outstanding.items, 0..) |packet, index| {
            if (packet.number == number and packet.space == space) {
                self.ack_count += 1;
                self.largest_acked = if (self.largest_acked) |largest|
                    @max(largest, number)
                else
                    number;
                return self.outstanding.swapRemove(index);
            }
        }
        return null;
    }

    /// Marks a tracked packet as lost.
    pub fn onLoss(self: *RecoveryState, number: u64, space: PacketNumberSpace) ?SentPacket {
        for (self.outstanding.items, 0..) |packet, index| {
            if (packet.number == number and packet.space == space) {
                self.loss_count += 1;
                return self.outstanding.swapRemove(index);
            }
        }
        return null;
    }
};

/// Congestion-control counters for the local QUIC transport.
pub const CongestionController = struct {
    /// Congestion window in bytes.
    congestion_window: usize,
    /// Slow-start threshold in bytes.
    slow_start_threshold: usize,
    /// Bytes currently considered in flight.
    bytes_in_flight: usize,
    /// Maximum datagram size used for growth heuristics.
    max_datagram_size: usize,

    /// Returns the default controller for the provided datagram size.
    pub fn init(max_datagram_size: usize) CongestionController {
        return .{
            .congestion_window = max_datagram_size * 10,
            .slow_start_threshold = std.math.maxInt(usize),
            .bytes_in_flight = 0,
            .max_datagram_size = max_datagram_size,
        };
    }

    /// Accounts for an in-flight packet.
    pub fn onPacketSent(self: *CongestionController, bytes: usize) void {
        self.bytes_in_flight += bytes;
    }

    /// Accounts for an acknowledged packet.
    pub fn onAck(self: *CongestionController, bytes: usize) void {
        self.bytes_in_flight = self.bytes_in_flight -| bytes;
        if (self.congestion_window < self.slow_start_threshold) {
            self.congestion_window += bytes;
        } else if (bytes > 0) {
            self.congestion_window += @max(self.max_datagram_size, bytes / 2);
        }
    }

    /// Accounts for a lost packet.
    pub fn onLoss(self: *CongestionController, bytes: usize) void {
        self.bytes_in_flight = self.bytes_in_flight -| bytes;
        self.slow_start_threshold = @max(self.congestion_window / 2, self.max_datagram_size * 2);
        self.congestion_window = self.slow_start_threshold;
    }
};

/// One locally tracked QUIC stream.
pub const StreamState = struct {
    /// Stable stream identifier.
    id: u64,
    /// Stream family.
    kind: StreamKind,
};

/// Decoded packet bytes returned after packet protection is removed.
pub const Packet = struct {
    /// Packet-number space.
    space: PacketNumberSpace,
    /// Packet number within the space.
    number: u64,
    /// Key phase marker stored in the header.
    key_phase: bool,
    /// Decrypted payload bytes.
    payload: []u8,

    /// Releases the owned payload buffer.
    pub fn deinit(self: *Packet, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

/// Minimal QUIC connection state holder used by the HTTP/3 modules.
pub const Connection = struct {
    /// Allocator used for packet tracking and stream bookkeeping.
    allocator: std.mem.Allocator,
    /// Current lifecycle state.
    state: ConnectionState,
    /// Local destination connection identifier.
    connection_id_local: ConnectionId,
    /// Peer connection identifier.
    connection_id_remote: ConnectionId,
    /// Packet-number spaces.
    packet_spaces: [3]PacketSpaceState,
    /// Loss-recovery state.
    recovery: RecoveryState,
    /// Congestion counters.
    congestion: CongestionController,
    /// Bidirectional streams opened by this endpoint.
    streams_bidi: std.ArrayListUnmanaged(StreamState),
    /// Unidirectional streams opened by this endpoint.
    streams_uni: std.ArrayListUnmanaged(StreamState),
    /// Connection close state.
    close_state: CloseState,

    /// Returns a new QUIC connection with the provided connection identifiers.
    pub fn init(
        allocator: std.mem.Allocator,
        local_id: ConnectionId,
        remote_id: ConnectionId,
    ) Connection {
        return .{
            .allocator = allocator,
            .state = .initial,
            .connection_id_local = local_id,
            .connection_id_remote = remote_id,
            .packet_spaces = .{ .{}, .{}, .{} },
            .recovery = RecoveryState.init(),
            .congestion = CongestionController.init(1200),
            .streams_bidi = .{},
            .streams_uni = .{},
            .close_state = .open,
        };
    }

    /// Releases connection-owned bookkeeping.
    pub fn deinit(self: *Connection) void {
        self.recovery.deinit(self.allocator);
        self.streams_bidi.deinit(self.allocator);
        self.streams_uni.deinit(self.allocator);
        self.* = undefined;
    }

    /// Moves the connection into the handshake state.
    pub fn beginHandshake(self: *Connection) void {
        if (self.state == .initial) {
            self.state = .handshake;
        }
    }

    /// Marks the connection as ready for application data.
    pub fn establish(self: *Connection) void {
        self.state = .established;
    }

    /// Begins connection close bookkeeping.
    pub fn beginClose(self: *Connection) void {
        self.close_state = .draining;
        self.state = .draining;
    }

    /// Marks the connection as fully closed.
    pub fn close(self: *Connection) void {
        self.close_state = .closed;
        self.state = .closed;
    }

    /// Opens a new stream in the selected stream family.
    pub fn openStream(self: *Connection, kind: StreamKind) std.mem.Allocator.Error!u64 {
        const stream_id = switch (kind) {
            .bidirectional => @as(u64, self.streams_bidi.items.len) * 4,
            .unidirectional => @as(u64, self.streams_uni.items.len) * 4 + 2,
        };
        const stream = StreamState{
            .id = stream_id,
            .kind = kind,
        };
        switch (kind) {
            .bidirectional => try self.streams_bidi.append(self.allocator, stream),
            .unidirectional => try self.streams_uni.append(self.allocator, stream),
        }
        return stream_id;
    }

    /// Applies reversible packet protection and returns an owned datagram.
    pub fn protectPacket(
        self: *Connection,
        allocator: std.mem.Allocator,
        space: PacketNumberSpace,
        payload: []const u8,
    ) Error![]u8 {
        const header_len = 28;
        const index = packetSpaceIndex(space);
        const packet_number = self.packet_spaces[index].next_packet_number;
        self.packet_spaces[index].next_packet_number += 1;

        const bytes = try allocator.alloc(u8, header_len + payload.len);
        errdefer allocator.free(bytes);

        bytes[0] = @intFromEnum(space);
        bytes[1] = if (space == .application and (packet_number & 1) == 1) 1 else 0;
        writeU64(bytes[2..10], packet_number);
        std.mem.copyForwards(u8, bytes[10..18], self.connection_id_remote[0..]);
        std.mem.copyForwards(u8, bytes[18..26], self.connection_id_local[0..]);
        writeU16(bytes[26..28], @intCast(payload.len));

        const mask = protectionMask(
            self.connection_id_local,
            self.connection_id_remote,
            packet_number,
            space,
        );
        for (payload, 0..) |byte, offset| {
            bytes[header_len + offset] = byte ^ mask;
        }

        try self.recovery.onPacketSent(self.allocator, .{
            .number = packet_number,
            .space = space,
            .bytes_in_flight = bytes.len,
            .ack_eliciting = true,
        });
        self.congestion.onPacketSent(bytes.len);

        return bytes;
    }

    /// Removes packet protection from an owned datagram.
    pub fn unprotectPacket(
        self: *Connection,
        allocator: std.mem.Allocator,
        packet_bytes: []const u8,
    ) Error!Packet {
        const header_len = 28;
        if (packet_bytes.len < header_len) {
            return error.ShortPacket;
        }

        const space: PacketNumberSpace = @enumFromInt(packet_bytes[0]);
        const packet_number = readU64(packet_bytes[2..10]);
        const payload_len = readU16(packet_bytes[26..28]);
        if (header_len + payload_len != packet_bytes.len) {
            return error.InvalidPacketLength;
        }
        if (!std.mem.eql(u8, packet_bytes[10..18], self.connection_id_local[0..])) {
            return error.ConnectionIdMismatch;
        }

        var source_id: ConnectionId = undefined;
        std.mem.copyForwards(u8, source_id[0..], packet_bytes[18..26]);
        const mask = protectionMask(
            source_id,
            self.connection_id_local,
            packet_number,
            space,
        );
        const payload = try allocator.alloc(u8, payload_len);
        errdefer allocator.free(payload);

        for (payload, 0..) |*byte, offset| {
            byte.* = packet_bytes[header_len + offset] ^ mask;
        }

        const index = packetSpaceIndex(space);
        self.packet_spaces[index].largest_received = if (self.packet_spaces[index].largest_received) |largest|
            @max(largest, packet_number)
        else
            packet_number;
        if (space == .application and self.state != .closed) {
            self.state = .established;
        }

        return .{
            .space = space,
            .number = packet_number,
            .key_phase = packet_bytes[1] != 0,
            .payload = payload,
        };
    }

    /// Marks one packet as acknowledged and updates congestion state.
    pub fn acknowledge(self: *Connection, space: PacketNumberSpace, number: u64) bool {
        const packet = self.recovery.onAck(number, space) orelse return false;
        self.congestion.onAck(packet.bytes_in_flight);
        return true;
    }

    /// Marks one packet as lost and updates congestion state.
    pub fn markLoss(self: *Connection, space: PacketNumberSpace, number: u64) bool {
        const packet = self.recovery.onLoss(number, space) orelse return false;
        self.congestion.onLoss(packet.bytes_in_flight);
        return true;
    }
};

/// Returns the packet-space index used by `Connection.packet_spaces`.
fn packetSpaceIndex(space: PacketNumberSpace) usize {
    return @intFromEnum(space);
}

/// Writes a big-endian `u16` into the provided slice.
fn writeU16(dest: []u8, value: u16) void {
    dest[0] = @intCast((value >> 8) & 0xff);
    dest[1] = @intCast(value & 0xff);
}

/// Reads a big-endian `u16` from the provided slice.
fn readU16(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | bytes[1];
}

/// Writes a big-endian `u64` into the provided slice.
fn writeU64(dest: []u8, value: u64) void {
    for (dest, 0..) |*byte, index| {
        const shift = @as(u6, @intCast((dest.len - 1 - index) * 8));
        byte.* = @intCast((value >> shift) & 0xff);
    }
}

/// Reads a big-endian `u64` from the provided slice.
fn readU64(bytes: []const u8) u64 {
    var value: u64 = 0;
    for (bytes) |byte| {
        value = (value << 8) | byte;
    }
    return value;
}

/// Derives a one-byte protection mask from the connection ids and packet number.
fn protectionMask(
    source_id: ConnectionId,
    destination_id: ConnectionId,
    packet_number: u64,
    space: PacketNumberSpace,
) u8 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(&source_id);
    hasher.update(&destination_id);
    const packet_number_bytes = std.mem.toBytes(packet_number);
    hasher.update(&packet_number_bytes);
    hasher.update(&[_]u8{@intFromEnum(space)});
    return @truncate(hasher.final());
}

test "quic packet protection round trips application payloads" {
    var client = Connection.init(std.testing.allocator, "client01".*, "server01".*);
    defer client.deinit();
    var server = Connection.init(std.testing.allocator, "server01".*, "client01".*);
    defer server.deinit();

    client.beginHandshake();
    client.establish();
    server.beginHandshake();
    server.establish();

    const encoded = try client.protectPacket(std.testing.allocator, .application, "hello-h3");
    defer std.testing.allocator.free(encoded);

    var packet = try server.unprotectPacket(std.testing.allocator, encoded);
    defer packet.deinit(std.testing.allocator);

    try std.testing.expectEqual(PacketNumberSpace.application, packet.space);
    try std.testing.expectEqualStrings("hello-h3", packet.payload);
    try std.testing.expectEqual(@as(?u64, 0), server.packet_spaces[@intFromEnum(PacketNumberSpace.application)].largest_received);
}

test "quic recovery updates congestion on ack and loss" {
    var client = Connection.init(std.testing.allocator, "client01".*, "server01".*);
    defer client.deinit();

    const first = try client.protectPacket(std.testing.allocator, .application, "first");
    defer std.testing.allocator.free(first);
    const second = try client.protectPacket(std.testing.allocator, .application, "second");
    defer std.testing.allocator.free(second);

    const before_ack = client.congestion.congestion_window;
    try std.testing.expect(client.acknowledge(.application, 0));
    try std.testing.expect(client.congestion.congestion_window > before_ack);

    const before_loss = client.congestion.congestion_window;
    try std.testing.expect(client.markLoss(.application, 1));
    try std.testing.expect(client.congestion.congestion_window <= before_loss);
    try std.testing.expectEqual(@as(usize, 0), client.recovery.outstanding.items.len);
}

test "quic stream ids separate bidirectional and unidirectional families" {
    var client = Connection.init(std.testing.allocator, "client01".*, "server01".*);
    defer client.deinit();

    try std.testing.expectEqual(@as(u64, 0), try client.openStream(.bidirectional));
    try std.testing.expectEqual(@as(u64, 4), try client.openStream(.bidirectional));
    try std.testing.expectEqual(@as(u64, 2), try client.openStream(.unidirectional));
}
