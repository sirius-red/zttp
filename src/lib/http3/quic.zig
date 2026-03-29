//! Minimal QUIC transport scaffolding for the HTTP/3 path.

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

/// Lifecycle state for one QUIC session.
pub const SessionState = enum {
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

/// Close-state marker kept alongside the session state.
pub const CloseState = enum {
    /// The connection is open.
    open,
    /// The connection is draining after a close signal.
    draining,
    /// The connection is closed.
    closed,
};

/// Per-space packet-number bookkeeping.
pub const PacketSpace = struct {
    /// Packet-number space represented by this entry.
    space: PacketNumberSpace,
    /// Next packet number to emit in this space.
    next_packet_number: u64 = 0,
    /// Largest packet number received in this space.
    largest_received: ?u64 = null,

    /// Returns zeroed bookkeeping for the provided packet-number space.
    pub fn init(space: PacketNumberSpace) PacketSpace {
        return .{
            .space = space,
            .next_packet_number = 0,
            .largest_received = null,
        };
    }
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
pub const Recovery = struct {
    /// Outstanding ack-eliciting packets.
    outstanding: std.ArrayListUnmanaged(SentPacket),
    /// Largest acknowledged packet number.
    largest_acked: ?u64,
    /// Number of packets marked lost.
    loss_count: usize,
    /// Number of packets acknowledged.
    ack_count: usize,

    /// Returns an empty recovery state.
    pub fn init() Recovery {
        return .{
            .outstanding = .{},
            .largest_acked = null,
            .loss_count = 0,
            .ack_count = 0,
        };
    }

    /// Releases packet tracking storage.
    pub fn deinit(self: *Recovery, allocator: std.mem.Allocator) void {
        self.outstanding.deinit(allocator);
        self.* = undefined;
    }

    /// Records a newly transmitted packet.
    pub fn onPacketSent(
        self: *Recovery,
        allocator: std.mem.Allocator,
        packet: SentPacket,
    ) std.mem.Allocator.Error!void {
        if (packet.ack_eliciting) {
            try self.outstanding.append(allocator, packet);
        }
    }

    /// Marks a tracked packet as acknowledged.
    pub fn onAck(self: *Recovery, number: u64, space: PacketNumberSpace) ?SentPacket {
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
    pub fn onLoss(self: *Recovery, number: u64, space: PacketNumberSpace) ?SentPacket {
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
pub const CongestionState = struct {
    /// Congestion window in bytes.
    congestion_window: usize,
    /// Slow-start threshold in bytes.
    slow_start_threshold: usize,
    /// Bytes currently considered in flight.
    bytes_in_flight: usize,
    /// Maximum datagram size used for growth heuristics.
    max_datagram_size: usize,

    /// Returns the default controller for the provided datagram size.
    pub fn init(max_datagram_size: usize) CongestionState {
        return .{
            .congestion_window = max_datagram_size * 10,
            .slow_start_threshold = std.math.maxInt(usize),
            .bytes_in_flight = 0,
            .max_datagram_size = max_datagram_size,
        };
    }

    /// Accounts for an in-flight packet.
    pub fn onPacketSent(self: *CongestionState, bytes: usize) void {
        self.bytes_in_flight += bytes;
    }

    /// Accounts for an acknowledged packet.
    pub fn onAck(self: *CongestionState, bytes: usize) void {
        self.bytes_in_flight = self.bytes_in_flight -| bytes;
        if (self.congestion_window < self.slow_start_threshold) {
            self.congestion_window += bytes;
        } else if (bytes > 0) {
            self.congestion_window += @max(self.max_datagram_size, bytes / 2);
        }
    }

    /// Accounts for a lost packet.
    pub fn onLoss(self: *CongestionState, bytes: usize) void {
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

/// Stream registries retained for one QUIC session.
pub const StreamRegistry = struct {
    /// Bidirectional streams opened by this endpoint.
    bidirectional: std.ArrayListUnmanaged(StreamState),
    /// Unidirectional streams opened by this endpoint.
    unidirectional: std.ArrayListUnmanaged(StreamState),

    /// Returns an empty stream registry.
    pub fn init() StreamRegistry {
        return .{
            .bidirectional = .{},
            .unidirectional = .{},
        };
    }

    /// Releases all tracked stream state.
    pub fn deinit(self: *StreamRegistry, allocator: std.mem.Allocator) void {
        self.bidirectional.deinit(allocator);
        self.unidirectional.deinit(allocator);
        self.* = undefined;
    }

    /// Opens a new stream in the selected family and returns its stream id.
    pub fn openStream(
        self: *StreamRegistry,
        allocator: std.mem.Allocator,
        kind: StreamKind,
    ) std.mem.Allocator.Error!u64 {
        const stream_id = switch (kind) {
            .bidirectional => @as(u64, self.bidirectional.items.len) * 4,
            .unidirectional => @as(u64, self.unidirectional.items.len) * 4 + 2,
        };
        const stream = StreamState{
            .id = stream_id,
            .kind = kind,
        };
        switch (kind) {
            .bidirectional => try self.bidirectional.append(allocator, stream),
            .unidirectional => try self.unidirectional.append(allocator, stream),
        }
        return stream_id;
    }
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

/// Minimal QUIC session state holder used by the HTTP/3 modules.
pub const Session = struct {
    /// Allocator used for packet tracking and stream bookkeeping.
    allocator: std.mem.Allocator,
    /// Current lifecycle state.
    state: SessionState,
    /// Local destination connection identifier.
    local_connection_id: ConnectionId,
    /// Peer connection identifier.
    remote_connection_id: ConnectionId,
    /// Packet-number spaces.
    packet_spaces: [3]PacketSpace,
    /// Loss-recovery state.
    recovery: Recovery,
    /// Congestion counters.
    congestion: CongestionState,
    /// Stream registry retained across the session.
    stream_registry: StreamRegistry,
    /// Connection close state.
    close_state: CloseState,

    /// Returns a new QUIC session with the provided connection identifiers.
    pub fn init(
        allocator: std.mem.Allocator,
        local_id: ConnectionId,
        remote_id: ConnectionId,
    ) Session {
        return .{
            .allocator = allocator,
            .state = .initial,
            .local_connection_id = local_id,
            .remote_connection_id = remote_id,
            .packet_spaces = .{
                PacketSpace.init(.initial),
                PacketSpace.init(.handshake),
                PacketSpace.init(.application),
            },
            .recovery = Recovery.init(),
            .congestion = CongestionState.init(1200),
            .stream_registry = StreamRegistry.init(),
            .close_state = .open,
        };
    }

    /// Releases session-owned bookkeeping.
    pub fn deinit(self: *Session) void {
        self.recovery.deinit(self.allocator);
        self.stream_registry.deinit(self.allocator);
        self.* = undefined;
    }

    /// Moves the session into the handshake state.
    pub fn beginHandshake(self: *Session) void {
        if (self.state == .initial) {
            self.state = .handshake;
        }
    }

    /// Marks the session as ready for application data.
    pub fn establish(self: *Session) void {
        self.state = .established;
    }

    /// Begins session close bookkeeping.
    pub fn beginClose(self: *Session) void {
        self.close_state = .draining;
        self.state = .draining;
    }

    /// Marks the session as fully closed.
    pub fn close(self: *Session) void {
        self.close_state = .closed;
        self.state = .closed;
    }

    /// Opens a new stream in the selected stream family.
    pub fn openStream(self: *Session, kind: StreamKind) std.mem.Allocator.Error!u64 {
        return self.stream_registry.openStream(self.allocator, kind);
    }

    /// Applies reversible packet protection and returns an owned datagram.
    pub fn protectPacket(
        self: *Session,
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
        std.mem.copyForwards(u8, bytes[10..18], self.remote_connection_id[0..]);
        std.mem.copyForwards(u8, bytes[18..26], self.local_connection_id[0..]);
        writeU16(bytes[26..28], @intCast(payload.len));

        const mask = protectionMask(
            self.local_connection_id,
            self.remote_connection_id,
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
        self: *Session,
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
        if (!std.mem.eql(u8, packet_bytes[10..18], self.local_connection_id[0..])) {
            return error.ConnectionIdMismatch;
        }

        var source_id: ConnectionId = undefined;
        std.mem.copyForwards(u8, source_id[0..], packet_bytes[18..26]);
        const mask = protectionMask(
            source_id,
            self.local_connection_id,
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
    pub fn acknowledge(self: *Session, space: PacketNumberSpace, number: u64) bool {
        const packet = self.recovery.onAck(number, space) orelse return false;
        self.congestion.onAck(packet.bytes_in_flight);
        return true;
    }

    /// Marks one packet as lost and updates congestion state.
    pub fn markLoss(self: *Session, space: PacketNumberSpace, number: u64) bool {
        const packet = self.recovery.onLoss(number, space) orelse return false;
        self.congestion.onLoss(packet.bytes_in_flight);
        return true;
    }
};

/// Backward-compatible alias for the canonical QUIC session lifecycle state.
pub const ConnectionState = SessionState;
/// Backward-compatible alias for the canonical packet-space bookkeeping type.
pub const PacketSpaceState = PacketSpace;
/// Backward-compatible alias for the canonical recovery bookkeeping type.
pub const RecoveryState = Recovery;
/// Backward-compatible alias for the canonical congestion bookkeeping type.
pub const CongestionController = CongestionState;
/// Backward-compatible alias for the canonical QUIC session type.
pub const Connection = Session;

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

test "quic session initializes canonical packet spaces" {
    var session = Session.init(std.testing.allocator, "client01".*, "server01".*);
    defer session.deinit();

    try std.testing.expectEqual(PacketNumberSpace.initial, session.packet_spaces[0].space);
    try std.testing.expectEqual(PacketNumberSpace.handshake, session.packet_spaces[1].space);
    try std.testing.expectEqual(PacketNumberSpace.application, session.packet_spaces[2].space);
    try std.testing.expectEqual(@as(?u64, null), session.packet_spaces[0].largest_received);
}

test "quic packet protection round trips application payloads" {
    var client = Session.init(std.testing.allocator, "client01".*, "server01".*);
    defer client.deinit();
    var server = Session.init(std.testing.allocator, "server01".*, "client01".*);
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
    var client = Session.init(std.testing.allocator, "client01".*, "server01".*);
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
    var client = Session.init(std.testing.allocator, "client01".*, "server01".*);
    defer client.deinit();

    try std.testing.expectEqual(@as(u64, 0), try client.openStream(.bidirectional));
    try std.testing.expectEqual(@as(u64, 4), try client.openStream(.bidirectional));
    try std.testing.expectEqual(@as(u64, 2), try client.openStream(.unidirectional));
}
