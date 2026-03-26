//! Deterministic in-repo HTTP/2 peer fixture for multiplexing scenarios.

const std = @import("std");
const types = @import("../types.zig");
const interop_harness = @import("../testing/interop_harness.zig");

/// Terminal action scripted by the fixture after body delivery begins.
pub const TerminalAction = enum {
    /// Deliver the full body successfully.
    none,
    /// Reset the current stream after the first body chunk.
    rst_stream,
    /// Begin draining the shared connection after the first body chunk.
    goaway,
};

/// Owned semantic response and delivery script for one HTTP/2 stream.
pub const PreparedResponse = struct {
    /// Allocator used for owned headers and body bytes.
    allocator: std.mem.Allocator,
    /// Response status code.
    status: types.Status,
    /// Response headers.
    headers: types.Headers,
    /// Response body bytes to stream.
    body: []u8,
    /// Delay before the first chunk is emitted.
    initial_delay_ns: u64,
    /// Delay between subsequent chunks.
    inter_chunk_delay_ns: u64,
    /// Maximum body bytes emitted per scheduler step.
    chunk_bytes: usize,
    /// Scripted terminal action for the stream.
    terminal_action: TerminalAction,

    /// Releases owned headers and body bytes.
    pub fn deinit(self: *PreparedResponse) void {
        self.headers.deinit();
        self.allocator.free(self.body);
        self.* = undefined;
    }
};

/// Prepares a deterministic semantic response and delivery script for a request.
pub fn prepareResponse(
    allocator: std.mem.Allocator,
    request: *const types.Request,
) !PreparedResponse {
    const request_body = if (request.body) |body_reader|
        try readBodyAlloc(allocator, body_reader, 256 * 1024)
    else
        try allocator.alloc(u8, 0);
    defer allocator.free(request_body);

    var semantic = try interop_harness.buildSemanticResponse(allocator, .{
        .method = request.method,
        .path = request.uri.path,
        .query = request.uri.query,
        .negotiated_protocol = .h2,
        .body = request_body,
        .cookie_header = request.headers.get("cookie"),
    });
    errdefer semantic.deinit();

    const status = semantic.status;
    const body = try allocator.dupe(u8, semantic.body);
    errdefer allocator.free(body);

    var headers = types.Headers.init(allocator);
    errdefer headers.deinit();
    var iterator = semantic.headers.iterator();
    while (iterator.next()) |header| {
        try headers.append(header.name, header.value);
    }

    const action = terminalActionForRequest(request.uri);
    const chunk_bytes = switch (action) {
        .none => if (std.mem.eql(u8, request.uri.path, "/stream/large")) 1024 else @max(body.len, 1),
        .rst_stream, .goaway => 8,
    };

    const initial_delay_ns: u64 = switch (action) {
        .none => if (std.mem.eql(u8, request.uri.path, "/health") or std.mem.eql(u8, request.uri.path, "/echo"))
            2 * std.time.ns_per_ms
        else
            std.time.ns_per_ms,
        .rst_stream, .goaway => std.time.ns_per_ms,
    };

    semantic.deinit();

    return .{
        .allocator = allocator,
        .status = status,
        .headers = headers,
        .body = body,
        .initial_delay_ns = initial_delay_ns,
        .inter_chunk_delay_ns = if (body.len > chunk_bytes) std.time.ns_per_ms else 0,
        .chunk_bytes = chunk_bytes,
        .terminal_action = action,
    };
}

/// Returns the scripted terminal action for the request URI.
fn terminalActionForRequest(uri: types.Uri) TerminalAction {
    const action = queryValue(uri.query, "action") orelse return .none;
    if (std.mem.eql(u8, action, "rst")) {
        return .rst_stream;
    }
    if (std.mem.eql(u8, action, "goaway")) {
        return .goaway;
    }
    return .none;
}

/// Returns the first matching query value for the given key.
fn queryValue(query: ?[]const u8, name: []const u8) ?[]const u8 {
    const raw_query = query orelse return null;
    var pairs = std.mem.splitScalar(u8, raw_query, '&');
    while (pairs.next()) |pair| {
        var entry = std.mem.splitScalar(u8, pair, '=');
        const key = entry.next() orelse continue;
        const value = entry.next() orelse continue;
        if (std.mem.eql(u8, key, name)) {
            return value;
        }
    }
    return null;
}

/// Reads a full request body into memory for the local fixture flow.
fn readBodyAlloc(
    allocator: std.mem.Allocator,
    body_reader: types.BodyReader,
    max_bytes: usize,
) ![]u8 {
    var collected = std.ArrayListUnmanaged(u8){};
    errdefer collected.deinit(allocator);

    var buffer: [4096]u8 = undefined;
    while (true) {
        const read_len = try body_reader.read(&buffer);
        if (read_len == 0) {
            break;
        }
        if (collected.items.len + read_len > max_bytes) {
            return error.BodyTooLarge;
        }
        try collected.appendSlice(allocator, buffer[0..read_len]);
    }

    return collected.toOwnedSlice(allocator);
}

test "http2 test peer prepares the concurrent health fixture" {
    const peer = interop_harness.alpnPeerProfileForId(.dual_alpn).?;

    var request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, peer.host, peer.port, "/health", null, null),
    );
    defer request.deinit();
    try request.headers.append("Host", peer.host);

    var response = try prepareResponse(std.testing.allocator, &request);
    defer response.deinit();

    try std.testing.expectEqual(types.Status.ok, response.status);
    try std.testing.expectEqual(TerminalAction.none, response.terminal_action);
    try std.testing.expect(response.chunk_bytes >= 1);
}

test "http2 test peer scripts reset and goaway actions from query parameters" {
    const peer = interop_harness.alpnPeerProfileForId(.dual_alpn).?;

    var rst_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, peer.host, peer.port, "/stream/chunked", "action=rst", null),
    );
    defer rst_request.deinit();
    try rst_request.headers.append("Host", peer.host);

    var rst_response = try prepareResponse(std.testing.allocator, &rst_request);
    defer rst_response.deinit();
    try std.testing.expectEqual(TerminalAction.rst_stream, rst_response.terminal_action);

    var goaway_request = types.Request.init(
        std.testing.allocator,
        .get,
        types.Uri.init(.https, peer.host, peer.port, "/stream/chunked", "action=goaway", null),
    );
    defer goaway_request.deinit();
    try goaway_request.headers.append("Host", peer.host);

    var goaway_response = try prepareResponse(std.testing.allocator, &goaway_request);
    defer goaway_response.deinit();
    try std.testing.expectEqual(TerminalAction.goaway, goaway_response.terminal_action);
}
