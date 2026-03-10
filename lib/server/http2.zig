//! Minimal HTTP/2 negotiation planning for the server runtime.

const std = @import("std");
const core = @import("../types.zig");
const server_types = @import("types.zig");

/// Cleartext HTTP/2 client connection preface.
pub const client_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Server-side protocol selection outcome.
pub const Negotiation = struct {
    /// Protocol selected for the accepted connection.
    protocol: core.NegotiatedProtocol,
    /// Whether the runtime can serve the selected protocol end to end.
    supported: bool,
};

/// Returns the selected protocol for the listener configuration.
pub fn negotiate(config: server_types.ServerConfig, peer_preference: ?core.NegotiatedProtocol) Negotiation {
    if (config.http2_enabled) {
        if (peer_preference) |protocol| {
            if (protocol == .h2) {
                return .{
                    .protocol = .h2,
                    .supported = false,
                };
            }
        }
    }

    return .{
        .protocol = .http_1_1,
        .supported = true,
    };
}

/// Returns true when the bytes start with the HTTP/2 connection preface.
pub fn startsWithClientPreface(bytes: []const u8) bool {
    if (bytes.len < client_preface.len) {
        return false;
    }
    return std.mem.eql(u8, bytes[0..client_preface.len], client_preface);
}

test "server http2 negotiation falls back to http1 by default" {
    const noop = struct {
        fn handle(_: ?*anyopaque, _: *server_types.ServerRequest, _: *server_types.ServerResponseWriter) !void {}
    };

    const config = server_types.ServerConfig.init(noop.handle);
    const result = negotiate(config, null);

    try std.testing.expectEqual(core.NegotiatedProtocol.http_1_1, result.protocol);
    try std.testing.expect(result.supported);
}

test "server http2 preface matcher recognizes the client magic" {
    try std.testing.expect(startsWithClientPreface(client_preface));
    try std.testing.expect(!startsWithClientPreface("GET / HTTP/1.1\r\n\r\n"));
}
