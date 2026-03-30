//! Server-side response compression policy and buffered flush helpers.

const std = @import("std");
const core = @import("../types.zig");
const shared_encoding = @import("../compression/encoding.zig");
const shared_encoder = @import("../compression/encoder.zig");
const server_types = @import("types.zig");

const default_supported_encodings = [_]shared_encoding.ContentEncoding{ .gzip, .identity };
const default_compressible_content_types = [_][]const u8{
    "text/",
    "application/json",
    "application/javascript",
    "application/xml",
};

/// Compression decision returned for one buffered response.
pub const Decision = struct {
    /// Wire encoding chosen for the response.
    encoding: shared_encoding.ContentEncoding,
    /// Action selected for the response.
    action: shared_encoding.EncodingDecision,
    /// Optional explanatory note for bypass or reject outcomes.
    reason: ?[]const u8,
};

/// Server-side compression policy for first-party application responses.
pub const Policy = struct {
    /// Encodings the server may emit.
    supported_encodings: []const shared_encoding.ContentEncoding,
    /// Minimum body size before compression is considered.
    minimum_body_bytes: usize,
    /// Content-type prefixes eligible for compression.
    compressible_content_types: []const []const u8,
    /// Protocols that must bypass compression.
    disallowed_protocols: []const core.NegotiatedProtocol,
    /// Whether pre-encoded responses must bypass compression.
    already_encoded_bypass: bool,
    /// Whether paired client helpers are expected to auto-decode.
    client_auto_decode: bool,

    /// Returns the default server-side compression policy.
    pub fn default() Policy {
        return .{
            .supported_encodings = &default_supported_encodings,
            .minimum_body_bytes = 32,
            .compressible_content_types = &default_compressible_content_types,
            .disallowed_protocols = &.{},
            .already_encoded_bypass = true,
            .client_auto_decode = true,
        };
    }

    /// Returns a policy derived from the provided route-level preference.
    pub fn withPreference(self: Policy, preference: server_types.ServerPolicyPreference) Policy {
        if (preference != .disabled) {
            return self;
        }

        var copy = self;
        copy.supported_encodings = &.{.identity};
        copy.minimum_body_bytes = std.math.maxInt(usize);
        return copy;
    }

    /// Selects the compression decision for the buffered response.
    pub fn decide(
        self: Policy,
        request: *const server_types.ServerRequest,
        headers: *const core.Headers,
        body: []const u8,
    ) Decision {
        if (body.len < self.minimum_body_bytes) {
            return .{
                .encoding = .identity,
                .action = .bypass,
                .reason = "below_minimum_size",
            };
        }
        if (protocolDisallowed(self.disallowed_protocols, request.negotiated_protocol)) {
            return .{
                .encoding = .identity,
                .action = .bypass,
                .reason = "protocol_disallowed",
            };
        }
        if (self.already_encoded_bypass and headers.get("Content-Encoding") != null) {
            return .{
                .encoding = .identity,
                .action = .bypass,
                .reason = "already_encoded",
            };
        }

        const content_type = headers.get("Content-Type") orelse headers.get("content-type") orelse "";
        if (!contentTypeCompressible(self.compressible_content_types, content_type)) {
            return .{
                .encoding = .identity,
                .action = .bypass,
                .reason = "content_type_ineligible",
            };
        }

        const accepted = acceptedEncoding(self.supported_encodings, request.header("Accept-Encoding"));
        if (accepted == .identity) {
            return .{
                .encoding = .identity,
                .action = .bypass,
                .reason = "client_prefers_identity",
            };
        }

        return .{
            .encoding = accepted,
            .action = .apply,
            .reason = null,
        };
    }
};

/// Buffered response body sink used to delay compression until dispatch completes.
pub const ResponseBuffer = struct {
    /// Allocator used for buffered body bytes.
    allocator: std.mem.Allocator,
    /// Buffered response body bytes.
    body: std.ArrayListUnmanaged(u8),

    /// Returns an empty response buffer.
    pub fn init(allocator: std.mem.Allocator) ResponseBuffer {
        return .{
            .allocator = allocator,
            .body = .{},
        };
    }

    /// Releases buffered response bytes.
    pub fn deinit(self: *ResponseBuffer) void {
        self.body.deinit(self.allocator);
        self.* = undefined;
    }

    /// Returns a response writer backed by the buffer.
    pub fn responseWriter(self: *ResponseBuffer) server_types.ServerResponseWriter {
        return server_types.ServerResponseWriter.init(
            self.allocator,
            self,
            writeBodyChunk,
            beginResponse,
            finishResponse,
            null,
        );
    }
};

/// Flushes a buffered response through the real protocol writer with compression applied when eligible.
pub fn flushBufferedResponse(
    policy: Policy,
    request: *const server_types.ServerRequest,
    buffered_writer: *const server_types.ServerResponseWriter,
    buffer: *const ResponseBuffer,
    writer: *server_types.ServerResponseWriter,
) !void {
    const decision = policy.decide(request, &buffered_writer.headers, buffer.body.items);
    const encoded = try encodeBody(policy, decision, writer.headers.allocator, buffer.body.items);
    defer if (encoded.owned) {
        writer.headers.allocator.free(encoded.bytes);
    };

    writer.setStatus(buffered_writer.status);
    try copyHeaders(writer, &buffered_writer.headers, decision);
    try copyTrailers(writer, &buffered_writer.trailers);
    var content_length_buffer: [32]u8 = undefined;
    const content_length = try std.fmt.bufPrint(&content_length_buffer, "{d}", .{encoded.bytes.len});
    try writer.appendHeader("Content-Length", content_length);

    if (request.method != .head and encoded.bytes.len > 0) {
        try writer.writeAll(encoded.bytes);
    }
}

/// Encoded response body selected for the final flush step.
const EncodedResult = struct {
    /// Bytes emitted through the final protocol writer.
    bytes: []const u8,
    /// Whether `bytes` must be freed by the caller.
    owned: bool,
};

/// Header emission is delayed until the buffered response is flushed.
fn beginResponse(_: ?*anyopaque, _: *server_types.ServerResponseWriter) anyerror!void {}

/// Appends one buffered body chunk.
fn writeBodyChunk(ctx: ?*anyopaque, bytes: []const u8) anyerror!void {
    const self: *ResponseBuffer = @ptrCast(@alignCast(ctx.?));
    try self.body.appendSlice(self.allocator, bytes);
}

/// Response completion is also delayed until the flush step.
fn finishResponse(_: ?*anyopaque, _: *server_types.ServerResponseWriter) anyerror!void {}

/// Returns the final body bytes selected for the response.
fn encodeBody(
    _: Policy,
    decision: Decision,
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !EncodedResult {
    if (decision.action != .apply or decision.encoding == .identity) {
        return .{
            .bytes = bytes,
            .owned = false,
        };
    }

    const encoded = try shared_encoder.Encoder.init(decision.encoding).encodeAlloc(allocator, bytes);
    return .{
        .bytes = encoded.bytes,
        .owned = true,
    };
}

/// Copies buffered response headers to the final protocol writer.
fn copyHeaders(
    writer: *server_types.ServerResponseWriter,
    headers: *const core.Headers,
    decision: Decision,
) !void {
    var iterator = headers.iterator();
    while (iterator.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "Content-Length")) {
            continue;
        }
        if (std.ascii.eqlIgnoreCase(header.name, "Transfer-Encoding")) {
            continue;
        }
        if (std.ascii.eqlIgnoreCase(header.name, "Content-Encoding")) {
            continue;
        }
        try writer.appendHeader(header.name, header.value);
    }

    if (decision.action == .apply and decision.encoding != .identity) {
        try writer.appendHeader("Content-Encoding", decision.encoding.asHeaderValue());
    }
}

/// Copies buffered response trailers to the final protocol writer.
fn copyTrailers(
    writer: *server_types.ServerResponseWriter,
    trailers: *const core.Headers,
) !void {
    var iterator = trailers.iterator();
    while (iterator.next()) |trailer| {
        try writer.appendTrailer(trailer.name, trailer.value);
    }
}

/// Returns true when the content type is eligible for compression.
fn contentTypeCompressible(prefixes: []const []const u8, content_type: []const u8) bool {
    if (content_type.len == 0) {
        return false;
    }
    for (prefixes) |prefix| {
        if (std.mem.startsWith(u8, content_type, prefix)) {
            return true;
        }
    }
    return false;
}

/// Returns true when the current protocol must bypass compression.
fn protocolDisallowed(
    disallowed_protocols: []const core.NegotiatedProtocol,
    protocol: core.NegotiatedProtocol,
) bool {
    for (disallowed_protocols) |disallowed| {
        if (disallowed == protocol) {
            return true;
        }
    }
    return false;
}

/// Selects the best content encoding accepted by the client and supported by the policy.
fn acceptedEncoding(
    supported_encodings: []const shared_encoding.ContentEncoding,
    accept_encoding_header: ?[]const u8,
) shared_encoding.ContentEncoding {
    const header = accept_encoding_header orelse return .identity;
    var tokens = std.mem.splitScalar(u8, header, ',');
    while (tokens.next()) |token| {
        const trimmed = std.mem.trim(u8, token, " \t");
        var attributes = std.mem.splitScalar(u8, trimmed, ';');
        const name = attributes.next() orelse continue;
        const parsed = shared_encoding.parseEncoding(name) orelse continue;
        for (supported_encodings) |supported| {
            if (supported == parsed) {
                return parsed;
            }
        }
    }
    return .identity;
}

test "server compression picks gzip only when the client accepts it" {
    const supported = [_]shared_encoding.ContentEncoding{ .gzip, .identity };

    try std.testing.expectEqual(shared_encoding.ContentEncoding.gzip, acceptedEncoding(&supported, "gzip, identity"));
    try std.testing.expectEqual(shared_encoding.ContentEncoding.identity, acceptedEncoding(&supported, "br"));
}
