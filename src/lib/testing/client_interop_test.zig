//! Client interop regression coverage tied to the shared harness contract.

const std = @import("std");
const client = @import("../client.zig");
const fixture_loader = @import("fixture_loader.zig");
const interop_harness = @import("interop_harness.zig");
const multipart_form_data = @import("../multipart/form_data.zig");
const smoke_runner = @import("smoke_runner.zig");
const types = @import("../types.zig");

/// Expected protocol coverage for first-party client convenience flows.
const client_flow_protocols = [_]types.NegotiatedProtocol{ .http_1_1, .h2, .h3 };

/// Declarative expectation for the multipart upload acceptance flow.
const MultipartAcceptanceExpectation = struct {
    /// Endpoint path exposed by the contract.
    path: []const u8,
    /// Metadata field name required by the multipart schema.
    metadata_field_name: []const u8,
    /// Metadata field value used by the acceptance fixture.
    metadata_field_value: []const u8,
    /// File field name required by the multipart schema.
    file_field_name: []const u8,
    /// Uploaded fixture filename.
    filename: []const u8,
    /// Uploaded fixture content type.
    content_type: []const u8,
    /// Expected success status for the route.
    accepted_status: types.Status,
    /// Minimum accepted part count required by the contract.
    minimum_part_count: usize,
};

/// Declarative expectation for the automatic decompression flow.
const DecompressionAcceptanceExpectation = struct {
    /// Endpoint path exposed by the contract.
    path: []const u8,
    /// Encoded content type served by the route.
    content_type: []const u8,
    /// Content encoding inspected by the first-party decoder.
    content_encoding: client.ContentEncoding,
};

/// Shared multipart acceptance contract for `/upload`.
const multipart_acceptance = MultipartAcceptanceExpectation{
    .path = "/upload",
    .metadata_field_name = "metadata",
    .metadata_field_value = "{\"fixture\":\"upload\"}",
    .file_field_name = "file",
    .filename = "upload.bin",
    .content_type = "application/octet-stream",
    .accepted_status = .created,
    .minimum_part_count = 2,
};

/// Shared automatic decompression acceptance contract for `/download/compressed`.
const decompression_acceptance = DecompressionAcceptanceExpectation{
    .path = "/download/compressed",
    .content_type = "application/octet-stream",
    .content_encoding = .gzip,
};

/// Expects one capability matrix entry to report supported client behavior.
fn expectSupportedCapability(
    feature: interop_harness.CapabilityFeatureId,
    protocol: types.NegotiatedProtocol,
) !void {
    const capability = interop_harness.capabilityFor(feature, protocol) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(types.FeatureSupportLevel.supported, capability.support);
}

test "client interop catalog covers required contract routes" {
    const health = interop_harness.scenarioForRoute(.health).?;
    const echo_get = interop_harness.scenarioForRoute(.echo_get).?;
    const redirect = interop_harness.scenarioForRoute(.redirect_count).?;
    const cookie_set = interop_harness.scenarioForRoute(.cookies_set).?;
    const cookie_read = interop_harness.scenarioForRoute(.cookies_read).?;
    const chunked = interop_harness.scenarioForRoute(.stream_chunked).?;
    const large = interop_harness.scenarioForRoute(.stream_large).?;

    try std.testing.expectEqualStrings("/health", health.path_template);
    try std.testing.expectEqualStrings("/echo", echo_get.path_template);
    try std.testing.expectEqualStrings("/redirect/{count}", redirect.path_template);
    try std.testing.expectEqualStrings("/cookies/set", cookie_set.path_template);
    try std.testing.expectEqualStrings("/cookies/read", cookie_read.path_template);
    try std.testing.expectEqualStrings("/stream/chunked", chunked.path_template);
    try std.testing.expectEqualStrings("/stream/large", large.path_template);
}

test "client interop catalog preserves expected response modes" {
    const redirect = interop_harness.scenarioForRoute(.redirect_count).?;
    const cookie_set = interop_harness.scenarioForRoute(.cookies_set).?;
    const chunked = interop_harness.scenarioForRoute(.stream_chunked).?;
    const large = interop_harness.scenarioForRoute(.stream_large).?;

    try std.testing.expectEqual(.redirect, redirect.response_mode);
    try std.testing.expectEqual(.no_content, cookie_set.response_mode);
    try std.testing.expectEqual(.text_stream, chunked.response_mode);
    try std.testing.expectEqual(.binary_stream, large.response_mode);
}

test "smoke scenarios retain request coverage for http and https" {
    const scenarios = smoke_runner.defaultScenarios();
    try std.testing.expect(scenarios.len >= 4);
    try std.testing.expectEqualStrings("request-http", scenarios[2].name);
    try std.testing.expectEqualStrings("request-https", scenarios[3].name);
    try std.testing.expect(scenarios[2].route != null);
    try std.testing.expect(scenarios[3].route != null);
}

test "client interop preserves the windows loopback readiness probe contract" {
    const readiness = interop_harness.readinessScenarioForId(.windows_loopback_cli_roundtrip).?;

    try std.testing.expectEqualStrings("windows-cli-loopback-roundtrip", readiness.name);
    try std.testing.expectEqual(interop_harness.RouteId.health, readiness.route);
    try std.testing.expectEqualStrings("request", readiness.request_command.name);
    try std.testing.expectEqualStrings("http://127.0.0.1:18080/health", readiness.request_command.argv[5]);
    try std.testing.expect(readiness.blocking);
    try std.testing.expect(std.mem.containsAtLeast(
        u8,
        readiness.expected_body_substring,
        1,
        "\"protocol\":\"http/1.1\"",
    ));
}

test "client interop loopback identities resolve to repository fixtures" {
    const loader = fixture_loader.Loader.init();
    var paths = try loader.loopbackIdentityPaths(std.testing.allocator);
    defer paths.deinit(std.testing.allocator);

    try std.testing.expect(
        std.mem.endsWith(u8, paths.certificate_chain_path, "certs/loopback-server.pem") or
            std.mem.endsWith(u8, paths.certificate_chain_path, "certs\\loopback-server.pem"),
    );
    try std.testing.expect(
        std.mem.endsWith(u8, paths.private_key_path, "certs/loopback-server.key") or
            std.mem.endsWith(u8, paths.private_key_path, "certs\\loopback-server.key"),
    );
}

test "client interop aligns multipart upload coverage with the shared local contract" {
    const loader = fixture_loader.Loader.init();
    const upload_bytes = try loader.loadHigherLevelAsset(std.testing.allocator, .upload_bin);
    defer std.testing.allocator.free(upload_bytes);

    var form = client.FormData.init(
        std.testing.allocator,
        multipart_form_data.Boundary.init("upload-boundary-01"),
    );
    defer form.deinit();

    try form.appendField(
        multipart_acceptance.metadata_field_name,
        multipart_acceptance.metadata_field_value,
    );
    try form.appendFile(
        multipart_acceptance.file_field_name,
        multipart_acceptance.filename,
        multipart_acceptance.content_type,
        upload_bytes,
    );

    const content_type = try form.contentTypeAlloc(std.testing.allocator);
    defer std.testing.allocator.free(content_type);

    try std.testing.expectEqualStrings("/upload", multipart_acceptance.path);
    try std.testing.expectEqual(types.Status.created, multipart_acceptance.accepted_status);
    try std.testing.expectEqual(multipart_form_data.Replayability.replayable, form.replayability);
    try std.testing.expectEqual(multipart_acceptance.minimum_part_count, form.parts.items.len);
    try std.testing.expect(std.mem.startsWith(u8, content_type, "multipart/form-data; boundary="));

    for (client_flow_protocols) |protocol| {
        try expectSupportedCapability(.client_multipart, protocol);
    }

    switch (form.parts.items[0]) {
        .field => |field| {
            try std.testing.expectEqualStrings(multipart_acceptance.metadata_field_name, field.name);
            try std.testing.expectEqualStrings(multipart_acceptance.metadata_field_value, field.value);
        },
        else => return error.TestUnexpectedResult,
    }

    switch (form.parts.items[1]) {
        .file => |file| {
            try std.testing.expectEqualStrings(multipart_acceptance.file_field_name, file.name);
            try std.testing.expectEqualStrings(multipart_acceptance.filename, file.filename);
            try std.testing.expectEqualStrings(multipart_acceptance.content_type, file.content_type);
            try std.testing.expect(std.mem.eql(u8, upload_bytes, file.bytes));
        },
        else => return error.TestUnexpectedResult,
    }
}

test "client interop aligns automatic decompression coverage with the shared local contract" {
    const loader = fixture_loader.Loader.init();
    const encoded_payload = try loader.loadHigherLevelAsset(std.testing.allocator, .upload_bin);
    defer std.testing.allocator.free(encoded_payload);

    const decoder = client.Decoder.init(decompression_acceptance.content_encoding);
    var decoded = try decoder.decodeAlloc(std.testing.allocator, encoded_payload);
    defer decoded.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("/download/compressed", decompression_acceptance.path);
    try std.testing.expectEqualStrings("application/octet-stream", decompression_acceptance.content_type);
    try std.testing.expectEqual(client.ContentEncoding.gzip, decoded.content_encoding);
    try std.testing.expect(decoded.transformed);
    try std.testing.expect(std.mem.eql(u8, encoded_payload, decoded.bytes));

    for (client_flow_protocols) |protocol| {
        try expectSupportedCapability(.client_decompression, protocol);
    }
}
