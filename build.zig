const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const http3_enabled = b.option(bool, "http3", "Enable experimental HTTP/3 support") orelse false;

    const zttp_build_options = b.addOptions();
    zttp_build_options.addOption(bool, "http3", http3_enabled);
    const zttp_build_options_module = zttp_build_options.createModule();

    const lib = b.addModule("zttp", .{
        .root_source_file = b.path("lib/zttp.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib.addImport("zttp_build_options", zttp_build_options_module);

    const tls = b.addModule("zttp_tls", .{
        .root_source_file = b.path("lib/tls/tls.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zttp_build_options", .module = zttp_build_options_module },
        },
    });
    const http2 = b.addModule("zttp_http2", .{
        .root_source_file = b.path("lib/http2/http2.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zttp_build_options", .module = zttp_build_options_module },
        },
    });
    const server = b.addModule("zttp_server", .{
        .root_source_file = b.path("lib/server/server.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zttp_build_options", .module = zttp_build_options_module },
        },
    });
    const http3 = b.addModule("zttp_http3", .{
        .root_source_file = b.path("lib/http3/http3.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zttp_build_options", .module = zttp_build_options_module },
        },
    });
    const testing = b.addModule("zttp_testing", .{
        .root_source_file = b.path("lib/testing/testing.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zttp_build_options", .module = zttp_build_options_module },
        },
    });

    lib.addImport("zttp_tls", tls);
    lib.addImport("zttp_http2", http2);
    lib.addImport("zttp_server", server);
    lib.addImport("zttp_http3", http3);
    lib.addImport("zttp_testing", testing);

    const cli = b.addExecutable(.{
        .name = "zttp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zttp", .module = lib },
                .{ .name = "zttp_build_options", .module = zttp_build_options_module },
            },
        }),
    });
    b.installArtifact(cli);

    const example_client_get = b.addExecutable(.{
        .name = "zttp-client-get",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/client_get.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zttp", .module = lib },
                .{ .name = "zttp_build_options", .module = zttp_build_options_module },
            },
        }),
    });
    b.installArtifact(example_client_get);

    const run_cmd = b.addRunArtifact(cli);
    const run_step = b.step("run", "Run the zttp cli with args passed after --");

    if (b.args) |args| run_cmd.addArgs(args);

    run_cmd.step.dependOn(b.getInstallStep());
    run_step.dependOn(&run_cmd.step);

    const lib_tests = b.addTest(.{ .root_module = lib });
    const cli_tests = b.addTest(.{ .root_module = cli.root_module });

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&lib_tests.step);
    test_step.dependOn(&cli_tests.step);

    const test_http3_step = b.step("test-http3", "Run the HTTP/3-enabled test suite when built with -Dhttp3=true");
    test_http3_step.dependOn(&lib_tests.step);
    test_http3_step.dependOn(&cli_tests.step);
}
