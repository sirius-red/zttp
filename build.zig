const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addModule("zttp", .{
        .root_source_file = b.path("src/lib/zttp.zig"),
        .target = target,
        .optimize = optimize,
    });

    const tls = b.addModule("zttp_tls", .{
        .root_source_file = b.path("src/lib/tls/tls.zig"),
        .target = target,
        .optimize = optimize,
    });
    const http2 = b.addModule("zttp_http2", .{
        .root_source_file = b.path("src/lib/http2/http2.zig"),
        .target = target,
        .optimize = optimize,
    });
    const http3 = b.addModule("zttp_http3", .{
        .root_source_file = b.path("src/lib/http3/http3.zig"),
        .target = target,
        .optimize = optimize,
    });
    const server = b.addModule("zttp_server", .{
        .root_source_file = b.path("src/lib/server/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    const testing = b.addModule("zttp_testing", .{
        .root_source_file = b.path("src/lib/testing/testing.zig"),
        .target = target,
        .optimize = optimize,
    });

    lib.addImport("zttp_tls", tls);
    lib.addImport("zttp_http2", http2);
    lib.addImport("zttp_http3", http3);
    lib.addImport("zttp_server", server);
    lib.addImport("zttp_testing", testing);

    const readiness_smoke = b.addExecutable(.{
        .name = "zttp-readiness-smoke",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lib/testing/readiness_smoke_main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zttp", .module = lib },
            },
        }),
    });

    const cli = b.addExecutable(.{
        .name = "zttp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zttp", .module = lib },
            },
        }),
    });
    b.installArtifact(cli);

    const run_cmd = b.addRunArtifact(cli);
    const run_step = b.step("run", "Run the zttp cli with args passed after --");

    if (b.args) |args| run_cmd.addArgs(args);

    run_cmd.step.dependOn(b.getInstallStep());
    run_step.dependOn(&run_cmd.step);

    const lib_tests = b.addTest(.{ .root_module = lib });
    const run_lib_tests = b.addRunArtifact(lib_tests);
    const cli_tests = b.addTest(.{ .root_module = cli.root_module });
    const run_cli_tests = b.addRunArtifact(cli_tests);
    const run_readiness_smoke = b.addRunArtifact(readiness_smoke);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_cli_tests.step);

    const smoke_step = b.step("smoke", "Run the readiness smoke scenario");
    run_readiness_smoke.step.dependOn(b.getInstallStep());
    smoke_step.dependOn(&run_readiness_smoke.step);

    const test_http3_step = b.step("test-http3", "Run the full test suite including the default HTTP/3 coverage");
    test_http3_step.dependOn(&run_lib_tests.step);
    test_http3_step.dependOn(&run_cli_tests.step);
}
