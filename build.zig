const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addModule("zttp", .{
        .root_source_file = b.path("lib/zttp.zig"),
        .target = target,
        .optimize = optimize,
    });

    const cli = b.addExecutable(.{
        .name = "zttp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/main.zig"),
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
    const cli_tests = b.addTest(.{ .root_module = cli.root_module });

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&lib_tests.step);
    test_step.dependOn(&cli_tests.step);
}
