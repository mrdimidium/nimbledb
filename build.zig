const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_module = b.addModule("nimbledb", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/root.zig"),
    });
    const cli_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/main.zig"),
        .imports = &.{.{ .name = "nimbledb", .module = lib_module }},
    });

    const exe = b.addExecutable(.{
        .name = "nimbledb",
        .root_module = cli_module,
    });
    b.installArtifact(exe);

    const lib_tests = b.addTest(.{ .root_module = lib_module });
    const run_mod_tests = b.addRunArtifact(lib_tests);

    const cli_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(cli_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
