const std = @import("std");
const config = @import("config");

const Step = std.Build.Step;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.addModule("nimbledb", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const static_lib: ?*Step.Compile = b.addStaticLibrary(.{
        .name = "nimbledb",
        .root_module = lib_mod,
        .root_source_file = b.path("src/api_c.zig"),
        .link_libc = true,
    });

    const shared_lib: ?*Step.Compile = b.addSharedLibrary(.{
        .name = "nimbledb",
        .root_module = lib_mod,
        .root_source_file = b.path("src/api_c.zig"),
    });

    const c_header = b.addInstallFileWithDir(b.path("include/nimbledb/nimbledb.h"), .header, "nimbledb/nimbledb.h");

    const pc: *Step.InstallFile = pc: {
        const file = b.addWriteFile("nimbledb.pc", b.fmt(
            \\prefix={s}
            \\includedir=${{prefix}}/include
            \\libdir=${{prefix}}/lib
            \\
            \\Name: nimbledb
            \\URL: https://github.com/mrdimidium/NimbleDB
            \\Description: High-performance, cross-platform event loop
            \\Version: 0.1.0
            \\Cflags: -I${{includedir}}
            \\Libs: -L${{libdir}} -lnimbledb
        , .{b.install_prefix}));

        break :pc b.addInstallFileWithDir(file.getDirectory().path(b, "nimbledb.pc"), .prefix, "share/pkgconfig/nimbledb.pc");
    };

    if (static_lib) |v| {
        b.installArtifact(v);
    }
    if (shared_lib) |v| {
        b.installArtifact(v);
    }

    b.getInstallStep().dependOn(&c_header.step);
    b.getInstallStep().dependOn(&pc.step);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const lib_unit_tests = b.addTest(.{
        .name = "nibmledb-test",
        .root_module = lib_mod,
        .target = target,
        .optimize = optimize,
    });

    const test_artifact = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_artifact.step);
}
