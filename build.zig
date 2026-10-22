const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("cvedex", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "cvedex",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "cvedex", .module = mod },
                .{ .name = "vaxis", .module = b.dependency("vaxis", .{ .target = target, .optimize = optimize }).module("vaxis") },
            },
        }),
    });
    b.installArtifact(exe);

    const test_step = b.step("test", "Run unit and fixture tests");
    // Patched copy of the default runner; see the file header for why and when to drop it.
    const test_runner: std.Build.Step.Compile.TestRunner = .{ .path = b.path("build/test_runner.zig"), .mode = .server };
    const mod_tests = b.addTest(.{ .root_module = mod, .test_runner = test_runner });
    test_step.dependOn(&b.addRunArtifact(mod_tests).step);
    const exe_tests = b.addTest(.{ .root_module = exe.root_module, .test_runner = test_runner });
    test_step.dependOn(&b.addRunArtifact(exe_tests).step);

    const run_step = b.step("run", "Run cvedex");
    const run = b.addRunArtifact(exe);
    if (b.args) |args| run.addArgs(args);
    run_step.dependOn(&run.step);
}
