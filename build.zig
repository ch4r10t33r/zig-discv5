const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zig_varint_mod = b.dependency("zig_varint", .{
        .target = target,
        .optimize = optimize,
    }).module("zig_varint");

    const mod = b.addModule("zig_discv5", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addImport("zig_varint", zig_varint_mod);

    const unit_tests = b.addTest(.{
        .name = "zig-discv5-tests",
        .root_module = mod,
    });
    const run_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
