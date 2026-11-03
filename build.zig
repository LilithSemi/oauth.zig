const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zurl_dep = b.dependency("zurl", .{
        .target = target,
        .optimize = optimize,
    });

    const core = b.addModule("oauth-core", .{
        .root_source_file = b.path("lib/oauth-core.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl", .module = zurl_dep.module("zurl") },
            .{ .name = "zurl-http", .module = zurl_dep.module("zurl-http") },
        },
    });

    const test_step = b.step("test", "Run the test suite");
    addTests(b, test_step, core);

    const mcp = b.addModule("oauth-mcp", .{
        .root_source_file = b.path("lib/oauth-mcp.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "oauth-core", .module = core }},
    });
    addTests(b, test_step, mcp);

    const openai = b.addModule("oauth-openai", .{
        .root_source_file = b.path("lib/oauth-openai.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "oauth-core", .module = core }},
    });
    addTests(b, test_step, openai);

    const github = b.addModule("oauth-github", .{
        .root_source_file = b.path("lib/oauth-github.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "oauth-core", .module = core }},
    });
    addTests(b, test_step, github);

    const anthropic = b.addModule("oauth-anthropic", .{
        .root_source_file = b.path("lib/oauth-anthropic.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "oauth-core", .module = core }},
    });
    addTests(b, test_step, anthropic);
}

fn addTests(b: *std.Build, step: *std.Build.Step, module: *std.Build.Module) void {
    const tests = b.addTest(.{ .root_module = module });
    const run = b.addRunArtifact(tests);
    run.skip_foreign_checks = true;
    step.dependOn(&run.step);
}
