//! Credentials from `$XDG_CONFIG_HOME/cvedex/config.json` (default `~/.config/cvedex/config.json`),
//! overridden field by field by `CVE_API_URL`, `CVE_API_ORG`, `CVE_API_USER` and `CVE_API_KEY`:
//! the names `cvelib` uses, so existing CNA setups work unchanged.

const std = @import("std");
const builtin = @import("builtin");
const client = @import("client.zig");

const Credentials = client.Credentials;
const Environ = std.process.Environ;

/// Path of the config file. Allocated in `arena`.
pub fn path(arena: std.mem.Allocator, env: *const Environ.Map) ![]const u8 {
    if (env.get("XDG_CONFIG_HOME")) |xdg| if (xdg.len > 0) return std.fs.path.join(arena, &.{ xdg, "cvedex", "config.json" });
    const home = env.get("HOME") orelse env.get("USERPROFILE") orelse return error.NoHomeDirectory;
    return std.fs.path.join(arena, &.{ home, ".config", "cvedex", "config.json" });
}

/// Reads the config file if it exists, then applies environment overrides. Strings borrow from
/// `arena` and `env`.
pub fn load(arena: std.mem.Allocator, io: std.Io, env: *const Environ.Map) !Credentials {
    var creds: Credentials = .{};
    const file = try path(arena, env);
    if (std.Io.Dir.cwd().readFileAlloc(io, file, arena, .limited(64 * 1024))) |json| {
        creds = try std.json.parseFromSliceLeaky(Credentials, arena, json, .{ .ignore_unknown_fields = true });
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    if (env.get("CVE_API_URL")) |v| creds.url = v;
    if (env.get("CVE_API_ORG")) |v| creds.org = v;
    if (env.get("CVE_API_USER")) |v| creds.user = v;
    if (env.get("CVE_API_KEY")) |v| creds.key = v;
    return creds;
}

/// Writes `creds` to the config file, readable by the owner only since it holds the API key.
pub fn save(arena: std.mem.Allocator, io: std.Io, env: *const Environ.Map, creds: Credentials) ![]const u8 {
    const file = try path(arena, env);
    if (std.fs.path.dirname(file)) |dir| try std.Io.Dir.cwd().createDirPath(io, dir);
    const json = try std.json.Stringify.valueAlloc(arena, creds, .{ .whitespace = .indent_2 });
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = file,
        .data = json,
        .flags = .{ .permissions = if (builtin.os.tag == .windows) .default_file else @enumFromInt(0o600) },
    });
    return file;
}

test "env overrides the config file field by field" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try std.fs.path.join(arena.allocator(), &.{ ".zig-cache", "tmp", &tmp.sub_path });

    var env: Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("XDG_CONFIG_HOME", home);
    _ = try save(arena.allocator(), io, &env, .{ .url = "https://cve.acme.org", .org = "acme", .user = "ada", .key = "k1" });
    try env.put("CVE_API_KEY", "k2");

    const creds = try load(arena.allocator(), io, &env);
    try std.testing.expectEqualStrings("https://cve.acme.org", creds.url);
    try std.testing.expectEqualStrings("ada", creds.user);
    try std.testing.expectEqualStrings("k2", creds.key);
}

test "a missing config file falls back to defaults" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var env: Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("XDG_CONFIG_HOME", ".zig-cache/tmp/cvedex-does-not-exist");
    const creds = try load(arena.allocator(), std.testing.io, &env);
    try std.testing.expectEqualStrings(client.default_url, creds.url);
}

test "path needs a home directory" {
    var env: Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try std.testing.expectError(error.NoHomeDirectory, path(std.testing.allocator, &env));
}
