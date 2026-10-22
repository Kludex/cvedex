//! Entry point: `cvedex mcp` serves MCP on stdio, `cvedex tui` opens the TUI, everything else is
//! the CLI.

const std = @import("std");
const cvedex = @import("cvedex");
const cli = @import("cli.zig");
const mcp = @import("mcp.zig");
const tui = @import("tui.zig");

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const permanent = init.arena.allocator();
    const raw_args = try init.minimal.args.toSlice(permanent);
    const args = try permanent.alloc([]const u8, raw_args.len);
    for (raw_args, args) |raw, *arg| arg.* = raw;

    const stdin_buf = try permanent.alloc(u8, mcp.max_frame_len);
    var stdout_buf: [64 * 1024]u8 = undefined;
    var stderr_buf: [4 * 1024]u8 = undefined;
    var stdin = std.Io.File.stdin().reader(io, stdin_buf);
    var stdout = std.Io.File.stdout().writer(io, &stdout_buf);
    var stderr = std.Io.File.stderr().writer(io, &stderr_buf);
    defer stdout.interface.flush() catch {};
    defer stderr.interface.flush() catch {};

    const mode = if (args.len > 1) args[1] else "";
    if (std.mem.eql(u8, mode, "mcp") or std.mem.eql(u8, mode, "tui")) {
        const creds = try cvedex.config.load(permanent, io, init.environ_map);
        var client: cvedex.Client = .init(init.gpa, io, creds);
        defer client.deinit();
        if (mode[0] == 'm') {
            try mcp.serve(init.gpa, &client, &stdin.interface, &stdout.interface);
        } else {
            try tui.run(init.gpa, io, init.environ_map, &client);
        }
        return 0;
    }

    var arena: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena.deinit();
    return cli.run(.{
        .arena = arena.allocator(),
        .io = io,
        .env = init.environ_map,
        .stdin = &stdin.interface,
        .stdout = &stdout.interface,
        .stderr = &stderr.interface,
    }, args[1..]);
}

test {
    _ = cli;
    _ = mcp;
    _ = tui;
}
