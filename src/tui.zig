//! `cvedex tui`: a full-screen view over the same client the CLI uses. Views are the CVE ID list,
//! the record viewer and, against `cvedexd`, the review queue, proposals and audit log. `Model`
//! holds the state and maps keys to actions; `run` performs the actions and draws.

const std = @import("std");
const cvedex = @import("cvedex");
const vaxis = @import("vaxis");

const Client = cvedex.Client;

pub const View = enum {
    ids,
    record,
    review,
    proposals,
    audit,

    fn title(self: View) []const u8 {
        return switch (self) {
            .ids => "CVE IDs",
            .record => "Record",
            .review => "Review queue",
            .proposals => "Proposals",
            .audit => "Audit",
        };
    }
};

pub const Action = union(enum) {
    none,
    quit,
    load: View,
    open: []const u8,
    reserve,
};

pub const Model = struct {
    view: View = .ids,
    /// Lines of the current view, owned by the page arena that `setLines` was given.
    lines: []const []const u8 = &.{},
    /// For the ID list, the CVE ID on each line.
    ids: []const []const u8 = &.{},
    cursor: usize = 0,
    status: []const u8 = "",
    cvedexd: bool = false,

    pub fn update(self: *Model, key: vaxis.Key) Action {
        if (key.matches('c', .{ .ctrl = true }) or key.matches('q', .{})) return .quit;
        if (key.matchesAny(&.{ vaxis.Key.down, 'j' }, .{})) {
            if (self.cursor + 1 < self.lines.len) self.cursor += 1;
        } else if (key.matchesAny(&.{ vaxis.Key.up, 'k' }, .{})) {
            self.cursor -|= 1;
        } else if (key.matches('g', .{})) {
            return .{ .load = if (self.view == .record) .ids else self.view };
        } else if (key.matchesAny(&.{ vaxis.Key.escape, vaxis.Key.backspace }, .{})) {
            if (self.view == .record) return .{ .load = .ids };
        } else if (key.matches(vaxis.Key.enter, .{})) {
            if (self.view == .ids and self.cursor < self.ids.len) return .{ .open = self.ids[self.cursor] };
        } else if (key.matches('r', .{})) {
            if (self.view == .ids) return .reserve;
        } else if (key.matches('1', .{})) {
            return .{ .load = .ids };
        } else if (self.cvedexd) {
            if (key.matches('2', .{})) return .{ .load = .review };
            if (key.matches('3', .{})) return .{ .load = .proposals };
            if (key.matches('4', .{})) return .{ .load = .audit };
        }
        return .none;
    }

    /// Shows `body` in `view`: one line per ID for the ID list, indented JSON otherwise.
    pub fn show(self: *Model, page: std.mem.Allocator, view: View, response: cvedex.Response) !void {
        self.view = view;
        self.cursor = 0;
        self.ids = &.{};
        self.status = if (response.ok()) "" else try std.fmt.allocPrint(page, "HTTP {d}", .{@intFromEnum(response.status)});
        var lines: std.ArrayList([]const u8) = .empty;
        if (view == .ids and response.ok()) {
            const list = try cvedex.record.parseIds(page, response.body);
            const ids = try page.alloc([]const u8, list.cve_ids.len);
            for (list.cve_ids, ids) |id, *out| {
                out.* = id.cve_id;
                try lines.append(page, try std.fmt.allocPrint(page, "{s:<16} {s:<10} {s}", .{ id.cve_id, id.state, id.reserved }));
            }
            self.ids = ids;
        } else {
            const text = if (std.json.parseFromSliceLeaky(std.json.Value, page, response.body, .{})) |value|
                try std.json.Stringify.valueAlloc(page, value, .{ .whitespace = .indent_2 })
            else |_|
                response.body;
            var it = std.mem.splitScalar(u8, text, '\n');
            while (it.next()) |line| try lines.append(page, line);
        }
        self.lines = lines.items;
    }
};

const Event = union(enum) {
    key_press: vaxis.Key,
    winsize: vaxis.Winsize,
};

pub fn run(gpa: std.mem.Allocator, io: std.Io, env: *std.process.Environ.Map, client: *Client) !void {
    var buffer: [4096]u8 = undefined;
    var tty: vaxis.Tty = try .init(io, &buffer);
    defer tty.deinit();
    var vx = try vaxis.init(io, gpa, env, .{});
    defer vx.deinit(gpa, tty.writer());
    var loop: vaxis.Loop(Event) = .init(io, &tty, &vx);
    try loop.start();
    defer loop.stop();
    try vx.enterAltScreen(tty.writer());
    try vx.queryTerminal(tty.writer(), .fromMilliseconds(250));

    var page: std.heap.ArenaAllocator = .init(gpa);
    defer page.deinit();
    var model: Model = .{};
    const health = try client.health(page.allocator());
    const Health = struct { server: []const u8 = "" };
    const info = std.json.parseFromSliceLeaky(Health, page.allocator(), health.body, .{
        .ignore_unknown_fields = true,
    }) catch Health{};
    model.cvedexd = std.mem.eql(u8, info.server, "cvedexd");
    var action: Action = .{ .load = .ids };

    while (true) {
        switch (action) {
            .none => {},
            .quit => return,
            .load, .open, .reserve => {
                _ = page.reset(.retain_capacity);
                const arena = page.allocator();
                const view: View, const response = switch (action) {
                    .load => |v| .{ v, try client.send(arena, .GET, switch (v) {
                        .ids, .record => "/api/cve-id",
                        .review => "/api/cvedexd/review",
                        .proposals => "/api/cvedexd/proposals",
                        .audit => "/api/cvedexd/audit",
                    }, null) },
                    .open => |id| .{ .record, try client.record(arena, id) },
                    .reserve => blk: {
                        const year = currentYear(io);
                        var reserved = try client.reserve(arena, .{ .year = year });
                        if (!reserved.ok()) break :blk .{ .ids, reserved };
                        break :blk .{ .ids, try client.listIds(arena, null) };
                    },
                    else => unreachable,
                };
                try model.show(arena, view, response);
            },
        }
        draw(&vx, &model, client.creds.url);
        try vx.render(tty.writer());
        try tty.writer().flush();
        action = switch (try loop.nextEvent()) {
            .key_press => |key| model.update(key),
            .winsize => |ws| blk: {
                try vx.resize(gpa, tty.writer(), ws);
                break :blk .none;
            },
        };
    }
}

fn draw(vx: *vaxis.Vaxis, model: *const Model, url: []const u8) void {
    const win = vx.window();
    win.clear();
    if (win.height < 3) return;
    const tabs = if (model.cvedexd) "[1] IDs  [2] Review  [3] Proposals  [4] Audit" else "[1] IDs";
    var header_buf: [256]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buf, " cvedex  {s}  {s}  {s}", .{ model.view.title(), tabs, url }) catch header_buf[0..];
    _ = win.printSegment(.{ .text = header, .style = .{ .bold = true, .reverse = true } }, .{ .wrap = .none });

    const body = win.child(.{ .y_off = 1, .height = win.height - 2 });
    const top = if (model.cursor >= body.height) model.cursor - body.height + 1 else 0;
    for (model.lines[@min(top, model.lines.len)..], 0..) |line, i| {
        if (i >= body.height) break;
        const row: u16 = @intCast(i);
        _ = body.printSegment(.{
            .text = line,
            .style = .{ .reverse = top + i == model.cursor and model.view != .record },
        }, .{ .row_offset = row, .wrap = .none });
    }

    const hints = switch (model.view) {
        .ids => "j/k move  enter open  r reserve  g reload  q quit",
        .record => "j/k scroll  esc back  q quit",
        else => "j/k move  g reload  q quit",
    };
    const footer = win.child(.{ .y_off = win.height - 1, .height = 1 });
    _ = footer.printSegment(.{ .text = if (model.status.len > 0) model.status else hints, .style = .{ .dim = true } }, .{ .wrap = .none });
}

fn currentYear(io: std.Io) u16 {
    const now = std.Io.Clock.real.now(io).toSeconds();
    return (std.time.epoch.EpochSeconds{ .secs = @intCast(@max(now, 0)) }).getEpochDay().calculateYearDay().year;
}

test "the ID list opens the record under the cursor" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var model: Model = .{};
    const recorded: cvedex.Upstream.Exchange = try .cassette(arena.allocator(), @embedFile("testdata/recorded/cve-id-list.json"));
    try model.show(arena.allocator(), .ids, .{ .status = .ok, .body = try arena.allocator().dupe(u8, recorded.body) });
    try std.testing.expectEqual(2, model.lines.len);
    try std.testing.expectEqual(Action.none, model.update(.{ .codepoint = 'j' }));
    try std.testing.expectEqual(Action.none, model.update(.{ .codepoint = 'j' }));
    try std.testing.expectEqual(1, model.cursor);
    const action = model.update(.{ .codepoint = vaxis.Key.enter });
    try std.testing.expectEqualStrings("CVE-2026-1100", action.open);
}

test "cvedexd views are only reachable against cvedexd" {
    var model: Model = .{};
    try std.testing.expectEqual(Action.none, model.update(.{ .codepoint = '2' }));
    model.cvedexd = true;
    try std.testing.expectEqual(View.review, model.update(.{ .codepoint = '2' }).load);
}

test "an error response shows the status and body" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var model: Model = .{};
    var body = "{\"error\":\"UNAUTHORIZED\"}".*;
    try model.show(arena.allocator(), .ids, .{ .status = .unauthorized, .body = &body });
    try std.testing.expectEqualStrings("HTTP 401", model.status);
    try std.testing.expectEqualStrings("  \"error\": \"UNAUTHORIZED\"", model.lines[1]);
}
