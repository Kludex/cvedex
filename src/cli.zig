//! The `cvedex` command line. Each command maps to one or two CVE Services calls. Bodies from
//! upstream are printed verbatim with `--json`, pretty-printed otherwise; an upstream error body
//! goes to stderr and the exit code is 1. Commands that only `cvedexd` serves check
//! `GET /api/health-check` first and refuse against a plain CVE Services URL.

const std = @import("std");
const cvedex = @import("cvedex");

const Client = cvedex.Client;
const Response = cvedex.Response;
const Escaped = cvedex.Escaped;
const Writer = std.Io.Writer;

pub const Context = struct {
    /// Freed by the caller when the command returns.
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    stdin: *std.Io.Reader,
    stdout: *Writer,
    stderr: *Writer,
};

pub const usage =
    \\usage: cvedex <command> [options]
    \\
    \\  login [--url U] [--org O] [--user U] [--key K]
    \\  reserve [--year Y] [--count N] [--sequential]
    \\  list [--state RESERVED|PUBLISHED|REJECTED]
    \\  show <CVE-ID> [--raw]
    \\  publish <CVE-ID> <record.json>
    \\  update <CVE-ID> <record.json>
    \\  reject <CVE-ID> <record.json>
    \\  org show | org users | org user add <username> [--first F] [--last L] [--role ADMIN]
    \\  org user reset-key <username>
    \\  ping
    \\  mcp                                  MCP server on stdio
    \\  tui                                  full-screen interface
    \\
    \\cvedexd only:
    \\  review | approve <CVE-ID> | request-changes <CVE-ID> <note>
    \\  proposals [approve|deny <proposal-id>]
    \\  audit [--user U] [--since DATE]
    \\  submitter add <name> | submitter token new <submitter-id> [--agent]
    \\
    \\Every command takes --json and --url. Credentials come from `cvedex login` or
    \\CVE_API_URL, CVE_API_ORG, CVE_API_USER, CVE_API_KEY.
    \\
;

const Command = enum {
    login,
    reserve,
    list,
    show,
    publish,
    update,
    reject,
    org,
    ping,
    review,
    approve,
    @"request-changes",
    proposals,
    audit,
    submitter,
    help,
    @"--help",
};

const boolean_flags = [_][]const u8{ "json", "raw", "sequential", "agent" };

/// Runs one command and returns the process exit code.
pub fn run(ctx: Context, argv: []const []const u8) !u8 {
    const args = Args.parse(ctx.arena, argv) catch |err| return fail(ctx, "{s}", .{@errorName(err)});
    if (args.positional.len == 0) {
        try ctx.stderr.writeAll(usage);
        return 2;
    }
    const command = std.meta.stringToEnum(Command, args.positional[0]) orelse
        return fail(ctx, "unknown command '{s}'\n\n{s}", .{ args.positional[0], usage });

    var creds = cvedex.config.load(ctx.arena, ctx.io, ctx.env) catch |err| return fail(ctx, "config: {s}", .{@errorName(err)});
    if (args.get("url")) |url| creds.url = url;
    var client: Client = .init(ctx.arena, ctx.io, creds);
    defer client.deinit();
    var cmd: Cmd = .{ .ctx = ctx, .args = args, .client = &client };
    return cmd.dispatch(command, args.positional[1..]) catch |err| switch (err) {
        error.MissingArgument => 2,
        else => fail(ctx, "{s}", .{@errorName(err)}),
    };
}

fn fail(ctx: Context, comptime fmt: []const u8, args: anytype) !u8 {
    try ctx.stderr.print("cvedex: " ++ fmt ++ "\n", args);
    return 1;
}

const Cmd = struct {
    ctx: Context,
    args: Args,
    client: *Client,

    fn dispatch(self: *Cmd, command: Command, rest: []const []const u8) !u8 {
        return switch (command) {
            .help, .@"--help" => {
                try self.ctx.stdout.writeAll(usage);
                return 0;
            },
            .login => self.login(),
            .reserve => self.reserve(),
            .list => self.list(),
            .show => self.show(try self.arg(rest, 0, "CVE-ID")),
            .publish => self.writeRecord(.POST, try self.arg(rest, 0, "CVE-ID"), try self.arg(rest, 1, "record.json")),
            .update => self.writeRecord(.PUT, try self.arg(rest, 0, "CVE-ID"), try self.arg(rest, 1, "record.json")),
            .reject => self.reject(try self.arg(rest, 0, "CVE-ID"), try self.arg(rest, 1, "record.json")),
            .org => self.org(rest),
            .ping => self.ping(),
            .review, .approve, .@"request-changes", .proposals, .audit, .submitter => self.cvedexd(command, rest),
        };
    }

    fn arg(self: *Cmd, rest: []const []const u8, index: usize, name: []const u8) ![]const u8 {
        if (index < rest.len) return rest[index];
        try self.ctx.stderr.print("cvedex: missing <{s}>\n\n{s}", .{ name, usage });
        return error.MissingArgument;
    }

    fn login(self: *Cmd) !u8 {
        var creds = self.client.creds;
        creds.url = self.args.get("url") orelse try self.prompt("CVE Services URL", creds.url);
        creds.org = self.args.get("org") orelse try self.prompt("Organization short name", creds.org);
        creds.user = self.args.get("user") orelse try self.prompt("Username", creds.user);
        creds.key = self.args.get("key") orelse try self.prompt("API key", "");
        self.client.creds = creds;
        var response = try self.client.sendFmt(self.ctx.arena, .GET, "/api/org/{f}/user/{f}", .{
            Escaped{ .raw = creds.org },
            Escaped{ .raw = creds.user },
        }, null);
        if (!response.ok()) return self.emit(&response);
        const path = try cvedex.config.save(self.ctx.arena, self.ctx.io, self.ctx.env, creds);
        try self.ctx.stdout.print("Logged in as {s} ({s}). Saved to {s}\n", .{ creds.user, creds.org, path });
        return 0;
    }

    fn prompt(self: *Cmd, label: []const u8, current: []const u8) ![]const u8 {
        if (current.len > 0) {
            try self.ctx.stderr.print("{s} [{s}]: ", .{ label, current });
        } else {
            try self.ctx.stderr.print("{s}: ", .{label});
        }
        try self.ctx.stderr.flush();
        const line = self.ctx.stdin.takeDelimiter('\n') catch |err| switch (err) {
            error.StreamTooLong => return error.InputTooLong,
            else => |e| return e,
        } orelse "";
        const value = std.mem.trim(u8, line, " \t\r");
        return if (value.len > 0) try self.ctx.arena.dupe(u8, value) else current;
    }

    fn reserve(self: *Cmd) !u8 {
        const year = if (self.args.get("year")) |y| try std.fmt.parseInt(u16, y, 10) else currentYear(self.ctx.io);
        const count = if (self.args.get("count")) |c| try std.fmt.parseInt(u32, c, 10) else 1;
        var response = try self.client.reserve(self.ctx.arena, .{
            .year = year,
            .count = count,
            .sequential = self.args.has("sequential"),
        });
        if (!response.ok() or self.args.has("json")) return self.emit(&response);
        return self.printIds(response.body);
    }

    fn list(self: *Cmd) !u8 {
        var response = try self.client.listIds(self.ctx.arena, self.args.get("state"));
        if (!response.ok() or self.args.has("json")) return self.emit(&response);
        return self.printIds(response.body);
    }

    fn printIds(self: *Cmd, body: []const u8) !u8 {
        const ids = try cvedex.record.parseIds(self.ctx.arena, body);
        for (ids.cve_ids) |id| try self.ctx.stdout.print("{s}\t{s}\t{s}\n", .{ id.cve_id, id.state, id.reserved });
        return 0;
    }

    fn show(self: *Cmd, id: []const u8) !u8 {
        var response = try self.client.record(self.ctx.arena, id);
        if (self.args.has("raw")) {
            try self.ctx.stdout.writeAll(response.body);
            return if (response.ok()) 0 else 1;
        }
        return self.emit(&response);
    }

    fn writeRecord(self: *Cmd, method: std.http.Method, id: []const u8, file: []const u8) !u8 {
        const payload = try self.readRecord(file);
        var response = try self.client.writeRecord(self.ctx.arena, method, id, payload);
        return self.emit(&response);
    }

    fn reject(self: *Cmd, id: []const u8, file: []const u8) !u8 {
        const payload = try self.readRecord(file);
        var response = try self.client.reject(self.ctx.arena, id, payload);
        return self.emit(&response);
    }

    fn readRecord(self: *Cmd, file: []const u8) ![]const u8 {
        const json = try std.Io.Dir.cwd().readFileAlloc(self.ctx.io, file, self.ctx.arena, .limited(4 * 1024 * 1024));
        return cvedex.record.cnaPayload(self.ctx.arena, json);
    }

    fn org(self: *Cmd, rest: []const []const u8) !u8 {
        const arena = self.ctx.arena;
        const org_name: Escaped = .{ .raw = self.client.creds.org };
        const sub = try self.arg(rest, 0, "show|users|user");
        var response: Response = if (std.mem.eql(u8, sub, "show"))
            try self.client.sendFmt(arena, .GET, "/api/org/{f}", .{org_name}, null)
        else if (std.mem.eql(u8, sub, "users"))
            try self.client.sendFmt(arena, .GET, "/api/org/{f}/users", .{org_name}, null)
        else if (std.mem.eql(u8, sub, "user")) blk: {
            const action = try self.arg(rest, 1, "add|reset-key");
            const username = try self.arg(rest, 2, "username");
            if (std.mem.eql(u8, action, "add")) {
                const role = self.args.get("role");
                const body = try std.json.Stringify.valueAlloc(arena, .{
                    .username = username,
                    .name = .{ .first = self.args.get("first") orelse "", .last = self.args.get("last") orelse "" },
                    .authority = .{ .active_roles = if (role) |r| &[_][]const u8{r} else &[_][]const u8{} },
                }, .{});
                break :blk try self.client.sendFmt(arena, .POST, "/api/org/{f}/user", .{org_name}, body);
            } else if (std.mem.eql(u8, action, "reset-key")) {
                break :blk try self.client.sendFmt(arena, .PUT, "/api/org/{f}/user/{f}/reset_secret", .{
                    org_name,
                    Escaped{ .raw = username },
                }, null);
            } else return fail(self.ctx, "unknown org user action '{s}'", .{action});
        } else return fail(self.ctx, "unknown org command '{s}'", .{sub});
        return self.emit(&response);
    }

    fn ping(self: *Cmd) !u8 {
        var response = try self.client.health(self.ctx.arena);
        if (!response.ok() or self.args.has("json")) return self.emit(&response);
        const server = try serverInfo(self.ctx.arena, response.body);
        if (server.isCvedexd()) {
            try self.ctx.stdout.print("ok: {s} (cvedexd {s})\n", .{ self.client.creds.url, server.version });
        } else {
            try self.ctx.stdout.print("ok: {s}\n", .{self.client.creds.url});
        }
        return 0;
    }

    fn cvedexd(self: *Cmd, command: Command, rest: []const []const u8) !u8 {
        const arena = self.ctx.arena;
        var health = try self.client.health(arena);
        if (!health.ok()) return self.emit(&health);
        if (!(try serverInfo(arena, health.body)).isCvedexd()) {
            return fail(self.ctx, "'{s}' needs a cvedexd server; {s} is plain CVE Services", .{
                @tagName(command),
                self.client.creds.url,
            });
        }
        var response: Response = switch (command) {
            .review => try self.client.send(arena, .GET, "/api/cvedexd/review", null),
            .approve => try self.client.sendFmt(arena, .POST, "/api/cvedexd/cve/{f}/approve", .{
                Escaped{ .raw = try self.arg(rest, 0, "CVE-ID") },
            }, null),
            .@"request-changes" => try self.client.sendFmt(arena, .POST, "/api/cvedexd/cve/{f}/request-changes", .{
                Escaped{ .raw = try self.arg(rest, 0, "CVE-ID") },
            }, try std.json.Stringify.valueAlloc(arena, .{ .note = try self.arg(rest, 1, "note") }, .{})),
            .proposals => if (rest.len == 0)
                try self.client.send(arena, .GET, "/api/cvedexd/proposals", null)
            else blk: {
                const action = rest[0];
                if (!std.mem.eql(u8, action, "approve") and !std.mem.eql(u8, action, "deny")) {
                    return fail(self.ctx, "unknown proposals action '{s}'", .{action});
                }
                break :blk try self.client.sendFmt(arena, .POST, "/api/cvedexd/proposals/{f}/{s}", .{
                    Escaped{ .raw = try self.arg(rest, 1, "proposal-id") },
                    action,
                }, null);
            },
            .audit => blk: {
                var target: Writer.Allocating = .init(arena);
                try target.writer.writeAll("/api/cvedexd/audit");
                var sep: u8 = '?';
                for ([_][]const u8{ "user", "since" }) |name| if (self.args.get(name)) |value| {
                    try target.writer.print("{c}{s}={f}", .{ sep, name, Escaped{ .raw = value } });
                    sep = '&';
                };
                break :blk try self.client.send(arena, .GET, target.written(), null);
            },
            .submitter => blk: {
                const sub = try self.arg(rest, 0, "add|token");
                if (std.mem.eql(u8, sub, "add")) {
                    const body = try std.json.Stringify.valueAlloc(arena, .{ .name = try self.arg(rest, 1, "name") }, .{});
                    break :blk try self.client.send(arena, .POST, "/api/cvedexd/submitters", body);
                } else if (std.mem.eql(u8, sub, "token")) {
                    _ = try self.arg(rest, 1, "new");
                    const kind = if (self.args.has("agent")) "agent" else "user";
                    break :blk try self.client.sendFmt(arena, .POST, "/api/cvedexd/submitters/{f}/tokens", .{
                        Escaped{ .raw = try self.arg(rest, 2, "submitter-id") },
                    }, try std.json.Stringify.valueAlloc(arena, .{ .kind = kind }, .{}));
                } else return fail(self.ctx, "unknown submitter command '{s}'", .{sub});
            },
            else => unreachable, // `run` only routes the cvedexd commands here
        };
        return self.emit(&response);
    }

    /// Prints a response: the body verbatim with `--json` or when it is not JSON, indented
    /// otherwise. Error bodies go to stderr.
    fn emit(self: *Cmd, response: *const Response) !u8 {
        const out = if (response.ok()) self.ctx.stdout else self.ctx.stderr;
        const body = std.mem.trimEnd(u8, response.body, "\n");
        if (self.args.has("json") or body.len == 0) {
            try out.writeAll(body);
        } else if (std.json.parseFromSliceLeaky(std.json.Value, self.ctx.arena, body, .{})) |value| {
            try std.json.Stringify.value(value, .{ .whitespace = .indent_2 }, out);
        } else |_| {
            try out.writeAll(body);
        }
        if (body.len > 0) try out.writeByte('\n');
        return if (response.ok()) 0 else 1;
    }
};

const ServerInfo = struct {
    server: []const u8 = "",
    version: []const u8 = "",

    fn isCvedexd(self: ServerInfo) bool {
        return std.mem.eql(u8, self.server, "cvedexd");
    }
};

/// Reads `GET /api/health-check`. CVE Services answers with an empty body.
fn serverInfo(arena: std.mem.Allocator, body: []const u8) !ServerInfo {
    return std.json.parseFromSliceLeaky(ServerInfo, arena, body, .{ .ignore_unknown_fields = true }) catch .{};
}

fn currentYear(io: std.Io) u16 {
    const now = std.Io.Clock.real.now(io).toSeconds();
    const day = (std.time.epoch.EpochSeconds{ .secs = @intCast(@max(now, 0)) }).getEpochDay();
    return day.calculateYearDay().year;
}

const Args = struct {
    positional: []const []const u8,
    flags: std.StringHashMapUnmanaged([]const u8),

    fn parse(arena: std.mem.Allocator, argv: []const []const u8) !Args {
        var positional: std.ArrayList([]const u8) = .empty;
        var flags: std.StringHashMapUnmanaged([]const u8) = .empty;
        var i: usize = 0;
        while (i < argv.len) : (i += 1) {
            const a = argv[i];
            if (!std.mem.startsWith(u8, a, "--") or a.len == 2) {
                try positional.append(arena, a);
                continue;
            }
            const name = a[2..];
            if (std.mem.indexOfScalar(u8, name, '=')) |eq| {
                try flags.put(arena, name[0..eq], name[eq + 1 ..]);
            } else if (isBoolean(name)) {
                try flags.put(arena, name, "");
            } else if (i + 1 < argv.len) {
                i += 1;
                try flags.put(arena, name, argv[i]);
            } else return error.FlagNeedsValue;
        }
        return .{ .positional = positional.items, .flags = flags };
    }

    fn isBoolean(name: []const u8) bool {
        for (boolean_flags) |b| if (std.mem.eql(u8, b, name)) return true;
        return false;
    }

    fn get(self: Args, name: []const u8) ?[]const u8 {
        return self.flags.get(name);
    }

    fn has(self: Args, name: []const u8) bool {
        return self.flags.contains(name);
    }
};

const Upstream = cvedex.Upstream;

const Run = struct {
    code: u8,
    stdout: []const u8,
    stderr: []const u8,
};

/// Runs `argv` against `exchanges` with credentials from the environment only.
fn runAgainst(arena: std.mem.Allocator, exchanges: []const Upstream.Exchange, argv: []const []const u8, stdin: []const u8) !Run {
    const io = std.testing.io;
    var upstream: Upstream = try .start(io, exchanges);
    defer upstream.deinit(io);
    var url_buf: [64]u8 = undefined;
    var env: std.process.Environ.Map = .init(arena);
    try env.put("XDG_CONFIG_HOME", ".zig-cache/tmp/cvedex-cli-tests");
    try env.put("CVE_API_URL", upstream.url(&url_buf));
    try env.put("CVE_API_ORG", "acme");
    try env.put("CVE_API_USER", "ada@acme.org");
    try env.put("CVE_API_KEY", "k");
    var in: std.Io.Reader = .fixed(stdin);
    var out: Writer.Allocating = .init(arena);
    var err: Writer.Allocating = .init(arena);
    const code = try run(.{
        .arena = arena,
        .io = io,
        .env = &env,
        .stdin = &in,
        .stdout = &out.writer,
        .stderr = &err.writer,
    }, argv);
    try upstream.finish(io);
    return .{ .code = code, .stdout = out.written(), .stderr = err.written() };
}

test "reserve prints one line per reserved id" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const recorded: Upstream.Exchange = try .cassette(arena.allocator(), @embedFile("testdata/recorded/reserve.json"));
    const r = try runAgainst(arena.allocator(), &.{recorded}, &.{ "reserve", "--year", "2026", "--count", "1" }, "");
    try std.testing.expectEqual(0, r.code);
    try std.testing.expectEqualStrings("CVE-2026-1100\tRESERVED\t2026-10-22T20:57:46.961Z\n", r.stdout);
}

test "list --json prints the body verbatim, newline-terminated" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var recorded: Upstream.Exchange = try .cassette(arena.allocator(), @embedFile("testdata/recorded/cve-id-list.json"));
    recorded.target = "/api/cve-id?state=PUBLISHED";
    const r = try runAgainst(arena.allocator(), &.{recorded}, &.{ "list", "--state", "PUBLISHED", "--json" }, "");
    try std.testing.expectEqual(0, r.code);
    try std.testing.expectEqualStrings(try std.mem.concat(arena.allocator(), u8, &.{ recorded.body, "\n" }), r.stdout);
}

test "an upstream error goes to stderr with exit code 1" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const recorded: Upstream.Exchange = try .cassette(arena.allocator(), @embedFile("testdata/recorded/cve-record-dne.json"));
    const r = try runAgainst(arena.allocator(), &.{recorded}, &.{ "show", "CVE-2021-44228", "--json" }, "");
    try std.testing.expectEqual(1, r.code);
    try std.testing.expectEqualStrings("", r.stdout);
    try std.testing.expectEqualStrings(try std.mem.concat(arena.allocator(), u8, &.{ recorded.body, "\n" }), r.stderr);
}

test "show pretty-prints a published record" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const r = try runAgainst(arena.allocator(), &.{
        try .cassette(arena.allocator(), @embedFile("testdata/recorded/cve-2025-0001.json")),
    }, &.{ "show", "CVE-2025-0001" }, "");
    try std.testing.expectEqual(0, r.code);
    try std.testing.expect(std.mem.startsWith(u8, r.stdout, "{\n  \"dataType\": \"CVE_RECORD\",\n"));
}

test "publish wraps a bare CNA container" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const container = std.mem.trim(u8, @embedFile("testdata/cna_container.json"), "\n");
    const r = try runAgainst(arena.allocator(), &.{.{
        .method = .POST,
        .target = "/api/cve/CVE-2025-0001/cna",
        .expect_body = try std.fmt.allocPrint(arena.allocator(), "{{\"cnaContainer\":{s}}}", .{container}),
        .body = "{\"message\":\"ok\"}",
    }}, &.{ "publish", "CVE-2025-0001", "src/testdata/cna_container.json" }, "");
    try std.testing.expectEqual(0, r.code);
    try std.testing.expectEqualStrings("{\n  \"message\": \"ok\"\n}\n", r.stdout);
}

test "ping reports a cvedexd server" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const r = try runAgainst(arena.allocator(), &.{
        .{ .method = .GET, .target = "/api/health-check", .body = @embedFile("testdata/health_cvedexd.json") },
    }, &.{"ping"}, "");
    try std.testing.expectEqual(0, r.code);
    try std.testing.expect(std.mem.endsWith(u8, r.stdout, "(cvedexd 0.1.0)\n"));
}

test "cvedexd commands refuse a plain CVE Services server" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const r = try runAgainst(arena.allocator(), &.{
        try .cassette(arena.allocator(), @embedFile("testdata/recorded/health-check.json")),
    }, &.{"review"}, "");
    try std.testing.expectEqual(1, r.code);
    try std.testing.expect(std.mem.indexOf(u8, r.stderr, "needs a cvedexd server") != null);
}

test "request-changes sends the note" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const r = try runAgainst(arena.allocator(), &.{
        .{ .method = .GET, .target = "/api/health-check", .body = @embedFile("testdata/health_cvedexd.json") },
        .{
            .method = .POST,
            .target = "/api/cvedexd/cve/CVE-2025-0001/request-changes",
            .expect_body = "{\"note\":\"add a CWE\"}",
            .body = "{\"state\":\"reserved\"}",
        },
    }, &.{ "request-changes", "CVE-2025-0001", "add a CWE" }, "");
    try std.testing.expectEqual(0, r.code);
}

test "audit encodes its filters" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const r = try runAgainst(arena.allocator(), &.{
        .{ .method = .GET, .target = "/api/health-check", .body = @embedFile("testdata/health_cvedexd.json") },
        .{ .method = .GET, .target = "/api/cvedexd/audit?user=ada%40acme.org&since=2025-01-01", .body = "[]" },
    }, &.{ "audit", "--user", "ada@acme.org", "--since=2025-01-01" }, "");
    try std.testing.expectEqual(0, r.code);
}

test "login verifies credentials before saving them" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var recorded: Upstream.Exchange = try .cassette(arena.allocator(), @embedFile("testdata/recorded/unauthorized.json"));
    recorded.expect_user = "ada";
    const r = try runAgainst(arena.allocator(), &.{recorded}, &.{ "login", "--user", "ada" }, "\n\nsecret\n");
    try std.testing.expectEqual(1, r.code);
}

test "a missing argument prints usage and exits 2" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const r = try runAgainst(arena.allocator(), &.{}, &.{"show"}, "");
    try std.testing.expectEqual(2, r.code);
    try std.testing.expect(std.mem.startsWith(u8, r.stderr, "cvedex: missing <CVE-ID>"));
}

test "an unknown command exits 1" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const r = try runAgainst(arena.allocator(), &.{}, &.{"frobnicate"}, "");
    try std.testing.expectEqual(1, r.code);
}

test "each command sends its CVE Services request" {
    const health: Upstream.Exchange = .{
        .method = .GET,
        .target = "/api/health-check",
        .body = @embedFile("testdata/health_cvedexd.json"),
    };
    const Case = struct { argv: []const []const u8, exchanges: []const Upstream.Exchange };
    const cases = [_]Case{
        .{ .argv = &.{ "org", "show" }, .exchanges = &.{.{ .method = .GET, .target = "/api/org/acme", .body = "{}" }} },
        .{ .argv = &.{ "org", "users" }, .exchanges = &.{.{ .method = .GET, .target = "/api/org/acme/users", .body = "{}" }} },
        .{ .argv = &.{ "org", "user", "add", "bob@acme.org", "--first", "Bob", "--role", "ADMIN" }, .exchanges = &.{.{
            .method = .POST,
            .target = "/api/org/acme/user",
            .expect_body = "{\"username\":\"bob@acme.org\",\"name\":{\"first\":\"Bob\",\"last\":\"\"},\"authority\":{\"active_roles\":[\"ADMIN\"]}}",
            .body = "{}",
        }} },
        .{ .argv = &.{ "org", "user", "reset-key", "bob@acme.org" }, .exchanges = &.{
            .{ .method = .PUT, .target = "/api/org/acme/user/bob%40acme.org/reset_secret", .body = "{}" },
        } },
        .{ .argv = &.{ "update", "CVE-2025-0001", "src/testdata/cna_container.json" }, .exchanges = &.{
            .{ .method = .PUT, .target = "/api/cve/CVE-2025-0001/cna", .body = "{}" },
        } },
        .{ .argv = &.{ "reject", "CVE-2025-0001", "src/testdata/cna_container.json" }, .exchanges = &.{
            .{ .method = .POST, .target = "/api/cve/CVE-2025-0001/reject", .body = "{}" },
        } },
        .{ .argv = &.{"review"}, .exchanges = &.{ health, .{ .method = .GET, .target = "/api/cvedexd/review", .body = "{}" } } },
        .{ .argv = &.{ "approve", "CVE-2025-0001" }, .exchanges = &.{
            health,
            .{ .method = .POST, .target = "/api/cvedexd/cve/CVE-2025-0001/approve", .body = "{}" },
        } },
        .{ .argv = &.{"proposals"}, .exchanges = &.{ health, .{ .method = .GET, .target = "/api/cvedexd/proposals", .body = "{}" } } },
        .{ .argv = &.{ "proposals", "deny", "p1" }, .exchanges = &.{
            health,
            .{ .method = .POST, .target = "/api/cvedexd/proposals/p1/deny", .body = "{}" },
        } },
        .{ .argv = &.{ "submitter", "add", "sam" }, .exchanges = &.{
            health,
            .{ .method = .POST, .target = "/api/cvedexd/submitters", .expect_body = "{\"name\":\"sam\"}", .body = "{}" },
        } },
        .{ .argv = &.{ "submitter", "token", "new", "7", "--agent" }, .exchanges = &.{
            health,
            .{ .method = .POST, .target = "/api/cvedexd/submitters/7/tokens", .expect_body = "{\"kind\":\"agent\"}", .body = "{}" },
        } },
    };
    for (cases) |case| {
        var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena.deinit();
        const r = try runAgainst(arena.allocator(), case.exchanges, case.argv, "");
        std.testing.expectEqual(0, r.code) catch |err| {
            std.debug.print("{s}: {s}\n", .{ case.argv[0], r.stderr });
            return err;
        };
    }
}

test "unknown subcommands are rejected without a request" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const r = try runAgainst(arena.allocator(), &.{}, &.{ "org", "frobnicate" }, "");
    try std.testing.expectEqual(1, r.code);
    try std.testing.expectEqualStrings("cvedex: unknown org command 'frobnicate'\n", r.stderr);
}
