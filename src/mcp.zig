//! MCP server on stdio: newline-delimited JSON-RPC 2.0. Tools map 1:1 to CLI commands and return
//! the upstream body as text. Against `cvedexd` with an agent token, writes come back as
//! `202 {proposal_id}`; that is reported as `pending_approval` so the agent knows a human decides.

const std = @import("std");
const cvedex = @import("cvedex");

const Client = cvedex.Client;
const Value = std.json.Value;

pub const protocol_version = "2025-06-18";

/// Longest accepted frame. A record is rarely past a few KiB; this leaves room without letting a
/// peer grow memory without bound.
pub const max_frame_len = 4 * 1024 * 1024;

/// Serves frames from `in` until end of stream.
pub fn serve(gpa: std.mem.Allocator, client: *Client, in: *std.Io.Reader, out: *std.Io.Writer) !void {
    while (true) {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const line = in.takeDelimiter('\n') catch |err| switch (err) {
            error.StreamTooLong => {
                _ = try in.discardDelimiterInclusive('\n');
                try out.writeAll(frame_too_long);
                try out.flush();
                continue;
            },
            else => |e| return e,
        } orelse return;
        if (try handle(arena.allocator(), client, line)) |frame| {
            try out.writeAll(frame);
            try out.writeByte('\n');
            try out.flush();
        }
    }
}

const parse_error = -32700;
const invalid_request = -32600;
const method_not_found = -32601;
const invalid_params = -32602;

const frame_too_long = std.fmt.comptimePrint(
    "{{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{{\"code\":{d},\"message\":\"frame too long\"}}}}\n",
    .{invalid_request},
);

/// Handles one frame and returns the response frame, or null for a notification.
pub fn handle(arena: std.mem.Allocator, client: *Client, line: []const u8) !?[]const u8 {
    const trimmed = std.mem.trim(u8, line, " \t\r");
    if (trimmed.len == 0) return null;
    const msg = std.json.parseFromSliceLeaky(Value, arena, trimmed, .{}) catch
        return try errorFrameAlloc(arena, .null, parse_error, "parse error");
    if (msg != .object) return try errorFrameAlloc(arena, .null, invalid_request, "expected an object");
    const id = msg.object.get("id") orelse return null;
    const method = switch (msg.object.get("method") orelse .null) {
        .string => |s| s,
        else => return try errorFrameAlloc(arena, id, invalid_request, "missing method"),
    };
    const params = msg.object.get("params") orelse Value{ .object = .empty };

    const result: Value = if (std.mem.eql(u8, method, "initialize"))
        try jsonValue(arena,
            \\{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},
            \\"serverInfo":{"name":"cvedex","version":"0.1.0"}}
        )
    else if (std.mem.eql(u8, method, "ping"))
        .{ .object = .empty }
    else if (std.mem.eql(u8, method, "tools/list"))
        try jsonValue(arena, tools_json)
    else if (std.mem.eql(u8, method, "tools/call"))
        callTool(arena, client, params) catch |err| switch (err) {
            error.InvalidParams => return try errorFrameAlloc(arena, id, invalid_params, "invalid tool or arguments"),
            else => |e| return e,
        }
    else
        return try errorFrameAlloc(arena, id, method_not_found, "method not found");

    return try std.json.Stringify.valueAlloc(arena, .{ .jsonrpc = "2.0", .id = id, .result = result }, .{});
}

const tools_json =
    \\{"tools":[
    \\{"name":"list_cves","description":"List the org's CVE IDs, optionally filtered by state.",
    \\"inputSchema":{"type":"object","properties":{"state":{"type":"string","enum":["RESERVED","PUBLISHED","REJECTED"]}}},
    \\"annotations":{"readOnlyHint":true}},
    \\{"name":"show_cve","description":"Show a CVE record.",
    \\"inputSchema":{"type":"object","properties":{"cve_id":{"type":"string"}},"required":["cve_id"]},
    \\"annotations":{"readOnlyHint":true}},
    \\{"name":"reserve_ids","description":"Reserve CVE IDs for a year.",
    \\"inputSchema":{"type":"object","properties":{"year":{"type":"integer"},"count":{"type":"integer","minimum":1},
    \\"sequential":{"type":"boolean"}},"required":["year"]},
    \\"annotations":{"destructiveHint":true}},
    \\{"name":"publish_cve","description":"Publish a CVE record. Takes the CNA container.",
    \\"inputSchema":{"type":"object","properties":{"cve_id":{"type":"string"},"cna_container":{"type":"object"}},
    \\"required":["cve_id","cna_container"]},
    \\"annotations":{"destructiveHint":true}},
    \\{"name":"update_cve","description":"Update a published CVE record. Takes the CNA container.",
    \\"inputSchema":{"type":"object","properties":{"cve_id":{"type":"string"},"cna_container":{"type":"object"}},
    \\"required":["cve_id","cna_container"]},
    \\"annotations":{"destructiveHint":true}}
    \\]}
;

const Tool = enum { list_cves, show_cve, reserve_ids, publish_cve, update_cve };

fn callTool(arena: std.mem.Allocator, client: *Client, params: Value) !Value {
    if (params != .object) return error.InvalidParams;
    const name = switch (params.object.get("name") orelse .null) {
        .string => |s| s,
        else => return error.InvalidParams,
    };
    const tool = std.meta.stringToEnum(Tool, name) orelse return error.InvalidParams;
    const args = params.object.get("arguments") orelse Value{ .object = .empty };
    const opts: std.json.ParseOptions = .{ .ignore_unknown_fields = true };

    const sent = switch (tool) {
        .list_cves => blk: {
            const a = std.json.parseFromValueLeaky(struct { state: ?[]const u8 = null }, arena, args, opts) catch
                return error.InvalidParams;
            break :blk client.listIds(arena, a.state);
        },
        .show_cve => blk: {
            const a = std.json.parseFromValueLeaky(struct { cve_id: []const u8 }, arena, args, opts) catch
                return error.InvalidParams;
            break :blk client.record(arena, a.cve_id);
        },
        .reserve_ids => blk: {
            const a = std.json.parseFromValueLeaky(Client.ReserveOptions, arena, args, opts) catch
                return error.InvalidParams;
            if (a.count == 0) return error.InvalidParams;
            break :blk client.reserve(arena, a);
        },
        .publish_cve, .update_cve => blk: {
            const a = std.json.parseFromValueLeaky(struct { cve_id: []const u8, cna_container: Value }, arena, args, opts) catch
                return error.InvalidParams;
            if (a.cna_container != .object) return error.InvalidParams;
            const payload = try std.json.Stringify.valueAlloc(arena, .{ .cnaContainer = a.cna_container }, .{});
            break :blk client.writeRecord(arena, if (tool == .publish_cve) .POST else .PUT, a.cve_id, payload);
        },
    };
    const response = sent catch |err| return toolResult(arena, @errorName(err), true);
    if (response.status == .accepted) {
        if (std.json.parseFromSliceLeaky(struct { proposal_id: Value }, arena, response.body, opts)) |p| {
            const text = try std.json.Stringify.valueAlloc(arena, .{ .status = "pending_approval", .proposal_id = p.proposal_id }, .{});
            return toolResult(arena, text, false);
        } else |_| {}
    }
    return toolResult(arena, response.body, !response.ok());
}

fn toolResult(arena: std.mem.Allocator, text: []const u8, is_error: bool) !Value {
    var content: std.json.Array = .init(arena);
    var item: std.json.ObjectMap = .empty;
    try item.put(arena, "type", .{ .string = "text" });
    try item.put(arena, "text", .{ .string = text });
    try content.append(.{ .object = item });
    var result: std.json.ObjectMap = .empty;
    try result.put(arena, "content", .{ .array = content });
    try result.put(arena, "isError", .{ .bool = is_error });
    return .{ .object = result };
}

fn jsonValue(arena: std.mem.Allocator, comptime json: []const u8) !Value {
    return std.json.parseFromSliceLeaky(Value, arena, json, .{});
}

fn errorFrameAlloc(arena: std.mem.Allocator, id: Value, code: i32, message: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(arena, .{
        .jsonrpc = "2.0",
        .id = id,
        .@"error" = .{ .code = code, .message = message },
    }, .{});
}

const Upstream = cvedex.Upstream;

fn expectFrame(expected: []const u8, client: *Client, line: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const frame = (try handle(arena.allocator(), client, line)) orelse return error.NoResponse;
    try std.testing.expectEqualStrings(expected, frame);
}

test "initialize advertises tools" {
    var client: Client = .init(std.testing.allocator, std.testing.io, .{});
    defer client.deinit();
    try expectFrame(
        \\{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"cvedex","version":"0.1.0"}}}
    , &client, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}");
}

test "notifications get no response" {
    var client: Client = .init(std.testing.allocator, std.testing.io, .{});
    defer client.deinit();
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqual(null, try handle(arena.allocator(), &client, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"));
}

test "malformed frames get JSON-RPC errors" {
    var client: Client = .init(std.testing.allocator, std.testing.io, .{});
    defer client.deinit();
    try expectFrame("{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"parse error\"}}", &client, "{");
    try expectFrame("{\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-32601,\"message\":\"method not found\"}}", &client, "{\"id\":7,\"method\":\"nope\"}");
    try expectFrame(
        "{\"jsonrpc\":\"2.0\",\"id\":8,\"error\":{\"code\":-32602,\"message\":\"invalid tool or arguments\"}}",
        &client,
        "{\"id\":8,\"method\":\"tools/call\",\"params\":{\"name\":\"show_cve\",\"arguments\":{}}}",
    );
}

test "tools/list marks writes destructive" {
    var client: Client = .init(std.testing.allocator, std.testing.io, .{});
    defer client.deinit();
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const frame = (try handle(arena.allocator(), &client, "{\"id\":1,\"method\":\"tools/list\"}")).?;
    const Listed = struct { result: struct { tools: []const struct {
        name: []const u8,
        annotations: struct { readOnlyHint: bool = false, destructiveHint: bool = false },
    } } };
    const listed = try std.json.parseFromSliceLeaky(Listed, arena.allocator(), frame, .{ .ignore_unknown_fields = true });
    for (listed.result.tools) |tool| {
        const writes = std.mem.eql(u8, tool.name, "reserve_ids") or std.mem.endsWith(u8, tool.name, "_cve") and !std.mem.eql(u8, tool.name, "show_cve");
        try std.testing.expectEqual(writes, tool.annotations.destructiveHint);
        try std.testing.expectEqual(!writes, tool.annotations.readOnlyHint);
    }
}

test "show_cve returns the record as text" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const recorded: Upstream.Exchange = try .cassette(arena.allocator(), @embedFile("testdata/recorded/cve-2025-0001.json"));
    var upstream: Upstream = try .start(io, &.{recorded});
    defer upstream.deinit(io);
    var buf: [64]u8 = undefined;
    var client: Client = .init(std.testing.allocator, io, .{ .url = upstream.url(&buf) });
    defer client.deinit();
    const frame = (try handle(arena.allocator(), &client,
        \\{"id":3,"method":"tools/call","params":{"name":"show_cve","arguments":{"cve_id":"CVE-2025-0001"}}}
    )).?;
    const Result = struct { result: struct { content: []const struct { text: []const u8 }, isError: bool } };
    const parsed = try std.json.parseFromSliceLeaky(Result, arena.allocator(), frame, .{ .ignore_unknown_fields = true });
    try std.testing.expect(!parsed.result.isError);
    try std.testing.expectEqualStrings(recorded.body, parsed.result.content[0].text);
    try upstream.finish(io);
}

test "a write held for approval reports pending_approval" {
    const io = std.testing.io;
    var upstream: Upstream = try .start(io, &.{.{
        .method = .POST,
        .target = "/api/cve/CVE-2025-0001/cna",
        .expect_body = "{\"cnaContainer\":{\"title\":\"x\"}}",
        .status = .accepted,
        .body = "{\"status\":\"pending_approval\",\"proposal_id\":\"p1\"}",
    }});
    defer upstream.deinit(io);
    var buf: [64]u8 = undefined;
    var client: Client = .init(std.testing.allocator, io, .{ .url = upstream.url(&buf) });
    defer client.deinit();
    try expectFrame(
        \\{"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"{\"status\":\"pending_approval\",\"proposal_id\":\"p1\"}"}],"isError":false}}
    , &client,
        \\{"id":4,"method":"tools/call","params":{"name":"publish_cve","arguments":{"cve_id":"CVE-2025-0001","cna_container":{"title":"x"}}}}
    );
    try upstream.finish(io);
}

test "serve answers each line and skips oversized frames" {
    var client: Client = .init(std.testing.allocator, std.testing.io, .{});
    defer client.deinit();
    var big: [80]u8 = @splat('x');
    big[big.len - 1] = '\n';
    const input = "{\"id\":1,\"method\":\"ping\"}\n" ++ big ++ "{\"id\":2,\"method\":\"ping\"}\n";
    var in_buf: [64]u8 = undefined;
    var source: std.Io.Reader = .fixed(input);
    var limited = source.limited(.unlimited, &in_buf);
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try serve(std.testing.allocator, &client, &limited.interface, &out.writer);
    try std.testing.expectEqualStrings(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n" ++ frame_too_long ++ "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n",
        out.written(),
    );
}

test "fuzz: handle never panics or leaks on arbitrary frames" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [512]u8 = undefined;
            const line = buf[0..smith.slice(&buf)];
            // Port 1 refuses connections, so a well-formed tools/call fails fast instead of hanging.
            var client: Client = .init(std.testing.allocator, std.testing.io, .{ .url = "http://127.0.0.1:1" });
            defer client.deinit();
            var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer arena.deinit();
            _ = try handle(arena.allocator(), &client, line);
        }
    }.testOne, .{ .corpus = &.{
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
        "{\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"list_cves\",\"arguments\":{\"state\":\"RESERVED\"}}}",
        "{\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"reserve_ids\",\"arguments\":{\"year\":2025,\"count\":0}}}",
    } });
}
