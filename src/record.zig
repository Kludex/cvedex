//! CVE JSON 5.1 shapes the client reads or builds. Records are passed through as opaque JSON:
//! only the fields the CLI prints are typed here, and upstream does the schema validation.

const std = @import("std");

/// One entry of `cve_ids` in `GET /api/cve-id` and `POST /api/cve-id` responses.
pub const CveId = struct {
    cve_id: []const u8,
    state: []const u8,
    owning_cna: []const u8 = "",
    reserved: []const u8 = "",
};

pub const IdList = struct {
    cve_ids: []const CveId = &.{},
};

/// Parses an ID list body. The result borrows from `arena`.
pub fn parseIds(arena: std.mem.Allocator, body: []const u8) !IdList {
    return std.json.parseFromSliceLeaky(IdList, arena, body, .{ .ignore_unknown_fields = true });
}

/// Returns `json` as a `{"cnaContainer": ...}` payload. A document that already has a top-level
/// `cnaContainer` is returned as is, so users can pass either form.
pub fn cnaPayload(arena: std.mem.Allocator, json: []const u8) ![]const u8 {
    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena, json, .{});
    if (value != .object) return error.RecordNotObject;
    if (value.object.contains("cnaContainer")) return json;
    return std.fmt.allocPrint(arena, "{{\"cnaContainer\":{s}}}", .{std.mem.trim(u8, json, " \t\r\n")});
}

test "cnaPayload wraps a bare CNA container" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("{\"cnaContainer\":{\"title\":\"x\"}}", try cnaPayload(arena.allocator(), "{\"title\":\"x\"}\n"));
}

test "cnaPayload keeps an already wrapped payload" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const wrapped = "{\"cnaContainer\":{}}";
    try std.testing.expectEqualStrings(wrapped, try cnaPayload(arena.allocator(), wrapped));
}

test "cnaPayload rejects a non-object" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.RecordNotObject, cnaPayload(arena.allocator(), "[]"));
}

test "parseIds reads ids and states" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const recorded: Upstream.Exchange = try .cassette(arena.allocator(), @embedFile("testdata/recorded/cve-id-list.json"));
    const ids = try parseIds(arena.allocator(), recorded.body);
    try std.testing.expectEqual(2, ids.cve_ids.len);
    try std.testing.expectEqualStrings("CVE-2026-1100", ids.cve_ids[1].cve_id);
    try std.testing.expectEqualStrings("PUBLISHED", ids.cve_ids[1].state);
}

const Upstream = @import("Upstream.zig");
