//! CVE Services HTTP client. Every call returns the upstream status and body verbatim: this module
//! never interprets an error response, so callers can show exactly what CVE Services said. It
//! speaks the same API to MITRE and to `cvedexd`; the base URL is the only difference.

const std = @import("std");

pub const Credentials = struct {
    url: []const u8 = default_url,
    org: []const u8 = "",
    user: []const u8 = "",
    key: []const u8 = "",
};

pub const default_url = "https://cveawg.mitre.org";

/// Formats with `{f}` as a percent-encoded path segment or query value.
pub const Escaped = struct {
    raw: []const u8,

    pub fn format(self: Escaped, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try std.Uri.Component.percentEncode(w, self.raw, isUnreserved);
    }

    fn isUnreserved(c: u8) bool {
        return std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~';
    }
};

/// A response body owned by the caller's allocator.
pub const Response = struct {
    status: std.http.Status,
    body: []u8,

    pub fn ok(self: *const Response) bool {
        return @intFromEnum(self.status) < 400;
    }

    pub fn deinit(self: *Response, gpa: std.mem.Allocator) void {
        gpa.free(self.body);
    }
};

pub const Client = struct {
    http: std.http.Client,
    creds: Credentials,

    pub fn init(gpa: std.mem.Allocator, io: std.Io, creds: Credentials) Client {
        return .{ .http = .{ .allocator = gpa, .io = io }, .creds = creds };
    }

    pub fn deinit(self: *Client) void {
        self.http.deinit();
    }

    /// Sends one request to `creds.url ++ target` with the three CVE Services auth headers.
    pub fn send(
        self: *Client,
        gpa: std.mem.Allocator,
        method: std.http.Method,
        target: []const u8,
        payload: ?[]const u8,
    ) !Response {
        const url = try std.mem.concat(gpa, u8, &.{ std.mem.trimEnd(u8, self.creds.url, "/"), target });
        defer gpa.free(url);
        var body: std.Io.Writer.Allocating = .init(gpa);
        defer body.deinit();
        // `std.http.Client` asserts that POST, PUT and PATCH carry a body, so send an empty one.
        const body_out: ?[]const u8 = payload orelse if (method.requestHasBody()) "" else null;
        const result = try self.http.fetch(.{
            .location = .{ .url = url },
            .method = method,
            .payload = body_out,
            .keep_alive = false,
            // Never follow a redirect: the auth headers would go along to wherever it points.
            .redirect_behavior = .unhandled,
            .response_writer = &body.writer,
            .headers = .{ .content_type = if (body_out != null) .{ .override = "application/json" } else .default },
            // `std.http.Client` 0.16 drops `privileged_headers` on the floor, so these go as extra headers.
            .extra_headers = &.{
                .{ .name = "CVE-API-ORG", .value = self.creds.org },
                .{ .name = "CVE-API-USER", .value = self.creds.user },
                .{ .name = "CVE-API-KEY", .value = self.creds.key },
            },
        });
        return .{ .status = result.status, .body = try body.toOwnedSlice() };
    }

    /// `GET /api/health-check`. `cvedexd` answers with `{"server":"cvedexd","version":...}`.
    pub fn health(self: *Client, gpa: std.mem.Allocator) !Response {
        return self.send(gpa, .GET, "/api/health-check", null);
    }

    pub const ReserveOptions = struct {
        year: u16,
        count: u32 = 1,
        sequential: bool = false,
    };

    /// `POST /api/cve-id`: reserves `count` IDs for `year` in the caller's org.
    pub fn reserve(self: *Client, gpa: std.mem.Allocator, options: ReserveOptions) !Response {
        const target = try std.fmt.allocPrint(gpa, "/api/cve-id?amount={d}&cve_year={d}&short_name={f}{s}", .{
            options.count,
            options.year,
            Escaped{ .raw = self.creds.org },
            if (options.count > 1) (if (options.sequential) "&batch_type=sequential" else "&batch_type=nonsequential") else "",
        });
        defer gpa.free(target);
        return self.send(gpa, .POST, target, null);
    }

    /// `GET /api/cve-id`, optionally filtered by `state` (`RESERVED`, `PUBLISHED`, `REJECTED`).
    pub fn listIds(self: *Client, gpa: std.mem.Allocator, state: ?[]const u8) !Response {
        const target = if (state) |s|
            try std.fmt.allocPrint(gpa, "/api/cve-id?state={f}", .{Escaped{ .raw = s }})
        else
            try gpa.dupe(u8, "/api/cve-id");
        defer gpa.free(target);
        return self.send(gpa, .GET, target, null);
    }

    /// `GET /api/cve/{id}`.
    pub fn record(self: *Client, gpa: std.mem.Allocator, id: []const u8) !Response {
        return self.sendFmt(gpa, .GET, "/api/cve/{f}", .{Escaped{ .raw = id }}, null);
    }

    /// `POST /api/cve/{id}/cna` to publish, or `PUT` to update. `payload` is `{"cnaContainer": ...}`.
    pub fn writeRecord(
        self: *Client,
        gpa: std.mem.Allocator,
        method: std.http.Method,
        id: []const u8,
        payload: []const u8,
    ) !Response {
        return self.sendFmt(gpa, method, "/api/cve/{f}/cna", .{Escaped{ .raw = id }}, payload);
    }

    /// `POST /api/cve/{id}/reject`. `payload` is `{"cnaContainer": {"rejectedReasons": [...]}}`.
    pub fn reject(self: *Client, gpa: std.mem.Allocator, id: []const u8, payload: []const u8) !Response {
        return self.sendFmt(gpa, .POST, "/api/cve/{f}/reject", .{Escaped{ .raw = id }}, payload);
    }

    /// Formats `fmt` with `args` into a request target and sends it.
    pub fn sendFmt(
        self: *Client,
        gpa: std.mem.Allocator,
        method: std.http.Method,
        comptime fmt: []const u8,
        args: anytype,
        payload: ?[]const u8,
    ) !Response {
        const target = try std.fmt.allocPrint(gpa, fmt, args);
        defer gpa.free(target);
        return self.send(gpa, method, target, payload);
    }
};

const Upstream = @import("Upstream.zig");

test "reserve sends org, year, amount and auth headers" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var upstream: Upstream = try .start(io, &.{.{
        .method = .POST,
        .target = "/api/cve-id?amount=2&cve_year=2025&short_name=acme&batch_type=sequential",
        .expect_user = "ada@acme.org",
        .body = @embedFile("testdata/reserve.json"),
    }});
    defer upstream.deinit(io);
    var buf: [64]u8 = undefined;
    var client: Client = .init(gpa, io, .{ .url = upstream.url(&buf), .org = "acme", .user = "ada@acme.org", .key = "k" });
    defer client.deinit();

    var response = try client.reserve(gpa, .{ .year = 2025, .count = 2, .sequential = true });
    defer response.deinit(gpa);
    try upstream.finish(io);

    try std.testing.expectEqual(std.http.Status.ok, response.status);
    try std.testing.expectEqualStrings(@embedFile("testdata/reserve.json"), response.body);
}

test "error responses are returned verbatim" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const recorded: Upstream.Exchange = try .cassette(arena.allocator(), @embedFile("testdata/recorded/cve-record-dne.json"));
    var upstream: Upstream = try .start(io, &.{recorded});
    defer upstream.deinit(io);
    var buf: [64]u8 = undefined;
    var client: Client = .init(gpa, io, .{ .url = upstream.url(&buf) });
    defer client.deinit();

    var response = try client.record(gpa, "CVE-2021-44228");
    defer response.deinit(gpa);
    try upstream.finish(io);

    try std.testing.expectEqual(std.http.Status.not_found, response.status);
    try std.testing.expectEqualStrings(recorded.body, response.body);
}

test "writeRecord sends the payload" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const payload = "{\"cnaContainer\":{}}";
    var upstream: Upstream = try .start(io, &.{
        .{ .method = .PUT, .target = "/api/cve/CVE-2025-0001/cna", .expect_body = payload },
    });
    defer upstream.deinit(io);
    var buf: [64]u8 = undefined;
    var client: Client = .init(gpa, io, .{ .url = upstream.url(&buf) });
    defer client.deinit();

    var response = try client.writeRecord(gpa, .PUT, "CVE-2025-0001", payload);
    defer response.deinit(gpa);
    try upstream.finish(io);
    try std.testing.expect(response.ok());
}
