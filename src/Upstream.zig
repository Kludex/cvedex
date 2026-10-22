//! A scripted CVE Services stand-in for tests: an `std.http.Server` on a loopback port that
//! answers a fixed list of exchanges, in order, one connection each, and checks that each request
//! matches what the exchange expects. It is test-only; nothing outside `test` blocks imports it.

const std = @import("std");

const Upstream = @This();

/// One request the client is expected to send, and the response to give it.
pub const Exchange = struct {
    method: std.http.Method,
    /// Path plus query string, exactly as sent on the request line.
    target: []const u8,
    status: std.http.Status = .ok,
    body: []const u8 = "",
    /// When set, the request body must equal this.
    expect_body: ?[]const u8 = null,
    /// When set, the `CVE-API-USER` header must equal this.
    expect_user: ?[]const u8 = null,
    /// Response headers. Empty means a JSON `content-type` only.
    headers: []const std.http.Header = &.{},

    /// Reads a cassette written by `scripts/record-fixtures.mjs`. Strings borrow from `arena` and
    /// `json`.
    pub fn cassette(arena: std.mem.Allocator, json: []const u8) !Exchange {
        const Cassette = struct {
            request: struct { method: []const u8, path: []const u8, body: ?[]const u8 = null },
            response: struct { status: u10, headers: std.json.ArrayHashMap([]const u8), body: []const u8 },
        };
        const c = try std.json.parseFromSliceLeaky(Cassette, arena, json, .{});
        const headers = try arena.alloc(std.http.Header, c.response.headers.map.count());
        for (c.response.headers.map.keys(), c.response.headers.map.values(), headers) |name, value, *h| {
            h.* = .{ .name = name, .value = value };
        }
        return .{
            .method = std.meta.stringToEnum(std.http.Method, c.request.method) orelse return error.UnknownMethod,
            .target = c.request.path,
            .status = @enumFromInt(c.response.status),
            .body = c.response.body,
            .expect_body = c.request.body,
            .headers = headers,
        };
    }
};

const json_content_type: []const std.http.Header = &.{.{ .name = "content-type", .value = "application/json" }};

server: std.Io.net.Server,
future: ?std.Io.Future(anyerror!void),
port: u16,

/// Starts serving `exchanges`, which must outlive the returned value.
pub fn start(io: std.Io, exchanges: []const Exchange) !Upstream {
    const address: std.Io.net.IpAddress = try .parse("127.0.0.1", 0);
    var server = try address.listen(io, .{ .reuse_address = true });
    errdefer server.deinit(io);
    return .{
        .server = server,
        .port = server.socket.address.getPort(),
        .future = try io.concurrent(serve, .{ server, io, exchanges }),
    };
}

/// Base URL to point a client at.
pub fn url(self: *const Upstream, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "http://127.0.0.1:{d}", .{self.port}) catch unreachable; // buf is sized by callers
}

/// Waits for every exchange to be served and returns the first mismatch, if any.
pub fn finish(self: *Upstream, io: std.Io) !void {
    var future = self.future orelse return;
    self.future = null;
    return future.await(io);
}

/// Stops serving. Call with `defer` right after declaring, so a failing test does not hang.
pub fn deinit(self: *Upstream, io: std.Io) void {
    if (self.future) |*future| future.cancel(io) catch {};
    self.server.deinit(io);
}

fn serve(listener: std.Io.net.Server, io: std.Io, exchanges: []const Exchange) anyerror!void {
    var server = listener;
    for (exchanges) |exchange| {
        const stream = try server.accept(io);
        defer stream.close(io);
        var in_buf: [16 * 1024]u8 = undefined;
        var out_buf: [16 * 1024]u8 = undefined;
        var reader = stream.reader(io, &in_buf);
        var writer = stream.writer(io, &out_buf);
        var http: std.http.Server = .init(&reader.interface, &writer.interface);
        var request = try http.receiveHead();

        try std.testing.expectEqual(exchange.method, request.head.method);
        try std.testing.expectEqualStrings(exchange.target, request.head.target);
        if (exchange.expect_user) |user| {
            var it = request.iterateHeaders();
            const sent = while (it.next()) |h| {
                if (std.ascii.eqlIgnoreCase(h.name, "CVE-API-USER")) break h.value;
            } else "";
            try std.testing.expectEqualStrings(user, sent);
        }
        if (exchange.expect_body) |expected| {
            var body_buf: [16 * 1024]u8 = undefined;
            const body_reader = request.readerExpectNone(&body_buf);
            var got: [16 * 1024]u8 = undefined;
            const n = try body_reader.readSliceShort(&got);
            try std.testing.expectEqualStrings(expected, got[0..n]);
        }
        try request.respond(exchange.body, .{
            .status = exchange.status,
            .keep_alive = false,
            .extra_headers = if (exchange.headers.len > 0) exchange.headers else json_content_type,
        });
    }
}
