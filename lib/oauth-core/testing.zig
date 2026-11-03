const std = @import("std");
const transport_mod = @import("transport.zig");

const Allocator = std.mem.Allocator;
const Transport = transport_mod.Transport;
const Request = transport_mod.Request;
const Response = transport_mod.Response;
const SendError = transport_mod.SendError;
/// Answers requests from a fixed list of replies and keeps a copy of each request.
pub const FakeTransport = struct {
    gpa: Allocator,
    replies: []const Reply,
    sent: std.ArrayList(Sent) = .empty,

    pub const Reply = struct {
        status: u16 = 200,
        head: []const u8 = "",
        body: []const u8 = "",
    };

    pub const Sent = struct {
        method: std.http.Method,
        url: []u8,
        headers: []std.http.Header,
        content_type: ?[]u8,
        body: ?[]u8,

        pub fn header(self: Sent, name: []const u8) ?[]const u8 {
            for (self.headers) |one| if (std.ascii.eqlIgnoreCase(one.name, name)) return one.value;
            return null;
        }

        fn deinit(self: *Sent, gpa: Allocator) void {
            for (self.headers) |one| {
                gpa.free(one.name);
                gpa.free(one.value);
            }
            gpa.free(self.headers);
            gpa.free(self.url);
            if (self.content_type) |value| gpa.free(value);
            if (self.body) |value| gpa.free(value);
        }
    };

    pub fn init(gpa: Allocator, replies: []const Reply) FakeTransport {
        return .{ .gpa = gpa, .replies = replies };
    }

    pub fn deinit(self: *FakeTransport) void {
        for (self.sent.items) |*one| one.deinit(self.gpa);
        self.sent.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn transport(self: *FakeTransport) Transport {
        return .{ .ptr = self, .vtable = &.{ .send = send } };
    }

    fn send(ptr: *anyopaque, gpa: Allocator, request: Request) SendError!Response {
        const self: *FakeTransport = @ptrCast(@alignCast(ptr));
        if (self.sent.items.len >= self.replies.len) return error.TransportFailed;
        try self.record(request);
        const reply = self.replies[self.sent.items.len - 1];
        const head = try std.fmt.allocPrint(gpa, "HTTP/1.1 {d} Fake\r\n{s}\r\n", .{ reply.status, reply.head });
        errdefer gpa.free(head);
        return .{ .status = reply.status, .head = head, .body = try gpa.dupe(u8, reply.body) };
    }

    fn record(self: *FakeTransport, request: Request) Allocator.Error!void {
        const gpa = self.gpa;
        var sent = try newSent(gpa, request);
        errdefer sent.deinit(gpa);
        if (request.content_type) |value| sent.content_type = try gpa.dupe(u8, value);
        if (request.body) |value| sent.body = try gpa.dupe(u8, value);
        try self.sent.append(gpa, sent);
    }

    fn newSent(gpa: Allocator, request: Request) Allocator.Error!Sent {
        const url_copy = try gpa.dupe(u8, request.url);
        errdefer gpa.free(url_copy);
        return .{
            .method = request.method,
            .url = url_copy,
            .headers = try dupeHeaders(gpa, request.headers),
            .content_type = null,
            .body = null,
        };
    }
};

fn dupeHeaders(gpa: Allocator, headers: []const std.http.Header) Allocator.Error![]std.http.Header {
    const out = try gpa.alloc(std.http.Header, headers.len);
    var copied: usize = 0;
    errdefer {
        for (out[0..copied]) |one| {
            gpa.free(one.name);
            gpa.free(one.value);
        }
        gpa.free(out);
    }
    for (headers) |one| {
        const name = try gpa.dupe(u8, one.name);
        errdefer gpa.free(name);
        out[copied] = .{ .name = name, .value = try gpa.dupe(u8, one.value) };
        copied += 1;
    }
    return out;
}

test "FakeTransport records the request and answers with the next reply" {
    const gpa = std.testing.allocator;
    var fake = FakeTransport.init(gpa, &.{
        .{ .status = 401, .head = "WWW-Authenticate: Bearer x\r\n", .body = "{}" },
    });
    defer fake.deinit();
    var response = try fake.transport().send(gpa, .{
        .method = .POST,
        .url = "https://a.example/t",
        .headers = &.{.{ .name = "Accept", .value = "application/json" }},
        .content_type = "application/x-www-form-urlencoded",
        .body = "a=b",
    });
    defer response.deinit(gpa);
    try std.testing.expectEqual(@as(u16, 401), response.status);
    try std.testing.expectEqualStrings("Bearer x", response.header("www-authenticate").?);
    try std.testing.expectEqualStrings("{}", response.body);
    const sent = fake.sent.items[0];
    try std.testing.expectEqual(std.http.Method.POST, sent.method);
    try std.testing.expectEqualStrings("https://a.example/t", sent.url);
    try std.testing.expectEqualStrings("a=b", sent.body.?);
    try std.testing.expectEqualStrings("application/json", sent.header("accept").?);
    try std.testing.expectEqualStrings("application/x-www-form-urlencoded", sent.content_type.?);
}

test "FakeTransport fails a request it has no reply for" {
    const gpa = std.testing.allocator;
    var fake = FakeTransport.init(gpa, &.{});
    defer fake.deinit();
    try std.testing.expectError(error.TransportFailed, fake.transport().send(gpa, .{ .method = .GET, .url = "https://a.example/" }));
}

test "Transport.send refuses an unsafe URL before the transport sees it" {
    const gpa = std.testing.allocator;
    var fake = FakeTransport.init(gpa, &.{.{}});
    defer fake.deinit();
    try std.testing.expectError(error.UrlNotSafe, fake.transport().send(gpa, .{ .method = .GET, .url = "http://a.example/" }));
    try std.testing.expectEqual(@as(usize, 0), fake.sent.items.len);
}
