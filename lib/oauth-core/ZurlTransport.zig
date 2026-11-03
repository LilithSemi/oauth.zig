const ZurlTransport = @This();

const std = @import("std");
const zurl = @import("zurl");
const transport_mod = @import("transport.zig");

const Allocator = std.mem.Allocator;
const Transport = transport_mod.Transport;
const Request = transport_mod.Request;
const Response = transport_mod.Response;
const SendError = transport_mod.SendError;

io: std.Io,
max_response_bytes: usize = 1024 * 1024,

pub fn init(io: std.Io) ZurlTransport {
    return .{ .io = io };
}

pub fn transport(self: *ZurlTransport) Transport {
    return .{ .ptr = self, .vtable = &.{ .send = send } };
}

fn send(ptr: *anyopaque, gpa: Allocator, request: Request) SendError!Response {
    const self: *ZurlTransport = @ptrCast(@alignCast(ptr));
    return self.sendUnchecked(gpa, request);
}

/// Sends with no URL check. `Transport.send` checks the URL first.
fn sendUnchecked(self: *ZurlTransport, gpa: Allocator, request: Request) SendError!Response {
    var client: zurl.Client = .init(gpa, self.io);
    defer client.deinit();
    var memory: zurl.request_body.Memory = .{
        .bytes = request.body orelse "",
        .content_type = request.content_type,
    };
    const response = client.perform(request.url, .{
        .method = request.method,
        .body = if (request.body != null) memory.source() else null,
        .headers = request.headers,
        .redirects = .unfollowed,
        .accept_encoding = false,
        .user_agent = "oauth.zig",
    }, null) catch |err| return mapError(err);

    const head = try gpa.dupe(u8, response.final_headers orelse "");
    errdefer gpa.free(head);
    const scratch = try gpa.alloc(u8, self.max_response_bytes + 1);
    defer {
        std.crypto.secureZero(u8, scratch);
        gpa.free(scratch);
    }
    const len = response.body.readSliceShort(scratch) catch |err| return switch (err) {
        error.ReadFailed => mapError(client.resolveBodyError(null)),
    };
    if (len > self.max_response_bytes) return error.ResponseTooLarge;
    const body = try gpa.dupe(u8, scratch[0..len]);
    return .{ .status = response.status, .head = head, .body = body };
}

/// Certificate faults keep their own errors, so a caller can tell a missing
/// trust store from a refusal by the server.
fn mapError(err: zurl.Error) SendError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.PeerFailedVerification, error.SslInvalidCertStatus => error.CertificateInvalid,
        error.CaCertBadFile => error.TrustStoreMissing,
        else => error.TransportFailed,
    };
}

const test_server = @import("zurl-http").test_server;
const testing = std.testing;

fn loopbackUrl(server: *const test_server.TestServer, path: []const u8) ![]u8 {
    return std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}{s}", .{ server.port(), path });
}

test "sendUnchecked posts the body and returns status, head and body" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();
    const target = try loopbackUrl(&server, "/token");
    defer testing.allocator.free(target);

    var zurl_transport = ZurlTransport.init(testing.io);
    var response = try zurl_transport.sendUnchecked(testing.allocator, .{
        .method = .POST,
        .url = target,
        .headers = &.{.{ .name = "Accept", .value = "application/json" }},
        .content_type = "application/x-www-form-urlencoded",
        .body = "a=b",
    });
    defer response.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expectEqualStrings("ok", response.body);
    try testing.expectEqualStrings("application/json", response.header("content-type").?);
    try testing.expectEqualStrings("a=b", server.requestBody(0).?);
}

test "sendUnchecked does not follow a redirect" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();
    const target = try loopbackUrl(&server, "/");
    defer testing.allocator.free(target);

    var zurl_transport = ZurlTransport.init(testing.io);
    var response = try zurl_transport.sendUnchecked(testing.allocator, .{ .method = .GET, .url = target });
    defer response.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 302), response.status);
    try testing.expectEqual(@as(usize, 1), server.accepts());
}

test "sendUnchecked refuses a body over the cap" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();
    const target = try loopbackUrl(&server, "/");
    defer testing.allocator.free(target);

    var zurl_transport = ZurlTransport.init(testing.io);
    zurl_transport.max_response_bytes = 4;
    try testing.expectError(error.ResponseTooLarge, zurl_transport.sendUnchecked(testing.allocator, .{ .method = .GET, .url = target }));
}

test "sendUnchecked takes a body of exactly the cap" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();
    const target = try loopbackUrl(&server, "/");
    defer testing.allocator.free(target);

    var zurl_transport = ZurlTransport.init(testing.io);
    zurl_transport.max_response_bytes = 7;
    var response = try zurl_transport.sendUnchecked(testing.allocator, .{ .method = .GET, .url = target });
    defer response.deinit(testing.allocator);
    try testing.expectEqualStrings("payload", response.body);
}

test "the transport interface refuses plain http" {
    var zurl_transport = ZurlTransport.init(testing.io);
    try testing.expectError(error.UrlNotSafe, zurl_transport.transport().send(testing.allocator, .{
        .method = .GET,
        .url = "http://127.0.0.1:1/",
    }));
}
