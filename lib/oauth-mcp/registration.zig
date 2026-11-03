const std = @import("std");
const core = @import("oauth-core");

const Allocator = std.mem.Allocator;
const FakeTransport = core.testing.FakeTransport;

pub const RegisterOptions = struct {
    client_name: []const u8,
    redirect_uris: []const []const u8,
    allow_confidential: bool = false,
};

pub const RegisterError = core.SendError || error{
    ServerRefused,
    MalformedResponse,
    ConfidentialClientUnsupported,
    AuthMethodUnspecified,
};

const Answer = struct {
    client_id: []const u8,
    client_secret: ?[]const u8 = null,
    token_endpoint_auth_method: ?[]const u8 = null,
};

/// The client may hold a secret. The caller must wipe the arena when done.
pub fn register(arena: Allocator, transport: core.Transport, endpoint: []const u8, options: RegisterOptions) RegisterError!core.Client {
    const auth_method = if (options.allow_confidential) "client_secret_basic" else "none";
    const body = try std.json.Stringify.valueAlloc(arena, .{
        .client_name = options.client_name,
        .redirect_uris = options.redirect_uris,
        .token_endpoint_auth_method = auth_method,
        .grant_types = &[_][]const u8{ "authorization_code", "refresh_token" },
        .response_types = &[_][]const u8{"code"},
    }, .{});
    const response = try transport.send(arena, .{
        .method = .POST,
        .url = endpoint,
        .headers = &.{.{ .name = "Accept", .value = "application/json" }},
        .content_type = "application/json",
        .body = body,
    });
    if (!response.isSuccess()) return error.ServerRefused;
    const answer = std.json.parseFromSliceLeaky(Answer, arena, response.body, .{ .ignore_unknown_fields = true }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    if (answer.client_id.len == 0) return error.MalformedResponse;

    const method = answer.token_endpoint_auth_method orelse
        if (options.allow_confidential) "client_secret_basic" else return error.AuthMethodUnspecified;
    if (std.mem.eql(u8, method, "none")) return .{ .id = answer.client_id };
    if (!options.allow_confidential) return error.ConfidentialClientUnsupported;
    const secret = answer.client_secret orelse return error.MalformedResponse;
    if (std.mem.eql(u8, method, "client_secret_basic"))
        return .{ .id = answer.client_id, .auth = .{ .secret_basic = secret } };
    if (std.mem.eql(u8, method, "client_secret_post"))
        return .{ .id = answer.client_id, .auth = .{ .secret_post = secret } };
    return error.ConfidentialClientUnsupported;
}

const testing = std.testing;

const test_options: RegisterOptions = .{
    .client_name = "Chock",
    .redirect_uris = &.{"http://127.0.0.1:9/cb"},
};

test "register asks for a public client and returns it" {
    var fake = FakeTransport.init(testing.allocator, &.{.{
        .status = 201,
        .body = "{\"client_id\":\"abc\",\"token_endpoint_auth_method\":\"none\"}",
    }});
    defer fake.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const client = try register(arena.allocator(), fake.transport(), "https://auth.example/register", test_options);
    try testing.expectEqualStrings("abc", client.id);
    try testing.expect(client.auth == .none);
    const body = fake.sent.items[0].body.?;
    try testing.expect(std.mem.indexOf(u8, body, "\"token_endpoint_auth_method\":\"none\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"redirect_uris\":[\"http://127.0.0.1:9/cb\"]") != null);
    try testing.expectEqualStrings("application/json", fake.sent.items[0].content_type.?);
}

test "register refuses a confidential answer unless asked" {
    var fake = FakeTransport.init(testing.allocator, &.{
        .{ .status = 201, .body = "{\"client_id\":\"abc\",\"client_secret\":\"s\",\"token_endpoint_auth_method\":\"client_secret_post\"}" },
        .{ .status = 201, .body = "{\"client_id\":\"abc\",\"client_secret\":\"s\"}" },
        .{ .status = 201, .body = "{\"client_id\":\"abc\",\"client_secret\":\"s\",\"token_endpoint_auth_method\":\"client_secret_post\"}" },
        .{ .status = 201, .body = "{\"client_id\":\"\",\"token_endpoint_auth_method\":\"none\"}" },
        .{ .status = 400, .body = "{\"error\":\"invalid_redirect_uri\"}" },
    });
    defer fake.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.ConfidentialClientUnsupported, register(a, fake.transport(), "https://auth.example/register", test_options));
    try testing.expectError(error.AuthMethodUnspecified, register(a, fake.transport(), "https://auth.example/register", test_options));
    var confidential = test_options;
    confidential.allow_confidential = true;
    const client = try register(a, fake.transport(), "https://auth.example/register", confidential);
    try testing.expectEqualStrings("s", client.auth.secret_post);
    try testing.expectError(error.MalformedResponse, register(a, fake.transport(), "https://auth.example/register", test_options));
    try testing.expectError(error.ServerRefused, register(a, fake.transport(), "https://auth.example/register", test_options));
}

test "register reads a missing method as client_secret_basic when confidential is allowed" {
    var fake = FakeTransport.init(testing.allocator, &.{.{
        .status = 201,
        .body = "{\"client_id\":\"abc\",\"client_secret\":\"s\"}",
    }});
    defer fake.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var confidential = test_options;
    confidential.allow_confidential = true;
    const client = try register(arena.allocator(), fake.transport(), "https://auth.example/register", confidential);
    try testing.expectEqualStrings("s", client.auth.secret_basic);
}

test "register accepts a named client_secret_basic answer" {
    var fake = FakeTransport.init(testing.allocator, &.{.{
        .status = 201,
        .body = "{\"client_id\":\"abc\",\"client_secret\":\"s\",\"token_endpoint_auth_method\":\"client_secret_basic\"}",
    }});
    defer fake.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var confidential = test_options;
    confidential.allow_confidential = true;
    const client = try register(arena.allocator(), fake.transport(), "https://auth.example/register", confidential);
    try testing.expectEqualStrings("s", client.auth.secret_basic);
}
