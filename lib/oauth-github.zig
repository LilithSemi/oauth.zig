//! GitHub OAuth apps and GitHub Apps. The caller gives the client id of its own app.

const std = @import("std");
const core = @import("oauth-core");

const testing = std.testing;

pub const endpoints: core.Endpoints = .{
    .authorization = "https://github.com/login/oauth/authorize",
    .token = "https://github.com/login/oauth/access_token",
    .device_authorization = "https://github.com/login/device/code",
};

pub fn client(client_id: []const u8) core.Client {
    return .{ .id = client_id };
}

test "a device login against GitHub shaped answers reaches a token" {
    var fake = core.testing.FakeTransport.init(testing.allocator, &.{
        .{ .body = "{\"device_code\":\"dc\",\"user_code\":\"WDJB-MJHT\",\"verification_uri\":\"https://github.com/login/device\",\"expires_in\":900,\"interval\":5}" },
        .{ .body = "{\"error\":\"authorization_pending\",\"error_description\":\"pending\"}" },
        .{ .body = "{\"access_token\":\"gho_x\",\"token_type\":\"bearer\",\"scope\":\"repo\"}" },
    });
    defer fake.deinit();
    const call: core.Call = .{ .transport = fake.transport(), .endpoints = endpoints, .client = client("Iv1.abc") };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const authorization = try core.device.deviceAuthorize(arena.allocator(), call, "repo");
    try testing.expectEqualStrings("WDJB-MJHT", authorization.user_code);
    try testing.expectEqual(core.device.PollResult.pending, try core.device.pollDeviceOnce(testing.allocator, call, authorization.device_code));
    var result = try core.device.pollDeviceOnce(testing.allocator, call, authorization.device_code);
    defer result.token.deinit();
    try testing.expectEqualStrings("gho_x", result.token.value().access_token);
    try testing.expectEqualStrings("https://github.com/login/device/code", fake.sent.items[0].url);
    try testing.expectEqualStrings("application/json", fake.sent.items[1].header("accept").?);
}

test "the preset endpoints pass the URL check" {
    try core.checkUrl(endpoints.authorization.?);
    try core.checkUrl(endpoints.token);
    try core.checkUrl(endpoints.device_authorization.?);
}
