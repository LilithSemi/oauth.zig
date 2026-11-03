const std = @import("std");
const token = @import("token.zig");
const client_mod = @import("client.zig");
const Param = @import("url.zig").Param;
const FakeTransport = @import("testing.zig").FakeTransport;

const Allocator = std.mem.Allocator;
const Call = client_mod.Call;
const ErrorCode = token.ErrorCode;
const TokenError = token.TokenError;
const TokenSet = token.TokenSet;
pub const slow_down_step: i64 = 5;

pub const DeviceAuthorization = struct {
    device_code: []const u8,
    user_code: []const u8,
    verification_uri: []const u8,
    verification_uri_complete: ?[]const u8 = null,
    expires_in: i64,
    interval: i64 = 5,
};

/// The result holds the device code. The caller must wipe the arena when done.
pub fn deviceAuthorize(arena: Allocator, call: Call, scope: []const u8) TokenError!DeviceAuthorization {
    const endpoint = call.endpoints.device_authorization orelse return error.EndpointMissing;
    const scope_params: []const Param = if (scope.len == 0) &.{} else &.{.{ .name = "scope", .value = scope }};
    var response = try token.postForm(arena, call, endpoint, scope_params);
    if (!response.isSuccess()) return token.refusal(arena, &response, call.error_code);
    const answer = std.json.parseFromSliceLeaky(DeviceAuthorization, arena, response.body, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            if (try token.hasErrorField(arena, response.body)) return token.refusal(arena, &response, call.error_code);
            return error.MalformedResponse;
        },
    };
    if (answer.interval < 1 or answer.expires_in < 1) return error.MalformedResponse;
    return answer;
}

pub const PollResult = union(enum) {
    token: TokenSet,
    pending,
    slow_down,
};

pub fn pollDeviceOnce(gpa: Allocator, call: Call, device_code: []const u8) TokenError!PollResult {
    var code: ErrorCode = .other;
    const response = try token.postForm(gpa, call, call.endpoints.token, &.{
        .{ .name = "grant_type", .value = "urn:ietf:params:oauth:grant-type:device_code" },
        .{ .name = "device_code", .value = device_code },
    });
    const set = token.readTokenSet(gpa, response, &code) catch |err| {
        if (err == error.TokenRefused) switch (code) {
            .authorization_pending => return .pending,
            .slow_down => return .slow_down,
            else => if (call.error_code) |out| {
                out.* = code;
            },
        };
        return err;
    };
    return .{ .token = set };
}

pub fn nextInterval(current: i64, result: std.meta.Tag(PollResult)) i64 {
    return switch (result) {
        .slow_down => current + slow_down_step,
        .token, .pending => current,
    };
}

const testing = std.testing;

fn testCall(fake: *FakeTransport, error_code: ?*ErrorCode) Call {
    return .{
        .transport = fake.transport(),
        .endpoints = .{ .token = "https://gh.example/token", .device_authorization = "https://gh.example/device" },
        .client = .{ .id = "client-1" },
        .error_code = error_code,
    };
}

test "deviceAuthorize sends the client and scope and reads the answer" {
    var fake = FakeTransport.init(testing.allocator, &.{.{
        .body = "{\"device_code\":\"dc\",\"user_code\":\"ABCD-1234\",\"verification_uri\":\"https://gh.example/login\",\"expires_in\":900}",
    }});
    defer fake.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const answer = try deviceAuthorize(arena.allocator(), testCall(&fake, null), "repo");
    try testing.expectEqualStrings("scope=repo&client_id=client-1", fake.sent.items[0].body.?);
    try testing.expectEqualStrings("https://gh.example/device", fake.sent.items[0].url);
    try testing.expectEqualStrings("ABCD-1234", answer.user_code);
    try testing.expectEqual(@as(i64, 5), answer.interval);
    try testing.expect(answer.verification_uri_complete == null);
}

test "deviceAuthorize needs a device endpoint" {
    var fake = FakeTransport.init(testing.allocator, &.{});
    defer fake.deinit();
    var no_device = testCall(&fake, null);
    no_device.endpoints.device_authorization = null;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.EndpointMissing, deviceAuthorize(arena.allocator(), no_device, ""));
}

test "deviceAuthorize refuses a zero interval or lifetime" {
    var fake = FakeTransport.init(testing.allocator, &.{
        .{ .body = "{\"device_code\":\"dc\",\"user_code\":\"U\",\"verification_uri\":\"https://gh.example/login\",\"expires_in\":900,\"interval\":0}" },
        .{ .body = "{\"device_code\":\"dc\",\"user_code\":\"U\",\"verification_uri\":\"https://gh.example/login\",\"expires_in\":0}" },
    });
    defer fake.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.MalformedResponse, deviceAuthorize(arena.allocator(), testCall(&fake, null), ""));
    try testing.expectError(error.MalformedResponse, deviceAuthorize(arena.allocator(), testCall(&fake, null), ""));
}

test "deviceAuthorize reads an error in a 2xx reply as a refusal" {
    var code: ErrorCode = .other;
    var fake = FakeTransport.init(testing.allocator, &.{.{ .body = "{\"error\":\"unauthorized_client\"}" }});
    defer fake.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.TokenRefused, deviceAuthorize(arena.allocator(), testCall(&fake, &code), ""));
    try testing.expectEqual(ErrorCode.unauthorized_client, code);
}

test "pollDeviceOnce reports pending, slow down and the token" {
    var fake = FakeTransport.init(testing.allocator, &.{
        .{ .status = 400, .body = "{\"error\":\"authorization_pending\"}" },
        .{ .status = 200, .body = "{\"error\":\"slow_down\"}" },
        .{ .body = "{\"access_token\":\"at\",\"token_type\":\"bearer\"}" },
    });
    defer fake.deinit();
    try testing.expectEqual(PollResult.pending, try pollDeviceOnce(testing.allocator, testCall(&fake, null), "dc"));
    try testing.expectEqual(PollResult.slow_down, try pollDeviceOnce(testing.allocator, testCall(&fake, null), "dc"));
    var result = try pollDeviceOnce(testing.allocator, testCall(&fake, null), "dc");
    defer result.token.deinit();
    try testing.expectEqualStrings("at", result.token.value().access_token);
    try testing.expectEqualStrings(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=dc&client_id=client-1",
        fake.sent.items[0].body.?,
    );
}

test "pollDeviceOnce passes other refusals through with their code" {
    var code: ErrorCode = .other;
    var fake = FakeTransport.init(testing.allocator, &.{.{ .status = 400, .body = "{\"error\":\"expired_token\"}" }});
    defer fake.deinit();
    try testing.expectError(error.TokenRefused, pollDeviceOnce(testing.allocator, testCall(&fake, &code), "dc"));
    try testing.expectEqual(ErrorCode.expired_token, code);
}

test "nextInterval adds five seconds only on slow down" {
    try testing.expectEqual(@as(i64, 5), nextInterval(5, .pending));
    try testing.expectEqual(@as(i64, 10), nextInterval(5, .slow_down));
}
