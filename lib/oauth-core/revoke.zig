const std = @import("std");
const token = @import("token.zig");
const client_mod = @import("client.zig");
const Param = @import("url.zig").Param;
const FakeTransport = @import("testing.zig").FakeTransport;

const Allocator = std.mem.Allocator;
const Call = client_mod.Call;
const ErrorCode = token.ErrorCode;
const TokenError = token.TokenError;

const testing = std.testing;

pub const TokenHint = enum { access_token, refresh_token };

/// RFC 7009 section 2.2: a 200 is success, also for a token the server does not know.
pub fn revoke(gpa: Allocator, call: Call, token_value: []const u8, hint: ?TokenHint) TokenError!void {
    const endpoint = call.endpoints.revocation orelse return error.EndpointMissing;
    var params: [2]Param = .{
        .{ .name = "token", .value = token_value },
        undefined,
    };
    var count: usize = 1;
    if (hint) |one| {
        params[1] = .{ .name = "token_type_hint", .value = @tagName(one) };
        count = 2;
    }
    var response = try token.postForm(gpa, call, endpoint, params[0..count]);
    if (response.status == 200) {
        response.deinit(gpa);
        return;
    }
    return token.refusal(gpa, &response, call.error_code);
}

fn testCall(fake: *FakeTransport, revocation: ?[]const u8, error_code: ?*ErrorCode) Call {
    return .{
        .transport = fake.transport(),
        .endpoints = .{ .token = "https://a.example/token", .revocation = revocation },
        .client = .{ .id = "client-1" },
        .error_code = error_code,
    };
}

test "revoke sends the token and hint and accepts a 200" {
    var fake = FakeTransport.init(testing.allocator, &.{.{ .status = 200 }});
    defer fake.deinit();
    try revoke(testing.allocator, testCall(&fake, "https://a.example/revoke", null), "rt", .refresh_token);
    try testing.expectEqualStrings("token=rt&token_type_hint=refresh_token&client_id=client-1", fake.sent.items[0].body.?);
}

test "revoke reports a refusal and a missing endpoint" {
    var code: ErrorCode = .other;
    var fake = FakeTransport.init(testing.allocator, &.{
        .{ .status = 400, .body = "{\"error\":\"unsupported_token_type\"}" },
        .{ .status = 503 },
    });
    defer fake.deinit();
    try testing.expectError(error.TokenRefused, revoke(testing.allocator, testCall(&fake, "https://a.example/revoke", &code), "at", null));
    try testing.expectEqual(ErrorCode.unsupported_token_type, code);
    try testing.expectError(error.ServerRefused, revoke(testing.allocator, testCall(&fake, "https://a.example/revoke", null), "at", null));
    try testing.expectError(error.EndpointMissing, revoke(testing.allocator, testCall(&fake, null, null), "at", null));
}
