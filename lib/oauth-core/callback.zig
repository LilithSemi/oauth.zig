const std = @import("std");
const url = @import("url.zig");
const pkce = @import("pkce.zig");

const Allocator = std.mem.Allocator;
const Param = url.Param;
const Attempt = pkce.Attempt;

pub const CallbackError = error{
    WrongPath,
    MissingCode,
    MissingState,
    StateMismatch,
    AuthorizationRefused,
    BadEncoding,
};

pub const Callback = struct {
    pairs: []const Param,

    pub fn get(self: Callback, name: []const u8) ?[]const u8 {
        for (self.pairs) |pair| if (std.mem.eql(u8, pair.name, name)) return pair.value;
        return null;
    }

    /// `parseCallback` returns a `Callback` only when it holds a code.
    pub fn code(self: Callback) []const u8 {
        return self.get("code").?;
    }
};

/// The result holds the code. The caller must wipe the arena when done.
pub fn parseCallback(
    arena: Allocator,
    target: []const u8,
    expected_path: []const u8,
    expected: *const Attempt,
) (CallbackError || Allocator.Error)!Callback {
    const query_at = std.mem.indexOfScalar(u8, target, '?') orelse target.len;
    if (!std.mem.eql(u8, target[0..query_at], expected_path)) return error.WrongPath;

    var pairs: std.ArrayList(Param) = .empty;
    if (query_at < target.len) {
        var it = std.mem.splitScalar(u8, target[query_at + 1 ..], '&');
        while (it.next()) |pair| {
            if (pair.len == 0) continue;
            const equals = std.mem.indexOfScalar(u8, pair, '=') orelse pair.len;
            const value = if (equals < pair.len) pair[equals + 1 ..] else "";
            try pairs.append(arena, .{
                .name = try decode(arena, pair[0..equals]),
                .value = try decode(arena, value),
            });
        }
    }
    const result: Callback = .{ .pairs = pairs.items };

    const state = result.get("state") orelse return error.MissingState;
    if (state.len != pkce.state_len) return error.StateMismatch;
    if (!std.crypto.timing_safe.eql([pkce.state_len]u8, expected.state, state[0..pkce.state_len].*)) return error.StateMismatch;
    if (result.get("error") != null) return error.AuthorizationRefused;
    const code = result.get("code") orelse return error.MissingCode;
    if (code.len == 0) return error.MissingCode;
    return result;
}

fn decode(arena: Allocator, text: []const u8) (CallbackError || Allocator.Error)![]u8 {
    const copy = try arena.dupe(u8, text);
    for (copy) |*byte| if (byte.* == '+') {
        byte.* = ' ';
    };
    var at: usize = 0;
    while (at < copy.len) : (at += 1) {
        if (copy[at] != '%') continue;
        if (at + 2 >= copy.len) return error.BadEncoding;
        if (!std.ascii.isHex(copy[at + 1]) or !std.ascii.isHex(copy[at + 2])) return error.BadEncoding;
    }
    return std.Uri.percentDecodeInPlace(copy);
}

const good_state: [43]u8 = @splat('s');
const other_state: [43]u8 = @splat('x');
const attempt: Attempt = .{
    .state = good_state,
    .nonce = @splat('n'),
    .verifier = @splat('v'),
    .challenge = @splat('c'),
};

fn parse(arena: *std.heap.ArenaAllocator, target: []const u8) !Callback {
    return parseCallback(arena.allocator(), target, "/auth/callback", &attempt);
}

test "parseCallback decodes the code and keeps every pair" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const callback = try parse(&arena, "/auth/callback?code=one%2Btwo&state=" ++ good_state ++ "&client_id=oaiapp_test&scope=openid+email");
    try std.testing.expectEqualStrings("one+two", callback.code());
    try std.testing.expectEqualStrings("oaiapp_test", callback.get("client_id").?);
    try std.testing.expectEqualStrings("openid email", callback.get("scope").?);
    try std.testing.expect(callback.get("missing") == null);
}

test "parseCallback checks state before it honours an error parameter" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.StateMismatch, parse(&arena, "/auth/callback?error=access_denied&state=" ++ other_state));
    try std.testing.expectError(error.StateMismatch, parse(&arena, "/auth/callback?error=access_denied&state=short"));
    try std.testing.expectError(error.MissingState, parse(&arena, "/auth/callback?error=access_denied"));
    try std.testing.expectError(error.AuthorizationRefused, parse(&arena, "/auth/callback?error=access_denied&state=" ++ good_state));
}

test "parseCallback refuses a wrong path, a missing code and bad encoding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.WrongPath, parse(&arena, "/other?code=x&state=" ++ good_state));
    try std.testing.expectError(error.MissingCode, parse(&arena, "/auth/callback?state=" ++ good_state));
    try std.testing.expectError(error.MissingCode, parse(&arena, "/auth/callback?code=&state=" ++ good_state));
    try std.testing.expectError(error.MissingState, parse(&arena, "/auth/callback"));
    try std.testing.expectError(error.BadEncoding, parse(&arena, "/auth/callback?code=%G1&state=" ++ good_state));
    try std.testing.expectError(error.BadEncoding, parse(&arena, "/auth/callback?code=%4&state=" ++ good_state));
}
