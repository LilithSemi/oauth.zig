const std = @import("std");
const url = @import("url.zig");
const Client = @import("client.zig").Client;
const Attempt = @import("pkce.zig").Attempt;

const Allocator = std.mem.Allocator;
const Param = url.Param;

pub const Options = struct {
    redirect_uri: []const u8,
    scope: []const u8 = "",
    send_nonce: bool = false,
    extra: []const Param = &.{},
};

pub fn authorizeUrl(
    gpa: Allocator,
    endpoint: []const u8,
    client: Client,
    attempt: *const Attempt,
    options: Options,
) (url.UrlError || Allocator.Error)![]u8 {
    try url.checkUrl(endpoint);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, endpoint);
    try out.append(gpa, if (std.mem.indexOfScalar(u8, endpoint, '?') == null) '?' else '&');
    try url.appendParam(gpa, &out, .{ .name = "response_type", .value = "code" });
    try url.appendParam(gpa, &out, .{ .name = "client_id", .value = client.id });
    try url.appendParam(gpa, &out, .{ .name = "redirect_uri", .value = options.redirect_uri });
    if (options.scope.len != 0) try url.appendParam(gpa, &out, .{ .name = "scope", .value = options.scope });
    try url.appendParam(gpa, &out, .{ .name = "state", .value = &attempt.state });
    if (options.send_nonce) try url.appendParam(gpa, &out, .{ .name = "nonce", .value = &attempt.nonce });
    try url.appendParam(gpa, &out, .{ .name = "code_challenge_method", .value = "S256" });
    try url.appendParam(gpa, &out, .{ .name = "code_challenge", .value = &attempt.challenge });
    for (options.extra) |param| try url.appendParam(gpa, &out, param);
    return out.toOwnedSlice(gpa);
}

const s43: [43]u8 = @splat('s');
const n43: [43]u8 = @splat('n');
const c43: [43]u8 = @splat('c');

const fixed_attempt: Attempt = .{
    .state = s43,
    .nonce = n43,
    .verifier = @splat('v'),
    .challenge = c43,
};

test "authorizeUrl carries the code flow, PKCE and the encoded callback" {
    const gpa = std.testing.allocator;
    const text = try authorizeUrl(gpa, "https://auth.example/authorize", .{ .id = "client-1" }, &fixed_attempt, .{
        .redirect_uri = "http://127.0.0.1:1234/cb",
        .scope = "read write",
    });
    defer gpa.free(text);
    try std.testing.expectEqualStrings(
        "https://auth.example/authorize?response_type=code&client_id=client-1" ++
            "&redirect_uri=http%3A%2F%2F127.0.0.1%3A1234%2Fcb&scope=read%20write" ++
            "&state=" ++ s43 ++ "&code_challenge_method=S256&code_challenge=" ++ c43,
        text,
    );
}

test "authorizeUrl keeps an existing query, sends the nonce on request and appends extras" {
    const gpa = std.testing.allocator;
    const text = try authorizeUrl(gpa, "https://auth.example/authorize?tenant=a", .{ .id = "c" }, &fixed_attempt, .{
        .redirect_uri = "https://app.example/cb",
        .send_nonce = true,
        .extra = &.{.{ .name = "resource", .value = "https://mcp.example/mcp" }},
    });
    defer gpa.free(text);
    try std.testing.expect(std.mem.startsWith(u8, text, "https://auth.example/authorize?tenant=a&response_type=code&"));
    try std.testing.expect(std.mem.indexOf(u8, text, "&nonce=" ++ n43) != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "scope=") == null);
    try std.testing.expect(std.mem.endsWith(u8, text, "&resource=https%3A%2F%2Fmcp.example%2Fmcp"));
}

test "authorizeUrl refuses an unsafe endpoint" {
    try std.testing.expectError(error.UrlNotSafe, authorizeUrl(std.testing.allocator, "http://auth.example/authorize", .{ .id = "c" }, &fixed_attempt, .{
        .redirect_uri = "https://app.example/cb",
    }));
}
