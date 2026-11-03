const std = @import("std");
const url = @import("url.zig");
const transport_mod = @import("transport.zig");
const client_mod = @import("client.zig");
const FakeTransport = @import("testing.zig").FakeTransport;

const Allocator = std.mem.Allocator;
const Param = url.Param;
const Response = transport_mod.Response;
const SendError = transport_mod.SendError;
const Client = client_mod.Client;
const Call = client_mod.Call;

pub const ErrorCode = enum {
    invalid_request,
    invalid_client,
    invalid_grant,
    unauthorized_client,
    unsupported_grant_type,
    invalid_scope,
    authorization_pending,
    slow_down,
    access_denied,
    expired_token,
    unsupported_token_type,
    other,

    pub fn parse(text: []const u8) ErrorCode {
        return std.meta.stringToEnum(ErrorCode, text) orelse .other;
    }
};

pub const TokenError = SendError || error{
    TokenRefused,
    ServerRefused,
    MalformedResponse,
    ConfidentialClientRequired,
    EndpointMissing,
};

pub const Fields = struct {
    access_token: []const u8,
    token_type: []const u8,
    expires_in: ?i64 = null,
    refresh_token: ?[]const u8 = null,
    scope: ?[]const u8 = null,
    id_token: ?[]const u8 = null,
};

pub const TokenSet = struct {
    gpa: Allocator,
    /// The raw response body. Strings in `parsed` point into it when they have no escapes.
    bytes: []u8,
    parsed: std.json.Parsed(Fields),

    pub fn value(self: TokenSet) Fields {
        return self.parsed.value;
    }

    /// The result can hold copies of token strings. The caller must wipe the arena when done.
    pub fn extension(self: TokenSet, arena: Allocator, comptime T: type) error{ MalformedResponse, OutOfMemory }!T {
        return std.json.parseFromSliceLeaky(T, arena, self.bytes, .{ .ignore_unknown_fields = true }) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.MalformedResponse,
        };
    }

    /// Strings with JSON escapes are copied out of `bytes` into the parse arena.
    fn wipeCopies(self: TokenSet) void {
        const fields = self.parsed.value;
        inline for (.{ fields.access_token, fields.token_type, fields.refresh_token, fields.scope, fields.id_token }) |field| {
            const text: []const u8 = if (@typeInfo(@TypeOf(field)) == .optional) field orelse "" else field;
            const start = @intFromPtr(text.ptr);
            const base = @intFromPtr(self.bytes.ptr);
            if (start < base or start >= base + self.bytes.len) {
                std.crypto.secureZero(u8, @constCast(text));
            }
        }
    }

    pub fn deinit(self: *TokenSet) void {
        self.wipeCopies();
        self.parsed.deinit();
        std.crypto.secureZero(u8, self.bytes);
        self.gpa.free(self.bytes);
        self.* = undefined;
    }
};

const ErrorBody = struct {
    @"error": ?[]const u8 = null,
};

pub fn postForm(gpa: Allocator, call: Call, endpoint: []const u8, params: []const Param) TokenError!Response {
    var auth_params: [2]Param = undefined;
    var auth_count: usize = 0;
    var authorization: ?[]u8 = null;
    defer if (authorization) |value| {
        std.crypto.secureZero(u8, value);
        gpa.free(value);
    };
    switch (call.client.auth) {
        .none => {
            auth_params[0] = .{ .name = "client_id", .value = call.client.id };
            auth_count = 1;
        },
        .secret_post => |secret| {
            auth_params[0] = .{ .name = "client_id", .value = call.client.id };
            auth_params[1] = .{ .name = "client_secret", .value = secret };
            auth_count = 2;
        },
        .secret_basic => |secret| authorization = try basicHeader(gpa, call.client.id, secret),
    }

    const body = try url.formBody(gpa, &.{ params, auth_params[0..auth_count], call.extra });
    defer {
        std.crypto.secureZero(u8, body);
        gpa.free(body);
    }
    var headers: [2]std.http.Header = .{
        .{ .name = "Accept", .value = "application/json" },
        undefined,
    };
    var header_count: usize = 1;
    if (authorization) |value| {
        headers[1] = .{ .name = "Authorization", .value = value };
        header_count = 2;
    }
    return call.transport.send(gpa, .{
        .method = .POST,
        .url = endpoint,
        .headers = headers[0..header_count],
        .content_type = "application/x-www-form-urlencoded",
        .body = body,
    });
}

/// RFC 6749 section 2.3.1 form encodes the id and secret before base64.
fn basicHeader(gpa: Allocator, id: []const u8, secret: []const u8) Allocator.Error![]u8 {
    const plain = try gpa.alloc(u8, url.encodedLen(id) + 1 + url.encodedLen(secret));
    defer {
        std.crypto.secureZero(u8, plain);
        gpa.free(plain);
    }
    var at = url.writeEncoded(plain, id);
    plain[at] = ':';
    at += 1;
    at += url.writeEncoded(plain[at..], secret);
    std.debug.assert(at == plain.len);
    const encoder = std.base64.standard.Encoder;
    const out = try gpa.alloc(u8, "Basic ".len + encoder.calcSize(plain.len));
    @memcpy(out[0.."Basic ".len], "Basic ");
    _ = encoder.encode(out["Basic ".len..], plain);
    return out;
}

pub fn refusal(gpa: Allocator, response: *Response, error_code: ?*ErrorCode) TokenError {
    defer response.deinit(gpa);
    if (response.status != 400 and response.status != 401 and !response.isSuccess()) return error.ServerRefused;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const parsed = std.json.parseFromSliceLeaky(ErrorBody, arena.allocator(), response.body, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.ServerRefused,
    };
    const text = parsed.@"error" orelse return error.ServerRefused;
    if (error_code) |out| out.* = ErrorCode.parse(text);
    return error.TokenRefused;
}

pub fn readTokenSet(gpa: Allocator, response: Response, error_code: ?*ErrorCode) TokenError!TokenSet {
    var owned = response;
    if (!owned.isSuccess()) return refusal(gpa, &owned, error_code);
    const refused = hasErrorField(gpa, owned.body) catch |err| {
        owned.deinit(gpa);
        return err;
    };
    if (refused) return refusal(gpa, &owned, error_code);

    gpa.free(owned.head);
    errdefer {
        std.crypto.secureZero(u8, owned.body);
        gpa.free(owned.body);
    }
    const parsed = std.json.parseFromSlice(Fields, gpa, owned.body, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    return .{ .gpa = gpa, .bytes = owned.body, .parsed = parsed };
}

/// Some servers send an error with a 2xx status. GitHub does this while a device login waits.
pub fn hasErrorField(gpa: Allocator, body: []const u8) Allocator.Error!bool {
    var scanner = std.json.Scanner.initCompleteInput(gpa, body);
    defer scanner.deinit();
    var has_error = false;
    var has_token = false;
    const first = scanner.next() catch |err| return skipMalformed(err);
    if (first != .object_begin) return false;
    while (true) {
        const key = scanner.nextAlloc(gpa, .alloc_if_needed) catch |err| return skipMalformed(err);
        switch (key) {
            .object_end => break,
            .string => |name| noteKey(name, &has_error, &has_token),
            .allocated_string => |name| {
                defer gpa.free(name);
                noteKey(name, &has_error, &has_token);
            },
            else => return false,
        }
        scanner.skipValue() catch |err| return skipMalformed(err);
    }
    return has_error and !has_token;
}

/// A body that is not valid JSON has no error field.
fn skipMalformed(err: (std.json.Scanner.NextError || std.json.Scanner.AllocError)) Allocator.Error!bool {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => false,
    };
}

fn noteKey(name: []const u8, has_error: *bool, has_token: *bool) void {
    if (std.mem.eql(u8, name, "error")) has_error.* = true;
    if (std.mem.eql(u8, name, "access_token")) has_token.* = true;
}

pub fn exchangeCode(gpa: Allocator, call: Call, code: []const u8, verifier: []const u8, redirect_uri: []const u8) TokenError!TokenSet {
    const response = try postForm(gpa, call, call.endpoints.token, &.{
        .{ .name = "grant_type", .value = "authorization_code" },
        .{ .name = "code", .value = code },
        .{ .name = "code_verifier", .value = verifier },
        .{ .name = "redirect_uri", .value = redirect_uri },
    });
    return readTokenSet(gpa, response, call.error_code);
}

pub fn refresh(gpa: Allocator, call: Call, refresh_token: []const u8) TokenError!TokenSet {
    const response = try postForm(gpa, call, call.endpoints.token, &.{
        .{ .name = "grant_type", .value = "refresh_token" },
        .{ .name = "refresh_token", .value = refresh_token },
    });
    return readTokenSet(gpa, response, call.error_code);
}

pub fn clientCredentials(gpa: Allocator, call: Call, scope: []const u8) TokenError!TokenSet {
    if (call.client.auth == .none) return error.ConfidentialClientRequired;
    const params: [2]Param = .{
        .{ .name = "grant_type", .value = "client_credentials" },
        .{ .name = "scope", .value = scope },
    };
    const count: usize = if (scope.len == 0) 1 else 2;
    const response = try postForm(gpa, call, call.endpoints.token, params[0..count]);
    return readTokenSet(gpa, response, call.error_code);
}

const testing = std.testing;
const token_json =
    \\{"access_token":"at","token_type":"Bearer","expires_in":3600,"refresh_token":"rt","scope":"a b","id_token":"x.y.z","earliest_refresh_at":42}
;

fn testCall(fake: *FakeTransport, auth: Client.Auth, error_code: ?*ErrorCode) Call {
    return .{
        .transport = fake.transport(),
        .endpoints = .{ .token = "https://auth.example/token" },
        .client = .{ .id = "client-1", .auth = auth },
        .extra = &.{.{ .name = "resource", .value = "https://r.example/" }},
        .error_code = error_code,
    };
}

test "exchangeCode sends the exact form and returns the fields" {
    var fake = FakeTransport.init(testing.allocator, &.{.{ .body = token_json }});
    defer fake.deinit();
    var set = try exchangeCode(testing.allocator, testCall(&fake, .none, null), "the code", "verifier", "http://127.0.0.1:9/cb");
    defer set.deinit();
    const sent = fake.sent.items[0];
    try testing.expectEqual(std.http.Method.POST, sent.method);
    try testing.expectEqualStrings("https://auth.example/token", sent.url);
    try testing.expectEqualStrings(
        "grant_type=authorization_code&code=the%20code&code_verifier=verifier" ++
            "&redirect_uri=http%3A%2F%2F127.0.0.1%3A9%2Fcb&client_id=client-1&resource=https%3A%2F%2Fr.example%2F",
        sent.body.?,
    );
    try testing.expectEqualStrings("application/x-www-form-urlencoded", sent.content_type.?);
    try testing.expectEqualStrings("application/json", sent.header("accept").?);
    try testing.expect(sent.header("authorization") == null);
    try testing.expectEqualStrings("at", set.value().access_token);
    try testing.expectEqualStrings("rt", set.value().refresh_token.?);
    try testing.expectEqual(@as(?i64, 3600), set.value().expires_in);
    try testing.expectEqualStrings("x.y.z", set.value().id_token.?);
}

test "extension reads provider fields from the same body" {
    var fake = FakeTransport.init(testing.allocator, &.{.{ .body = token_json }});
    defer fake.deinit();
    var set = try refresh(testing.allocator, testCall(&fake, .none, null), "old");
    defer set.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const Extra = struct { earliest_refresh_at: ?i64 = null };
    try testing.expectEqual(@as(?i64, 42), (try set.extension(arena.allocator(), Extra)).earliest_refresh_at);
    try testing.expectEqualStrings(
        "grant_type=refresh_token&refresh_token=old&client_id=client-1&resource=https%3A%2F%2Fr.example%2F",
        fake.sent.items[0].body.?,
    );
}

test "secret_basic sends an encoded Basic header and no client_id" {
    var fake = FakeTransport.init(testing.allocator, &.{ .{ .body = token_json }, .{ .body = token_json } });
    defer fake.deinit();
    var one = try clientCredentials(testing.allocator, testCall(&fake, .{ .secret_basic = "s3cret" }, null), "");
    defer one.deinit();
    try testing.expectEqualStrings("Basic Y2xpZW50LTE6czNjcmV0", fake.sent.items[0].header("authorization").?);
    try testing.expectEqualStrings("grant_type=client_credentials&resource=https%3A%2F%2Fr.example%2F", fake.sent.items[0].body.?);

    var odd = testCall(&fake, .{ .secret_basic = "p&q" }, null);
    odd.client.id = "a b";
    var two = try clientCredentials(testing.allocator, odd, "x");
    defer two.deinit();
    try testing.expectEqualStrings("Basic YSUyMGI6cCUyNnE=", fake.sent.items[1].header("authorization").?);
}

test "secret_post puts the secret in the body" {
    var fake = FakeTransport.init(testing.allocator, &.{.{ .body = token_json }});
    defer fake.deinit();
    var set = try clientCredentials(testing.allocator, testCall(&fake, .{ .secret_post = "s3cret" }, null), "read");
    defer set.deinit();
    try testing.expectEqualStrings(
        "grant_type=client_credentials&scope=read&client_id=client-1&client_secret=s3cret&resource=https%3A%2F%2Fr.example%2F",
        fake.sent.items[0].body.?,
    );
}

test "clientCredentials refuses a public client without a request" {
    var fake = FakeTransport.init(testing.allocator, &.{});
    defer fake.deinit();
    try testing.expectError(error.ConfidentialClientRequired, clientCredentials(testing.allocator, testCall(&fake, .none, null), ""));
    try testing.expectEqual(@as(usize, 0), fake.sent.items.len);
}

test "an RFC 6749 error body is TokenRefused with its code" {
    var code: ErrorCode = .other;
    var fake = FakeTransport.init(testing.allocator, &.{
        .{ .status = 400, .body = "{\"error\":\"invalid_grant\",\"error_description\":\"secret text\"}" },
        .{ .status = 200, .body = "{\"error\":\"authorization_pending\"}" },
        .{ .status = 401, .body = "{\"error\":\"something_new\"}" },
    });
    defer fake.deinit();
    try testing.expectError(error.TokenRefused, refresh(testing.allocator, testCall(&fake, .none, &code), "rt"));
    try testing.expectEqual(ErrorCode.invalid_grant, code);
    try testing.expectError(error.TokenRefused, refresh(testing.allocator, testCall(&fake, .none, &code), "rt"));
    try testing.expectEqual(ErrorCode.authorization_pending, code);
    try testing.expectError(error.TokenRefused, refresh(testing.allocator, testCall(&fake, .none, &code), "rt"));
    try testing.expectEqual(ErrorCode.other, code);
}

test "other failures are ServerRefused or MalformedResponse" {
    var fake = FakeTransport.init(testing.allocator, &.{
        .{ .status = 500, .body = "{\"error\":\"invalid_grant\"}" },
        .{ .status = 400, .body = "not json" },
        .{ .status = 200, .body = "not json" },
        .{ .status = 302, .head = "Location: https://evil.example/\r\n" },
    });
    defer fake.deinit();
    try testing.expectError(error.ServerRefused, refresh(testing.allocator, testCall(&fake, .none, null), "rt"));
    try testing.expectError(error.ServerRefused, refresh(testing.allocator, testCall(&fake, .none, null), "rt"));
    try testing.expectError(error.MalformedResponse, refresh(testing.allocator, testCall(&fake, .none, null), "rt"));
    try testing.expectError(error.ServerRefused, refresh(testing.allocator, testCall(&fake, .none, null), "rt"));
}

test "an unsafe token endpoint sends nothing" {
    var fake = FakeTransport.init(testing.allocator, &.{.{ .body = token_json }});
    defer fake.deinit();
    var unsafe = testCall(&fake, .none, null);
    unsafe.endpoints.token = "http://auth.example/token";
    try testing.expectError(error.UrlNotSafe, refresh(testing.allocator, unsafe, "rt"));
    try testing.expectEqual(@as(usize, 0), fake.sent.items.len);
}

test "a 2xx body with error and access_token is a token" {
    var fake = FakeTransport.init(testing.allocator, &.{.{ .body = "{\"error\":\"x\",\"access_token\":\"at\",\"token_type\":\"Bearer\"}" }});
    defer fake.deinit();
    var set = try refresh(testing.allocator, testCall(&fake, .none, null), "rt");
    defer set.deinit();
    try testing.expectEqualStrings("at", set.value().access_token);
}

test "a 2xx body without a token is MalformedResponse" {
    var fake = FakeTransport.init(testing.allocator, &.{.{ .body = "{}" }});
    defer fake.deinit();
    try testing.expectError(error.MalformedResponse, refresh(testing.allocator, testCall(&fake, .none, null), "rt"));
}

test "an escaped token string is read and wiped without a leak" {
    var fake = FakeTransport.init(testing.allocator, &.{.{ .body = "{\"access_token\":\"a\\/b\",\"token_type\":\"Bearer\"}" }});
    defer fake.deinit();
    var set = try refresh(testing.allocator, testCall(&fake, .none, null), "rt");
    defer set.deinit();
    try testing.expectEqualStrings("a/b", set.value().access_token);
}

fn refreshWith(gpa: Allocator, reply: FakeTransport.Reply) !void {
    var fake = FakeTransport.init(gpa, &.{reply});
    defer fake.deinit();
    var set = refresh(gpa, testCall(&fake, .none, null), "rt") catch |err| switch (err) {
        error.TokenRefused => return,
        else => return err,
    };
    set.deinit();
}

test "refresh returns OutOfMemory for each failed allocation" {
    try testing.checkAllAllocationFailures(testing.allocator, refreshWith, .{FakeTransport.Reply{ .body = token_json }});
    try testing.checkAllAllocationFailures(testing.allocator, refreshWith, .{FakeTransport.Reply{ .status = 200, .body = "{\"error\":\"slow_down\"}" }});
    try testing.checkAllAllocationFailures(testing.allocator, refreshWith, .{FakeTransport.Reply{ .status = 400, .body = "{\"error\":\"invalid_grant\"}" }});
}
