const std = @import("std");
const url = @import("url.zig");
const jwk = @import("jwk.zig");
const transport_mod = @import("transport.zig");
const Endpoints = @import("client.zig").Endpoints;
const FakeTransport = @import("testing.zig").FakeTransport;

const Allocator = std.mem.Allocator;
const Transport = transport_mod.Transport;
const SendError = transport_mod.SendError;

pub const Metadata = struct {
    issuer: []const u8,
    authorization_endpoint: []const u8,
    token_endpoint: []const u8,
    jwks_uri: []const u8,
    device_authorization_endpoint: ?[]const u8 = null,
    revocation_endpoint: ?[]const u8 = null,
    code_challenge_methods_supported: []const []const u8 = &.{},

    pub fn endpoints(self: Metadata) Endpoints {
        return .{
            .authorization = self.authorization_endpoint,
            .token = self.token_endpoint,
            .device_authorization = self.device_authorization_endpoint,
            .revocation = self.revocation_endpoint,
        };
    }
};

pub const DiscoverError = SendError || error{ ServerRefused, MalformedResponse, IssuerMismatch };

pub fn discover(arena: Allocator, transport: Transport, issuer: []const u8) DiscoverError!Metadata {
    try url.checkUrl(issuer);
    const base = std.mem.trimEnd(u8, issuer, "/");
    const location = try std.fmt.allocPrint(arena, "{s}/.well-known/openid-configuration", .{base});
    const body = try getBody(arena, transport, location);
    const metadata = std.json.parseFromSliceLeaky(Metadata, arena, body, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    if (!std.mem.eql(u8, metadata.issuer, issuer)) return error.IssuerMismatch;
    try url.checkUrl(metadata.authorization_endpoint);
    try url.checkUrl(metadata.token_endpoint);
    try url.checkUrl(metadata.jwks_uri);
    if (metadata.device_authorization_endpoint) |one| try url.checkUrl(one);
    if (metadata.revocation_endpoint) |one| try url.checkUrl(one);
    return metadata;
}

pub fn fetchJwks(arena: Allocator, transport: Transport, jwks_uri: []const u8) DiscoverError![]const u8 {
    return getBody(arena, transport, jwks_uri);
}

fn getBody(arena: Allocator, transport: Transport, location: []const u8) DiscoverError![]const u8 {
    const response = try transport.send(arena, .{
        .method = .GET,
        .url = location,
        .headers = &.{.{ .name = "Accept", .value = "application/json" }},
    });
    if (!response.isSuccess()) return error.ServerRefused;
    return response.body;
}

pub const Expect = struct {
    issuer: []const u8,
    client_id: []const u8,
    nonce: []const u8,
    now: i64,
    algs: []const jwk.Alg = jwk.default_algs,
};

pub const Claims = struct {
    iss: []const u8,
    /// OIDC allows one audience string or an array of them.
    aud: std.json.Value,
    sub: []const u8,
    email: ?[]const u8 = null,
    nonce: []const u8,
    exp: i64,
    iat: i64,
};

pub const VerifyError = jwk.VerifyError || error{
    MalformedIdToken,
    WrongIssuer,
    WrongAudience,
    WrongNonce,
    TokenExpired,
    TokenIssuedInFuture,
};

pub const Verified = struct {
    subject: []const u8,
    email: ?[]const u8,
    /// The decoded claims JSON, for provider claims.
    payload: []const u8,
};

const clock_skew_seconds = 60;

pub fn verifyIdToken(arena: Allocator, id_token: []const u8, jwks: []const u8, expect_values: Expect) VerifyError!Verified {
    const verified = try jwk.verify(arena, id_token, jwks, expect_values.algs);
    const claims = std.json.parseFromSliceLeaky(Claims, arena, verified.payload, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedIdToken,
    };
    try checkClaims(claims, expect_values);
    return .{ .subject = claims.sub, .email = claims.email, .payload = verified.payload };
}

pub fn checkClaims(claims: Claims, expect_values: Expect) VerifyError!void {
    if (!std.mem.eql(u8, claims.iss, expect_values.issuer)) return error.WrongIssuer;
    if (!audienceHolds(claims.aud, expect_values.client_id)) return error.WrongAudience;
    if (!std.mem.eql(u8, claims.nonce, expect_values.nonce)) return error.WrongNonce;
    if (claims.exp <= expect_values.now) return error.TokenExpired;
    if (claims.iat > expect_values.now + clock_skew_seconds) return error.TokenIssuedInFuture;
}

fn audienceHolds(audience: std.json.Value, client_id: []const u8) bool {
    return switch (audience) {
        .string => |one| std.mem.eql(u8, one, client_id),
        .array => |many| for (many.items) |one| {
            if (one == .string and std.mem.eql(u8, one.string, client_id)) break true;
        } else false,
        else => false,
    };
}

const testing = std.testing;

const fixture_token =
    "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5IiwidHlwIjoiSldUIn0" ++
    ".eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoiY2xpZW50LTEiLCJzdWIiOiJzdWJqZWN0LTEiLCJlbWFpbCI6InBlcnNvbkBleGFtcGxlLmNvbSIsIm5vbmNlIjoibm9uY2UtMSIsImV4cCI6MjAwMDAwMDAwMCwiaWF0IjoxNzAwMDAwMDAwfQ" ++
    ".nVb7lDlW1VFnvdV8Kp6ucKtr2XGaYQQfPuTYDkBYXxskq7ya2ewng4yusWZg1N2M1BxjCVeHjUJXGq4YKp8odbM9ynzFEjeYnlYgJYyy5p5wkj0vOblIF-RISkLIebTXC1mUec5Jh6BALF-HfyhsCLAfJxIuMe_ykyNdQ79ChtcpFtWvM_VaLGI9Zyk0aMySsUn6eOpC4lnNxzlEEnkPlm2GRyHSDn4-Th_r3SUMcF5oLqdTD9sEDUVxBcU35KMaEETWXPEEZOWJHE3hAidu1wz9PUdQp_TAgD_BXykYakkqjSd8WSF0ApwycIjAWNfkLTcjuvalxms5dMUnHZxOzw";

const fixture_n = "qd_vtOL92CcNH_g-kzC_7x2ijlm08sH0f8NJ9vCMA-FrzlP2UcGW-cT3wZOwFU4BbVvl_1zYgCQSDNUUSCzoNayGjYXzllOjU2dzyNDTvHBcqYMvHyhAGfOADvJV7IfjEE58UHdNupqq6iR6o043gWsEJj6lCBo4QVC6hog_eQIdmYRmGxVw64dNGVs8LyPH30dFk4RDD9qz-oq6GtJFvUkfmmRxB2sAGzB-v7ovxZMbbnRXG5y03wUMwf7rW60Ha986nnAsUQuZHLoZCIumonQlqFsnd76bXl5Dob8KmrZ45OehgciIkkN1Z39zj346AV3pT1jgnE5Ek6srDA40Zw";

const fixture_jwks = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"test-key\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"" ++ fixture_n ++ "\",\"e\":\"AQAB\"}]}";

const expect: Expect = .{
    .issuer = "https://issuer.example",
    .client_id = "client-1",
    .nonce = "nonce-1",
    .now = 1_800_000_000,
};

test "verifyIdToken accepts the fixture token" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const verified = try verifyIdToken(arena.allocator(), fixture_token, fixture_jwks, expect);
    try testing.expectEqualStrings("subject-1", verified.subject);
    try testing.expectEqualStrings("person@example.com", verified.email.?);
    try testing.expect(std.mem.indexOf(u8, verified.payload, "\"nonce\":\"nonce-1\"") != null);
}

test "verifyIdToken refuses a changed signature, an unknown key and another algorithm" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const changed = try a.dupe(u8, fixture_token);
    const signature_at = std.mem.lastIndexOfScalar(u8, changed, '.').? + 1;
    changed[signature_at] = if (changed[signature_at] == 'n') 'm' else 'n';
    try testing.expectError(error.BadSignature, verifyIdToken(a, changed, fixture_jwks, expect));

    const other_kid = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"other\",\"alg\":\"RS256\",\"n\":\"" ++ fixture_n ++ "\",\"e\":\"AQAB\"}]}";
    try testing.expectError(error.SigningKeyNotFound, verifyIdToken(a, fixture_token, other_kid, expect));

    try testing.expectError(error.UnsupportedAlgorithm, verifyIdToken(a, "eyJhbGciOiJIUzI1NiJ9.e30.AA", fixture_jwks, expect));
    try testing.expectError(error.MalformedToken, verifyIdToken(a, "a.b", fixture_jwks, expect));
    try testing.expectError(error.MalformedToken, verifyIdToken(a, "a.b.c.d", fixture_jwks, expect));
    try testing.expectError(error.MalformedJwks, verifyIdToken(a, fixture_token, "not json", expect));
}

test "verifyIdToken applies the claim rules after the signature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var late = expect;
    late.now = 2_000_000_000;
    try testing.expectError(error.TokenExpired, verifyIdToken(arena.allocator(), fixture_token, fixture_jwks, late));
    var other_nonce = expect;
    other_nonce.nonce = "nonce-2";
    try testing.expectError(error.WrongNonce, verifyIdToken(arena.allocator(), fixture_token, fixture_jwks, other_nonce));
}

test "checkClaims takes an audience string or array and bounds iat" {
    var values: std.json.Array = .init(testing.allocator);
    defer values.deinit();
    try values.append(.{ .string = "another" });
    try values.append(.{ .string = "client-1" });
    var claims: Claims = .{
        .iss = "https://issuer.example",
        .aud = .{ .array = values },
        .sub = "s",
        .nonce = "nonce-1",
        .exp = expect.now + 1,
        .iat = expect.now + 60,
    };
    try checkClaims(claims, expect);

    claims.iat = expect.now + 61;
    try testing.expectError(error.TokenIssuedInFuture, checkClaims(claims, expect));
    claims.iat = expect.now;
    claims.exp = expect.now;
    try testing.expectError(error.TokenExpired, checkClaims(claims, expect));
    claims.exp = expect.now + 1;
    claims.aud = .{ .string = "another" };
    try testing.expectError(error.WrongAudience, checkClaims(claims, expect));
    claims.aud = .{ .integer = 1 };
    try testing.expectError(error.WrongAudience, checkClaims(claims, expect));
    claims.aud = .{ .string = "client-1" };
    claims.iss = "https://issuer.example/";
    try testing.expectError(error.WrongIssuer, checkClaims(claims, expect));
}

const metadata_json =
    \\{"issuer":"https://issuer.example","authorization_endpoint":"https://issuer.example/auth",
    \\"token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/jwks",
    \\"revocation_endpoint":"https://issuer.example/revoke"}
;

test "discover reads metadata from the well known path" {
    var fake = FakeTransport.init(testing.allocator, &.{ .{ .body = metadata_json }, .{ .body = metadata_json } });
    defer fake.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const one = try discover(arena.allocator(), fake.transport(), "https://issuer.example");
    // The issuer must match exactly, so a trailing slash is a different issuer.
    try testing.expectError(error.IssuerMismatch, discover(arena.allocator(), fake.transport(), "https://issuer.example/"));
    try testing.expectEqualStrings("https://issuer.example/.well-known/openid-configuration", fake.sent.items[0].url);
    try testing.expectEqualStrings("https://issuer.example/.well-known/openid-configuration", fake.sent.items[1].url);
    const endpoints = one.endpoints();
    try testing.expectEqualStrings("https://issuer.example/token", endpoints.token);
    try testing.expectEqualStrings("https://issuer.example/revoke", endpoints.revocation.?);
}

test "discover refuses another issuer and an unsafe endpoint" {
    var fake = FakeTransport.init(testing.allocator, &.{
        .{ .body = metadata_json },
        .{ .body = "{\"issuer\":\"https://issuer.example\",\"authorization_endpoint\":\"https://issuer.example/auth\",\"token_endpoint\":\"http://issuer.example/token\",\"jwks_uri\":\"https://issuer.example/jwks\"}" },
    });
    defer fake.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.IssuerMismatch, discover(arena.allocator(), fake.transport(), "https://other.example"));
    try testing.expectError(error.UrlNotSafe, discover(arena.allocator(), fake.transport(), "https://issuer.example"));
}

fn verifyFixture(gpa: Allocator) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    _ = try verifyIdToken(arena.allocator(), fixture_token, fixture_jwks, expect);
}

test "verifyIdToken returns OutOfMemory for each failed allocation" {
    try testing.checkAllAllocationFailures(testing.allocator, verifyFixture, .{});
}

test "verifyIdToken refuses an algorithm that is not in Expect.algs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var only_es256 = expect;
    only_es256.algs = &.{.ES256};
    try testing.expectError(error.UnsupportedAlgorithm, verifyIdToken(arena.allocator(), fixture_token, fixture_jwks, only_es256));
}
