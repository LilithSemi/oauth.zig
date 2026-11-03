//! OpenAI agent login. A first login gets a client id issued in the callback,
//! and later logins must keep that client id.

const std = @import("std");
const core = @import("oauth-core");

const Allocator = std.mem.Allocator;
const testing = std.testing;

pub const issuer = "https://auth.openai.com";
pub const endpoints: core.Endpoints = .{
    .authorization = "https://auth.openai.com/api/accounts/authorize",
    .token = "https://auth.openai.com/api/accounts/oauth/token",
};
pub const jwks_uri = "https://auth.openai.com/.well-known/jwks.json";
/// Pass in `oidc.Expect.algs` to verify an ID token from this issuer.
pub const algs: []const core.jwk.Alg = &.{.RS256};
pub const resource = "https://api.openai.com/v1";
pub const scopes = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
pub const initial_client_id = "dynamic_agent_client";

/// Send with every token request.
pub const token_extra: []const core.Param = &.{.{ .name = "resource", .value = resource }};

pub const Registration = union(enum) {
    initial: Initial,
    stored: Stored,

    pub const Initial = struct {
        agent_name: []const u8,
        /// From `hostId`. Store it and use it again on every later login.
        host_id: []const u8,
    };

    pub const Stored = struct {
        client_id: []const u8,
        host_id: []const u8,
        id_token_hint: ?[]const u8 = null,
        login_hint: ?[]const u8 = null,
    };

    pub fn clientId(self: Registration) []const u8 {
        return switch (self) {
            .initial => initial_client_id,
            .stored => |stored| stored.client_id,
        };
    }

    pub fn client(self: Registration) core.Client {
        return .{ .id = self.clientId() };
    }
};

pub fn authorizeOptions(registration: Registration, redirect_uri: []const u8, buffer: *[6]core.Param) core.authorize.Options {
    var count: usize = 0;
    switch (registration) {
        .initial => |initial| {
            buffer[count] = .{ .name = "agent_name_hint", .value = initial.agent_name };
            count += 1;
            buffer[count] = .{ .name = "ext_agent_host_id", .value = initial.host_id };
            count += 1;
        },
        .stored => |stored| {
            buffer[count] = .{ .name = "ext_agent_host_id", .value = stored.host_id };
            count += 1;
            if (stored.login_hint) |value| {
                buffer[count] = .{ .name = "login_hint", .value = value };
                count += 1;
            }
            if (stored.id_token_hint) |value| {
                buffer[count] = .{ .name = "id_token_hint", .value = value };
                count += 1;
            }
        },
    }
    buffer[count] = token_extra[0];
    count += 1;
    return .{
        .redirect_uri = redirect_uri,
        .scope = scopes,
        .send_nonce = true,
        .extra = buffer[0..count],
    };
}

/// Returns the client id for the code exchange, every refresh and the ID token audience.
pub fn issuedClientId(registration: Registration, callback: core.Callback) error{ MissingIssuedClientId, ClientIdChanged }![]const u8 {
    const given = callback.get("client_id");
    return switch (registration) {
        .initial => given orelse error.MissingIssuedClientId,
        .stored => |stored| {
            if (given) |value| if (!std.mem.eql(u8, value, stored.client_id)) return error.ClientIdChanged;
            return stored.client_id;
        },
    };
}

pub const Extension = struct {
    earliest_refresh_at: ?i64 = null,
};

pub fn hasInferenceScope(scope: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, scope, ' ');
    while (it.next()) |one| if (std.mem.eql(u8, one, "chatgpt.tokens.use.direct")) return true;
    return false;
}

pub fn hostId(gpa: Allocator, io: std.Io) Allocator.Error![]u8 {
    var raw: [16]u8 = undefined;
    io.random(&raw);
    raw[6] = (raw[6] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    const hex = std.fmt.bytesToHex(raw, .lower);
    return std.fmt.allocPrint(gpa, "urn:uuid:{s}-{s}-{s}-{s}-{s}", .{ hex[0..8], hex[8..12], hex[12..16], hex[16..20], hex[20..32] });
}

fn callbackWith(pairs: []const core.Param) core.Callback {
    return .{ .pairs = pairs };
}

test "a first login sends the agent hint and needs an issued client id" {
    const registration: Registration = .{ .initial = .{ .agent_name = "Chock", .host_id = "urn:uuid:h" } };
    var buffer: [6]core.Param = undefined;
    const options = authorizeOptions(registration, "http://127.0.0.1:1455/auth/callback", &buffer);
    try testing.expect(options.send_nonce);
    try testing.expectEqualStrings(scopes, options.scope);
    try testing.expectEqualStrings("agent_name_hint", options.extra[0].name);
    try testing.expectEqualStrings("ext_agent_host_id", options.extra[1].name);
    try testing.expectEqualStrings("resource", options.extra[options.extra.len - 1].name);
    try testing.expectEqualStrings(initial_client_id, registration.clientId());

    try testing.expectEqualStrings("oaiapp_1", try issuedClientId(registration, callbackWith(&.{.{ .name = "client_id", .value = "oaiapp_1" }})));
    try testing.expectError(error.MissingIssuedClientId, issuedClientId(registration, callbackWith(&.{})));
}

test "a later login keeps its client id and refuses a change" {
    const registration: Registration = .{ .stored = .{
        .client_id = "oaiapp_1",
        .host_id = "urn:uuid:h",
        .login_hint = "person@example.com",
    } };
    var buffer: [6]core.Param = undefined;
    const options = authorizeOptions(registration, "http://127.0.0.1:1455/auth/callback", &buffer);
    for (options.extra) |param| try testing.expect(!std.mem.eql(u8, param.name, "agent_name_hint"));
    try testing.expectEqualStrings("login_hint", options.extra[1].name);

    try testing.expectEqualStrings("oaiapp_1", try issuedClientId(registration, callbackWith(&.{})));
    try testing.expectEqualStrings("oaiapp_1", try issuedClientId(registration, callbackWith(&.{.{ .name = "client_id", .value = "oaiapp_1" }})));
    try testing.expectError(error.ClientIdChanged, issuedClientId(registration, callbackWith(&.{.{ .name = "client_id", .value = "oaiapp_2" }})));
}

test "hasInferenceScope finds the direct token scope" {
    try testing.expect(hasInferenceScope(scopes));
    try testing.expect(!hasInferenceScope("openid email"));
}

test "hostId is a version 4 urn uuid" {
    const id = try hostId(testing.allocator, testing.io);
    defer testing.allocator.free(id);
    try testing.expectEqual(@as(usize, "urn:uuid:".len + 36), id.len);
    try testing.expect(std.mem.startsWith(u8, id, "urn:uuid:"));
    try testing.expectEqual(@as(u8, '4'), id["urn:uuid:".len + 14]);
}

test "the preset endpoints pass the URL check" {
    try core.checkUrl(endpoints.authorization.?);
    try core.checkUrl(endpoints.token);
    try core.checkUrl(jwks_uri);
}
