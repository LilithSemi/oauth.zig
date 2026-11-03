//! Anthropic login for a client that Anthropic registered. The caller gives
//! the client id, endpoints and scopes from that registration.

const std = @import("std");
const core = @import("oauth-core");

const testing = std.testing;

pub const Config = struct {
    client_id: []const u8,
    endpoints: core.Endpoints,
    scopes: []const u8,
    extra: []const core.Param = &.{},

    pub fn check(self: Config) core.UrlError!void {
        if (self.endpoints.authorization) |one| try core.checkUrl(one);
        try core.checkUrl(self.endpoints.token);
        if (self.endpoints.revocation) |one| try core.checkUrl(one);
        if (self.endpoints.device_authorization) |one| try core.checkUrl(one);
    }

    pub fn client(self: Config) core.Client {
        return .{ .id = self.client_id };
    }

    pub fn authorizeOptions(self: Config, redirect_uri: []const u8) core.authorize.Options {
        return .{ .redirect_uri = redirect_uri, .scope = self.scopes, .extra = self.extra };
    }
};

const config: Config = .{
    .client_id = "registered-client",
    .endpoints = .{ .authorization = "https://auth.example/authorize", .token = "https://auth.example/token" },
    .scopes = "a b",
};

test "Config gives a public client and authorize options from its own values" {
    try config.check();
    try testing.expectEqualStrings("registered-client", config.client().id);
    try testing.expect(config.client().auth == .none);
    const options = config.authorizeOptions("http://127.0.0.1:9/cb");
    try testing.expectEqualStrings("a b", options.scope);
    try testing.expectEqualStrings("http://127.0.0.1:9/cb", options.redirect_uri);
}

test "Config.check refuses an unsafe endpoint" {
    var bad = config;
    bad.endpoints.token = "http://auth.example/token";
    try testing.expectError(error.UrlNotSafe, bad.check());
}
