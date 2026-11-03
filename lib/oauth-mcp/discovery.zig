const std = @import("std");
const core = @import("oauth-core");

const Allocator = std.mem.Allocator;
const FakeTransport = core.testing.FakeTransport;
const testing = std.testing;

const challenge = "WWW-Authenticate: Bearer realm=\"mcp\", resource_metadata=\"https://mcp.example/.well-known/oauth-protected-resource\"\r\n";
const resource_json = "{\"resource\":\"https://mcp.example/mcp\",\"authorization_servers\":[\"https://auth.example/tenant\"],\"scopes_supported\":[\"read\",\"write\"]}";

pub const Options = struct {
    client_name: []const u8,
    client_version: []const u8 = "1",
    protocol_version: []const u8 = "2025-06-18",
};

pub const Discovery = struct {
    resource_metadata_url: []const u8,
    resource: []const u8,
    issuer: []const u8,
    endpoints: core.Endpoints,
    scopes_supported: []const []const u8,
    registration_endpoint: ?[]const u8,
};

pub const DiscoverError = core.SendError || error{
    AuthorizationChallengeMissing,
    ResourceMetadataMissing,
    ResourceMetadataMismatch,
    NoAuthorizationServer,
    IssuerMismatch,
    PkceS256Unsupported,
    ServerRefused,
    MalformedResponse,
};

const ProtectedResource = struct {
    resource: []const u8,
    authorization_servers: []const []const u8,
    scopes_supported: []const []const u8 = &.{},
};

const AuthorizationServer = struct {
    issuer: []const u8,
    authorization_endpoint: []const u8,
    token_endpoint: []const u8,
    registration_endpoint: ?[]const u8 = null,
    revocation_endpoint: ?[]const u8 = null,
    code_challenge_methods_supported: []const []const u8 = &.{},
};

pub fn discover(arena: Allocator, transport: core.Transport, resource_url: []const u8, options: Options) DiscoverError!Discovery {
    const metadata_url = try challengeMetadataUrl(arena, transport, resource_url, options);

    const resource = try getJson(ProtectedResource, arena, transport, metadata_url);
    if (!std.mem.eql(u8, resource.resource, resource_url)) return error.ResourceMetadataMismatch;
    if (resource.authorization_servers.len == 0) return error.NoAuthorizationServer;
    const issuer = resource.authorization_servers[0];

    const server_url = try authorizationMetadataUrl(arena, issuer);
    const server = try getJson(AuthorizationServer, arena, transport, server_url);
    if (!std.mem.eql(u8, server.issuer, issuer)) return error.IssuerMismatch;
    try core.checkUrl(server.authorization_endpoint);
    try core.checkUrl(server.token_endpoint);
    if (server.registration_endpoint) |one| try core.checkUrl(one);
    if (server.revocation_endpoint) |one| try core.checkUrl(one);
    for (server.code_challenge_methods_supported) |method| {
        if (std.mem.eql(u8, method, "S256")) break;
    } else return error.PkceS256Unsupported;

    return .{
        .resource_metadata_url = metadata_url,
        .resource = resource.resource,
        .issuer = issuer,
        .endpoints = .{
            .authorization = server.authorization_endpoint,
            .token = server.token_endpoint,
            .revocation = server.revocation_endpoint,
        },
        .scopes_supported = resource.scopes_supported,
        .registration_endpoint = server.registration_endpoint,
    };
}

pub fn resourceParam(resource: []const u8) core.Param {
    return .{ .name = "resource", .value = resource };
}

pub fn scopeString(arena: Allocator, scopes: []const []const u8) Allocator.Error![]u8 {
    return std.mem.join(arena, " ", scopes);
}

fn challengeMetadataUrl(arena: Allocator, transport: core.Transport, resource_url: []const u8, options: Options) DiscoverError![]const u8 {
    const body = try std.json.Stringify.valueAlloc(arena, .{
        .jsonrpc = "2.0",
        .id = 1,
        .method = "initialize",
        .params = .{
            .protocolVersion = options.protocol_version,
            .capabilities = .{},
            .clientInfo = .{ .name = options.client_name, .version = options.client_version },
        },
    }, .{});
    const response = try transport.send(arena, .{
        .method = .POST,
        .url = resource_url,
        .headers = &.{
            .{ .name = "MCP-Protocol-Version", .value = options.protocol_version },
            .{ .name = "Accept", .value = "application/json, text/event-stream" },
        },
        .content_type = "application/json",
        .body = body,
    });
    if (response.status != 401) return error.AuthorizationChallengeMissing;
    const header = response.header("www-authenticate") orelse return error.ResourceMetadataMissing;
    const found = resourceMetadataIn(header) orelse return error.ResourceMetadataMissing;
    try core.checkUrl(found);
    return found;
}

fn resourceMetadataIn(header: []const u8) ?[]const u8 {
    const blanks = " \t";
    var rest = std.mem.trimStart(u8, header, blanks);
    rest = rest[std.mem.indexOfAny(u8, rest, blanks) orelse rest.len ..];
    while (rest.len > 0) {
        rest = std.mem.trimStart(u8, rest, ", \t");
        const name_end = std.mem.indexOfAny(u8, rest, "=, \t") orelse rest.len;
        const name = rest[0..name_end];
        rest = std.mem.trimStart(u8, rest[name_end..], blanks);
        if (rest.len == 0 or rest[0] != '=') {
            if (name.len == 0 and rest.len > 0) rest = rest[1..];
            continue;
        }
        rest = std.mem.trimStart(u8, rest[1..], blanks);
        var value: []const u8 = undefined;
        if (rest.len > 0 and rest[0] == '"') {
            var at: usize = 1;
            while (at < rest.len and rest[at] != '"') : (at += 1) {
                if (rest[at] == '\\') at += 1;
            }
            if (at >= rest.len) return null;
            value = rest[1..at];
            rest = rest[at + 1 ..];
        } else {
            const end = std.mem.indexOfAny(u8, rest, ", \t") orelse rest.len;
            value = rest[0..end];
            rest = rest[end..];
        }
        if (std.ascii.eqlIgnoreCase(name, "resource_metadata")) return value;
    }
    return null;
}

/// RFC 8414 section 3.1 puts the well known segment between the host and the issuer path.
fn authorizationMetadataUrl(arena: Allocator, issuer: []const u8) DiscoverError![]u8 {
    try core.checkUrl(issuer);
    const rest = issuer["https://".len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const path = std.mem.trimEnd(u8, rest[slash..], "/");
    return std.fmt.allocPrint(arena, "https://{s}/.well-known/oauth-authorization-server{s}", .{ rest[0..slash], path });
}

fn getJson(comptime T: type, arena: Allocator, transport: core.Transport, location: []const u8) DiscoverError!T {
    const response = try transport.send(arena, .{
        .method = .GET,
        .url = location,
        .headers = &.{.{ .name = "Accept", .value = "application/json" }},
    });
    if (!response.isSuccess()) return error.ServerRefused;
    return std.json.parseFromSliceLeaky(T, arena, response.body, .{ .ignore_unknown_fields = true }) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.MalformedResponse,
    };
}

const server_json =
    \\{"issuer":"https://auth.example/tenant","authorization_endpoint":"https://auth.example/authorize",
    \\"token_endpoint":"https://auth.example/token","registration_endpoint":"https://auth.example/register",
    \\"code_challenge_methods_supported":["S256"]}
;

test "discover follows the challenge to both metadata documents" {
    var fake = FakeTransport.init(testing.allocator, &.{
        .{ .status = 401, .head = challenge },
        .{ .body = resource_json },
        .{ .body = server_json },
    });
    defer fake.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const result = try discover(arena.allocator(), fake.transport(), "https://mcp.example/mcp", .{ .client_name = "test" });

    try testing.expectEqual(std.http.Method.POST, fake.sent.items[0].method);
    try testing.expectEqualStrings("2025-06-18", fake.sent.items[0].header("MCP-Protocol-Version").?);
    try testing.expect(std.mem.indexOf(u8, fake.sent.items[0].body.?, "\"method\":\"initialize\"") != null);
    try testing.expectEqualStrings("https://mcp.example/.well-known/oauth-protected-resource", fake.sent.items[1].url);
    try testing.expectEqualStrings("https://auth.example/.well-known/oauth-authorization-server/tenant", fake.sent.items[2].url);
    try testing.expectEqualStrings("https://auth.example/token", result.endpoints.token);
    try testing.expectEqualStrings("https://auth.example/register", result.registration_endpoint.?);
    try testing.expectEqualStrings("https://auth.example/tenant", result.issuer);
    try testing.expectEqualStrings("read write", try scopeString(arena.allocator(), result.scopes_supported));
}

fn expectFailure(expected: anyerror, replies: []const FakeTransport.Reply) !void {
    try expectFailureAt(expected, "https://mcp.example/mcp", replies);
}

fn expectFailureAt(expected: anyerror, resource_url: []const u8, replies: []const FakeTransport.Reply) !void {
    var fake = FakeTransport.init(testing.allocator, replies);
    defer fake.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(expected, discover(arena.allocator(), fake.transport(), resource_url, .{ .client_name = "test" }));
}

test "discover refuses each broken trust link" {
    try expectFailure(error.AuthorizationChallengeMissing, &.{.{ .status = 200 }});
    try expectFailure(error.ResourceMetadataMissing, &.{.{ .status = 401, .head = "WWW-Authenticate: Bearer realm=\"mcp\"\r\n" }});
    try expectFailure(error.ResourceMetadataMismatch, &.{
        .{ .status = 401, .head = challenge },
        .{ .body = "{\"resource\":\"https://evil.example/mcp\",\"authorization_servers\":[\"https://auth.example/tenant\"]}" },
    });
    try expectFailure(error.NoAuthorizationServer, &.{
        .{ .status = 401, .head = challenge },
        .{ .body = "{\"resource\":\"https://mcp.example/mcp\",\"authorization_servers\":[]}" },
    });
    try expectFailure(error.IssuerMismatch, &.{
        .{ .status = 401, .head = challenge },
        .{ .body = resource_json },
        .{ .body = "{\"issuer\":\"https://evil.example\",\"authorization_endpoint\":\"https://auth.example/a\",\"token_endpoint\":\"https://auth.example/t\",\"code_challenge_methods_supported\":[\"S256\"]}" },
    });
    try expectFailure(error.PkceS256Unsupported, &.{
        .{ .status = 401, .head = challenge },
        .{ .body = resource_json },
        .{ .body = "{\"issuer\":\"https://auth.example/tenant\",\"authorization_endpoint\":\"https://auth.example/a\",\"token_endpoint\":\"https://auth.example/t\",\"code_challenge_methods_supported\":[\"plain\"]}" },
    });
    try expectFailure(error.UrlNotSafe, &.{.{ .status = 401, .head = "WWW-Authenticate: Bearer resource_metadata=\"http://mcp.example/m\"\r\n" }});
}

test "the challenge parser reads quoted and bare values" {
    try testing.expectEqualStrings("https://a.example/m", resourceMetadataIn("Bearer resource_metadata=\"https://a.example/m\"").?);
    try testing.expectEqualStrings("https://a.example/m", resourceMetadataIn("Bearer resource_metadata=https://a.example/m, realm=x").?);
    try testing.expect(resourceMetadataIn("Bearer realm=\"mcp\"") == null);
    try testing.expectEqualStrings(
        "https://mcp.notion.com/.well-known/oauth-protected-resource/mcp",
        resourceMetadataIn("Bearer realm=\"OAuth\", resource_metadata=\"https://mcp.notion.com/.well-known/oauth-protected-resource/mcp\", scope=\"default\"").?,
    );
}

test "resourceParam names the resource indicator" {
    const param = resourceParam("https://mcp.example/mcp");
    try testing.expectEqualStrings("resource", param.name);
    try testing.expectEqualStrings("https://mcp.example/mcp", param.value);
}

test "an http resource url is refused before anything is sent" {
    var fake = FakeTransport.init(testing.allocator, &.{.{ .status = 401, .head = challenge }});
    defer fake.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.UrlNotSafe, discover(arena.allocator(), fake.transport(), "http://mcp.example/mcp", .{ .client_name = "test" }));
    try testing.expectEqual(@as(usize, 0), fake.sent.items.len);
}

test "the challenge parser rejects hostile input" {
    try testing.expectEqualStrings("", resourceMetadataIn("Bearer resource_metadata=\"\"").?);
    try expectFailure(error.UrlNotSafe, &.{.{ .status = 401, .head = "WWW-Authenticate: Bearer resource_metadata=\"\"\r\n" }});
    try testing.expect(resourceMetadataIn("Bearer resource_metadata=\"https://a.example/m") == null);
    try testing.expect(resourceMetadataIn("Bearer error_description=\"see resource_metadata=https://x\"") == null);
    try testing.expect(resourceMetadataIn("Bearer xresource_metadata=https://x") == null);
    try testing.expectEqualStrings("https://x", resourceMetadataIn("Bearer RESOURCE_METADATA=https://x").?);
    try testing.expectEqualStrings("https://x", resourceMetadataIn("Bearer a=\"q\\\"z\", resource_metadata=\"https://x\"").?);
}

test "authorization metadata url keeps the issuer path" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings(
        "https://auth.example/.well-known/oauth-authorization-server",
        try authorizationMetadataUrl(arena.allocator(), "https://auth.example"),
    );
    try testing.expectEqualStrings(
        "https://auth.example/.well-known/oauth-authorization-server/tenant",
        try authorizationMetadataUrl(arena.allocator(), "https://auth.example/tenant/"),
    );
}
