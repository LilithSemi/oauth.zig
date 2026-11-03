const Transport = @import("transport.zig").Transport;
const Param = @import("url.zig").Param;
const ErrorCode = @import("token.zig").ErrorCode;

pub const Client = struct {
    id: []const u8,
    auth: Auth = .none,

    /// A public client is the default. A secret is used only when the caller gives one.
    pub const Auth = union(enum) {
        none,
        secret_basic: []const u8,
        secret_post: []const u8,
    };
};

pub const Endpoints = struct {
    authorization: ?[]const u8 = null,
    token: []const u8,
    device_authorization: ?[]const u8 = null,
    revocation: ?[]const u8 = null,
};

/// What every request to the authorization server needs.
pub const Call = struct {
    transport: Transport,
    endpoints: Endpoints,
    client: Client,
    extra: []const Param = &.{},
    /// Receives the RFC 6749 error code when a request returns `error.TokenRefused`.
    error_code: ?*ErrorCode = null,
};
