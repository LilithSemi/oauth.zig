//! OAuth 2.0 and OpenID Connect flows over an injected transport.

pub const url = @import("oauth-core/url.zig");
pub const Param = url.Param;
pub const UrlError = url.UrlError;
pub const checkUrl = url.checkUrl;

pub const transport = @import("oauth-core/transport.zig");
pub const Transport = transport.Transport;
pub const Request = transport.Request;
pub const Response = transport.Response;
pub const SendError = transport.SendError;
pub const testing = @import("oauth-core/testing.zig");
pub const ZurlTransport = @import("oauth-core/ZurlTransport.zig");

pub const client = @import("oauth-core/client.zig");
pub const Client = client.Client;
pub const Endpoints = client.Endpoints;
pub const Call = client.Call;
pub const pkce = @import("oauth-core/pkce.zig");
pub const Attempt = pkce.Attempt;
pub const authorize = @import("oauth-core/authorize.zig");
pub const authorizeUrl = authorize.authorizeUrl;
pub const token = @import("oauth-core/token.zig");
pub const ErrorCode = token.ErrorCode;
pub const TokenSet = token.TokenSet;
pub const TokenError = token.TokenError;
pub const exchangeCode = token.exchangeCode;
pub const refresh = token.refresh;
pub const clientCredentials = token.clientCredentials;
pub const device = @import("oauth-core/device.zig");
pub const DeviceAuthorization = device.DeviceAuthorization;
pub const PollResult = device.PollResult;
pub const revoke = @import("oauth-core/revoke.zig").revoke;
pub const TokenHint = @import("oauth-core/revoke.zig").TokenHint;
pub const callback = @import("oauth-core/callback.zig");
pub const Callback = callback.Callback;
pub const parseCallback = callback.parseCallback;
pub const CallbackError = callback.CallbackError;
pub const jwk = @import("oauth-core/jwk.zig");
pub const oidc = @import("oauth-core/oidc.zig");

test {
    _ = url;
    _ = transport;
    _ = testing;
    _ = ZurlTransport;
    _ = client;
    _ = pkce;
    _ = authorize;
    _ = callback;
    _ = token;
    _ = device;
    _ = @import("oauth-core/revoke.zig");
    _ = jwk;
    _ = oidc;
}
