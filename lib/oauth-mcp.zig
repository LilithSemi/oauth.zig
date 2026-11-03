//! OAuth for remote MCP servers: RFC 9728 and RFC 8414 discovery, and RFC 7591 registration.

pub const discovery = @import("oauth-mcp/discovery.zig");
pub const Discovery = discovery.Discovery;
pub const discover = discovery.discover;
pub const DiscoverError = discovery.DiscoverError;
pub const resourceParam = discovery.resourceParam;
pub const scopeString = discovery.scopeString;
pub const registration = @import("oauth-mcp/registration.zig");
pub const register = registration.register;
pub const RegisterOptions = registration.RegisterOptions;
pub const RegisterError = registration.RegisterError;

test {
    _ = discovery;
    _ = registration;
}
