const std = @import("std");

pub const state_len = 43;

pub const Attempt = struct {
    state: [state_len]u8,
    nonce: [43]u8,
    verifier: [86]u8,
    challenge: [43]u8,

    pub fn init(io: std.Io) Attempt {
        var state_raw: [32]u8 = undefined;
        var nonce_raw: [32]u8 = undefined;
        var verifier_raw: [64]u8 = undefined;
        defer {
            std.crypto.secureZero(u8, &state_raw);
            std.crypto.secureZero(u8, &nonce_raw);
            std.crypto.secureZero(u8, &verifier_raw);
        }
        io.random(&state_raw);
        io.random(&nonce_raw);
        io.random(&verifier_raw);

        var self: Attempt = undefined;
        _ = std.base64.url_safe_no_pad.Encoder.encode(&self.state, &state_raw);
        _ = std.base64.url_safe_no_pad.Encoder.encode(&self.nonce, &nonce_raw);
        _ = std.base64.url_safe_no_pad.Encoder.encode(&self.verifier, &verifier_raw);
        challengeFor(&self.challenge, &self.verifier);
        return self;
    }

    pub fn wipe(self: *Attempt) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub fn challengeFor(out: *[43]u8, verifier: []const u8) void {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    std.crypto.hash.sha2.Sha256.hash(verifier, &digest, .{});
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, &digest);
}

test "the PKCE challenge matches RFC 7636 appendix B" {
    var challenge: [43]u8 = undefined;
    challengeFor(&challenge, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    try std.testing.expectEqualStrings("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", &challenge);
}

test "Attempt.init gives fresh values and a matching challenge" {
    const one = Attempt.init(std.testing.io);
    const two = Attempt.init(std.testing.io);
    try std.testing.expect(!std.mem.eql(u8, &one.state, &two.state));
    try std.testing.expect(!std.mem.eql(u8, &one.verifier, &two.verifier));
    var expected: [43]u8 = undefined;
    challengeFor(&expected, &one.verifier);
    try std.testing.expectEqualStrings(&expected, &one.challenge);
}
