//! JWS signature verification with keys from a JWK set (RFC 7515, RFC 7517, RFC 7518).

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Alg = enum { RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, EdDSA };
pub const default_algs: []const Alg = &.{ .RS256, .RS384, .RS512, .PS256, .PS384, .PS512, .ES256, .ES384, .EdDSA };

pub const Verified = struct {
    alg: Alg,
    kid: ?[]const u8,
    /// The decoded payload bytes.
    payload: []const u8,
};

pub const VerifyError = Allocator.Error || error{
    MalformedToken,
    MalformedJwks,
    UnsupportedAlgorithm,
    SigningKeyNotFound,
    AmbiguousKey,
    WeakKey,
    BadSignature,
};

const Header = struct {
    alg: []const u8,
    kid: ?[]const u8 = null,
};

const Key = struct {
    kty: []const u8,
    kid: ?[]const u8 = null,
    alg: ?[]const u8 = null,
    use: ?[]const u8 = null,
    key_ops: ?[]const []const u8 = null,
    crv: ?[]const u8 = null,
    n: ?[]const u8 = null,
    e: ?[]const u8 = null,
    x: ?[]const u8 = null,
    y: ?[]const u8 = null,
};

const KeySet = struct {
    keys: []const Key,
};

const min_rsa_bits = 2048;

pub fn verify(arena: Allocator, token: []const u8, jwks_json: []const u8, allowed: []const Alg) VerifyError!Verified {
    var parts = std.mem.splitScalar(u8, token, '.');
    const header_text = parts.next().?;
    const payload_text = parts.next() orelse return error.MalformedToken;
    const signature_text = parts.next() orelse return error.MalformedToken;
    if (parts.next() != null) return error.MalformedToken;

    const header_bytes = try decode(arena, header_text, error.MalformedToken);
    const signature = try decode(arena, signature_text, error.MalformedToken);
    const header = std.json.parseFromSliceLeaky(Header, arena, header_bytes, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedToken,
    };
    const alg = std.meta.stringToEnum(Alg, header.alg) orelse return error.UnsupportedAlgorithm;
    if (std.mem.indexOfScalar(Alg, allowed, alg) == null) return error.UnsupportedAlgorithm;

    const key_set = std.json.parseFromSliceLeaky(KeySet, arena, jwks_json, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedJwks,
    };
    const key = try selectKey(key_set.keys, header.kid, alg);

    const signed = token[0 .. header_text.len + 1 + payload_text.len];
    const rsa = std.crypto.Certificate.rsa;
    const sha2 = std.crypto.hash.sha2;
    switch (alg) {
        .RS256 => try verifyRsa(rsa.PKCS1v1_5Signature, sha2.Sha256, arena, key, signature, signed),
        .RS384 => try verifyRsa(rsa.PKCS1v1_5Signature, sha2.Sha384, arena, key, signature, signed),
        .RS512 => try verifyRsa(rsa.PKCS1v1_5Signature, sha2.Sha512, arena, key, signature, signed),
        .PS256 => try verifyRsa(rsa.PSSSignature, sha2.Sha256, arena, key, signature, signed),
        .PS384 => try verifyRsa(rsa.PSSSignature, sha2.Sha384, arena, key, signature, signed),
        .PS512 => try verifyRsa(rsa.PSSSignature, sha2.Sha512, arena, key, signature, signed),
        .ES256 => try verifyEcdsa(std.crypto.sign.ecdsa.EcdsaP256Sha256, arena, key, signature, signed),
        .ES384 => try verifyEcdsa(std.crypto.sign.ecdsa.EcdsaP384Sha384, arena, key, signature, signed),
        .EdDSA => try verifyEd25519(arena, key, signature, signed),
    }

    const payload = try decode(arena, payload_text, error.MalformedToken);
    return .{ .alg = alg, .kid = header.kid, .payload = payload };
}

fn selectKey(keys: []const Key, kid: ?[]const u8, alg: Alg) VerifyError!Key {
    var found: ?Key = null;
    for (keys) |key| {
        if (kid) |wanted| {
            const have = key.kid orelse continue;
            if (!std.mem.eql(u8, have, wanted)) continue;
        }
        if (!fits(key, alg)) continue;
        if (found != null) return error.AmbiguousKey;
        found = key;
    }
    return found orelse error.SigningKeyNotFound;
}

fn fits(key: Key, alg: Alg) bool {
    const kty: []const u8, const crv: ?[]const u8 = switch (alg) {
        .RS256, .RS384, .RS512, .PS256, .PS384, .PS512 => .{ "RSA", null },
        .ES256 => .{ "EC", "P-256" },
        .ES384 => .{ "EC", "P-384" },
        .EdDSA => .{ "OKP", "Ed25519" },
    };
    if (!std.mem.eql(u8, key.kty, kty)) return false;
    if (crv) |wanted| {
        const have = key.crv orelse return false;
        if (!std.mem.eql(u8, have, wanted)) return false;
    }
    if (key.alg) |have| {
        if (!std.mem.eql(u8, have, @tagName(alg))) return false;
    }
    if (key.use) |have| {
        if (!std.mem.eql(u8, have, "sig")) return false;
    }
    if (key.key_ops) |ops| {
        for (ops) |op| {
            if (std.mem.eql(u8, op, "verify")) break;
        } else return false;
    }
    return true;
}

fn verifyRsa(comptime Scheme: type, comptime Hash: type, arena: Allocator, key: Key, signature: []const u8, signed: []const u8) VerifyError!void {
    const modulus = try decode(arena, key.n orelse return error.MalformedJwks, error.MalformedJwks);
    const exponent = try decode(arena, key.e orelse return error.MalformedJwks, error.MalformedJwks);
    const public_key = std.crypto.Certificate.rsa.PublicKey.fromBytes(exponent, modulus) catch return error.MalformedJwks;
    const bits = public_key.n.bits();
    if (bits < min_rsa_bits) return error.WeakKey;
    if (signature.len != (bits + 7) / 8) return error.BadSignature;
    // The std verifiers take the modulus length at comptime.
    switch (signature.len) {
        inline 256, 384, 512 => |len| Scheme.verify(len, signature[0..len], signed, public_key, Hash) catch return error.BadSignature,
        else => return error.MalformedJwks,
    }
}

fn verifyEcdsa(comptime Ecdsa: type, arena: Allocator, key: Key, signature: []const u8, signed: []const u8) VerifyError!void {
    const coordinate_len = Ecdsa.Curve.Fe.encoded_length;
    const x = try decode(arena, key.x orelse return error.MalformedJwks, error.MalformedJwks);
    const y = try decode(arena, key.y orelse return error.MalformedJwks, error.MalformedJwks);
    if (x.len != coordinate_len or y.len != coordinate_len) return error.MalformedJwks;
    const sec1 = [1]u8{0x04} ++ x[0..coordinate_len].* ++ y[0..coordinate_len].*;
    const public_key = Ecdsa.PublicKey.fromSec1(&sec1) catch return error.MalformedJwks;
    if (signature.len != Ecdsa.Signature.encoded_length) return error.BadSignature;
    const parsed = Ecdsa.Signature.fromBytes(signature[0..Ecdsa.Signature.encoded_length].*);
    parsed.verify(signed, public_key) catch return error.BadSignature;
}

fn verifyEd25519(arena: Allocator, key: Key, signature: []const u8, signed: []const u8) VerifyError!void {
    const Ed25519 = std.crypto.sign.Ed25519;
    const x = try decode(arena, key.x orelse return error.MalformedJwks, error.MalformedJwks);
    if (x.len != Ed25519.PublicKey.encoded_length) return error.MalformedJwks;
    const public_key = Ed25519.PublicKey.fromBytes(x[0..Ed25519.PublicKey.encoded_length].*) catch return error.MalformedJwks;
    if (signature.len != Ed25519.Signature.encoded_length) return error.BadSignature;
    const parsed = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
    parsed.verifyStrict(signed, public_key) catch return error.BadSignature;
}

fn decode(arena: Allocator, text: []const u8, comptime fault: VerifyError) VerifyError![]u8 {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const size = decoder.calcSizeForSlice(text) catch return fault;
    const out = try arena.alloc(u8, size);
    decoder.decode(out, text) catch return fault;
    return out;
}

const testing = std.testing;

const fixture_payload = "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoiY2xpZW50LTEiLCJzdWIiOiJzdWJqZWN0LTEiLCJub25jZSI6Im5vbmNlLTEiLCJleHAiOjIwMDAwMDAwMDAsImlhdCI6MTcwMDAwMDAwMH0";
const payload_json = "{\"iss\":\"https://issuer.example\",\"aud\":\"client-1\",\"sub\":\"subject-1\",\"nonce\":\"nonce-1\",\"exp\":2000000000,\"iat\":1700000000}";

const rs256_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYSJ9." ++ fixture_payload ++ ".tCnSeG6rD8kkXQ6FquSYr1wOnIwnxW3qtuh_JUA11iUOJqRY75SyxY40riOEpmUA6DMlYCIQtLRiYMjJr1qc6g5jfB1lyu4ke69stLl5EmECaqhkzkPc62kaBZkTlpLh-emBycuRTtGA-UfX6PDC5s7ngqD10BfDVv8AHedC8K-o-Nf78V7TGQ8e-PyRiE4H7OvstwpeeWUq_cccxXVzttYhr14560hzrZc6L0z-3nGo2iLDqC36Yr_MFD2063wYIsk0nYrr6-LE_vgrO0uTX6_Q7rZ_DOWaU0FNWw4aEGroaTSnTCj3TWnQM_ApqIwXBrtJ4pZCurv1u7pTBQb5FQ";
const ps256_token = "eyJhbGciOiJQUzI1NiIsImtpZCI6InJzYSJ9." ++ fixture_payload ++ ".pnzWlmrHPXa9U7uXhF_T5oQ2STapoz4cibDRgkmUo5R0qIctXrKzhwpCHshTrHuuldf8oZ076WdrZfncbl4j_tKeImitvng_UHbaTP0hGXM2nqSuap1viZuPGXbFi62R29D7ao8AMOAm6hoRiJovV7Gatg3Q9QhDuhV9IvsZfpl4kcLV23-z3KiJaTBwSfVIi7pE3zi37LpkOMifRcbC2iado_WbjGYvd01WjBX8n1TCwL4Ob0jFI1gov0GeP_HBb1kNxR6ePEnDj-EUimJ94VKqxU1wAQtahUq0zHYlKbToeNqCgn6frLiH7EMGIxpoDbBCCjI77n8Smg0MUbLydQ";
const rs256_small_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS1zbWFsbCJ9." ++ fixture_payload ++ ".oC8jyYNweSww2ghQgoCoh7IWr3NU7lw7buODtyWi-eE8vGK337JpOdSPBnOmTuvPP42QLDYJU3CUkJOSI-KWUfDZf2kRetdrTQ7YdQno-baNW8inh44MH2TIK11g0J74c91rahU3ZmKOHxsQ3SuXDlh4e9zh90W7HT4TXVxCxVw";
const es256_token = "eyJhbGciOiJFUzI1NiIsImtpZCI6InAyNTYifQ." ++ fixture_payload ++ ".Ejnz2ySUYGjD3-BmuJb3i5D2Sp0bxbqHq-vvIg9jGgg620n-QgVBbGd0FUZHeXnkG2Lm9s_usKU2DrhmletAlA";
const es384_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6InAzODQifQ." ++ fixture_payload ++ ".1ZeOzXRSIT_8cSauan5sW2NaI9CHeVA9wyzR_32geX2XG8lzcayILIg-AQ88trD0IxlZa3V1J8uQ7lbccXA9sLtP0J2TawrZkyA75AtUi1YnCaH6gUz2VcsHisR6P1hM";
const eddsa_token = "eyJhbGciOiJFZERTQSJ9." ++ fixture_payload ++ ".Iwi3QlbsDbADZ8D7POKzZFCsYUGASNM-Zp8KXZNRA4ZxclENvGoV1isUty7ktITezWcRErHdDPT-YzZRw6HqCQ";

const rsa_n = "wm9aUSE2h5WBij0ciPmr8k6TRCE0OBJMCkOwLgw1OCmRnAuX_rhmxG9crY_YRy8o556B3vxZF55ryg4GQhgOVATpHKG-aIkU55ifdjXYfjZDzY-jWVHxdbMbJ6x3e78XVFuN2EqlDX8ZYgdA09Db-Ti9aaAC1jWEKS5nAGFbdZyVkyKzOJMGcoj1Dhftstyq_g9C7evFwVkYl-xj9RJkai0OrXG77Cmp-IE3r7yd5HKgyqlzIkIAP3UlMgZimq5c5dpNeONAZBEmn8rLw9CL3AzRsxFT5yDtRUEVKS9YSZGzHd1uYVCD9N2hKd_WLpvg0fsXolcgUmm8DkVUp8RJqQ";
const rsa_small_n = "tCmU7l19yVxlyV4UO3M25AAS8nH01l4n3Dgn2YOzt2ODPNu3bYL6jnddSzfeSSQxajJcdL9mMF-xy7OtxlQT6UFcnyNBnXWpTf_vKc10j1rZQuhPIxvQCRseAQxNqT03pp3TEMNEyC1MuNlPuR4Nj1BbAOnbcPW0f8EfObA7jSE";
const p256_x = "gRRqCHb6PKaFEO8gfkPx1No3bRmyShEhxUGq8_VonCg";
const p256_y = "6IODbWgTHWKKXkRqvLUdtG5QrdJPq9G0kQN_cImuPZ4";
const p384_x = "dVtJ-SYhLDrV8Vpl_cW3Y1YSv7BuLwYa5roPmEWjcT0LI-b5kA_SuLawuc5y-kN1";
const p384_y = "Uy_YN_KKIdQbyUGvGlXXCKCrQcp11vbSGLvr5v2ayTTRv3Jlpxwa57frd-SzBGyC";
const ed_x = "sCj_FofwjyQRffjxc_ctA1L2TzE-OuKtH_b9NUPma28";

const rsa_jwk = "{\"kty\":\"RSA\",\"kid\":\"rsa\",\"n\":\"" ++ rsa_n ++ "\",\"e\":\"AQAB\"}";
const p256_jwk = "{\"kty\":\"EC\",\"kid\":\"p256\",\"crv\":\"P-256\",\"x\":\"" ++ p256_x ++ "\",\"y\":\"" ++ p256_y ++ "\"}";
const p384_jwk = "{\"kty\":\"EC\",\"kid\":\"p384\",\"crv\":\"P-384\",\"x\":\"" ++ p384_x ++ "\",\"y\":\"" ++ p384_y ++ "\"}";
const ed_jwk = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" ++ ed_x ++ "\"}";
const all_jwks = "{\"keys\":[" ++ rsa_jwk ++ "," ++ p256_jwk ++ "," ++ p384_jwk ++ "," ++ ed_jwk ++ "]}";

fn expectVerified(token: []const u8, alg: Alg, kid: ?[]const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const verified = try verify(arena.allocator(), token, all_jwks, default_algs);
    try testing.expectEqual(alg, verified.alg);
    if (kid) |one| try testing.expectEqualStrings(one, verified.kid.?) else try testing.expect(verified.kid == null);
    try testing.expectEqualStrings(payload_json, verified.payload);
}

/// Changes one character in the middle of the signature part.
fn changeSignature(arena: Allocator, token: []const u8) ![]u8 {
    const changed = try arena.dupe(u8, token);
    const start = std.mem.lastIndexOfScalar(u8, changed, '.').? + 1;
    const at = start + (changed.len - start) / 2;
    changed[at] = if (changed[at] == 'A') 'B' else 'A';
    return changed;
}

/// Puts a new header in front of the payload and signature of `token`.
fn withHeader(arena: Allocator, header_json: []const u8, token: []const u8) ![]u8 {
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const header = try arena.alloc(u8, encoder.calcSize(header_json.len));
    _ = encoder.encode(header, header_json);
    const rest = token[std.mem.indexOfScalar(u8, token, '.').?..];
    return std.mem.concat(arena, u8, &.{ header, rest });
}

test "verify accepts RS256 with kid rsa" {
    try expectVerified(rs256_token, .RS256, "rsa");
}

test "verify accepts PS256 with kid rsa" {
    try expectVerified(ps256_token, .PS256, "rsa");
}

test "verify accepts ES256 with kid p256" {
    try expectVerified(es256_token, .ES256, "p256");
}

test "verify accepts ES384 with kid p384" {
    try expectVerified(es384_token, .ES384, "p384");
}

test "verify accepts EdDSA without a kid" {
    try expectVerified(eddsa_token, .EdDSA, null);
}

test "verify refuses a changed signature for RS256, ES256 and EdDSA" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_][]const u8{ rs256_token, es256_token, eddsa_token }) |token| {
        try testing.expectError(error.BadSignature, verify(a, try changeSignature(a, token), all_jwks, default_algs));
    }
}

test "verify refuses an algorithm that is not allowed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.UnsupportedAlgorithm, verify(arena.allocator(), rs256_token, all_jwks, &.{.ES256}));
}

test "verify refuses alg none and HS256" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const none = try withHeader(a, "{\"alg\":\"none\"}", rs256_token);
    try testing.expectError(error.UnsupportedAlgorithm, verify(a, none, all_jwks, default_algs));
    const hs256 = try withHeader(a, "{\"alg\":\"HS256\",\"kid\":\"rsa\"}", rs256_token);
    try testing.expectError(error.UnsupportedAlgorithm, verify(a, hs256, all_jwks, default_algs));
}

test "verify refuses a key with the kid but another kty or alg" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ec_kty = "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"rsa\",\"n\":\"" ++ rsa_n ++ "\",\"e\":\"AQAB\"}]}";
    try testing.expectError(error.SigningKeyNotFound, verify(a, rs256_token, ec_kty, default_algs));
    const rs384 = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"rsa\",\"alg\":\"RS384\",\"n\":\"" ++ rsa_n ++ "\",\"e\":\"AQAB\"}]}";
    try testing.expectError(error.SigningKeyNotFound, verify(a, rs256_token, rs384, default_algs));
}

test "verify refuses two keys that both fit" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const two_ed = "{\"keys\":[" ++ ed_jwk ++ "," ++ ed_jwk ++ "]}";
    try testing.expectError(error.AmbiguousKey, verify(a, eddsa_token, two_ed, default_algs));
    const two_rsa = "{\"keys\":[" ++ rsa_jwk ++ "," ++ rsa_jwk ++ "]}";
    try testing.expectError(error.AmbiguousKey, verify(a, rs256_token, two_rsa, default_algs));
}

test "verify checks use and key_ops and accepts a key without alg" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const enc = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"rsa\",\"use\":\"enc\",\"n\":\"" ++ rsa_n ++ "\",\"e\":\"AQAB\"}]}";
    try testing.expectError(error.SigningKeyNotFound, verify(a, rs256_token, enc, default_algs));
    const encrypt = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"rsa\",\"key_ops\":[\"encrypt\"],\"n\":\"" ++ rsa_n ++ "\",\"e\":\"AQAB\"}]}";
    try testing.expectError(error.SigningKeyNotFound, verify(a, rs256_token, encrypt, default_algs));
    const entra = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"rsa\",\"use\":\"sig\",\"key_ops\":[\"verify\"],\"x5t\":\"abc\",\"n\":\"" ++ rsa_n ++ "\",\"e\":\"AQAB\"}]}";
    const verified = try verify(a, rs256_token, entra, default_algs);
    try testing.expectEqual(Alg.RS256, verified.alg);
    try testing.expectEqualStrings(payload_json, verified.payload);
}

test "verify refuses an RSA key under 2048 bits" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const small = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"rsa-small\",\"n\":\"" ++ rsa_small_n ++ "\",\"e\":\"AQAB\"}]}";
    try testing.expectError(error.WeakKey, verify(arena.allocator(), rs256_small_token, small, default_algs));
}

test "verify refuses an RSA signature shorter than the modulus" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    // The cut leaves 253 bytes and zero leftover bits, so the base64url stays valid.
    const short = rs256_token[0 .. rs256_token.len - 4];
    try testing.expectError(error.BadSignature, verify(arena.allocator(), short, all_jwks, default_algs));
}

test "verify refuses an EC point that is not on the curve" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const bad_y = "6IODcWgTHWKKXkRqvLUdtG5QrdJPq9G0kQN_cImuPZ4";
    const off_curve = "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"p256\",\"crv\":\"P-256\",\"x\":\"" ++ p256_x ++ "\",\"y\":\"" ++ bad_y ++ "\"}]}";
    try testing.expectError(error.MalformedJwks, verify(arena.allocator(), es256_token, off_curve, default_algs));
}

test "verify refuses a wrong part count and bad base64url" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.MalformedToken, verify(a, "a.b", all_jwks, default_algs));
    try testing.expectError(error.MalformedToken, verify(a, rs256_token ++ ".e30", all_jwks, default_algs));
    try testing.expectError(error.MalformedToken, verify(a, "eyJ!bGciOiJFUzI1NiJ9." ++ fixture_payload ++ ".AA", all_jwks, default_algs));
    try testing.expectError(error.MalformedToken, verify(a, es256_token ++ "*", all_jwks, default_algs));
}

test "verify refuses a JWK set that is not JSON" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.MalformedJwks, verify(arena.allocator(), es256_token, "not json", default_algs));
}

fn verifyEs256(gpa: Allocator) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    _ = try verify(arena.allocator(), es256_token, all_jwks, default_algs);
}

test "verify returns OutOfMemory for each failed allocation" {
    try testing.checkAllAllocationFailures(testing.allocator, verifyEs256, .{});
}
