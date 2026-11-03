const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Param = struct {
    name: []const u8,
    value: []const u8,
};

pub const UrlError = error{UrlNotSafe};

pub fn checkUrl(text: []const u8) UrlError!void {
    const uri = std.Uri.parse(text) catch return error.UrlNotSafe;
    if (!std.mem.eql(u8, uri.scheme, "https")) return error.UrlNotSafe;
    const host = uri.host orelse return error.UrlNotSafe;
    if (host.isEmpty()) return error.UrlNotSafe;
    if (uri.fragment != null or uri.user != null or uri.password != null) return error.UrlNotSafe;
}

/// Encodes with the RFC 3986 unreserved set. This is also a valid
/// application/x-www-form-urlencoded value.
pub fn appendEncoded(gpa: Allocator, out: *std.ArrayList(u8), bytes: []const u8) Allocator.Error!void {
    const hex = "0123456789ABCDEF";
    for (bytes) |byte| {
        if (isUnreserved(byte)) {
            try out.append(gpa, byte);
        } else {
            try out.appendSlice(gpa, &.{ '%', hex[byte >> 4], hex[byte & 0x0f] });
        }
    }
}

pub fn appendParam(gpa: Allocator, out: *std.ArrayList(u8), param: Param) Allocator.Error!void {
    if (out.items.len != 0) {
        const last = out.items[out.items.len - 1];
        if (last != '?' and last != '&') try out.append(gpa, '&');
    }
    try appendEncoded(gpa, out, param.name);
    try out.append(gpa, '=');
    try appendEncoded(gpa, out, param.value);
}

fn isUnreserved(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '.' or byte == '_' or byte == '~';
}

pub fn encodedLen(bytes: []const u8) usize {
    var len: usize = 0;
    for (bytes) |byte| len += if (isUnreserved(byte)) 1 else 3;
    return len;
}

pub fn writeEncoded(out: []u8, bytes: []const u8) usize {
    const hex = "0123456789ABCDEF";
    var at: usize = 0;
    for (bytes) |byte| {
        if (isUnreserved(byte)) {
            out[at] = byte;
            at += 1;
        } else {
            out[at..][0..3].* = .{ '%', hex[byte >> 4], hex[byte & 0x0f] };
            at += 3;
        }
    }
    return at;
}

/// Allocates the exact size once, so no earlier copy of a secret stays on the heap.
pub fn formBody(gpa: Allocator, groups: []const []const Param) Allocator.Error![]u8 {
    var len: usize = 0;
    var count: usize = 0;
    for (groups) |group| for (group) |param| {
        len += encodedLen(param.name) + 1 + encodedLen(param.value);
        count += 1;
    };
    if (count != 0) len += count - 1;

    const out = try gpa.alloc(u8, len);
    var at: usize = 0;
    var first = true;
    for (groups) |group| for (group) |param| {
        if (!first) {
            out[at] = '&';
            at += 1;
        }
        first = false;
        at += writeEncoded(out[at..], param.name);
        out[at] = '=';
        at += 1;
        at += writeEncoded(out[at..], param.value);
    };
    std.debug.assert(at == len);
    return out;
}

test "checkUrl accepts an https URL with a host" {
    try checkUrl("https://auth.example/token");
    try checkUrl("https://auth.example:8443/a?b=c");
}

test "checkUrl refuses each unsafe shape" {
    const bad = [_][]const u8{
        "http://auth.example/token",
        "https:///token",
        "https://auth.example/token#frag",
        "https://user@auth.example/token",
        "https://user:pass@auth.example/token",
        "not a url",
        "",
    };
    for (bad) |text| try std.testing.expectError(error.UrlNotSafe, checkUrl(text));
}

test "appendParam keeps unreserved bytes and percent encodes the rest" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try appendParam(gpa, &out, .{ .name = "scope", .value = "read write" });
    try appendParam(gpa, &out, .{ .name = "x", .value = "a-._~/:&=" });
    try std.testing.expectEqualStrings("scope=read%20write&x=a-._~%2F%3A%26%3D", out.items);
}

test "appendParam adds no separator after a question mark or ampersand" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try out.appendSlice(gpa, "https://a.example/x?");
    try appendParam(gpa, &out, .{ .name = "a", .value = "1" });
    try out.append(gpa, '&');
    try appendParam(gpa, &out, .{ .name = "b", .value = "2" });
    try std.testing.expectEqualStrings("https://a.example/x?a=1&b=2", out.items);
}

test "formBody joins groups in order" {
    const gpa = std.testing.allocator;
    const body = try formBody(gpa, &.{
        &.{.{ .name = "grant_type", .value = "refresh_token" }},
        &.{},
        &.{.{ .name = "resource", .value = "https://r.example/" }},
    });
    defer gpa.free(body);
    try std.testing.expectEqualStrings("grant_type=refresh_token&resource=https%3A%2F%2Fr.example%2F", body);
}

test "formBody length matches the encoded text for multi-byte values" {
    const gpa = std.testing.allocator;
    const body = try formBody(gpa, &.{
        &.{.{ .name = "n", .value = "\u{e9}" }},
        &.{.{ .name = "k", .value = "v" }},
    });
    defer gpa.free(body);
    const expected = "n=%C3%A9&k=v";
    try std.testing.expectEqual(expected.len, body.len);
    try std.testing.expectEqualStrings(expected, body);
}
