const std = @import("std");
const zurl = @import("zurl");
const url = @import("url.zig");

const Allocator = std.mem.Allocator;

pub const Request = struct {
    method: std.http.Method,
    url: []const u8,
    headers: []const std.http.Header = &.{},
    content_type: ?[]const u8 = null,
    body: ?[]const u8 = null,
};

pub const Response = struct {
    status: u16,
    /// The raw response head, from the status line to the empty line.
    head: []u8,
    body: []u8,

    pub fn header(self: Response, name: []const u8) ?[]const u8 {
        return zurl.Response.headerIn(self.head, name);
    }

    pub fn isSuccess(self: Response) bool {
        return self.status >= 200 and self.status < 300;
    }

    pub fn deinit(self: *Response, gpa: Allocator) void {
        std.crypto.secureZero(u8, self.body);
        gpa.free(self.body);
        gpa.free(self.head);
        self.* = undefined;
    }
};

pub const SendError = error{
    OutOfMemory,
    UrlNotSafe,
    ResponseTooLarge,
    CertificateInvalid,
    TrustStoreMissing,
    TransportFailed,
};

pub const Transport = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (ptr: *anyopaque, gpa: Allocator, request: Request) SendError!Response,
    };

    pub fn send(self: Transport, gpa: Allocator, request: Request) SendError!Response {
        try url.checkUrl(request.url);
        return self.vtable.send(self.ptr, gpa, request);
    }
};
