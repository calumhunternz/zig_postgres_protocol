const std = @import("std");
const assert = std.debug.assert;
const backend_msg = @import("./backend_messages.zig");
const frontend_msg = @import("./frontend_messages.zig");
const types = @import("./types.zig");
const Reader = types.Reader;
const Writer = types.Writer;

const Codec = @This();

alloc: std.mem.Allocator,
store: std.ArrayList([]u8),

pub fn init(alloc: std.mem.Allocator) Codec {
    return Codec{
        .alloc = alloc,
        .store = std.ArrayList([]u8).init(alloc),
    };
}

pub fn decode(self: *Codec, buf: []const u8) !BackendMsg {
    _ = self;
    var reader = Reader.reader(buf);
    return try BackendMsg.decode(buf, &reader);
}

pub fn encode(self: *Codec, msg: *const FrontendMsg) ![]const u8 {
    const buf = try self.alloc.alloc(u8, msg.size());
    try self.store.append(buf);
    var writer = Writer.writer(buf);
    try msg.encode(&writer);
    return buf;
}

pub fn deinit(self: *Codec) void {
    for (self.store.items) |stored| self.alloc.free(stored);
    self.store.deinit();
}

pub const BackendMsg = union(enum) {
    Auth: backend_msg.AuthRes,
    Error: backend_msg.ErrorRes,

    const MsgType = enum(u8) {
        AuthRes = 'R',
        ErrorRes = 'E',
    };

    const HEADER_SIZE: usize = 5;

    const Header = struct {
        msg_type: MsgType,
        len: u32,
    };

    pub fn decode(
        reader: *Reader,
    ) !BackendMsg {
        const header = parseHeader(reader);

        switch (header.msg_type) {
            .AuthRes => {
                const auth_res = try backend_msg.AuthRes.decode(reader);
                return BackendMsg{ .Auth = auth_res };
            },
            .ErrorRes => {
                const error_res = try backend_msg.ErrorRes.decode(reader);
                return BackendMsg{ .Error = error_res };
            },
        }
    }

    fn parseHeader(reader: *Reader) Header {
        return .{
            .msg_type = @as(MsgType, @enumFromInt(reader.readByte1())),
            .len = reader.readu32(),
        };
    }

    pub fn free(self: *BackendMsg, alloc: std.mem.Allocator) void {
        switch (self.*) {
            .Error => |error_res| {
                if (error_res.field) |field| {
                    alloc.free(field);
                }
            },
            else => return,
        }
    }
};

pub const FrontendMsg = union(FrontendMsgType) {
    Startup: frontend_msg.StartupMsg,
    SASLInit: frontend_msg.SASLInitMsg,

    const FrontendMsgType = enum {
        Startup,
        SASLInit,
    };

    pub fn encode(
        self: *const FrontendMsg,
        writer: *Writer,
    ) !void {
        return switch (self.*) {
            .Startup => |startup_msg| startup_msg.encode(writer),
            .SASLInit => |sasl_initial_msg| sasl_initial_msg.encode(writer),
        };
    }

    pub fn size(self: *const FrontendMsg) usize {
        return switch (self.*) {
            .Startup => |startup| startup.size(),
            .SASLInit => |sasl_init| sasl_init.size(),
        };
    }
};
