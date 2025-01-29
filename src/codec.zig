const std = @import("std");
const print = std.debug.print;
const assert = std.debug.assert;

pub const FrontendMsg = union(FrontendMsgType) {
    Startup: StartupMsg,

    const FrontendMsgType = enum {
        Startup,
    };

    pub fn new(msg_type: FrontendMsgType, ctx: anytype) FrontendMsg {
        assert(@typeInfo(@TypeOf(ctx)) == .Struct);
        return switch (msg_type) {
            .Startup => .{ .Startup = StartupMsg.new(ctx.user, ctx.database) },
        };
    }

    pub fn encode(self: *const FrontendMsg, buf: []u8) !void {
        return switch (self.*) {
            .Startup => |startup_msg| startup_msg.encode(buf),
        };
    }

    pub fn size(self: *const FrontendMsg) usize {
        return switch (self.*) {
            .Startup => |startup| startup.size(),
        };
    }
};

pub const BackendMsg = union(enum) {
    Auth: AuthRes,
    Error: ErrorRes,

    const MsgType = enum(u8) {
        AuthRes = 'R',
        ErrorRes = 'E',
    };

    const HEADER_SIZE: usize = 5;

    const Header = struct {
        msg_type: MsgType,
        len: u32,
    };

    pub fn decode(buf: []const u8, codec: *Codec) !BackendMsg {
        const header = parseHeader(buf);

        switch (header.msg_type) {
            .AuthRes => {
                const auth_res = try AuthRes.decode(buf[HEADER_SIZE..]);
                return BackendMsg{ .Auth = auth_res };
            },
            .ErrorRes => {
                const error_res = try ErrorRes.decode(buf[HEADER_SIZE..], codec);
                return BackendMsg{ .Error = error_res };
            },
        }
    }

    fn parseHeader(buf: []const u8) Header {
        assert(buf.len > HEADER_SIZE);
        const msg_type: MsgType = @enumFromInt(buf[0]);
        const len = std.mem.readInt(u32, buf[1..5], .little);
        assert(len == buf[1..].len);

        return .{
            .msg_type = msg_type,
            .len = len,
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

pub const Codec = struct {
    alloc: std.mem.Allocator,
    store: std.ArrayList([]u8),

    pub fn init(alloc: std.mem.Allocator) Codec {
        return Codec{ .alloc = alloc, .store = std.ArrayList([]u8).init(alloc) };
    }

    pub fn decode(self: *Codec, buf: []const u8) !BackendMsg {
        return try BackendMsg.decode(buf, self);
    }

    pub fn encode(self: *Codec, msg: *const FrontendMsg) ![]const u8 {
        const buf = try self.alloc.alloc(u8, msg.size());
        try self.store.append(buf);
        try msg.encode(buf);
        return buf;
    }

    pub fn deinit(self: *Codec) void {
        for (self.store.items) |stored| self.alloc.free(stored);
        self.store.deinit();
    }
};

pub const ValuePair = struct {
    key: []const u8,
    val: []const u8,
    const padding: usize = 2;

    pub fn size(self: *const ValuePair) usize {
        return self.key.len + self.val.len + padding;
    }
};

const ErrorRes = struct {
    error_type: ErrorType,
    field: ?[]const u8 = null,

    // posibility of an unrecognisable error code being added
    // postgres reccomends ignoring them.
    // https://www.postgresql.org/docs/current/protocol-error-fields.html
    const ErrorType = enum(u8) {
        Severity = 'S',
        LocalizedSeverity = 'V',
        SQLState = 'C',
        Message = 'M',
        Detail = 'D',
        Hint = 'H',
        Position = 'P',
        InternalPosition = 'p',
        InternalQuery = 'q',
        Where = 'W',
        SchemaName = 's',
        TableName = 't',
        ColumnName = 'c',
        DataTypeName = 'd',
        ConstraintName = 'n',
        File = 'F',
        Line = 'L',
        Routine = 'R',
    };

    pub fn decode(buf: []const u8, codec: *Codec) !ErrorRes {
        const type_offset = 1;

        assert(buf.len >= type_offset);

        const error_type: ErrorType = @enumFromInt(buf[0]);

        if (buf[type_offset..].len > 0) {
            const field_buf = try codec.alloc.alloc(u8, buf[type_offset..].len);
            try codec.store.append(field_buf);
            @memcpy(field_buf, buf[type_offset..]);
            return ErrorRes{ .error_type = error_type, .field = field_buf };
        }
        return ErrorRes{ .error_type = error_type };
    }
};

const AuthRes = struct {
    auth_type: AuthType,
    extra: AuthExtra = .None,

    const AuthType = enum(u32) {
        Ok = 0,
        KerberosV5 = 2,
        ClearTextPassword = 3,
        MD5Password = 5,
        GSS = 7,
        GSSContinue = 8,
        SSPI = 9,
        SASL = 10,
        SASLContinue = 11,
        SASLFinal = 12,
    };

    const AuthExtra = union(enum) {
        MD5Password: struct { salt: [4]u8 },
        GSSContinue: struct { data: []u8 },
        SASL: struct { mechanism: []const u8 }, // null terminated list of auth schemes will require enum once those are found.
        SASLContinue: struct { data: []u8 },
        SALSFinal: struct { data: []u8 },
        None,
    };

    pub fn decode(buf: []const u8) !AuthRes {
        const type_offset: usize = 4;
        assert(buf.len >= type_offset);

        const auth_type: AuthType = @enumFromInt(std.mem.readInt(u32, buf[0..type_offset], .little));
        const extra = switch (auth_type) {
            .MD5Password => extra: {
                assert(buf[type_offset..].len == 4);
                var salt: [4]u8 = undefined;
                @memcpy(&salt, buf[type_offset..]);
                break :extra AuthExtra{ .MD5Password = .{ .salt = salt } };
            },
            else => AuthExtra.None,
        };

        return AuthRes{ .auth_type = auth_type, .extra = extra };
    }
};

// TODO: allow for passing in option, replication and protocol
// currenly going to just use ver 3 protocol and not worry about
// options and replication
pub const StartupMsg = struct {
    protocol: u32 = 0x00030000, // 16 sig bit for major 16 bit for minor
    user: ValuePair,
    database: ?ValuePair = null,
    options: ?ValuePair = null, // Depracated in postgres but leaving here
    replication: ?ValuePair = null, // not going to use for now but leaving here

    pub fn new(usr: []const u8, database: ?[]const u8) StartupMsg {
        const user = ValuePair{ .key = "user", .val = usr };
        // const len = width(database) + user.size() + @sizeOf(u32) + @sizeOf(u32);
        const db: ?ValuePair = if (database) |db| .{ .key = "database", .val = db } else null;

        return .{
            // .len = @intCast(len),
            .user = user,
            .database = db,
        };
    }

    pub fn encode(self: *const StartupMsg, buf: []u8) !void {
        var w_pos: usize = 0;
        const len_width = 4;
        const proto_width = 4;

        const len: u32 = @intCast(width(self.database) + self.user.size() + len_width + proto_width + 1); // len and proto width final null byte
        w_pos += writeInt(len, buf[w_pos..len_width][0..len_width]);
        w_pos += writeInt(self.protocol, buf[w_pos .. w_pos + proto_width][0..proto_width]);
        w_pos += writeValuePair(self.user, buf[w_pos .. w_pos + self.user.size()][0..self.user.size()]);
        w_pos += writeOptional(self.database, w_pos, buf);
        w_pos += writeOptional(self.options, w_pos, buf);
        w_pos += writeOptional(self.replication, w_pos, buf);
        buf[w_pos] = 0x00;
    }

    pub fn size(self: *const StartupMsg) usize {
        return 8 + width(self.user) +
            width(self.database) +
            width(self.options) +
            width(self.replication) +
            1; // trailing null byte
    }
};

pub fn writeValuePair(value_pair: ValuePair, buf: []u8) usize {
    assert(buf.len == value_pair.size());
    _ = writeSlice(value_pair.key, buf[0..value_pair.key.len]);
    buf[value_pair.key.len] = 0x00; // padding
    _ = writeSlice(value_pair.val, buf[value_pair.key.len + 1 .. value_pair.key.len + 1 + value_pair.val.len]);
    buf[value_pair.key.len + 1 + value_pair.val.len] = 0x00; // padding

    return buf.len;
}

pub fn writeSlice(slice: anytype, buf: []u8) usize {
    assert(@typeInfo(@TypeOf(slice)) == .Pointer);
    assert(buf.len == width(slice));
    @memcpy(buf, slice);
    return buf.len;
}

pub fn writeInt(int: anytype, buf: []u8) usize {
    const T = @TypeOf(int);
    assert(@typeInfo(T) == .Int);
    assert(buf.len == @sizeOf(T));

    std.mem.writeInt(T, buf[0..@sizeOf(T)], int, .little);
    return buf.len;
}

pub fn writeOptional(op_val: anytype, w_pos: usize, buf: []u8) usize {
    assert(@typeInfo(@TypeOf(op_val)) == .Optional);
    if (op_val) |val| {
        if (@TypeOf(val) == ValuePair) return writeValuePair(val, buf[w_pos .. w_pos + val.size()]);

        return switch (@typeInfo(@TypeOf(val))) {
            .Pointer => writeSlice(val, buf),
            .Int => writeInt(val, buf),
            else => std.debug.panic("Unsupported Type: {}", .{@TypeOf(val)}),
        };
    }
    return 0;
}

pub fn width(val: anytype) usize {
    const T = @TypeOf(val);

    if (T == ValuePair) return val.size();

    return switch (@typeInfo(T)) {
        .Pointer => |ptr| {
            assert(@typeInfo(ptr.child) == .Int);
            return @sizeOf(ptr.child) * val.len;
        },
        .Int => @sizeOf(T),
        .Optional => if (val) |value| width(value) else 0,
        else => std.debug.panic("Unsupported Type: {}", .{T}),
    };
}

test "decode auth res" {
    const alloc = std.testing.allocator;

    const input = &[_]u8{ 'R', 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    var codec = Codec.init(alloc);
    const result = try codec.decode(input);
    defer codec.deinit();

    const expected = AuthRes{
        .auth_type = .Ok,
    };

    try std.testing.expect(testAuthRes(result, expected));
}

test "decode error" {
    const alloc = std.testing.allocator;

    const input = &[_]u8{ 'E', 0x0a, 0x00, 0x00, 0x00, 'S', 'P', 'A', 'N', 'I', 'C' };
    var codec = Codec.init(alloc);
    const result = try codec.decode(input);
    defer codec.deinit();

    const expected = ErrorRes{
        .error_type = ErrorRes.ErrorType.Severity,
        .field = "PANIC",
    };

    try std.testing.expect(testErrorRes(result, expected));
}

test "encode startup" {
    const alloc = std.testing.allocator;
    var codec = Codec.init(alloc);
    defer codec.deinit();

    const msg = FrontendMsg{
        .Startup = StartupMsg{
            .user = ValuePair{ .key = "user", .val = "test" },
            .database = ValuePair{ .key = "database", .val = "test" },
        },
    };
    const result = try codec.encode(&msg);

    const expect = &[_]u8{
        0x20, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00,
        0x75, 0x73, 0x65, 0x72,
        0x00, 0x74, 0x65, 0x73,
        0x74, 0x00, 0x64, 0x61,
        0x74, 0x61, 0x62, 0x61,
        0x73, 0x65, 0x00, 0x74,
        0x65, 0x73, 0x74, 0x00,
    };

    try std.testing.expect(std.mem.eql(u8, expect, result));
}

fn testErrorRes(res: BackendMsg, expected: ErrorRes) bool {
    const error_res = switch (res) {
        .Error => |auth| auth,
        else => return false,
    };
    if (error_res.error_type != expected.error_type) {
        print("Inccorect error_type found: {} expected: {}\n", .{ error_res.error_type, expected.error_type });
        return false;
    }
    const res_field = if (error_res.field) |res_field| res_field else "";
    const expected_field = if (expected.field) |expected_field| expected_field else "";

    if ((res_field.len > 0 or expected_field.len > 0) and !std.mem.eql(u8, res_field, expected_field)) {
        print("Inccorect field found: {s} expected: {s}\n", .{ res_field, expected_field });
        return false;
    }
    return true;
}

fn testAuthRes(res: BackendMsg, expected: AuthRes) bool {
    const auth_res = switch (res) {
        .Auth => |auth| auth,
        else => return false,
    };
    if (auth_res.auth_type != expected.auth_type) {
        print("Inccorect auth_type found: {} expected: {}\n", .{ auth_res.auth_type, expected.auth_type });
        return false;
    }
    if (std.meta.activeTag(auth_res.extra) != std.meta.activeTag(expected.extra)) {
        print("Inccorect auth_type found: {} expected: {}\n", .{ auth_res.auth_type, expected.auth_type });
        return false;
    }
    if (auth_res.extra == .MD5Password and expected.extra == .MD5Password) {
        if (!std.mem.eql(u8, &auth_res.extra.MD5Password.salt, &expected.extra.MD5Password.salt)) {
            print("Inccorect extra found: {s} expected: {s}\n", .{ auth_res.extra.MD5Password.salt, expected.extra.MD5Password.salt });
            return false;
        }
    }
    return true;
}
