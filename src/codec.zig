const std = @import("std");
const print = std.debug.print;
const assert = std.debug.assert;

pub fn print_slice(slice: anytype, tag: []const u8) void {
    print("{s}: ", .{tag});
    for (slice) |x| print("{x} ", .{x});
    print("\n", .{});
}

pub const FrontendMsg = union(FrontendMsgType) {
    Startup: StartupMsg,
    SASLInit: SASLInitMsg,

    const FrontendMsgType = enum {
        Startup,
        SASLInit,
    };

    pub fn encode(
        self: *const FrontendMsg,
        buf: []u8,
        writer: *Writer,
    ) !void {
        return switch (self.*) {
            .Startup => |startup_msg| startup_msg.encode(buf, writer),
            .SASLInit => |sasl_initial_msg| sasl_initial_msg.encode(buf),
        };
    }

    pub fn size(self: *const FrontendMsg) usize {
        return switch (self.*) {
            .Startup => |startup| startup.size(),
            .SASLInit => |sasl_init| sasl_init.size(),
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

    pub fn decode(
        buf: []const u8,
        reader: *Reader,
    ) !BackendMsg {
        const header = parseHeader(buf, reader);

        switch (header.msg_type) {
            .AuthRes => {
                const auth_res = try AuthRes.decode(reader);
                return BackendMsg{ .Auth = auth_res };
            },
            .ErrorRes => {
                const error_res = try ErrorRes.decode(reader);
                return BackendMsg{ .Error = error_res };
            },
        }
    }

    fn parseHeader(buf: []const u8, reader: *Reader) Header {
        assert(buf.len > HEADER_SIZE);
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

pub const Codec = struct {
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
        try msg.encode(buf, &writer);
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

    pub fn decode(reader: *Reader) !ErrorRes {
        return ErrorRes{
            .error_type = @enumFromInt(reader.readByte1()),
            // TODO: field is different per error code just mapping all remaining data to a buf for now
            // but would want individual mapping in future
            .field = reader.readRemaining(),
        };
    }
};

const SASLMechanism = enum {
    SCRAM_SHA_256,
    SCRAM_SHA_256_PLUS,

    pub fn str(self: *const SASLMechanism) []const u8 {
        return switch (self.*) {
            .SCRAM_SHA_256 => "SCRAM-SHA-256",
            .SCRAM_SHA_256_PLUS => "SCRAM-SHA-256-PLUS",
        };
    }
};

pub const AuthRes = struct {
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
        SASL: SASLMechanism, // null terminated list of auth schemes will require enum once those are found.
        SASLContinue: struct { data: []u8 },
        SALSFinal: struct { data: []u8 },
        None,
    };

    const DecodeError = error{
        NoSaslMechanism,
    };

    pub fn decode(reader: *Reader) !AuthRes {
        const auth_type: AuthType = @enumFromInt(reader.readu32());
        const extra = switch (auth_type) {
            .SASL => extra: {
                const mechanism = reader.readToDelimeter(0x00); // Server sends in order of preference so only the first one is needed
                // Should this be assert or error since it is coming over wire stuff could go bad.
                assert(std.mem.eql(u8, mechanism, "SCRAM-SHA-256") or std.mem.eql(u8, mechanism, "SCRAM-SHA-256-PLUS"));

                if (std.mem.eql(u8, mechanism, "SCRAM-SHA-256")) {
                    break :extra AuthExtra{ .SASL = SASLMechanism.SCRAM_SHA_256 };
                } else if (std.mem.eql(u8, mechanism, "SCRAM-SHA-256-PLUS")) {
                    break :extra AuthExtra{ .SASL = SASLMechanism.SCRAM_SHA_256_PLUS };
                }
                unreachable;
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
        const db: ?ValuePair = if (database) |db| .{ .key = "database", .val = db } else null;
        return .{
            .user = user,
            .database = db,
        };
    }

    pub fn encode(self: *const StartupMsg, buf: []u8, writer: *Writer) !void {
        writer.writeInt(@as(u32, @intCast(self.size())));
        writer.writeInt(self.protocol);
        writer.writeValuePair(self.user);
        writer.writeOptional(self.database);
        writer.writeOptional(self.options);
        writer.writeOptional(self.replication);
        writer.writeByte(0x00);

        _ = buf;

        // var w_pos: usize = 0;
        // w_pos += writeInt(@as(u32, @intCast(self.size())), w_pos, buf);
        // w_pos += writeInt(self.protocol, w_pos, buf);
        // w_pos += writeValuePair(self.user, w_pos, buf);
        // w_pos += writeOptional(self.database, w_pos, buf);
        // w_pos += writeOptional(self.options, w_pos, buf);
        // w_pos += writeOptional(self.replication, w_pos, buf);
        // w_pos += writeByte(0x00, w_pos, buf);
    }

    pub fn size(self: *const StartupMsg) usize {
        return 8 + width(self.user) +
            width(self.database) +
            width(self.options) +
            width(self.replication) +
            1; // trailing null byte
    }
};

pub const SASLInitMsg = struct {
    msg_type: u8 = 'p',
    mech: SASLMechanism,
    res: []const u8,

    pub fn new(mech: SASLMechanism, res: []u8) SASLInitMsg {
        return .{ .mech = mech, .res = res };
    }

    pub fn size(self: *const SASLInitMsg) usize {
        return 1 + 4 + self.mech.str().len + 1 + 4 + self.res.len + 1;
    }

    pub fn encode(self: SASLInitMsg, buf: []u8) void {
        var w_pos: usize = 0;
        const len_width = 4;
        const len: u32 = @intCast(len_width + self.mech.str().len + 1 + 4 + self.res.len + 1);

        w_pos += writeByte(self.msg_type, w_pos, buf);
        w_pos += writeInt(len, w_pos, buf);
        w_pos += writeSlice(self.mech.str(), w_pos, buf);
        w_pos += writeByte(0x00, w_pos, buf);
        w_pos += writeInt(@as(u32, @intCast(self.res.len)), w_pos, buf);
        w_pos += writeSlice(self.res, w_pos, buf);
        w_pos += writeByte(0x00, w_pos, buf);
    }
};

pub fn writeByte(val: u8, w_pos: usize, buf: []u8) usize {
    assert(w_pos < buf.len);
    buf[w_pos] = val;
    return 1;
}

pub fn writeValuePair(value_pair: ValuePair, w_pos: usize, buf: []u8) usize {
    assert(buf.len >= w_pos + value_pair.size());
    const key_len = writeSlice(value_pair.key, w_pos, buf);
    buf[w_pos + key_len] = 0x00; // padding
    const val_len = writeSlice(value_pair.val, w_pos + key_len + 1, buf);
    buf[w_pos + key_len + 1 + val_len] = 0x00; // padding

    return value_pair.size();
}

pub fn writeSlice(slice: anytype, w_pos: usize, buf: []u8) usize {
    assert(@typeInfo(@TypeOf(slice)) == .Pointer);
    assert(@typeInfo(@TypeOf(slice)).Pointer.child == u8);

    const slice_size = slice.len;

    assert(buf.len >= w_pos + slice.len);
    @memcpy(buf[w_pos .. w_pos + slice.len][0..slice.len], slice);
    return slice_size;
}

pub fn writeInt(int: anytype, w_pos: usize, buf: []u8) usize {
    const T = @TypeOf(int);
    assert(@typeInfo(T) == .Int);
    const int_size = @sizeOf(T);
    assert(buf.len >= w_pos + int_size);

    std.mem.writeInt(T, buf[w_pos .. w_pos + int_size][0..int_size], int, .big);
    return int_size;
}

pub fn writeOptional(op_val: anytype, w_pos: usize, buf: []u8) usize {
    assert(@typeInfo(@TypeOf(op_val)) == .Optional);
    if (op_val) |val| {
        if (@TypeOf(val) == ValuePair) return writeValuePair(val, w_pos, buf);

        return switch (@typeInfo(@TypeOf(val))) {
            .Pointer => writeSlice(val, buf),
            .Int => writeInt(val, w_pos, w_pos, buf),
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

pub const Writer = struct {
    w_pos: usize = 0,
    buf: []u8,

    pub fn writer(buf: []u8) Writer {
        return Writer{ .buf = buf };
    }

    pub fn writeByte(self: *Writer, val: u8) void {
        assert(self.w_pos < self.buf.len);
        self.buf[self.w_pos] = val;
        self.w_pos += 1;
    }

    pub fn writeInt(self: *Writer, int: anytype) void {
        const T = @TypeOf(int);
        const int_size = @sizeOf(T);

        assert(@typeInfo(T) == .Int);
        assert(self.buf.len >= self.w_pos + int_size);

        std.mem.writeInt(T, self.buf[self.w_pos .. self.w_pos + int_size][0..int_size], int, .big);
        self.w_pos += int_size;
    }

    pub fn writeSlice(self: *Writer, val: anytype) void {
        assert(@typeInfo(@TypeOf(val)) == .Pointer);
        assert(@typeInfo(@TypeOf(val)).Pointer.child == u8);
        assert(self.buf.len >= self.w_pos + val.len);

        @memcpy(self.buf[self.w_pos .. self.w_pos + val.len][0..val.len], val);
        self.w_pos += val.len;
    }

    pub fn writeValuePair(self: *Writer, value_pair: ValuePair) void {
        assert(self.buf.len >= self.w_pos + value_pair.size());
        self.writeSlice(value_pair.key);
        self.writeByte(0x00);
        self.writeSlice(value_pair.val);
        self.writeByte(0x00);
    }

    // Does nothing if optional value is null
    pub fn writeOptional(self: *Writer, val: anytype) void {
        assert(@typeInfo(@TypeOf(val)) == .Optional);
        if (val == null) return;
        if (@TypeOf(val.?) == ValuePair) return self.writeValuePair(val.?);
        switch (@typeInfo(@TypeOf(val.?))) {
            .Pointer => self.writeSlice(val.?),
            .Int => self.writeInt(val.?),
            else => std.debug.panic("Unsupported Type: {}", .{@TypeOf(val)}),
        }
    }
};

pub const Reader = struct {
    r_pos: usize = 0,
    buf: []const u8,

    pub fn reader(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    pub fn readByte1(self: *Reader) u8 {
        assert(self.r_pos < self.buf.len); // r_pos should never be outside the buf bounds
        assert(self.r_pos != self.buf.len);
        const byte = self.next();
        assert(byte != null);
        return byte.?;
    }

    pub fn readu32(self: *Reader) u32 {
        assert(self.r_pos < self.buf.len);
        assert(self.r_pos <= self.buf.len - 4);
        const num = std.mem.readInt(u32, self.buf[self.r_pos .. self.r_pos + 4][0..4], .big);
        self.r_pos += 4;
        return num;
    }

    pub fn readToDelimeter(self: *Reader, delimeter: u8) []const u8 {
        const start = self.r_pos;
        while (self.r_pos - start < self.buf[start..].len) {
            if (self.peek() == delimeter) {
                self.r_pos += 1;
                break;
            }
            self.r_pos += 1;
        }
        return self.buf[start..self.r_pos];
    }

    pub fn readRemaining(self: *Reader) ?[]const u8 {
        if (self.r_pos >= self.buf.len) return null;

        const remaining = self.buf[self.r_pos..];
        self.r_pos += remaining.len;
        assert(self.r_pos == self.buf.len);
        return remaining;
    }

    pub fn next(self: *Reader) ?u8 {
        if (self.r_pos >= self.buf.len) return null;
        const byte = self.buf[self.r_pos];
        self.r_pos += 1;
        return byte;
    }

    pub fn peek(self: *Reader) ?u8 {
        if (self.r_pos >= self.buf.len - 1) return null;
        return self.buf[self.r_pos + 1];
    }
};

test "decode auth res" {
    const alloc = std.testing.allocator;

    const input = &[_]u8{ 'R', 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00 };
    var codec = Codec.init(alloc);
    const result = try codec.decode(input);
    defer codec.deinit();

    const expected = BackendMsg{ .Auth = AuthRes{
        .auth_type = .Ok,
    } };

    try std.testing.expectEqualDeep(expected, result);
}

test "decode SASL" {
    const input1 = &[_]u8{
        0,   0,   0,   0x0a,
        'S', 'C', 'R', 'A',
        'M', '-', 'S', 'H',
        'A', '-', '2', '5',
        '6', 0,   0,
    };
    var reader1 = Reader.reader(input1);
    const result1 = AuthRes.decode(&reader1);
    const expected1 = AuthRes{
        .auth_type = .SASL,
        .extra = .{ .SASL = .SCRAM_SHA_256 },
    };
    try std.testing.expectEqualDeep(expected1, result1);

    const input2 = &[_]u8{
        0,   0,   0,   0x0a,
        'S', 'C', 'R', 'A',
        'M', '-', 'S', 'H',
        'A', '-', '2', '5',
        '6', '-', 'P', 'L',
        'U', 'S', 0,   0,
    };
    var reader2 = Reader.reader(input2);
    const result2 = AuthRes.decode(&reader2);
    const expected2 = AuthRes{
        .auth_type = .SASL,
        .extra = .{ .SASL = .SCRAM_SHA_256_PLUS },
    };
    try std.testing.expectEqualDeep(expected2, result2);
    const input3 = &[_]u8{
        0,   0,   0,   0x0a, 'S',
        'C', 'R', 'A', 'M',  '-',
        'S', 'H', 'A', '-',  '2',
        '5', '6', '-', 'P',  'L',
        'U', 'S', 0,   'S',  'C',
        'R', 'A', 'M', '-',  'S',
        'H', 'A', '-', '2',  '5',
        '6', 0,   0,
    };
    var reader3 = Reader.reader(input3);
    const result3 = AuthRes.decode(&reader3);
    const expected3 = AuthRes{
        .auth_type = .SASL,
        .extra = .{ .SASL = .SCRAM_SHA_256_PLUS },
    };
    try std.testing.expectEqualDeep(expected3, result3);
}

test "SASLInit" {
    const alloc = std.testing.allocator;
    var codec = Codec.init(alloc);
    defer codec.deinit();

    const msg = FrontendMsg{ .SASLInit = .{
        .mech = .SCRAM_SHA_256,
        .res = "hello there",
    } };

    const result = try codec.encode(&msg);

    const expect = &[_]u8{
        'p',  0x00, 0x00, 0x00, 0x22,
        'S',  'C',  'R',  'A',  'M',
        '-',  'S',  'H',  'A',  '-',
        '2',  '5',  '6',  0x00, 0x00,
        0x00, 0x00, 0x0b, 'h',  'e',
        'l',  'l',  'o',  ' ',  't',
        'h',  'e',  'r',  'e',  0x00,
    };
    print_slice(expect, "expect");
    print_slice(result, "result");

    try std.testing.expect(std.mem.eql(u8, expect, result));
}

test "decode error" {
    const alloc = std.testing.allocator;

    const input = &[_]u8{ 'E', 0x00, 0x00, 0x00, 0x0a, 'S', 'P', 'A', 'N', 'I', 'C' };
    var codec = Codec.init(alloc);
    const result = try codec.decode(input);
    defer codec.deinit();

    const expected = BackendMsg{ .Error = ErrorRes{
        .error_type = ErrorRes.ErrorType.Severity,
        .field = "PANIC",
    } };

    try std.testing.expectEqualDeep(result, expected);
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
        0x00, 0x00, 0x00, 0x21,
        0x00, 0x03, 0x00, 0x00,
        0x75, 0x73, 0x65, 0x72,
        0x00, 0x74, 0x65, 0x73,
        0x74, 0x00, 0x64, 0x61,
        0x74, 0x61, 0x62, 0x61,
        0x73, 0x65, 0x00, 0x74,
        0x65, 0x73, 0x74, 0x00,
        0x00,
    };

    try std.testing.expect(std.mem.eql(u8, expect, result));
}
