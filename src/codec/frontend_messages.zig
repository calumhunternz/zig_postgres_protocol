const std = @import("std");
const types = @import("./types.zig");
const Writer = types.Writer;
const ValuePair = types.ValuePair;
const SASLMechanism = types.SASLMechanism;

pub const StartupMsg = struct {
    protocol: u32 = 0x00030000, // 16 sig bit for major 16 bit for minor
    user: ValuePair,
    database: ?ValuePair = null,
    options: ?ValuePair = null, // Depracated in postgres but leaving here
    replication: ?ValuePair = null, // not going to use for now but leaving here

    pub fn new(usr: []const u8, database: ?[]const u8) StartupMsg {
        return .{
            .user = .{ .key = "user", .val = usr },
            .database = if (database) |db| .{ .key = "database", .val = db } else null,
        };
    }

    pub fn encode(self: *const StartupMsg, writer: *Writer) void {
        writer.writeInt(@as(u32, @intCast(self.size())));
        writer.writeInt(self.protocol);
        writer.writeValuePair(self.user);
        writer.writeOptional(self.database);
        writer.writeOptional(self.options);
        writer.writeOptional(self.replication);
        writer.writeByte(0x00);
    }

    pub fn size(self: *const StartupMsg) usize {
        return 8 + self.user.size() +
            (if (self.database) |db| db.size() else 0) +
            (if (self.options) |op| op.size() else 0) +
            (if (self.replication) |rep| rep.size() else 0) +
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

    pub fn encode(self: SASLInitMsg, writer: *Writer) void {
        writer.writeByte(self.msg_type);
        writer.writeInt(@as(u32, @intCast(self.size())) - 1); // len does not include the msg_type
        writer.writeSlice(self.mech.str());
        writer.writeByte(0x00);
        writer.writeInt(@as(u32, @intCast(self.res.len)));
        writer.writeSlice(self.res);
        writer.writeByte(0x00);
    }
};

test "Startup" {
    const msg = StartupMsg{
        .user = ValuePair{ .key = "user", .val = "test" },
        .database = ValuePair{ .key = "database", .val = "test" },
    };
    const alloc = std.testing.allocator;
    const buf = try alloc.alloc(u8, msg.size());
    defer alloc.free(buf);
    var writer = Writer.writer(buf);

    msg.encode(&writer);

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

    try std.testing.expect(std.mem.eql(u8, expect, buf));
}

test "SASLInit" {
    const msg = SASLInitMsg{
        .mech = .SCRAM_SHA_256,
        .res = "hello there",
    };
    const alloc = std.testing.allocator;
    const buf = try alloc.alloc(u8, msg.size());
    defer alloc.free(buf);
    var writer = Writer.writer(buf);

    msg.encode(&writer);

    const expect = &[_]u8{
        'p',  0x00, 0x00, 0x00, 0x22,
        'S',  'C',  'R',  'A',  'M',
        '-',  'S',  'H',  'A',  '-',
        '2',  '5',  '6',  0x00, 0x00,
        0x00, 0x00, 0x0b, 'h',  'e',
        'l',  'l',  'o',  ' ',  't',
        'h',  'e',  'r',  'e',  0x00,
    };
    try std.testing.expect(std.mem.eql(u8, expect, buf));
}
