const std = @import("std");
const debug = @import("../testing/debug_utils.zig");
const types = @import("./types.zig");
const Writer = @import("./writer.zig");
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
        return 1 + 8 + self.user.size() +
            (if (self.database) |db| db.size() else 0) +
            (if (self.options) |op| op.size() else 0) +
            (if (self.replication) |rep| rep.size() else 0);
    }
};

pub const SASLInitMsg = struct {
    msg_type: u8 = 'p',
    mech: SASLMechanism,
    client_first_message: []const u8,

    pub fn new(mech: SASLMechanism, client_first_message: []const u8) SASLInitMsg {
        return .{
            .mech = mech,
            .client_first_message = client_first_message,
        };
    }

    pub fn size(self: *const SASLInitMsg) usize {
        return 4 + self.mech.str().len + 1 + 4 + self.client_first_message.len + 1;
    }

    pub fn encode(self: SASLInitMsg, writer: *Writer) void {
        writer.writeByte(self.msg_type);
        writer.writeInt(@as(u32, @intCast(self.size() - 1))); // len does not include msg_type
        writer.writeSlice(self.mech.str());
        writer.writeByte(0x00);
        writer.writeInt(@as(u32, @intCast(self.client_first_message.len)));
        writer.writeSlice(self.client_first_message);
    }
};

pub const SASLResMsg = struct {
    msg_type: u8 = 'p',
    client_final_msg: []const u8,

    pub fn new(client_final_msg: []const u8) SASLResMsg {
        return .{ .client_final_msg = client_final_msg };
    }

    pub fn size(self: *const SASLResMsg) usize {
        return 1 + 4 + self.client_final_msg.len;
    }

    pub fn encode(self: SASLResMsg, writer: *Writer) void {
        writer.writeByte(self.msg_type);
        writer.writeInt(@as(u32, @intCast(self.size() - 1)));
        writer.writeSlice(self.client_final_msg);
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

pub fn print_slice(slice: anytype, tag: []const u8) void {
    std.debug.print("{s}: ", .{tag});
    for (slice) |x| {
        std.debug.print("{X:0>2} ", .{x});
    }
    std.debug.print("\n", .{});
}

test "SASLInit" {
    const msg = SASLInitMsg{
        .mech = .SCRAM_SHA_256,
        .client_first_message = "n,,n=postgres,r=ABC123",
    };
    const alloc = std.testing.allocator;
    const buf = try alloc.alloc(u8, msg.size());
    defer alloc.free(buf);
    var writer = Writer.writer(buf);

    msg.encode(&writer);

    const expect = &[_]u8{
        'p',  0x00, 0x00, 0x00, 0x2C,
        'S',  'C',  'R',  'A',  'M',
        '-',  'S',  'H',  'A',  '-',
        '2',  '5',  '6',  0x00, 0x00,
        0x00, 0x00, 0x16, 'n',  ',',
        ',',  'n',  '=',  'p',  'o',
        's',  't',  'g',  'r',  'e',
        's',  ',',  'r',  '=',  'A',
        'B',  'C',  '1',  '2',  '3',
    };

    try std.testing.expect(std.mem.eql(u8, expect, buf));
}
