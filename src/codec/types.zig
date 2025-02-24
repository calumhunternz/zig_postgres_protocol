const std = @import("std");
const assert = std.debug.assert;

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

    pub fn readInt32(self: *Reader) u32 {
        assert(self.r_pos < self.buf.len);
        assert(self.r_pos <= self.buf.len - 4);

        const num = std.mem.readInt(u32, self.buf[self.r_pos .. self.r_pos + 4][0..4], .big);
        self.r_pos += 4;
        return num;
    }

    pub fn readIntStr(self: *Reader, comptime T: type, size: usize) !T {
        assert(@typeInfo(T) == .Int);
        const num = try std.fmt.parseInt(T, self.buf[self.r_pos .. self.r_pos + size], 10);
        self.r_pos += 4;
        return num;
    }

    pub fn readToDelimeter(self: *Reader, delimeter: u8) ?[]const u8 {
        const start = self.r_pos;
        while (self.r_pos - start < self.buf[start..].len) {
            if (self.peek() == delimeter) {
                self.r_pos += 1;
                const buf = self.buf[start..self.r_pos];
                self.r_pos += 1; // skip past delimeter
                return buf;
            }
            self.r_pos += 1;
        }
        return null;
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

    pub fn skip(self: *Reader, n: usize) void {
        assert(self.buf.len >= self.r_pos + n);
        self.r_pos += n;
    }

    pub fn peek(self: *Reader) ?u8 {
        if (self.r_pos >= self.buf.len - 1) return null;
        return self.buf[self.r_pos + 1];
    }
};

pub const ValuePair = struct {
    key: []const u8,
    val: []const u8,
    const padding: usize = 2;

    pub fn size(self: *const ValuePair) u32 {
        return @intCast(self.key.len + self.val.len + padding);
    }
};

pub const SASLMechanism = enum {
    SCRAM_SHA_256,
    SCRAM_SHA_256_PLUS,

    pub fn str(self: *const SASLMechanism) []const u8 {
        return switch (self.*) {
            .SCRAM_SHA_256 => "SCRAM-SHA-256",
            .SCRAM_SHA_256_PLUS => "SCRAM-SHA-256-PLUS",
        };
    }
};

pub const AuthType = enum(u32) {
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
