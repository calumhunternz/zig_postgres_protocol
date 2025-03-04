const std = @import("std");
const assert = std.debug.assert;

const Reader = @This();

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
