const std = @import("std");
const assert = std.debug.assert;
const types = @import("./types.zig");
const ValuePair = types.ValuePair;

const Writer = @This();

w_pos: usize = 0,
buf: []u8,

pub fn writer(buf: []u8) Writer {
    return Writer{ .buf = buf };
}

pub fn init(self: *Writer, buf: []u8) void {
    self.buf = buf;
    self.w_pos = 0;
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
