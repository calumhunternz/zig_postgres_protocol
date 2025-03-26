const std = @import("std");

pub fn print_slice(slice: anytype, tag: []const u8) void {
    std.debug.print("{s}: ", .{tag});
    for (slice) |x| {
        std.debug.print("{X:0>2} ", .{x});
    }
    std.debug.print("\n", .{});
}

pub fn print_slice_ch(slice: anytype, tag: []const u8) void {
    std.debug.print("{s}: ", .{tag});
    for (slice) |x| {
        std.debug.print("{c}", .{x});
    }
    std.debug.print("\n", .{});
}
