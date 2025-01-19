const std = @import("std");
const http = std.http;
const Allocator = std.mem.Allocator;
const Protocol = http.Client.Connection.Protocol;
const assert = std.debug.assert;

pub fn main() !void {
    // var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    // const alloc = gpa.allocator();
    // defer _ = gpa.deinit();
    // var startup = try StartupMessage.create(3, .{ .user = "test", .database = "test" });
    // const buf = try alloc.alloc(u8, startup.size());
    // defer alloc.free(buf);
    // startup.write(buf);
    //
    // var conn = try Conn.init("127.0.0.1", 8080, Protocol.plain, alloc);
    //
    // const payload = "noice";
    //
    // var buff: [1 + 4 + payload.len]u8 = undefined;
    // Message.write(1, payload, &buff);
    //
    // var read_buf: [10]u8 = undefined;
    //
    // try conn.write(&buff);
    //
    // try conn.read(&read_buf);
    // std.debug.print("res: ", .{});
    // for (read_buf) |read| std.debug.print("0x{x} ", .{read});
    // std.debug.print("\n", .{});
    //
    // try conn.write(buf);
    //
    // try conn.read(&read_buf);
    //
    // defer conn.deinit();
}
