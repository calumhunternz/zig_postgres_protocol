const std = @import("std");
const c = @import("./client.zig");

const PostgresClient = c.PostgresClient;
const http = std.http;
const Allocator = std.mem.Allocator;
const Protocol = http.Client.Connection.Protocol;
const assert = std.debug.assert;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    defer _ = gpa.deinit();

    var client = try PostgresClient.init(.{
        .host = "127.0.0.1",
        .port = 5433,
        .enable_tls = false,
        .user = "postgres",
        .database = "zig_db",
    }, alloc);
    defer client.deinit();

    const res = try client.connect();

    std.debug.print("connection res: {}", .{res});
}
