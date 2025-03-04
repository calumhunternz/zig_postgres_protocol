const std = @import("std");
const debug = @import("./testing/debug_utils.zig");

const print_slice = debug.print_slice;
const print_slice_ch = debug.print_slice_ch;
const Allocator = std.mem.Allocator;
const Protocol = std.http.Client.Connection.Protocol;
const Connection = @This();

stream: std.net.Stream,
address: std.net.Address,
alloc: Allocator,
// TODO: add tls support

read_start: usize = 0,
read_end: usize = 0,
write_end: usize = 0,
read_buf: [buffer_size]u8 = undefined,
write_buf: [buffer_size]u8 = undefined,

pub const buffer_size = std.crypto.tls.max_ciphertext_record_len;

pub fn init(host: []const u8, port: u16, protocol: Protocol, alloc: Allocator) !Connection {
    _ = protocol;

    const address = std.net.Address.parseIp4(host, port) catch return error.InvalidConnectionOptions;
    // TODO: add timeout (requires accessing the posix socket instead of stream since the setting is not exposed via higher level api)
    const stream = std.net.tcpConnectToAddress(address) catch |err| {
        return err;
    };
    errdefer stream.close();

    return .{
        .stream = stream,
        .address = address,
        .alloc = alloc,
    };
}

pub fn write(self: *Connection, buf: []const u8) !void {
    // TODO: optimize message parser to use writev instead of parsing
    // message to an intermediate buffer
    try self.stream.writeAll(buf);
}

pub const ReadError = error{
    ReadBufTooSmall,
    ConnectionClosed,
};

fn ensureSize(self: *Connection, size: usize) !void {
    if (self.read_buf.len < size) return ReadError.ReadBufTooSmall;
    const space = self.read_buf.len - self.read_start;
    if (space > size) return;

    std.mem.copyForwards(u8, self.read_buf[self.read_start..self.read_end], self.read_buf[0..]);
    self.read_end = self.read_end - self.read_start;
    self.read_start = 0;
}

fn bufferedMsg(self: *Connection) !?[]u8 {
    std.debug.assert(self.read_end >= self.read_start);
    const header_size = 5;
    if (self.read_end - self.read_start < header_size) {
        try self.ensureSize(header_size);
        return null;
    }

    const len = std.mem.readInt(u32, self.read_buf[self.read_start + 1 ..][0..4], .big);

    const msg_type_size = 1;
    const msg_size = len + msg_type_size;

    // if the read did not read a full msg
    if (self.read_end - self.read_start < msg_size) {
        try self.ensureSize(msg_size);
        return null;
    }
    const msg = self.read_buf[self.read_start..][0..msg_size];
    self.read_start += msg_size;
    return msg;
}

pub fn read_raw(self: *Connection) ![]u8 {
    std.debug.print("read start {d}", .{self.read_start});
    const n = try self.stream.read(self.read_buf[self.read_start..]);
    if (n == 0) return ReadError.ConnectionClosed;
    self.read_end += n;
    const buf = self.read_buf[self.read_start..self.read_end];
    self.read_start = self.read_end;
    return buf;
}

pub fn read(self: *Connection) ![]u8 {
    while (true) {
        if (try self.bufferedMsg()) |msg| {
            return msg;
        }
        const n = try self.stream.read(self.read_buf[self.read_start..]);

        if (n == 0) return ReadError.ConnectionClosed;
        self.read_end += n;
    }
}

pub fn deinit(self: *Connection) void {
    _ = self;
    return;
}
