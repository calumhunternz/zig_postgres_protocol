const std = @import("std");
const codec = @import("./codec.zig");
const Codec = codec.Codec;
const http = std.http;
const Allocator = std.mem.Allocator;
const Protocol = http.Client.Connection.Protocol;

pub const PostgresClient = struct {
    allocator: Allocator,
    connection: Connection,
    codec: Codec,
    options: PgConOps,

    pub fn init(options: PgConOps, alloc: Allocator) !PostgresClient {
        const protocol = if (options.enable_tls) Protocol.tls else Protocol.plain;
        const con = try Connection.init(options.host, options.port, protocol, alloc);
        return PostgresClient{
            .allocator = alloc,
            .connection = con,
            .codec = Codec.init(alloc),
            .options = options,
        };
    }

    pub fn connect(self: *PostgresClient) !codec.BackendMsg {
        const startup_msg = codec.FrontendMsg.new(.Startup, .{
            .user = self.options.user,
            .database = self.options.database,
        });
        const startup_msg_buf = try self.codec.encode(&startup_msg);
        try self.connection.write(startup_msg_buf);

        const msg_buf = try self.connection.read();

        const msg: codec.BackendMsg = try self.codec.decode(msg_buf);
        return msg;
    }

    pub fn deinit(self: *PostgresClient) void {
        self.connection.deinit();
        self.codec.deinit();
    }
};

const ConnectionError = error{
    CouldNotConnect,
};

pub const ConnectionResult = union(enum) {
    Error: ConnectionError,
    Ok,
};

pub const PgConOps = struct {
    host: []const u8,
    port: u16,
    enable_tls: bool,
    user: []const u8,
    database: ?[]const u8 = null,
    timeout: u32 = 30,
};

pub const Connection = struct {
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
        const address = try std.net.Address.parseIp4(host, port);
        const stream = try std.net.tcpConnectToAddress(address);
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
        // @memcpy(self.read_buf[self.read_start..self.read_end], self.read_buf[0..]);
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

        const len = std.mem.readInt(u32, self.read_buf[self.read_start + 1 .. self.read_end][0..4], .little);
        const msg_type_size = 1;
        const msg_size = len + msg_type_size;

        // if the read did not read a full msg
        if (self.read_end - self.read_start < msg_size) {
            try self.ensureSize(msg_size);
            return null;
        }
        const msg = self.read_buf[self.read_start..self.read_end];
        self.read_start += msg_size;
        return msg;
    }

    pub fn read(self: *Connection) ![]u8 {
        while (true) {
            if (try self.bufferedMsg()) |msg| {
                std.debug.print("Backend Response: ", .{});
                for (msg) |x| std.debug.print("0x{x} ", .{x});
                std.debug.print("\n", .{});
                return msg;
            }

            const n = try self.stream.read(&self.read_buf);

            if (n == 0) return ReadError.ConnectionClosed;
            self.read_end += n;
        }
    }

    pub fn deinit(self: *Connection) void {
        _ = self;
        return;
        // self.client.connection_pool.release(self.alloc, self.connection);
        // self.client.deinit();
    }
};

const TestServer = @import("./testing/tcp_server.zig");

test "test client connection" {
    var server = try TestServer.start(.{});

    const con_opts: PgConOps = .{
        .host = "127.0.0.1",
        .port = 5882,
        .enable_tls = false,
        .user = "test",
    };
    const alloc = std.testing.allocator;

    var client = try PostgresClient.init(con_opts, alloc);
    defer client.deinit();

    const res = try client.connect();

    switch (res) {
        .Auth => |auth| {
            std.debug.assert(auth.auth_type == .Ok);
        },
        else => unreachable,
    }

    server.stop();
}
