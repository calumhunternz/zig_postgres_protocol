const std = @import("std");
const ggg = @import("../codec.zig");
const tested = ggg.BackendMsg;
const posix = std.posix;

running: std.atomic.Value(bool),
pub const TestServer = @This();

pub const Server = struct {
    address: std.net.Address,
    server: std.net.Server,
    conn: std.net.Stream,
    reader: Reader,
    running: *std.atomic.Value(bool),
    stop: *std.atomic.Value(bool),

    pub const Reader = struct {
        stream: std.net.Stream,
        read_start: usize = 0,
        read_end: usize = 0,
        write_end: usize = 0,
        read_buf: [buffer_size]u8 = undefined,
        write_buf: [buffer_size]u8 = undefined,

        pub const buffer_size = std.crypto.tls.max_ciphertext_record_len;

        pub const ReadError = error{
            ReadBufTooSmall,
            ConnectionClosed,
        };

        fn ensureSize(self: *Reader, size: usize) !void {
            if (self.read_buf.len < size) return ReadError.ReadBufTooSmall;
            const space = self.read_buf.len - self.read_start;
            if (space > size) return;

            std.mem.copyForwards(u8, self.read_buf[self.read_start..self.read_end], self.read_buf[0..]);
            self.read_end = self.read_end - self.read_start;
            self.read_start = 0;
        }

        fn bufferedMsg(self: *Reader) !?[]u8 {
            std.debug.assert(self.read_end >= self.read_start);
            const header_size = 4;
            if (self.read_end - self.read_start < header_size) {
                try self.ensureSize(header_size);
                return null;
            }

            const msg_size = std.mem.readInt(u32, self.read_buf[self.read_start..self.read_end][0..4], .little);

            if (self.read_end - self.read_start < msg_size) {
                try self.ensureSize(msg_size);
                return null;
            }
            const msg = self.read_buf[self.read_start..self.read_end];
            self.read_start += msg_size;
            return msg;
        }

        pub fn read(self: *Reader) ![]u8 {
            while (true) {
                if (try self.bufferedMsg()) |msg| {
                    return msg;
                }

                const n = try self.stream.read(&self.read_buf);

                if (n == 0) return ReadError.ConnectionClosed;
                self.read_end += n;
            }
        }
    };

    // TODO set up a struct so that from the test i can just call testing_server.start/stop functions to hide thread management from tests

    pub fn start(port: u16, res: []const u8, running: *std.atomic.Value(bool)) !void {
        const address = try std.net.Address.parseIp("127.0.0.1", port);
        var server = try address.listen(.{ .reuse_port = true });
        errdefer server.deinit();

        var res_cpy: [1000]u8 = undefined;

        std.mem.copyForwards(u8, &res_cpy, res);
        const response = res_cpy[0..res.len];

        var conn = try server.accept();
        running.store(true, .seq_cst);
        errdefer conn.stream.close();
        var reader = Reader{ .stream = conn.stream };

        while (running.load(.seq_cst)) {
            const red = try reader.read();
            if (red.len > 0) {
                try conn.stream.writeAll(response);
            }
        }

        server.deinit();
    }
};

pub const TestServerOptions = struct {
    port: u16 = 5882,
};

pub fn start(options: TestServerOptions) !TestServer {
    var server = TestServer{
        .running = std.atomic.Value(bool).init(false),
    };
    const res: []const u8 = &[_]u8{
        'R',
        0x08,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    const server_thread = try std.Thread.spawn(.{}, Server.start, .{
        options.port,
        res,
        &server.running,
    });
    defer server_thread.detach();

    return server;
}

pub fn stop(self: *TestServer) void {
    self.running.store(false, .seq_cst);
}
