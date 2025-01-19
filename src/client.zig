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

    pub fn connect(self: *PostgresClient) ConnectionResult {
        // HANDSHAKE
        // const strt_msg = Star
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
};

pub const Connection = struct {
    alloc: Allocator,
    client: http.Client,
    connection: *http.Client.Connection,

    pub fn init(host: []const u8, port: u16, protocol: Protocol, alloc: Allocator) !Connection {
        var client = http.Client{ .allocator = alloc };
        const connection = try client.connectTcp(host, port, protocol);

        return .{ .client = client, .connection = connection, .alloc = alloc };
    }

    pub fn write(self: *Connection, input: []const u8) !void {
        // writeAllDirect writes into the buffer and the sends it
        // regular write writes into the buffer but does not send until
        // flush is called
        _ = try self.connection.write(input);
        try self.connection.flush();
    }

    pub fn read(self: *Connection, output: []u8) !void {
        _ = try self.connection.read(output);
    }

    pub fn deinit(self: *Connection) void {
        self.client.connection_pool.release(self.alloc, self.connection);
        self.client.deinit();
    }
};
