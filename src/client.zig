const std = @import("std");
const codec = @import("./codec.zig");
const Codec = codec.Codec;
const FMsg = Codec.FrontendMsg;
const BMsg = Codec.BackendMsg;
const MsgParam = FMsg.MsgParam;
const http = std.http;
const Allocator = std.mem.Allocator;
const Protocol = http.Client.Connection.Protocol;
const Base64Decoder = std.base64.standard.Decoder;
const Base64Encoder = std.base64.standard.Encoder;

pub fn print_slice(slice: anytype, tag: []const u8) void {
    _ = tag;
    // std.debug.print("{s}: ", .{tag});
    for (slice) |x| {
        // if (x == 0xf8 or x == 0xb8) break; // undefined memory
        std.debug.print("{X:0>2} ", .{x});
    }
    std.debug.print("\n", .{});
}

pub fn print_slice_ch(slice: anytype, tag: []const u8) void {
    std.debug.print("{s}: ", .{tag});
    for (slice) |x| {
        // if (x == 0xf8 or x == 0xb8) break; // undefined memory
        std.debug.print("{c}", .{x});
    }
    std.debug.print("\n", .{});
}

pub const ClientError = error{
    InvalidConnectionOptions,
};

pub const PgClient = struct {
    allocator: Allocator,
    conn: Connection,
    codec: Codec,
    options: PgConOps,

    pub fn init(options: PgConOps, alloc: Allocator) !PgClient {
        const protocol = if (options.enable_tls) Protocol.tls else Protocol.plain;
        const con = Connection.init(options.host, options.port, protocol, alloc) catch {
            std.debug.print("Invalid ip: {s}\n", .{options.host});
            return ClientError.InvalidConnectionOptions;
        };
        return PgClient{
            .allocator = alloc,
            .conn = con,
            .codec = Codec.init(alloc),
            .options = options,
        };
    }

    pub fn connect(self: *PgClient) !ConnectionResult {
        const startup_msg = FMsg.new(MsgParam{ .Startup = .{
            .user = self.options.user,
            .database = self.options.database,
        } });

        const startup_msg_buf = try self.codec.encode(&startup_msg);

        try self.conn.write(startup_msg_buf);

        const msg_buf = self.conn.read() catch |err| {
            self.conn.deinit();
            return err;
        };

        const msg = self.codec.decode(msg_buf) catch |e| {
            std.debug.print("error: {}\n", .{e});
            self.conn.deinit();
            return AuthError.InternalError;
        };

        self.authenticate(msg) catch {
            return ConnectionResult{ .Error = ConnectionError.CouldNotConnect };
        };

        return ConnectionResult.Ok;
    }

    pub fn deinit(self: *PgClient) void {
        self.conn.deinit();
        self.codec.deinit();
    }

    fn authenticate(self: *PgClient, msg: BMsg) AuthError!void {
        msg.log();
        const auth_method = switch (msg) {
            .Auth => |auth| auth: {
                break :auth auth;
            },
            .Error => {
                return AuthError.ErrorResponse;
            },
        };

        return switch (auth_method.auth_type) {
            .Ok => return,
            .SASL => {
                std.debug.assert(auth_method.extra == .SASL);
                const extra = switch (auth_method.extra) {
                    .SASL => |sasl_mech| sasl_mech,
                    else => return AuthError.NotSupported,
                };
                const initial_msg = FMsg.new(MsgParam{ .SASLInit = .{
                    .mech = extra,
                    .user = self.options.user,
                } });

                const initial_msg_buf = self.codec.encode(&initial_msg) catch |e| {
                    std.debug.print("error: {}\n", .{e});
                    self.conn.deinit();
                    return AuthError.InternalError;
                };
                print_slice(initial_msg_buf, "initial_msg_buf");

                self.conn.write(initial_msg_buf) catch |e| {
                    std.debug.print("error: {}\n", .{e});
                    self.conn.deinit();
                    return AuthError.InternalError;
                };

                std.debug.print("reading...\n", .{});
                const res = self.conn.read() catch |e| {
                    std.debug.print("error: {}\n", .{e});
                    self.conn.deinit();
                    return AuthError.InternalError;
                };

                print_slice(res, "sasl initial msg res");
                const sasl_continue = self.codec.decode(res) catch |e| {
                    std.debug.print("error: {}\n", .{e});
                    self.conn.deinit();
                    return AuthError.InternalError;
                };
                print_slice_ch(sasl_continue.Auth.extra.SASLContinue.salt, "jshfjkshdfkjsdhkf");
                print_slice_ch(sasl_continue.Auth.extra.SASLContinue.server_nonce, "server_nonce");
                const client_first_bare = initial_msg_buf[26..];
                //
                // var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
                // defer arena.deinit();
                // const allocator = arena.allocator();

                // const client_fin = clientFinalMessage(
                //     self.options.password,
                //     sasl_continue.Auth.extra.SASLContinue.server_nonce,
                //     sasl_continue.Auth.extra.SASLContinue.salt,
                //     sasl_continue.Auth.extra.SASLContinue.iteration,
                //     client_first_bare,
                //     sasl_continue.Auth.extra.SASLContinue.server_response,
                //     allocator,
                // ) catch |e| {
                //     std.debug.print("error: {}\n", .{e});
                //     return AuthError.InternalError;
                // };

                var msg_buf: [1026]u8 = undefined;
                const client_final_message_buf = scram(
                    self.options.password,
                    sasl_continue.Auth.extra.SASLContinue.server_nonce,
                    sasl_continue.Auth.extra.SASLContinue.salt,
                    sasl_continue.Auth.extra.SASLContinue.iteration,
                    client_first_bare,
                    sasl_continue.Auth.extra.SASLContinue.server_response,
                    &msg_buf,
                ) catch |e| {
                    std.debug.print("error: {}\n", .{e});
                    return AuthError.InternalError;
                };

                // print_slice(client_fin, "");
                print_slice(client_final_message_buf, "");
                // print_slice_ch(client_fin, "TEST");
                print_slice_ch(client_final_message_buf, "TEST");

                const client_final_message = FMsg.new(MsgParam{ .SASLRes = .{
                    .client_final_msg = client_final_message_buf,
                } });

                const client_final_message_buf2 = self.codec.encode(&client_final_message) catch |e| {
                    std.debug.print("error: {}\n", .{e});
                    self.conn.deinit();
                    return AuthError.InternalError;
                };

                self.conn.write(client_final_message_buf2) catch |e| {
                    std.debug.print("error: {}\n", .{e});
                    self.conn.deinit();
                    return AuthError.InternalError;
                };

                std.debug.print("reading...\n", .{});
                const res_from_final = self.conn.read() catch |e| {
                    std.debug.print("error: {}\n", .{e});
                    self.conn.deinit();
                    return AuthError.InternalError;
                };

                print_slice(res_from_final, "res from final");
                // Below is what i get. if it is not similar to this then it is wrong
                // Server Final message
                // 52 00 00 00 36 00 00 00 0C 76 3D 38 33 52 48 65 76 65 6A 49 4F 4D 64 38 68 53 7A 34 53 64 51 34 77 6C 63 38 75 35 70 31 71 2F 54 4F 67 2B 37 54 6A 6D 4D 5A 56 49 3D
                //
                // AuthenticationOk
                // 52 00 00 00 08 00 00 00 00
                //
                // ParameterStatus
                // 53 00 00 00 16 61 70 70 6C 69 63 61 74 69 6F 6E 5F 6E 61 6D 65 00 00
                // 53 00 00 00 19 63 6C 69 65 6E 74 5F 65 6E 63 6F 64 69 6E 67 00 55 54 46 38 00
                // 53 00 00 00 17 44 61 74 65 53 74 79 6C 65 00 49 53 4F 2C 20 4D 44 59 00
                // 53 00 00 00 26 64 65 66 61 75 6C 74 5F 74 72 61 6E 73 61 63 74 69 6F 6E 5F 72 65 61 64 5F 6F 6E 6C 79 00 6F 66 66 00
                // 53 00 00 00 17 69 6E 5F 68 6F 74 5F 73 74 61 6E 64 62 79 00 6F 66 66 00
                // 53 00 00 00 19 69 6E 74 65 67 65 72 5F 64 61 74 65 74 69 6D 65 73 00 6F 6E 00
                // 53 00 00 00 1B 49 6E 74 65 72 76 61 6C 53 74 79 6C 65 00 70 6F 73 74 67 72 65 73 00
                // 53 00 00 00 14 69 73 5F 73 75 70 65 72 75 73 65 72 00 6F 6E 00
                // 53 00 00 00 19 73 65 72 76 65 72 5F 65 6E 63 6F 64 69 6E 67 00 55 54 46 38 00
                // 53 00 00 00 34 73 65 72 76 65 72 5F 76 65 72 73 69 6F 6E 00 31 35 2E 31 30 20 28 44 65 62 69 61 6E 20 31 35 2E 31 30 2D 31 2E 70 67 64 67 31 32 30 2B 31 29 00
                // 53 00 00 00 23 73 65 73 73 69 6F 6E 5F 61 75 74 68 6F 72 69 7A 61 74 69 6F 6E 00 70 6F 73 74 67 72 65 73 00
                // 53 00 00 00 23 73 74 61 6E 64 61 72 64 5F 63 6F 6E 66 6F 72 6D 69 6E 67 5F 73 74 72 69 6E 67 73 00 6F 6E 00
                // 53 00 00 00 15 54 69 6D 65 5A 6F 6E 65 00 45 74 63 2F 55 54 43 00
                //
                // BackendKeyData
                // 4B 00 00 00 0C 00 00 00 4F 78 27 47 27
                //
                // ReadyForQuery
                // 5A 00 00 00 05 49
                return;
            },
            else => AuthError.NotSupported,
        };
    }
};

pub fn scram(
    password: []const u8,
    server_nonce: []const u8,
    salt_encoded: []const u8,
    iterations: u32,
    client_first_message_bare: []const u8,
    server_first_message: []const u8,
    msg_buf: []u8,
) ![]const u8 {
    std.debug.print("\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n", .{});
    var salt_buf: [1026]u8 = undefined;
    print_slice_ch(salt_encoded, "salt encoded");

    try Base64Decoder.decode(&salt_buf, salt_encoded);
    const salt_decode_size = try Base64Decoder.calcSizeForSlice(salt_encoded);

    var salted_pw: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(
        &salted_pw,
        password,
        salt_buf[0..salt_decode_size],
        iterations,
        std.crypto.auth.hmac.sha2.HmacSha256,
    );
    print_slice(salted_pw, "salted password");

    var client_key: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&client_key, "Client Key", &salted_pw);

    var stored_key: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&client_key, &stored_key, .{});

    // client first message bare
    var cfmb = msg_buf[0..client_first_message_bare.len];
    @memcpy(cfmb[0..cfmb.len], client_first_message_bare);
    msg_buf[cfmb.len] = ',';

    // server first message
    var sfm = msg_buf[cfmb.len + 1 .. cfmb.len + 1 + server_first_message.len];
    @memcpy(sfm[0..sfm.len], server_first_message);

    msg_buf[cfmb.len + 1 + sfm.len] = ',';

    //client final message without proof
    var cfmwp = msg_buf[cfmb.len + 1 + sfm.len + 1 .. cfmb.len + 1 + sfm.len + 1 + 9 + server_nonce.len];
    @memcpy(cfmwp[0..9], "c=biws,r=");
    @memcpy(cfmwp[9 .. 9 + server_nonce.len], server_nonce);

    const auth_message_without_proof = msg_buf[0 .. cfmb.len + sfm.len + cfmwp.len + 2];
    std.debug.print("auth_message: {s}\n", .{auth_message_without_proof});

    var client_signature: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&client_signature, auth_message_without_proof, &stored_key);

    var client_proof_buf: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;

    for (client_key, client_signature, 0..) |ck, cs, i| {
        client_proof_buf[i] = ck ^ cs;
    }
    var client_proof_encoded: [44]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&client_proof_encoded, &client_proof_buf);
    std.debug.print("client_proof: {s}\n", .{client_proof_encoded});

    msg_buf[auth_message_without_proof.len] = ',';
    var client_proof = msg_buf[1 + auth_message_without_proof.len .. 1 + auth_message_without_proof.len + 2 + client_proof_encoded.len];
    @memcpy(client_proof[0..2], "p=");
    @memcpy(client_proof[2 .. 2 + client_proof_encoded.len], &client_proof_encoded);

    std.debug.print("client_prroooof: {s} {d}\n", .{ client_proof, client_proof.len });

    const response = msg_buf[cfmb.len + 1 + sfm.len + 1 .. cfmb.len + 1 + sfm.len + 1 + 9 + server_nonce.len + 1 + client_proof.len];

    // std.debug.print("response: {s}\n", .{response});
    // std.debug.print("msg_buf: {s}\n", .{msg_buf});

    std.debug.print("\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n\n", .{});
    return response;
}

const AuthError = error{
    NotSupported,
    ErrorResponse,
    UnexpectedMessage,
    InternalError,
};

const AuthResult = union(enum) {
    Error: AuthError,
    Ok,
};

const ConnectionError = error{
    CouldNotConnect,
    CouldNotAuthenticate,
};

pub const ConnectionResult = union(enum) {
    Error: ConnectionError,
    Ok,
};

pub const PgConOps = struct {
    host: []const u8 = "127.0.0.1",
    password: []const u8 = "password",
    port: u16 = 5882,
    enable_tls: bool = false,
    user: []const u8,
    database: ?[]const u8 = null, // defaults to username
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

        const address = std.net.Address.parseIp4(host, port) catch return ClientError.InvalidConnectionOptions;
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

        const len = std.mem.readInt(u32, self.read_buf[self.read_start + 1 .. self.read_end][0..4], .big);

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

    pub fn read_raw(self: *Connection) ![]u8 {
        std.debug.print("read start {d}", .{self.read_start});
        const n = try self.stream.read(self.read_buf[self.read_start..]);
        if (n == 0) return ReadError.ConnectionClosed;
        self.read_end += n;
        const buf = self.read_buf[self.read_start..self.read_end];
        self.read_start = self.read_end;
        print_slice(self.read_buf, "buffed innit");
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
            // print_slice(self.read_buf[self.read_start..self.read_end], "Read");
        }
    }

    pub fn deinit(self: *Connection) void {
        _ = self;
        return;
    }
};

test "invalid host" {
    const alloc = std.testing.allocator;

    try std.testing.expectError(
        ClientError.InvalidConnectionOptions,
        PgClient.init(.{ .user = "test", .host = "hosteded" }, alloc),
    );
}

// var server_key: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
// std.crypto.auth.hmac.sha2.HmacSha256.create(
//     &server_key,
//     "Server Key",
//     &salted_pw,
// );
//
// var server_signature: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
// std.crypto.auth.hmac.sha2.HmacSha256.create(
//     &server_signature,
//     auth_message,
//     &server_key,
// );
//
// std.debug.print("client_first_msg {s} end\n\n", .{auth_message});

// var recovered_client_key: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
// for (client_proof_buf, client_signature, 0..) |cp, cs, i| {
//     recovered_client_key[i] = cp ^ cs;
// }
//
// print_slice(stored_key, "stored_key");
// var profff: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
// std.crypto.hash.sha2.Sha256.hash(&recovered_client_key, &profff, .{});
// print_slice(recovered_client_key, "recovered_client_key");
// print_slice(profff, "profff");
//
// var msg_buf_test: [1026]u8 = undefined;

// std.debug.print("glsgfldfj: {s}", .{sasl_continue.Auth.extra.SASLContinue.server_response});
//
// const client_final_message_buf_test = scram(
//     "pencil",
//     "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
//     "W22ZaJ0SNY7soEsUEjb6gQ==",
//     4096,
//     "n=postgres,r=rOprNGfwEbeRWgbNEkqO",
//     "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
//     &msg_buf_test,
// ) catch |e| {
//     std.debug.print("error: {}\n", .{e});
//     return AuthError.InternalError;
// };
//
// var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
// defer arena.deinit();
// const allocator = arena.allocator();
//
// const client_fin = clientFinalMessage(
//     "pencil",
//     "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
//     "W22ZaJ0SNY7soEsUEjb6gQ==",
//     4096,
//     "n=postgres,r=rOprNGfwEbeRWgbNEkqO",
//     "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
//     allocator,
// ) catch |e| {
//     std.debug.print("error: {}\n", .{e});
//     return AuthError.InternalError;
// };

// print_slice(client_final_message_buf_test, "TEST");
// print_slice(client_fin, "TEST");
// print_slice_ch(client_final_message_buf_test, "TEST");
// print_slice_ch(client_fin, "TEST");
