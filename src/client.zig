const std = @import("std");
const codec = @import("./codec.zig");
const debug = @import("./testing/debug_utils.zig");
const assert = std.debug.assert;
const print_slice = debug.print_slice;
const print_slice_ch = debug.print_slice_ch;
const Connection = @import("./Connection.zig");
const auth = @import("./auth.zig");
const Codec = codec.Codec;
const FMsg = Codec.FrontendMsg;
const BMsg = Codec.BackendMsg;
const MsgParam = FMsg.MsgParam;
const http = std.http;
const Allocator = std.mem.Allocator;
const Protocol = http.Client.Connection.Protocol;
const Base64Decoder = std.base64.standard.Decoder;
const Base64Encoder = std.base64.standard.Encoder;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const hash = std.crypto.hash.sha2.Sha256.hash;
const m_len = std.crypto.auth.hmac.sha2.HmacSha256.mac_length;

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
            .Auth => |method| auth: {
                break :auth method;
            },
            .Error => {
                return AuthError.ErrorResponse;
            },
        };

        return switch (auth_method.auth_type) {
            .Ok => return,
            .SASL => {
                std.debug.assert(auth_method.extra == .SASL);
                var authenticator = auth.SASLAuth.init(&self.conn, &self.codec);
                const client_first_message = authenticator.initialResponse(
                    auth_method.extra.SASL,
                    self.options.user,
                    18,
                    self.allocator,
                ) catch |e| {
                    std.debug.print("error: {}\n", .{e});
                    self.conn.deinit();
                    return AuthError.InternalError;
                };
                defer self.allocator.free(client_first_message);

                print_slice_ch(client_first_message, "client_first_message");

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

                // print_slice_ch(initial_msg_buf, "jskhfkjsdhfkjsdhfksdjh");
                const client_first_bare = client_first_message;

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
    buf: []u8,
) ![]const u8 {
    var w_pos: usize = 0;
    const s_size = try Base64Decoder.calcSizeForSlice(salt_encoded);
    assert(buf.len >= s_size + (m_len * 3) + client_first_message_bare.len);

    try Base64Decoder.decode(buf, salt_encoded);
    w_pos += s_size;

    var salted_pw: [m_len]u8 = buf[w_pos..][0..m_len].*;
    try std.crypto.pwhash.pbkdf2(
        &salted_pw,
        password,
        buf[0..s_size],
        iterations,
        std.crypto.auth.hmac.sha2.HmacSha256,
    );
    w_pos += m_len;

    var client_key: [m_len]u8 = buf[w_pos..][0..m_len].*;
    Hmac.create(&client_key, "Client Key", &salted_pw);
    w_pos += m_len;

    var stored_key: [m_len]u8 = buf[w_pos..][0..m_len].*;
    hash(&client_key, &stored_key, .{});
    w_pos += m_len;

    // client first message bare
    const auth_msg_start = w_pos;

    var cfmb = buf[w_pos..][0..client_first_message_bare.len];
    @memcpy(cfmb[0..cfmb.len], client_first_message_bare);
    w_pos += cfmb.len;
    buf[w_pos] = ',';
    w_pos += 1;

    // server first message
    var sfm = buf[w_pos..][0..server_first_message.len];
    @memcpy(sfm[0..sfm.len], server_first_message);
    w_pos += sfm.len;
    buf[w_pos] = ',';
    w_pos += 1;

    const res_start = w_pos;

    var cfmwp = buf[w_pos..][0 .. 9 + server_nonce.len];
    @memcpy(cfmwp[0..9], "c=biws,r=");
    @memcpy(cfmwp[9 .. 9 + server_nonce.len], server_nonce);
    w_pos += 9 + server_nonce.len;

    const auth_message_without_proof = buf[auth_msg_start..w_pos];

    buf[w_pos] = ',';
    w_pos += 1;

    var client_signature: [m_len]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&client_signature, auth_message_without_proof, &stored_key);

    var client_proof_buf: [m_len]u8 = undefined;
    for (client_key, client_signature, 0..) |ck, cs, i| {
        client_proof_buf[i] = ck ^ cs;
    }
    var client_proof_encoded: [44]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&client_proof_encoded, &client_proof_buf);

    var client_proof = buf[w_pos..][0 .. 2 + client_proof_encoded.len];
    @memcpy(client_proof[0..2], "p=");
    @memcpy(client_proof[2..][0..client_proof_encoded.len], &client_proof_encoded);
    w_pos += client_proof.len;

    const response = buf[res_start..w_pos];
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

test "invalid host" {
    const alloc = std.testing.allocator;

    try std.testing.expectError(
        ClientError.InvalidConnectionOptions,
        PgClient.init(.{ .user = "test", .host = "hosteded" }, alloc),
    );
}

test "scram" {
    var msg_buf_test: [1024]u8 = undefined;
    const client_final_message = try scram(
        "pencil",
        "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
        "W22ZaJ0SNY7soEsUEjb6gQ==",
        4096,
        "n=postgres,r=rOprNGfwEbeRWgbNEkqO",
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
        &msg_buf_test,
    );

    const expect = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=27pyzYupie09+PRPp9VSIPH4UcrkfAc9C8GgYoFMEEY=";
    try std.testing.expectEqualStrings(expect, client_final_message);
}
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
