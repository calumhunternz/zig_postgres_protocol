const std = @import("std");
const assert = std.debug.assert;
const debug_util = @import("./testing/debug_utils.zig");
const c = @import("./codec.zig");
const Connection = @import("./Connection.zig");
const t = @import("./codec/types.zig");
const SASLMechanism = c.Codec.SASLMechanism;
const Codec = c.Codec;
const FMsg = Codec.FrontendMsg;
const BMsg = Codec.BackendMsg;
const MsgParam = FMsg.MsgParam;
const Base64Decoder = std.base64.standard.Decoder;
const Base64Encoder = std.base64.standard.Encoder;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const hash = std.crypto.hash.sha2.Sha256.hash;
const m_len = std.crypto.auth.hmac.sha2.HmacSha256.mac_length;

const AuthError = error{
    NotSupported,
    ErrorResponse,
    UnexpectedMessage,
    InternalError,
};

pub const SASLAuth = struct {
    allocator: *std.mem.Allocator,
    conn: *Connection,
    codec: *Codec,
    user: []const u8,
    pw_salt: []const u8 = undefined,
    nonce: []const u8 = undefined,
    salt: []const u8 = undefined,
    iteration: u32 = 4096,
    initial_msg: []u8 = undefined,
    client_first_message: []u8 = undefined,
    server_response: []const u8 = undefined,
    client_final_message: []const u8 = undefined,
    auth_message: []const u8 = undefined,

    const NONCE_SIZE: u32 = 18;

    pub fn init(
        user: []const u8,
        conn: *Connection,
        codec: *Codec,
        allocator: *std.mem.Allocator,
    ) SASLAuth {
        return .{
            .conn = conn,
            .codec = codec,
            .user = user,
            .allocator = allocator,
        };
    }

    pub fn authenticate(self: *SASLAuth, pw: []const u8, mech: SASLMechanism) !void {
        self.initialResponse(
            mech,
            NONCE_SIZE,
        ) catch |e| {
            std.debug.print("sasl initial response failed: {}\n", .{e});
            return AuthError.InternalError;
        };
        self.initialServerResponse() catch |e| {
            std.debug.print("sasl initial server response failed: {}\n", .{e});
            return AuthError.InternalError;
        };
        self.clientFinalResponse(pw) catch |e| {
            std.debug.print("sasl client final response failed: {}\n", .{e});
            return AuthError.InternalError;
        };

        self.verify() catch |e| {
            std.debug.print("sasl final verify failed: {}\n", .{e});
            return AuthError.InternalError;
        };
    }

    pub fn initialResponse(
        self: *SASLAuth,
        mech: SASLMechanism,
        nonce_len: usize,
    ) !void {
        assert(nonce_len <= 50);
        const buf = try self.allocator.alloc(u8, 5 + self.user.len + 3 + std.base64.standard.Encoder.calcSize(nonce_len));

        @memcpy(buf[0..5], "n,,n=");
        @memcpy(buf[5..][0..self.user.len], self.user);
        @memcpy(buf[5 + self.user.len ..][0..3], ",r=");

        var nonce_buf: [50]u8 = undefined;
        std.crypto.random.bytes(nonce_buf[0..nonce_len]);
        const nonce = buf[5 + self.user.len + 3 ..][0..std.base64.standard.Encoder.calcSize(nonce_len)];
        _ = std.base64.standard.Encoder.encode(nonce, nonce_buf[0..nonce_len]);

        self.client_first_message = buf;

        const initial_msg = FMsg.new(MsgParam{ .SASLInit = .{
            .mech = mech,
            .client_first_msg = self.client_first_message,
        } });
        const initial_msg_buf = self.codec.encode(&initial_msg) catch |e| {
            std.debug.print("error: {}\n", .{e});
            return AuthError.InternalError;
        };

        try self.conn.write(initial_msg_buf);
    }

    pub fn initialServerResponse(self: *SASLAuth) !void {
        const res = try self.conn.read();

        const sasl_continue = try self.codec.decode(res);
        assert(sasl_continue.Auth.extra == .SASLContinue);

        const sasl_extra = sasl_continue.Auth.extra.SASLContinue;

        self.nonce = sasl_extra.server_nonce;
        self.salt = sasl_extra.salt;
        self.iteration = sasl_extra.iteration;
        self.server_response = sasl_extra.server_response;
    }

    pub fn clientFinalResponse(
        self: *SASLAuth,
        password: []const u8,
    ) !void {
        const client_first_bare = self.client_first_message[3..];
        var msg_buf: [1026]u8 = undefined;
        const client_final_message = try self.scram(
            password,
            self.nonce,
            self.salt,
            self.iteration,
            client_first_bare,
            self.server_response,
            &msg_buf,
        );

        const client_final_msg = FMsg.new(MsgParam{ .SASLRes = .{
            .client_final_msg = client_final_message,
        } });

        const client_final_message_buf = try self.codec.encode(&client_final_msg);
        try self.conn.write(client_final_message_buf);
    }

    pub fn verify(self: *SASLAuth) !void {
        const sasl_final_buf = try self.conn.read();
        const sasl_final = try self.codec.decode(sasl_final_buf);
        const verifier = sasl_final.Auth.extra.SASLFinal.data;

        var server_key: [m_len]u8 = undefined;
        Hmac.create(&server_key, "Server Key", self.pw_salt);

        var server_signature: [m_len]u8 = undefined;
        Hmac.create(&server_signature, self.auth_message, &server_key);

        var server_signature_encoded: [44]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&server_signature_encoded, &server_signature);

        assert(std.mem.eql(u8, &server_signature_encoded, verifier.?));
    }

    fn scram(
        self: *SASLAuth,
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
        // TODO: avoid dupes
        self.pw_salt = try self.allocator.dupe(u8, &salted_pw);

        w_pos += m_len;

        var client_key: [m_len]u8 = buf[w_pos..][0..m_len].*;
        Hmac.create(&client_key, "Client Key", self.pw_salt);
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
        self.auth_message = try self.allocator.dupe(u8, auth_message_without_proof);

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

    pub fn deinit(self: *SASLAuth) void {
        self.allocator.free(self.client_first_message);
        self.allocator.free(self.pw_salt);
        self.allocator.free(self.auth_message);
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
};
