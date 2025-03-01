const std = @import("std");
const debug_util = @import("./testing/debug_utils.zig");
const c = @import("./codec.zig");
const Connection = @import("./Connection.zig");
const t = @import("./codec/types.zig");
const SASLMechanism = c.Codec.SASLMechanism;
const Codec = c.Codec;
const FMsg = Codec.FrontendMsg;
const BMsg = Codec.BackendMsg;
const MsgParam = FMsg.MsgParam;

const AuthError = error{
    NotSupported,
    ErrorResponse,
    UnexpectedMessage,
    InternalError,
};

pub const SASLAuth = struct {
    conn: *Connection,
    codec: *Codec,
    nonce: []u8 = undefined,
    salt: []u8 = undefined,
    iteration: u32 = 4096,
    client_first_message: []u8 = undefined,
    server_response: []u8 = undefined,

    pub fn init(conn: *Connection, codec: *Codec) SASLAuth {
        return .{ .conn = conn, .codec = codec };
    }

    pub fn initialResponse(
        self: *SASLAuth,
        mech: SASLMechanism,
        user: []const u8,
        nonce_len: usize,
        allocator: std.mem.Allocator,
    ) ![]const u8 {
        std.debug.assert(nonce_len <= 50);
        const buf = try allocator.alloc(u8, 5 + user.len + 3 + std.base64.standard.Encoder.calcSize(nonce_len));

        @memcpy(buf[0..5], "n,,n=");
        @memcpy(buf[5..][0..user.len], user);
        @memcpy(buf[5 + user.len ..][0..3], ",r=");

        var nonce_buf: [50]u8 = undefined;
        std.crypto.random.bytes(nonce_buf[0..nonce_len]);
        const nonce = buf[5 + user.len + 3 ..][0..std.base64.standard.Encoder.calcSize(nonce_len)];
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
        return buf;
    }

    pub fn initialServerResponse(self: *SASLAuth) void {
        const res = try self.conn.read();

        const sasl_continue = try self.codec.decode(res);
        std.debug.assert(sasl_continue.Auth.extra == .SASLContinue);

        const sasl_extra = sasl_continue.Auth.extra.SASLContinue;

        self.nonce = sasl_extra.server_nonce;
        self.salt = sasl_extra.salt;
        self.iteration = sasl_extra.iteration;
        self.server_response = sasl_extra.server_response;
    }
};

// test "scram" {
//     var msg_buf_test: [1024]u8 = undefined;
//     const client_final_message = try scram(
//         "pencil",
//         "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
//         "W22ZaJ0SNY7soEsUEjb6gQ==",
//         4096,
//         "n=postgres,r=rOprNGfwEbeRWgbNEkqO",
//         "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
//         &msg_buf_test,
//     );
//
//     const expect = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=27pyzYupie09+PRPp9VSIPH4UcrkfAc9C8GgYoFMEEY=";
//     try std.testing.expectEqualStrings(expect, client_final_message);
// }
