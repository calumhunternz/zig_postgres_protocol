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
            .codec = try Codec.init(alloc),
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
                var authenticator = auth.SASLAuth.init(
                    self.options.user,
                    &self.conn,
                    &self.codec,
                    &self.allocator,
                );
                defer authenticator.deinit();
                try authenticator.authenticate(self.options.password, auth_method.extra.SASL);
            },
            else => AuthError.NotSupported,
        };
    }
};

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
