const std = @import("std");
const assert = std.debug.assert;

pub const ValuePair = struct {
    key: []const u8,
    val: []const u8,
    const padding: usize = 2;

    pub fn size(self: *const ValuePair) u32 {
        return @intCast(self.key.len + self.val.len + padding);
    }
};

pub const SASLMechanism = enum {
    SCRAM_SHA_256,
    SCRAM_SHA_256_PLUS,

    pub fn str(self: *const SASLMechanism) []const u8 {
        return switch (self.*) {
            .SCRAM_SHA_256 => "SCRAM-SHA-256",
            .SCRAM_SHA_256_PLUS => "SCRAM-SHA-256-PLUS",
        };
    }
};

pub const AuthType = enum(u32) {
    Ok = 0,
    KerberosV5 = 2,
    ClearTextPassword = 3,
    MD5Password = 5,
    GSS = 7,
    GSSContinue = 8,
    SSPI = 9,
    SASL = 10,
    SASLContinue = 11,
    SASLFinal = 12,
};
