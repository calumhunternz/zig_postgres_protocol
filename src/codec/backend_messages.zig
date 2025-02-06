const std = @import("std");
const assert = std.debug.assert;
const types = @import("./types.zig");
const Reader = types.Reader;
const SASLMechanism = types.SASLMechanism;

const ErrorRes = struct {
    error_type: ErrorType,
    field: ?[]const u8 = null,

    // posibility of an unrecognisable error code being added
    // postgres reccomends ignoring them.
    // https://www.postgresql.org/docs/current/protocol-error-fields.html
    const ErrorType = enum(u8) {
        Severity = 'S',
        LocalizedSeverity = 'V',
        SQLState = 'C',
        Message = 'M',
        Detail = 'D',
        Hint = 'H',
        Position = 'P',
        InternalPosition = 'p',
        InternalQuery = 'q',
        Where = 'W',
        SchemaName = 's',
        TableName = 't',
        ColumnName = 'c',
        DataTypeName = 'd',
        ConstraintName = 'n',
        File = 'F',
        Line = 'L',
        Routine = 'R',
    };

    pub fn decode(reader: *Reader) !ErrorRes {
        return ErrorRes{
            .error_type = @enumFromInt(reader.readByte1()),
            // TODO: field is different per error code just mapping all remaining data to a buf for now
            // but would want individual mapping in future
            .field = reader.readRemaining(),
        };
    }
};

pub const AuthRes = struct {
    auth_type: AuthType,
    extra: AuthExtra = .None,

    const AuthType = enum(u32) {
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

    const AuthExtra = union(enum) {
        MD5Password: struct { salt: [4]u8 },
        GSSContinue: struct { data: []u8 },
        SASL: SASLMechanism, // null terminated list of auth schemes will require enum once those are found.
        SASLContinue: struct { data: []u8 },
        SALSFinal: struct { data: []u8 },
        None,
    };

    const DecodeError = error{
        NoSaslMechanism,
    };

    pub fn decode(reader: *Reader) !AuthRes {
        const auth_type: AuthType = @enumFromInt(reader.readu32());
        const extra: AuthExtra = switch (auth_type) {
            .SASL => extra: {
                const mechanism = reader.readToDelimeter(0x00); // Server sends in order of preference so only the first one is needed
                // Should this be assert or error since it is coming over wire stuff could go bad.
                assert(std.mem.eql(u8, mechanism, "SCRAM-SHA-256") or std.mem.eql(u8, mechanism, "SCRAM-SHA-256-PLUS"));

                if (std.mem.eql(u8, mechanism, "SCRAM-SHA-256")) {
                    break :extra .{ .SASL = SASLMechanism.SCRAM_SHA_256 };
                } else if (std.mem.eql(u8, mechanism, "SCRAM-SHA-256-PLUS")) {
                    break :extra .{ .SASL = SASLMechanism.SCRAM_SHA_256_PLUS };
                }
                unreachable;
            },
            else => AuthExtra.None,
        };

        return .{
            .auth_type = auth_type,
            .extra = extra,
        };
    }
};

test "AuthRes" {
    // const input = &[_]u8{ 'R', 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00 };
    const input = &[_]u8{ 0x00, 0x00, 0x00, 0x00 };
    var reader = Reader.reader(input);
    const result = try AuthRes.decode(&reader);

    const expected = AuthRes{
        .auth_type = .Ok,
    };

    try std.testing.expectEqualDeep(expected, result);
}

test "ErrorRes" {
    // const input = &[_]u8{ 'E', 0x00, 0x00, 0x00, 0x0a, 'S', 'P', 'A', 'N', 'I', 'C' };
    const input = &[_]u8{ 'S', 'P', 'A', 'N', 'I', 'C' };
    var reader = Reader.reader(input);
    const result = try ErrorRes.decode(&reader);

    const expected = ErrorRes{
        .error_type = ErrorRes.ErrorType.Severity,
        .field = "PANIC",
    };

    try std.testing.expectEqualDeep(result, expected);
}

test "SASL" {
    const input1 = &[_]u8{
        0,   0,   0,   0x0a,
        'S', 'C', 'R', 'A',
        'M', '-', 'S', 'H',
        'A', '-', '2', '5',
        '6', 0,   0,
    };
    var reader1 = Reader.reader(input1);
    const result1 = AuthRes.decode(&reader1);
    const expected1 = AuthRes{
        .auth_type = .SASL,
        .extra = .{ .SASL = .SCRAM_SHA_256 },
    };
    try std.testing.expectEqualDeep(expected1, result1);

    const input2 = &[_]u8{
        0,   0,   0,   0x0a,
        'S', 'C', 'R', 'A',
        'M', '-', 'S', 'H',
        'A', '-', '2', '5',
        '6', '-', 'P', 'L',
        'U', 'S', 0,   0,
    };
    var reader2 = Reader.reader(input2);
    const result2 = AuthRes.decode(&reader2);
    const expected2 = AuthRes{
        .auth_type = .SASL,
        .extra = .{ .SASL = .SCRAM_SHA_256_PLUS },
    };
    try std.testing.expectEqualDeep(expected2, result2);
    const input3 = &[_]u8{
        0,   0,   0,   0x0a, 'S',
        'C', 'R', 'A', 'M',  '-',
        'S', 'H', 'A', '-',  '2',
        '5', '6', '-', 'P',  'L',
        'U', 'S', 0,   'S',  'C',
        'R', 'A', 'M', '-',  'S',
        'H', 'A', '-', '2',  '5',
        '6', 0,   0,
    };
    var reader3 = Reader.reader(input3);
    const result3 = AuthRes.decode(&reader3);
    const expected3 = AuthRes{
        .auth_type = .SASL,
        .extra = .{ .SASL = .SCRAM_SHA_256_PLUS },
    };
    try std.testing.expectEqualDeep(expected3, result3);
}
