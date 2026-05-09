//! Unsigned LEB128 (protobuf-style) varints for `u64`.
//!
//! Encoding is minimal (shortest byte sequence). Decoding rejects non-minimal forms,
//! overflow, truncation, and sequences longer than 10 bytes (the maximum for `u64`).

const std = @import("std");

pub const max_len: usize = 10;

pub const DecodeError = error{
    Truncated,
    Overflow,
    TooLong,
    NonMinimal,
};

/// Writes the minimal encoding of `value` into `buf` and returns the used prefix.
pub fn encode(buf: *[max_len]u8, value: u64) []const u8 {
    var v = value;
    var i: usize = 0;
    while (i < max_len) : (i += 1) {
        const byte: u8 = @truncate(v & 0x7f);
        v >>= 7;
        if (v == 0) {
            buf[i] = byte;
            return buf[0 .. i + 1];
        }
        buf[i] = byte | 0x80;
    }
    unreachable;
}

/// Decodes one varint from the start of `slice`. Returns the value and consumed length.
pub fn decode(slice: []const u8) DecodeError!struct { value: u64, len: usize } {
    if (slice.len == 0) return error.Truncated;

    var result: u64 = 0;
    var shift: u6 = 0;

    for (0..max_len) |idx| {
        if (idx >= slice.len) return error.Truncated;
        const b = slice[idx];
        const digit: u64 = b & 0x7f;

        if (shift == 63 and digit > 1) return error.Overflow;

        const shifted = digit << @as(u6, @intCast(shift));
        const ov = @addWithOverflow(result, shifted);
        if (ov[1] != 0) return error.Overflow;
        result = ov[0];

        if (b & 0x80 == 0) {
            var enc: [max_len]u8 = undefined;
            const enc_slice = encode(&enc, result);
            if (enc_slice.len != idx + 1 or !std.mem.eql(u8, enc_slice, slice[0 .. idx + 1])) {
                return error.NonMinimal;
            }
            return .{ .value = result, .len = idx + 1 };
        }

        if (shift == 63) return error.TooLong;
        shift += 7;
    }

    return error.TooLong;
}

test "encode decode roundtrip" {
    const cases = [_]u64{
        0,
        1,
        127,
        128,
        16383,
        16384,
        std.math.maxInt(u64),
    };

    for (cases) |v| {
        var buf: [max_len]u8 = undefined;
        const enc = encode(&buf, v);
        const dec = try decode(enc);
        try std.testing.expectEqual(v, dec.value);
        try std.testing.expectEqual(enc.len, dec.len);
    }
}

test "decode truncated" {
    const bytes = [_]u8{0x80};
    try std.testing.expectError(error.Truncated, decode(&bytes));
}

test "decode too long" {
    const bytes = [_]u8{
        0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80,
    };
    try std.testing.expectError(error.TooLong, decode(&bytes));
}

test "decode overflow" {
    const bytes = [_]u8{
        0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x03,
    };
    try std.testing.expectError(error.Overflow, decode(&bytes));
}

test "decode non-minimal" {
    const bytes = [_]u8{ 0x80, 0x00 };
    try std.testing.expectError(error.NonMinimal, decode(&bytes));
}
