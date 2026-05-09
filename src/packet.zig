//! Discovery v5 UDP packet layout: masking IV, AES-128-CTR header unmasking, static header parse.
//!
//! Matches [discv5-wire](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md)
//! and the layout used by go-ethereum (`p2p/discover/v5wire`).

const std = @import("std");
const aes = std.crypto.core.aes;

pub const max_packet_size: usize = 1280;
pub const min_packet_size: usize = 63;
pub const masking_iv_size: usize = 16;
/// `protocol-id || version || flag || nonce || authdata-size` after unmasking.
pub const static_header_size: usize = 6 + 2 + 1 + 12 + 2;
pub const static_prefix_size: usize = masking_iv_size + static_header_size;
/// Minimum bytes after the static header (auth + message) for ordinary / handshake packets.
pub const min_message_tail: usize = 48;

pub const protocol_id = "discv5";

pub const PacketFlag = enum(u8) {
    message = 0,
    whoareyou = 1,
    handshake = 2,
    _,

    pub fn parse(b: u8) ?PacketFlag {
        return switch (b) {
            0 => .message,
            1 => .whoareyou,
            2 => .handshake,
            else => null,
        };
    }
};

pub const Error = error{
    PacketTooShort,
    PacketTooLarge,
    InvalidProtocol,
    VersionTooLow,
    UnknownFlag,
    AuthBeyondPacket,
    MessageTooShort,
};

pub const StaticHeader = struct {
    flag: PacketFlag,
    nonce: [12]u8,
    auth_size: u16,
};

pub const ParsedPacket = struct {
    iv: [16]u8,
    header: StaticHeader,
    /// Unmasked auth data; slice into the same `packet` buffer after `decodeInPlace`.
    auth_data: []u8,
    /// Ciphertext + tag after the header (may be empty for WHOAREYOU).
    message_cipher: []u8,
};

/// XOR `buf` with the discv5 header keystream starting at `stream_byte_offset` from the IV.
fn xorMaskRange(key: [16]u8, iv: [16]u8, buf: []u8, stream_byte_offset: usize) void {
    if (buf.len == 0) return;

    var ctx = aes.Aes128.initEnc(key);
    const start_block: u128 = @intCast(stream_byte_offset / 16);
    const intra: usize = stream_byte_offset % 16;

    var ctr_block: [16]u8 = undefined;
    const iv_val = std.mem.readInt(u128, &iv, .big);
    std.mem.writeInt(u128, &ctr_block, iv_val +% start_block, .big);

    var pos: usize = 0;
    if (intra != 0) {
        var ks: [16]u8 = undefined;
        ctx.encrypt(&ks, &ctr_block);
        var j = intra;
        while (pos < buf.len and j < 16) : (j += 1) {
            buf[pos] ^= ks[j];
            pos += 1;
        }
        if (pos == buf.len) return;
        const next = std.mem.readInt(u128, &ctr_block, .big) +% 1;
        std.mem.writeInt(u128, &ctr_block, next, .big);
    }

    while (pos + 16 <= buf.len) {
        var ks: [16]u8 = undefined;
        ctx.encrypt(&ks, &ctr_block);
        for (0..16) |t| {
            buf[pos + t] ^= ks[t];
        }
        pos += 16;
        const next = std.mem.readInt(u128, &ctr_block, .big) +% 1;
        std.mem.writeInt(u128, &ctr_block, next, .big);
    }
    if (pos < buf.len) {
        var ks: [16]u8 = undefined;
        ctx.encrypt(&ks, &ctr_block);
        for (buf[pos..], 0..) |*b, t| {
            b.* ^= ks[t];
        }
    }
}

test "xorMaskRange matches std.crypto.core.modes.ctr for contiguous range" {
    const modes = std.crypto.core.modes;
    const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const iv = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

    const plain = [_]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    };
    var ref: [plain.len]u8 = plain;
    const ctx = aes.Aes128.initEnc(key);
    modes.ctr(aes.AesEncryptCtx(aes.Aes128), ctx, ref[0..], ref[0..], iv, .big);

    var split: [plain.len]u8 = plain;
    xorMaskRange(key, iv, split[0..23], 0);
    xorMaskRange(key, iv, split[23..], 23);

    try std.testing.expectEqualSlices(u8, &ref, &split);
}

/// Parses the 23-byte static header (already unmasked). Does not interpret `auth_size` against the packet.
pub fn parseStaticHeader(unmasked: []const u8) Error!StaticHeader {
    if (unmasked.len < static_header_size) return error.PacketTooShort;
    if (!std.mem.eql(u8, unmasked[0..6], protocol_id)) return error.InvalidProtocol;
    const version = std.mem.readInt(u16, unmasked[6..][0..2], .big);
    if (version < 1) return error.VersionTooLow;
    const flag = PacketFlag.parse(unmasked[8]) orelse return error.UnknownFlag;
    var nonce: [12]u8 = undefined;
    @memcpy(&nonce, unmasked[9..21]);
    const auth_size = std.mem.readInt(u16, unmasked[21..][0..2], .big);
    return .{
        .flag = flag,
        .nonce = nonce,
        .auth_size = auth_size,
    };
}

/// Unmasks header + auth in `packet` and returns views. Mutates `packet[16 .. 16 + static_header_size + header.auth_size]`.
pub fn decodeInPlace(dest_node_id: *const [32]u8, packet: []u8) Error!ParsedPacket {
    if (packet.len < min_packet_size) return error.PacketTooShort;
    if (packet.len > max_packet_size) return error.PacketTooLarge;
    if (packet.len < static_prefix_size) return error.PacketTooShort;

    const key = dest_node_id[0..16].*;
    var iv: [16]u8 = undefined;
    @memcpy(&iv, packet[0..16]);

    const static_masked = packet[masking_iv_size..][0..static_header_size];
    xorMaskRange(key, iv, static_masked, 0);

    const header = try parseStaticHeader(static_masked);

    const tail_len = packet.len - static_prefix_size;
    if (header.flag != .whoareyou and tail_len < min_message_tail) return error.MessageTooShort;
    if (header.auth_size > tail_len) return error.AuthBeyondPacket;

    const auth_masked = packet[static_prefix_size..][0..header.auth_size];
    xorMaskRange(key, iv, auth_masked, static_header_size);

    return .{
        .iv = iv,
        .header = header,
        .auth_data = auth_masked,
        .message_cipher = packet[static_prefix_size + header.auth_size ..],
    };
}

test "whoareyou minimum packet roundtrip mask" {
    var dest_id: [32]u8 = undefined;
    @memset(&dest_id, 0xab);

    var iv: [16]u8 = undefined;
    @memset(&iv, 0x11);

    var static_plain: [static_header_size]u8 = undefined;
    @memcpy(static_plain[0..6], protocol_id);
    std.mem.writeInt(u16, static_plain[6..][0..2], 1, .big);
    static_plain[8] = @intFromEnum(PacketFlag.whoareyou);
    @memset(static_plain[9..21], 0);
    std.mem.writeInt(u16, static_plain[21..][0..2], 24, .big);

    var auth_plain: [24]u8 = undefined;
    @memset(&auth_plain, 0xcc);

    var packet: [63]u8 = undefined;
    @memcpy(packet[0..16], &iv);
    @memcpy(packet[16..][0..static_header_size], &static_plain);
    @memcpy(packet[39..][0..24], &auth_plain);

    const key = dest_id[0..16].*;
    xorMaskRange(key, iv, packet[16..][0..static_header_size], 0);
    xorMaskRange(key, iv, packet[39..][0..24], static_header_size);

    const dec = try decodeInPlace(&dest_id, &packet);
    try std.testing.expect(dec.header.flag == .whoareyou);
    try std.testing.expectEqual(@as(u16, 24), dec.header.auth_size);
    try std.testing.expectEqualSlices(u8, &auth_plain, dec.auth_data);
    try std.testing.expectEqual(@as(usize, 0), dec.message_cipher.len);
}
