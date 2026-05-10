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
    WrongAuthSize,
    InvalidHandshakeAuth,
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

    /// Decodes `auth_data` according to `header.flag`.
    pub fn decodeAuth(self: *const ParsedPacket) Error!AuthBody {
        return switch (self.header.flag) {
            .message => .{ .message = try parseMessageAuth(self.auth_data) },
            .whoareyou => .{ .whoareyou = try parseWhoareyouAuth(self.auth_data) },
            .handshake => .{ .handshake = try parseHandshakeAuth(self.auth_data) },
        };
    }
};

/// Fixed auth sizes from [discv5-wire](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md).
pub const message_auth_size: usize = 32;
pub const whoareyou_auth_size: usize = 16 + 8;
pub const handshake_auth_head_size: usize = 32 + 1 + 1;

pub const MessageAuth = struct {
    src_id: [32]u8,
};

pub const WhoareyouAuth = struct {
    id_nonce: [16]u8,
    enr_seq: u64,
};

/// Handshake `authdata` after the fixed head: signature, ephemeral pubkey, optional ENR bytes.
pub const HandshakeAuth = struct {
    src_id: [32]u8,
    sig_size: u8,
    eph_key_size: u8,
    signature: []const u8,
    eph_pubkey: []const u8,
    record: []const u8,
};

pub const AuthBody = union(enum) {
    message: MessageAuth,
    whoareyou: WhoareyouAuth,
    handshake: HandshakeAuth,
};

pub fn parseMessageAuth(data: []const u8) Error!MessageAuth {
    if (data.len != message_auth_size) return error.WrongAuthSize;
    var src_id: [32]u8 = undefined;
    @memcpy(&src_id, data[0..32]);
    return .{ .src_id = src_id };
}

pub fn parseWhoareyouAuth(data: []const u8) Error!WhoareyouAuth {
    if (data.len != whoareyou_auth_size) return error.WrongAuthSize;
    var id_nonce: [16]u8 = undefined;
    @memcpy(&id_nonce, data[0..16]);
    const enr_seq = std.mem.readInt(u64, data[16..][0..8], .big);
    return .{ .id_nonce = id_nonce, .enr_seq = enr_seq };
}

pub fn parseHandshakeAuth(data: []const u8) Error!HandshakeAuth {
    if (data.len < handshake_auth_head_size) return error.PacketTooShort;
    var src_id: [32]u8 = undefined;
    @memcpy(&src_id, data[0..32]);
    const sig_size = data[32];
    const eph_key_size = data[33];
    const rest_len = data.len - handshake_auth_head_size;
    const need = @as(usize, sig_size) + @as(usize, eph_key_size);
    if (rest_len < need) return error.InvalidHandshakeAuth;
    const sig_off = handshake_auth_head_size;
    const pk_off = sig_off + sig_size;
    const end_keys = pk_off + eph_key_size;
    return .{
        .src_id = src_id,
        .sig_size = sig_size,
        .eph_key_size = eph_key_size,
        .signature = data[sig_off..pk_off],
        .eph_pubkey = data[pk_off..end_keys],
        .record = data[end_keys..],
    };
}

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

pub fn writePlaintextStaticHeader(out: *[static_header_size]u8, flag: PacketFlag, nonce: [12]u8, auth_size: u16) void {
    @memcpy(out[0..6], protocol_id);
    std.mem.writeInt(u16, out[6..][0..2], 1, .big);
    out[8] = @intFromEnum(flag);
    @memcpy(out[9..21], &nonce);
    std.mem.writeInt(u16, out[21..][0..2], auth_size, .big);
}

pub fn maskHeaderAndAuth(dest_node_id: [32]u8, iv: [16]u8, static_hdr: []u8, auth: []u8) void {
    std.debug.assert(static_hdr.len == static_header_size);
    const key = dest_node_id[0..16].*;
    xorMaskRange(key, iv, static_hdr, 0);
    xorMaskRange(key, iv, auth, static_header_size);
}

pub const EncodeError = error{ BadHandshakeAuthSizes, AuthSizeTooLarge } || std.mem.Allocator.Error;

pub fn allocWhoareyouChallengeData(
    allocator: std.mem.Allocator,
    iv: [16]u8,
    echo_message_nonce: [12]u8,
    id_nonce: [16]u8,
    enr_seq: u64,
) std.mem.Allocator.Error![]u8 {
    const n = static_prefix_size + whoareyou_auth_size;
    const out = try allocator.alloc(u8, n);
    @memcpy(out[0..16], &iv);
    var static_plain: [static_header_size]u8 = undefined;
    writePlaintextStaticHeader(&static_plain, .whoareyou, echo_message_nonce, whoareyou_auth_size);
    @memcpy(out[16..][0..static_header_size], &static_plain);
    const auth_off = static_prefix_size;
    @memcpy(out[auth_off..][0..16], &id_nonce);
    std.mem.writeInt(u64, out[auth_off + 16 ..][0..8], enr_seq, .big);
    return out;
}

/// Writes the WHOAREYOU challenge bytes used as HKDF salt in **handshake.deriveSessionKeys** (unmasked prefix).
pub fn writeWhoareyouChallengeData(out: *[static_prefix_size + whoareyou_auth_size]u8, parsed: ParsedPacket) void {
    std.debug.assert(parsed.header.flag == .whoareyou);
    std.debug.assert(parsed.auth_data.len == whoareyou_auth_size);
    @memcpy(out[0..16], &parsed.iv);
    var static_plain: [static_header_size]u8 = undefined;
    writePlaintextStaticHeader(&static_plain, .whoareyou, parsed.header.nonce, whoareyou_auth_size);
    @memcpy(out[16..][0..static_header_size], &static_plain);
    @memcpy(out[static_prefix_size..], parsed.auth_data);
}

pub fn encodeWhoareyouPacket(
    allocator: std.mem.Allocator,
    dest_node_id: [32]u8,
    iv: [16]u8,
    echo_message_nonce: [12]u8,
    id_nonce: [16]u8,
    enr_seq: u64,
) EncodeError![]u8 {
    const auth_len = whoareyou_auth_size;
    const total_len = static_prefix_size + auth_len;
    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);
    @memcpy(out[0..16], &iv);
    var static_plain: [static_header_size]u8 = undefined;
    writePlaintextStaticHeader(&static_plain, .whoareyou, echo_message_nonce, auth_len);
    @memcpy(out[16..][0..static_header_size], &static_plain);
    const auth_off = static_prefix_size;
    @memcpy(out[auth_off..][0..16], &id_nonce);
    std.mem.writeInt(u64, out[auth_off + 16 ..][0..8], enr_seq, .big);
    maskHeaderAndAuth(dest_node_id, iv, out[16..][0..static_header_size], out[auth_off..][0..auth_len]);
    return out;
}

pub fn encodeOrdinaryMessagePacket(
    allocator: std.mem.Allocator,
    dest_node_id: [32]u8,
    iv: [16]u8,
    nonce: [12]u8,
    src_id: [32]u8,
    message_cipher_and_tag: []const u8,
) EncodeError![]u8 {
    const auth_len = message_auth_size;
    const total_len = static_prefix_size + auth_len + message_cipher_and_tag.len;
    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);
    @memcpy(out[0..16], &iv);
    var static_plain: [static_header_size]u8 = undefined;
    writePlaintextStaticHeader(&static_plain, .message, nonce, auth_len);
    @memcpy(out[16..][0..static_header_size], &static_plain);
    const auth_off = static_prefix_size;
    @memcpy(out[auth_off..][0..auth_len], &src_id);
    @memcpy(out[auth_off + auth_len ..], message_cipher_and_tag);
    maskHeaderAndAuth(dest_node_id, iv, out[16..][0..static_header_size], out[auth_off..][0..auth_len]);
    return out;
}

pub fn encodeHandshakePacket(
    allocator: std.mem.Allocator,
    dest_node_id: [32]u8,
    iv: [16]u8,
    nonce: [12]u8,
    src_id: [32]u8,
    sig_size: u8,
    eph_key_size: u8,
    signature: []const u8,
    eph_pubkey: []const u8,
    record: []const u8,
    message_cipher_and_tag: []const u8,
) EncodeError![]u8 {
    if (signature.len != sig_size or eph_pubkey.len != eph_key_size) return error.BadHandshakeAuthSizes;
    const auth_len = handshake_auth_head_size + signature.len + eph_pubkey.len + record.len;
    const auth_size_u16 = std.math.cast(u16, auth_len) orelse return error.AuthSizeTooLarge;
    const total_len = static_prefix_size + auth_len + message_cipher_and_tag.len;
    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);
    @memcpy(out[0..16], &iv);
    var static_plain: [static_header_size]u8 = undefined;
    writePlaintextStaticHeader(&static_plain, .handshake, nonce, auth_size_u16);
    @memcpy(out[16..][0..static_header_size], &static_plain);
    const auth_off = static_prefix_size;
    const auth = out[auth_off..][0..auth_len];
    @memcpy(auth[0..32], &src_id);
    auth[32] = sig_size;
    auth[33] = eph_key_size;
    @memcpy(auth[34 .. 34 + signature.len], signature);
    @memcpy(auth[34 + signature.len ..][0..eph_pubkey.len], eph_pubkey);
    @memcpy(auth[34 + signature.len + eph_pubkey.len ..], record);
    @memcpy(out[auth_off + auth_len ..], message_cipher_and_tag);
    maskHeaderAndAuth(dest_node_id, iv, out[16..][0..static_header_size], auth);
    return out;
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

    const auth = try dec.decodeAuth();
    try std.testing.expect(auth == .whoareyou);
    try std.testing.expectEqual(@as(u64, 0xcccccccccccccccc), auth.whoareyou.enr_seq);
}

test "parse message auth" {
    var buf: [32]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(i);

    const a = try parseMessageAuth(&buf);
    try std.testing.expectEqualSlices(u8, &buf, &a.src_id);
}

test "parse whoareyou auth endian" {
    var buf: [24]u8 = undefined;
    @memset(&buf, 0);
    std.mem.writeInt(u64, buf[16..][0..8], 0x0102030405060708, .big);

    const a = try parseWhoareyouAuth(&buf);
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), a.enr_seq);
}

test "parse handshake auth v4 layout" {
    var buf: [34 + 64 + 33]u8 = undefined;
    @memset(&buf, 0xee);
    buf[32] = 64;
    buf[33] = 33;

    const a = try parseHandshakeAuth(&buf);
    try std.testing.expectEqual(@as(usize, 64), a.signature.len);
    try std.testing.expectEqual(@as(usize, 33), a.eph_pubkey.len);
    try std.testing.expectEqual(@as(usize, 0), a.record.len);
}

test "parse handshake auth rejects truncated" {
    var buf: [40]u8 = undefined;
    @memset(&buf, 0);
    buf[32] = 64;
    buf[33] = 33;
    try std.testing.expectError(error.InvalidHandshakeAuth, parseHandshakeAuth(&buf));
}

test "wrong message auth size" {
    try std.testing.expectError(error.WrongAuthSize, parseMessageAuth(&[_]u8{0} ** 31));
}

test "encode WHOAREYOU roundtrip decodeInPlace" {
    const alloc = std.testing.allocator;

    var dest_id: [32]u8 = undefined;
    @memset(&dest_id, 0x37);

    var iv: [16]u8 = undefined;
    @memset(&iv, 0x55);
    const echo_nonce = [_]u8{0x01} ** 12;
    var id_nonce: [16]u8 = undefined;
    @memset(&id_nonce, 0x66);

    const enc = try encodeWhoareyouPacket(alloc, dest_id, iv, echo_nonce, id_nonce, 0x8899aabbccddeeff);
    defer alloc.free(enc);

    const dec_buf = try alloc.dupe(u8, enc);
    defer alloc.free(dec_buf);

    const parsed = try decodeInPlace(&dest_id, dec_buf);
    try std.testing.expect(parsed.header.flag == .whoareyou);
    try std.testing.expectEqualSlices(u8, &echo_nonce, &parsed.header.nonce);
    const body = try parsed.decodeAuth();
    try std.testing.expectEqual(@as(u64, 0x8899aabbccddeeff), body.whoareyou.enr_seq);
    try std.testing.expectEqualSlices(u8, &id_nonce, &body.whoareyou.id_nonce);
}
