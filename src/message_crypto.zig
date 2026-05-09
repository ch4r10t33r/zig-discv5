//! AES-128-GCM payload encryption for ordinary discovery v5 messages.
//!
//! Matches go-ethereum `encryptGCM` / `decryptGCM` ([`v5wire/crypto.go`](https://github.com/ethereum/go-ethereum/blob/master/p2p/discover/v5wire/crypto.go)):
//! wire format is ciphertext concatenated with a 16-byte tag. Nonce is the 12-byte header
//! nonce. Additional authenticated data is `packet[0 .. static_prefix + auth_size]` after
//! header unmasking (masking IV + static header + auth).

const std = @import("std");
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const packet = @import("packet.zig");

pub const tag_length: usize = Aes128Gcm.tag_length;
pub const nonce_length: usize = Aes128Gcm.nonce_length;
pub const key_length: usize = Aes128Gcm.key_length;

pub const Error = error{
    CiphertextTooShort,
    DecryptFailed,
    NotOrdinaryPacket,
};

/// Slice used as GCM `ad`: IV + unmasked static header + unmasked auth (prefix of `full_packet`).
pub fn messageAdditionalData(full_packet: []const u8, parsed: *const packet.ParsedPacket) []const u8 {
    const end = packet.static_prefix_size + parsed.auth_data.len;
    return full_packet[0..end];
}

/// Decrypts `ciphertext_and_tag` (`ciphertext || tag`) using the session read key.
pub fn decryptMessage(
    allocator: std.mem.Allocator,
    read_key: [key_length]u8,
    nonce: [nonce_length]u8,
    ciphertext_and_tag: []const u8,
    additional_data: []const u8,
) (Error || std.mem.Allocator.Error)![]u8 {
    if (ciphertext_and_tag.len < tag_length) return error.CiphertextTooShort;
    const ct_len = ciphertext_and_tag.len - tag_length;
    const tag: [tag_length]u8 = ciphertext_and_tag[ct_len..][0..tag_length].*;
    const ct = ciphertext_and_tag[0..ct_len];

    const out = try allocator.alloc(u8, ct_len);
    errdefer allocator.free(out);
    Aes128Gcm.decrypt(out, ct, tag, additional_data, nonce, read_key) catch return error.DecryptFailed;
    return out;
}

/// Encrypts plaintext to `ciphertext || tag`.
pub fn encryptMessage(
    allocator: std.mem.Allocator,
    write_key: [key_length]u8,
    nonce: [nonce_length]u8,
    plaintext: []const u8,
    additional_data: []const u8,
) std.mem.Allocator.Error![]u8 {
    const out = try allocator.alloc(u8, plaintext.len + tag_length);
    errdefer allocator.free(out);
    var tag: [tag_length]u8 = undefined;
    Aes128Gcm.encrypt(out[0..plaintext.len], &tag, plaintext, additional_data, nonce, write_key);
    @memcpy(out[plaintext.len..][0..tag_length], &tag);
    return out;
}

/// Decrypts the message section of an ordinary (`flag == 0`) packet.
pub fn decryptOrdinaryMessage(
    allocator: std.mem.Allocator,
    full_packet: []const u8,
    parsed: *const packet.ParsedPacket,
    read_key: [key_length]u8,
) (Error || std.mem.Allocator.Error)![]u8 {
    if (parsed.header.flag != .message) return error.NotOrdinaryPacket;
    const ad = messageAdditionalData(full_packet, parsed);
    return decryptMessage(allocator, read_key, parsed.header.nonce, parsed.message_cipher, ad);
}

test "gcm ping plaintext roundtrip" {
    const alloc = std.testing.allocator;

    const message_mod = @import("message.zig");

    var ad: [71]u8 = undefined;
    @memset(&ad, 0x5a);

    const key = [_]u8{0x42} ** 16;
    var nonce: [12]u8 = undefined;
    @memset(&nonce, 0x33);

    const pt = try message_mod.encodePingPlaintext(alloc, &.{ 0xab, 0xcd }, 0x0102030405060708);
    defer alloc.free(pt);

    const ct = try encryptMessage(alloc, key, nonce, pt, &ad);
    defer alloc.free(ct);

    const pt2 = try decryptMessage(alloc, key, nonce, ct, &ad);
    defer alloc.free(pt2);

    try std.testing.expectEqualSlices(u8, pt, pt2);

    const dec_msg = try message_mod.decodePlaintext(pt2, alloc);
    defer dec_msg.deinit(alloc);
    try std.testing.expect(dec_msg == .ping);
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), dec_msg.ping.enr_seq);
}
