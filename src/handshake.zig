//! Handshake key derivation and identity proof hashing per [discv5-theory](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-theory.md).
//! ECDH and ECDSA for the identity proof are implemented in `identity_v4.zig` alongside compressed pubkeys.
//!
//! Exported as `handshake` from the package root; `crypto` is a public alias of the same module.

const std = @import("std");

const hkdf = std.crypto.kdf.hkdf.HkdfSha256;

/// Literal prefix for HKDF-Expand info (`kdf-info`).
pub const kdf_info_text: []const u8 = "discovery v5 key agreement";

/// Literal prefix hashed into the identity proof.
pub const identity_proof_text: []const u8 = "discovery v5 identity proof";

comptime {
    std.debug.assert(kdf_info_text.len == 26);
    std.debug.assert(identity_proof_text.len == 27);
}

pub const SessionKeys = struct {
    /// Encrypt / decrypt for packets sent by the handshake initiator (node A).
    initiator_key: [16]u8,
    /// Encrypt / decrypt for packets sent by the handshake recipient (node B).
    recipient_key: [16]u8,
};

/// Builds `kdf-info` into `buf` and returns the written length (`kdf_info_text.len + 64`).
pub fn writeKdfInfo(initiator_id: [32]u8, recipient_id: [32]u8, buf: []u8) usize {
    const n = kdf_info_text.len + 32 + 32;
    std.debug.assert(buf.len >= n);
    @memcpy(buf[0..kdf_info_text.len], kdf_info_text);
    @memcpy(buf[kdf_info_text.len..][0..32], &initiator_id);
    @memcpy(buf[kdf_info_text.len + 32 ..][0..32], &recipient_id);
    return n;
}

/// Derives session AES-128 keys from the ECDH secret and WHOAREYOU challenge material.
/// `challenge_data` is `masking-iv || static-header || authdata` from the unmasked WHOAREYOU packet.
/// HKDF follows go-ethereum: salt = challenge, IKM = ECDH output (`hkdf.New(sha256, eph, challenge, info)`).
pub fn deriveSessionKeys(
    ecdh_secret: []const u8,
    challenge_data: []const u8,
    initiator_id: [32]u8,
    recipient_id: [32]u8,
) SessionKeys {
    var info: [kdf_info_text.len + 32 + 32]u8 = undefined;
    const info_len = writeKdfInfo(initiator_id, recipient_id, &info);

    const prk = hkdf.extract(challenge_data, ecdh_secret);
    var key_data: [32]u8 = undefined;
    hkdf.expand(&key_data, info[0..info_len], prk);
    return .{
        .initiator_key = key_data[0..16].*,
        .recipient_key = key_data[16..32].*,
    };
}

/// SHA-256 hash of the identity proof preimage: label || challenge || ephemeral pubkey || recipient node id.
/// The v4 identity scheme signs this hash with the static secp256k1 key (64-byte `r || s`).
pub fn hashIdentityProof(
    challenge_data: []const u8,
    ephemeral_pubkey: []const u8,
    recipient_node_id: [32]u8,
) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(identity_proof_text);
    h.update(challenge_data);
    h.update(ephemeral_pubkey);
    h.update(&recipient_node_id);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

test "deriveSessionKeys vector" {
    var n1: [32]u8 = undefined;
    for (&n1, 0..) |*b, i| b.* = @truncate(i);
    var n2: [32]u8 = undefined;
    for (&n2, 0..) |*b, i| b.* = @truncate(i + 32);

    const eph = [_]u8{0x02} ++ [_]u8{0x11} ** 32;
    const challenge = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd } ** 8;

    const keys = deriveSessionKeys(&eph, &challenge, n1, n2);

    const exp_prk = [_]u8{
        0x55, 0xef, 0xc2, 0x3f, 0x5c, 0xf7, 0xb7, 0x30, 0x61, 0x1d, 0x11, 0xf7, 0x8a, 0x91, 0x95, 0x27,
        0xe4, 0xb8, 0x77, 0x6c, 0xab, 0x84, 0xb8, 0x72, 0xf5, 0x61, 0xd4, 0xf7, 0xd5, 0x84, 0xa0, 0xc0,
    };
    const prk = hkdf.extract(&challenge, &eph);
    try std.testing.expectEqualSlices(u8, &exp_prk, &prk);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x5a, 0x89, 0x71, 0x7d, 0xcb, 0xa6, 0x6d, 0x15, 0x59, 0x09, 0x80, 0x4e, 0xd0, 0x76, 0x56, 0x76,
    }, &keys.initiator_key);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x0c, 0x76, 0x0b, 0xb6, 0x6d, 0x5d, 0xa9, 0xc2, 0x85, 0xc3, 0xef, 0x9c, 0x35, 0x5e, 0xc8, 0x14,
    }, &keys.recipient_key);
}

test "hashIdentityProof vector" {
    const challenge = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd } ** 8;
    const eph = [_]u8{0x03} ++ [_]u8{0x22} ** 32;
    const dest = [_]u8{0x55} ** 32;
    const h = hashIdentityProof(&challenge, &eph, dest);
    const exp = [_]u8{
        0x65, 0xe3, 0x33, 0x4b, 0x61, 0x3b, 0xb2, 0xda, 0x1f, 0x06, 0xa8, 0xac, 0xe7, 0x25, 0x68, 0x55,
        0x00, 0x5e, 0xb4, 0x77, 0xcf, 0xd4, 0xc5, 0xac, 0x2d, 0xa7, 0x55, 0xcd, 0xe5, 0xa6, 0xdc, 0xfb,
    };
    try std.testing.expectEqualSlices(u8, &exp, &h);
}
