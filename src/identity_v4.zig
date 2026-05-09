//! secp256k1 "v4" identity helpers for discv5: compressed public keys and ECDH shared secret encoding
//! per [discv5-theory](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-theory.md) (same as go-ethereum `ecdh`).

const std = @import("std");
const Secp256k1 = std.crypto.ecc.Secp256k1;

pub const EcdhError = std.crypto.errors.IdentityElementError ||
    std.crypto.errors.EncodingError ||
    std.crypto.errors.NotSquareError ||
    std.crypto.errors.NonCanonicalError;

fn compressJacobian(p: Secp256k1) [33]u8 {
    const aff = p.affineCoordinates();
    var out: [33]u8 = undefined;
    out[0] = if (aff.y.isOdd()) 0x03 else 0x02;
    @memcpy(out[1..], &aff.x.toBytes(.big));
    return out;
}

/// Compressed SEC1 public key (`0x02` / `0x03` prefix + 32-byte big-endian x) for `secret_key * G`.
/// `secret_key` is a 32-byte big-endian scalar (same encoding as Ethereum private keys).
pub fn compressedPubkeyFromSecretKey(secret_key: [32]u8) EcdhError![33]u8 {
    const p = try Secp256k1.basePoint.mul(secret_key, .big);
    return compressJacobian(p);
}

/// ECDH shared secret `local_secret_key * remote_public` in discv5 encoding:
/// `0x02 | y-parity` byte followed by 32-byte big-endian x of the shared point.
pub fn ecdhLocalSecret(remote_compressed_pubkey: [33]u8, local_secret_key: [32]u8) EcdhError![33]u8 {
    const remote = try Secp256k1.fromSec1(&remote_compressed_pubkey);
    const shared = try remote.mul(local_secret_key, .big);
    return compressJacobian(shared);
}

test "compressed pubkey and ECDH symmetry" {
    var sk1: [32]u8 = @splat(0);
    sk1[31] = 2;
    var sk2: [32]u8 = @splat(0);
    sk2[31] = 3;

    const pk1 = try compressedPubkeyFromSecretKey(sk1);
    const pk2 = try compressedPubkeyFromSecretKey(sk2);

    const s12 = try ecdhLocalSecret(pk2, sk1);
    const s21 = try ecdhLocalSecret(pk1, sk2);
    try std.testing.expectEqualSlices(u8, &s12, &s21);

    const q1 = try Secp256k1.fromSec1(&pk1);
    try std.testing.expect(q1.equivalent(try Secp256k1.basePoint.mul(sk1, .big)));
}

test "ECDH feeds handshake deriveSessionKeys" {
    const handshake = @import("handshake.zig");

    var sk1: [32]u8 = @splat(0);
    sk1[31] = 5;
    var sk2: [32]u8 = @splat(0);
    sk2[31] = 7;

    const pk2 = try compressedPubkeyFromSecretKey(sk2);
    const ikm = try ecdhLocalSecret(pk2, sk1);

    var n1: [32]u8 = undefined;
    for (&n1, 0..) |*b, i| b.* = @truncate(i);
    var n2: [32]u8 = undefined;
    for (&n2, 0..) |*b, i| b.* = @truncate(i + 100);

    const challenge = [_]u8{0x01} ** 40;
    const keys_a = handshake.deriveSessionKeys(&ikm, &challenge, n1, n2);

    const pk1 = try compressedPubkeyFromSecretKey(sk1);
    const ikm_b = try ecdhLocalSecret(pk1, sk2);
    try std.testing.expectEqualSlices(u8, &ikm, &ikm_b);

    const keys_b = handshake.deriveSessionKeys(&ikm_b, &challenge, n1, n2);
    try std.testing.expectEqualSlices(u8, &keys_a.initiator_key, &keys_b.initiator_key);
    try std.testing.expectEqualSlices(u8, &keys_a.recipient_key, &keys_b.recipient_key);
}
