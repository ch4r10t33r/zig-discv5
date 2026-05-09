//! secp256k1 "v4" identity helpers for discv5: compressed public keys, ECDH shared secret (`eph`),
//! and ECDSA over **handshake.hashIdentityProof** (64-byte `r || s` on the wire).
//!
//! Matches [discv5-theory](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-theory.md) and go-ethereum `v5wire` (`ecdh`, `makeIDSignature`, `verifyIDSignature`).

const std = @import("std");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

const EcdsaV4 = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

pub const IdentityProofSignError = std.crypto.errors.IdentityElementError || std.crypto.errors.NonCanonicalError;

pub const IdentityProofVerifyError = EcdsaV4.Signature.VerifyError ||
    std.crypto.errors.EncodingError ||
    std.crypto.errors.NotSquareError;

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

/// Ethereum v4 node id: Keccak-256 over 64-byte uncompressed SEC1 `x || y` (no `0x04` prefix).
pub fn nodeIdV4FromCompressedSec1(compressed: [33]u8) EcdhError![32]u8 {
    const q = try Secp256k1.fromSec1(&compressed);
    const aff = q.affineCoordinates();
    var xy: [64]u8 = undefined;
    @memcpy(xy[0..32], &aff.x.toBytes(.big));
    @memcpy(xy[32..64], &aff.y.toBytes(.big));
    var out: [32]u8 = undefined;
    Keccak256.hash(&xy, &out, .{});
    return out;
}

pub fn nodeIdV4FromSecretKey(secret_key: [32]u8) EcdhError![32]u8 {
    const pk = try compressedPubkeyFromSecretKey(secret_key);
    return nodeIdV4FromCompressedSec1(pk);
}

/// ECDH shared secret `local_secret_key * remote_public` in discv5 encoding:
/// `0x02 | y-parity` byte followed by 32-byte big-endian x of the shared point.
pub fn ecdhLocalSecret(remote_compressed_pubkey: [33]u8, local_secret_key: [32]u8) EcdhError![33]u8 {
    const remote = try Secp256k1.fromSec1(&remote_compressed_pubkey);
    const shared = try remote.mul(local_secret_key, .big);
    return compressJacobian(shared);
}

/// Signs `sha256_digest`, the 32-byte output of **handshake.hashIdentityProof**, using the static secp256k1 key.
/// `noise` may be null for deterministic ECDSA; otherwise supply 32 random bytes (recommended for fault resistance).
pub fn signIdentityProofHash(
    sha256_digest: [32]u8,
    secret_key: [32]u8,
    noise: ?[32]u8,
) IdentityProofSignError![64]u8 {
    const sk = try EcdsaV4.SecretKey.fromBytes(secret_key);
    const kp = try EcdsaV4.KeyPair.fromSecretKey(sk);
    const sig = try kp.signPrehashed(sha256_digest, noise);
    return sig.toBytes();
}

/// Verifies a 64-byte `r || s` signature (big-endian) against the identity-proof hash and compressed public key.
pub fn verifyIdentityProofHash(
    signature_rs: [64]u8,
    sha256_digest: [32]u8,
    static_public_compressed: [33]u8,
) IdentityProofVerifyError!void {
    const pk = try EcdsaV4.PublicKey.fromSec1(&static_public_compressed);
    const sig = EcdsaV4.Signature.fromBytes(signature_rs);
    try sig.verifyPrehashed(sha256_digest, pk);
}

/// Hashes the identity proof preimage (**handshake.hashIdentityProof**) then signs it.
pub fn signIdentityProof(
    challenge_data: []const u8,
    ephemeral_pubkey: []const u8,
    recipient_node_id: [32]u8,
    secret_key: [32]u8,
    noise: ?[32]u8,
) IdentityProofSignError![64]u8 {
    const handshake = @import("handshake.zig");
    const h = handshake.hashIdentityProof(challenge_data, ephemeral_pubkey, recipient_node_id);
    return signIdentityProofHash(h, secret_key, noise);
}

/// Verifies **signIdentityProof** output for the given preimage fields.
pub fn verifyIdentityProof(
    signature_rs: [64]u8,
    challenge_data: []const u8,
    ephemeral_pubkey: []const u8,
    recipient_node_id: [32]u8,
    static_public_compressed: [33]u8,
) IdentityProofVerifyError!void {
    const handshake = @import("handshake.zig");
    const h = handshake.hashIdentityProof(challenge_data, ephemeral_pubkey, recipient_node_id);
    try verifyIdentityProofHash(signature_rs, h, static_public_compressed);
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

test "identity proof ECDSA roundtrip" {
    var sk: [32]u8 = @splat(0);
    sk[31] = 11;

    const pk = try compressedPubkeyFromSecretKey(sk);
    const challenge = [_]u8{0xab} ** 16;
    const eph = [_]u8{0x02} ++ [_]u8{0xcd} ** 32;
    const recipient = [_]u8{0x42} ** 32;

    const sig = try signIdentityProof(&challenge, &eph, recipient, sk, null);
    try verifyIdentityProof(sig, &challenge, &eph, recipient, pk);

    var wrong: [32]u8 = recipient;
    wrong[0] +%= 1;
    try std.testing.expectError(error.SignatureVerificationFailed, verifyIdentityProof(sig, &challenge, &eph, wrong, pk));
}
