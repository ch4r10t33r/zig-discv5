//! Ethereum Node Records ([EIP-778](https://eips.ethereum.org/EIPS/eip-778)) — decode textual `enr:` form.
//!
//! Verifies top-level RLP list layout, **v4** signature length (64-byte **r ‖ s** per [devp2p enr.md](https://github.com/ethereum/devp2p/blob/master/enr.md), or 65-byte **r ‖ s ‖ v**),
//! minimal big-endian sequence number, and an even number of key/value string pairs.

const std = @import("std");
const rlp = @import("rlp.zig");

const Keccak256 = std.crypto.hash.sha3.Keccak256;
const EcdsaV4 = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

pub const Error = error{
    MissingPrefix,
    InvalidRecord,
    BadSignatureLength,
    BadSequenceEncoding,
    UnpairedEntry,
    MalformedPair,
    MissingSecp256k1Key,
    MissingIdentityScheme,
    InvalidIdentityScheme,
    InvalidV4Signature,
} || std.base64.Error || rlp.Error;

pub const SignV4Error = Error || std.mem.Allocator.Error ||
    std.crypto.errors.IdentityElementError || std.crypto.errors.NonCanonicalError;

pub const RecordPayload = struct {
    /// **r ‖ s** (64 bytes) or **r ‖ s ‖ recovery** (65 bytes) for the v4 identity scheme.
    signature: []const u8,
    /// Monotonic record version.
    seq: u64,
    /// Remaining RLP-encoded key/value strings (keys and values alternate).
    pairs_payload: []const u8,
};

/// Decodes the raw RLP record bytes (after base64 decoding). All slices are views into `raw`.
pub fn decodeRecordBytes(raw: []const u8) Error!RecordPayload {
    const top = try rlp.decodeFirst(raw);
    if (top.item != .list) return error.InvalidRecord;
    if (top.len != raw.len) return error.InvalidRecord;

    var rest = top.item.list;

    const sig_it = try rlp.decodeFirst(rest);
    if (sig_it.item != .string) return error.InvalidRecord;
    const signature = sig_it.item.string;
    if (signature.len != 64 and signature.len != 65) return error.BadSignatureLength;
    rest = rest[sig_it.len..];

    const seq_it = try rlp.decodeFirst(rest);
    if (seq_it.item != .string) return error.InvalidRecord;
    const seq = decodeSeqBeU64(seq_it.item.string) catch return error.BadSequenceEncoding;
    rest = rest[seq_it.len..];

    try verifyPairsPayload(rest);

    return .{
        .signature = signature,
        .seq = seq,
        .pairs_payload = rest,
    };
}

fn decodeSeqBeU64(s: []const u8) error{BadSequenceEncoding}!u64 {
    if (s.len > 8) return error.BadSequenceEncoding;
    if (s.len == 0) return 0;
    if (s[0] == 0 and s.len > 1) return error.BadSequenceEncoding;
    var v: u64 = 0;
    for (s) |b| {
        v = (v << 8) | b;
    }
    return v;
}

fn verifyPairsPayload(payload: []const u8) Error!void {
    var rest = payload;
    var count: usize = 0;
    while (rest.len > 0) {
        const d = try rlp.decodeFirst(rest);
        if (d.item != .string) return error.InvalidRecord;
        count += 1;
        rest = rest[d.len..];
    }
    if (count % 2 != 0) return error.UnpairedEntry;
}

/// Returns the compressed secp256k1 public key (33 bytes) from ENR `pairs_payload` (post-signature RLP tail).
pub fn compressedSecp256k1Pubkey(pairs_payload: []const u8) Error![33]u8 {
    var rest = pairs_payload;
    while (rest.len > 0) {
        const k = try rlp.decodeFirst(rest);
        if (k.item != .string) return error.MalformedPair;
        rest = rest[k.len..];
        const v = try rlp.decodeFirst(rest);
        if (v.item != .string) return error.MalformedPair;
        rest = rest[v.len..];

        if (std.mem.eql(u8, k.item.string, "secp256k1")) {
            if (v.item.string.len != 33) return error.MalformedPair;
            var out: [33]u8 = undefined;
            @memcpy(&out, v.item.string);
            return out;
        }
    }
    return error.MissingSecp256k1Key;
}

fn appendMinimalSeqString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, seq: u64) std.mem.Allocator.Error!void {
    var seq_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_buf, seq, .big);
    var seq_start: usize = 0;
    while (seq_start < seq_buf.len and seq_buf[seq_start] == 0) seq_start += 1;
    const seq_slice: []const u8 = if (seq == 0) &[_]u8{} else seq_buf[seq_start..];
    try rlp.appendString(out, allocator, seq_slice);
}

fn requireIdentitySchemeV4(pairs_payload: []const u8) Error!void {
    var rest = pairs_payload;
    while (rest.len > 0) {
        const k = try rlp.decodeFirst(rest);
        if (k.item != .string) return error.MalformedPair;
        rest = rest[k.len..];
        const v = try rlp.decodeFirst(rest);
        if (v.item != .string) return error.MalformedPair;
        rest = rest[v.len..];

        if (std.mem.eql(u8, k.item.string, "id")) {
            if (std.mem.eql(u8, v.item.string, "v4")) return;
            return error.InvalidIdentityScheme;
        }
    }
    return error.MissingIdentityScheme;
}

/// Keccak256 hash over **RLP([seq, k₁, v₁, …])** (record contents without the signature), then ECDSA verify
/// using the **secp256k1** compressed key in the record ([devp2p enr.md](https://github.com/ethereum/devp2p/blob/master/enr.md) v4 scheme).
pub fn verifyV4RecordPayload(allocator: std.mem.Allocator, rec: RecordPayload) (Error || std.mem.Allocator.Error)!void {
    try requireIdentitySchemeV4(rec.pairs_payload);
    const pk_compressed = try compressedSecp256k1Pubkey(rec.pairs_payload);
    const pk = EcdsaV4.PublicKey.fromSec1(&pk_compressed) catch return error.MalformedPair;

    var content_items: std.ArrayList(u8) = .empty;
    defer content_items.deinit(allocator);
    try appendMinimalSeqString(&content_items, allocator, rec.seq);
    try content_items.appendSlice(allocator, rec.pairs_payload);

    var content_list: std.ArrayList(u8) = .empty;
    defer content_list.deinit(allocator);
    try rlp.appendListPayload(&content_list, allocator, content_items.items);

    var digest: [32]u8 = undefined;
    Keccak256.hash(content_list.items, &digest, .{});

    if (rec.signature.len < 64) return error.BadSignatureLength;
    var rs: [64]u8 = undefined;
    @memcpy(&rs, rec.signature[0..64]);

    const sig = EcdsaV4.Signature.fromBytes(rs);
    sig.verifyPrehashed(digest, pk) catch return error.InvalidV4Signature;
}

pub fn verifyV4RecordSignature(allocator: std.mem.Allocator, raw: []const u8) (Error || std.mem.Allocator.Error)!void {
    const rec = try decodeRecordBytes(raw);
    try verifyV4RecordPayload(allocator, rec);
}

/// Builds a full signed v4 ENR RLP blob: **[signature, seq, …pairs]** where `pairs_rlp` is the concatenation of
/// RLP-encoded key/value strings (same layout as **RecordPayload.pairs_payload**).
pub fn encodeV4RecordSigned(
    allocator: std.mem.Allocator,
    secret_key: [32]u8,
    seq: u64,
    pairs_rlp: []const u8,
) SignV4Error![]u8 {
    var content_items: std.ArrayList(u8) = .empty;
    defer content_items.deinit(allocator);
    try appendMinimalSeqString(&content_items, allocator, seq);
    try content_items.appendSlice(allocator, pairs_rlp);

    var content_list: std.ArrayList(u8) = .empty;
    defer content_list.deinit(allocator);
    try rlp.appendListPayload(&content_list, allocator, content_items.items);

    var digest: [32]u8 = undefined;
    Keccak256.hash(content_list.items, &digest, .{});

    const sk = try EcdsaV4.SecretKey.fromBytes(secret_key);
    const kp = try EcdsaV4.KeyPair.fromSecretKey(sk);
    const esig = try kp.signPrehashed(digest, null);
    const rs = esig.toBytes();

    var record_items: std.ArrayList(u8) = .empty;
    defer record_items.deinit(allocator);
    try rlp.appendString(&record_items, allocator, &rs);
    try appendMinimalSeqString(&record_items, allocator, seq);
    try record_items.appendSlice(allocator, pairs_rlp);

    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(allocator);
    try rlp.appendListPayload(&raw, allocator, record_items.items);
    return try raw.toOwnedSlice(allocator);
}

const decoder = std.base64.url_safe_no_pad.Decoder;

/// Base64-decoded record bytes; free with `deinit`.
pub const DecodedUri = struct {
    bytes: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *DecodedUri) void {
        self.allocator.free(self.bytes);
        self.bytes = &.{};
    }

    pub fn payload(self: *const DecodedUri) Error!RecordPayload {
        return decodeRecordBytes(self.bytes);
    }
};

/// Decodes an `enr:` URI (URL-safe base64, no padding). Allocates a copy of the raw record.
pub fn decodeUri(allocator: std.mem.Allocator, uri: []const u8) (Error || std.mem.Allocator.Error)!DecodedUri {
    const trimmed = std.mem.trim(u8, uri, &std.ascii.whitespace);
    const prefix = "enr:";
    if (!std.mem.startsWith(u8, trimmed, prefix)) return error.MissingPrefix;

    const b64 = trimmed[prefix.len..];
    const out_len = try decoder.calcSizeForSlice(b64);
    const buf = try allocator.alloc(u8, out_len);
    errdefer allocator.free(buf);
    try decoder.decode(buf, b64);
    _ = decodeRecordBytes(buf) catch {
        allocator.free(buf);
        return error.InvalidRecord;
    };
    return .{ .bytes = buf, .allocator = allocator };
}

test "decode synthetic enr uri roundtrip" {
    const alloc = std.testing.allocator;

    var sig: [65]u8 = undefined;
    @memset(&sig, 0x02);

    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(alloc);
    try rlp.appendString(&inner, alloc, &sig);
    try rlp.appendString(&inner, alloc, &[_]u8{1});
    try rlp.appendString(&inner, alloc, "id");
    try rlp.appendString(&inner, alloc, "v4");

    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(alloc);
    try rlp.appendListPayload(&raw, alloc, inner.items);

    const encoder = std.base64.url_safe_no_pad.Encoder;
    const enc_len = encoder.calcSize(raw.items.len);
    const enc_buf = try alloc.alloc(u8, enc_len + "enr:".len);
    defer alloc.free(enc_buf);
    @memcpy(enc_buf[0..4], "enr:");
    const enc_slice = encoder.encode(enc_buf[4..], raw.items);

    const uri = enc_buf[0 .. 4 + enc_slice.len];

    var dec = try decodeUri(alloc, uri);
    defer dec.deinit();

    const rec = try dec.payload();
    try std.testing.expectEqualSlices(u8, &sig, rec.signature);
    try std.testing.expectEqual(@as(u64, 1), rec.seq);
    try std.testing.expectEqualStrings("id", (try rlp.decodeFirst(rec.pairs_payload)).item.string);
}

test "reject missing prefix" {
    try std.testing.expectError(error.MissingPrefix, decodeUri(std.testing.allocator, "nope"));
}

test "reject odd pair count" {
    const alloc = std.testing.allocator;

    var sig: [65]u8 = undefined;
    @memset(&sig, 0x02);

    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(alloc);
    try rlp.appendString(&inner, alloc, &sig);
    try rlp.appendString(&inner, alloc, &[_]u8{1});
    try rlp.appendString(&inner, alloc, "id");

    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(alloc);
    try rlp.appendListPayload(&raw, alloc, inner.items);

    try std.testing.expectError(error.UnpairedEntry, decodeRecordBytes(raw.items));
}

test "reject wrong signature length" {
    const alloc = std.testing.allocator;

    var sig: [63]u8 = undefined;
    @memset(&sig, 0x02);

    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(alloc);
    try rlp.appendString(&inner, alloc, &sig);
    try rlp.appendString(&inner, alloc, &[_]u8{1});

    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(alloc);
    try rlp.appendListPayload(&raw, alloc, inner.items);

    try std.testing.expectError(error.BadSignatureLength, decodeRecordBytes(raw.items));
}

test "v4 sign and verify roundtrip" {
    const alloc = std.testing.allocator;
    const identity_v4 = @import("identity_v4.zig");

    var sk: [32]u8 = @splat(0);
    sk[31] = 0x77;
    const pk = try identity_v4.compressedPubkeyFromSecretKey(sk);

    var pairs: std.ArrayList(u8) = .empty;
    defer pairs.deinit(alloc);
    try rlp.appendString(&pairs, alloc, "id");
    try rlp.appendString(&pairs, alloc, "v4");
    try rlp.appendString(&pairs, alloc, "secp256k1");
    try rlp.appendString(&pairs, alloc, &pk);

    const raw = try encodeV4RecordSigned(alloc, sk, 3, pairs.items);
    defer alloc.free(raw);

    try verifyV4RecordSignature(alloc, raw);
}

test "verify devp2p enr.md example record" {
    const alloc = std.testing.allocator;
    const identity_v4 = @import("identity_v4.zig");

    const uri = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";

    var dec = try decodeUri(alloc, uri);
    defer dec.deinit();

    try verifyV4RecordSignature(alloc, dec.bytes);

    const rec = try decodeRecordBytes(dec.bytes);
    const pk_c = try compressedSecp256k1Pubkey(rec.pairs_payload);
    const nid = try identity_v4.nodeIdV4FromCompressedSec1(pk_c);

    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7");
    try std.testing.expectEqualSlices(u8, &want, &nid);
}

test "reject non-minimal sequence encoding" {
    const alloc = std.testing.allocator;

    var sig: [65]u8 = undefined;
    @memset(&sig, 0x02);

    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(alloc);
    try rlp.appendString(&inner, alloc, &sig);
    try rlp.appendString(&inner, alloc, &[_]u8{ 0x00, 0x01 });

    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(alloc);
    try rlp.appendListPayload(&raw, alloc, inner.items);

    try std.testing.expectError(error.BadSequenceEncoding, decodeRecordBytes(raw.items));
}
