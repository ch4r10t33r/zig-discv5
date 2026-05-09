//! Ethereum Node Records ([EIP-778](https://eips.ethereum.org/EIPS/eip-778)) — decode textual `enr:` form.
//!
//! Verifies top-level RLP list layout, 65-byte v4-style signature length, minimal big-endian
//! sequence number, and an even number of key/value string pairs.

const std = @import("std");
const rlp = @import("rlp.zig");

pub const Error = error{
    MissingPrefix,
    InvalidRecord,
    BadSignatureLength,
    BadSequenceEncoding,
    UnpairedEntry,
} || std.base64.Error || rlp.Error;

pub const RecordPayload = struct {
    /// 65-byte recoverable secp256k1 signature (v4 scheme).
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
    if (signature.len != 65) return error.BadSignatureLength;
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

    var sig: [64]u8 = undefined;
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
