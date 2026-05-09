//! Minimal [Recursive Length Prefix](https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/) codec.
//!
//! Covers byte strings and lists as used by Ethereum Node Records (EIP-778) and related
//! devp2p payloads: short and long forms, with strict length checks and rejection of
//! non-canonical single-byte encodings.

const std = @import("std");

pub const Error = error{
    Incomplete,
    Malformed,
};

pub const Item = union(enum) {
    string: []const u8,
    list: []const u8,
};

/// Decodes the first RLP item in `input`. `string` and `list` slices are views into `input`.
pub fn decodeFirst(input: []const u8) Error!struct { item: Item, len: usize } {
    if (input.len == 0) return error.Incomplete;
    const b = input[0];

    if (b < 0x80) {
        return .{ .item = .{ .string = input[0..1] }, .len = 1 };
    }

    if (b < 0xb8) {
        const len = b - 0x80;
        if (len == 0) return .{ .item = .{ .string = &.{} }, .len = 1 };
        if (len == 1 and input[1] < 0x80) return error.Malformed;
        if (1 + len > input.len) return error.Incomplete;
        return .{ .item = .{ .string = input[1..][0..len] }, .len = 1 + len };
    }

    if (b < 0xc0) {
        const len_of_len = b - 0xb7;
        if (1 + len_of_len > input.len) return error.Incomplete;
        const payload_len = readBigEndianLength(input[1..][0..len_of_len]) orelse return error.Malformed;
        const start = 1 + len_of_len;
        if (start + payload_len > input.len) return error.Incomplete;
        if (payload_len < 56) return error.Malformed;
        return .{ .item = .{ .string = input[start..][0..payload_len] }, .len = start + payload_len };
    }

    if (b < 0xf8) {
        const len = b - 0xc0;
        if (len == 0) return .{ .item = .{ .list = &.{} }, .len = 1 };
        if (1 + len > input.len) return error.Incomplete;
        return .{ .item = .{ .list = input[1..][0..len] }, .len = 1 + len };
    }

    const len_of_len = b - 0xf7;
    if (1 + len_of_len > input.len) return error.Incomplete;
    const payload_len = readBigEndianLength(input[1..][0..len_of_len]) orelse return error.Malformed;
    const start = 1 + len_of_len;
    if (start + payload_len > input.len) return error.Incomplete;
    if (payload_len < 56) return error.Malformed;
    return .{ .item = .{ .list = input[start..][0..payload_len] }, .len = start + payload_len };
}

fn readBigEndianLength(bytes: []const u8) ?usize {
    if (bytes.len == 0) return null;
    if (bytes[0] == 0) return null;
    if (bytes.len > @sizeOf(usize)) return null;
    var n: usize = 0;
    for (bytes) |x| {
        n = std.math.mul(usize, n, 256) catch return null;
        n = std.math.add(usize, n, x) catch return null;
    }
    return n;
}

/// Appends the canonical RLP encoding of `bytes` to `out`.
pub fn appendString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error!void {
    if (bytes.len == 1 and bytes[0] < 0x80) {
        try out.append(allocator, bytes[0]);
        return;
    }
    if (bytes.len < 56) {
        try out.append(allocator, @intCast(0x80 + bytes.len));
        try out.appendSlice(allocator, bytes);
        return;
    }
    const len_be = lengthToBeBytes(bytes.len);
    const llen: u8 = @intCast(len_be.len);
    try out.append(allocator, 0xb7 + llen);
    try out.appendSlice(allocator, len_be.slice());
    try out.appendSlice(allocator, bytes);
}

/// Appends the canonical RLP encoding of a list whose encoded payload is `payload`.
pub fn appendListPayload(out: *std.ArrayList(u8), allocator: std.mem.Allocator, payload: []const u8) std.mem.Allocator.Error!void {
    if (payload.len < 56) {
        try out.append(allocator, @intCast(0xc0 + payload.len));
        try out.appendSlice(allocator, payload);
        return;
    }
    const len_be = lengthToBeBytes(payload.len);
    const llen: u8 = @intCast(len_be.len);
    try out.append(allocator, 0xf7 + llen);
    try out.appendSlice(allocator, len_be.slice());
    try out.appendSlice(allocator, payload);
}

const BeBytes = struct {
    buf: [8]u8,
    len: usize,

    fn slice(self: *const BeBytes) []const u8 {
        return self.buf[self.buf.len - self.len ..];
    }
};

fn lengthToBeBytes(n: usize) BeBytes {
    var buf: [8]u8 = undefined;
    var x = n;
    var i: usize = 0;
    while (x != 0) : (i += 1) {
        buf[buf.len - 1 - i] = @truncate(x);
        x >>= 8;
    }
    return .{ .buf = buf, .len = @max(i, 1) };
}

test "empty string and empty list" {
    const empty_str = [_]u8{0x80};
    const d0 = try decodeFirst(&empty_str);
    try std.testing.expect(d0.item == .string);
    try std.testing.expectEqualStrings("", d0.item.string);
    try std.testing.expectEqual(1, d0.len);

    const empty_list = [_]u8{0xc0};
    const d1 = try decodeFirst(&empty_list);
    try std.testing.expect(d1.item == .list);
    try std.testing.expectEqualStrings("", d1.item.list);
    try std.testing.expectEqual(1, d1.len);
}

test "short string roundtrip" {
    const dog = "dog";
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try appendString(&out, std.testing.allocator, dog);
    try std.testing.expectEqualSlices(u8, &.{ 0x83, 'd', 'o', 'g' }, out.items);

    const d = try decodeFirst(out.items);
    try std.testing.expectEqualStrings(dog, d.item.string);
}

test "single byte canonical" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try appendString(&out, std.testing.allocator, &.{0x7f});
    try std.testing.expectEqualSlices(u8, &.{0x7f}, out.items);

    const d = try decodeFirst(out.items);
    try std.testing.expectEqualSlices(u8, &.{0x7f}, d.item.string);
}

test "reject non-canonical short string" {
    const bad = [_]u8{ 0x81, 0x7f };
    try std.testing.expectError(error.Malformed, decodeFirst(&bad));
}

test "long string roundtrip" {
    var payload: [65]u8 = undefined;
    @memset(&payload, 0xab);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try appendString(&out, std.testing.allocator, &payload);

    const d = try decodeFirst(out.items);
    try std.testing.expectEqualStrings(&payload, d.item.string);
    try std.testing.expectEqual(out.items.len, d.len);
}

test "short list roundtrip" {
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(std.testing.allocator);
    try appendString(&inner, std.testing.allocator, "cat");
    try appendString(&inner, std.testing.allocator, "dog");

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try appendListPayload(&out, std.testing.allocator, inner.items);

    const d = try decodeFirst(out.items);
    try std.testing.expect(d.item == .list);
    var rest = d.item.list;
    const a = try decodeFirst(rest);
    try std.testing.expectEqualStrings("cat", a.item.string);
    rest = rest[a.len..];
    const b = try decodeFirst(rest);
    try std.testing.expectEqualStrings("dog", b.item.string);
    try std.testing.expectEqual(rest.len, b.len);
}

test "incomplete buffer" {
    const bytes = [_]u8{ 0x83, 'd', 'o' };
    try std.testing.expectError(error.Incomplete, decodeFirst(&bytes));
}
