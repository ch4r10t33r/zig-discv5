//! RLP protocol messages (`message-type` byte + `message-data` list) per [discv5-wire](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md).

const std = @import("std");
const rlp = @import("rlp.zig");

pub const type_ping: u8 = 0x01;
pub const type_pong: u8 = 0x02;
pub const type_findnode: u8 = 0x03;
pub const type_nodes: u8 = 0x04;
pub const type_talkreq: u8 = 0x05;
pub const type_talkresp: u8 = 0x06;

pub const Error = error{
    EmptyPlaintext,
    UnknownKind,
    BadEncoding,
    RequestIdTooLong,
    TrailingGarbage,
};

pub const DecodeError = Error || rlp.Error;

pub const Ping = struct {
    req_id: []const u8,
    enr_seq: u64,
};

pub const Pong = struct {
    req_id: []const u8,
    enr_seq: u64,
    to_ip: []const u8,
    to_port: u16,
};

pub const Findnode = struct {
    req_id: []const u8,
    distances: []u32,

    pub fn deinit(self: *const Findnode, allocator: std.mem.Allocator) void {
        allocator.free(self.distances);
    }
};

pub const Nodes = struct {
    req_id: []const u8,
    resp_count: u8,
    enr_records: []const []const u8,

    pub fn deinit(self: *const Nodes, allocator: std.mem.Allocator) void {
        allocator.free(self.enr_records);
    }
};

pub const TalkRequest = struct {
    req_id: []const u8,
    protocol: []const u8,
    message: []const u8,
};

pub const TalkResponse = struct {
    req_id: []const u8,
    response: []const u8,
};

pub const DecodedMessage = union(enum) {
    ping: Ping,
    pong: Pong,
    findnode: Findnode,
    nodes: Nodes,
    talkreq: TalkRequest,
    talkresp: TalkResponse,

    pub fn deinit(self: *const DecodedMessage, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .findnode => |f| f.deinit(allocator),
            .nodes => |n| n.deinit(allocator),
            else => {},
        }
    }
};

fn rlpUintToU64(s: []const u8) Error!u64 {
    if (s.len > 8) return error.BadEncoding;
    if (s.len == 0) return 0;
    if (s[0] == 0 and s.len > 1) return error.BadEncoding;
    var v: u64 = 0;
    for (s) |b| v = (v << 8) | b;
    return v;
}

fn rlpUintToU32(s: []const u8) Error!u32 {
    const v = try rlpUintToU64(s);
    if (v > std.math.maxInt(u32)) return error.BadEncoding;
    return @intCast(v);
}

fn rlpUintToU16(s: []const u8) Error!u16 {
    const v = try rlpUintToU64(s);
    if (v > std.math.maxInt(u16)) return error.BadEncoding;
    return @intCast(v);
}

fn requireString(it: rlp.Item) Error![]const u8 {
    return switch (it) {
        .string => |s| s,
        .list => error.BadEncoding,
    };
}

fn requireList(it: rlp.Item) Error![]const u8 {
    return switch (it) {
        .list => |l| l,
        .string => error.BadEncoding,
    };
}

pub fn decodePlaintext(plaintext: []const u8, allocator: std.mem.Allocator) (DecodeError || std.mem.Allocator.Error)!DecodedMessage {
    if (plaintext.len == 0) return error.EmptyPlaintext;
    const kind = plaintext[0];
    const body = plaintext[1..];
    return switch (kind) {
        type_ping => .{ .ping = try decodePing(body) },
        type_pong => .{ .pong = try decodePong(body) },
        type_findnode => .{ .findnode = try decodeFindnode(allocator, body) },
        type_nodes => .{ .nodes = try decodeNodes(allocator, body) },
        type_talkreq => .{ .talkreq = try decodeTalkRequest(body) },
        type_talkresp => .{ .talkresp = try decodeTalkResponse(body) },
        else => error.UnknownKind,
    };
}

fn decodePing(body: []const u8) DecodeError!Ping {
    const top = try rlp.decodeFirst(body);
    const list_payload = try requireList(top.item);
    if (top.len != body.len) return error.TrailingGarbage;

    var rest = list_payload;
    const e0 = try rlp.decodeFirst(rest);
    const req_id = try requireString(e0.item);
    if (req_id.len > 8) return error.RequestIdTooLong;
    rest = rest[e0.len..];
    const e1 = try rlp.decodeFirst(rest);
    const seqs = try requireString(e1.item);
    if (e1.len != rest.len) return error.TrailingGarbage;
    const enr_seq = try rlpUintToU64(seqs);

    return .{ .req_id = req_id, .enr_seq = enr_seq };
}

fn decodePong(body: []const u8) DecodeError!Pong {
    const top = try rlp.decodeFirst(body);
    const list_payload = try requireList(top.item);
    if (top.len != body.len) return error.TrailingGarbage;

    var rest = list_payload;
    const e0 = try rlp.decodeFirst(rest);
    const req_id = try requireString(e0.item);
    if (req_id.len > 8) return error.RequestIdTooLong;
    rest = rest[e0.len..];

    const e1 = try rlp.decodeFirst(rest);
    const seqs = try requireString(e1.item);
    rest = rest[e1.len..];

    const e2 = try rlp.decodeFirst(rest);
    const ip = try requireString(e2.item);
    if (ip.len != 4 and ip.len != 16) return error.BadEncoding;
    rest = rest[e2.len..];

    const e3 = try rlp.decodeFirst(rest);
    const ports = try requireString(e3.item);
    if (e3.len != rest.len) return error.TrailingGarbage;
    const to_port = try rlpUintToU16(ports);

    const enr_seq = try rlpUintToU64(seqs);

    return .{ .req_id = req_id, .enr_seq = enr_seq, .to_ip = ip, .to_port = to_port };
}

fn decodeFindnode(alloc: std.mem.Allocator, body: []const u8) (DecodeError || std.mem.Allocator.Error)!Findnode {
    const top = try rlp.decodeFirst(body);
    const list_payload = try requireList(top.item);
    if (top.len != body.len) return error.TrailingGarbage;

    var rest = list_payload;
    const e0 = try rlp.decodeFirst(rest);
    const req_id = try requireString(e0.item);
    if (req_id.len > 8) return error.RequestIdTooLong;
    rest = rest[e0.len..];

    const e1 = try rlp.decodeFirst(rest);
    const dist_list = try requireList(e1.item);
    if (e1.len != rest.len) return error.TrailingGarbage;

    var out: std.ArrayList(u32) = .empty;
    errdefer out.deinit(alloc);
    var drest = dist_list;
    while (drest.len > 0) {
        const d = try rlp.decodeFirst(drest);
        const sd = try requireString(d.item);
        const dist = try rlpUintToU32(sd);
        try out.append(alloc, dist);
        drest = drest[d.len..];
    }
    return .{ .req_id = req_id, .distances = try out.toOwnedSlice(alloc) };
}

fn decodeNodes(alloc: std.mem.Allocator, body: []const u8) (DecodeError || std.mem.Allocator.Error)!Nodes {
    const top = try rlp.decodeFirst(body);
    const list_payload = try requireList(top.item);
    if (top.len != body.len) return error.TrailingGarbage;

    var rest = list_payload;
    const e0 = try rlp.decodeFirst(rest);
    const req_id = try requireString(e0.item);
    if (req_id.len > 8) return error.RequestIdTooLong;
    rest = rest[e0.len..];

    const e1 = try rlp.decodeFirst(rest);
    const rc = try requireString(e1.item);
    if (rc.len != 1) return error.BadEncoding;
    const resp_count = rc[0];
    rest = rest[e1.len..];

    const e2 = try rlp.decodeFirst(rest);
    const rec_list = try requireList(e2.item);
    if (e2.len != rest.len) return error.TrailingGarbage;

    var records: std.ArrayList([]const u8) = .empty;
    errdefer records.deinit(alloc);
    var rrest = rec_list;
    while (rrest.len > 0) {
        const d = try rlp.decodeFirst(rrest);
        const rec = try requireString(d.item);
        try records.append(alloc, rec);
        rrest = rrest[d.len..];
    }

    return .{
        .req_id = req_id,
        .resp_count = resp_count,
        .enr_records = try records.toOwnedSlice(alloc),
    };
}

fn decodeTalkRequest(body: []const u8) DecodeError!TalkRequest {
    const top = try rlp.decodeFirst(body);
    const list_payload = try requireList(top.item);
    if (top.len != body.len) return error.TrailingGarbage;

    var rest = list_payload;
    const e0 = try rlp.decodeFirst(rest);
    const req_id = try requireString(e0.item);
    if (req_id.len > 8) return error.RequestIdTooLong;
    rest = rest[e0.len..];

    const e1 = try rlp.decodeFirst(rest);
    const proto = try requireString(e1.item);
    rest = rest[e1.len..];

    const e2 = try rlp.decodeFirst(rest);
    const msg = try requireString(e2.item);
    if (e2.len != rest.len) return error.TrailingGarbage;

    return .{ .req_id = req_id, .protocol = proto, .message = msg };
}

fn decodeTalkResponse(body: []const u8) DecodeError!TalkResponse {
    const top = try rlp.decodeFirst(body);
    const list_payload = try requireList(top.item);
    if (top.len != body.len) return error.TrailingGarbage;

    var rest = list_payload;
    const e0 = try rlp.decodeFirst(rest);
    const req_id = try requireString(e0.item);
    if (req_id.len > 8) return error.RequestIdTooLong;
    rest = rest[e0.len..];

    const e1 = try rlp.decodeFirst(rest);
    const resp = try requireString(e1.item);
    if (e1.len != rest.len) return error.TrailingGarbage;

    return .{ .req_id = req_id, .response = resp };
}

fn appendMinimalU64(out: *std.ArrayList(u8), allocator: std.mem.Allocator, n: u64) std.mem.Allocator.Error!void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, n, .big);
    var i: usize = 0;
    while (i < 7 and buf[i] == 0) i += 1;
    const slice: []const u8 = if (n == 0) &[_]u8{} else buf[i..];
    try rlp.appendString(out, allocator, slice);
}

fn appendMinimalU16(out: *std.ArrayList(u8), allocator: std.mem.Allocator, n: u16) std.mem.Allocator.Error!void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, n, .big);
    const slice: []const u8 = if (buf[0] == 0) buf[1..2] else buf[0..2];
    try rlp.appendString(out, allocator, slice);
}

pub fn encodePingPlaintext(allocator: std.mem.Allocator, req_id: []const u8, enr_seq: u64) std.mem.Allocator.Error![]u8 {
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(allocator);
    try rlp.appendString(&inner, allocator, req_id);
    try appendMinimalU64(&inner, allocator, enr_seq);
    var outer: std.ArrayList(u8) = .empty;
    defer outer.deinit(allocator);
    try rlp.appendListPayload(&outer, allocator, inner.items);
    const out = try allocator.alloc(u8, 1 + outer.items.len);
    out[0] = type_ping;
    @memcpy(out[1..], outer.items);
    return out;
}

pub fn encodePongPlaintext(
    allocator: std.mem.Allocator,
    req_id: []const u8,
    enr_seq: u64,
    ip: []const u8,
    port: u16,
) (Error || std.mem.Allocator.Error)![]u8 {
    if (ip.len != 4 and ip.len != 16) return error.BadEncoding;
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(allocator);
    try rlp.appendString(&inner, allocator, req_id);
    try appendMinimalU64(&inner, allocator, enr_seq);
    try rlp.appendString(&inner, allocator, ip);
    try appendMinimalU16(&inner, allocator, port);
    var outer: std.ArrayList(u8) = .empty;
    defer outer.deinit(allocator);
    try rlp.appendListPayload(&outer, allocator, inner.items);
    const out = try allocator.alloc(u8, 1 + outer.items.len);
    out[0] = type_pong;
    @memcpy(out[1..], outer.items);
    return out;
}

pub fn encodeFindnodePlaintext(allocator: std.mem.Allocator, req_id: []const u8, distances: []const u32) std.mem.Allocator.Error![]u8 {
    var dist_payload: std.ArrayList(u8) = .empty;
    defer dist_payload.deinit(allocator);
    for (distances) |d| {
        try appendMinimalU64(&dist_payload, allocator, @as(u64, d));
    }
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(allocator);
    try rlp.appendString(&inner, allocator, req_id);
    try rlp.appendListPayload(&inner, allocator, dist_payload.items);
    var outer: std.ArrayList(u8) = .empty;
    defer outer.deinit(allocator);
    try rlp.appendListPayload(&outer, allocator, inner.items);
    const out = try allocator.alloc(u8, 1 + outer.items.len);
    out[0] = type_findnode;
    @memcpy(out[1..], outer.items);
    return out;
}

pub fn encodeNodesPlaintext(
    allocator: std.mem.Allocator,
    req_id: []const u8,
    resp_count: u8,
    enr_payloads: []const []const u8,
) std.mem.Allocator.Error![]u8 {
    var rec_list: std.ArrayList(u8) = .empty;
    defer rec_list.deinit(allocator);
    for (enr_payloads) |p| {
        try rlp.appendString(&rec_list, allocator, p);
    }
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(allocator);
    try rlp.appendString(&inner, allocator, req_id);
    try rlp.appendString(&inner, allocator, &.{resp_count});
    try rlp.appendListPayload(&inner, allocator, rec_list.items);
    var outer: std.ArrayList(u8) = .empty;
    defer outer.deinit(allocator);
    try rlp.appendListPayload(&outer, allocator, inner.items);
    const out = try allocator.alloc(u8, 1 + outer.items.len);
    out[0] = type_nodes;
    @memcpy(out[1..], outer.items);
    return out;
}

pub fn encodeTalkRequestPlaintext(
    allocator: std.mem.Allocator,
    req_id: []const u8,
    protocol: []const u8,
    msg: []const u8,
) std.mem.Allocator.Error![]u8 {
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(allocator);
    try rlp.appendString(&inner, allocator, req_id);
    try rlp.appendString(&inner, allocator, protocol);
    try rlp.appendString(&inner, allocator, msg);
    var outer: std.ArrayList(u8) = .empty;
    defer outer.deinit(allocator);
    try rlp.appendListPayload(&outer, allocator, inner.items);
    const out = try allocator.alloc(u8, 1 + outer.items.len);
    out[0] = type_talkreq;
    @memcpy(out[1..], outer.items);
    return out;
}

pub fn encodeTalkResponsePlaintext(allocator: std.mem.Allocator, req_id: []const u8, response: []const u8) std.mem.Allocator.Error![]u8 {
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(allocator);
    try rlp.appendString(&inner, allocator, req_id);
    try rlp.appendString(&inner, allocator, response);
    var outer: std.ArrayList(u8) = .empty;
    defer outer.deinit(allocator);
    try rlp.appendListPayload(&outer, allocator, inner.items);
    const out = try allocator.alloc(u8, 1 + outer.items.len);
    out[0] = type_talkresp;
    @memcpy(out[1..], outer.items);
    return out;
}

test "ping roundtrip" {
    const alloc = std.testing.allocator;
    const enc = try encodePingPlaintext(alloc, &.{ 0x01, 0x02 }, 42);
    defer alloc.free(enc);
    const dec = try decodePlaintext(enc, alloc);
    defer dec.deinit(alloc);
    try std.testing.expect(dec == .ping);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, dec.ping.req_id);
    try std.testing.expectEqual(@as(u64, 42), dec.ping.enr_seq);
}

test "pong roundtrip v4" {
    const alloc = std.testing.allocator;
    const ip = [_]u8{ 192, 168, 0, 1 };
    const enc = try encodePongPlaintext(alloc, &.{0xfa}, 9, &ip, 30303);
    defer alloc.free(enc);
    const dec = try decodePlaintext(enc, alloc);
    defer dec.deinit(alloc);
    try std.testing.expect(dec == .pong);
    try std.testing.expectEqualSlices(u8, &ip, dec.pong.to_ip);
    try std.testing.expectEqual(@as(u16, 30303), dec.pong.to_port);
}

test "findnode roundtrip" {
    const alloc = std.testing.allocator;
    const dists = [_]u32{ 0, 1, 256 };
    const enc = try encodeFindnodePlaintext(alloc, &.{0x11}, &dists);
    defer alloc.free(enc);
    const dec = try decodePlaintext(enc, alloc);
    defer dec.deinit(alloc);
    try std.testing.expect(dec == .findnode);
    try std.testing.expectEqualSlices(u32, &dists, dec.findnode.distances);
}

test "nodes talk roundtrip" {
    const alloc = std.testing.allocator;

    const enc_n = try encodeNodesPlaintext(alloc, &.{0x22}, 3, &.{ "enr-a", "enr-b" });
    defer alloc.free(enc_n);
    const dec_n = try decodePlaintext(enc_n, alloc);
    defer dec_n.deinit(alloc);
    try std.testing.expect(dec_n == .nodes);
    try std.testing.expectEqual(@as(u8, 3), dec_n.nodes.resp_count);
    try std.testing.expectEqual(@as(usize, 2), dec_n.nodes.enr_records.len);
    try std.testing.expectEqualStrings("enr-a", dec_n.nodes.enr_records[0]);
    try std.testing.expectEqualStrings("enr-b", dec_n.nodes.enr_records[1]);

    const enc_t = try encodeTalkRequestPlaintext(alloc, &.{0x33}, "eth/66", &.{0xaa});
    defer alloc.free(enc_t);
    const dec_t = try decodePlaintext(enc_t, alloc);
    defer dec_t.deinit(alloc);
    try std.testing.expect(dec_t == .talkreq);
    try std.testing.expectEqualStrings("eth/66", dec_t.talkreq.protocol);

    const enc_r = try encodeTalkResponsePlaintext(alloc, &.{0x44}, "ok");
    defer alloc.free(enc_r);
    const dec_r = try decodePlaintext(enc_r, alloc);
    defer dec_r.deinit(alloc);
    try std.testing.expect(dec_r == .talkresp);
    try std.testing.expectEqualStrings("ok", dec_r.talkresp.response);
}
