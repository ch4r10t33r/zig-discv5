//! Discovery v5 node: inbound `handleReceive`, outbound handshake opening, session cache, and encrypted PING/PONG.

const std = @import("std");
const builtin = @import("builtin");
const enr = @import("enr.zig");
const handshake = @import("handshake.zig");
const identity_v4 = @import("identity_v4.zig");
const message = @import("message.zig");
const message_crypto = @import("message_crypto.zig");
const packet = @import("packet.zig");
const routing = @import("routing.zig");
const session = @import("session.zig");

pub const NodeId = routing.NodeId;

pub const RemoteUdp = struct {
    ip: session.IpAddr,
    port: u16,
};

pub const Config = struct {
    secret_key: [32]u8,
    enr_seq: u64 = 0,
    session_table_cap: usize = 256,
};

pub const Node = struct {
    const PendingChallenge = struct {
        peer_id: NodeId,
        challenge_data: []u8,
    };

    const OutboundHandshake = struct {
        peer_id: NodeId,
        peer_pubkey_compressed: [33]u8,
        remote: RemoteUdp,
        message_nonce: [12]u8,
    };

    allocator: std.mem.Allocator,
    secret_key: [32]u8,
    node_id: NodeId,
    enr_seq: u64,
    sessions: session.SessionTable,
    routing: routing.RoutingTable,
    pending: std.ArrayList(PendingChallenge),
    outbound: std.ArrayList(OutboundHandshake),

    pub const InitError = identity_v4.EcdhError || session.InitError;

    pub fn init(allocator: std.mem.Allocator, cfg: Config) InitError!Node {
        const nid = try identity_v4.nodeIdV4FromSecretKey(cfg.secret_key);
        var sessions = try session.SessionTable.init(allocator, cfg.session_table_cap);
        errdefer sessions.deinit();
        return .{
            .allocator = allocator,
            .secret_key = cfg.secret_key,
            .node_id = nid,
            .enr_seq = cfg.enr_seq,
            .sessions = sessions,
            .routing = routing.RoutingTable.init(nid),
            .pending = .empty,
            .outbound = .empty,
        };
    }

    pub fn deinit(self: *Node) void {
        for (self.pending.items) |p| self.allocator.free(p.challenge_data);
        self.pending.deinit(self.allocator);
        self.outbound.deinit(self.allocator);
        self.sessions.deinit();
    }

    pub fn makeEndpoint(_: *const Node, peer_id: NodeId, ip: session.IpAddr, port: u16) session.UdpEndpoint {
        return .{ .node_id = peer_id, .ip = ip, .port = port };
    }

    fn clearPendingForPeer(self: *Node, peer_id: NodeId) void {
        var i: usize = 0;
        while (i < self.pending.items.len) {
            if (std.mem.eql(u8, &self.pending.items[i].peer_id, &peer_id)) {
                self.allocator.free(self.pending.items[i].challenge_data);
                _ = self.pending.swapRemove(i);
            } else i += 1;
        }
    }

    fn takePending(self: *Node, peer_id: NodeId) ?[]u8 {
        var i: usize = 0;
        while (i < self.pending.items.len) {
            if (std.mem.eql(u8, &self.pending.items[i].peer_id, &peer_id)) {
                const cd = self.pending.items[i].challenge_data;
                _ = self.pending.swapRemove(i);
                return cd;
            }
            i += 1;
        }
        return null;
    }

    pub const OpeningHandshakeError = packet.EncodeError ||
        message_crypto.Error ||
        std.mem.Allocator.Error ||
        identity_v4.EcdhError ||
        error{PeerKeyIdMismatch};

    pub const ReceiveError = packet.Error ||
        message_crypto.Error ||
        message.DecodeError ||
        enr.Error ||
        identity_v4.IdentityProofVerifyError ||
        identity_v4.IdentityProofSignError ||
        identity_v4.EcdhError ||
        packet.EncodeError ||
        routing.Error ||
        std.mem.Allocator.Error ||
        error{ MissingHandshakePending, EmptyHandshakeRecord, EnrNodeIdMismatch, BadHandshakeSignatureLength };

    fn clearOutboundForPeer(self: *Node, peer_id: NodeId) void {
        var i: usize = 0;
        while (i < self.outbound.items.len) {
            if (std.mem.eql(u8, &self.outbound.items[i].peer_id, &peer_id)) {
                _ = self.outbound.swapRemove(i);
            } else i += 1;
        }
    }

    fn takeOutboundByMessageNonce(self: *Node, message_nonce: [12]u8) ?OutboundHandshake {
        var i: usize = 0;
        while (i < self.outbound.items.len) {
            if (std.mem.eql(u8, &self.outbound.items[i].message_nonce, &message_nonce)) {
                return self.outbound.swapRemove(i);
            }
            i += 1;
        }
        return null;
    }

    /// First encrypted ordinary (unknown session) toward `peer_id`, using a random throwaway AES key.
    /// Completes after the peer's WHOAREYOU is passed to **handleReceive**. Caller frees the returned datagram.
    pub fn allocOpeningPingHandshake(
        self: *Node,
        peer_id: NodeId,
        peer_pubkey_compressed: [33]u8,
        remote: RemoteUdp,
        req_id: []const u8,
        ping_enr_seq: u64,
    ) OpeningHandshakeError![]u8 {
        const alloc = self.allocator;
        const derived = try identity_v4.nodeIdV4FromCompressedSec1(peer_pubkey_compressed);
        if (!std.mem.eql(u8, &derived, &peer_id)) return error.PeerKeyIdMismatch;

        self.clearOutboundForPeer(peer_id);

        var iv: [16]u8 = undefined;
        fillRandomBytes(&iv);
        var nonce: [12]u8 = undefined;
        fillRandomBytes(&nonce);

        var temp_key: [16]u8 = undefined;
        fillRandomBytes(&temp_key);
        defer @memset(&temp_key, 0);

        const ping_pt = try message.encodePingPlaintext(alloc, req_id, ping_enr_seq);
        defer alloc.free(ping_pt);

        var prefix: [packet.static_prefix_size + packet.message_auth_size]u8 = undefined;
        @memcpy(prefix[0..16], &iv);
        var static_plain: [packet.static_header_size]u8 = undefined;
        packet.writePlaintextStaticHeader(&static_plain, .message, nonce, packet.message_auth_size);
        @memcpy(prefix[16..][0..packet.static_header_size], &static_plain);
        @memcpy(prefix[packet.static_prefix_size..][0..packet.message_auth_size], &self.node_id);

        const ct = try message_crypto.encryptMessage(alloc, temp_key, nonce, ping_pt, &prefix);
        defer alloc.free(ct);

        const pkt = try packet.encodeOrdinaryMessagePacket(alloc, peer_id, iv, nonce, self.node_id, ct);
        errdefer alloc.free(pkt);

        try self.outbound.append(alloc, .{
            .peer_id = peer_id,
            .peer_pubkey_compressed = peer_pubkey_compressed,
            .remote = remote,
            .message_nonce = nonce,
        });
        return pkt;
    }

    /// On success, each element of `responses_out` is an allocated reply packet; caller must free them.
    pub fn handleReceive(
        self: *Node,
        remote: RemoteUdp,
        datagram: []const u8,
        responses_out: *std.ArrayList([]u8),
    ) ReceiveError!void {
        const alloc = self.allocator;

        const copy = try alloc.dupe(u8, datagram);
        defer alloc.free(copy);

        const parsed = try packet.decodeInPlace(&self.node_id, copy);
        switch (parsed.header.flag) {
            .whoareyou => try self.handleWhoareyouAsInitiator(remote, copy, parsed, responses_out),
            .message => try self.handleOrdinary(remote, copy, parsed, responses_out),
            .handshake => try self.handleHandshake(remote, copy, parsed, responses_out),
        }
    }

    fn handleWhoareyouAsInitiator(
        self: *Node,
        remote: RemoteUdp,
        _: []u8,
        parsed: packet.ParsedPacket,
        responses_out: *std.ArrayList([]u8),
    ) ReceiveError!void {
        const alloc = self.allocator;
        const o = self.takeOutboundByMessageNonce(parsed.header.nonce) orelse return;

        _ = try parsed.decodeAuth();

        var cd_buf: [packet.static_prefix_size + packet.whoareyou_auth_size]u8 = undefined;
        packet.writeWhoareyouChallengeData(&cd_buf, parsed);

        var sk_eph: [32]u8 = undefined;
        fillRandomBytes(&sk_eph);
        defer @memset(&sk_eph, 0);

        const eph_pub = try identity_v4.compressedPubkeyFromSecretKey(sk_eph);
        const ikm = try identity_v4.ecdhLocalSecret(o.peer_pubkey_compressed, sk_eph);

        const keys = handshake.deriveSessionKeys(&ikm, &cd_buf, self.node_id, o.peer_id);
        const sig = try identity_v4.signIdentityProof(&cd_buf, &eph_pub, o.peer_id, self.secret_key, null);

        const pk_self = try identity_v4.compressedPubkeyFromSecretKey(self.secret_key);
        const record = try buildMinimalEnrRlp(alloc, pk_self, self.enr_seq);
        defer alloc.free(record);

        var iv1: [16]u8 = undefined;
        fillRandomBytes(&iv1);
        var nonce_hs: [12]u8 = undefined;
        fillRandomBytes(&nonce_hs);

        const hs_pkt = try packet.encodeHandshakePacket(
            alloc,
            o.peer_id,
            iv1,
            nonce_hs,
            self.node_id,
            64,
            33,
            &sig,
            &eph_pub,
            record,
            &.{},
        );
        errdefer alloc.free(hs_pkt);

        const ep = self.makeEndpoint(o.peer_id, remote.ip, remote.port);
        try self.sessions.put(ep, session.CachedSession.fromDerived(keys), false);
        errdefer _ = self.sessions.remove(ep);

        _ = try self.routing.add(o.peer_id);

        try responses_out.append(alloc, hs_pkt);
    }

    fn handleOrdinary(
        self: *Node,
        remote: RemoteUdp,
        copy: []u8,
        parsed: packet.ParsedPacket,
        responses_out: *std.ArrayList([]u8),
    ) ReceiveError!void {
        const alloc = self.allocator;
        const auth = try parsed.decodeAuth();
        const src_id = switch (auth) {
            .message => |m| m.src_id,
            else => unreachable,
        };
        const ep = self.makeEndpoint(src_id, remote.ip, remote.port);

        if (self.sessions.get(ep)) |lu| {
            const read_key = if (lu.peer_handshake_initiator)
                lu.session.readKeyPeerWasInitiator()
            else
                lu.session.readKeyWeWereInitiator();

            const plain = try message_crypto.decryptOrdinaryMessage(alloc, copy, &parsed, read_key);
            defer alloc.free(plain);

            const decoded = try message.decodePlaintext(plain, alloc);
            switch (decoded) {
                .ping => |p| {
                    const reply = try self.buildEncryptedPong(remote, ep, lu, p);
                    errdefer alloc.free(reply);
                    try responses_out.append(alloc, reply);
                },
                else => {},
            }
            return;
        }

        self.clearPendingForPeer(src_id);

        var iv: [16]u8 = undefined;
        fillRandomBytes(&iv);
        var id_nonce: [16]u8 = undefined;
        fillRandomBytes(&id_nonce);

        const challenge = try packet.allocWhoareyouChallengeData(alloc, iv, parsed.header.nonce, id_nonce, self.enr_seq);
        errdefer alloc.free(challenge);

        try self.pending.append(alloc, .{ .peer_id = src_id, .challenge_data = challenge });
        errdefer {
            const last = self.pending.pop() orelse unreachable;
            alloc.free(last.challenge_data);
        }

        const way = try packet.encodeWhoareyouPacket(alloc, src_id, iv, parsed.header.nonce, id_nonce, self.enr_seq);
        errdefer alloc.free(way);

        try responses_out.append(alloc, way);
    }

    fn buildEncryptedPong(
        self: *Node,
        remote: RemoteUdp,
        ep: session.UdpEndpoint,
        lu: session.SessionLookup,
        ping: message.Ping,
    ) ReceiveError![]u8 {
        const alloc = self.allocator;

        var iv: [16]u8 = undefined;
        fillRandomBytes(&iv);

        var rand8: [8]u8 = undefined;
        fillRandomBytes(&rand8);
        const msg_nonce = lu.session.nextMessageNonce(rand8);

        var prefix: [packet.static_prefix_size + packet.message_auth_size]u8 = undefined;
        @memcpy(prefix[0..16], &iv);
        var static_plain: [packet.static_header_size]u8 = undefined;
        packet.writePlaintextStaticHeader(&static_plain, .message, msg_nonce, packet.message_auth_size);
        @memcpy(prefix[16..][0..packet.static_header_size], &static_plain);
        @memcpy(prefix[packet.static_prefix_size..][0..packet.message_auth_size], &self.node_id);

        const ad = prefix[0..prefix.len];
        const write_key = if (lu.peer_handshake_initiator)
            lu.session.writeKeyPeerWasInitiator()
        else
            lu.session.writeKeyWeWereInitiator();

        const ip_slice: []const u8 = switch (remote.ip) {
            .v4 => |a| &a,
            .v6 => |a| &a,
        };
        const pong_pt = try message.encodePongPlaintext(alloc, ping.req_id, self.enr_seq, ip_slice, remote.port);
        defer alloc.free(pong_pt);

        const ct = try message_crypto.encryptMessage(alloc, write_key, msg_nonce, pong_pt, ad);
        defer alloc.free(ct);

        return packet.encodeOrdinaryMessagePacket(alloc, ep.node_id, iv, msg_nonce, self.node_id, ct);
    }

    fn handleHandshake(
        self: *Node,
        remote: RemoteUdp,
        copy: []u8,
        parsed: packet.ParsedPacket,
        responses_out: *std.ArrayList([]u8),
    ) ReceiveError!void {
        const alloc = self.allocator;
        const auth = try parsed.decodeAuth();
        const hs = switch (auth) {
            .handshake => |h| h,
            else => unreachable,
        };
        const initiator_id = hs.src_id;

        const challenge_data = self.takePending(initiator_id) orelse return error.MissingHandshakePending;
        defer alloc.free(challenge_data);

        if (hs.record.len == 0) return error.EmptyHandshakeRecord;

        const rec = try enr.decodeRecordBytes(hs.record);
        const pk = try enr.compressedSecp256k1Pubkey(rec.pairs_payload);
        const enr_id = try identity_v4.nodeIdV4FromCompressedSec1(pk);
        if (!std.mem.eql(u8, &enr_id, &initiator_id)) return error.EnrNodeIdMismatch;

        if (hs.signature.len != 64) return error.BadHandshakeSignatureLength;
        const sig: [64]u8 = hs.signature[0..64].*;

        const eph: [33]u8 = hs.eph_pubkey[0..33].*;

        const ikm = try identity_v4.ecdhLocalSecret(eph, self.secret_key);

        const keys = handshake.deriveSessionKeys(&ikm, challenge_data, initiator_id, self.node_id);
        try identity_v4.verifyIdentityProof(sig, challenge_data, hs.eph_pubkey, self.node_id, pk);

        const ep = self.makeEndpoint(initiator_id, remote.ip, remote.port);
        try self.sessions.put(ep, session.CachedSession.fromDerived(keys), true);
        _ = try self.routing.add(initiator_id);

        if (parsed.message_cipher.len == 0) return;

        const read_key = keys.initiator_key;
        const ad = message_crypto.messageAdditionalData(copy, &parsed);
        const plain = try message_crypto.decryptMessage(alloc, read_key, parsed.header.nonce, parsed.message_cipher, ad);
        defer alloc.free(plain);
        const decoded = try message.decodePlaintext(plain, alloc);
        switch (decoded) {
            .ping => |p| {
                const lu = self.sessions.get(ep) orelse unreachable;
                const reply = try self.buildEncryptedPong(remote, ep, lu, p);
                errdefer alloc.free(reply);
                try responses_out.append(alloc, reply);
            },
            else => {},
        }
    }
};

var g_entropy_counter = std.atomic.Value(u64).init(0x14650fb0739d0383);

fn fillRandomBytes(buf: []u8) void {
    if (builtin.link_libc and @hasDecl(std.c, "arc4random_buf")) {
        std.c.arc4random_buf(buf.ptr, buf.len);
        return;
    }
    if (builtin.os.tag == .linux) {
        var off: usize = 0;
        while (off < buf.len) {
            const rc = std.os.linux.getrandom(buf.ptr + off, buf.len - off, 0);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => off += rc,
                .INTR => continue,
                else => break,
            }
        }
        if (off >= buf.len) return;
        weakRandomFill(buf[off..]);
        return;
    }
    weakRandomFill(buf);
}

fn weakRandomFill(buf: []u8) void {
    var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
    const c = g_entropy_counter.fetchAdd(1, .monotonic);
    const p = @intFromPtr(buf.ptr);
    std.mem.writeInt(u64, seed[0..8], c, .little);
    std.mem.writeInt(usize, seed[8..][0..@sizeOf(usize)], p, .little);
    for (seed[16..], 0..) |*b, i| b.* = seed[i % 16] ^ @as(u8, @intCast(i +% 3));
    var cs = std.Random.DefaultCsprng.init(seed);
    cs.random().bytes(buf);
    @memset(&seed, 0);
}

fn buildMinimalEnrRlp(allocator: std.mem.Allocator, compressed_pk: [33]u8, seq: u64) ![]u8 {
    const rlp_mod = @import("rlp.zig");
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(allocator);
    var sig65: [65]u8 = undefined;
    @memset(&sig65, 0);
    try rlp_mod.appendString(&inner, allocator, &sig65);
    var seq_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_buf, seq, .big);
    var seq_start: usize = 0;
    while (seq_start < seq_buf.len and seq_buf[seq_start] == 0) seq_start += 1;
    const seq_slice: []const u8 = if (seq == 0) &[_]u8{} else seq_buf[seq_start..];
    try rlp_mod.appendString(&inner, allocator, seq_slice);
    try rlp_mod.appendString(&inner, allocator, "id");
    try rlp_mod.appendString(&inner, allocator, "v4");
    try rlp_mod.appendString(&inner, allocator, "secp256k1");
    try rlp_mod.appendString(&inner, allocator, &compressed_pk);
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(allocator);
    try rlp_mod.appendListPayload(&raw, allocator, inner.items);
    return try raw.toOwnedSlice(allocator);
}

test "unknown session ordinary yields WHOAREYOU with echoed nonce" {
    const alloc = std.testing.allocator;

    var sk_b: [32]u8 = @splat(0);
    sk_b[31] = 3;
    var node_b = try Node.init(alloc, .{ .secret_key = sk_b, .enr_seq = 9 });
    defer node_b.deinit();

    var sk_a: [32]u8 = @splat(0);
    sk_a[31] = 5;
    const id_a = try identity_v4.nodeIdV4FromSecretKey(sk_a);

    var iv: [16]u8 = undefined;
    @memset(&iv, 0x2a);
    var nonce: [12]u8 = undefined;
    for (&nonce, 0..) |*b, i| b.* = @truncate(i + 1);

    const ping_pt = try message.encodePingPlaintext(alloc, &.{0x07}, 4);
    defer alloc.free(ping_pt);

    const key = [_]u8{0x55} ** 16;
    var prefix: [packet.static_prefix_size + packet.message_auth_size]u8 = undefined;
    @memcpy(prefix[0..16], &iv);
    var static_plain: [packet.static_header_size]u8 = undefined;
    packet.writePlaintextStaticHeader(&static_plain, .message, nonce, packet.message_auth_size);
    @memcpy(prefix[16..][0..packet.static_header_size], &static_plain);
    @memcpy(prefix[packet.static_prefix_size..][0..packet.message_auth_size], &id_a);

    const ct = try message_crypto.encryptMessage(alloc, key, nonce, ping_pt, &prefix);
    defer alloc.free(ct);

    const ordinary = try packet.encodeOrdinaryMessagePacket(alloc, node_b.node_id, iv, nonce, id_a, ct);
    defer alloc.free(ordinary);

    var responses: std.ArrayList([]u8) = .empty;
    defer {
        for (responses.items) |s| alloc.free(s);
        responses.deinit(alloc);
    }

    const remote: RemoteUdp = .{ .ip = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 30303 };
    try node_b.handleReceive(remote, ordinary, &responses);

    try std.testing.expectEqual(@as(usize, 1), responses.items.len);
    const dec_copy = try alloc.dupe(u8, responses.items[0]);
    defer alloc.free(dec_copy);
    const parsed = try packet.decodeInPlace(&id_a, dec_copy);
    try std.testing.expect(parsed.header.flag == .whoareyou);
    try std.testing.expectEqualSlices(u8, &nonce, &parsed.header.nonce);
}

test "session present ping yields encrypted pong" {
    const alloc = std.testing.allocator;

    var sk_b: [32]u8 = @splat(0);
    sk_b[31] = 11;
    var node_b = try Node.init(alloc, .{ .secret_key = sk_b });
    defer node_b.deinit();

    var sk_a: [32]u8 = @splat(0);
    sk_a[31] = 13;
    const id_a = try identity_v4.nodeIdV4FromSecretKey(sk_a);

    const ikm = [_]u8{0x02} ++ [_]u8{0x33} ** 32;
    const challenge = [_]u8{0x77} ** (packet.static_prefix_size + packet.whoareyou_auth_size);
    const keys = handshake.deriveSessionKeys(&ikm, &challenge, id_a, node_b.node_id);

    const ep = node_b.makeEndpoint(id_a, .{ .v4 = .{ 192, 168, 1, 20 } }, 9000);
    try node_b.sessions.put(ep, session.CachedSession.fromDerived(keys), true);

    var iv: [16]u8 = undefined;
    @memset(&iv, 0x3c);
    var nonce: [12]u8 = undefined;
    @memset(&nonce, 0x19);

    const ping_pt = try message.encodePingPlaintext(alloc, &.{ 0xaa, 0xbb }, 2);
    defer alloc.free(ping_pt);

    var prefix: [packet.static_prefix_size + packet.message_auth_size]u8 = undefined;
    @memcpy(prefix[0..16], &iv);
    var static_plain: [packet.static_header_size]u8 = undefined;
    packet.writePlaintextStaticHeader(&static_plain, .message, nonce, packet.message_auth_size);
    @memcpy(prefix[16..][0..packet.static_header_size], &static_plain);
    @memcpy(prefix[packet.static_prefix_size..][0..packet.message_auth_size], &id_a);

    const ct = try message_crypto.encryptMessage(alloc, keys.initiator_key, nonce, ping_pt, &prefix);
    defer alloc.free(ct);

    const ordinary = try packet.encodeOrdinaryMessagePacket(alloc, node_b.node_id, iv, nonce, id_a, ct);
    defer alloc.free(ordinary);

    var responses: std.ArrayList([]u8) = .empty;
    defer {
        for (responses.items) |s| alloc.free(s);
        responses.deinit(alloc);
    }

    const remote: RemoteUdp = .{ .ip = ep.ip, .port = ep.port };
    try node_b.handleReceive(remote, ordinary, &responses);

    try std.testing.expectEqual(@as(usize, 1), responses.items.len);
    const pong_copy = try alloc.dupe(u8, responses.items[0]);
    defer alloc.free(pong_copy);

    const parsed = try packet.decodeInPlace(&id_a, pong_copy);
    const plain = try message_crypto.decryptOrdinaryMessage(alloc, pong_copy, &parsed, keys.recipient_key);
    defer alloc.free(plain);
    const dec = try message.decodePlaintext(plain, alloc);
    try std.testing.expect(dec == .pong);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, dec.pong.req_id);
}

test "responder completes handshake and answers ping inside handshake" {
    const alloc = std.testing.allocator;

    var sk_b: [32]u8 = @splat(0);
    sk_b[31] = 101;
    var node_b = try Node.init(alloc, .{ .secret_key = sk_b, .enr_seq = 3 });
    defer node_b.deinit();

    var sk_a: [32]u8 = @splat(0);
    sk_a[31] = 103;
    const id_a = try identity_v4.nodeIdV4FromSecretKey(sk_a);
    const pk_a = try identity_v4.compressedPubkeyFromSecretKey(sk_a);

    var iv0: [16]u8 = undefined;
    @memset(&iv0, 0x40);
    var nonce0: [12]u8 = undefined;
    @memset(&nonce0, 0x51);

    const ping_pt = try message.encodePingPlaintext(alloc, &.{0xde}, 1);
    defer alloc.free(ping_pt);

    const dummy_key = [_]u8{0x99} ** 16;
    var prefix0: [packet.static_prefix_size + packet.message_auth_size]u8 = undefined;
    @memcpy(prefix0[0..16], &iv0);
    var st0: [packet.static_header_size]u8 = undefined;
    packet.writePlaintextStaticHeader(&st0, .message, nonce0, packet.message_auth_size);
    @memcpy(prefix0[16..][0..packet.static_header_size], &st0);
    @memcpy(prefix0[packet.static_prefix_size..][0..packet.message_auth_size], &id_a);
    const ct0 = try message_crypto.encryptMessage(alloc, dummy_key, nonce0, ping_pt, &prefix0);
    defer alloc.free(ct0);
    const ordinary = try packet.encodeOrdinaryMessagePacket(alloc, node_b.node_id, iv0, nonce0, id_a, ct0);
    defer alloc.free(ordinary);

    var responses: std.ArrayList([]u8) = .empty;
    defer {
        for (responses.items) |s| alloc.free(s);
        responses.deinit(alloc);
    }
    const remote: RemoteUdp = .{ .ip = .{ .v4 = .{ 10, 9, 8, 7 } }, .port = 40404 };
    try node_b.handleReceive(remote, ordinary, &responses);
    try std.testing.expectEqual(@as(usize, 1), responses.items.len);
    const way = responses.items[0];

    const challenge = try alloc.dupe(u8, way);
    defer alloc.free(challenge);
    const parsed_way = try packet.decodeInPlace(&id_a, challenge);

    var sk_eph: [32]u8 = @splat(0);
    sk_eph[31] = 107;
    const eph_pub = try identity_v4.compressedPubkeyFromSecretKey(sk_eph);

    const pk_b_static = try identity_v4.compressedPubkeyFromSecretKey(node_b.secret_key);
    const ikm_a = try identity_v4.ecdhLocalSecret(pk_b_static, sk_eph);

    var cd_buf: [packet.static_prefix_size + packet.whoareyou_auth_size]u8 = undefined;
    @memcpy(cd_buf[0..16], &parsed_way.iv);
    var stw: [packet.static_header_size]u8 = undefined;
    packet.writePlaintextStaticHeader(&stw, .whoareyou, parsed_way.header.nonce, packet.whoareyou_auth_size);
    @memcpy(cd_buf[16..][0..packet.static_header_size], &stw);
    @memcpy(cd_buf[packet.static_prefix_size..], parsed_way.auth_data);

    const keys_a = handshake.deriveSessionKeys(&ikm_a, &cd_buf, id_a, node_b.node_id);

    const record = try buildMinimalEnrRlp(alloc, pk_a, 1);
    defer alloc.free(record);

    const sig = try identity_v4.signIdentityProof(&cd_buf, &eph_pub, node_b.node_id, sk_a, null);

    var iv1: [16]u8 = undefined;
    @memset(&iv1, 0x61);
    var nonce1: [12]u8 = undefined;
    @memset(&nonce1, 0x62);

    const auth_total = packet.handshake_auth_head_size + 64 + 33 + record.len;
    const prefix1 = try alloc.alloc(u8, packet.static_prefix_size + auth_total);
    defer alloc.free(prefix1);
    @memcpy(prefix1[0..16], &iv1);
    var st1: [packet.static_header_size]u8 = undefined;
    packet.writePlaintextStaticHeader(&st1, .handshake, nonce1, @intCast(auth_total));
    @memcpy(prefix1[16..][0..packet.static_header_size], &st1);
    const auth_slice = prefix1[packet.static_prefix_size..];
    @memcpy(auth_slice[0..32], &id_a);
    auth_slice[32] = 64;
    auth_slice[33] = 33;
    @memcpy(auth_slice[34..98], &sig);
    @memcpy(auth_slice[98..131], &eph_pub);
    @memcpy(auth_slice[131 .. 131 + record.len], record);

    const ad1 = prefix1[0 .. packet.static_prefix_size + auth_total];
    const inner_ping = try message.encodePingPlaintext(alloc, &.{0x11}, 5);
    defer alloc.free(inner_ping);
    const inner_ct = try message_crypto.encryptMessage(alloc, keys_a.initiator_key, nonce1, inner_ping, ad1);
    defer alloc.free(inner_ct);

    const hs_pkt = try packet.encodeHandshakePacket(
        alloc,
        node_b.node_id,
        iv1,
        nonce1,
        id_a,
        64,
        33,
        &sig,
        &eph_pub,
        record,
        inner_ct,
    );
    defer alloc.free(hs_pkt);

    for (responses.items) |s| alloc.free(s);
    responses.clearRetainingCapacity();

    try node_b.handleReceive(remote, hs_pkt, &responses);
    try std.testing.expectEqual(@as(usize, 1), responses.items.len);

    const pong_wire = responses.items[0];
    const pong_copy = try alloc.dupe(u8, pong_wire);
    defer alloc.free(pong_copy);
    const parsed_pong = try packet.decodeInPlace(&id_a, pong_copy);
    const plain = try message_crypto.decryptOrdinaryMessage(alloc, pong_copy, &parsed_pong, keys_a.recipient_key);
    defer alloc.free(plain);
    const msg2 = try message.decodePlaintext(plain, alloc);
    try std.testing.expect(msg2 == .pong);
    try std.testing.expectEqualSlices(u8, &.{0x11}, msg2.pong.req_id);
}

test "initiator opening ping completes handshake after WHOAREYOU" {
    const alloc = std.testing.allocator;

    var sk_b: [32]u8 = @splat(0);
    sk_b[31] = 201;
    var node_b = try Node.init(alloc, .{ .secret_key = sk_b, .enr_seq = 4 });
    defer node_b.deinit();

    var sk_a: [32]u8 = @splat(0);
    sk_a[31] = 203;
    var node_a = try Node.init(alloc, .{ .secret_key = sk_a, .enr_seq = 2 });
    defer node_a.deinit();

    const id_a = node_a.node_id;
    const id_b = node_b.node_id;
    const pk_b = try identity_v4.compressedPubkeyFromSecretKey(sk_b);

    const remote_a: RemoteUdp = .{ .ip = .{ .v4 = .{ 10, 0, 0, 11 } }, .port = 51111 };
    const remote_b: RemoteUdp = .{ .ip = .{ .v4 = .{ 10, 0, 0, 22 } }, .port = 52222 };

    const ordinary = try node_a.allocOpeningPingHandshake(id_b, pk_b, remote_b, &.{ 0xca, 0xfe }, 9);
    defer alloc.free(ordinary);

    var from_b: std.ArrayList([]u8) = .empty;
    defer {
        for (from_b.items) |s| alloc.free(s);
        from_b.deinit(alloc);
    }
    try node_b.handleReceive(remote_a, ordinary, &from_b);
    try std.testing.expectEqual(@as(usize, 1), from_b.items.len);
    const way = from_b.items[0];

    var from_a: std.ArrayList([]u8) = .empty;
    defer {
        for (from_a.items) |s| alloc.free(s);
        from_a.deinit(alloc);
    }
    try node_a.handleReceive(remote_b, way, &from_a);
    try std.testing.expectEqual(@as(usize, 1), from_a.items.len);
    const hs = from_a.items[0];

    for (from_b.items) |s| alloc.free(s);
    from_b.clearRetainingCapacity();

    try node_b.handleReceive(remote_a, hs, &from_b);
    try std.testing.expectEqual(@as(usize, 0), from_b.items.len);

    const ep_on_a = node_a.makeEndpoint(id_b, remote_b.ip, remote_b.port);
    const ep_on_b = node_b.makeEndpoint(id_a, remote_a.ip, remote_a.port);
    const lu_a = node_a.sessions.get(ep_on_a) orelse unreachable;
    const lu_b = node_b.sessions.get(ep_on_b) orelse unreachable;
    try std.testing.expect(!lu_a.peer_handshake_initiator);
    try std.testing.expect(lu_b.peer_handshake_initiator);

    var iv: [16]u8 = undefined;
    @memset(&iv, 0x5e);
    var nonce: [12]u8 = undefined;
    @memset(&nonce, 0x6f);

    const ping_pt2 = try message.encodePingPlaintext(alloc, &.{ 0x01, 0x02 }, 3);
    defer alloc.free(ping_pt2);

    var prefix: [packet.static_prefix_size + packet.message_auth_size]u8 = undefined;
    @memcpy(prefix[0..16], &iv);
    var static_plain: [packet.static_header_size]u8 = undefined;
    packet.writePlaintextStaticHeader(&static_plain, .message, nonce, packet.message_auth_size);
    @memcpy(prefix[16..][0..packet.static_header_size], &static_plain);
    @memcpy(prefix[packet.static_prefix_size..][0..packet.message_auth_size], &id_a);

    const write_key = lu_a.session.writeKeyWeWereInitiator();
    const ct2 = try message_crypto.encryptMessage(alloc, write_key, nonce, ping_pt2, &prefix);
    defer alloc.free(ct2);

    const ordinary2 = try packet.encodeOrdinaryMessagePacket(alloc, id_b, iv, nonce, id_a, ct2);
    defer alloc.free(ordinary2);

    var from_b2: std.ArrayList([]u8) = .empty;
    defer {
        for (from_b2.items) |s| alloc.free(s);
        from_b2.deinit(alloc);
    }
    try node_b.handleReceive(remote_a, ordinary2, &from_b2);
    try std.testing.expectEqual(@as(usize, 1), from_b2.items.len);

    const pong_copy = try alloc.dupe(u8, from_b2.items[0]);
    defer alloc.free(pong_copy);
    const parsed_pong = try packet.decodeInPlace(&id_a, pong_copy);
    const read_key = lu_a.session.readKeyWeWereInitiator();
    const plain = try message_crypto.decryptOrdinaryMessage(alloc, pong_copy, &parsed_pong, read_key);
    defer alloc.free(plain);
    const msg2 = try message.decodePlaintext(plain, alloc);
    try std.testing.expect(msg2 == .pong);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, msg2.pong.req_id);
}
