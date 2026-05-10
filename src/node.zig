//! Discovery v5 node: inbound `handleReceive`, outbound handshake opening, session cache, and encrypted
//! PING/PONG, FINDNODE/NODES (cached peer ENRs, chunked replies), and TALKREQ/TALKRESP (default echo).
//!
//! Pass a shared **`now_ms`** clock into **handleReceive** so optional session TTL, pending WHOAREYOU TTL,
//! and decrypt-fail recovery (drop session → WHOAREYOU) behave deterministically.
//!
//! Routing table: **FINDNODE** only returns peers with **ping_replied** (discv5-theory). Handshake completion
//! marks the peer verified; for strict PING tracking call **registerOutboundPing** before sending an encrypted
//! PING, then an inbound **PONG** with the same **req_id** sets **ping_replied**. Use **RoutingTable.pickStaleBucketForRefresh**
//! / **markBucketRefreshed** for periodic bucket refresh.
//!
//! Operational limits: **Config.ingress** and **udp_runtime.pumpOnceEx** with **PumpOpts.egress_limiter** (same
//! **ingress_limit.IngressLimiter** type for send-side windows).

const std = @import("std");
const builtin = @import("builtin");
const enr = @import("enr.zig");
const ingress_limit = @import("ingress_limit.zig");
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

/// Opaque key for **ingress_limit** (IPv4 address big-endian in high bits, port in low 16 bits; IPv6 uses Wyhash).
pub fn ingressRateKey(remote: RemoteUdp) u64 {
    switch (remote.ip) {
        .v4 => |b| {
            const ipu = std.mem.readInt(u32, &b, .big);
            return (@as(u64, ipu) << 16) | @as(u64, remote.port);
        },
        .v6 => |b| {
            const h = std.hash.Wyhash.hash(0, &b);
            return h ^ (@as(u64, remote.port) << 48);
        },
    }
}

pub const Config = struct {
    secret_key: [32]u8,
    enr_seq: u64 = 0,
    session_table_cap: usize = 256,
    /// Drop cached sessions when `now_ms - last_seen_ms` exceeds this. Null disables time-based expiry.
    session_ttl_ms: ?u64 = null,
    /// Remove WHOAREYOU challenge state older than this. Null disables.
    pending_challenge_ttl_ms: ?u64 = null,
    /// Upper bound on pending WHOAREYOU entries; oldest is evicted when full.
    pending_challenge_cap: usize = 256,
    /// Inbound datagram rate limits (applied before decode). Defaults disable limits.
    ingress: ingress_limit.Config = .{},
    /// Drop **allocOpeningPingHandshake** state when no WHOAREYOU arrives within this time. Null disables.
    outbound_opening_ttl_ms: ?u64 = null,
};

/// Max number of logarithmic distances in one FINDNODE (discv5 clients typically use small lists).
const max_findnode_distances: usize = 32;
/// Max ENR payloads per NODES packet (conservative; keeps UDP datagrams under typical MTU).
const max_enrs_per_nodes_packet: usize = 3;

/// Upper bound on remembered outbound PING **req_id**s for PONG correlation.
const outbound_ping_track_cap: usize = 128;

const PeerEnrEntry = struct {
    id: NodeId,
    raw: []u8,
};

pub const Node = struct {
    const PendingChallenge = struct {
        peer_id: NodeId,
        challenge_data: []u8,
        /// Responder's copy of the initiator's ENR when WHOAREYOU was sent; null if none was cached.
        cached_initiator_record: ?[]u8,
        created_ms: u64,
    };

    const TakenPending = struct {
        challenge_data: []u8,
        cached_initiator_record: ?[]u8,
    };

    const OutboundHandshake = struct {
        peer_id: NodeId,
        peer_pubkey_compressed: [33]u8,
        remote: RemoteUdp,
        message_nonce: [12]u8,
        created_ms: u64,
    };

    const OutboundPing = struct {
        peer_id: NodeId,
        req_id: []u8,
    };

    allocator: std.mem.Allocator,
    secret_key: [32]u8,
    node_id: NodeId,
    enr_seq: u64,
    pending_challenge_ttl_ms: ?u64,
    pending_challenge_cap: usize,
    outbound_opening_ttl_ms: ?u64,
    ingress: ingress_limit.IngressLimiter,
    sessions: session.SessionTable,
    routing: routing.RoutingTable,
    /// Raw ENR RLP bytes keyed by node id (e.g. from verified inbound handshakes). Used for NODES replies.
    peer_enrs: std.ArrayList(PeerEnrEntry),
    pending: std.ArrayList(PendingChallenge),
    outbound: std.ArrayList(OutboundHandshake),
    outbound_pings: std.ArrayList(OutboundPing),

    pub const InitError = identity_v4.EcdhError || session.InitError;

    pub fn init(allocator: std.mem.Allocator, cfg: Config) InitError!Node {
        const nid = try identity_v4.nodeIdV4FromSecretKey(cfg.secret_key);
        var sessions = try session.SessionTable.init(allocator, cfg.session_table_cap, cfg.session_ttl_ms);
        errdefer sessions.deinit();
        return .{
            .allocator = allocator,
            .secret_key = cfg.secret_key,
            .node_id = nid,
            .enr_seq = cfg.enr_seq,
            .pending_challenge_ttl_ms = cfg.pending_challenge_ttl_ms,
            .pending_challenge_cap = @max(1, cfg.pending_challenge_cap),
            .outbound_opening_ttl_ms = cfg.outbound_opening_ttl_ms,
            .ingress = ingress_limit.IngressLimiter.init(cfg.ingress),
            .sessions = sessions,
            .routing = routing.RoutingTable.init(nid),
            .peer_enrs = .empty,
            .pending = .empty,
            .outbound = .empty,
            .outbound_pings = .empty,
        };
    }

    pub fn deinit(self: *Node) void {
        for (self.peer_enrs.items) |e| self.allocator.free(e.raw);
        self.peer_enrs.deinit(self.allocator);
        for (self.pending.items) |p| {
            self.allocator.free(p.challenge_data);
            if (p.cached_initiator_record) |r| self.allocator.free(r);
        }
        self.pending.deinit(self.allocator);
        for (self.outbound_pings.items) |e| self.allocator.free(e.req_id);
        self.outbound_pings.deinit(self.allocator);
        self.outbound.deinit(self.allocator);
        self.ingress.deinit(self.allocator);
        self.sessions.deinit();
    }

    /// Register the **req_id** of an encrypted PING about to be sent to **peer_id**. A matching inbound **PONG**
    /// marks the peer **ping_replied** in the routing table. Evicts oldest entries when over capacity.
    pub fn registerOutboundPing(self: *Node, peer_id: NodeId, req_id: []const u8) std.mem.Allocator.Error!void {
        const alloc = self.allocator;
        while (self.outbound_pings.items.len >= outbound_ping_track_cap) {
            const old = self.outbound_pings.orderedRemove(0);
            alloc.free(old.req_id);
        }
        const dup = try alloc.dupe(u8, req_id);
        errdefer alloc.free(dup);
        try self.outbound_pings.append(alloc, .{ .peer_id = peer_id, .req_id = dup });
    }

    fn consumeOutboundPingForPong(self: *Node, peer_id: NodeId, req_id: []const u8) void {
        const alloc = self.allocator;
        var i: usize = 0;
        while (i < self.outbound_pings.items.len) {
            const e = self.outbound_pings.items[i];
            if (std.mem.eql(u8, &e.peer_id, &peer_id) and std.mem.eql(u8, e.req_id, req_id)) {
                alloc.free(e.req_id);
                _ = self.outbound_pings.swapRemove(i);
                _ = self.routing.markPingReplied(peer_id);
                return;
            }
            i += 1;
        }
    }

    /// Stores or replaces the cached raw ENR for `node_id` (e.g. after a verified handshake).
    pub fn rememberPeerRecord(self: *Node, node_id: NodeId, raw_enr: []const u8) std.mem.Allocator.Error!void {
        const alloc = self.allocator;
        const dup = try alloc.dupe(u8, raw_enr);
        errdefer alloc.free(dup);
        for (self.peer_enrs.items) |*e| {
            if (std.mem.eql(u8, &e.id, &node_id)) {
                alloc.free(e.raw);
                e.raw = dup;
                return;
            }
        }
        try self.peer_enrs.append(alloc, .{ .id = node_id, .raw = dup });
    }

    fn peerRecordBytes(self: *const Node, node_id: NodeId) ?[]const u8 {
        for (self.peer_enrs.items) |e| {
            if (std.mem.eql(u8, &e.id, &node_id)) return e.raw;
        }
        return null;
    }

    pub fn makeEndpoint(_: *const Node, peer_id: NodeId, ip: session.IpAddr, port: u16) session.UdpEndpoint {
        return .{ .node_id = peer_id, .ip = ip, .port = port };
    }

    fn pruneStaleOutbounds(self: *Node, now_ms: u64) void {
        const ttl = self.outbound_opening_ttl_ms orelse return;
        var i: usize = 0;
        while (i < self.outbound.items.len) {
            if (now_ms -| self.outbound.items[i].created_ms > ttl) {
                _ = self.outbound.swapRemove(i);
            } else i += 1;
        }
    }

    fn pruneExpiredPending(self: *Node, now_ms: u64) void {
        const ttl = self.pending_challenge_ttl_ms orelse return;
        var i: usize = 0;
        while (i < self.pending.items.len) {
            if (now_ms -| self.pending.items[i].created_ms > ttl) {
                self.allocator.free(self.pending.items[i].challenge_data);
                if (self.pending.items[i].cached_initiator_record) |r| self.allocator.free(r);
                _ = self.pending.swapRemove(i);
            } else i += 1;
        }
    }

    fn evictOldestPending(self: *Node) void {
        if (self.pending.items.len == 0) return;
        var min_i: usize = 0;
        var min_t = self.pending.items[0].created_ms;
        for (self.pending.items[1..], 1..) |p, j| {
            if (p.created_ms < min_t) {
                min_t = p.created_ms;
                min_i = j;
            }
        }
        self.allocator.free(self.pending.items[min_i].challenge_data);
        if (self.pending.items[min_i].cached_initiator_record) |r| self.allocator.free(r);
        _ = self.pending.swapRemove(min_i);
    }

    fn clearPendingForPeer(self: *Node, peer_id: NodeId) void {
        var i: usize = 0;
        while (i < self.pending.items.len) {
            if (std.mem.eql(u8, &self.pending.items[i].peer_id, &peer_id)) {
                self.allocator.free(self.pending.items[i].challenge_data);
                if (self.pending.items[i].cached_initiator_record) |r| self.allocator.free(r);
                _ = self.pending.swapRemove(i);
            } else i += 1;
        }
    }

    fn takePending(self: *Node, peer_id: NodeId) ?TakenPending {
        var i: usize = 0;
        while (i < self.pending.items.len) {
            if (std.mem.eql(u8, &self.pending.items[i].peer_id, &peer_id)) {
                const p = self.pending.items[i];
                _ = self.pending.swapRemove(i);
                return .{
                    .challenge_data = p.challenge_data,
                    .cached_initiator_record = p.cached_initiator_record,
                };
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
        std.crypto.errors.IdentityElementError ||
        std.crypto.errors.NonCanonicalError ||
        ingress_limit.RateLimited ||
        error{ MissingHandshakePending, EmptyHandshakeRecord, EnrNodeIdMismatch, BadHandshakeSignatureLength, FindnodeResponseTooLarge };

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
        now_ms: u64,
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
            .created_ms = now_ms,
        });
        return pkt;
    }

    /// On success, each element of `responses_out` is an allocated reply packet; caller must free them.
    /// `now_ms` is application monotonic or wall time in milliseconds; used for session and pending-challenge TTL.
    pub fn handleReceive(
        self: *Node,
        remote: RemoteUdp,
        datagram: []const u8,
        responses_out: *std.ArrayList([]u8),
        now_ms: u64,
    ) ReceiveError!void {
        const alloc = self.allocator;

        self.pruneExpiredPending(now_ms);
        self.pruneStaleOutbounds(now_ms);

        self.ingress.recordInbound(alloc, ingressRateKey(remote), now_ms) catch |err| switch (err) {
            error.RateLimited => return error.RateLimited,
            else => |e| return e,
        };

        const copy = try alloc.dupe(u8, datagram);
        defer alloc.free(copy);

        const parsed = try packet.decodeInPlace(&self.node_id, copy);
        switch (parsed.header.flag) {
            .whoareyou => try self.handleWhoareyouAsInitiator(remote, copy, parsed, responses_out, now_ms),
            .message => try self.handleOrdinary(remote, copy, parsed, responses_out, now_ms),
            .handshake => try self.handleHandshake(remote, copy, parsed, responses_out, now_ms),
        }
    }

    fn handleWhoareyouAsInitiator(
        self: *Node,
        remote: RemoteUdp,
        _: []u8,
        parsed: packet.ParsedPacket,
        responses_out: *std.ArrayList([]u8),
        now_ms: u64,
    ) ReceiveError!void {
        const alloc = self.allocator;
        const o = self.takeOutboundByMessageNonce(parsed.header.nonce) orelse return;

        const auth = try parsed.decodeAuth();
        const way_enr_seq = switch (auth) {
            .whoareyou => |w| w.enr_seq,
            else => unreachable,
        };

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
        const omit_record = way_enr_seq != 0 and way_enr_seq == self.enr_seq;
        var record_owned: ?[]u8 = null;
        defer if (record_owned) |r| alloc.free(r);
        const record_slice: []const u8 = blk: {
            if (omit_record) break :blk &.{};
            const r = try buildMinimalEnrRlp(alloc, self.secret_key, pk_self, self.enr_seq);
            record_owned = r;
            break :blk r;
        };

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
            record_slice,
            &.{},
        );
        errdefer alloc.free(hs_pkt);

        const ep = self.makeEndpoint(o.peer_id, remote.ip, remote.port);
        try self.sessions.put(ep, session.CachedSession.fromDerived(keys), false, now_ms);
        errdefer _ = self.sessions.remove(ep);

        _ = try self.routing.add(o.peer_id);
        _ = self.routing.markPingReplied(o.peer_id);

        try responses_out.append(alloc, hs_pkt);
    }

    fn sendWhoareyouForUnknownOrdinary(
        self: *Node,
        src_id: NodeId,
        parsed: packet.ParsedPacket,
        responses_out: *std.ArrayList([]u8),
        now_ms: u64,
    ) ReceiveError!void {
        const alloc = self.allocator;

        self.clearPendingForPeer(src_id);

        while (self.pending.items.len >= self.pending_challenge_cap) {
            self.evictOldestPending();
        }

        var iv: [16]u8 = undefined;
        fillRandomBytes(&iv);
        var id_nonce: [16]u8 = undefined;
        fillRandomBytes(&id_nonce);

        var way_enr_seq: u64 = 0;
        var cached_dup: ?[]u8 = null;
        errdefer if (cached_dup) |s| alloc.free(s);
        if (self.peerRecordBytes(src_id)) |raw| {
            way_enr_seq = try enr.recordSequenceFromRaw(raw);
            cached_dup = try alloc.dupe(u8, raw);
        }

        const challenge = try packet.allocWhoareyouChallengeData(alloc, iv, parsed.header.nonce, id_nonce, way_enr_seq);
        errdefer alloc.free(challenge);

        self.pending.append(alloc, .{
            .peer_id = src_id,
            .challenge_data = challenge,
            .cached_initiator_record = cached_dup,
            .created_ms = now_ms,
        }) catch |err| {
            alloc.free(challenge);
            if (cached_dup) |s| alloc.free(s);
            return err;
        };
        cached_dup = null;

        errdefer {
            const last = self.pending.pop() orelse unreachable;
            alloc.free(last.challenge_data);
            if (last.cached_initiator_record) |r| alloc.free(r);
        }

        const way = try packet.encodeWhoareyouPacket(alloc, src_id, iv, parsed.header.nonce, id_nonce, way_enr_seq);
        errdefer alloc.free(way);

        try responses_out.append(alloc, way);
    }

    fn handleOrdinary(
        self: *Node,
        remote: RemoteUdp,
        copy: []u8,
        parsed: packet.ParsedPacket,
        responses_out: *std.ArrayList([]u8),
        now_ms: u64,
    ) ReceiveError!void {
        const alloc = self.allocator;
        const auth = try parsed.decodeAuth();
        const src_id = switch (auth) {
            .message => |m| m.src_id,
            else => unreachable,
        };
        const ep = self.makeEndpoint(src_id, remote.ip, remote.port);

        if (self.sessions.get(ep, now_ms)) |lu| {
            const read_key = if (lu.peer_handshake_initiator)
                lu.session.readKeyPeerWasInitiator()
            else
                lu.session.readKeyWeWereInitiator();

            const plain = message_crypto.decryptOrdinaryMessage(alloc, copy, &parsed, read_key) catch |err| {
                switch (err) {
                    error.DecryptFailed, error.CiphertextTooShort => {
                        _ = self.sessions.remove(ep);
                        try self.sendWhoareyouForUnknownOrdinary(src_id, parsed, responses_out, now_ms);
                        return;
                    },
                    else => return err,
                }
            };
            defer alloc.free(plain);

            var decoded = try message.decodePlaintext(plain, alloc);
            defer decoded.deinit(alloc);
            switch (decoded) {
                .ping => |p| {
                    const reply = try self.buildEncryptedPong(remote, ep, lu, p);
                    errdefer alloc.free(reply);
                    try responses_out.append(alloc, reply);
                },
                .pong => |p| {
                    self.consumeOutboundPingForPong(src_id, p.req_id);
                },
                .findnode => |f| {
                    if (!findnodeDistancesOk(f.distances)) return;
                    try self.appendFindnodeResponses(ep, lu, f.req_id, f.distances, responses_out);
                },
                .talkreq => |t| {
                    if (t.protocol.len == 0) return;
                    const resp_pt = try message.encodeTalkResponsePlaintext(alloc, t.req_id, t.message);
                    defer alloc.free(resp_pt);
                    const reply = try self.buildEncryptedOrdinaryReply(ep, lu, resp_pt);
                    errdefer alloc.free(reply);
                    try responses_out.append(alloc, reply);
                },
                else => {},
            }
            return;
        }

        try self.sendWhoareyouForUnknownOrdinary(src_id, parsed, responses_out, now_ms);
    }

    fn buildEncryptedOrdinaryReply(
        self: *Node,
        ep: session.UdpEndpoint,
        lu: session.SessionLookup,
        plaintext: []const u8,
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

        const ct = try message_crypto.encryptMessage(alloc, write_key, msg_nonce, plaintext, ad);
        defer alloc.free(ct);

        return packet.encodeOrdinaryMessagePacket(alloc, ep.node_id, iv, msg_nonce, self.node_id, ct);
    }

    fn buildEncryptedPong(
        self: *Node,
        remote: RemoteUdp,
        ep: session.UdpEndpoint,
        lu: session.SessionLookup,
        ping: message.Ping,
    ) ReceiveError![]u8 {
        const alloc = self.allocator;
        const ip_slice: []const u8 = switch (remote.ip) {
            .v4 => |a| &a,
            .v6 => |a| &a,
        };
        const pong_pt = try message.encodePongPlaintext(alloc, ping.req_id, self.enr_seq, ip_slice, remote.port);
        defer alloc.free(pong_pt);
        return self.buildEncryptedOrdinaryReply(ep, lu, pong_pt);
    }

    fn appendFindnodeResponses(
        self: *Node,
        ep: session.UdpEndpoint,
        lu: session.SessionLookup,
        req_id: []const u8,
        distances: []const u32,
        responses_out: *std.ArrayList([]u8),
    ) ReceiveError!void {
        const alloc = self.allocator;

        var id_candidates: std.ArrayList(NodeId) = .empty;
        defer id_candidates.deinit(alloc);
        try self.routing.appendNodesForLogDistances(distances, alloc, &id_candidates);

        var deduped: std.ArrayList(NodeId) = .empty;
        defer deduped.deinit(alloc);
        outer: for (id_candidates.items) |nid| {
            for (deduped.items) |e| {
                if (std.mem.eql(u8, &e, &nid)) continue :outer;
            }
            try deduped.append(alloc, nid);
        }

        var payloads: std.ArrayList([]const u8) = .empty;
        defer payloads.deinit(alloc);
        for (deduped.items) |nid| {
            if (self.peerRecordBytes(nid)) |raw| try payloads.append(alloc, raw);
        }

        const n = payloads.items.len;
        if (n == 0) {
            const pt = try message.encodeNodesPlaintext(alloc, req_id, 1, &[0][]const u8{});
            defer alloc.free(pt);
            const pkt = try self.buildEncryptedOrdinaryReply(ep, lu, pt);
            errdefer alloc.free(pkt);
            try responses_out.append(alloc, pkt);
            return;
        }

        const packet_count = (n + max_enrs_per_nodes_packet - 1) / max_enrs_per_nodes_packet;
        if (packet_count > 255) return error.FindnodeResponseTooLarge;
        const resp_count: u8 = @intCast(packet_count);

        var start: usize = 0;
        while (start < n) {
            const end = @min(start + max_enrs_per_nodes_packet, n);
            const slice = payloads.items[start..end];
            const pt = try message.encodeNodesPlaintext(alloc, req_id, resp_count, slice);
            defer alloc.free(pt);
            const pkt = try self.buildEncryptedOrdinaryReply(ep, lu, pt);
            errdefer alloc.free(pkt);
            try responses_out.append(alloc, pkt);
            start = end;
        }
    }

    fn handleHandshake(
        self: *Node,
        remote: RemoteUdp,
        copy: []u8,
        parsed: packet.ParsedPacket,
        responses_out: *std.ArrayList([]u8),
        now_ms: u64,
    ) ReceiveError!void {
        const alloc = self.allocator;
        const auth = try parsed.decodeAuth();
        const hs = switch (auth) {
            .handshake => |h| h,
            else => unreachable,
        };
        const initiator_id = hs.src_id;

        const pending = self.takePending(initiator_id) orelse return error.MissingHandshakePending;
        defer alloc.free(pending.challenge_data);
        defer if (pending.cached_initiator_record) |s| alloc.free(s);

        const record_bytes: []const u8 = if (hs.record.len > 0)
            hs.record
        else
            (pending.cached_initiator_record orelse return error.EmptyHandshakeRecord);
        if (record_bytes.len == 0) return error.EmptyHandshakeRecord;

        const rec = try enr.decodeRecordBytes(record_bytes);
        try enr.verifyV4RecordPayload(alloc, rec);
        const pk = try enr.compressedSecp256k1Pubkey(rec.pairs_payload);
        const enr_id = try identity_v4.nodeIdV4FromCompressedSec1(pk);
        if (!std.mem.eql(u8, &enr_id, &initiator_id)) return error.EnrNodeIdMismatch;

        if (hs.signature.len != 64) return error.BadHandshakeSignatureLength;
        const sig: [64]u8 = hs.signature[0..64].*;

        const eph: [33]u8 = hs.eph_pubkey[0..33].*;

        const ikm = try identity_v4.ecdhLocalSecret(eph, self.secret_key);

        const keys = handshake.deriveSessionKeys(&ikm, pending.challenge_data, initiator_id, self.node_id);
        try identity_v4.verifyIdentityProof(sig, pending.challenge_data, hs.eph_pubkey, self.node_id, pk);

        try self.rememberPeerRecord(initiator_id, record_bytes);

        const ep = self.makeEndpoint(initiator_id, remote.ip, remote.port);
        try self.sessions.put(ep, session.CachedSession.fromDerived(keys), true, now_ms);
        _ = try self.routing.add(initiator_id);
        _ = self.routing.markPingReplied(initiator_id);

        if (parsed.message_cipher.len == 0) return;

        const read_key = keys.initiator_key;
        const ad = message_crypto.messageAdditionalData(copy, &parsed);
        const plain = try message_crypto.decryptMessage(alloc, read_key, parsed.header.nonce, parsed.message_cipher, ad);
        defer alloc.free(plain);
        var decoded = try message.decodePlaintext(plain, alloc);
        defer decoded.deinit(alloc);
        switch (decoded) {
            .ping => |p| {
                const lu = self.sessions.get(ep, now_ms) orelse unreachable;
                const reply = try self.buildEncryptedPong(remote, ep, lu, p);
                errdefer alloc.free(reply);
                try responses_out.append(alloc, reply);
            },
            else => {},
        }
    }
};

fn findnodeDistancesOk(distances: []const u32) bool {
    if (distances.len == 0) return false;
    if (distances.len > max_findnode_distances) return false;
    for (distances) |d| {
        if (d > 255) return false;
    }
    return true;
}

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

fn buildMinimalEnrRlp(allocator: std.mem.Allocator, secret_key: [32]u8, compressed_pk: [33]u8, seq: u64) ![]u8 {
    const rlp_mod = @import("rlp.zig");
    const enr_mod = @import("enr.zig");
    var pairs: std.ArrayList(u8) = .empty;
    defer pairs.deinit(allocator);
    try rlp_mod.appendString(&pairs, allocator, "id");
    try rlp_mod.appendString(&pairs, allocator, "v4");
    try rlp_mod.appendString(&pairs, allocator, "secp256k1");
    try rlp_mod.appendString(&pairs, allocator, &compressed_pk);
    return try enr_mod.encodeV4RecordSigned(allocator, secret_key, seq, pairs.items);
}

test "handleReceive ingress per-peer cap" {
    const alloc = std.testing.allocator;

    var sk: [32]u8 = @splat(0);
    sk[31] = 3;
    var node_b = try Node.init(alloc, .{
        .secret_key = sk,
        .ingress = .{
            .per_peer_max_packets = 2,
            .per_peer_window_ms = 60_000,
            .global_max_packets = null,
        },
    });
    defer node_b.deinit();

    const remote: RemoteUdp = .{ .ip = .{ .v4 = .{ 203, 0, 113, 7 } }, .port = 7777 };
    var junk: [packet.min_packet_size]u8 = @splat(0xaa);

    var responses: std.ArrayList([]u8) = .empty;
    defer {
        for (responses.items) |s| alloc.free(s);
        responses.deinit(alloc);
    }

    try std.testing.expectError(error.InvalidProtocol, node_b.handleReceive(remote, &junk, &responses, 0));
    try std.testing.expectError(error.InvalidProtocol, node_b.handleReceive(remote, &junk, &responses, 1));
    try std.testing.expectError(error.RateLimited, node_b.handleReceive(remote, &junk, &responses, 2));
}

test "outbound opening handshake state expires" {
    const alloc = std.testing.allocator;

    var sk_a: [32]u8 = @splat(0);
    sk_a[31] = 41;
    var node_a = try Node.init(alloc, .{ .secret_key = sk_a, .outbound_opening_ttl_ms = 50 });
    defer node_a.deinit();

    var sk_b: [32]u8 = @splat(0);
    sk_b[31] = 43;
    const id_b = try identity_v4.nodeIdV4FromSecretKey(sk_b);
    const pk_b = try identity_v4.compressedPubkeyFromSecretKey(sk_b);
    const remote_b: RemoteUdp = .{ .ip = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 40000 };

    const pkt = try node_a.allocOpeningPingHandshake(id_b, pk_b, remote_b, &.{0xab}, 1, 0);
    defer alloc.free(pkt);
    try std.testing.expectEqual(@as(usize, 1), node_a.outbound.items.len);

    var junk: [packet.min_packet_size]u8 = @splat(0xbb);
    var responses: std.ArrayList([]u8) = .empty;
    defer {
        for (responses.items) |s| alloc.free(s);
        responses.deinit(alloc);
    }
    const r: RemoteUdp = .{ .ip = .{ .v4 = .{ 9, 9, 9, 9 } }, .port = 1 };
    try std.testing.expectError(error.InvalidProtocol, node_a.handleReceive(r, &junk, &responses, 100));
    try std.testing.expectEqual(@as(usize, 0), node_a.outbound.items.len);
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
    try node_b.handleReceive(remote, ordinary, &responses, 0);

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
    try node_b.sessions.put(ep, session.CachedSession.fromDerived(keys), true, 0);

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
    try node_b.handleReceive(remote, ordinary, &responses, 0);

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

test "inbound pong with registered req_id marks routing ping_replied" {
    const alloc = std.testing.allocator;

    var sk_b: [32]u8 = @splat(0);
    sk_b[31] = 11;
    var node_b = try Node.init(alloc, .{ .secret_key = sk_b });
    defer node_b.deinit();

    var sk_a: [32]u8 = @splat(0);
    sk_a[31] = 13;
    const id_a = try identity_v4.nodeIdV4FromSecretKey(sk_a);

    _ = try node_b.routing.add(id_a);
    try std.testing.expect(!node_b.routing.pingReplied(id_a));
    try node_b.registerOutboundPing(id_a, &.{ 0x99, 0x01 });

    const ikm = [_]u8{0x02} ++ [_]u8{0x33} ** 32;
    const challenge = [_]u8{0x77} ** (packet.static_prefix_size + packet.whoareyou_auth_size);
    const keys = handshake.deriveSessionKeys(&ikm, &challenge, id_a, node_b.node_id);

    const ep = node_b.makeEndpoint(id_a, .{ .v4 = .{ 192, 168, 1, 20 } }, 9000);
    try node_b.sessions.put(ep, session.CachedSession.fromDerived(keys), true, 0);

    const remote: RemoteUdp = .{ .ip = ep.ip, .port = ep.port };
    const ip_slice: []const u8 = switch (remote.ip) {
        .v4 => |a| &a,
        .v6 => |a| &a,
    };

    var iv: [16]u8 = undefined;
    @memset(&iv, 0x2f);
    var nonce: [12]u8 = undefined;
    @memset(&nonce, 0x4a);

    const pong_pt = try message.encodePongPlaintext(alloc, &.{ 0x99, 0x01 }, 0, ip_slice, remote.port);
    defer alloc.free(pong_pt);

    var prefix: [packet.static_prefix_size + packet.message_auth_size]u8 = undefined;
    @memcpy(prefix[0..16], &iv);
    var static_plain: [packet.static_header_size]u8 = undefined;
    packet.writePlaintextStaticHeader(&static_plain, .message, nonce, packet.message_auth_size);
    @memcpy(prefix[16..][0..packet.static_header_size], &static_plain);
    @memcpy(prefix[packet.static_prefix_size..][0..packet.message_auth_size], &id_a);

    const ct = try message_crypto.encryptMessage(alloc, keys.initiator_key, nonce, pong_pt, &prefix);
    defer alloc.free(ct);

    const ordinary = try packet.encodeOrdinaryMessagePacket(alloc, node_b.node_id, iv, nonce, id_a, ct);
    defer alloc.free(ordinary);

    var responses: std.ArrayList([]u8) = .empty;
    defer {
        for (responses.items) |s| alloc.free(s);
        responses.deinit(alloc);
    }

    try node_b.handleReceive(remote, ordinary, &responses, 0);
    try std.testing.expectEqual(@as(usize, 0), responses.items.len);
    try std.testing.expect(node_b.routing.pingReplied(id_a));
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
    try node_b.handleReceive(remote, ordinary, &responses, 0);
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

    const record = try buildMinimalEnrRlp(alloc, sk_a, pk_a, 1);
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

    try node_b.handleReceive(remote, hs_pkt, &responses, 0);
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

    const ordinary = try node_a.allocOpeningPingHandshake(id_b, pk_b, remote_b, &.{ 0xca, 0xfe }, 9, 0);
    defer alloc.free(ordinary);

    var from_b: std.ArrayList([]u8) = .empty;
    defer {
        for (from_b.items) |s| alloc.free(s);
        from_b.deinit(alloc);
    }
    try node_b.handleReceive(remote_a, ordinary, &from_b, 0);
    try std.testing.expectEqual(@as(usize, 1), from_b.items.len);
    const way = from_b.items[0];

    var from_a: std.ArrayList([]u8) = .empty;
    defer {
        for (from_a.items) |s| alloc.free(s);
        from_a.deinit(alloc);
    }
    try node_a.handleReceive(remote_b, way, &from_a, 0);
    try std.testing.expectEqual(@as(usize, 1), from_a.items.len);
    const hs = from_a.items[0];

    for (from_b.items) |s| alloc.free(s);
    from_b.clearRetainingCapacity();

    try node_b.handleReceive(remote_a, hs, &from_b, 0);
    try std.testing.expectEqual(@as(usize, 0), from_b.items.len);

    const ep_on_a = node_a.makeEndpoint(id_b, remote_b.ip, remote_b.port);
    const ep_on_b = node_b.makeEndpoint(id_a, remote_a.ip, remote_a.port);
    const lu_a = node_a.sessions.get(ep_on_a, 0) orelse unreachable;
    const lu_b = node_b.sessions.get(ep_on_b, 0) orelse unreachable;
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
    try node_b.handleReceive(remote_a, ordinary2, &from_b2, 0);
    try std.testing.expectEqual(@as(usize, 1), from_b2.items.len);

    const pong_copy = try alloc.dupe(u8, from_b2.items[0]);
    defer alloc.free(pong_copy);
    const parsed_pong = try packet.decodeInPlace(&id_a, pong_copy);
    const read_key = lu_a.session.readKeyWeWereInitiator();
    const plain = try message_crypto.decryptOrdinaryMessage(alloc, pong_copy, &parsed_pong, read_key);
    defer alloc.free(plain);
    const msg2 = try message.decodePlaintext(plain, alloc);
    defer msg2.deinit(alloc);
    try std.testing.expect(msg2 == .pong);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, msg2.pong.req_id);
}

test "initiator omits handshake record when WHOAREYOU enr-seq matches cached seq" {
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

    const ordinary1 = try node_a.allocOpeningPingHandshake(id_b, pk_b, remote_b, &.{0x10}, 9, 0);
    defer alloc.free(ordinary1);

    var from_b: std.ArrayList([]u8) = .empty;
    defer {
        for (from_b.items) |s| alloc.free(s);
        from_b.deinit(alloc);
    }
    try node_b.handleReceive(remote_a, ordinary1, &from_b, 0);
    try std.testing.expectEqual(@as(usize, 1), from_b.items.len);
    const way1 = from_b.items[0];

    var from_a: std.ArrayList([]u8) = .empty;
    defer {
        for (from_a.items) |s| alloc.free(s);
        from_a.deinit(alloc);
    }
    try node_a.handleReceive(remote_b, way1, &from_a, 0);
    try std.testing.expectEqual(@as(usize, 1), from_a.items.len);
    const hs1 = from_a.items[0];

    const hs1_copy = try alloc.dupe(u8, hs1);
    defer alloc.free(hs1_copy);
    const parsed_hs1 = try packet.decodeInPlace(&id_b, hs1_copy);
    const auth1 = try parsed_hs1.decodeAuth();
    const h1 = switch (auth1) {
        .handshake => |h| h,
        else => unreachable,
    };
    try std.testing.expect(h1.record.len > 0);

    for (from_b.items) |s| alloc.free(s);
    from_b.clearRetainingCapacity();

    try node_b.handleReceive(remote_a, hs1, &from_b, 0);

    const ep_on_a = node_a.makeEndpoint(id_b, remote_b.ip, remote_b.port);
    const ep_on_b = node_b.makeEndpoint(id_a, remote_a.ip, remote_a.port);
    _ = node_a.sessions.remove(ep_on_a);
    _ = node_b.sessions.remove(ep_on_b);

    const ordinary2 = try node_a.allocOpeningPingHandshake(id_b, pk_b, remote_b, &.{0x20}, 1, 0);
    defer alloc.free(ordinary2);

    for (from_b.items) |s| alloc.free(s);
    from_b.clearRetainingCapacity();
    try node_b.handleReceive(remote_a, ordinary2, &from_b, 0);
    try std.testing.expectEqual(@as(usize, 1), from_b.items.len);
    const way2 = from_b.items[0];

    const way2_copy = try alloc.dupe(u8, way2);
    defer alloc.free(way2_copy);
    const parsed_way2 = try packet.decodeInPlace(&id_a, way2_copy);
    const way_auth = try parsed_way2.decodeAuth();
    const way_body = switch (way_auth) {
        .whoareyou => |w| w,
        else => unreachable,
    };
    try std.testing.expectEqual(@as(u64, 2), way_body.enr_seq);

    for (from_a.items) |s| alloc.free(s);
    from_a.clearRetainingCapacity();
    try node_a.handleReceive(remote_b, way2, &from_a, 0);
    try std.testing.expectEqual(@as(usize, 1), from_a.items.len);
    const hs2 = from_a.items[0];

    const hs2_copy = try alloc.dupe(u8, hs2);
    defer alloc.free(hs2_copy);
    const parsed_hs2 = try packet.decodeInPlace(&id_b, hs2_copy);
    const auth2 = try parsed_hs2.decodeAuth();
    const h2 = switch (auth2) {
        .handshake => |h| h,
        else => unreachable,
    };
    try std.testing.expectEqual(@as(usize, 0), h2.record.len);

    for (from_b.items) |s| alloc.free(s);
    from_b.clearRetainingCapacity();

    try node_b.handleReceive(remote_a, hs2, &from_b, 0);
    try std.testing.expectEqual(@as(usize, 0), from_b.items.len);

    try std.testing.expect(node_a.sessions.get(ep_on_a, 0) != null);
    try std.testing.expect(node_b.sessions.get(ep_on_b, 0) != null);
}

test "session findnode returns encrypted nodes for cached peer enrs" {
    const alloc = std.testing.allocator;

    var sk_b: [32]u8 = @splat(0);
    sk_b[31] = 17;
    var node_b = try Node.init(alloc, .{ .secret_key = sk_b });
    defer node_b.deinit();

    var sk_a: [32]u8 = @splat(0);
    sk_a[31] = 19;
    const id_a = try identity_v4.nodeIdV4FromSecretKey(sk_a);

    var id_c: NodeId = @splat(0);
    id_c[0] = 0x80;
    const d = routing.logDistance(node_b.node_id, id_c).?;
    _ = try node_b.routing.add(id_c);
    try std.testing.expect(node_b.routing.markPingReplied(id_c));
    try node_b.rememberPeerRecord(id_c, &.{ 0xde, 0xad, 0xbe, 0xef });

    const ikm = [_]u8{0x0c} ++ [_]u8{0x44} ** 32;
    const challenge = [_]u8{0x88} ** (packet.static_prefix_size + packet.whoareyou_auth_size);
    const keys = handshake.deriveSessionKeys(&ikm, &challenge, id_a, node_b.node_id);

    const ep = node_b.makeEndpoint(id_a, .{ .v4 = .{ 172, 16, 0, 5 } }, 30305);
    try node_b.sessions.put(ep, session.CachedSession.fromDerived(keys), true, 0);

    var iv: [16]u8 = undefined;
    @memset(&iv, 0x4d);
    var nonce: [12]u8 = undefined;
    @memset(&nonce, 0x2e);

    const fn_pt = try message.encodeFindnodePlaintext(alloc, &.{0x9c}, &[_]u32{d});
    defer alloc.free(fn_pt);

    var prefix: [packet.static_prefix_size + packet.message_auth_size]u8 = undefined;
    @memcpy(prefix[0..16], &iv);
    var static_plain: [packet.static_header_size]u8 = undefined;
    packet.writePlaintextStaticHeader(&static_plain, .message, nonce, packet.message_auth_size);
    @memcpy(prefix[16..][0..packet.static_header_size], &static_plain);
    @memcpy(prefix[packet.static_prefix_size..][0..packet.message_auth_size], &id_a);

    const ct = try message_crypto.encryptMessage(alloc, keys.initiator_key, nonce, fn_pt, &prefix);
    defer alloc.free(ct);

    const ordinary = try packet.encodeOrdinaryMessagePacket(alloc, node_b.node_id, iv, nonce, id_a, ct);
    defer alloc.free(ordinary);

    var responses: std.ArrayList([]u8) = .empty;
    defer {
        for (responses.items) |s| alloc.free(s);
        responses.deinit(alloc);
    }

    const remote: RemoteUdp = .{ .ip = ep.ip, .port = ep.port };
    try node_b.handleReceive(remote, ordinary, &responses, 0);

    try std.testing.expectEqual(@as(usize, 1), responses.items.len);

    const wire = try alloc.dupe(u8, responses.items[0]);
    defer alloc.free(wire);
    const parsed = try packet.decodeInPlace(&id_a, wire);
    const plain = try message_crypto.decryptOrdinaryMessage(alloc, wire, &parsed, keys.recipient_key);
    defer alloc.free(plain);
    var dec = try message.decodePlaintext(plain, alloc);
    defer dec.deinit(alloc);
    try std.testing.expect(dec == .nodes);
    try std.testing.expectEqual(@as(u8, 1), dec.nodes.resp_count);
    try std.testing.expectEqual(@as(usize, 1), dec.nodes.enr_records.len);
    try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, dec.nodes.enr_records[0]);
}

test "session talkreq yields talkresp echoing message payload" {
    const alloc = std.testing.allocator;

    var sk_b: [32]u8 = @splat(0);
    sk_b[31] = 23;
    var node_b = try Node.init(alloc, .{ .secret_key = sk_b });
    defer node_b.deinit();

    var sk_a: [32]u8 = @splat(0);
    sk_a[31] = 29;
    const id_a = try identity_v4.nodeIdV4FromSecretKey(sk_a);

    const ikm = [_]u8{0x0d} ++ [_]u8{0x55} ** 32;
    const challenge = [_]u8{0x99} ** (packet.static_prefix_size + packet.whoareyou_auth_size);
    const keys = handshake.deriveSessionKeys(&ikm, &challenge, id_a, node_b.node_id);

    const ep = node_b.makeEndpoint(id_a, .{ .v4 = .{ 192, 0, 2, 3 } }, 40443);
    try node_b.sessions.put(ep, session.CachedSession.fromDerived(keys), true, 0);

    var iv: [16]u8 = undefined;
    @memset(&iv, 0x71);
    var nonce: [12]u8 = undefined;
    @memset(&nonce, 0x82);

    const tq = try message.encodeTalkRequestPlaintext(alloc, &.{ 0x01, 0x02 }, "eth/66", "hello");
    defer alloc.free(tq);

    var prefix: [packet.static_prefix_size + packet.message_auth_size]u8 = undefined;
    @memcpy(prefix[0..16], &iv);
    var static_plain: [packet.static_header_size]u8 = undefined;
    packet.writePlaintextStaticHeader(&static_plain, .message, nonce, packet.message_auth_size);
    @memcpy(prefix[16..][0..packet.static_header_size], &static_plain);
    @memcpy(prefix[packet.static_prefix_size..][0..packet.message_auth_size], &id_a);

    const ct = try message_crypto.encryptMessage(alloc, keys.initiator_key, nonce, tq, &prefix);
    defer alloc.free(ct);

    const ordinary = try packet.encodeOrdinaryMessagePacket(alloc, node_b.node_id, iv, nonce, id_a, ct);
    defer alloc.free(ordinary);

    var responses: std.ArrayList([]u8) = .empty;
    defer {
        for (responses.items) |s| alloc.free(s);
        responses.deinit(alloc);
    }

    const remote: RemoteUdp = .{ .ip = ep.ip, .port = ep.port };
    try node_b.handleReceive(remote, ordinary, &responses, 0);

    try std.testing.expectEqual(@as(usize, 1), responses.items.len);

    const wire = try alloc.dupe(u8, responses.items[0]);
    defer alloc.free(wire);
    const parsed = try packet.decodeInPlace(&id_a, wire);
    const plain = try message_crypto.decryptOrdinaryMessage(alloc, wire, &parsed, keys.recipient_key);
    defer alloc.free(plain);
    var dec = try message.decodePlaintext(plain, alloc);
    defer dec.deinit(alloc);
    try std.testing.expect(dec == .talkresp);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, dec.talkresp.req_id);
    try std.testing.expectEqualSlices(u8, "hello", dec.talkresp.response);
}

test "decrypt failure with cached session drops session and sends WHOAREYOU" {
    const alloc = std.testing.allocator;

    var sk_b: [32]u8 = @splat(0);
    sk_b[31] = 41;
    var node_b = try Node.init(alloc, .{ .secret_key = sk_b });
    defer node_b.deinit();

    var sk_a: [32]u8 = @splat(0);
    sk_a[31] = 43;
    const id_a = try identity_v4.nodeIdV4FromSecretKey(sk_a);

    const ikm = [_]u8{0x0e} ++ [_]u8{0x66} ** 32;
    const challenge = [_]u8{0xaa} ** (packet.static_prefix_size + packet.whoareyou_auth_size);
    const keys = handshake.deriveSessionKeys(&ikm, &challenge, id_a, node_b.node_id);

    const ep = node_b.makeEndpoint(id_a, .{ .v4 = .{ 10, 1, 2, 3 } }, 9001);
    try node_b.sessions.put(ep, session.CachedSession.fromDerived(keys), true, 0);

    var iv: [16]u8 = undefined;
    @memset(&iv, 0x81);
    var nonce: [12]u8 = undefined;
    @memset(&nonce, 0x92);

    const ping_pt = try message.encodePingPlaintext(alloc, &.{0xef}, 1);
    defer alloc.free(ping_pt);

    var prefix: [packet.static_prefix_size + packet.message_auth_size]u8 = undefined;
    @memcpy(prefix[0..16], &iv);
    var static_plain: [packet.static_header_size]u8 = undefined;
    packet.writePlaintextStaticHeader(&static_plain, .message, nonce, packet.message_auth_size);
    @memcpy(prefix[16..][0..packet.static_header_size], &static_plain);
    @memcpy(prefix[packet.static_prefix_size..][0..packet.message_auth_size], &id_a);

    const ct = try message_crypto.encryptMessage(alloc, keys.recipient_key, nonce, ping_pt, &prefix);
    defer alloc.free(ct);

    const ordinary = try packet.encodeOrdinaryMessagePacket(alloc, node_b.node_id, iv, nonce, id_a, ct);
    defer alloc.free(ordinary);

    var responses: std.ArrayList([]u8) = .empty;
    defer {
        for (responses.items) |s| alloc.free(s);
        responses.deinit(alloc);
    }

    const remote: RemoteUdp = .{ .ip = ep.ip, .port = ep.port };
    try node_b.handleReceive(remote, ordinary, &responses, 0);

    try std.testing.expectEqual(@as(usize, 1), responses.items.len);
    const way_copy = try alloc.dupe(u8, responses.items[0]);
    defer alloc.free(way_copy);
    const parsed = try packet.decodeInPlace(&id_a, way_copy);
    try std.testing.expect(parsed.header.flag == .whoareyou);
    try std.testing.expect(node_b.sessions.get(ep, 0) == null);
}

test "session TTL expiry treats next ordinary as unknown session" {
    const alloc = std.testing.allocator;

    var sk_b: [32]u8 = @splat(0);
    sk_b[31] = 47;
    var node_b = try Node.init(alloc, .{ .secret_key = sk_b, .session_ttl_ms = 1000 });
    defer node_b.deinit();

    var sk_a: [32]u8 = @splat(0);
    sk_a[31] = 53;
    const id_a = try identity_v4.nodeIdV4FromSecretKey(sk_a);

    const ikm = [_]u8{0x0f} ++ [_]u8{0x77} ** 32;
    const challenge = [_]u8{0xbb} ** (packet.static_prefix_size + packet.whoareyou_auth_size);
    const keys = handshake.deriveSessionKeys(&ikm, &challenge, id_a, node_b.node_id);

    const ep = node_b.makeEndpoint(id_a, .{ .v4 = .{ 10, 2, 3, 4 } }, 9002);
    const t_establish: u64 = 1_000_000;
    try node_b.sessions.put(ep, session.CachedSession.fromDerived(keys), true, t_establish);

    var iv: [16]u8 = undefined;
    @memset(&iv, 0x93);
    var nonce: [12]u8 = undefined;
    @memset(&nonce, 0xa4);

    const ping_pt = try message.encodePingPlaintext(alloc, &.{0xfe}, 2);
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
    const t_late = t_establish + 1001;
    try node_b.handleReceive(remote, ordinary, &responses, t_late);

    try std.testing.expectEqual(@as(usize, 1), responses.items.len);
    const way_copy = try alloc.dupe(u8, responses.items[0]);
    defer alloc.free(way_copy);
    const parsed = try packet.decodeInPlace(&id_a, way_copy);
    try std.testing.expect(parsed.header.flag == .whoareyou);
}
