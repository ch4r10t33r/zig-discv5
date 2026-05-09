//! In-memory session cache and outbound nonce layout per [discv5-theory](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-theory.md)
//! (session cache, AES-GCM nonce guidance).

const std = @import("std");
const handshake = @import("handshake.zig");

pub const InitError = error{ZeroCapacity};

pub const IpAddr = union(enum) {
    v4: [4]u8,
    v6: [16]u8,
};

/// Remote peer identity plus UDP endpoint. Used as the session cache key (node id and IP/port).
pub const UdpEndpoint = struct {
    node_id: [32]u8,
    ip: IpAddr,
    /// Port in host byte order; use the same convention as your socket layer when looking up sessions.
    port: u16,

    pub fn eql(a: UdpEndpoint, b: UdpEndpoint) bool {
        if (!std.mem.eql(u8, &a.node_id, &b.node_id) or a.port != b.port) return false;
        return switch (a.ip) {
            .v4 => |va| switch (b.ip) {
                .v4 => |vb| std.mem.eql(u8, &va, &vb),
                .v6 => false,
            },
            .v6 => |va| switch (b.ip) {
                .v6 => |vb| std.mem.eql(u8, &va, &vb),
                .v4 => false,
            },
        };
    }
};

/// AES-128 session halves from **handshake.deriveSessionKeys** plus an outbound message counter for nonces.
pub const CachedSession = struct {
    initiator_key: [16]u8,
    recipient_key: [16]u8,
    outbound_nonce_counter: u32 = 0,

    pub fn fromDerived(derived: handshake.SessionKeys) CachedSession {
        return .{
            .initiator_key = derived.initiator_key,
            .recipient_key = derived.recipient_key,
            .outbound_nonce_counter = 0,
        };
    }

    pub fn readKeyPeerWasInitiator(self: *const CachedSession) [16]u8 {
        return self.initiator_key;
    }

    pub fn writeKeyPeerWasInitiator(self: *const CachedSession) [16]u8 {
        return self.recipient_key;
    }

    pub fn readKeyWeWereInitiator(self: *const CachedSession) [16]u8 {
        return self.recipient_key;
    }

    pub fn writeKeyWeWereInitiator(self: *const CachedSession) [16]u8 {
        return self.initiator_key;
    }

    /// Writes the next 12-byte GCM nonce and increments the counter (wrapping add).
    /// First four bytes are **big-endian** `outbound_nonce_counter` before the increment; last eight are `random_suffix`.
    pub fn nextMessageNonce(self: *CachedSession, random_suffix: [8]u8) [12]u8 {
        const idx = self.outbound_nonce_counter;
        self.outbound_nonce_counter +%= 1;
        return encodeMessageNonce(idx, random_suffix);
    }
};

/// 96-bit AES-GCM nonce: outbound message index (big-endian) || 64 random bits (discv5-theory recommendation).
pub fn encodeMessageNonce(outbound_index: u32, random_suffix: [8]u8) [12]u8 {
    var n: [12]u8 = undefined;
    std.mem.writeInt(u32, n[0..4], outbound_index, .big);
    @memcpy(n[4..12], &random_suffix);
    return n;
}

const Entry = struct {
    ep: UdpEndpoint,
    session: CachedSession,
    peer_handshake_initiator: bool,
    last_touch: u64,
};

pub const SessionLookup = struct {
    session: *CachedSession,
    peer_handshake_initiator: bool,
};

/// Bounded LRU table: least-recently touched entry is replaced when full.
pub const SessionTable = struct {
    allocator: std.mem.Allocator,
    max_entries: usize,
    entries: std.ArrayList(Entry),
    clock: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) InitError!SessionTable {
        if (max_entries == 0) return error.ZeroCapacity;
        return .{
            .allocator = allocator,
            .max_entries = max_entries,
            .entries = .empty,
        };
    }

    pub fn deinit(self: *SessionTable) void {
        self.entries.deinit(self.allocator);
    }

    fn bump(self: *SessionTable) u64 {
        self.clock += 1;
        return self.clock;
    }

    /// Inserts or updates a session for `ep`.
    pub fn put(
        self: *SessionTable,
        ep: UdpEndpoint,
        sess: CachedSession,
        peer_handshake_initiator: bool,
    ) std.mem.Allocator.Error!void {
        for (self.entries.items) |*e| {
            if (ep.eql(e.ep)) {
                e.session = sess;
                e.peer_handshake_initiator = peer_handshake_initiator;
                e.last_touch = self.bump();
                return;
            }
        }

        const touch = self.bump();
        if (self.entries.items.len < self.max_entries) {
            try self.entries.append(self.allocator, .{
                .ep = ep,
                .session = sess,
                .peer_handshake_initiator = peer_handshake_initiator,
                .last_touch = touch,
            });
            return;
        }

        var min_i: usize = 0;
        var min_t = self.entries.items[0].last_touch;
        for (self.entries.items[1..], 1..) |e, j| {
            if (e.last_touch < min_t) {
                min_t = e.last_touch;
                min_i = j;
            }
        }
        self.entries.items[min_i] = .{
            .ep = ep,
            .session = sess,
            .peer_handshake_initiator = peer_handshake_initiator,
            .last_touch = touch,
        };
    }

    /// Returns the session for `ep` after marking it most-recently used, or `null`.
    pub fn get(self: *SessionTable, ep: UdpEndpoint) ?SessionLookup {
        for (self.entries.items) |*e| {
            if (ep.eql(e.ep)) {
                e.last_touch = self.bump();
                return .{
                    .session = &e.session,
                    .peer_handshake_initiator = e.peer_handshake_initiator,
                };
            }
        }
        return null;
    }

    /// Removes the entry for `ep`. Returns whether it existed.
    pub fn remove(self: *SessionTable, ep: UdpEndpoint) bool {
        for (self.entries.items, 0..) |e, i| {
            if (ep.eql(e.ep)) {
                _ = self.entries.swapRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn count(self: *const SessionTable) usize {
        return self.entries.items.len;
    }
};

test "encodeMessageNonce layout" {
    const n = encodeMessageNonce(0x01020304, [_]u8{9} ** 8);
    try std.testing.expectEqual(@as(u8, 0x01), n[0]);
    try std.testing.expectEqual(@as(u8, 0x02), n[1]);
    try std.testing.expectEqual(@as(u8, 0x03), n[2]);
    try std.testing.expectEqual(@as(u8, 0x04), n[3]);
    try std.testing.expectEqualSlices(u8, &([_]u8{9} ** 8), n[4..12]);
}

test "CachedSession nonce sequence" {
    var s = CachedSession{
        .initiator_key = @splat(0),
        .recipient_key = @splat(0),
        .outbound_nonce_counter = 0,
    };
    const r = [_]u8{0} ** 8;
    const a = s.nextMessageNonce(r);
    const b = s.nextMessageNonce(r);
    try std.testing.expect(a[3] != b[3] or a[2] != b[2] or a[1] != b[1] or a[0] != b[0]);
    try std.testing.expectEqual(@as(u32, 2), s.outbound_nonce_counter);
}

test "SessionTable LRU eviction" {
    const alloc = std.testing.allocator;
    var t = try SessionTable.init(alloc, 2);
    defer t.deinit();

    const ep_a: UdpEndpoint = .{
        .node_id = @splat(1),
        .ip = .{ .v4 = .{ 127, 0, 0, 1 } },
        .port = 30303,
    };
    const ep_b: UdpEndpoint = .{
        .node_id = @splat(2),
        .ip = .{ .v4 = .{ 127, 0, 0, 2 } },
        .port = 30303,
    };
    const ep_c: UdpEndpoint = .{
        .node_id = @splat(3),
        .ip = .{ .v4 = .{ 127, 0, 0, 3 } },
        .port = 30303,
    };

    const sa = CachedSession{ .initiator_key = @splat(0xaa), .recipient_key = @splat(0), .outbound_nonce_counter = 0 };
    const sb = CachedSession{ .initiator_key = @splat(0xbb), .recipient_key = @splat(0), .outbound_nonce_counter = 0 };
    const sc = CachedSession{ .initiator_key = @splat(0xcc), .recipient_key = @splat(0), .outbound_nonce_counter = 0 };

    try t.put(ep_a, sa, false);
    try t.put(ep_b, sb, false);
    try std.testing.expectEqual(@as(usize, 2), t.count());

    _ = t.get(ep_a);
    try t.put(ep_c, sc, false);

    try std.testing.expect(t.get(ep_a) != null);
    try std.testing.expect(t.get(ep_c) != null);
    try std.testing.expect(t.get(ep_b) == null);

    try std.testing.expect(t.remove(ep_a));
    try std.testing.expectEqual(@as(usize, 1), t.count());
}

test "fromDerived" {
    const d = handshake.SessionKeys{ .initiator_key = @splat(7), .recipient_key = @splat(8) };
    var c = CachedSession.fromDerived(d);
    try std.testing.expectEqualSlices(u8, &d.initiator_key, &c.initiator_key);
    _ = c.nextMessageNonce([_]u8{0} ** 8);
    try std.testing.expectEqual(@as(u32, 1), c.outbound_nonce_counter);
}
