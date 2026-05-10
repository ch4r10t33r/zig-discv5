//! Sliding-window counters for inbound datagrams (per peer key and global).
//! Peer keys are opaque **u64**s (e.g. IPv4 host+port); see **Node** for encoding.
//! Applied before crypto decode so cheap bogus traffic still consumes quota.

const std = @import("std");

pub const RateLimited = error{RateLimited};

pub const Config = struct {
    /// Max datagrams per peer key per window. Null disables.
    per_peer_max_packets: ?u32 = null,
    per_peer_window_ms: u64 = 1000,
    /// Max datagrams from all peers combined per window. Null disables.
    global_max_packets: ?u32 = null,
    global_window_ms: u64 = 1000,
    /// Max distinct peer keys tracked; LRU by **last_seen_ms** when full.
    peer_table_cap: usize = 4096,
};

const PeerRec = struct {
    count: u32,
    window_start: u64,
    last_seen_ms: u64,
};

pub const IngressLimiter = struct {
    cfg: Config,
    global_window_start: u64 = 0,
    global_count: u32 = 0,
    peers: std.AutoHashMapUnmanaged(u64, PeerRec) = .{},

    pub fn init(cfg: Config) IngressLimiter {
        return .{ .cfg = cfg };
    }

    pub fn deinit(self: *IngressLimiter, allocator: std.mem.Allocator) void {
        self.peers.deinit(allocator);
        self.* = undefined;
    }

    fn resetGlobalWindow(self: *IngressLimiter, now_ms: u64) void {
        self.global_count = 0;
        self.global_window_start = now_ms;
    }

    fn touchGlobal(self: *IngressLimiter, now_ms: u64) RateLimited!void {
        const max = self.cfg.global_max_packets orelse return;
        const win = self.cfg.global_window_ms;
        if (win == 0) return error.RateLimited;

        if (self.global_count == 0) {
            self.global_window_start = now_ms;
        } else if (now_ms -| self.global_window_start >= win) {
            self.resetGlobalWindow(now_ms);
        }

        if (self.global_count >= max) return error.RateLimited;
        self.global_count += 1;
    }

    fn evictOldestPeer(self: *IngressLimiter) void {
        if (self.peers.count() == 0) return;
        var worst_k: u64 = 0;
        var worst_t: u64 = std.math.maxInt(u64);
        var it = self.peers.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.last_seen_ms < worst_t) {
                worst_t = e.value_ptr.last_seen_ms;
                worst_k = e.key_ptr.*;
            }
        }
        _ = self.peers.remove(worst_k);
    }

    fn touchPeer(self: *IngressLimiter, allocator: std.mem.Allocator, key: u64, now_ms: u64) (RateLimited || std.mem.Allocator.Error)!void {
        const max = self.cfg.per_peer_max_packets orelse return;
        const win = self.cfg.per_peer_window_ms;
        if (win == 0) return error.RateLimited;

        const is_new = !self.peers.contains(key);
        if (is_new and self.peers.count() >= self.cfg.peer_table_cap) {
            self.evictOldestPeer();
        }

        const gop = try self.peers.getOrPut(allocator, key);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .count = 0,
                .window_start = now_ms,
                .last_seen_ms = now_ms,
            };
        }
        const rec = gop.value_ptr;

        rec.last_seen_ms = now_ms;

        if (rec.count == 0) {
            rec.window_start = now_ms;
        } else if (now_ms -| rec.window_start >= win) {
            rec.count = 0;
            rec.window_start = now_ms;
        }

        if (rec.count >= max) return error.RateLimited;
        rec.count += 1;
    }

    /// Count this inbound datagram. Fails with **error.RateLimited** if a cap is exceeded.
    pub fn recordInbound(
        self: *IngressLimiter,
        allocator: std.mem.Allocator,
        peer_key: u64,
        now_ms: u64,
    ) (RateLimited || std.mem.Allocator.Error)!void {
        const any_peer = self.cfg.per_peer_max_packets != null;
        const any_global = self.cfg.global_max_packets != null;
        if (!any_peer and !any_global) return;

        if (any_global) try self.touchGlobal(now_ms);
        if (any_peer) try self.touchPeer(allocator, peer_key, now_ms);
    }
};

test "ingress global window" {
    const alloc = std.testing.allocator;
    var lim = IngressLimiter.init(.{
        .global_max_packets = 2,
        .global_window_ms = 1000,
        .per_peer_max_packets = null,
    });
    defer lim.deinit(alloc);

    try lim.recordInbound(alloc, 1, 0);
    try lim.recordInbound(alloc, 2, 0);
    try std.testing.expectError(error.RateLimited, lim.recordInbound(alloc, 3, 0));
    try lim.recordInbound(alloc, 1, 1000);
}

test "ingress per-peer window" {
    const alloc = std.testing.allocator;
    var lim = IngressLimiter.init(.{
        .per_peer_max_packets = 2,
        .per_peer_window_ms = 500,
        .global_max_packets = null,
        .peer_table_cap = 8,
    });
    defer lim.deinit(alloc);

    const ka: u64 = 0x0100007f_3030; // arbitrary distinct keys
    const kb: u64 = 0x0200007f_3030;
    try lim.recordInbound(alloc, ka, 0);
    try lim.recordInbound(alloc, ka, 0);
    try std.testing.expectError(error.RateLimited, lim.recordInbound(alloc, ka, 0));
    try lim.recordInbound(alloc, kb, 0);
    try lim.recordInbound(alloc, kb, 0);
    try lim.recordInbound(alloc, ka, 500);
}
