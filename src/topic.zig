//! Topic advertisement data structures per [discv5-theory](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-theory.md)
//! (topic table, FIFO topic queues, registration throttling).
//!
//! Wire messages for topics (REGTOPIC, TICKET, …) are non-final; inbound decode is gated by the
//! `experimental_topic_wire` build option in `message.zig` / `wire.zig`.

const std = @import("std");
const routing = @import("routing.zig");

pub const NodeId = routing.NodeId;
/// 32-byte topic identifier as used on the wire (TOPICQUERY).
pub const TopicHash = [32]u8;

/// How long an ad should remain in a queue before the slot is recycled (`target-ad-lifetime` in the spec).
pub const target_ad_lifetime_secs: u64 = 15 * 60;

/// Suggested default from discv5-theory (implementation-defined).
pub const default_queue_ad_limit: usize = 100;
/// Suggested global cap from discv5-theory.
pub const default_global_ad_limit: usize = 50_000;

pub const RegisterError = error{
    /// The advertiser is already present in this topic queue.
    DuplicateAdvertiser,
};

pub const RegisterOutcome = union(enum) {
    admitted,
    deferred: struct { wait_seconds: u32 },
};

const TopicHashContext = struct {
    pub fn hash(_: TopicHashContext, key: TopicHash) u64 {
        return std.hash.Wyhash.hash(0, &key);
    }
    pub fn eql(_: TopicHashContext, a: TopicHash, b: TopicHash) bool {
        return std.mem.eql(u8, &a, &b);
    }
};

pub const TopicAd = struct {
    node_id: NodeId,
    /// Raw RLP ENR bytes (owned by `TopicQueue`).
    enr_raw: []u8,
    /// Monotonic seconds from the caller (wall clock or logical); used for lifetime and wait hints.
    placed_at: u64,
};

pub const TopicQueue = struct {
    ads: std.ArrayList(TopicAd),
    max_ads: usize,

    fn init(max_ads: usize) TopicQueue {
        return .{
            .ads = .empty,
            .max_ads = max_ads,
        };
    }

    pub fn deinit(self: *TopicQueue, allocator: std.mem.Allocator) void {
        for (self.ads.items) |ad| allocator.free(ad.enr_raw);
        self.ads.deinit(allocator);
    }

    fn hasAdvertiser(self: *const TopicQueue, node_id: NodeId) bool {
        for (self.ads.items) |ad| {
            if (std.mem.eql(u8, &ad.node_id, &node_id)) return true;
        }
        return false;
    }
};

/// Per-topic FIFO queues plus a global ad budget. Not networked on its own — combine with `message` and a UDP runtime later.
pub const TopicTable = struct {
    allocator: std.mem.Allocator,
    queues: std.HashMap(TopicHash, TopicQueue, TopicHashContext, std.hash_map.default_max_load_percentage),
    queue_ad_limit: usize,
    global_ad_limit: usize,
    total_ads: usize = 0,

    pub fn init(allocator: std.mem.Allocator, queue_ad_limit: usize, global_ad_limit: usize) TopicTable {
        return .{
            .allocator = allocator,
            .queues = .init(allocator),
            .queue_ad_limit = queue_ad_limit,
            .global_ad_limit = global_ad_limit,
        };
    }

    pub fn deinit(self: *TopicTable) void {
        var it = self.queues.iterator();
        while (it.next()) |kv| {
            var q = kv.value_ptr.*;
            q.deinit(self.allocator);
        }
        self.queues.deinit();
    }

    /// Drops expired ads (older than `target_ad_lifetime_secs`) and removes empty topic entries.
    pub fn purgeExpired(self: *TopicTable, now_secs: u64) std.mem.Allocator.Error!void {
        var dead_topics: std.ArrayList(TopicHash) = .empty;
        defer dead_topics.deinit(self.allocator);

        var it = self.queues.iterator();
        while (it.next()) |kv| {
            const topic_key = kv.key_ptr.*;
            const queue_ptr = kv.value_ptr;

            while (queue_ptr.ads.items.len > 0) {
                const head = queue_ptr.ads.items[0];
                if (now_secs -| head.placed_at < target_ad_lifetime_secs) break;
                self.allocator.free(head.enr_raw);
                _ = queue_ptr.ads.orderedRemove(0);
                self.total_ads -= 1;
            }

            if (queue_ptr.ads.items.len == 0) {
                try dead_topics.append(self.allocator, topic_key);
            }
        }

        for (dead_topics.items) |tk| {
            const rm = self.queues.fetchRemove(tk) orelse continue;
            var q = rm.value;
            q.deinit(self.allocator);
        }
    }

    fn oldestPlacedAcross(self: *const TopicTable) ?u64 {
        var min_t: ?u64 = null;
        var it = self.queues.iterator();
        while (it.next()) |kv| {
            const q = kv.value_ptr.*;
            if (q.ads.items.len == 0) continue;
            const t = q.ads.items[0].placed_at;
            min_t = if (min_t) |m| @min(m, t) else t;
        }
        return min_t;
    }

    fn waitHintSeconds(oldest_placed_at: u64, now_secs: u64) u32 {
        const age = now_secs -| oldest_placed_at;
        const remain = target_ad_lifetime_secs -| age;
        return @intCast(@min(remain, @as(u64, std.math.maxInt(u32))));
    }

    /// Registers an ad for `topic`. Purges expired entries first. On success duplicates are rejected.
    pub fn registerAd(
        self: *TopicTable,
        topic: TopicHash,
        node_id: NodeId,
        enr_raw: []const u8,
        now_secs: u64,
    ) (RegisterError || std.mem.Allocator.Error)!RegisterOutcome {
        try self.purgeExpired(now_secs);

        const gop = try self.queues.getOrPut(topic);
        if (!gop.found_existing) {
            gop.value_ptr.* = TopicQueue.init(self.queue_ad_limit);
        }
        const queue = gop.value_ptr;

        if (queue.hasAdvertiser(node_id)) return error.DuplicateAdvertiser;

        const queue_has_room = queue.ads.items.len < self.queue_ad_limit;
        const global_has_room = self.total_ads < self.global_ad_limit;

        if (queue_has_room and global_has_room) {
            try queue.ads.append(self.allocator, .{
                .node_id = node_id,
                .enr_raw = try self.allocator.dupe(u8, enr_raw),
                .placed_at = now_secs,
            });
            self.total_ads += 1;
            return .admitted;
        }

        if (!queue_has_room) {
            const oldest = queue.ads.items[0].placed_at;
            return .{ .deferred = .{ .wait_seconds = waitHintSeconds(oldest, now_secs) } };
        }

        const oldest_g = self.oldestPlacedAcross() orelse 0;
        return .{ .deferred = .{ .wait_seconds = waitHintSeconds(oldest_g, now_secs) } };
    }
};

test "topic table admit and duplicate" {
    const alloc = std.testing.allocator;
    var table = TopicTable.init(alloc, 16, 1000);
    defer table.deinit();

    var topic: TopicHash = @splat(0);
    topic[0] = 42;
    var id_a: NodeId = @splat(0);
    id_a[31] = 1;
    var id_b: NodeId = @splat(0);
    id_b[31] = 2;

    const enr_a = "enr-a";
    const enr_b = "enr-b";

    const r1 = try table.registerAd(topic, id_a, enr_a, 1_000);
    try std.testing.expect(r1 == .admitted);
    const r2 = try table.registerAd(topic, id_b, enr_b, 1_000);
    try std.testing.expect(r2 == .admitted);

    try std.testing.expectError(error.DuplicateAdvertiser, table.registerAd(topic, id_a, "enr-a2", 1_000));
}

test "topic table deferred when queue full" {
    const alloc = std.testing.allocator;
    var table = TopicTable.init(alloc, 2, 1000);
    defer table.deinit();

    var topic: TopicHash = @splat(0);
    topic[0] = 99;
    var id1: NodeId = @splat(0);
    id1[31] = 1;
    var id2: NodeId = @splat(0);
    id2[31] = 2;

    _ = try table.registerAd(topic, id1, "e1", 100);
    _ = try table.registerAd(topic, id2, "e2", 100);

    var id3: NodeId = @splat(0);
    id3[31] = 3;
    const r = try table.registerAd(topic, id3, "e3", 100);
    try std.testing.expect(r == .deferred);
    try std.testing.expectEqual(@as(u32, @intCast(target_ad_lifetime_secs)), r.deferred.wait_seconds);
}

test "topic table purge frees slot" {
    const alloc = std.testing.allocator;
    var table = TopicTable.init(alloc, 2, 1000);
    defer table.deinit();

    var topic: TopicHash = @splat(0);
    topic[0] = 7;
    var id1: NodeId = @splat(0);
    id1[31] = 1;
    var id2: NodeId = @splat(0);
    id2[31] = 2;
    var id3: NodeId = @splat(0);
    id3[31] = 3;

    _ = try table.registerAd(topic, id1, "e1", 0);
    _ = try table.registerAd(topic, id2, "e2", 0);

    var r = try table.registerAd(topic, id3, "e3", 0);
    try std.testing.expect(r == .deferred);

    try table.purgeExpired(target_ad_lifetime_secs + 1);

    r = try table.registerAd(topic, id3, "e3", target_ad_lifetime_secs + 2);
    try std.testing.expect(r == .admitted);
}
