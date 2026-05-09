//! Kademlia-style node table per [discv5-theory](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-theory.md):
//! 256 buckets by logarithmic XOR distance, `k = 16` entries per bucket, LRU at index 0 and MRU at the tail.

const std = @import("std");

pub const NodeId = [32]u8;

/// Bucket capacity from the Node Discovery Protocol (`k = 16`).
pub const bucket_k: usize = 16;

/// Replacement-cache capacity per bucket (discv5-theory recommends keeping a cache alongside each full bucket).
pub const replacement_k: usize = 16;

pub const Error = error{
    CannotAddSelf,
};

/// Bitwise XOR of two node IDs interpreted as big-endian integers.
pub fn xorDistance(a: NodeId, b: NodeId) NodeId {
    var out: NodeId = undefined;
    for (&out, a, b) |*o, x, y| o.* = x ^ y;
    return out;
}

/// `log2(n₁ XOR n₂)` using the XOR as a 256-bit big-endian integer.
/// Returns `null` when the two IDs are equal.
pub fn logDistance(a: NodeId, b: NodeId) ?u8 {
    const x = xorDistance(a, b);
    if (std.mem.eql(u8, &x, &@as(NodeId, @splat(0)))) return null;
    const val = std.mem.readInt(u256, &x, .big);
    return @intCast(std.math.log2_int(u256, val));
}

/// Compares XOR distances `a` vs `target` and `b` vs `target` as big-endian integers.
/// Returns `.lt` if `a` is strictly closer to `target` than `b`.
pub fn cmpXorToTarget(a: NodeId, b: NodeId, target: NodeId) std.math.Order {
    const xa = xorDistance(a, target);
    const xb = xorDistance(b, target);
    return std.mem.order(u8, &xa, &xb);
}

const Bucket = struct {
    nodes: [bucket_k]NodeId = undefined,
    len: u8 = 0,

    fn find(self: *const Bucket, id: NodeId) ?usize {
        for (self.nodes[0..self.len], 0..) |n, i| {
            if (std.mem.eql(u8, &n, &id)) return i;
        }
        return null;
    }

    fn moveToMru(self: *Bucket, idx: usize) void {
        if (idx + 1 == self.len) return;
        const id = self.nodes[idx];
        for (idx..self.len - 1) |j| {
            self.nodes[j] = self.nodes[j + 1];
        }
        self.nodes[self.len - 1] = id;
    }

    fn appendMru(self: *Bucket, id: NodeId) void {
        self.nodes[self.len] = id;
        self.len += 1;
    }

    fn removeLru(self: *Bucket) NodeId {
        const out = self.nodes[0];
        for (1..self.len) |i| {
            self.nodes[i - 1] = self.nodes[i];
        }
        self.len -= 1;
        return out;
    }

    fn removeAt(self: *Bucket, idx: usize) void {
        for (idx..self.len - 1) |j| {
            self.nodes[j] = self.nodes[j + 1];
        }
        self.len -= 1;
    }
};

const ReplacementCache = struct {
    nodes: [replacement_k]NodeId = undefined,
    len: u8 = 0,

    fn find(self: *const ReplacementCache, id: NodeId) ?usize {
        for (self.nodes[0..self.len], 0..) |n, i| {
            if (std.mem.eql(u8, &n, &id)) return i;
        }
        return null;
    }

    fn moveToMru(self: *ReplacementCache, idx: usize) void {
        if (idx + 1 == self.len) return;
        const id = self.nodes[idx];
        for (idx..self.len - 1) |j| {
            self.nodes[j] = self.nodes[j + 1];
        }
        self.nodes[self.len - 1] = id;
    }

    fn appendMru(self: *ReplacementCache, id: NodeId) void {
        self.nodes[self.len] = id;
        self.len += 1;
    }

    fn removeLru(self: *ReplacementCache) NodeId {
        const out = self.nodes[0];
        for (1..self.len) |i| {
            self.nodes[i - 1] = self.nodes[i];
        }
        self.len -= 1;
        return out;
    }

    /// Insert or refresh MRU; if full, drops the replacement LRU before appending.
    fn push(self: *ReplacementCache, id: NodeId) void {
        if (self.find(id)) |i| {
            self.moveToMru(i);
            return;
        }
        if (self.len < replacement_k) {
            self.appendMru(id);
            return;
        }
        _ = self.removeLru();
        self.appendMru(id);
    }

    fn removeIfPresent(self: *ReplacementCache, id: NodeId) bool {
        const idx = self.find(id) orelse return false;
        for (idx..self.len - 1) |j| {
            self.nodes[j] = self.nodes[j + 1];
        }
        self.len -= 1;
        return true;
    }
};

pub const AddResult = union(enum) {
    inserted,
    /// Node was already present; it was moved to MRU.
    updated,
    /// Bucket is full; the caller should revalidate `lru` (least recently seen) before replacing it.
    bucket_full: struct { lru: NodeId },
};

pub const RoutingTable = struct {
    local_id: NodeId,
    buckets: [256]Bucket = @splat(.{}),
    replacements: [256]ReplacementCache = @splat(.{}),

    pub fn init(local_id: NodeId) RoutingTable {
        return .{ .local_id = local_id };
    }

    fn promoteOneReplacement(self: *RoutingTable, bidx: usize) void {
        const bucket = &self.buckets[bidx];
        const rep = &self.replacements[bidx];
        if (bucket.len >= bucket_k) return;
        if (rep.len == 0) return;
        const id = rep.removeLru();
        if (bucket.find(id) != null) return;
        bucket.appendMru(id);
    }

    /// Inserts or refreshes a peer. The local node ID is rejected.
    pub fn add(self: *RoutingTable, node: NodeId) Error!AddResult {
        if (std.mem.eql(u8, &node, &self.local_id)) return error.CannotAddSelf;
        const bidx = logDistance(self.local_id, node) orelse return error.CannotAddSelf;
        const bucket = &self.buckets[bidx];
        _ = self.replacements[bidx].removeIfPresent(node);

        if (bucket.find(node)) |i| {
            bucket.moveToMru(i);
            return .updated;
        }

        if (bucket.len < bucket_k) {
            bucket.appendMru(node);
            return .inserted;
        }

        self.replacements[bidx].push(node);
        return .{ .bucket_full = .{ .lru = bucket.nodes[0] } };
    }

    /// Removes the least recently seen entry from the bucket that would hold `node`, then inserts `node`.
    /// Used after a failed liveness check on the LRU peer.
    pub fn replaceLruInBucketOf(self: *RoutingTable, node: NodeId) Error!void {
        if (std.mem.eql(u8, &node, &self.local_id)) return error.CannotAddSelf;
        const bidx = logDistance(self.local_id, node) orelse return error.CannotAddSelf;
        const bucket = &self.buckets[bidx];
        if (bucket.find(node)) |i| {
            bucket.moveToMru(i);
            return;
        }
        if (bucket.len < bucket_k) {
            _ = try self.add(node);
            return;
        }
        _ = bucket.removeLru();
        bucket.appendMru(node);
        _ = self.replacements[bidx].removeIfPresent(node);
    }

    /// Removes a node from whichever bucket contains it. Returns whether it was found.
    pub fn remove(self: *RoutingTable, node: NodeId) bool {
        const bidx = logDistance(self.local_id, node) orelse return false;
        const bucket = &self.buckets[bidx];
        const idx = bucket.find(node) orelse {
            return self.replacements[bidx].removeIfPresent(node);
        };
        bucket.removeAt(idx);
        self.promoteOneReplacement(bidx);
        return true;
    }

    /// Appends every node stored in buckets whose indices appear in `distances` (logarithmic distances).
    /// Duplicate indices in `distances` may yield duplicate IDs in `out`.
    pub fn appendNodesForLogDistances(
        self: *const RoutingTable,
        distances: []const u32,
        allocator: std.mem.Allocator,
        out: *std.ArrayList(NodeId),
    ) std.mem.Allocator.Error!void {
        for (distances) |d| {
            if (d > 255) continue;
            const b = self.buckets[d];
            try out.appendSlice(allocator, b.nodes[0..b.len]);
        }
    }

    /// Returns up to `limit` nodes in the table closest to `target` by XOR metric (owned slice).
    pub fn closest(
        self: *const RoutingTable,
        target: NodeId,
        limit: usize,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error![]NodeId {
        var tmp: std.ArrayList(NodeId) = .empty;
        defer tmp.deinit(allocator);

        for (self.buckets) |b| {
            try tmp.appendSlice(allocator, b.nodes[0..b.len]);
        }
        if (tmp.items.len == 0) {
            return try allocator.alloc(NodeId, 0);
        }

        const Context = struct {
            target: NodeId,
            fn less(ctx: @This(), a: NodeId, b: NodeId) bool {
                return cmpXorToTarget(a, b, ctx.target) == .lt;
            }
        };
        std.sort.pdq(NodeId, tmp.items, Context{ .target = target }, Context.less);

        const n = @min(limit, tmp.items.len);
        const out = try allocator.alloc(NodeId, n);
        @memcpy(out, tmp.items[0..n]);
        return out;
    }

    /// Total number of stored peers.
    pub fn count(self: *const RoutingTable) usize {
        var n: usize = 0;
        for (self.buckets) |b| {
            n += b.len;
        }
        return n;
    }

    /// Peers waiting in per-bucket replacement caches (not counted by **count**).
    pub fn countReplacements(self: *const RoutingTable) usize {
        var n: usize = 0;
        for (self.replacements) |r| {
            n += r.len;
        }
        return n;
    }
};

test "logDistance examples" {
    const z = @as(NodeId, @splat(0));
    var a: NodeId = @splat(0);
    var b: NodeId = @splat(0);
    b[31] = 1;
    try std.testing.expectEqual(@as(?u8, 0), logDistance(a, b));
    a[0] = 0x80;
    b = @splat(0);
    try std.testing.expectEqual(@as(?u8, 255), logDistance(a, b));
    try std.testing.expectEqual(@as(?u8, null), logDistance(z, z));
}

test "add MRU order and bucket full" {
    const local = @as(NodeId, @splat(0));
    var t = RoutingTable.init(local);

    var n_a: NodeId = @splat(0);
    n_a[31] = 32;
    var n_b: NodeId = @splat(0);
    n_b[31] = 33;

    try std.testing.expectEqual(@as(?u8, 5), logDistance(local, n_a));
    try std.testing.expect((try t.add(n_a)) == .inserted);
    try std.testing.expect((try t.add(n_b)) == .inserted);
    try std.testing.expectEqual(@as(usize, 2), t.buckets[5].len);
    try std.testing.expectEqualSlices(u8, &n_a, &t.buckets[5].nodes[0]);
    try std.testing.expectEqualSlices(u8, &n_b, &t.buckets[5].nodes[1]);

    try std.testing.expect((try t.add(n_a)) == .updated);
    try std.testing.expectEqualSlices(u8, &n_b, &t.buckets[5].nodes[0]);
    try std.testing.expectEqualSlices(u8, &n_a, &t.buckets[5].nodes[1]);

    try std.testing.expectError(error.CannotAddSelf, t.add(local));

    for (2..bucket_k) |i| {
        var nx: NodeId = @splat(0);
        nx[31] = @truncate(32 + i);
        _ = try t.add(nx);
    }
    var overflow: NodeId = @splat(0);
    overflow[31] = 32 + bucket_k;
    const r = try t.add(overflow);
    try std.testing.expect(r == .bucket_full);
    try std.testing.expectEqualSlices(u8, &t.buckets[5].nodes[0], &r.bucket_full.lru);

    try t.replaceLruInBucketOf(overflow);
    try std.testing.expectEqualSlices(u8, &overflow, &t.buckets[5].nodes[bucket_k - 1]);
}

test "closest ordering" {
    const local = @as(NodeId, @splat(0));
    var t = RoutingTable.init(local);

    var far: NodeId = @splat(0);
    far[0] = 0x80;
    var mid: NodeId = @splat(0);
    mid[0] = 0x40;
    var near: NodeId = @splat(0);
    near[31] = 1;

    _ = try t.add(far);
    _ = try t.add(mid);
    _ = try t.add(near);

    const target: NodeId = @splat(0);
    const got = try t.closest(target, 3, std.testing.allocator);
    defer std.testing.allocator.free(got);
    try std.testing.expectEqual(@as(usize, 3), got.len);
    try std.testing.expect(cmpXorToTarget(got[0], got[1], target) == .lt);
    try std.testing.expect(cmpXorToTarget(got[1], got[2], target) == .lt);
}

test "replacement cache and promote on remove" {
    const local = @as(NodeId, @splat(0));
    var t = RoutingTable.init(local);

    for (0..bucket_k) |i| {
        var nx: NodeId = @splat(0);
        nx[31] = @truncate(32 + i);
        _ = try t.add(nx);
    }
    try std.testing.expectEqual(@as(usize, bucket_k), t.count());
    try std.testing.expectEqual(@as(usize, 0), t.countReplacements());

    var extra: NodeId = @splat(0);
    extra[31] = 32 + bucket_k;
    const r = try t.add(extra);
    try std.testing.expect(r == .bucket_full);
    try std.testing.expectEqual(@as(usize, 1), t.countReplacements());

    const victim = t.buckets[5].nodes[0];
    try std.testing.expect(t.remove(victim));
    try std.testing.expectEqual(@as(usize, bucket_k), t.count());
    try std.testing.expectEqual(@as(usize, 0), t.countReplacements());
    try std.testing.expect(t.buckets[5].find(extra) != null);
}

test "appendNodesForLogDistances" {
    const local = @as(NodeId, @splat(0));
    var t = RoutingTable.init(local);
    var n5a: NodeId = @splat(0);
    n5a[31] = 32;
    var n5b: NodeId = @splat(0);
    n5b[31] = 33;
    _ = try t.add(n5a);
    _ = try t.add(n5b);

    var out: std.ArrayList(NodeId) = .empty;
    defer out.deinit(std.testing.allocator);
    const dists = [_]u32{ 5, 999 };
    try t.appendNodesForLogDistances(&dists, std.testing.allocator, &out);
    try std.testing.expectEqual(@as(usize, 2), out.items.len);
}
