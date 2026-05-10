//! IPv4 UDP socket helpers and a single-step receive loop into `Node.handleReceive`.
//!
//! Uses libc (`std.c`) datagram I/O. The `zig_discv5` module must be built with `link_libc`.

const std = @import("std");
const builtin = @import("builtin");

const node_mod = @import("node.zig");
const ingress_limit = @import("ingress_limit.zig");
const identity_v4 = @import("identity_v4.zig");
const message = @import("message.zig");
const message_crypto = @import("message_crypto.zig");
const packet = @import("packet.zig");

comptime {
    if (!builtin.link_libc) @compileError("udp_runtime requires link_libc; enable it on the zig_discv5 module in build.zig");
}

pub const Node = node_mod.Node;
pub const RemoteUdp = node_mod.RemoteUdp;

/// Pass to `recvDatagram` / `pumpOnce` for a non-blocking receive (`MSG_DONTWAIT` where available).
pub const recv_flags_nonblocking: u32 = std.c.MSG.DONTWAIT;

pub const UdpSocket = struct {
    fd: std.c.fd_t,

    pub const invalid_fd: std.c.fd_t = -1;

    pub const InitError = error{SocketFailed};
    pub const BindError = error{BindFailed};
    pub const NameError = error{GetSockNameFailed};

    pub fn initIpv4Udp() InitError!UdpSocket {
        const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.DGRAM, std.c.IPPROTO.UDP);
        if (fd == -1) return error.SocketFailed;
        return .{ .fd = fd };
    }

    /// Binds to `0.0.0.0`:`port` (host byte order). Use port `0` for an ephemeral local port.
    pub fn bindIpv4Any(self: UdpSocket, port_host: u16) BindError!void {
        const addr: std.c.sockaddr.in = .{
            .port = std.mem.nativeToBig(u16, port_host),
            .addr = 0,
        };
        if (std.c.bind(self.fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) == -1) {
            return error.BindFailed;
        }
    }

    pub fn localPort(self: UdpSocket) NameError!u16 {
        var addr: std.c.sockaddr.in = undefined;
        var len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
        if (std.c.getsockname(self.fd, @ptrCast(&addr), &len) == -1) return error.GetSockNameFailed;
        if (addr.family != std.c.AF.INET) return error.GetSockNameFailed;
        return std.mem.bigToNative(u16, addr.port);
    }

    pub fn close(self: *UdpSocket) void {
        if (self.fd != invalid_fd) {
            _ = std.c.close(self.fd);
            self.fd = invalid_fd;
        }
    }
};

pub const RecvError = error{ RecvFailed, UnexpectedInetFamily };
pub const SendError = error{ SendFailed, PartialSend, IPv6NotSupported };

pub fn remoteFromSockaddrIn(src: std.c.sockaddr.in) error{UnexpectedInetFamily}!RemoteUdp {
    if (src.family != std.c.AF.INET) return error.UnexpectedInetFamily;
    return .{
        .ip = .{ .v4 = @bitCast(src.addr) },
        .port = std.mem.bigToNative(u16, src.port),
    };
}

/// Receives one datagram. Returns `null` when `flags` include `recv_flags_nonblocking` and the read would block.
pub fn recvDatagram(sock: UdpSocket, buf: []u8, flags: u32) RecvError!?struct { len: usize, remote: RemoteUdp } {
    var src: std.c.sockaddr.in = undefined;
    var slen: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);

    const n: isize = blk: {
        while (true) {
            const r = std.c.recvfrom(sock.fd, buf.ptr, buf.len, flags, @ptrCast(&src), &slen);
            if (r != -1) break :blk r;
            switch (std.c.errno(r)) {
                .INTR => continue,
                .AGAIN => {
                    if (flags & recv_flags_nonblocking != 0) return null;
                    return error.RecvFailed;
                },
                else => return error.RecvFailed,
            }
        }
    };

    if (n < 0) return error.RecvFailed;
    const len: usize = @intCast(n);
    if (slen != @sizeOf(std.c.sockaddr.in) or src.family != std.c.AF.INET) {
        return error.UnexpectedInetFamily;
    }
    const remote = try remoteFromSockaddrIn(src);
    return .{ .len = len, .remote = remote };
}

pub fn sendDatagram(sock: UdpSocket, remote: RemoteUdp, payload: []const u8) SendError!void {
    switch (remote.ip) {
        .v4 => |b| {
            const dst: std.c.sockaddr.in = .{
                .port = std.mem.nativeToBig(u16, remote.port),
                .addr = @bitCast(b),
            };
            const rc = std.c.sendto(sock.fd, payload.ptr, payload.len, 0, @ptrCast(&dst), @sizeOf(std.c.sockaddr.in));
            if (rc == -1) return error.SendFailed;
            if (@as(usize, @intCast(rc)) != payload.len) return error.PartialSend;
        },
        .v6 => return error.IPv6NotSupported,
    }
}

pub const PumpError = RecvError || SendError || Node.ReceiveError || ingress_limit.RateLimited || std.mem.Allocator.Error;

pub const PumpResult = enum { idle, progressed };

/// Optional limits for **pumpOnceEx** (send-side uses the same sliding-window type as inbound).
pub const PumpOpts = struct {
    /// If non-null, each outbound datagram to the source address counts before **sendDatagram**; excess returns **error.RateLimited** (unsent replies are freed in defer).
    egress_limiter: ?*ingress_limit.IngressLimiter = null,
};

/// Receives at most one datagram, runs `Node.handleReceive`, and sends each reply to the source address.
/// `responses` must be empty on entry; allocated replies are freed before returning.
/// `now_ms` is forwarded to the node (session / pending TTL); use the same clock as the rest of your app.
pub fn pumpOnce(
    allocator: std.mem.Allocator,
    sock: UdpSocket,
    node_ptr: *Node,
    recv_buf: []u8,
    responses: *std.ArrayList([]u8),
    recv_flags: u32,
    now_ms: u64,
) PumpError!PumpResult {
    return pumpOnceEx(allocator, sock, node_ptr, recv_buf, responses, recv_flags, now_ms, .{});
}

/// Like **pumpOnce** with optional **egress_limiter** for per-pump send caps.
pub fn pumpOnceEx(
    allocator: std.mem.Allocator,
    sock: UdpSocket,
    node_ptr: *Node,
    recv_buf: []u8,
    responses: *std.ArrayList([]u8),
    recv_flags: u32,
    now_ms: u64,
    opts: PumpOpts,
) PumpError!PumpResult {
    std.debug.assert(responses.items.len == 0);

    const got = try recvDatagram(sock, recv_buf, recv_flags) orelse return .idle;
    std.debug.assert(got.len <= recv_buf.len);

    try node_ptr.handleReceive(got.remote, recv_buf[0..got.len], responses, now_ms);
    defer {
        for (responses.items) |p| allocator.free(p);
        responses.clearRetainingCapacity();
    }

    const peer_key = node_mod.ingressRateKey(got.remote);
    for (responses.items) |pkt| {
        if (opts.egress_limiter) |lim| {
            try lim.recordInbound(allocator, peer_key, now_ms);
        }
        try sendDatagram(sock, got.remote, pkt);
    }
    return .progressed;
}

test "nonblocking pump is idle when no datagram" {
    const alloc = std.testing.allocator;

    var sock = try UdpSocket.initIpv4Udp();
    defer sock.close();
    try sock.bindIpv4Any(0);

    var sk: [32]u8 = @splat(0);
    sk[31] = 7;
    var n = try Node.init(alloc, .{ .secret_key = sk });
    defer n.deinit();

    var recv_buf: [packet.max_packet_size]u8 = undefined;
    var responses: std.ArrayList([]u8) = .empty;
    defer responses.deinit(alloc);

    const st = try pumpOnce(alloc, sock, &n, &recv_buf, &responses, recv_flags_nonblocking, 0);
    try std.testing.expectEqual(@as(@TypeOf(st), .idle), st);
}

test "UDP pump sends WHOAREYOU to peer socket" {
    const alloc = std.testing.allocator;

    var server = try UdpSocket.initIpv4Udp();
    defer server.close();
    try server.bindIpv4Any(0);
    const server_port = try server.localPort();

    var client = try UdpSocket.initIpv4Udp();
    defer client.close();
    try client.bindIpv4Any(0);

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

    const dst: RemoteUdp = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = server_port };
    try sendDatagram(client, dst, ordinary);

    var recv_buf: [packet.max_packet_size]u8 = undefined;
    var responses: std.ArrayList([]u8) = .empty;
    defer responses.deinit(alloc);

    const st = try pumpOnce(alloc, server, &node_b, &recv_buf, &responses, 0, 0);
    try std.testing.expectEqual(@as(@TypeOf(st), .progressed), st);

    var reply_buf: [packet.max_packet_size]u8 = undefined;
    const reply = (try recvDatagram(client, &reply_buf, 0)) orelse unreachable;
    try std.testing.expect(reply.len > 0);

    const dec_copy = try alloc.dupe(u8, reply_buf[0..reply.len]);
    defer alloc.free(dec_copy);
    const parsed = try packet.decodeInPlace(&id_a, dec_copy);
    try std.testing.expect(parsed.header.flag == .whoareyou);
    try std.testing.expectEqualSlices(u8, &nonce, &parsed.header.nonce);
}

test "pumpOnceEx egress limiter blocks second reply burst to same peer" {
    const alloc = std.testing.allocator;

    var egress = ingress_limit.IngressLimiter.init(.{
        .per_peer_max_packets = 1,
        .per_peer_window_ms = 60_000,
        .global_max_packets = null,
    });
    defer egress.deinit(alloc);

    var server = try UdpSocket.initIpv4Udp();
    defer server.close();
    try server.bindIpv4Any(0);
    const server_port = try server.localPort();

    var client = try UdpSocket.initIpv4Udp();
    defer client.close();
    try client.bindIpv4Any(0);

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

    const dst: RemoteUdp = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = server_port };
    try sendDatagram(client, dst, ordinary);

    var recv_buf: [packet.max_packet_size]u8 = undefined;
    var responses: std.ArrayList([]u8) = .empty;
    defer responses.deinit(alloc);

    const st1 = try pumpOnceEx(alloc, server, &node_b, &recv_buf, &responses, 0, 0, .{ .egress_limiter = &egress });
    try std.testing.expectEqual(@as(@TypeOf(st1), .progressed), st1);

    var reply_buf: [packet.max_packet_size]u8 = undefined;
    _ = (try recvDatagram(client, &reply_buf, 0)) orelse unreachable;

    var nonce2: [12]u8 = undefined;
    for (&nonce2, 0..) |*b, i| b.* = @truncate(i + 3);
    const ping_pt2 = try message.encodePingPlaintext(alloc, &.{0x08}, 4);
    defer alloc.free(ping_pt2);
    packet.writePlaintextStaticHeader(&static_plain, .message, nonce2, packet.message_auth_size);
    @memcpy(prefix[16..][0..packet.static_header_size], &static_plain);
    @memcpy(prefix[packet.static_prefix_size..][0..packet.message_auth_size], &id_a);
    const ct2 = try message_crypto.encryptMessage(alloc, key, nonce2, ping_pt2, &prefix);
    defer alloc.free(ct2);
    const ordinary2 = try packet.encodeOrdinaryMessagePacket(alloc, node_b.node_id, iv, nonce2, id_a, ct2);
    defer alloc.free(ordinary2);
    try sendDatagram(client, dst, ordinary2);

    try std.testing.expectError(error.RateLimited, pumpOnceEx(alloc, server, &node_b, &recv_buf, &responses, 0, 0, .{ .egress_limiter = &egress }));
}
