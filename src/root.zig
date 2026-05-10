//! Pure Zig [Node Discovery Protocol v5](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md) implementation.
//!
//! Requires Zig 0.16.0 or later.

pub const errors = @import("errors.zig");
pub const varint = @import("varint.zig");
pub const rlp = @import("rlp.zig");
pub const wire = @import("wire.zig");
pub const enr = @import("enr.zig");
pub const handshake = @import("handshake.zig");
/// Same module as `handshake`; kept for discoverability next to `message_crypto`.
pub const crypto = handshake;
pub const packet = @import("packet.zig");
pub const message = @import("message.zig");
pub const message_crypto = @import("message_crypto.zig");
pub const routing = @import("routing.zig");
pub const ingress_limit = @import("ingress_limit.zig");
pub const identity_v4 = @import("identity_v4.zig");
pub const session = @import("session.zig");
pub const topic = @import("topic.zig");
pub const node = @import("node.zig");
pub const udp_runtime = @import("udp_runtime.zig");

test {
    _ = errors;
    _ = varint;
    _ = rlp;
    _ = wire;
    _ = enr;
    _ = handshake;
    _ = crypto;
    _ = packet;
    _ = message;
    _ = message_crypto;
    _ = routing;
    _ = ingress_limit;
    _ = identity_v4;
    _ = session;
    _ = topic;
    _ = node;
    _ = udp_runtime;
}
