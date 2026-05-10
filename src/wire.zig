//! Wire encoding and message framing ([discv5-wire](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md)).

const std = @import("std");
const build_options = @import("build_options");
const errors = @import("errors.zig");

pub const varint = @import("varint.zig");
pub const packet = @import("packet.zig");
pub const message = @import("message.zig");
pub const message_crypto = @import("message_crypto.zig");
pub const routing = @import("routing.zig");
pub const identity_v4 = @import("identity_v4.zig");
pub const session = @import("session.zig");
pub const handshake = @import("handshake.zig");
pub const crypto = handshake;

/// First byte of decrypted `message-pt` (`message-type` in discv5-wire).
pub const MessageKind = enum(u8) {
    ping = 0x01,
    pong = 0x02,
    findnode = 0x03,
    nodes = 0x04,
    talkreq = 0x05,
    talkresp = 0x06,
    regtopic = 0x07,
    ticket = 0x08,
    regconfirmation = 0x09,
    topicquery = 0x0a,
    _,

    pub fn parse(b: u8) ?MessageKind {
        return switch (b) {
            0x01 => .ping,
            0x02 => .pong,
            0x03 => .findnode,
            0x04 => .nodes,
            0x05 => .talkreq,
            0x06 => .talkresp,
            0x07 => if (build_options.experimental_topic_wire) .regtopic else null,
            0x08 => if (build_options.experimental_topic_wire) .ticket else null,
            0x09 => if (build_options.experimental_topic_wire) .regconfirmation else null,
            0x0a => if (build_options.experimental_topic_wire) .topicquery else null,
            else => null,
        };
    }
};

pub fn placeholder() errors.Discv5Error!void {
    return error.NotImplemented;
}

test "wire stub" {
    try std.testing.expectError(error.NotImplemented, placeholder());
}

test "message kind parse" {
    try std.testing.expect(MessageKind.parse(0x01).? == .ping);
    if (build_options.experimental_topic_wire) {
        try std.testing.expect(MessageKind.parse(0x0a).? == .topicquery);
    } else {
        try std.testing.expect(MessageKind.parse(0x0a) == null);
    }
    try std.testing.expect(MessageKind.parse(0xff) == null);
}
