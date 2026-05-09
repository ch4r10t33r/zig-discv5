//! Wire encoding and message framing ([discv5-wire](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md)) — stub.

const std = @import("std");
const errors = @import("errors.zig");

pub fn placeholder() errors.Discv5Error!void {
    return error.NotImplemented;
}

test "wire stub" {
    try std.testing.expectError(error.NotImplemented, placeholder());
}
