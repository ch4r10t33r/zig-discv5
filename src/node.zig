//! Local node runtime (UDP socket, sessions, RPC orchestration) — stub.

const std = @import("std");
const errors = @import("errors.zig");

pub fn placeholder() errors.Discv5Error!void {
    return error.NotImplemented;
}

test "node stub" {
    try std.testing.expectError(error.NotImplemented, placeholder());
}
