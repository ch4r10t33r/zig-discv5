//! Ethereum Node Records (ENR) — stub.

const std = @import("std");
const errors = @import("errors.zig");

pub fn placeholder() errors.Discv5Error!void {
    return error.NotImplemented;
}

test "enr stub" {
    try std.testing.expectError(error.NotImplemented, placeholder());
}
