//! Backward-compatible re-export of the unsigned varint codec from
//! [`zig-varint`](https://github.com/ch4r10t33r/zig-varint).
//!
//! Existing call sites import this module by its previous in-tree name; the
//! actual implementation now lives in `zig_varint.unsigned` and is shared
//! with the rest of the `ch4r10t33r/zig-*` networking stack.

const unsigned = @import("zig_varint").unsigned;

pub const max_len = unsigned.max_len;
pub const DecodeError = unsigned.DecodeError;

pub const encode = unsigned.encode;
pub const encodedLen = unsigned.encodedLen;
pub const decode = unsigned.decode;
pub const decodeRelaxed = unsigned.decodeRelaxed;

test {
    _ = unsigned;
}
