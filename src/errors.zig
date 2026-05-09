//! Shared error types for discv5 layers.

pub const Discv5Error = error{
    InvalidInput,
    BufferTooSmall,
    Truncated,
    Oversized,
    UnsupportedVersion,
    VerifyFailed,
    NotImplemented,
};
