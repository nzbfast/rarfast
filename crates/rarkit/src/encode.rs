//! The RAR 5 and RAR 2.9 LZ encoders (spec H3 part B), which spec G's
//! writers call.
//!
//! Both produce a member's packed bytes from its input bytes and options.
//! Neither writes a header, chooses a volume boundary or computes a
//! checksum: those are spec G's.
//!
//! Determinism is a promise and not a target (API promise 6): the same
//! input, the same options and the same entropy give byte identical output
//! on every platform, with `parallel` on or off, at any thread count. No
//! choice below may depend on thread count or on iteration order over a
//! hash map.

pub(crate) mod bits;
pub(crate) mod chain;
pub(crate) mod class;
pub(crate) mod cut;
pub(crate) mod drive;
pub(crate) mod filter;
pub(crate) mod floor_count;
pub(crate) mod huffman;
pub(crate) mod lz;
pub(crate) mod rar29;
pub(crate) mod rar5;
pub(crate) mod sample;
#[cfg(test)]
mod tests;
#[cfg(feature = "tree-walk-census")]
pub(crate) mod tree_census;
