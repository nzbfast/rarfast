//! Carried from the predecessor's `crc32/mod.rs` at an earlier revision: items ours from birth
//! per the provenance census (and clean-room outputs, clean by provenance).

/// Below this many bytes in all, [`Crc32::update_pieces`] hashes on the
/// calling thread: two 1 MiB pieces already ran 11.4 GB/s against 9.8 for
/// one stream, and anything smaller is spawn cost for nothing.
#[cfg(feature = "parallel")]
// Reached only through the `internals_*` seam, behind the
// `bench-internals` feature; no shipped build enables it.
#[allow(dead_code)]
pub(crate) const PARALLEL_PIECES_MIN_BYTES: usize = 2 << 20;
