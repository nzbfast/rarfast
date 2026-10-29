//! Is there anything in this parse block for the finder to find?
//!
//! A level above the first spends most of its time SEARCHING, and on
//! already-compressed bytes - the video, the JPEG stills and the nested
//! archives a downloader's poster is mostly made of - every one of those
//! searches fails. Measured 19 Sep 2026 on the 16 MiB `media16` and
//! `random16` corpora of a bench script: the whole span of plans from the
//! cheapest to the dearest moves `media16` by 0.25% and `random16` by
//! 0.001%, for up to 3.6 times the CPU. That is the wall a user pays for
//! nothing, and it is paid on exactly the data that pays least back.
//!
//! So each parse block is SAMPLED before it is parsed, and a block with
//! nothing to find is parsed at the floor effort instead of the level's.
//! What the sample does NOT do is skip the entropy coder: already
//! compressed bytes still carry a few per cent of structure in their
//! headers and their file boundaries, and `media16` gives up 11% of
//! itself to the floor effort's parse alone. This drops the SEARCH, not
//! the compression.
//!
//! Three properties this has to have, and how each is had:
//!
//! - **It cannot move a byte with the thread count.** The verdict is a
//!   pure function of the block's own bytes, taken on the thread that
//!   parses the block, reading nothing outside it.
//! - **It has to be free.** It reads [`WINDOWS`] windows of
//!   [`WINDOW_BYTES`] of a 256 KiB block, so an eighth of it, through one
//!   direct-mapped table that fits in L1. Measured below a quarter of a
//!   nanosecond per block byte against a parse that costs thirty to a
//!   hundred.
//! - **It has to be conservative.** A block wrongly called empty loses
//!   real ratio, where a block wrongly called full only costs the search
//!   that was going to run anyway. [`LEAST_YIELD_PER_MILLE`] is set an
//!   order of magnitude under the lowest yield any compressible corpus
//!   shows, which the measured histogram is what settles.

/// How many windows of the block are sampled, spread evenly across it.
/// More than one, because a block is not uniform: a seam between two
/// files lands in one window and not the others.
const WINDOWS: usize = 4;
/// How many bytes each window reads.
///
/// Small, because the two populations the sample separates are nowhere
/// near each other: measured over the six corpora of a bench script,
/// every block of every compressible one reads above 215 repeats per
/// thousand and every block of `random16` reads 0. A sample that only has
/// to tell 0 from 215 does not need many positions, and what it costs is
/// paid on every block of every level above the floor, including the ones
/// where it finds plenty and changes nothing.
const WINDOW_BYTES: usize = 2 << 10;
/// Positions in the direct-mapped table, which holds one earlier position
/// per four byte prefix. A power of two, and small enough to stay in L1
/// beside the window it is reading.
const TABLE: usize = 1 << 12;
/// A block whose sampled positions carry fewer than this many four byte
/// repeats per thousand has nothing for the finder to find.
///
/// Set from the measured histogram: the compressible corpora
/// sit above 300 per mille and the already-compressed ones under 3, so
/// anything in between separates them. It is put at the bottom of that
/// gap rather than the middle because the two errors are not symmetric.
const LEAST_YIELD_PER_MILLE: u32 = 16;
/// A block shorter than this is not sampled at all: there is no wall in
/// it worth saving, and a short block is a bad sample of itself.
const LEAST_BLOCK_BYTES: usize = 32 << 10;

const HASH_MULTIPLIER: u32 = 0x9E37_79B1;

#[inline]
fn hash_at(bytes: &[u8], at: usize) -> usize {
    let word = u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    (word.wrapping_mul(HASH_MULTIPLIER) >> (32 - TABLE.trailing_zeros())) as usize
}

/// Four byte repeats per thousand sampled positions of `bytes`.
///
/// Public to the crate so that `examples/ladder_probe.rs` can print the
/// histogram the threshold above is read off, rather than the threshold
/// being a number nobody can check.
pub(crate) fn yield_per_mille(bytes: &[u8]) -> u32 {
    if bytes.len() < LEAST_BLOCK_BYTES {
        // Not sampled, and reported as richly repeating, so that the one
        // caller treats it as a block to search normally.
        return 1000;
    }
    let mut table = [0u32; TABLE];
    let mut seen = 0u32;
    let mut hits = 0u32;
    let window = WINDOW_BYTES.min(bytes.len() / WINDOWS);
    for index in 0..WINDOWS {
        // Evenly spread, last window ending at the block's end, so a
        // block's seams and its middle are both looked at.
        let start = index * (bytes.len() - window) / (WINDOWS - 1).max(1);
        let slice = &bytes[start..start + window];
        for at in 0..slice.len() - 4 {
            let slot = &mut table[hash_at(slice, at)];
            let held = *slot;
            // Zero means empty, so positions are stored plus one.
            if held != 0 {
                let earlier = (held - 1) as usize;
                if slice[earlier..earlier + 4] == slice[at..at + 4] {
                    hits += 1;
                }
            }
            *slot = at as u32 + 1;
            seen += 1;
        }
        table.fill(0);
    }
    if seen == 0 {
        return 1000;
    }
    (hits as u64 * 1000 / seen as u64) as u32
}

/// Whether a reading clears the threshold.
#[inline]
pub(crate) fn worth(yield_per_mille: u32) -> bool {
    yield_per_mille >= LEAST_YIELD_PER_MILLE
}

/// A block that reads worth searching but under this many repeats per
/// thousand reads THIN: it has something to find, but little and mostly
/// short, and at level 3 it is parsed by the thin scan
/// (`Plan::for_thin_block`) rather than the level's own parse.
///
/// Every block of the six corpora [`WINDOW_BYTES`] names reads above 215
/// per mille where it is compressible; a big member's blocks that are worth
/// searching read 24 to 248 (1 GiB of one, counted 14 Oct 2026).
pub(crate) const THIN_UNDER_PER_MILLE: u32 = 256;

/// Whether a reading is worth searching and still under `under`.
#[inline]
pub(crate) fn thin(yield_per_mille: u32, under: u32) -> bool {
    worth(yield_per_mille) && yield_per_mille < under
}

/// Whether this block is worth the level's search effort, or should be
/// parsed at the floor effort instead.
#[inline]
pub(crate) fn worth_searching(bytes: &[u8]) -> bool {
    worth(yield_per_mille(bytes))
}
