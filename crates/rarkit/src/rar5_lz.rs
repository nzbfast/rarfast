//! The RAR 5.0 LZ decoder (package H, part 2).
//!
//! Implemented from `specs/SPEC-H2-rarkit-rar5-lz.md` alone; no other RAR
//! implementation and no copy of the predecessor was opened. Where section
//! 1.3 names an item as CARRIED it is used from `crate::carry` rather than
//! rewritten; where it names one that did not exist yet because it depended
//! on this specification, it is built here to the behaviour stated.
//!
//! The shape of the package:
//!
//! - [`block`] locates a block from its header alone (3.1, 3.2), which is
//!   what lets the chain be walked without decoding a symbol.
//! - [`tables`] reads the code length alphabet and the four tables (3.3)
//!   and builds the STRICT canonical code (3.4).
//! - [`ladders`] holds the two slot ladders (3.5).
//! - [`output`] is the window, a ring of the declared dictionary size, and
//!   the streaming emission (3.7).
//! - [`filters`] frames a filter record and hands the span to spec C (3.6).
//! - [`tape`] is the parallel block decode (3.8), behind `parallel`.

#[cfg(feature = "parallel")]
pub(crate) mod ahead;
pub(crate) mod bits;
pub(crate) mod block;
#[cfg(any(test, feature = "bench-internals"))]
pub(crate) mod container;
pub(crate) mod filters;
pub(crate) mod ladders;
#[cfg(feature = "parallel")]
mod onepass;
pub(crate) mod output;
mod serial_batch;
#[cfg(feature = "parallel")]
pub(crate) mod symbols;
pub(crate) mod tables;
#[cfg(feature = "parallel")]
pub(crate) mod tape;

/// Whether a member that CONTINUES a solid chain takes the tape path from
/// [`SOLID_TAPE_FLOOR`] rather than from the carried `MT_MIN_OUTPUT`:
/// `RARKIT_SOLID_TAPE`, `0` or `off` to turn it off, `1` or `on`, anything
/// else or unset for the default below (ON).
///
/// **Why.** A solid chain's members between the chain decode-ahead's reach
/// (`ahead::AHEAD_MEMBER_MAX`, 1 MiB) and the tape path's floor (16 MiB)
/// get neither lever, so their Huffman decode and their apply run
/// interleaved on the walking thread. On the rivals comparison's c6 set (2 GiB
/// of text at `-m3 -s`, log-normal sizes, median 1 MiB) that band is 79
/// percent of the bytes and 88 percent of a `t`'s wall, at about 553 MB/s
/// against 1,100 MB/s for a member whose decode had been done elsewhere
/// (the solid decode width measurement, 23 Sep 2026). The tape
/// path decodes a member's blocks on lanes while this thread applies them,
/// its memory bounded per lane (`tape::TAPE_BYTES_PER_LANE`), and a member
/// that CONTINUES the chain has only its window carried in, which the
/// tape path already handles for the chain's members of 16 MiB and more.
///
/// The carried floor stays for everything else: a member that starts a
/// stream (the first of an archive, every member of a non-solid one) is
/// where `MT_MIN_OUTPUT`'s own pricing was done, and a non-solid archive's
/// members already run side by side on the concurrent driver.
#[cfg(feature = "parallel")]
pub(crate) const SOLID_TAPE_ENV: &str = "RARKIT_SOLID_TAPE";

/// ON, on its measured wall (decided 23 Sep
/// 2026): on an Apple M3 Mac the c6-shaped solid text set's `t` read 1.876x and
/// its `x` 1.810x of the lever off, 1.517x and 1.608x of reference unrar,
/// CPU +13 and +14 percent, peak RSS +7 and +9 MiB (the
/// solid decode width measurement, 23 Sep 2026).
#[cfg(feature = "parallel")]
const SOLID_TAPE_DEFAULT: bool = true;

/// The smallest continuing member the lever sends down the tape path:
/// every member the chain decode-ahead refuses for size.
#[cfg(feature = "parallel")]
pub(crate) const SOLID_TAPE_FLOOR: u64 = ahead::AHEAD_MEMBER_MAX + 1;

/// A bench knob that replaces [`SOLID_TAPE_FLOOR`] with a figure in KiB,
/// so a timed run can price the floor in cells. Nothing ships setting it.
#[cfg(feature = "parallel")]
pub(crate) const SOLID_TAPE_FLOOR_ENV: &str = "RARKIT_SOLID_TAPE_FLOOR_KIB";

#[cfg(feature = "parallel")]
fn solid_tape_env() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        match crate::knob::reader_var(SOLID_TAPE_ENV)
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("1" | "on") => true,
            Some("0" | "off") => false,
            _ => SOLID_TAPE_DEFAULT,
        }
    })
}

/// Whether a decoder built on this thread takes the lever.
#[cfg(all(feature = "parallel", feature = "test-support"))]
fn solid_tape() -> bool {
    crate::probe::solid_tape().unwrap_or_else(solid_tape_env)
}

#[cfg(all(feature = "parallel", not(feature = "test-support")))]
fn solid_tape() -> bool {
    solid_tape_env()
}

#[cfg(feature = "parallel")]
fn solid_tape_floor() -> u64 {
    static FLOOR: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *FLOOR.get_or_init(|| {
        crate::knob::reader_var(SOLID_TAPE_FLOOR_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&kib| kib > 0)
            .map_or(SOLID_TAPE_FLOOR, |kib| kib.saturating_mul(1024))
    })
}

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) mod vectors;

use std::sync::Arc;

use bits::BitReader;
use block::block_in_hand;
use filters::Filters;
use ladders::{
    bits_after_slot, distance_named, extra_bits_value, fresh_match_length, length_from_slot,
    DISTANCE_SLOT_BITS,
};
use output::{LzSink, Window};
use tables::{TableScratch, Tables};

use crate::carry::c_lz::codec::rar50::{
    lut_entry_is_literal, lut_entry_symbol, HUFF_LUT_DISTANCE_BITS_MASK,
    HUFF_LUT_DISTANCE_BITS_SHIFT, HUFF_LUT_DISTANCE_INVALID_BIT,
};
use crate::memory::MemoryPolicy;
use crate::{Resource, Result};

// The decoder's parts, one module a seam.
mod apply;
mod member;
mod serial;
use serial::*;

/// The main alphabet's control symbols (section 3.5).
const SYMBOL_FILTER: usize = 256;
const SYMBOL_REPEAT_LAST: usize = 257;
const SYMBOL_REPEAT_BASE: usize = 258;
const SYMBOL_MATCH_BASE: usize = 262;
/// The most bytes a block header can be: two plus a three byte length.
const MAX_BLOCK_HEADER: usize = 5;
/// The most packed bytes a decoder ever needs contiguous: a block header
/// plus the largest payload its 24 bit length field can name (section
/// 4.1). ONE constant for both ends of the streamed walk: what the tape
/// path asks for at most ([`STREAM_CHUNK_MAX`]) and what spec F's
/// buffered source holds at most (`read::extract`'s `Buffered`), which
/// until 29 Sep 2026 were two constants equal only by hand.
pub(crate) const MAX_PACKED: usize = MAX_BLOCK_HEADER + (1 << 24);
/// The packed bytes the tape path asks for at a time, and the most it ever
/// asks for: a block's payload length is 24 bits wide (section 4.1), so no
/// block is larger than the ceiling and the chunked walk always advances.
///
/// **Why this is megabytes and not kilobytes.** A chunk is planned, then
/// piped, then advanced past, so it is also the span one crew of decode
/// lanes lives for, and a chunk too small to hold more blocks than there
/// are lanes pays a thread spawn and join for a few blocks of work. At 256
/// KiB, which this was until 19 Sep 2026, a real `-m3` archive put about
/// fifteen blocks in a chunk against a wave of sixteen, so the decode
/// NEVER ran ahead of the apply stage at all and the chain of 32,768
/// blocks crossed 2,188 of them. Four MiB holds about two hundred and
/// forty, which is thirty crews for a whole 534 MiB set. The packed buffer
/// this asks of spec F's source was already allowed to reach the ceiling
/// below, since one maximal block does, so nothing here widens the peak a
/// caller was promised.
#[cfg(feature = "parallel")]
const STREAM_CHUNK: usize = 1 << 22;

/// The least [`STREAM_CHUNK`] a small budget lowers the streamed ask to.
#[cfg(feature = "parallel")]
const STREAM_CHUNK_FLOOR: usize = 64 << 10;

/// The tapes each piped lane takes from its decoder's pool at the start of a
/// chunk and gives back at the end; see `member_piped`.
#[cfg(feature = "parallel")]
const POOL_TAPES_PER_LANE: usize = 2;
#[cfg(feature = "parallel")]
const STREAM_CHUNK_MAX: usize = MAX_PACKED;

/// A lookup entry's symbol, with the carried metadata masked away.
#[inline(always)]
pub(crate) fn lut_symbol(entry: u32) -> usize {
    lut_entry_symbol(entry)
}

/// Every fault this package raises, in one place, so the error kinds and
/// the sections that name them stay together (section 2's table).
pub(crate) mod fault {
    use crate::{Corruption, Error, ErrorKind, Rar5Fault, Resource};

    fn corrupt(fault: Rar5Fault) -> Error {
        Error::new(ErrorKind::Corrupt(Corruption::Rar5(fault)))
    }

    pub(crate) fn truncated() -> Error {
        Error::new(ErrorKind::Truncated)
    }
    pub(crate) fn block_header_checksum() -> Error {
        corrupt(Rar5Fault::BlockHeaderChecksum)
    }
    pub(crate) fn block_size_width() -> Error {
        corrupt(Rar5Fault::BlockSizeWidth)
    }
    pub(crate) fn level_symbol() -> Error {
        corrupt(Rar5Fault::LevelSymbol)
    }
    pub(crate) fn repeat_at_start() -> Error {
        corrupt(Rar5Fault::RepeatAtStart)
    }
    pub(crate) fn oversubscribed() -> Error {
        corrupt(Rar5Fault::Oversubscribed)
    }
    pub(crate) fn invalid_code() -> Error {
        corrupt(Rar5Fault::InvalidCode)
    }
    pub(crate) fn empty_table() -> Error {
        corrupt(Rar5Fault::EmptyTable)
    }
    pub(crate) fn length_slot() -> Error {
        corrupt(Rar5Fault::LengthSlot)
    }
    pub(crate) fn uninitialised_repeat() -> Error {
        corrupt(Rar5Fault::UninitialisedRepeat)
    }
    pub(crate) fn distance_out_of_range() -> Error {
        corrupt(Rar5Fault::DistanceOutOfRange)
    }
    pub(crate) fn filter_type() -> Error {
        corrupt(Rar5Fault::FilterType)
    }
    pub(crate) fn filter_range() -> Error {
        corrupt(Rar5Fault::FilterRange)
    }
    pub(crate) fn incomplete_member() -> Error {
        corrupt(Rar5Fault::IncompleteMember)
    }

    /// A window the policy will not budget, or one this target cannot
    /// address (section 4.2).
    pub(crate) fn window_too_large(needed: u64) -> Error {
        Error::new(ErrorKind::LimitExceeded {
            resource: Resource::Window,
            needed,
            limit: usize::MAX as u64,
        })
    }
    /// A ring the policy allowed and the HOST would not map (SPEC-API 8.1
    /// term 4): `LimitExceeded { AddressSpace }` with the ring's bytes, and
    /// the ceiling the caller set as the policy's figure.
    pub(crate) fn window_unmapped(needed: u64, ceiling: u64) -> Error {
        crate::memory::host_refused(needed, ceiling)
    }
    /// The pending filter queue's bounds, as numbers (section 8 item 2).
    pub(crate) fn hold_exceeded(needed: u64) -> Error {
        Error::new(ErrorKind::LimitExceeded {
            resource: Resource::Window,
            needed,
            limit: super::filters::FILTER_HOLD_LIMIT as u64,
        })
    }
    pub(crate) fn pending_exceeded(needed: u64) -> Error {
        Error::new(ErrorKind::LimitExceeded {
            resource: Resource::Window,
            needed,
            limit: super::filters::WAITING_AT_ONCE as u64,
        })
    }
}

/// The length of the ring [`output::Window::new`] allocates for a window of
/// `declared` bytes under `ceiling`: the ONE place that sizing is written,
/// so the read pools' admission charges exactly what a decoder commits
/// (a stated budget is hard). It lives here and not
/// in `output.rs`, because a function added there re-partitions
/// `put_symbols` (the md128k partition finding).
pub(crate) fn ring_len(declared: u64, ceiling: u64) -> Result<usize> {
    let size = usize::try_from(declared).map_err(|_| fault::window_too_large(declared))?;
    let floor = usize::try_from(ceiling)
        .unwrap_or(usize::MAX)
        .min(output::RING_FLOOR);
    // A ring shorter than one operation could not hold a single match.
    // The floor bounds the WHOLE ring, spill included, so every
    // dictionary under it gets a ring of exactly `RING_FLOOR`, a power
    // of two (`gather_direct`'s masked form); the correctness margins
    // stay on top of the declared size either way.
    // The window reaches back `WINDOW_FLOOR` at the least, whatever the
    // header declares and whatever the ceiling (SPEC-H2 3.7): a constant
    // of the format, on top of which the margins stand as they did.
    Ok(size
        .max(output::MIN_RING)
        .max(output::WINDOW_FLOOR)
        .checked_add(output::SPILL)
        .ok_or_else(|| fault::window_too_large(declared))?
        .max(floor))
}

/// Where a member's packed bytes come from. They may arrive in pieces; the
/// decoder never needs a byte twice (section 2).
pub(crate) trait PackedSource {
    /// Make up to `want` bytes available from the current position. Having
    /// fewer is not an error here and does NOT say the member has ended: a
    /// source may hold at most [`MAX_PACKED`] (spec F's buffered source
    /// does), or hand bytes over in pieces. [`PackedSource::exhausted`] is
    /// what says the member's bytes ran out.
    fn fill(&mut self, want: usize) -> Result<()>;
    /// What is available now.
    fn available(&self) -> &[u8];
    /// Consume `n` of the available bytes.
    fn advance(&mut self, n: usize);
    /// Whether the member has no bytes beyond [`PackedSource::available`]:
    /// the only honest end-of-member signal. Until 29 Sep 2026 the
    /// streamed tape walk read "fewer than asked" as the end, and a request
    /// over the buffered source's cap then ended a member early with a
    /// checksum failure. Only the streamed walk, which is the `parallel` feature's,
    /// asks it.
    #[cfg_attr(not(feature = "parallel"), allow(dead_code))]
    fn exhausted(&self) -> bool;
}

/// A whole member's packed bytes, already in memory.
pub(crate) struct SliceSource<'a> {
    rest: &'a [u8],
}

impl<'a> SliceSource<'a> {
    pub(crate) fn new(packed: &'a [u8]) -> SliceSource<'a> {
        SliceSource { rest: packed }
    }
}

impl PackedSource for SliceSource<'_> {
    fn fill(&mut self, _want: usize) -> Result<()> {
        Ok(())
    }
    fn available(&self) -> &[u8] {
        self.rest
    }
    fn advance(&mut self, n: usize) {
        self.rest = &self.rest[n..];
    }
    /// The whole member is in hand.
    fn exhausted(&self) -> bool {
        true
    }
}

/// Whether a stream takes the parallel block decode (section 3.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParallelMode {
    /// The carried policy decides: members below `MT_MIN_OUTPUT` and hosts
    /// with no spare core decode serially.
    Auto,
    /// The tape path whatever the member's size, for the differential
    /// tests, the fuzz target and the bench leg that reports the split's
    /// worth.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    On,
    /// The serial path, which the `parallel` feature being off also gives.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    Off,
}

/// The four repeated distances and the last match length (section 3.5).
///
/// This state is consumed only when a decoded operation is APPLIED to the
/// window, never when a symbol is decoded. That is section 3.8's property,
/// and it is what lets a block be decoded ahead of the blocks before it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct MatchState {
    pub(crate) repeats: [usize; 4],
    pub(crate) last_length: usize,
}

impl MatchState {
    /// A fresh match: the four become `[d, r0, r1, r2]`.
    #[inline(always)]
    pub(crate) fn fresh(&mut self, distance: usize, length: usize) {
        self.repeats = [distance, self.repeats[0], self.repeats[1], self.repeats[2]];
        self.last_length = length;
    }

    /// Repeated distance `k`: the chosen distance moves to the front and
    /// the ones before it shift back; the ones after it do not move.
    #[inline(always)]
    pub(crate) fn rotate(&mut self, k: usize, length: usize) -> Result<usize> {
        let distance = self.repeats[k];
        if distance == 0 {
            return Err(fault::uninitialised_repeat());
        }
        let mut moved = self.repeats;
        moved[0] = distance;
        moved[1..=k].copy_from_slice(&self.repeats[..k]);
        self.repeats = moved;
        self.last_length = length;
        Ok(distance)
    }

    /// [`MatchState::rotate`] for the apply walks, OUT OF LINE, answering
    /// the distance, or 0 for an uninitialised repeat, with the state
    /// then untouched.
    ///
    /// The inlined `rotate` copies `k` slots with a variable-length slice
    /// copy, which LLVM lowers to a call to libc's `memcpy` in every apply
    /// walk it is inlined into: about 10 ns a repeat on M3, 14 percent of
    /// `rar5_code_32m_m3`'s apply thread (measured 24 Sep 2026). Moving
    /// the slots as a select per slot inline removes the call, but lets
    /// LLVM lift the state out of memory for the whole walk, and the
    /// walk then pays a stack shuffle on every fresh match (text rows +3
    /// percent instructions by screen). Out of line, the walk still hands
    /// the state's address to a call, keeps it in memory as it does
    /// today, and the call is this function rather than `memcpy`. The
    /// distance comes back in a register, zero standing for the fault the
    /// caller raises, because a stored distance is never zero.
    // The tape walks are its only callers, and they exist with `parallel`.
    #[cfg(feature = "parallel")]
    #[inline(never)]
    pub(crate) fn rotate_outlined(&mut self, k: usize, length: usize) -> usize {
        let r = self.repeats;
        let distance = r[k];
        if distance == 0 {
            return 0;
        }
        self.repeats = [
            distance,
            if k >= 1 { r[0] } else { r[1] },
            if k >= 2 { r[1] } else { r[2] },
            if k >= 3 { r[2] } else { r[3] },
        ];
        self.last_length = length;
        distance
    }
}

/// One RAR 5 stream: the window, the repeated distances, the last match
/// length, the pending filters and the table set carried between blocks.
pub(crate) struct Rar5Lz {
    window: Window,
    /// The table set in force, which a block with the table bit clear uses
    /// unchanged and which a solid chain carries across a member boundary.
    ///
    /// It is an `Arc` because the parallel workers share it. On the serial
    /// path the count is always one, so the allocation is handed straight
    /// back to `spare` and no block allocates; on the parallel path the
    /// plan holds a reference to each group's set until the member ends.
    current: Option<Arc<Tables>>,
    /// The allocation the last table set left behind.
    spare: Option<Tables>,
    scratch: TableScratch,
    filters: Filters,
    state: MatchState,
    /// The member's algorithm version (section 3.3), from spec F.
    algorithm: u8,
    /// The tape decode's width ceiling: `ReadOptions::workers` as the
    /// read resolved it (API section 8.4.2), never the memory policy's
    /// `max_workers`, which since 20 Sep 2026 is a memory field only.
    /// A decoder is built once per method and window and reused across
    /// members, so the width is SET rather than constructed in: a member
    /// decoded on a worker at a share of the ceiling and one decoded on
    /// the walking thread at the whole of it use the same decoder.
    // Live with the `parallel` feature only, which the default build has.
    #[allow(dead_code)]
    max_workers: usize,
    /// The lanes this decoder's MEMORY BUDGET affords, from
    /// `MemoryPolicy::working_limit` through `tape::lanes_within_budget`
    /// (API 8.4.1). Read at construction because the policy is what
    /// `new` is handed and a decoder is built once per method and window;
    /// `set_tape_width` mins the caller's width against it, which is
    /// 8.4.2's precedence rule: the width is what `workers` allows,
    /// lowered as far as the budget forces and no further.
    // Live with the `parallel` feature only, which the default build has.
    #[allow(dead_code)]
    budget_lanes: usize,
    /// Whether `max_workers` is a width the caller STATED, which reaches
    /// the lanes as it always did, or the engine's default, whose lanes
    /// count physical cores (`tape::workers`). False until a read path
    /// says otherwise, which is the default.
    #[allow(dead_code)]
    width_stated: bool,
    /// Whether the NEXT member carries no checksum, of either kind, which
    /// only its reader knows. Taken by [`Rar5Lz::member`], so it is said
    /// once a member and a caller that says nothing gets the strict
    /// answer (SPEC-H2 3.1: a completed span past the declared size is
    /// `FilterRange` under a checksum and passes without one).
    unchecked: bool,
    /// Whether the read's width, as `set_tape_width` was last handed it and
    /// before the budget lowered it, is ONE: the caller's thread is then
    /// the one decode lane (SPEC-API 8.4.2), and the chain's
    /// decode-ahead opens none beside it (`Rar5Lz::ahead_refused`).
    #[allow(dead_code)]
    width_one: bool,
    /// Whether the parallel block decode is used for this stream.
    parallel: ParallelMode,
    #[cfg(feature = "parallel")]
    tapes: tape::TapePool,
    /// The wave buffers the two sides of the overlap pass to each other,
    /// kept across members so a steady state wave allocates nothing.
    #[cfg(feature = "parallel")]
    waves: Vec<tape::Wave>,
    /// The blocks in one wave, when something forces it away from twice
    /// the worker count. The tests and the `rar5_wave_overlap` bench leg
    /// set it so a member of a few blocks still crosses several waves,
    /// which is the only place the overlap can be seen.
    #[cfg(feature = "parallel")]
    wave_blocks: Option<usize>,
    /// The packed bytes one tape unit may span, when something forces it
    /// away from `tape::TAPE_UNIT_BYTES`: the tests set it so one binary
    /// decodes the same member in one-block units and in runs of blocks,
    /// which must give the same bytes (SPEC-API 8.2).
    #[cfg(feature = "parallel")]
    tape_unit: Option<usize>,
    /// The caller's working limit, which a tape unit is charged against
    /// (`tape::unit_bytes_within_budget`).
    #[cfg(feature = "parallel")]
    working_limit: u64,
    /// Whether wave N+1 is decoded while wave N is applied. Off is the
    /// BULK SYNCHRONOUS driver this replaced - decode a wave, stop, apply
    /// it, start the next - which the `rar5_wave_overlap` bench legs keep
    /// so the two can be priced against each other in one binary in the
    /// same minutes. It is scheduling and must not change a byte.
    #[cfg(feature = "parallel")]
    overlap: bool,
    /// The DECLARED dictionary, which bounds a distance (section 3.7) and
    /// which the symbol pass (`symbols`) is gated on: the lanes check a
    /// block's distances against it and the pass runs only where the ring
    /// is at least twice it.
    #[cfg(feature = "parallel")]
    declared: usize,
    /// The chain of the member being decoded, reused so no member
    /// allocates a plan of its own (section 4.2).
    #[cfg(feature = "parallel")]
    plan: tape::Plan,
    /// The lanes every member decoding at once shares (SPEC-API 8.3).
    ///
    /// `None` is the sequential path and the arrangement that divides the
    /// ceiling at dispatch: both give this decoder its width outright.
    #[cfg(feature = "parallel")]
    budget: Option<Arc<crate::read::lanes::LaneBudget>>,
    /// THE DEFAULT WIDTH'S LANES FOR THE NEXT CHUNK: the ceiling until a
    /// chunk has been decoded; then falling while the apply stage never
    /// waits on its lanes, and growing back while it does ([`tape::Width`]). `None` where the width was stated, or a
    /// bench knob fixed the host figure: those widths are the figure
    /// itself, as they always were. Kept across the chunks and the
    /// members of one decoder, so a solid chain carries what it learned.
    #[cfg(feature = "parallel")]
    tape_grow: Option<tape::Width>,
    /// The decode-ahead that spans a SOLID CHAIN's members, which is the
    /// only parallelism a chain of one-block members has (see `ahead`).
    /// It is fed by whoever walks the chain and is empty until it is.
    #[cfg(feature = "parallel")]
    ahead: ahead::Ahead,
    /// The floor a member CONTINUING the chain takes the tape path from,
    /// when the lever is on ([`SOLID_TAPE_ENV`]); `None` is the carried
    /// floor for every member.
    #[cfg(feature = "parallel")]
    chain_tape_floor: Option<u64>,
    /// Members decoded since the stream began or was last reset: a member
    /// that finds this above zero continues a solid chain.
    chain_members: u64,
    /// Whether the member being decoded continues a chain.
    continuing: bool,
    /// THE STAGE PROBE'S ONE DIAL: with this set, the apply stage does
    /// nothing at all, so a timed run prices the plan, the lanes and the
    /// hand-off with the apply stage subtracted out. Behind its own
    /// feature and never `bench-internals`, so no benchmark binary compiles the
    /// branch into a function it calls.
    #[cfg(all(feature = "parallel", feature = "h2-stage-probe"))]
    probe_no_apply: bool,
    /// THE STAGE PROBE'S SECOND DIAL: how deep each lane's hand-off
    /// channel is. One is what ships, and it is the bound API 8.2 is read
    /// against - lane `k` then holds at most the tape it is filling and
    /// the tape it has handed over, so `2 * lanes` tapes are alive inside
    /// 8.2's `4 * W`. A depth of two lets a lane that finished early run
    /// one block further ahead, which is the candidate for the 4 to 6
    /// percent of apply-thread samples the 21 Sep apply work measured
    /// BLOCKED IN `recv`; it puts `3 * lanes` tapes alive, still inside
    /// `4 * W`. This is a DIAL for pricing that candidate by subtraction,
    /// not a change: nothing outside the probe feature can move it.
    #[cfg(all(feature = "parallel", feature = "h2-stage-probe"))]
    probe_channel_depth: usize,
}

/// What a member's WIDTH is priced against (SPEC-API 8.4.1, the account
/// per width): under a NAMED budget, the lesser of the WHOLE limit and
/// TWICE what the limit leaves beside this member's ring and the fixed
/// part.
///
/// A member whose ring is half the limit or less is priced against the
/// whole limit, which is what a named budget always did for the members
/// it admitted: the same lanes, the same unit, the same look-ahead share.
/// A member whose ring is over half the limit, which a named budget
/// refused until the account was stated per width, is priced against
/// less as its ring nears the limit, and at the limit against nothing: a
/// width of one, which holds no tape. A default budget is an allowance
/// nobody chose and is priced whole, as it was.
///
/// The first form priced every member against what its ring left and
/// never against the whole limit. That narrowed members a budget had
/// always run wide: a 4 GiB member of a 16 MiB window under the tool's
/// `-mm128m` went from six lanes to four and tested 6 percent slower on
/// an M5 Ultra, at the same 54 MiB peak (13 Oct 2026).
///
/// **What this does not promise.** A lane's price is a bound on its tape
/// buffers and not what they hold, and for a member priced against the
/// whole limit the ring and the lanes AT THEIR BOUNDS can still come to
/// more than the limit, as they always could. The cap is held by what the
/// process holds, which the tool's tests measure; whether tapes ever near
/// their bound on a genuine member is a count owed before anything is
/// narrowed again.
#[cfg(feature = "parallel")]
fn width_room(policy: &MemoryPolicy, window: u64) -> u64 {
    if !policy.limit_named {
        return policy.working_limit;
    }
    let ring = ring_len(window, policy.max_window).map_or(window, |n| n as u64);
    let left = policy
        .working_limit
        .saturating_sub(ring)
        .saturating_sub(policy.read_ahead)
        .saturating_sub(WIDTH_FIXED);
    policy.working_limit.min(left.saturating_mul(2))
}

/// What [`width_room`] answers, pinned.
#[cfg(all(test, feature = "parallel"))]
mod width_room_tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    fn lanes(limit: u64, window: u64) -> usize {
        tape::lanes_within_budget(width_room(&MemoryPolicy::from_limit(limit), window))
    }

    /// A member whose ring is half the limit or less is one a budget
    /// admitted before the account per width, at the lanes the WHOLE
    /// limit pays for; it keeps them. A 16 MiB window under 96 MiB (the
    /// engine's limit under the tool's `-mm128m`) is six lanes, where a
    /// price against what the window left gave it four and a 4 GiB member
    /// tested 6 percent slower for it.
    #[test]
    fn a_member_a_budget_always_admitted_keeps_the_whole_limits_lanes() {
        assert_eq!(tape::lanes_within_budget(96 * MIB), 6);
        assert_eq!(lanes(96 * MIB, 16 * MIB), 6);
        assert_eq!(lanes(96 * MIB, 4 * MIB), 6);
        assert_eq!(
            lanes(512 * MIB, 128 * MIB),
            tape::lanes_within_budget(512 * MIB)
        );
    }

    /// A ring over half the limit is narrowed, down to a width of one as
    /// it nears the limit; a default budget is priced whole.
    #[test]
    fn a_ring_over_half_the_limit_is_narrowed_down_to_one() {
        assert!(lanes(96 * MIB, 64 * MIB) < tape::lanes_within_budget(96 * MIB));
        assert_eq!(lanes(32 * MIB, 16 * MIB), 1);
        assert_eq!(lanes(96 * MIB, 90 * MIB), 1);
        let default = MemoryPolicy::default();
        assert_eq!(width_room(&default, 64 * MIB), default.working_limit);
    }
}

/// [`MemoryPolicy::member_width`]: the lanes the budget leaves one member
/// of this window, or `None` where the member is not shared out at all.
pub(crate) fn member_width(policy: &MemoryPolicy, window: u64, unpacked: u64) -> Option<usize> {
    #[cfg(feature = "parallel")]
    {
        tape::shared_out(unpacked).then(|| tape::lanes_within_budget(width_room(policy, window)))
    }
    #[cfg(not(feature = "parallel"))]
    {
        let _ = (policy, window, unpacked);
        None
    }
}

/// The fixed part [`width_room`] sets aside: the decoder's tables and the
/// output buffers, which grow with neither the member, the window nor the
/// width. The read's own one-member floor uses the same megabyte.
#[cfg(feature = "parallel")]
const WIDTH_FIXED: u64 = 1 << 20;

impl Rar5Lz {
    /// How many filter records of each kind this stream has queued, and
    /// their bytes, for the untimed census.
    #[cfg_attr(not(feature = "bench-internals"), allow(dead_code))]
    pub(crate) fn filter_kinds(&self) -> ([u64; 4], [u64; 4]) {
        (self.filters.kinds, self.filters.kind_bytes)
    }

    /// Turn the untimed harness's filter-span capture on, and forget any
    /// spans already held. Only `internals_h2::x86_filter_blocks` calls
    /// this; see `filters::Filters::capture`.
    #[cfg_attr(not(feature = "bench-internals"), allow(dead_code))]
    pub(crate) fn capture_filter_spans(&mut self) {
        self.filters.capture = true;
        self.filters.captured.clear();
    }

    /// The spans captured since the last [`Self::capture_filter_spans`]:
    /// `(member relative start, length, kind slot)`.
    #[cfg_attr(not(feature = "bench-internals"), allow(dead_code))]
    pub(crate) fn captured_filter_spans(&self) -> &[(u64, u32, u8)] {
        &self.filters.captured
    }

    /// How many batches of filter transforms the drain handed to the pool.
    #[cfg(all(feature = "parallel", feature = "bench-internals"))]
    pub(crate) fn filter_batches_sealed(&self) -> u64 {
        self.filters.batches_sealed()
    }

    /// What this stream's drain path has copied, for the untimed census.
    #[cfg_attr(not(feature = "bench-internals"), allow(dead_code))]
    pub(crate) fn drain_counts(&self) -> crate::rar5_lz::output::DrainCounts {
        self.window.drain_counts()
    }

    /// The width this decoder's tape lanes may spread over, from
    /// `ReadOptions::workers` (API 8.4.2). A ceiling and never a demand:
    /// the size floor, the blocks a chunk actually has and the lane
    /// budget each lower it further.
    pub(crate) fn set_tape_width(&mut self, width: usize) {
        // 8.4.2's precedence, in one line: the dial, lowered by the budget
        // wherever the bytes force it and no further. Never below one, so
        // a budget too small for even one lane still decodes, serially,
        // rather than refusing (8.2: running narrower is in contract).
        self.max_workers = width.max(1).min(self.budget_lanes).max(1);
        self.width_one = width <= 1;
        #[cfg(feature = "parallel")]
        self.ahead.set_width(self.max_workers);
    }

    /// The member about to be decoded carries no checksum, neither a
    /// CRC32 field nor a hash record. It holds for that one member.
    pub(crate) fn next_member_is_unchecked(&mut self) {
        self.unchecked = true;
    }

    /// Whether the width `set_tape_width` last set was STATED by the
    /// caller (`ReadOptions::workers`) or is the engine's default.
    pub(crate) fn set_width_stated(&mut self, stated: bool) {
        self.width_stated = stated;
        #[cfg(feature = "parallel")]
        {
            self.tape_grow = match (stated, self.tape_grow) {
                (true, _) => None,
                (false, Some(width)) => Some(width),
                (false, None) => tape::default_width(),
            };
        }
    }

    /// The lanes this decoder's solid-chain decode-ahead OPENS with, when
    /// the read path has a policy for them apart from the tape width
    /// (`read::lanes::ahead_lanes`). The stage may grow from there, one
    /// lane at a time while its apply stage keeps waiting, up to what
    /// `set_tape_width` last allowed, so the budget still bounds it; call
    /// it after that. `lanes` equal to that width is a stage that opens
    /// every lane at once and never grows, which is what it was before.
    #[cfg(feature = "parallel")]
    pub(crate) fn set_ahead_lanes(&mut self, lanes: usize) {
        self.ahead.set_lanes(lanes, self.max_workers.max(1));
    }

    /// Share this operation's lane budget, or take the width outright.
    #[cfg(feature = "parallel")]
    pub(crate) fn set_lane_budget(&mut self, budget: Option<Arc<crate::read::lanes::LaneBudget>>) {
        self.budget = budget;
    }

    /// A decoder with a window of `window` bytes.
    pub(crate) fn new(window: u64, policy: &MemoryPolicy) -> Result<Rar5Lz> {
        Rar5Lz::with_reach(window, window, policy)
    }

    /// Give the ring's pages back to the kernel before this decoder is
    /// dropped or replaced (`crate::pages::release`). The
    /// decoder is not used again after it. Linux and macOS.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn release_ring(&mut self) {
        crate::pages::release(&mut self.window.ring);
    }

    /// A decoder for a stream that declares a `declared` byte dictionary
    /// and can produce at most `reach` bytes (SPEC-API 8.1, the 26 Sep
    /// 2026 erratum).
    ///
    /// The window is `min(declared, reach)`: no distance in a stream can
    /// exceed the bytes the stream has produced, so a window larger than
    /// the stream's own output is memory that is committed and zeroed and
    /// never read. The policy's ceiling is checked against that same
    /// figure, before any allocation, and a refusal names it as `needed`.
    /// The caller passes `reach == declared` wherever more output may
    /// follow in the same window (a solid archive's chain), which is the
    /// rule of the declared dictionary exactly as it stood before.
    pub(crate) fn with_reach(declared: u64, reach: u64, policy: &MemoryPolicy) -> Result<Rar5Lz> {
        let window = declared.min(reach);
        if window > policy.max_window {
            return Err(crate::Error::new(crate::ErrorKind::LimitExceeded {
                resource: Resource::Window,
                needed: window,
                limit: policy.max_window,
            }));
        }
        // What the caller's memory budget affords this decoder's tape
        // lanes, read once here because `new` is where the policy is in
        // hand (API 8.4.1).
        #[cfg(feature = "parallel")]
        let room = width_room(policy, window);
        #[cfg(feature = "parallel")]
        let budget_lanes = tape::lanes_within_budget(room);
        #[cfg(not(feature = "parallel"))]
        let budget_lanes = 1usize;
        #[allow(unused_mut)]
        let mut lz = Rar5Lz {
            // The caller's own ceiling goes with the declared size, so
            // `RING_FLOOR` can never raise the ring above a budget that
            // was actually stated.
            window: Window::new(window, policy.max_window)?,
            current: None,
            spare: None,
            scratch: TableScratch::default(),
            filters: Filters::for_dictionary(window),
            state: MatchState::default(),
            algorithm: 0,
            // THE ENGINE'S OWN DEFAULT READ WIDTH, which is what a
            // caller who states no width gets (API 8.4.3): `None`
            // resolves to the width of the pool the caller owns, and
            // `crate::read::pool_width` is that same figure. The policy
            // is not asked for a WIDTH, because a memory budget is not a
            // thread count (8.4.2). It is still asked what the width may
            // COST, which is `budget_lanes` below and a different
            // question, and which lowers this default exactly as
            // `set_tape_width` lowers a stated one (8.4.2's precedence).
            //
            // It is a DEFAULT and not a floor. Until 20 Sep 2026 this
            // read `1`, on a comment claiming `set_tape_width` replaced
            // it "before the first member reaches it on any read path".
            // That was true of spec F's read path, whose `Decoders`
            // helper does set it per member, and false of the
            // `internals_h2` seam, which builds a decoder directly: every
            // H2 bench leg and test therefore decoded at tape width ONE,
            // correct in its bytes and serial in its threads. A default
            // that is the documented one costs a forgetful seam nothing;
            // a floor of 1 costs it every lane it has.
            max_workers: crate::read::pool_width().min(budget_lanes).max(1),
            budget_lanes,
            width_stated: false,
            unchecked: false,
            width_one: false,
            #[cfg(feature = "parallel")]
            tape_grow: tape::default_width(),
            parallel: ParallelMode::Auto,
            #[cfg(feature = "parallel")]
            tapes: tape::TapePool::default(),
            #[cfg(feature = "parallel")]
            waves: Vec::new(),
            #[cfg(feature = "parallel")]
            wave_blocks: None,
            #[cfg(feature = "parallel")]
            tape_unit: None,
            #[cfg(feature = "parallel")]
            working_limit: room,
            #[cfg(feature = "parallel")]
            budget: None,
            #[cfg(feature = "parallel")]
            overlap: true,
            // `Window::new` above has already refused a size that does not
            // fit a `usize`.
            #[cfg(feature = "parallel")]
            declared: usize::try_from(window).unwrap_or(usize::MAX),
            #[cfg(feature = "parallel")]
            plan: tape::Plan::default(),
            // THE CALLER'S OWN BUDGET, never a constant: a
            // stated memory budget is hard, and this stage is the one term
            // that grows with the members held ahead rather than with the
            // width.
            #[cfg(feature = "parallel")]
            ahead: {
                // Bound to a name and returned, as the wide stage's removal
                // found it: the shipped code generation of this
                // constructor is left exactly as it was.
                #[allow(clippy::let_and_return)]
                let stage = ahead::Ahead::new(
                    ahead::bytes_within_budget(room),
                    crate::read::pool_width().min(budget_lanes).max(1),
                );
                stage
            },
            #[cfg(feature = "parallel")]
            chain_tape_floor: solid_tape().then(solid_tape_floor),
            chain_members: 0,
            continuing: false,
            #[cfg(all(feature = "parallel", feature = "h2-stage-probe"))]
            probe_no_apply: false,
            #[cfg(all(feature = "parallel", feature = "h2-stage-probe"))]
            probe_channel_depth: 1,
        };
        // THE FAR PREFETCH'S DICTIONARY FLOOR, a property of the stream:
        // its plans and its decode-ahead's plans all carry it to the lanes.
        #[cfg(feature = "parallel")]
        {
            let far_off = lz.window.far_off();
            lz.plan.far_off = far_off;
            lz.ahead.set_far_off(far_off);
        }
        Ok(lz)
    }

    /// Drop the window, the repeated distances, the last length, the
    /// pending filters and the table set in force; keep the allocation.
    ///
    /// This is a member with its solid bit CLEAR in a solid archive
    /// (spec F 3.6), or any member of a non-solid one: a fresh stream
    /// (section 3.7).
    ///
    /// **The decode-ahead queue is KEPT.** Everything in it was offered by
    /// the cursor walking in front of this member, so it lies BEHIND the
    /// chain break, not before it; the cursor never offers a member with
    /// its bit clear and breaks the run there (`read::ahead`), so no run
    /// carries a table set across the break; and a tape depends only on
    /// the tables in force for its block, never on the window or the
    /// repeated distances (section 3.8), so the fresh window takes those
    /// tapes exactly as the old one would have. Each is still claimed only
    /// on an exact match of its packed bytes. Clearing it here would throw
    /// away the next chain's head start at every chain break of a `-s<N>`
    /// set, which the decode-ahead kept before RAR 5 chain breaks reset at
    /// all (27 Sep 2026).
    pub(crate) fn reset(&mut self) {
        self.window.reset();
        self.state = MatchState::default();
        self.filters.clear();
        self.release_tables();
        self.chain_members = 0;
    }

    /// `[ignored, refused]`: records this decoder ignored for being longer
    /// than 4 MiB, and kept spans it refused for being `W` or longer
    /// (section 3.6, "Long records"), for the `internals` seam.
    #[cfg(feature = "bench-internals")]
    pub(crate) fn long_filter_records(&self) -> [u64; 2] {
        self.filters.long_records
    }

    /// Bytes held back from the sink for pending filters.
    // Live in the `cfg(test)` build only: this package's own tests are its
    // one caller.
    #[allow(dead_code)]
    pub(crate) fn held_bytes(&self) -> u64 {
        self.window.held_bytes()
    }

    /// Force the parallel block decode on or off for this stream, which
    /// the differential test of section 5.5, the fuzz target and the
    /// `rar5_serial_vs_parallel` bench leg use. Forcing it ON ignores the
    /// carried size floor, so a small member takes the tape path too.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub(crate) fn set_parallel(&mut self, parallel: bool) {
        self.parallel = if parallel {
            ParallelMode::On
        } else {
            ParallelMode::Off
        };
    }

    /// Force the blocks in one wave, which the tests and the
    /// `rar5_wave_overlap` bench leg use: the default is twice the worker
    /// count, and a vector archive has too few blocks for that to cross a
    /// wave boundary at all. It is a scheduling decision and must not
    /// change a byte, which is what
    /// `every_wave_length_and_worker_count_gives_the_same_bytes` asserts.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[cfg(feature = "parallel")]
    #[allow(dead_code)]
    pub(crate) fn set_wave_blocks(&mut self, blocks: Option<usize>) {
        self.wave_blocks = blocks;
    }

    /// Force the packed bytes one tape unit may span; `Some(0)` gives one
    /// block a unit, the per-block form. Scheduling only: it must not
    /// change a byte, which `tests/rar5_tape_unit.rs` asserts.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[cfg(feature = "parallel")]
    #[allow(dead_code)]
    pub(crate) fn set_tape_unit(&mut self, bytes: Option<usize>) {
        self.tape_unit = bytes;
    }

    /// Force the overlap off, which is the wave at a time driver, or on.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[cfg(feature = "parallel")]
    #[allow(dead_code)]
    pub(crate) fn set_overlap(&mut self, overlap: bool) {
        self.overlap = overlap;
    }

    /// Every tape this decoder is holding once a member has finished, for
    /// the bound of `the_tapes_in_flight_are_bounded_by_the_lanes`.
    ///
    /// A member gives every tape back before it returns, so after one this
    /// is the high-water mark of the tapes that were alive at once: two
    /// per lane, which is inside API section 8.2's `4 * W`. A third per
    /// lane would mean the hand-over had stopped bounding them.
    #[cfg(all(test, feature = "parallel"))]
    pub(crate) fn tapes_held(&self) -> usize {
        self.tapes.len() + self.waves.iter().map(Vec::len).sum::<usize>()
    }

    /// The most the chain's decode-ahead has held at once, which the
    /// operation's reported peak carries beside the window (API 5.2).
    #[cfg(feature = "parallel")]
    pub(crate) fn ahead_peak_bytes(&self) -> u64 {
        self.ahead.peak_bytes()
    }

    /// The window's allocation, for the memory test of section 4.2.
    pub(crate) fn window_bytes(&self) -> usize {
        self.window.ring_bytes()
    }

    /// Hand the current table set's allocation back, so the next set
    /// reuses it rather than allocating.
    fn release_tables(&mut self) {
        if let Some(previous) = self.current.take() {
            if let Ok(tables) = Arc::try_unwrap(previous) {
                self.spare = Some(tables);
            }
        }
    }

    /// Read a block's tables into a fresh set, reusing the spare.
    fn read_tables(&mut self, bits: &mut BitReader<'_>) -> Result<()> {
        let mut tables = self.spare.take().unwrap_or_default();
        let outcome = tables.read(bits, self.algorithm, &mut self.scratch);
        match outcome {
            Ok(()) => {
                self.release_tables();
                self.current = Some(Arc::new(tables));
                Ok(())
            }
            Err(err) => {
                self.spare = Some(tables);
                Err(err)
            }
        }
    }

    /// Read the table set of every block a zero byte member owns, and
    /// decode every symbol those blocks carry into the window and the
    /// repeat state with no output, so the set its writer left in force,
    /// the window's end and the repeats are the ones the next member of
    /// the chain starts under (see [`Rar5Lz::member`], and SPEC-H2 3.1's
    /// zero byte paragraph as reconciled on 28 Sep 2026).
    ///
    /// A member that owes no bytes cannot be failed by them: its output is
    /// the empty output whatever its blocks hold. A block whose HEADER or
    /// TABLES do not read DROPS the set in force instead, so a member
    /// after it that leans on the carried set fails with `EmptyTable`
    /// rather than decoding under a set its writer did not mean. A SYMBOL
    /// that fails does not: it ends its block and the set is kept.
    fn carry_empty_member_tables<P: PackedSource, S: LzSink>(
        &mut self,
        packed: &mut P,
        sink: &mut S,
    ) {
        if self.read_empty_member_tables(packed, sink).is_err() {
            self.release_tables();
        }
    }

    /// [`Rar5Lz::carry_empty_member_tables`] with `?` on every read.
    fn read_empty_member_tables<P: PackedSource, S: LzSink>(
        &mut self,
        packed: &mut P,
        sink: &mut S,
    ) -> Result<()> {
        loop {
            packed.fill(MAX_BLOCK_HEADER)?;
            if packed.available().is_empty() {
                return Ok(());
            }
            let want = block::extent_hint(packed.available());
            packed.fill(want)?;
            let block = block_in_hand(packed.available())?;
            let available = packed.available();
            if available.len() < block.past() {
                return Err(fault::truncated());
            }
            let payload = block.payload(available);
            let mut bits = BitReader::new(payload, block.bits());
            if block.carries_tables() {
                self.read_tables(&mut bits)?;
            }
            // THE SYMBOLS THE BLOCK CARRIES, applied as any member's are
            // past its declared end: the blocks genuine rar writes here
            // carry tables and no symbol, and this is then not reached.
            // The declared size is zero, so the window's drain hands the
            // sink nothing.
            //
            // A SYMBOL THAT FAILS ENDS ITS BLOCK (SPEC-H2 3.1, the bullet
            // of 4 Oct 2026, measured on the reference): the symbols
            // before it stay applied, nothing after it in the block is,
            // the member passes, its NEXT block is still decoded and the
            // set in force is KEPT, because the tables did read. A block
            // with its table bit clear and no set in force is the same
            // case, `EmptyTable` at a symbol read. A kept filter record is
            // not this: it fails the member `FilterRange` through the
            // filter queue, as for any member, and decodes on. Only an
            // error that is not the stream's own (the sink's) leaves here.
            if !bits.at_end() {
                if let Some(tables) = self.current.clone() {
                    let decoded = decode_block(
                        &tables,
                        &mut self.state,
                        &mut self.window,
                        &mut self.filters,
                        &mut bits,
                        0,
                        sink,
                    );
                    match decoded {
                        Err(err)
                            if !matches!(
                                err.kind(),
                                crate::ErrorKind::Corrupt(_) | crate::ErrorKind::Truncated
                            ) =>
                        {
                            return Err(err)
                        }
                        _ => {}
                    }
                }
            }
            packed.advance(block.past());
            if block.ends_member() {
                return Ok(());
            }
        }
    }

    /// A block's decode, with ONE outcome past the member's declared end
    /// answered as the block's end rather than as a failure.
    ///
    /// SPEC-H2 3.1 (measured 28 Sep 2026): once the member's output is
    /// complete, a symbol, or its extra bits, CUT by its block's end ENDS
    /// the block, applying nothing, and the member passes on its checksum.
    /// Before the declared end the same cut leaves the member short, which
    /// is `IncompleteMember`. That is `Truncated` from inside a block: a
    /// packed stream that runs out between blocks is the block walk's.
    /// The old engine's fixture `rar50/solid_match_overruns_member.rar`
    /// ends `m1.bin`'s one block with 4 bits that are no whole code, 4
    /// bytes past its declared 37, and reference unrar 7.23 passes it.
    /// A PINNED DIFFERENCE remains: the reference completes the cut symbol
    /// with bits from beyond the block, which the format does not define,
    /// so a solid successor that reads that symbol's bytes may differ; no
    /// genuine writer is known to end a block that way.
    ///
    /// A SYMBOL THAT FAILS there is answered the same way (3.1, "A symbol
    /// that FAILS past the declared end", 8 Oct 2026, measured on the
    /// reference): it ends its block, the symbols before it stay applied,
    /// the member's next block is still decoded, the set in force is
    /// kept and the member passes on its checksum, every declared byte
    /// delivered. Before the declared end it fails the member under its
    /// own name. Every arm's block failure comes through here, the tape
    /// path's deferred one included, so the arms cannot differ in it.
    fn surplus_tail(&self, outcome: Result<()>, unpacked: u64) -> Result<()> {
        match outcome {
            Err(err) if matches!(err.kind(), crate::ErrorKind::Truncated) => {
                if self.window.produced() >= unpacked {
                    Ok(())
                } else {
                    // BEFORE the declared end the same cut leaves the
                    // member short, which is `IncompleteMember` (3.1).
                    Err(fault::incomplete_member())
                }
            }
            Err(err) if self.window.produced() >= unpacked && ends_a_block(&err) => Ok(()),
            other => other,
        }
    }
}

/// Whether `err` is a SYMBOL's failure, one of the names SPEC-H2 3.1
/// gives for a symbol met past a member's declared end: a bit pattern
/// with no code, a table with no code at a symbol read, a slot off its
/// ladder, and a repeat of a distance never set. A filter type no
/// transform has is not among them: it is never raised past the
/// declared end (3.6, `Filters::push`). A kept filter record's range is
/// not one of them either (it is the filter
/// queue's, at the member's end), nor is a distance, which past the
/// declared end copies zeros (3.1).
///
/// Out of line and cold: it is asked only of a block that failed.
#[cold]
#[inline(never)]
fn ends_a_block(err: &crate::Error) -> bool {
    use crate::Rar5Fault as Fault;
    matches!(
        err.kind(),
        crate::ErrorKind::Corrupt(crate::Corruption::Rar5(
            Fault::InvalidCode
                | Fault::EmptyTable
                | Fault::LengthSlot
                | Fault::DistanceSlot
                | Fault::UninitialisedRepeat
        ))
    )
}
