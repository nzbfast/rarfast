//! The window and the streaming output (SPEC-H2 sections 3.7 and 4.2).
//!
//! The window is a RING of the declared dictionary size plus [`SPILL`]
//! bytes, indexed by a write point that is kept rather than masked; nothing
//! is memmoved, nothing grows and nothing shrinks within a stream (section
//! 7.3 item 8), and the window is the only part of this package's memory
//! that scales with the archive (4.2).
//!
//! WHY THE RING IS NOT EXACTLY THE DICTIONARY. The short match copy writes
//! whole 16 byte strides, so it spills up to 15 bytes past a match's end,
//! and in a full ring the slots just ahead of the write point hold the
//! OLDEST bytes. With a ring of exactly the dictionary those are the bytes
//! a distance at or just short of the dictionary size names (section 3.7),
//! and a later match from that far back read the spill: wrong bytes and no
//! error (found 18 Sep 2026 by the H3 follow-up). The
//! first fix, 19 Sep, made the copy write exactly `length` bytes, which is
//! right and which cost every leg 9% to 40% of its wall in the branches of
//! a length ladder on the hottest path there is. With `SPILL` more slots
//! than the dictionary, the oldest `SPILL` bytes of the ring are further
//! back than any distance `copy_match` admits, so the spill lands where
//! nothing can look and the copy pays nothing for it.
//!
//! The ring holds the UNFILTERED bytes (section 3.6): a later match reaching
//! into a filtered span reads what the LZ decoder wrote there. Filtered
//! bytes are produced into a scratch buffer on the way to the sink and are
//! never written back.
//!
//! Implemented from `specs/SPEC-H2-rarkit-rar5-lz.md` alone.

use std::collections::VecDeque;

use super::fault;
use crate::carry::c_lz::codec::rar50::{
    flat_literal_ladder, FLAT_EMIT_THRESHOLD, LITERAL_INLINE_MAX,
};
use crate::Result;

/// The longest a single decoded operation can append: a match length of at
/// most 4,100 (section 4.1). A literal run from a tape can be longer and
/// the apply stage cuts it to [`Window::drain_batch`].
// Live in the `cfg(test)` build only: this package's own tests are its
// one caller.
#[allow(dead_code)]
pub(crate) const MAX_APPEND: usize = 4_100;

/// The smallest ring CORRECTNESS needs. RAR 5 declares its dictionary as
/// `131,072 << n`, so no archive asks for less; the floor is here so the
/// drain cadence - half a ring - always leaves room for a whole operation
/// on top of it, whatever a caller passes.
pub(crate) const MIN_RING: usize = 1 << 16;

/// The smallest ring SPEED wants, and the two are kept apart on purpose so
/// a reader can tell which part of the number a byte of output depends on.
///
/// [`Window::copy_match`] takes its stride ladder only while
/// `distance <= at`, which is exactly "the match's source does not wrap the
/// ring's end"; `at` is the ring index, so for a match of distance `d` that
/// guard fails on `d / ring_len` of the write positions. On a ring of
/// exactly a 128 KiB dictionary a distance may be almost the whole ring, so
/// it fails constantly and every failure falls to [`Window::copy_match_slow`],
/// which loops and reaches a `memmove` libcall for a copy that averages under
/// seven bytes. Measured on `rar5_text_64m_m5_md128k`, 21 Sep 2026: that cold
/// path is 31 percent of the one apply thread there and under 1 percent on
/// `rar5_text_64m_m5_md256m`, the same material at the same level, and the
/// same member decoded through a larger ring with its operations and its
/// distances untouched runs 1.52x faster. The same floor returns the drain
/// cadence to the carried [`FLAT_EMIT_THRESHOLD`] instead of half a small
/// ring, which is a second, smaller term.
///
/// (Since 23 Sep 2026 the stride ladder also takes a wrapped source whose
/// reach ends inside the ring, so the guard above fails only for a source
/// within `STRIDE_MAX` behind the ring's start; the floor was priced
/// against the older guard and is kept on its own measurement, the drain
/// cadence term included.)
///
/// **It moves no byte and no error, and that is the whole of why it is
/// allowed to exist.** [`Window::limit`] stays the DECLARED dictionary, so
/// every distance keeps exactly the legality it had; SPEC-H2 4.2's erratum
/// sizes the window as "the declared size PLUS A SMALL CONSTANT MARGIN ... a
/// constant the implementation adds on top", with `MemoryPolicy::max_window`
/// checked against the DECLARED size, so a constant floor is the shape that
/// section already describes. A stream whose dictionary is at or above it
/// allocates exactly what it did before, which is every dictionary from 1 MiB
/// up and therefore every leg but the small-dictionary ones.
///
/// **It bounds the WHOLE ring, [`SPILL`] included** (since 27 Sep 2026):
/// a dictionary under it gets a ring of exactly `RING_FLOOR`, 64 bytes
/// less than the floor plus the margin it had before, and still at least
/// the declared size plus [`SPILL`]. A power-of-two ring lets the wide
/// gather's direct form take a name across the ring's end with a mask
/// (`gather_direct`) instead of a compare, a select and a bounds check.
pub(crate) const RING_FLOOR: usize = 1 << 20;

/// The least a window reaches back, whatever dictionary the header
/// declares (SPEC-H2 3.7, as amended on 11 Oct 2026): with `D` the declared
/// dictionary, a match is honoured at every distance up to the larger of
/// `D` and this, and gives zero bytes beyond it. It is a property of the
/// FORMAT's readers, measured on the genuine programs, and not a speed
/// constant: it moves bytes, where [`RING_FLOOR`] moves none.
pub(crate) const WINDOW_FLOOR: usize = 256 << 10;

/// Where one member's bytes go. The LZ decoder never sees the caller's
/// `Sink`; spec F wires that.
pub(crate) trait LzSink {
    /// Take the next bytes of the member, in order.
    fn put(&mut self, bytes: &[u8]) -> Result<()>;
}

impl LzSink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

/// A sink that passes on its first `left` bytes and drops the rest: how
/// [`Window::drain`] keeps a member's output at its declared size while a
/// filter span that straddles it is run whole. Dynamic on purpose: it is
/// built for such a member only, and one copy of the drain serves it
/// whatever the sink.
struct Capped<'a> {
    sink: &'a mut dyn LzSink,
    left: u64,
}

impl LzSink for Capped<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let take = self.left.min(bytes.len() as u64) as usize;
        self.left -= take as u64;
        if take == 0 {
            return Ok(());
        }
        self.sink.put(&bytes[..take])
    }
}

/// A sink that counts and drops, for the test legs and the `t` command.
// Reached only through the `internals_*` seam, behind the
// `bench-internals` feature; no shipped build enables it.
#[allow(dead_code)]
pub(crate) struct NullSink {
    pub(crate) bytes: u64,
}

impl LzSink for NullSink {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.bytes += bytes.len() as u64;
        Ok(())
    }
}

/// The window, the stream's byte count and the emission cursor.
pub(crate) struct Window {
    /// `pub(crate)` for `Rar5Lz::release_ring` alone, which
    /// lives in the parent module so that no function is added here: one
    /// added in this file re-partitions `put_symbols` (the
    /// md128k partition finding).
    pub(crate) ring: Vec<u8>,
    /// The ring index the next byte is written at, always below the ring's
    /// length. `pub(crate)` for the one-pass region alone (`super::onepass`),
    /// which writes the ring directly and hands the write point back.
    pub(crate) at: usize,
    /// Stream bytes produced up to the ring's slot 0 on this lap, so the
    /// STREAM's byte count, across a solid chain, is `lap_base + at`.
    pub(crate) lap_base: u64,
    /// How far back a match is honoured: the declared dictionary size, or
    /// [`WINDOW_FLOOR`] where that is larger (section 3.7). A distance past
    /// it gives zero bytes even though the ring, `SPILL` longer and maybe
    /// floored, still holds a byte there.
    pub(crate) limit: usize,
    /// Where the current member started in the stream.
    member_base: u64,
    /// How many of the member's bytes reach its OUTPUT: its declared size
    /// (SPEC-H2 3.1). The member DECODES past it, into the ring and the
    /// repeat state, and none of that surplus is drained. `u64::MAX`, the
    /// default a member starts with, caps nothing.
    output: u64,
    /// Member bytes already sent to the sink.
    ///
    /// `u64`, not `usize`: a RAR 5 member may declare an unpacked size of
    /// more than 4 GiB, so on a 32-bit target a member-relative count does
    /// not fit a `usize` (section 3.1).
    emitted: u64,
    /// Member bytes copied out of the ring for a pending filter, starting
    /// at `emitted`. Empty whenever no filter is pending.
    hold: Vec<u8>,
    /// Scratch for one filter's output.
    filtered: Vec<u8>,
    /// How much output accumulates before a batch goes to the sink.
    emit_batch: usize,
    /// What the drain path has copied, for the untimed census
    /// (`examples/h2_drain_census.rs`). Counted per COPY and not per byte,
    /// so a member pays a handful of adds for the whole census.
    counts: DrainCounts,
    /// The member offset the next drain is due at. `u64` for the reason
    /// [`Window::emitted`] gives.
    ///
    /// The cadence belongs to the MEMBER and not to a block: a member is a
    /// chain of blocks and the reference writer cuts a fresh table set
    /// every few hundred kilobytes, so a cadence restarted per block never
    /// comes due and the ring laps what has not left it.
    next_drain: u64,
    /// What earlier drains accounted for and have not yet put, in member
    /// order and contiguous from `emitted`: `(start, end, handed)`, where
    /// `handed` is a span whose transform was handed away and otherwise
    /// the range is still in the ring. Empty unless the filter queue
    /// offloads (`FilterQueue::offload`).
    handed: VecDeque<(u64, u64, bool)>,
    /// How many copies took [`Window::copy_match_slow`], in test builds
    /// only, so a test can pin WHICH path an edge case takes and not only
    /// the bytes it produced: a fast path narrowed back to the slow one
    /// produces the same bytes and only the count can see it.
    #[cfg(test)]
    slow_copies: u64,
}

/// Bytes each of [`Window::drain`]'s paths moves, counted rather than
/// timed: a count is a property of the stream and reads the same on every
/// machine. `hold_memmove` is what `Vec::drain` shifts down after a span is
/// served out of the hold, which is quadratic in the spans one batch holds.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct DrainCounts {
    pub(crate) drains: u64,
    pub(crate) ring_direct: u64,
    pub(crate) ring_to_scratch: u64,
    pub(crate) ring_to_hold: u64,
    pub(crate) hold_to_sink: u64,
    pub(crate) hold_to_scratch: u64,
    pub(crate) hold_memmove: u64,
    pub(crate) spans_fast: u64,
    pub(crate) spans_held: u64,
}

/// The widest match the stride ladder takes. Past it the slow path's loop
/// is the better shape, and a match that long is rare.
pub(crate) const STRIDE_MAX: usize = 64;
/// The ladder's stride, and the least distance it runs at: a stride reads
/// bytes that landed at least one stride earlier, so an overlapping match
/// at a distance of at least this still reads what it has already written,
/// which is the byte at a time result section 3.7 asks for.
pub(crate) const STRIDE: usize = 16;

/// How many slots the ring has beyond the declared dictionary. The stride
/// copy spills at most `STRIDE - 1` bytes past a match's end (see the
/// module comment); the margin is a whole fast match, so it does not rest
/// on the stride ladder's arithmetic.
pub(crate) const SPILL: usize = STRIDE_MAX;

/// How many slots past a match the write side guard watches, in test
/// builds. WIDER THAN [`SPILL`] on purpose: the first `SPILL` slots are
/// unreachable by construction on this ring, so a watch only that wide
/// could never fail and would prove nothing. The slots past the margin
/// are reachable, and a copy that outgrows the margin has to fail there.
#[cfg(debug_assertions)]
const SPILL_WATCH: usize = STRIDE_MAX + SPILL;

/// Copy `length` bytes at `pos` from `src` in WHOLE strides, at
/// most four, spelled out so the common path carries no loop backedge and
/// no branch on the length's low bits. It writes up to `STRIDE - 1` bytes
/// past `pos + length`, and reads as far past the source's end; the caller
/// keeps `pos + STRIDE_MAX` inside the ring, and [`SPILL`] is why the
/// bytes written past the end are nobody's source. Each stride reads what
/// the one before it landed, which keeps an overlapping match exact for
/// `distance >= STRIDE`.
///
/// `src` is the source's ring index, which the caller has already taken
/// across the ring's start for a wrapped match ([`Window::copy_match`]).
///
/// **NO STRIDE IS `copy_within`** (the first two since 2 Oct 2026:
/// [`stride_inside`]).
///
/// **THE THIRD AND FOURTH STRIDES ARE AN ARRAY READ AND A STORE, NOT
/// `copy_within`.** `copy_within` checks its range through core's
/// `slice::index::range`, a generic whose inlining is the compiler's
/// choice at each site. For the first two strides it was taken in every
/// build read until 2 Oct 2026, and each compiled to one 16 byte load and
/// one store. For the
/// last two it was declined in every shipped serial `decode_block`: each
/// became a call to the range check and a 16 byte `memmove` call, with
/// seven registers spilled and reloaded around each, and only a bench
/// build that happened to inline it had the loop without them. The array
/// form leaves nothing to decline, and the serial loop compiles to that
/// lean shape in every build: 7 percent fewer instructions in the
/// function, 5.6 to 8.7 percent fewer retired on the four serial rows
/// (24 Sep 2026, the serial shape).
///
/// **Measured and declined:** all four strides in [`stride_at`]'s form. It
/// cost the serial loop stores the first two strides did not need, and the
/// apply walk 0.5 to 1.2 percent more instructions on every parallel row
/// (and again on 2 Oct 2026: 1.5 percent on the serial rows).
#[inline(always)]
pub(crate) fn stride_copy(ring: &mut [u8], pos: usize, src: usize, length: usize) {
    stride_inside(ring, pos, src);
    if length > STRIDE {
        stride_inside(ring, pos + STRIDE, src + STRIDE);
        if length > 2 * STRIDE {
            stride_at(ring, pos + 2 * STRIDE, src + 2 * STRIDE);
            if length > 3 * STRIDE {
                stride_at(ring, pos + 3 * STRIDE, src + 3 * STRIDE);
            }
        }
    }
}

/// A fast match's whole source, [`STRIDE_MAX`] bytes, read before any
/// byte is written, then written: for a source at least `STRIDE_MAX` back,
/// where no byte read is one this copy writes, so the result is
/// [`stride_copy`]'s. It writes up to `STRIDE_MAX - 2` bytes past a match
/// of two or more, which the ring's [`SPILL`] margin holds as it holds
/// `Window::literals_padded`'s fixed width.
#[inline(always)]
fn wide_copy(ring: &mut [u8], pos: usize, src: usize) {
    let chunk: [u8; STRIDE_MAX] = ring[src..src + STRIDE_MAX]
        .try_into()
        .expect("a range of STRIDE_MAX is STRIDE_MAX long");
    ring[pos..pos + STRIDE_MAX].copy_from_slice(&chunk);
}

/// One of [`stride_copy`]'s FIRST TWO strides: `STRIDE` bytes from `src`
/// to `pos`, both ends checked ONCE against the ring's length and the
/// bytes then read whole into an array before any is written, which is a
/// 16 byte `memmove`'s own rule, so the bytes are `copy_within`'s.
///
/// **Why not `copy_within`, which these two strides were until 2 Oct
/// 2026.** Its range check is core's `slice::index::range`, a generic the
/// compiler may leave out of line at any site (the note on
/// [`stride_copy`]). In two of two release-pgo draws of a tree whose read
/// pool decodes members side by side it did, for these two strides, inside
/// the serial `decode_block`: a call to the range check and three small
/// bodies beside it, 10 to 12 percent more instructions wherever a member
/// decodes on one thread (1 Oct
/// 2026: 42.66 G against 47.65 and 46.76 G on 41 large
/// members at `-mt2`), while the plain build and the parent's draw kept it
/// inline. Nothing here is a call the compiler can decline.
///
/// **Why not [`stride_at`], which the third and fourth strides are.** That
/// form checks each of its two ranges on its own, four compares a stride;
/// on the first two strides, which every match takes, it reads 1.5 percent
/// more instructions on the serial rows (counted again on 2 Oct; the note
/// on [`stride_copy`] records the same of 24 Sep). The one `assert!` here
/// is two compares against a length the loop holds in a register, after
/// which both ranges are known to be inside the ring: 0.9987 to 0.9996 of
/// the `copy_within` form on the serial and the parallel rows, plain build.
///
/// A `src` or `pos` that would run past the ring panics here, as
/// `copy_within` did; no caller can produce one ([`stride_copy`]).
#[inline(always)]
fn stride_inside(ring: &mut [u8], pos: usize, src: usize) {
    let len = ring.len();
    assert!(
        len >= STRIDE && src <= len - STRIDE && pos <= len - STRIDE,
        "a stride inside the ring"
    );
    let chunk: [u8; STRIDE] = ring[src..src + STRIDE]
        .try_into()
        .expect("a range of one stride is one stride long");
    ring[pos..pos + STRIDE].copy_from_slice(&chunk);
}

/// One of [`stride_copy`]'s third and fourth strides: `STRIDE` bytes from
/// `src` to `pos`, read whole into an array before any is written, which
/// is a 16 byte `memmove`'s own rule, so the bytes are the same.
#[inline(always)]
fn stride_at(ring: &mut [u8], pos: usize, src: usize) {
    let chunk: [u8; STRIDE] = ring[src..src + STRIDE]
        .try_into()
        .expect("a range of one stride is one stride long");
    ring[pos..pos + STRIDE].copy_from_slice(&chunk);
}

impl Window {
    /// A window of `declared` bytes, which bounds a distance; the ring is
    /// `SPILL` longer, and at least [`RING_FLOOR`] long in all (the spill
    /// counted in it) unless `ceiling` says otherwise.
    ///
    /// `ceiling` is the most the CALLER allowed, `MemoryPolicy::max_window`
    /// on the shipped path and `u64::MAX` where no budget was stated.
    /// [`RING_FLOOR`] is a speed constant and a stated
    /// memory budget comes first, so **the floor never raises the ring above the
    /// ceiling**: a caller who allows 128 KiB and meets a 128 KiB
    /// dictionary gets a 128 KiB ring and the slow copy back, which is the
    /// trade that caller asked for. SPEC-H2 4.2 puts the margin outside
    /// the ceiling and `SPILL` stays on top either way, being a
    /// CORRECTNESS margin rather than a speed one; `MIN_RING` likewise.
    pub(crate) fn new(declared: u64, ceiling: u64) -> Result<Window> {
        let ring_len = super::ring_len(declared, ceiling)?;
        let declared = usize::try_from(declared).map_err(|_| fault::window_too_large(declared))?;
        // The allocation is asked for FALLIBLY first, because a declared
        // dictionary is untrusted (section 4.2) and a ring the host cannot
        // map must answer an error rather than abort: SPEC-API 8.1 term
        // 4's `LimitExceeded { AddressSpace }`, since the policy allowed
        // it and the host refused it. The probe stays in front of the ring
        // even though the ring is fallible too: freeing it moves glibc's
        // dynamic mmap and trim thresholds before the ring is made, and
        // taking it out read 1 to 7 MiB more peak RSS (median, K=5) on
        // the 1 GiB many-member text set on a Zen 4 rental, and putting it
        // back read the parent's.
        let mut probe: Vec<u8> = Vec::new();
        probe
            .try_reserve_exact(ring_len)
            .map_err(|_| fault::window_unmapped(ring_len as u64, ceiling))?;
        drop(probe);
        // Then the ring itself, ZEROED memory as `vec![0u8; n]` asks for
        // (`pages::zeroed`), which for a ring this size is a fresh
        // anonymous mapping the kernel already guarantees is zero, so
        // nothing is memset: reserving and then `resize`ing to zero - which
        // is what this once did - memset the whole ring in user space,
        // faulting in 32 MiB that the decode was about to write anyway.
        // Measured at about 3% of any leg whose member is close to its
        // window size (19 Sep 2026). It too answers a
        // refusal, which the probe does not rule out: another thread may
        // take the address space between the two.
        let mut ring = crate::pages::zeroed(ring_len)
            .ok_or_else(|| fault::window_unmapped(ring_len as u64, ceiling))?;
        // Before the first write: on Linux the ring's first touch in 4 KiB
        // pages was a short run's largest fixed cost (`crate::pages`).
        crate::pages::advise_huge(&mut ring);
        Ok(Window {
            at: 0,
            lap_base: 0,
            // Drain often enough that no byte is overwritten before it has
            // been emitted or held: half a ring, and never more than the
            // carried emit cadence.
            emit_batch: FLAT_EMIT_THRESHOLD.min(ring_len / 2),
            ring,
            // THE DECLARED DICTIONARY OR THE FORMAT'S FLOOR, never
            // `ring_len`. `RING_FLOOR` may have made the ring larger than
            // the window; the window is what bounds a distance (section
            // 3.7), and `the_ring_floor_moves_no_distance_and_no_byte` is
            // what keeps these two from being confused again.
            limit: declared.max(WINDOW_FLOOR),
            counts: DrainCounts::default(),
            member_base: 0,
            output: u64::MAX,
            emitted: 0,
            hold: Vec::new(),
            filtered: Vec::new(),
            next_drain: 0,
            handed: VecDeque::new(),
            #[cfg(test)]
            slow_copies: 0,
        })
    }

    /// The ring's allocation, for the memory test of section 4.2.
    pub(crate) fn ring_bytes(&self) -> usize {
        self.ring.len()
    }

    /// Drop the window and start a fresh stream, keeping the allocation.
    pub(crate) fn reset(&mut self) {
        self.at = 0;
        self.lap_base = 0;
        self.member_base = 0;
        self.output = u64::MAX;
        self.emitted = 0;
        self.next_drain = self.emit_batch as u64;
        self.hold.clear();
        self.handed.clear();
    }

    /// Begin a member: the filter base resets here (section 3.6).
    pub(crate) fn begin_member(&mut self) {
        self.member_base = self.stream_produced();
        self.output = u64::MAX;
        self.emitted = 0;
        self.next_drain = self.emit_batch as u64;
        self.hold.clear();
        self.handed.clear();
    }

    /// A match the window cannot honour: its distance reaches before the
    /// start of the stream, or past the window (section 3.7).
    ///
    /// It is NOT A FAULT, inside the member's declared output as past it
    /// (SPEC-H2 3.7 as amended on 11 Oct 2026, the genuine programs' behaviour; until
    /// then it was `DistanceOutOfRange` inside the declared output). The
    /// match gives a ZERO for every byte it cannot honour: for all of them
    /// where the distance is past the window, whatever the stream holds
    /// there, and for those whose place is before the stream's start
    /// otherwise, the stream's own bytes following once the match has run
    /// into it. Nothing is said, and the member's checksum decides the
    /// member. Byte at a time for that reason; cold, because no sound
    /// stream reaches it.
    ///
    /// A distance of 0 is the one refusal left: no ladder names it, so it
    /// is a decoder's own state gone wrong and never a stream's doing.
    #[cold]
    #[inline(never)]
    fn copy_out_of_range(&mut self, distance: usize, length: usize) -> Result<()> {
        if distance == 0 {
            return Err(fault::distance_out_of_range());
        }
        for _ in 0..length {
            let byte = if distance > self.limit || distance as u64 > self.stream_produced() {
                0
            } else if distance <= self.at {
                self.ring[self.at - distance]
            } else {
                self.ring[self.at + self.ring.len() - distance]
            };
            self.literal(byte);
        }
        Ok(())
    }

    /// Cap this member's OUTPUT at `declared` bytes, its declared size.
    ///
    /// SPEC-H2 3.1 (amended 28 Sep 2026): a member's output ends at
    /// its declared size and its decode does not. Every symbol of every
    /// block it owns is applied to the ring and the repeat state, the
    /// surplus of the operation that crosses the end and everything after
    /// it included; [`Window::drain`] sends the first `declared` bytes and
    /// nothing more, and the next member begins at the ring's TRUE end.
    pub(crate) fn set_output(&mut self, declared: u64) {
        self.output = declared;
    }

    /// Bytes this MEMBER has produced.
    ///
    /// `u64` END TO END. A member's declared unpacked size is a 64 bit
    /// field (section 3.1) and members above 4 GiB are ordinary traffic,
    /// so narrowing here would truncate the count on a 32-bit target and
    /// leave every termination test in the decode loop comparing a wrapped
    /// count against the true size.
    #[inline(always)]
    pub(crate) fn produced(&self) -> u64 {
        self.stream_produced() - self.member_base
    }

    /// Bytes this MEMBER has sent to the sink. After a forced drain it is
    /// [`Window::produced`] unless a pending filter kept some back.
    pub(crate) fn emitted(&self) -> u64 {
        self.emitted
    }

    /// Whether every distance from 1 to `reach` is one [`Window::copy_match`]
    /// admits now, and so for the rest of the stream: the declared window
    /// holds it and the stream has produced that much (which only grows).
    /// A tape whose fresh matches all reach no further (the lane's
    /// `BlockTape::reach`) needs none of the copy's range tests.
    #[inline(always)]
    pub(crate) fn admits_reach(&self, reach: usize) -> bool {
        reach <= self.limit && reach as u64 <= self.stream_produced()
    }

    /// Bytes the whole stream has produced.
    #[inline(always)]
    pub(crate) fn stream_produced(&self) -> u64 {
        self.lap_base + self.at as u64
    }

    /// Bytes held back from the sink for pending filters.
    // Live in the `cfg(test)` build only: this package's own tests are its
    // one caller.
    #[allow(dead_code)]
    pub(crate) fn held_bytes(&self) -> u64 {
        self.hold.len() as u64
    }

    /// The write point reached the ring's end: back to slot 0.
    #[cold]
    fn lap(&mut self) {
        debug_assert!(self.at == self.ring.len());
        self.lap_base += self.ring.len() as u64;
        self.at = 0;
    }

    /// Move the write point `count` bytes on, which may reach the ring's
    /// end and never passes it.
    #[inline]
    fn advance(&mut self, count: usize) {
        self.at += count;
        if self.at == self.ring.len() {
            self.lap();
        }
    }

    /// Put one literal byte.
    #[inline(always)]
    pub(crate) fn literal(&mut self, byte: u8) {
        let at = self.at;
        self.ring[at] = byte;
        self.at = at + 1;
        if at + 1 == self.ring.len() {
            self.lap();
        }
    }

    /// Put a run of literals.
    #[inline(always)]
    // Live with the `parallel` feature only, which the default build has.
    #[allow(dead_code)]
    pub(crate) fn literals(&mut self, bytes: &[u8]) {
        let at = self.at;
        let count = bytes.len();
        // Strictly short of the ring's end, so the write point needs no
        // lap here; a run that lands exactly on the end goes the cold way.
        if count < self.ring.len() - at {
            if count <= LITERAL_INLINE_MAX {
                // The carried ladder: every copy has a constant length, so
                // it lowers to inline load/store pairs rather than a
                // `memcpy` libcall, and most runs are this short.
                flat_literal_ladder(&mut self.ring, at, bytes);
            } else {
                self.ring[at..at + count].copy_from_slice(bytes);
            }
            self.at = at + count;
            return;
        }
        self.literals_wrapping(bytes);
    }

    /// Put a run of literals of `count` bytes, out of a source that has
    /// at least [`STRIDE_MAX`] readable bytes from its start, whatever
    /// `count` is.
    ///
    /// **THE SAME BARGAIN THE MATCH COPY ALREADY MAKES, on the other arm
    /// of the apply loop.** [`Window::copy_match`]'s fast path writes a
    /// fixed `STRIDE` whatever the match's length is, and pays for the
    /// bytes past the match's end out of the ring's [`SPILL`] margin.
    /// [`Window::literals`] instead branches on the run's length four
    /// times, through the carried inline ladder's `count & 8`, `& 4`,
    /// `& 2` and `& 1`, and takes a `memmove` libcall past
    /// `LITERAL_INLINE_MAX`. On a member whose run lengths are
    /// unpredictable those four branches are four coin flips per run, and
    /// `rar5_incompressible_64m` has 5.88 million runs, 46 percent of its
    /// operations. This writes a FIXED width instead and branches once.
    ///
    /// **Why the bytes past the run are nobody's.** The slot `j` bytes
    /// ahead of the write point is `ring.len() - j` back, and `ring.len()`
    /// is `limit + SPILL`, so that slot's only name is a distance of
    /// `limit + SPILL - j`, which is past the declared window for every
    /// `j` below `SPILL`. `copy_match` refuses those, and `drain` never
    /// reads past `produced()`. This writes at most `STRIDE_MAX - 1` = 63
    /// bytes past the run's end and `SPILL` is 64, so every spilled slot
    /// is unnameable. That is section 4.2's erratum read the way the
    /// in-place work read it, and
    /// `the_room_ahead_of_the_apply_point_is_the_spill_margin_and_no_more`
    /// is the test that holds the margin to it from both sides.
    ///
    /// The `at + STRIDE_MAX < self.ring.len()` guard is `copy_match`'s
    /// own, for its own reason: it keeps the widest write inside the ring
    /// and the write point short of the ring's end, so no lap can fall in
    /// the middle of one.
    ///
    /// # Panics
    ///
    /// Debug builds assert the source's width. A caller that passes a
    /// short source in a release build reads the bytes after it, which is
    /// why there is exactly ONE caller and why the tape pads its literal
    /// buffer rather than leaving the reasoning to the call site.
    #[inline(always)]
    // Live with the `parallel` feature only, which the default build has.
    #[allow(dead_code)]
    pub(crate) fn literals_padded(&mut self, source: &[u8], count: usize) {
        debug_assert!(source.len() >= STRIDE_MAX, "the tape pads its literals");
        debug_assert!(source.len() >= count);
        let at = self.at;
        if count <= STRIDE_MAX && at + STRIDE_MAX < self.ring.len() {
            // THE SAME WRITE SIDE GUARD THE MATCH COPY CARRIES, for the
            // same reason: a write past what this operation may touch is
            // invisible in the output until a much later match reads the
            // damage, which is the defect of 19 Sep 2026. Test builds
            // only.
            #[cfg(debug_assertions)]
            let watch = self.spill_watch(at, count);
            // Two constant widths rather than one, and one branch between
            // them: the narrow arm is what almost every run takes, and
            // widening it to `STRIDE_MAX` for all of them would write four
            // times the bytes for the same branch count.
            if count <= STRIDE {
                self.ring[at..at + STRIDE].copy_from_slice(&source[..STRIDE]);
            } else {
                self.ring[at..at + STRIDE_MAX].copy_from_slice(&source[..STRIDE_MAX]);
            }
            self.at = at + count;
            #[cfg(debug_assertions)]
            self.assert_no_reachable_spill(at, count, &watch);
            return;
        }
        // A run past the widest constant, or a write point near the ring's
        // end: the general path, unchanged, which is also what every run
        // takes on the serial arm and in `apply_checked`.
        self.literals(&source[..count]);
    }

    /// A long run of literals with the sink kept up to date, for the
    /// tests: the decoder appends at most one operation's worth between
    /// drains, and never lets the ring lap what has not left it.
    #[cfg(test)]
    pub(crate) fn literals_chunked<S: LzSink, F: FilterQueue>(
        &mut self,
        bytes: &[u8],
        sink: &mut S,
        filters: &mut F,
    ) {
        for chunk in bytes.chunks(MAX_APPEND) {
            self.literals(chunk);
            if self.drain_due() {
                self.drain(sink, filters, false).unwrap();
            }
        }
    }

    #[cold]
    // Live with the `parallel` feature only, which the default build has.
    #[allow(dead_code)]
    fn literals_wrapping(&mut self, bytes: &[u8]) {
        let mut rest = bytes;
        while !rest.is_empty() {
            let at = self.at;
            let take = rest.len().min(self.ring.len() - at);
            self.ring[at..at + take].copy_from_slice(&rest[..take]);
            self.advance(take);
            rest = &rest[take..];
        }
    }

    /// Copy a match of `length` bytes from `distance` back.
    ///
    /// A match that reaches before the start of the stream, or past the
    /// window, gives zero bytes and is no fault (section 3.7). Overlapping
    /// copies produce exactly the byte at a time result.
    #[inline(always)]
    pub(crate) fn copy_match(&mut self, distance: usize, length: usize) -> Result<()> {
        self.copy_match_in::<false, false>(distance, length)
    }

    /// ONE SEQUENCE OP'S FAST PATH:
    /// the `prefix` literals at
    /// the head of `lits`, then a match of `length` from `distance` back,
    /// under ONE test that holds both, so the write point, the ring and its
    /// length are read once for the two. What the test does not hold is
    /// [`Window::literals_padded`] and then [`Window::copy_match_in`],
    /// exactly, so a refused distance fails at the same output position.
    ///
    /// **Why one test is enough.** A prefix of at most [`STRIDE`] written
    /// as one fixed stride ends at `at + STRIDE`, and the match's write
    /// point `to = at + prefix` keeps `to + STRIDE_MAX` inside the ring, so
    /// both writes are inside it. The match's source lies at least a stride
    /// behind `to`, so it never reads the stride's bytes past the prefix,
    /// and the match overwrites those before anything could.
    // The tape walks are its only callers, and they exist with `parallel`.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn sequence<const TRUSTED: bool, const WIDE: bool>(
        &mut self,
        lits: &[u8],
        prefix: usize,
        distance: usize,
        length: usize,
    ) -> Result<()> {
        let at = self.at;
        let to = at + prefix;
        let admitted = TRUSTED
            || (distance != 0
                && distance as u64 <= self.lap_base + to as u64
                && distance <= self.limit);
        if admitted
            && prefix <= STRIDE
            && length <= STRIDE_MAX
            && distance >= STRIDE
            && distance.wrapping_sub(to + 1) >= STRIDE_MAX - 1
            && to + STRIDE_MAX < self.ring.len()
        {
            debug_assert!(!TRUSTED || self.admits_reach(distance));
            #[cfg(debug_assertions)]
            let watch = self.spill_watch(at, prefix + length);
            self.ring[at..at + STRIDE].copy_from_slice(&lits[..STRIDE]);
            let src = if distance <= to {
                to - distance
            } else {
                to + self.ring.len() - distance
            };
            if WIDE && length > STRIDE && distance >= STRIDE_MAX {
                wide_copy(&mut self.ring, to, src);
            } else {
                stride_copy(&mut self.ring, to, src, length);
            }
            self.at = to + length;
            #[cfg(debug_assertions)]
            self.assert_no_reachable_spill(at, prefix + length, &watch);
            return Ok(());
        }
        self.literals_padded(lits, prefix);
        self.copy_match_in::<TRUSTED, WIDE>(distance, length)
    }

    /// [`Window::copy_match`] with the sequence op's two copy pieces.
    /// `TRUSTED`: the caller has
    /// answered the three range tests below for this distance already (the
    /// lane's reach, [`Window::admits_reach`]), so none is asked here.
    /// `WIDE`: a fast match of more than one stride from at least
    /// [`STRIDE_MAX`] back reads its whole source, 64 bytes, before it
    /// writes any ([`wide_copy`]), where the ladder reads each stride after
    /// the one before it landed; from that far back no stride reads what
    /// another writes, so the bytes are the ladder's. With both false this
    /// is `copy_match` exactly.
    #[inline(always)]
    pub(crate) fn copy_match_in<const TRUSTED: bool, const WIDE: bool>(
        &mut self,
        distance: usize,
        length: usize,
    ) -> Result<()> {
        // THE THREE TESTS, AND A CHEAPER FORM WAS MEASURED AND DECLINED.
        //
        // Section 3.7 admits a distance from 1 to `min(limit, produced)`.
        // Subtracted on an Apple M1 Mac on 22 Sep 2026, asking that costs 3.13
        // to 5.10 percent of the apply stage, which made it the largest
        // removable per-operation cost in the walk. It was rewritten as
        // ONE unsigned compare against a cached lower bound on that
        // minimum, refreshed only on the cold path it guards, and the
        // same-binary pair priced that form at 0.9963x, 1.0142x and
        // 0.9750x against this one: a loss on two legs of three and a
        // 2.5 percent loss on `md128k`, outside that cell's 0.09 percent
        // floor. A cached field load plus a cold call site costs what
        // three perfectly predicted compares on already hot operands
        // cost (measured 22 Sep 2026).
        //
        // The saving is real and this form does not capture it. What
        // might: `distance > self.limit` does not depend on the window's
        // STATE at all, so the tape decode could answer it on a lane, in
        // parallel, and park the block on the rare failure, leaving this
        // thread one compare against `produced`. Noted, not taken.
        if TRUSTED {
            debug_assert!(self.admits_reach(distance));
        } else if distance == 0 || distance as u64 > self.stream_produced() || distance > self.limit
        {
            return self.copy_out_of_range(distance, length);
        }
        let at = self.at;
        // The fast match: short, distance at least a stride, its source's
        // whole stride reach inside the ring, and the write inside it too.
        //
        // THE SOURCE MAY WRAP. `at` is the ring index, so a source with
        // `distance > at` sits behind the ring's start, at `at + ring_len -
        // distance`. Its reach, `STRIDE_MAX` bytes, ends inside the ring
        // exactly when `distance >= at + STRIDE_MAX`, and since `distance
        // <= limit <= ring_len - SPILL` such a source starts at least
        // `SPILL` past the write point, so what the strides read and what
        // they write, spill included, never meet. The one test left out is
        // the source within `STRIDE_MAX` behind the ring's start, which
        // reads across the ring's end: `distance - at - 1` below
        // `STRIDE_MAX - 1`, unsigned, which is ONE compare, the one
        // `distance <= at` used to be, so the loop carries no more
        // branches than it did (the wrapped copy as a SECOND test cost the
        // apply loop 7 to 14 percent on M3 by its shape alone,
        // the far miss's second half). A source that does
        // not wrap makes the subtraction wrap instead, past every bound.
        //
        // THE PRICE, measured and accepted: the source is
        // now a select (`cmp`, `csel`, `add`), three instructions on every
        // fast copy where the control's `subs` gave the source for free, about 1
        // to 1.5 percent of the instructions on a member that never wraps
        // and 1 to 2.3 percent of wall on four rows that stay WON, for
        // `rar5_text_64m_m3` from 0.95x FAIL to 1.04x WON on an Apple M3 Mac
        // (24 Sep 2026). Two cheaper spellings compiled to
        // these instructions or worse.
        //
        // The last bound keeps the widest ladder, `STRIDE_MAX` bytes
        // whatever `length` is, inside the ring, and the write point short
        // of the ring's end. What the strides spill past the match's end
        // lands on slots further back than `limit`, which is what `SPILL`
        // is for. The range check above has already refused a distance
        // past the declared window.
        if length <= STRIDE_MAX
            && distance >= STRIDE
            && distance.wrapping_sub(at + 1) >= STRIDE_MAX - 1
            && at + STRIDE_MAX < self.ring.len()
        {
            let src = if distance <= at {
                at - distance
            } else {
                at + self.ring.len() - distance
            };
            #[cfg(debug_assertions)]
            let watch = self.spill_watch(at, length);
            if WIDE && length > STRIDE && distance >= STRIDE_MAX {
                wide_copy(&mut self.ring, at, src);
            } else {
                stride_copy(&mut self.ring, at, src, length);
            }
            self.at = at + length;
            #[cfg(debug_assertions)]
            self.assert_no_reachable_spill(at, length, &watch);
            return Ok(());
        }
        #[cfg(debug_assertions)]
        let (slow_at, watch) = (self.at, self.spill_watch(self.at, length));
        self.copy_match_slow(distance, length);
        #[cfg(debug_assertions)]
        self.assert_no_reachable_spill(slow_at, length, &watch);
        Ok(())
    }

    /// How many operations the tape walk's prefetch pass reaches ahead of
    /// the apply point (its chunk), when no harness has said otherwise.
    /// 64, the depth two timed measurements on an Apple M3 Mac priced (23 Sep 2026,
    /// the far-copy prefetch measurement): on the
    /// rows it reaches rarkit's own wall 10 to 19 percent down at less CPU.
    /// The lever lands only on its measured wall; zero turns it
    /// off.
    #[cfg(feature = "parallel")]
    pub(crate) const FAR_PREFETCH_DEPTH: usize = 64;

    /// THE GATE: a tape is hinted only when its first
    /// [`Window::FAR_GATE_SAMPLE`] operations carry at least one fresh
    /// match in [`Window::FAR_GATE_EVERY`] reaching back
    /// [`Window::FAR_GATE_DISTANCE`] or further. On a member whose copies
    /// hit the cache the pass is pure cost: on an Apple M3 Mac (23 Sep 2026) the
    /// branch-free pass cost `code_32m_m3` and `md128k`, whose ceilings
    /// are 0.995x and 1.06x, 13 to 17 percent of the apply stage.
    #[cfg(feature = "parallel")]
    pub(crate) const FAR_GATE_SAMPLE: usize = 256;
    /// See [`Window::FAR_GATE_SAMPLE`].
    #[cfg(feature = "parallel")]
    pub(crate) const FAR_GATE_EVERY: usize = 8;
    /// See [`Window::FAR_GATE_SAMPLE`]: further back than an M3 core's L1
    /// and most of its share of L2 hold.
    #[cfg(feature = "parallel")]
    pub(crate) const FAR_GATE_DISTANCE: usize = 256 << 10;

    /// THE FAR PREFETCH'S DICTIONARY FLOOR: a stream whose DECLARED
    /// dictionary is this or smaller builds no far list and hints nothing
    /// (the large window measurement, 28 Sep 2026).
    ///
    /// A ring this small stays in the apply core's L2 whole, so every
    /// source the hint would fetch is already a short hit and the list
    /// (built on the decode lane) and the pass (walked on the apply thread)
    /// are pure cost. Counted on an Apple M3 Mac, one binary with the hint off
    /// against on, the solid 1 GiB text set at `-m3`: at 2 MiB 7.1 percent
    /// fewer instructions and 3.6 percent fewer cycles, at 4 MiB cycles
    /// 0.978 but the wall already worse, and from 8 MiB on the hint is
    /// worth 12 to 43 percent of the wall. A distance floor was screened
    /// instead and lost at every ring from 4 MiB: once the ring outgrows
    /// the cache, sources 256 KiB to 2 MiB back miss too.
    ///
    /// aarch64 only: an x86-64 core's L2 is 1 or 2 MiB, so the
    /// same ring there is an L3 hit, which the hint may well still pay for;
    /// until that is counted the floor is zero there and nothing changes.
    #[cfg(all(feature = "parallel", target_arch = "aarch64"))]
    pub(crate) const FAR_DICTIONARY_FLOOR: usize = 2 << 20;
    /// See the aarch64 `FAR_DICTIONARY_FLOOR`.
    #[cfg(all(feature = "parallel", not(target_arch = "aarch64")))]
    pub(crate) const FAR_DICTIONARY_FLOOR: usize = 0;

    /// Whether this stream's dictionary is at or under
    /// [`Window::FAR_DICTIONARY_FLOOR`], so that nothing is hinted. With
    /// `h2-apply-arms`, `RARKIT_FAR_FLOOR_KIB` replaces the floor.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn far_off(&self) -> bool {
        #[cfg(feature = "h2-apply-arms")]
        let floor = crate::probe::far_floor();
        #[cfg(not(feature = "h2-apply-arms"))]
        let floor = Window::FAR_DICTIONARY_FLOOR;
        self.limit <= floor
    }

    /// [`Window::FAR_GATE_DISTANCE`] as the lane, the gate and the walk
    /// read it: the constant, or with `h2-apply-arms` the measuring dial
    /// `RARKIT_FAR_DISTANCE` (`probe::far_distance`). Read once a tape.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn far_distance() -> usize {
        #[cfg(feature = "h2-apply-arms")]
        let distance = crate::probe::far_distance();
        #[cfg(not(feature = "h2-apply-arms"))]
        let distance = Window::FAR_GATE_DISTANCE;
        distance
    }

    /// [`Window::FAR_GATE_EVERY`], or with `h2-apply-arms` the dial
    /// `RARKIT_FAR_EVERY` (`probe::far_every`). Read once a tape.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn far_every() -> usize {
        #[cfg(feature = "h2-apply-arms")]
        let every = crate::probe::far_every();
        #[cfg(not(feature = "h2-apply-arms"))]
        let every = Window::FAR_GATE_EVERY;
        every
    }
    /// See [`Window::FAR_GATE_SAMPLE`]: a tape whose sampled operations
    /// average more than this many bytes is not hinted. A chunk of long
    /// copies spans megabytes, so its hints land far past the write point
    /// and are evicted before use: on an Apple M3 Mac (23 Sep 2026, the first
    /// timed measurement) `f/extract-m5-text64`, 64 MiB in 7.5 ms, read 0.923x
    /// on the knob. The text rows the lever is for run 5 to 9 bytes an
    /// operation.
    #[cfg(feature = "parallel")]
    pub(crate) const FAR_GATE_BYTES_PER_OP: usize = 32;

    /// The ring index of the byte `distance` back from `ahead` bytes past
    /// the write point, CLAMPED into the ring: an estimate past either end
    /// (a distance past the ring, which only an invalid tape carries, or
    /// an `ahead` past a lap) names the ring's last byte instead. Safe,
    /// and the whole of the arithmetic [`Window::prefetch_source`] hints
    /// on.
    ///
    /// BRANCH FREE ON PURPOSE: every test here is a select, not a jump. A
    /// data-dependent branch in the prefetch pass mispredicted on members
    /// whose literal runs and matches interleave and cost `code_32m_m3`
    /// and `md128k` 21 to 27 percent of the apply stage with NO hint issued
    /// at all (an Apple M3 Mac, 23 Sep 2026, the dry-run cell).
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn source_index(&self, ahead: usize, distance: usize) -> usize {
        let ring_len = self.ring.len();
        let pos = self.at + ahead;
        let pos = if pos >= ring_len { pos - ring_len } else { pos };
        let pos = if pos < distance { pos + ring_len } else { pos };
        pos.wrapping_sub(distance).min(ring_len - 1)
    }

    /// Hint the core that the byte `distance` back from `ahead` bytes past
    /// the write point is about to be read, and do nothing else.
    ///
    /// **Why this exists.** On the text rows the apply thread's time is
    /// the match copy, and the copy's source is up to a whole 32 MiB
    /// dictionary behind the write point, so most copies start with a
    /// miss to memory (the 22 Sep per-operation table:
    /// 10.95 ns a copy on `text_64m_m3`). The tape holds every operation
    /// ahead of the apply point, so the source of a match several
    /// operations on is known now. A plain load of it was measured on 21
    /// Sep and cost CPU at every depth, because a load that misses holds
    /// up retirement like any other; a PREFETCH retires at once and only
    /// starts the line on its way. Safe Rust offers no prefetch, which is
    /// why [`Window::prefetch_line`], which this calls, carries the crate's
    /// only `unsafe` outside the AES chain.
    ///
    /// **What it may not do.** It computes an ESTIMATE: `ahead` is the
    /// sum of the lengths of the operations between the apply point and
    /// the hinted one, so a `REP_LAST` or a filter record between them
    /// can shift it. An estimate outside the ring is clamped onto its last
    /// byte ([`Window::source_index`]), and the index is then taken through
    /// a bounds-checked slice access, so the address is always a byte of
    /// the ring; one that lands on the wrong byte wastes one line of
    /// bandwidth.
    /// Neither changes a byte of output or an error: the hint reads and
    /// writes no program-visible state.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn prefetch_source(&self, ahead: usize, distance: usize) {
        Window::prefetch_line(&self.ring[self.source_index(ahead, distance)]);
    }

    /// THE ANCHOR of the far list's precomputed hints:
    /// the write point plus
    /// one ring, so that [`Window::prefetch_back`] needs one wrap and no
    /// other test. Read once a chunk, never an operation.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn hint_anchor(&self) -> usize {
        self.at + self.ring.len()
    }

    /// Hint the source `back` bytes behind the write point, where the
    /// decode lane wrote `back` as the far match's distance less the tape
    /// length between here and it, and `anchor` is [`Window::hint_anchor`].
    /// For every distance the ring can hold this is exactly
    /// [`Window::source_index`] of the same operation: `anchor - back` lies
    /// in `[0, 2 * ring)`, so one wrap brings it into the ring. Anything
    /// else (a distance past the ring, which only an invalid tape carries,
    /// or a back the lane wrapped below zero) falls outside the ring or on
    /// another of its bytes, and costs at most one line. Safe: the address
    /// is a bounds-checked `&u8`.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn prefetch_back(&self, anchor: usize, back: u32) -> usize {
        let ring_len = self.ring.len();
        let idx = anchor.wrapping_sub(back as usize);
        let idx = if idx >= ring_len {
            idx.wrapping_sub(ring_len)
        } else {
            idx
        };
        if let Some(line) = self.ring.get(idx) {
            Window::prefetch_line(line);
        }
        idx
    }

    /// THE ONE PREFETCH HINT: tell the core the line holding `line` is
    /// about to be read, and do nothing else. Both [`Window::prefetch_source`]
    /// and [`Window::prefetch_back`] reach the ring only through here.
    ///
    /// THE RULE (decided 22 Sep 2026):
    /// ONE `unsafe` block, in ONE function that does nothing but issue a
    /// prefetch hint, `#[allow(unsafe_code)]` on that function alone with
    /// its safety argument beside it; the crate stays
    /// `#![deny(unsafe_code)]` everywhere else, and any further unsafe
    /// needs its own decision. The block moved here from
    /// `prefetch_source` unchanged, so that a caller holding a ring index
    /// need not recompute one. An associated function and not a method
    /// since 30 Sep 2026, so the
    /// one-pass region, which holds the ring's bytes mutably, can hint a
    /// source through a shared reborrow of one of them; the block and its
    /// argument are unchanged, and the region is its one caller beyond
    /// these two (`onepass::region`, with a bounds-checked `&u8` as well).
    #[cfg(feature = "parallel")]
    #[inline(always)]
    #[allow(unsafe_code)]
    pub(crate) fn prefetch_line(line: &u8) {
        let line: *const u8 = line;
        // SAFETY: the one instruction below is a prefetch HINT (`prfm
        // pldl1keep` on aarch64, `prefetcht0` on x86-64). Architecturally
        // it reads no memory into any register, writes no memory, changes
        // no register or flag and cannot fault or trap, whatever address
        // it names; the asm declares exactly that (`nostack`,
        // `preserves_flags`, `readonly`, no outputs). The address is taken
        // from a live, bounds-checked `&u8` into a window's ring, borrowed
        // for the whole call, so it names a byte that window owns in any case;
        // that reference, which every caller must produce to call this at
        // all, is the whole precondition.
        // Nothing the rest of the crate relies on can observe that it ran.
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        unsafe {
            #[cfg(target_arch = "aarch64")]
            core::arch::asm!(
                "prfm pldl1keep, [{line}]",
                line = in(reg) line,
                options(nostack, preserves_flags, readonly)
            );
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!(
                "prefetcht0 [{line}]",
                line = in(reg) line,
                options(nostack, preserves_flags, readonly)
            );
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        let _ = line;
    }

    /// The bytes just past where this copy is allowed to write, kept so
    /// [`Window::assert_no_reachable_spill`] can say whether it touched
    /// them. Test builds only.
    #[cfg(debug_assertions)]
    fn spill_watch(&self, at: usize, length: usize) -> [u8; SPILL_WATCH] {
        let ring_len = self.ring.len();
        let mut watch = [0u8; SPILL_WATCH];
        for (index, slot) in watch.iter_mut().enumerate() {
            *slot = self.ring[(at + length + index) % ring_len];
        }
        watch
    }

    /// THE GUARD FOR THE WHOLE CLASS THE WINDOW EDGE DEFECT BELONGS TO.
    ///
    /// A copy may write `[at, at + length)` and nothing else. What made the
    /// defect silent was that a write PAST that range is invisible: the
    /// bytes are still in range, the copy still succeeds, and only a much
    /// later match at a distance near the dictionary ever reads the damage.
    /// Every test this package had compares what comes OUT, and a spill
    /// that the member's own next bytes overwrite before anything reads it
    /// changes no output at all. So this checks the invariant itself, on
    /// every copy, on both paths, in every test build: a slot past the
    /// match may differ ONLY if no distance the decoder admits can name it.
    ///
    /// It is written against the INVARIANT and not against the fix, on
    /// purpose, so it keeps holding if the ring is reshaped again:
    ///
    /// - on THIS ring, the dictionary plus [`SPILL`], the first `SPILL`
    ///   slots past the match sit at distances above `limit`, `copy_match`
    ///   refuses those above, and the guard passes them. That is the fix
    ///   working, stated as something the suite enforces rather than as an
    ///   argument in a comment;
    /// - the slots BEYOND the margin are reachable, so a copy that ever
    ///   spills further than `SPILL` fails here rather than silently. That
    ///   is why the watch is wider than the margin: a guard only as wide as
    ///   `SPILL` would be vacuous on this ring and could not catch the
    ///   margin being outgrown or shrunk;
    /// - on a ring of exactly the dictionary, every slot here is reachable,
    ///   so ANY spill fails. Against the code at an earlier revision this fails
    ///   `every_archive_reproduces_the_check_table` on `h5_far_small_md`.
    ///
    /// Slot `at + length + i` is, against the count this copy has just
    /// produced, the byte `ring_len - i` back.
    #[cfg(debug_assertions)]
    fn assert_no_reachable_spill(&self, at: usize, length: usize, watch: &[u8; SPILL_WATCH]) {
        let ring_len = self.ring.len();
        let produced = self.stream_produced();
        for (index, &was) in watch.iter().enumerate() {
            let slot = (at + length + index) % ring_len;
            if self.ring[slot] == was {
                continue;
            }
            let distance = ring_len - index;
            if distance <= self.limit && distance as u64 <= produced {
                panic!(
                    "a copy of {length} bytes at {at} wrote slot {slot}, which is \
                     {distance} back and READABLE: the window's dictionary is {} \
                     and the stream has produced {produced}. SPEC-H2 section 3.7.",
                    self.limit
                );
            }
        }
    }

    /// The match copy with ONE ARM of its per-operation cost removed,
    /// for `probe::apply_arms`. Monomorphised per arm, so the shipped
    /// walk (`ARM == SHIPPED`) is the same instructions it always was
    /// and no arm pays for another's existence.
    ///
    /// Most arms produce WRONG BYTES on purpose and are reachable only
    /// through the dial with `test-support`: they are upper bounds on
    /// levers that have not been written, which is how the near-match
    /// path was priced and then declined.
    #[cfg(feature = "h2-apply-arms")]
    #[inline(always)]
    #[allow(dead_code)]
    pub(crate) fn copy_match_ablated<const ARM: u8>(
        &mut self,
        distance: usize,
        length: usize,
    ) -> Result<()> {
        use crate::probe::apply_arms;
        if ARM == apply_arms::NO_MATCH_COPY || ARM == apply_arms::NO_STORES {
            // The bytes are not written and the write point moves as
            // though they were, so the member still ends at the operation
            // it always ended at and nothing downstream errors early.
            self.skip_write(length);
            return Ok(());
        }
        if ARM != apply_arms::NO_RANGE
            && (distance == 0 || distance as u64 > self.stream_produced() || distance > self.limit)
        {
            return self.copy_out_of_range(distance, length);
        }
        // THE NEAR SOURCE arm: the same copy, taken from a byte at most
        // `NEAR_SOURCE_REACH` back, so it hits the cache where the real
        // source may miss. WRONG BYTES. It is the CEILING on any prefetch
        // of the copy's source: a perfect hint could hide the miss and
        // nothing more, and this arm has no miss to hide.
        let distance = if ARM == apply_arms::NEAR_SOURCE {
            distance.min(apply_arms::NEAR_SOURCE_REACH)
        } else {
            distance
        };
        let at = self.at;
        if length <= STRIDE_MAX
            && distance >= STRIDE
            && distance.wrapping_sub(at + 1) >= STRIDE_MAX - 1
            && at + STRIDE_MAX < self.ring.len()
        {
            let src = if distance <= at {
                at - distance
            } else {
                at + self.ring.len() - distance
            };
            stride_copy(&mut self.ring, at, src, length);
            self.at = at + length;
            return Ok(());
        }
        // THE WRAP STRIDE arm: a wrapped source whose `STRIDE_MAX` reach
        // ends inside the ring. `distance <= limit <= ring_len - SPILL`, so
        // the source starts at least `SPILL` past the write point and the
        // bytes read and written, spill included, are disjoint: byte exact.
        if ARM == apply_arms::WRAP_STRIDE
            && length <= STRIDE_MAX
            && distance >= at + STRIDE_MAX
            && at + STRIDE_MAX < self.ring.len()
        {
            let src = at + self.ring.len() - distance;
            for stride in 0..length.div_ceil(STRIDE) {
                let from = src + stride * STRIDE;
                self.ring
                    .copy_within(from..from + STRIDE, at + stride * STRIDE);
            }
            self.at = at + length;
            return Ok(());
        }
        self.copy_match_slow(distance, length);
        Ok(())
    }

    /// Move the write point on as though `count` bytes had been written,
    /// writing none of them. An ablation arm's primitive and nothing
    /// else: the byte COUNT is preserved so the member stops where it
    /// always stopped, and the bytes are whatever the ring held.
    #[cfg(feature = "h2-apply-arms")]
    #[inline(always)]
    #[allow(dead_code)]
    pub(crate) fn skip_write(&mut self, count: usize) {
        let at = self.at + count;
        let ring_len = self.ring.len();
        if at >= ring_len {
            self.lap_base += ring_len as u64;
            self.at = at - ring_len;
        } else {
            self.at = at;
        }
    }

    #[cold]
    fn copy_match_slow(&mut self, distance: usize, length: usize) {
        #[cfg(test)]
        {
            self.slow_copies += 1;
        }
        let ring_len = self.ring.len();
        let mut left = length;
        // DISTANCE ONE IS A FILL: every byte of the match is the byte
        // before it, so one span a lap takes what the loop below takes a
        // byte at a time (a 64 byte match, 64 trips to 1). `copy_match`
        // has refused a distance past what the stream produced, so the
        // byte before the write point exists; at slot 0 it is the ring's
        // last.
        if distance == 1 {
            let at = self.at;
            let byte = self.ring[if at == 0 { ring_len } else { at } - 1];
            while left > 0 {
                let at = self.at;
                let run = left.min(ring_len - at);
                self.ring[at..at + run].fill(byte);
                self.advance(run);
                left -= run;
            }
            return;
        }
        while left > 0 {
            let at = self.at;
            // `distance` is at most `limit`, which is short of the ring's
            // length, so the source is never the write point itself.
            let src = if distance <= at {
                at - distance
            } else {
                at + ring_len - distance
            };
            // Stop at either end of the ring, and never let the write point
            // reach the read point, so an overlapping match still reads the
            // bytes this copy has already written.
            let gap = at.abs_diff(src);
            let run = left.min(ring_len - at).min(ring_len - src).min(gap);
            if src < at {
                self.ring.copy_within(src..src + run, at);
            } else {
                let (front, back) = self.ring.split_at_mut(src);
                front[at..at + run].copy_from_slice(&back[..run]);
            }
            self.advance(run);
            left -= run;
        }
    }

    /// The bytes at member offsets `from..to`, as at most two slices.
    ///
    /// THE ONE PLACE the emission path indexes the ring, and therefore the
    /// one place it depends on the ring's GEOMETRY. The split below is
    /// already stated by comparison against `ring.len()` and carries to a
    /// ring of any length; only `start`'s reduction is a mask, so a ring
    /// that stops being a power of two (a dictionary plus a spill margin,
    /// say) needs that one line and nothing else here. Every caller's
    /// precondition is `to - from <= ring.len()`, which is stated in
    /// `ring.len()` terms too and not in the mask's.
    fn ring_slices(&self, from: u64, to: u64) -> (&[u8], &[u8]) {
        // How far back of the write point member offset `from` sits: never
        // more than a lap, which `drain` asserts. Both this and `len` are
        // therefore at most `ring.len()`, so both fit a `usize` on a 32-bit
        // target as well; the offsets they are computed FROM do not, which
        // is why the parameters are `u64`.
        let back = self.produced() - from;
        debug_assert!(back <= self.ring.len() as u64);
        let back = back as usize;
        let start = if back <= self.at {
            self.at - back
        } else {
            self.at + self.ring.len() - back
        };
        debug_assert!(to - from <= self.ring.len() as u64);
        let len = (to - from) as usize;
        let first = (self.ring.len() - start).min(len);
        (&self.ring[start..start + first], &self.ring[..len - first])
    }

    /// How much output accumulates before a batch goes to the sink. It is
    /// never more than half the ring, so no byte is overwritten before it
    /// has been emitted or copied into the hold.
    #[inline(always)]
    // Live with the `parallel` feature only, which the default build has.
    #[allow(dead_code)]
    pub(crate) fn drain_batch(&self) -> usize {
        self.emit_batch
    }

    /// How many bytes the apply stage may produce before the drain
    /// cadence needs looking at again.
    ///
    /// The member's declared size is NOT part of it (SPEC-H2 3.1, amended
    /// 28 Sep 2026): a member decodes every symbol it owns, and
    /// its output is capped by [`Window::drain`] instead. Zero means the
    /// next operation must take the checked path, which is what a due
    /// drain reduces to. Once the member's output is complete no drain is
    /// ever due again, so the budget is then unbounded.
    ///
    /// Called by the parallel apply stage and by the serial decode loop,
    /// so it is live in every build.
    #[inline(always)]
    pub(crate) fn apply_budget(&self) -> usize {
        let until_drain = self.next_drain.saturating_sub(self.produced());
        usize::try_from(until_drain).unwrap_or(usize::MAX)
    }

    /// Whether a batch is due. One compare on the decode path, and the
    /// cadence survives a block boundary.
    #[inline(always)]
    pub(crate) fn drain_due(&self) -> bool {
        self.produced() >= self.next_drain
    }

    /// Send what may leave, holding back what a pending filter covers.
    ///
    /// `pending` yields each queued filter in start order; the closure runs
    /// a filter's transform over the span handed to it. `force` sends a
    /// partial batch, which the end of a member does.
    pub(crate) fn drain<S: LzSink, F: FilterQueue>(
        &mut self,
        sink: &mut S,
        filters: &mut F,
        force: bool,
    ) -> Result<()> {
        // A queued span that STRADDLES the declared size, which only a
        // member with no checksum keeps: one compare a drain, and the
        // drain below is otherwise the one it was.
        let reach = filters.reach();
        if reach > self.output {
            return self.drain_past_declared(sink, filters, force, reach);
        }
        // THE OUTPUT CAP (SPEC-H2 3.1): nothing past the member's declared
        // size is drained, however far the decode has run past it. Once
        // the output is COMPLETE, everything still due goes now rather
        // than at the next batch: the member's surplus keeps writing the
        // ring, and no later drain is scheduled (`next_drain` saturates),
        // so a byte due and left in the ring would be lapped by it.
        let produced = self.produced().min(self.output);
        let complete = produced == self.output;
        let force = force || complete;
        self.counts.drains += 1;
        self.next_drain = if complete {
            u64::MAX
        } else {
            produced + self.emit_batch as u64
        };
        // What the last drain handed away goes out first, in member order.
        if !self.handed.is_empty() {
            self.put_handed(sink, filters)?;
        }
        // THE TRANSFORM OFFLOAD, where the queue asks for it and a filter
        // is actually queued. On a ring at least four batches long a
        // range left in the ring until the next drain is at most two
        // batches and a span old when it is put, so the ring cannot lap
        // it; a shorter ring, every dictionary up to 2 MiB, copies out
        // everything it accounts for instead (`drain_handing`). A member
        // with no filter queued and anything the hold would serve take
        // the path below unchanged. The queued test is what keeps an
        // UNFILTERED member on exactly the shipped drain: without it
        // `rar5_incompressible_64m`, which carries no record at all, read
        // 0.995x against itself on an Apple M3 Mac (the
        // density rows' measurement).
        if filters.offload()
            && !complete
            && filters.front().is_some()
            && self.hold.is_empty()
            && self.drain_handing(sink, filters, produced, force)?
        {
            return Ok(());
        }
        if filters.open_len() > 0 {
            self.hold_open(filters);
        }
        // Nothing may wait longer than a lap of the ring: the drain cadence
        // is half a ring, and a remainder left in the ring brings the next
        // drain forward (the end of this function), so this cannot fire
        // from the decode path.
        debug_assert!(produced - self.emitted - self.hold.len() as u64 <= self.ring.len() as u64);
        // Straight out of the RING, while nothing is held back.
        //
        // The hold below exists for one case only: a span whose bytes the
        // ring may lap before the span is complete. When the span IS
        // complete and its bytes are still in the ring, going through the
        // hold costs two whole extra passes over the member's bytes - ring
        // to hold, hold to scratch - plus a `drain` that memmoves what is
        // left of the hold after every span. A filtered member pays that
        // on every byte it produces and an unfiltered one pays none of it,
        // which is what made the x86 code leg the one leg in this suite
        // that lost to the old engine on both architectures
        // (19 Sep 2026). One copy, out of the ring and
        // into the scratch the transform runs over, is the floor: section
        // 3.6 requires the ring to keep the UNFILTERED bytes, so the
        // transform cannot run in place.
        //
        // The bytes are known to be live: the loop runs only with the hold
        // empty, so the assertion above reads
        // `produced - emitted <= ring.len()`, and `span.start` is at or
        // after `emitted`. That argument is in `ring.len()` terms and not
        // in the ring index's, so it holds whatever the ring's length is;
        // the indexing itself is [`Window::ring_slices`]'s alone.
        while self.hold.is_empty() {
            let Some(span) = filters.front() else {
                break;
            };
            if span.start < self.emitted {
                // A span that starts BEHIND what has already left. The
                // queue no longer holds one: `Filters::push` ignores a
                // record that starts before the end of the last one kept,
                // as the reference does, and that is where an overlapping
                // record used to come from. A queue that did hold one
                // takes the hold path, which may leave the member short,
                // and `Rar5Lz::finish_member` then fails it
                // `IncompleteMember` rather than report it whole.
                //
                // (It is not an indexing hazard. Every span the loop below
                // serves has `start >= emitted` on entry to this drain, and
                // `produced - emitted <= ring.len()` there, so a served
                // span is never longer than the ring.)
                break;
            }
            if span.start > self.emitted {
                let upto = span.start.min(produced);
                if upto > self.emitted {
                    self.emit_range(sink, self.emitted, upto)?;
                }
                if self.emitted < span.start {
                    return Ok(());
                }
            }
            let end = span.start + span.length as u64;
            if end > produced {
                // Not complete yet: the hold takes it from here, because
                // the ring may lap it before it is.
                break;
            }
            // The scratch is taken out and put back because the ring
            // slices borrow `self`; it keeps its allocation across spans
            // and across members, so nothing here allocates per filter.
            let mut filtered = std::mem::take(&mut self.filtered);
            filtered.clear();
            let (a, b) = self.ring_slices(span.start, end);
            filtered.extend_from_slice(a);
            filtered.extend_from_slice(b);
            self.filtered = filtered;
            self.counts.ring_to_scratch += self.filtered.len() as u64;
            self.counts.spans_fast += 1;
            filters.apply(&span, &mut self.filtered);
            sink.put(&self.filtered)?;
            self.emitted = end;
            filters.pop();
        }
        if filters.front().is_some() {
            // Everything available moves into the hold first: the ring may
            // lap it before the filter's span completes.
            let already = self.emitted + self.hold.len() as u64;
            if produced > already {
                let mut hold = std::mem::take(&mut self.hold);
                let (a, b) = self.ring_slices(already, produced);
                hold.extend_from_slice(a);
                hold.extend_from_slice(b);
                self.hold = hold;
                self.counts.ring_to_hold += produced - already;
            }
            if self.hold.len() > super::filters::FILTER_HOLD_LIMIT {
                return Err(fault::hold_exceeded(self.hold.len() as u64));
            }
        }
        // THE HOLD IS SERVED BY A CURSOR and shifted down ONCE, after the
        // last span this drain serves from it. Shifted after every span,
        // as it was, the remainder moved once per span, which is
        // quadratic in the spans one drain holds: a real 140 MB library
        // with 1496 records moved 478 to 505 MB through the hold (measured
        // 27 Sep 2026). The bytes the
        // sink sees, their order and the state an error leaves are
        // unchanged: `served` and `emitted` move together, and only after
        // a put succeeds.
        let mut served = 0usize;
        let stopped = self.serve_hold(sink, filters, &mut served);
        if served > 0 {
            self.counts.hold_memmove += (self.hold.len() - served) as u64;
            self.hold.drain(..served);
        }
        if stopped? {
            return Ok(());
        }
        if !self.hold.is_empty() {
            self.counts.hold_to_sink += self.hold.len() as u64;
            sink.put(&self.hold)?;
            self.emitted += self.hold.len() as u64;
            self.hold.clear();
        }
        let ready = produced - self.emitted;
        if ready > 0 && (force || ready >= self.emit_batch as u64) {
            self.emit_range(sink, self.emitted, produced)?;
        } else if ready > 0 {
            self.due_from_what_left(produced);
        }
        Ok(())
    }

    /// [`Window::drain`] for a member whose queue holds a span that
    /// starts inside its declared output and ends at `reach`, past it
    /// (SPEC-H2 3.1, rule 2 of "a kept filter record whose span is not
    /// wholly inside the member's declared output").
    ///
    /// The transform needs its WHOLE span, so for the length of this
    /// drain the member's output is taken to end at `reach`: the bytes of
    /// the span wait in the hold as they would for any open span, the
    /// drain cadence goes on past the declared size until the span is
    /// complete, and the transform runs once over all of it. What the
    /// SINK sees is cut at the declared size (rule 1: no byte past it is
    /// ever delivered), so the emission cursor ends at `reach` and the
    /// sink at the declared size. Between drains the declared size is
    /// back in place, which is what a distance is judged against (3.7).
    #[cold]
    #[inline(never)]
    fn drain_past_declared<S: LzSink, F: FilterQueue>(
        &mut self,
        sink: &mut S,
        filters: &mut F,
        force: bool,
        reach: u64,
    ) -> Result<()> {
        let declared = self.output;
        let mut capped = Capped {
            sink,
            left: declared.saturating_sub(self.emitted),
        };
        self.output = reach;
        let outcome = self.drain(&mut capped, filters, force);
        self.output = declared;
        outcome
    }

    /// Serve the queued spans out of the hold from `served` on, in member
    /// order, moving `served` past each byte the sink took. `true` when a
    /// span is not yet whole in the hold, so the drain stops there.
    fn serve_hold<S: LzSink, F: FilterQueue>(
        &mut self,
        sink: &mut S,
        filters: &mut F,
        served: &mut usize,
    ) -> Result<bool> {
        while let Some(span) = filters.front() {
            let held = self.hold.len() - *served;
            if span.start > self.emitted {
                // At most `held`, so the narrowing is exact on any width;
                // the subtraction it narrows is not.
                let take = (span.start - self.emitted).min(held as u64) as usize;
                if take > 0 {
                    self.counts.hold_to_sink += take as u64;
                    sink.put(&self.hold[*served..*served + take])?;
                    *served += take;
                    self.emitted += take as u64;
                }
                if self.emitted < span.start {
                    return Ok(true);
                }
            }
            if self.hold.len() - *served < span.length {
                return Ok(true);
            }
            self.filtered.clear();
            self.filtered
                .extend_from_slice(&self.hold[*served..*served + span.length]);
            self.counts.hold_to_scratch += span.length as u64;
            self.counts.spans_held += 1;
            filters.apply(&span, &mut self.filtered);
            sink.put(&self.filtered)?;
            *served += span.length;
            self.emitted += span.length as u64;
            filters.pop();
        }
        Ok(false)
    }

    /// THE REMAINDER STAYS IN THE RING, so the next drain is due from what
    /// has LEFT it, not from what was produced. A span served mid-batch
    /// leaves less than a batch at the end of [`Window::drain`], and a
    /// caller may write up to `drain_batch()` bytes between two due tests
    /// (the tape walk's checked literal arm does), so the due point is kept
    /// where that widest write still cannot reach a byte that has not left:
    /// `next_drain - 1 + emit_batch - emitted <= ring.len()`. Anchored on
    /// `produced`, a ring of two batches (every dictionary up to 2 MiB)
    /// lapped about a batch of unemitted bytes and a release build emitted
    /// them (found in the md128k work, 23 Sep 2026;
    /// `a_filtered_member_never_laps_the_ring_at_the_tape_walks_cadence`).
    /// On a ring of three batches or more this bound is past `produced +
    /// emit_batch` and changes nothing; an unfiltered member never reaches
    /// it.
    ///
    /// Out of line and cold on purpose: written inline, the arm moved
    /// `rar5_code_32m_m3` (a 32 MiB ring, where it never changes the
    /// cadence) by about 3.5 percent on an Apple M3 Mac, untimed, by the shape of
    /// `drain`'s code alone (23 Sep 2026).
    #[cold]
    #[inline(never)]
    fn due_from_what_left(&mut self, produced: u64) {
        let reach = (self.ring.len() - self.emit_batch) as u64 + 1;
        self.next_drain = self.next_drain.min(self.emitted + reach);
        // Still ahead of the write point, so `apply_budget` is never zero
        // after a drain: `ready < emit_batch <= ring - emit_batch`.
        debug_assert!(self.next_drain > produced);
    }

    /// Put everything earlier drains handed away or left in the ring, in
    /// member order.
    fn put_handed<S: LzSink, F: FilterQueue>(
        &mut self,
        sink: &mut S,
        filters: &mut F,
    ) -> Result<()> {
        while let Some((start, end, handed)) = self.handed.pop_front() {
            debug_assert_eq!(start, self.emitted);
            if handed {
                let put = filters.put_handed(sink)?;
                debug_assert_eq!(put as u64, end - start);
                self.emitted = end;
            } else {
                debug_assert!(self.produced() - start <= self.ring.len() as u64);
                self.emit_range(sink, start, end)?;
            }
        }
        Ok(())
    }

    /// The drain with the transforms handed away (`filters::Offload`).
    ///
    /// Every span complete in the ring is copied out and handed to the
    /// queue's task as one batch; the ranges between them, and what
    /// follows up to the next span's start, stay in the ring. All of it is
    /// recorded in `handed` and put by the next drain, in member order, so
    /// the sink sees exactly the bytes and the order the path below gives
    /// it, one drain later. Answers `false`, having put everything, where
    /// that path must take over: a span that starts behind what is
    /// already accounted for, a span still open that is too long for the
    /// ring to keep, or a span still open when `force` ends the member.
    fn drain_handing<S: LzSink, F: FilterQueue>(
        &mut self,
        sink: &mut S,
        filters: &mut F,
        produced: u64,
        force: bool,
    ) -> Result<bool> {
        if self.ring.len() < 4 * self.emit_batch {
            return self.drain_handing_short(sink, filters, produced, force);
        }
        let mut queued = self.emitted;
        let mut any = false;
        while let Some(span) = filters.front() {
            let end = span.start + span.length as u64;
            if span.start < queued || end > produced {
                break;
            }
            if span.start > queued {
                self.handed.push_back((queued, span.start, false));
            }
            let (a, b) = self.ring_slices(span.start, end);
            filters.hand_away(a, b);
            self.counts.ring_to_scratch += span.length as u64;
            self.counts.spans_fast += 1;
            self.handed.push_back((span.start, end, true));
            queued = end;
            any = true;
            filters.pop();
        }
        filters.seal();
        // A span left OPEN here stays in the ring until a later drain
        // finds it complete, so the ring must keep it and two batches
        // besides. That held for every span while none was longer than
        // 0x3ffff; since section 3.6's long records (28 Sep 2026) a span
        // may be as long as the dictionary, and one the ring cannot keep
        // goes to the hold, which is what the path below does with it.
        let keeps =
            |span: &Span| span.length as u64 + 2 * self.emit_batch as u64 <= self.ring.len() as u64;
        let front = filters.front();
        if front.is_some_and(|span| span.start < queued || !keeps(&span)) {
            self.put_handed(sink, filters)?;
            return Ok(false);
        }
        let upto = front.map_or(produced, |span| span.start.min(produced));
        if upto > queued {
            self.handed.push_back((queued, upto, false));
        }
        if force || !any {
            self.put_handed(sink, filters)?;
        }
        Ok(!(force && front.is_some()))
    }

    /// [`Window::drain_handing`] on a ring shorter than four batches,
    /// which is every dictionary up to 2 MiB, rarkit's default among them
    /// (the filter layout work, 28 Sep 2026). Such a ring cannot keep a
    /// range until the next drain puts it: two batches of writes may land
    /// before then, and the ring is barely two. So NOTHING this drain
    /// accounts for is left in it. A range before the first span handed
    /// here goes straight out, as the path below sends it; a range after
    /// one is copied out as a plain entry, to be put in member order; and
    /// the produced bytes of a span still open are copied into the
    /// queue's open buffer, which later drains extend and hand away whole.
    /// The ring then needs only what the path below needs, the bytes of
    /// one drain interval, and the drain cadence is the shipped one. So
    /// the four batch form's test that the ring can keep an open span
    /// (section 3.6's long records) has no counterpart here: a span of
    /// any length is copied out as it is produced.
    ///
    /// Without it a filtered member on such a ring ran every transform on
    /// the apply thread: the 60 s six channel 16 bit member rarkit writes
    /// at its default 2 MiB extracted 1.46 times its unfiltered twin's wall
    /// on a Zen 4, and rar's own archive of it
    /// at `-md2m` as much, while at `-md4m` both were level.
    #[cold]
    #[inline(never)]
    fn drain_handing_short<S: LzSink, F: FilterQueue>(
        &mut self,
        sink: &mut S,
        filters: &mut F,
        produced: u64,
        force: bool,
    ) -> Result<bool> {
        let mut queued = self.emitted;
        let mut any = false;
        while let Some(span) = filters.front() {
            let end = span.start + span.length as u64;
            if span.start < queued || end > produced {
                break;
            }
            if span.start > queued {
                self.hand_range(sink, filters, queued, span.start)?;
            }
            let from = span.start + filters.open_len() as u64;
            let (a, b) = self.ring_slices(from, end);
            filters.hand_away(a, b);
            self.counts.ring_to_scratch += end - from;
            self.counts.spans_fast += 1;
            self.handed.push_back((span.start, end, true));
            queued = end;
            any = true;
            filters.pop();
        }
        let front = filters.front();
        if front.is_some_and(|span| span.start < queued) {
            filters.seal();
            self.put_handed(sink, filters)?;
            return Ok(false);
        }
        let upto = front.map_or(produced, |span| span.start.min(produced));
        if upto > queued {
            self.hand_range(sink, filters, queued, upto)?;
        }
        if let Some(span) = front {
            let from = span.start + filters.open_len() as u64;
            if produced > from {
                let (a, b) = self.ring_slices(from, produced);
                filters.hand_open(a, b);
                self.counts.ring_to_hold += produced - from;
            }
        }
        filters.seal();
        if force || !any {
            self.put_handed(sink, filters)?;
        }
        Ok(!(force && front.is_some()))
    }

    /// Account for member offsets `from..to`, which no filter covers, in
    /// the short ring form: straight out when nothing handed is waiting
    /// ahead of them, and copied out as a plain entry otherwise.
    fn hand_range<S: LzSink, F: FilterQueue>(
        &mut self,
        sink: &mut S,
        filters: &mut F,
        from: u64,
        to: u64,
    ) -> Result<()> {
        if self.handed.is_empty() {
            debug_assert_eq!(from, self.emitted);
            return self.emit_range(sink, from, to);
        }
        let (a, b) = self.ring_slices(from, to);
        filters.hand_plain(a, b);
        self.counts.ring_to_scratch += to - from;
        self.handed.push_back((from, to, true));
        Ok(())
    }

    /// The path below takes over from the short ring form with the front
    /// span open: what the queue copied out of it becomes the hold, which
    /// is exactly where that path keeps an open span's bytes. Everything
    /// handed before the span is put by now, so the hold starts at the
    /// emission cursor.
    #[cold]
    #[inline(never)]
    fn hold_open<F: FilterQueue>(&mut self, filters: &mut F) {
        debug_assert!(self.handed.is_empty() && self.hold.is_empty());
        debug_assert_eq!(filters.front().map(|span| span.start), Some(self.emitted));
        if let Some(open) = filters.take_open() {
            self.hold = open;
        }
    }

    /// Send member offsets `from..to` straight out of the ring, as at most
    /// two slices, and advance the emission cursor.
    fn emit_range<S: LzSink>(&mut self, sink: &mut S, from: u64, to: u64) -> Result<()> {
        self.counts.ring_direct += to - from;
        let (a, b) = self.ring_slices(from, to);
        sink.put(a)?;
        if !b.is_empty() {
            sink.put(b)?;
        }
        self.emitted = to;
        Ok(())
    }
}

impl Window {
    /// What the drain path has copied so far. Read through the
    /// `internals` seam, behind the `bench-internals` feature.
    #[cfg_attr(not(feature = "bench-internals"), allow(dead_code))]
    pub(crate) fn drain_counts(&self) -> DrainCounts {
        self.counts
    }
}

#[cfg(test)]
impl Window {
    /// The declared dictionary, which is what bounds a distance.
    pub(crate) fn limit_for_test(&self) -> usize {
        self.limit
    }

    /// The write point's ring index.
    pub(crate) fn at_for_test(&self) -> usize {
        self.at
    }

    /// The whole ring, spill slots included.
    pub(crate) fn ring_for_test(&self) -> &[u8] {
        &self.ring
    }

    /// Overwrite the whole ring with `bytes` and put the write point at
    /// `at`, so a gather can be driven at any placement.
    pub(crate) fn fill_for_test(&mut self, bytes: &[u8], at: usize) {
        assert!(at < self.ring.len(), "a write point past the ring");
        self.ring.copy_from_slice(bytes);
        self.at = at;
    }

    /// How many copies have taken the slow path so far.
    pub(crate) fn slow_copies_for_test(&self) -> u64 {
        self.slow_copies
    }

    /// Write one byte `ahead` bytes PAST the write point, without moving
    /// the write point: exactly what a tape lane writing its block's
    /// literal runs straight into the ring region the block will occupy
    /// would do, and the whole of what that direction needs from the
    /// window.
    ///
    /// It exists so that
    /// `the_room_ahead_of_the_apply_point_is_the_spill_margin_and_no_more`
    /// can SHOW what such a write destroys rather than deriving it, and it
    /// is `cfg(test)` because no shipped path may write ahead of the apply
    /// point at all (21 Sep 2026).
    pub(crate) fn poke_ahead_for_test(&mut self, ahead: usize, byte: u8) {
        let slot = (self.at + ahead) % self.ring.len();
        self.ring[slot] = byte;
    }

    /// What that slot holds now.
    pub(crate) fn peek_ahead_for_test(&self, ahead: usize) -> u8 {
        self.ring[(self.at + ahead) % self.ring.len()]
    }

    /// Place the counters where a member several gigabytes into a solid
    /// chain would have them.
    ///
    /// THIS is how the behaviour of a 32-bit target is exercised on a
    /// 64-bit host: no machine this project is built on could produce 4 GiB of
    /// output in a test, and every one of them is 64-bit, so the
    /// arithmetic above 4 GiB is driven rather than produced.
    pub(crate) fn seed_counters_for_test(&mut self, stream: u64, member_base: u64) {
        assert!(stream >= self.at as u64, "a stream count short of the ring");
        assert!(member_base <= stream, "a member starting after the stream");
        self.lap_base = stream - self.at as u64;
        self.member_base = member_base;
        // Everything the member has produced so far counts as ALREADY
        // emitted: nothing of it is in the ring, and `drain` asserts that
        // what has not left is at most a lap.
        self.emitted = stream - member_base;
        self.next_drain = self.emitted + self.emit_batch as u64;
        self.hold.clear();
    }
}

/// A member driven straight through a [`Window`] at the TAPE WALK's drain
/// cadence, against the same member in a ring that cannot lap: the
/// regression ladder for the drain lap of 23 Sep 2026 and its fuzz seam
/// (`fuzz:rar5_drain_lap`) share this one walk.
#[cfg(any(test, feature = "bench-internals"))]
pub(crate) mod lap {
    use super::super::filters::{FilterKind, Filters, Record};
    use super::{Span, Window, MAX_APPEND};
    use crate::Result;

    /// One step: a literal run, a match, or a filter record whose span
    /// starts `offset` bytes past the bytes produced when it is pushed.
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Step {
        Lits(usize),
        Match {
            distance: usize,
            length: usize,
        },
        Filter {
            offset: u64,
            length: usize,
            kind: FilterKind,
        },
    }

    /// The bytes of literal run `index`, seeded so no two runs agree.
    pub(crate) fn run(index: usize, length: usize) -> Vec<u8> {
        let mut seed = 0x2309_2026u32 ^ (index as u32).wrapping_mul(0x9E37_79B1);
        (0..length)
            .map(|_| {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (seed >> 21) as u8
            })
            .collect()
    }

    /// Drive `steps` through a window of dictionary `dictionary` the way
    /// `tape::apply` does. An operation that fits the budget before the
    /// next drain is written whole; one that does not goes the checked
    /// way, a match whole and a literal run in chunks of `drain_batch()`
    /// with the due test after each chunk, which is the widest write any
    /// caller makes between two due tests. `reference` instead writes at
    /// most `MAX_APPEND` bytes between due tests into a ring that holds
    /// the whole member, so nothing in it can lap: the member's true
    /// bytes.
    pub(crate) fn walk(
        dictionary: u64,
        ceiling: u64,
        offload: bool,
        steps: &[Step],
        reference: bool,
    ) -> Result<Vec<u8>> {
        let total: usize = steps
            .iter()
            .map(|step| match step {
                Step::Lits(length) | Step::Match { length, .. } => *length,
                Step::Filter { .. } => 0,
            })
            .sum();
        let mut win = if reference {
            Window::new((total as u64).max(dictionary) + (1 << 20), u64::MAX)?
        } else {
            Window::new(dictionary, ceiling)?
        };
        win.reset();
        win.begin_member();
        let mut filters = Filters::for_dictionary(dictionary);
        filters.offload = offload;
        let mut sink: Vec<u8> = Vec::new();
        for (index, step) in steps.iter().enumerate() {
            let length = match *step {
                Step::Filter {
                    offset,
                    length,
                    kind,
                } => {
                    if win.drain_due() {
                        win.drain(&mut sink, &mut filters, false)?;
                    }
                    let span = Span {
                        start: win.produced() + offset,
                        length,
                    };
                    filters.push(Record { span, kind })?;
                    continue;
                }
                Step::Lits(length) | Step::Match { length, .. } => length,
            };
            let fits = !reference && {
                let budget = win.apply_budget();
                budget != 0 && length <= budget
            };
            if !fits && win.drain_due() {
                win.drain(&mut sink, &mut filters, false)?;
            }
            match *step {
                Step::Match { distance, length } => win.copy_match(distance, length)?,
                _ => {
                    let bytes = run(index, length);
                    let chunk = if reference {
                        MAX_APPEND
                    } else if fits {
                        length
                    } else {
                        win.drain_batch()
                    };
                    for piece in bytes.chunks(chunk) {
                        win.literals(piece);
                        if !fits && win.drain_due() {
                            win.drain(&mut sink, &mut filters, false)?;
                        }
                    }
                    continue;
                }
            }
            if reference && win.drain_due() {
                win.drain(&mut sink, &mut filters, false)?;
            }
        }
        win.drain(&mut sink, &mut filters, true)?;
        Ok(sink)
    }

    /// The rings a dictionary can give, smallest first: a stated 128 KiB
    /// budget, the floor, and up past the ring of four batches.
    pub(crate) const LADDER: [(u64, u64); 7] = [
        (128 << 10, 128 << 10),
        (128 << 10, u64::MAX),
        (256 << 10, 256 << 10),
        (1 << 20, u64::MAX),
        (2 << 20, u64::MAX),
        (3 << 20, u64::MAX),
        (4 << 20, u64::MAX),
    ];

    /// A member out of a fuzz `script`: its first byte picks the rung, its
    /// second the offload, and the rest steer a seeded generator, cycling,
    /// so a short script still reaches every shape. The member is three
    /// rings long by CONSTRUCTION, whatever the script's length
    /// (the fuzz target inventory), and its operations lean on the
    /// widths that matter to the drain: a batch and a byte either side,
    /// the run to the next batch edge, spans placed on and around that
    /// edge, and matches that overshoot it.
    pub(crate) fn from_script(script: &[u8]) -> (u64, u64, bool, Vec<Step>) {
        let pick = |i: usize| script.get(i).copied().unwrap_or(0);
        let (dictionary, ceiling) = LADDER[usize::from(pick(0)) % LADDER.len()];
        let offload = pick(1) & 1 == 1;
        let probe = Window::new(dictionary, ceiling).expect("a ladder rung allocates");
        let (ring, b) = (probe.ring_bytes(), probe.drain_batch());
        drop(probe);
        let mut rng = script.iter().fold(0x2309_2026u32, |h, &x| {
            h.rotate_left(5) ^ u32::from(x).wrapping_mul(0x9E37_79B1)
        }) | 1;
        let mut at = 1usize;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 17;
            rng ^= rng << 5;
            let steer = if script.len() > 2 {
                at = 2 + (at - 1) % (script.len() - 2);
                u32::from(script[at])
            } else {
                0
            };
            (rng ^ steer) as usize
        };
        let total = 3 * ring + next() % b;
        let kinds = [
            FilterKind::Delta(1),
            FilterKind::Delta(3),
            FilterKind::X86Call,
            FilterKind::X86CallJump,
            FilterKind::Arm,
        ];
        let mut steps = Vec::new();
        let mut produced = 0usize;
        let mut clear_from = 0usize;
        let mut spans = 0usize;
        while produced < total {
            let to_edge = b - produced % b;
            let r = next();
            let step = match r % 16 {
                0 | 1 if spans < 2_000 => {
                    let start = match next() % 4 {
                        0 => produced,
                        1 => produced + next() % 4_000,
                        2 => (produced + to_edge).saturating_sub(next() % 300),
                        _ => produced + to_edge + next() % 300,
                    }
                    // Never behind the bytes produced: a span reaching back
                    // behind the emission cursor is the overlap section 3.6
                    // leaves open, which this seam does not ask about.
                    .max(produced)
                    .max(clear_from);
                    let length = match next() % 4 {
                        0 => next() % 64,
                        1 => next() % 4_096,
                        _ => next() % super::super::filters::MAX_FILTER_BLOCK_LENGTH,
                    };
                    clear_from = start + length;
                    spans += 1;
                    Step::Filter {
                        offset: (start - produced) as u64,
                        length,
                        kind: kinds[next() % kinds.len()],
                    }
                }
                2 => Step::Lits(b - 1 + next() % 3),
                3 => Step::Lits((to_edge + next() % 3).saturating_sub(1).max(1)),
                4..=6 if produced > 0 => Step::Match {
                    distance: 1 + next() % produced.min(dictionary as usize),
                    length: 2 + next() % 4_099,
                },
                7..=9 => Step::Lits(1 + next() % 64),
                10..=12 => Step::Lits(1 + next() % 4_000),
                _ => Step::Lits(1 + next() % (b / 2)),
            };
            if let Step::Lits(length) | Step::Match { length, .. } = step {
                produced += length;
            }
            steps.push(step);
        }
        (dictionary, ceiling, offload, steps)
    }

    /// The fuzz seam's check: the member out of `script` comes out of the
    /// rung's ring exactly as out of the ring that cannot lap, errors
    /// included. Answers the member's length.
    pub(crate) fn agrees(script: &[u8]) -> usize {
        let (dictionary, ceiling, offload, steps) = from_script(script);
        let want = walk(dictionary, ceiling, false, &steps, true);
        let got = walk(dictionary, ceiling, offload, &steps, false);
        match (&want, &got) {
            (Ok(want), Ok(got)) => {
                assert!(
                    want == got,
                    "dictionary {dictionary}, ceiling {ceiling}, offload {offload}: \
                     the ring lapped unemitted bytes"
                );
                got.len()
            }
            (Err(want), Err(got)) => {
                assert_eq!(
                    format!("{:?}", want.kind()),
                    format!("{:?}", got.kind()),
                    "the two rings failed differently"
                );
                0
            }
            _ => panic!("one ring failed and the other did not: {want:?} / {got:?}"),
        }
    }
}

/// One queued filter's span and what it takes to run it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Span {
    /// Member relative start (section 3.6). `u64`: a member may be
    /// larger than 4 GiB, so a span may start past what a 32-bit `usize`
    /// holds. The LENGTH stays a `usize`: section 3.6 queues no span of
    /// more than `filters::IGNORED_ABOVE` (4 MiB), well under 4 GiB.
    pub(crate) start: u64,
    pub(crate) length: usize,
}

/// The pending filter queue, as [`Window::drain`] sees it.
pub(crate) trait FilterQueue {
    /// The queued filter with the lowest start, if any.
    fn front(&self) -> Option<Span>;
    /// Run that filter's transform over `data`, which is its whole span.
    fn apply(&mut self, span: &Span, data: &mut [u8]);
    /// Drop the front filter.
    fn pop(&mut self);
    /// Where a queued span that runs PAST the member's declared size
    /// ends, member relative, and zero when the queue holds none: the
    /// drain runs through to it and delivers nothing past the declared
    /// size ([`Window::drain`]). Only a queue that knows the member
    /// carries no checksum ever answers above zero.
    fn reach(&self) -> u64 {
        0
    }
    /// Whether [`Window::drain`] may hand the front filter's transform
    /// away rather than run it here (`filters::Offload`). Off by default,
    /// which is every queue but the tape path's.
    fn offload(&self) -> bool {
        false
    }
    /// Hand the front filter away with its span's bytes, `first` then
    /// `second`, copied out of the ring after any [`Self::hand_open`]
    /// already took. The caller pops it after.
    fn hand_away(&mut self, _first: &[u8], _second: &[u8]) {}
    /// Hand away a range no filter covers, to be put as it is, in member
    /// order with the spans around it.
    fn hand_plain(&mut self, _first: &[u8], _second: &[u8]) {}
    /// Copy out the next bytes of the front filter's span while it is
    /// still open.
    fn hand_open(&mut self, _first: &[u8], _second: &[u8]) {}
    /// How many bytes of the front filter's span [`Self::hand_open`] has
    /// copied out.
    fn open_len(&self) -> usize {
        0
    }
    /// Take back what [`Self::hand_open`] copied out.
    fn take_open(&mut self) -> Option<Vec<u8>> {
        None
    }
    /// Send what this drain handed away to be transformed.
    fn seal(&mut self) {}
    /// Put the oldest handed filter's transformed span to `sink`, waiting
    /// for it if it is still being transformed, and answer its length.
    fn put_handed<S: LzSink>(&mut self, _sink: &mut S) -> Result<usize> {
        Ok(0)
    }
}

/// No filters at all: what the block chain uses before any record is read.
// Live in the `cfg(test)` build only: this package's own tests are its
// one caller.
#[allow(dead_code)]
pub(crate) struct NoFilters;

impl FilterQueue for NoFilters {
    fn front(&self) -> Option<Span> {
        None
    }
    fn apply(&mut self, _span: &Span, _data: &mut [u8]) {}
    fn pop(&mut self) {}
}

/// THE SYMBOL PASS's apply half (`super::symbols` is the rest).
///
/// A decode lane has already walked a block's operations into one 32-bit
/// SYMBOL per output byte: a literal byte tagged with
/// [`Window::SYMBOL_LITERAL`], or the NAME of a byte from before the
/// block's gathered part, as how far back of that part's first byte it
/// sits. Every byte a RAR 5 block produces is a literal or a copy of one
/// earlier byte (SPEC-H2 3.7, byte at a time), so a copy of a literal is a
/// literal and a copy of a name is the same name; nothing is left for this
/// thread to resolve but the gather.
impl Window {
    /// The tag of a literal symbol; its low byte is the literal.
    #[cfg(feature = "parallel")]
    pub(crate) const SYMBOL_LITERAL: u32 = 1 << 31;

    /// How far back of a gathered part [`Window::put_symbols`]'s fast form
    /// reads, as a fixed-size array: a power of two, and the smallest RAR 5
    /// dictionary, so every name of a 128 KiB member fits it (a name counts
    /// back at most the declared dictionary).
    #[cfg(feature = "parallel")]
    pub(crate) const GATHER_WINDOW: usize = 1 << 17;

    /// Write the bytes `symbols` stand for at the write point, where the
    /// first of them is `origin` bytes past the gathered part's first
    /// byte, which is what every name counts back from, and no name counts
    /// back further than `reach`.
    ///
    /// **Why every read is a final byte.** A name points before the
    /// gathered part, which this thread wrote before this call. The caller
    /// (`symbols::apply`) admits a part only when its length plus its
    /// farthest name fits the ring, so no byte this call writes lands on a
    /// slot a later symbol of the same part still reads; and it cuts the
    /// part at the drain cadence exactly as the walk would, so the ring
    /// never laps what has not left it.
    ///
    /// **The fast form.** Where every name reaches at most
    /// [`Window::GATHER_WINDOW`] back, the names are read through a
    /// fixed-size array of that many bytes ending at the part's first byte,
    /// indexed under its mask, so a read carries no bounds check and no
    /// wrap arithmetic, and the bytes land in the ring directly, the part
    /// cut at the ring's end so no write wraps. The array is the ring
    /// itself where the history is one run of it, and otherwise a copy of
    /// the history's two runs into a scratch, made once per piece. A name
    /// past the window, or a ring shorter than two windows, takes
    /// [`Window::put_symbols_wide`].
    /// Safe code in both.
    #[cfg(feature = "parallel")]
    pub(crate) fn put_symbols(&mut self, symbols: &[u32], origin: usize, reach: usize) {
        const WINDOW: usize = Window::GATHER_WINDOW;
        let ring_len = self.ring.len();
        debug_assert!(origin + symbols.len() + reach <= ring_len);
        if reach > WINDOW || ring_len < 2 * WINDOW {
            self.put_symbols_wide(symbols, origin, reach);
            return;
        }
        // One scratch per thread for a history that wraps the ring's end.
        thread_local! {
            static WRAPPED: std::cell::RefCell<Box<[u8; Window::GATHER_WINDOW]>> =
                std::cell::RefCell::new(
                    vec![0u8; Window::GATHER_WINDOW]
                        .into_boxed_slice()
                        .try_into()
                        .expect("a box of exactly the window's length"),
                );
        }
        let mut done = 0usize;
        while done < symbols.len() {
            let at = self.at;
            let origin = origin + done;
            // Up to the ring's end: the write side never wraps inside a run.
            let n = (symbols.len() - done).min(ring_len - at);
            let part = &symbols[done..done + n];
            if at >= origin + WINDOW {
                // The history is one run of the ring, just behind the part.
                let start = at - origin;
                let (front, back) = self.ring.split_at_mut(at);
                let history: &[u8; WINDOW] = (&front[start - WINDOW..start])
                    .try_into()
                    .expect("a slice of exactly the window's length");
                gather(history, part, &mut back[..n], reach);
            } else {
                // The history wraps the ring's end: copied once, two runs,
                // into the thread's scratch. Every byte of it is behind the
                // part, so nothing the loop below writes is in it.
                let start = if at >= origin {
                    at - origin
                } else {
                    at + ring_len - origin
                };
                WRAPPED.with(|scratch| {
                    let mut history = scratch.borrow_mut();
                    let tail = WINDOW.saturating_sub(start);
                    history[..tail].copy_from_slice(&self.ring[ring_len - tail..]);
                    history[tail..].copy_from_slice(&self.ring[start + tail - WINDOW..start]);
                    gather(&history, part, &mut self.ring[at..at + n], reach);
                });
            }
            self.advance(n);
            done += n;
        }

        /// The gather itself: one symbol, one masked read of the history
        /// and one select per byte, no bounds check and no branch.
        ///
        /// OUT OF LINE so its loop is compiled on its own: inlined, LLVM's
        /// unroll of it followed whichever function it landed in, and a
        /// change elsewhere in the module turned a four-way interleave (7.75
        /// instructions a symbol) into a three-way unroll (9), md128k +3
        /// percent (the md128k partition census).
        #[inline(never)]
        fn gather(history: &[u8; WINDOW], part: &[u32], out: &mut [u8], reach: usize) {
            let _ = reach;
            for (out, &symbol) in out.iter_mut().zip(part) {
                let name = (symbol & !Window::SYMBOL_LITERAL) as usize;
                #[cfg(debug_assertions)]
                if symbol & Window::SYMBOL_LITERAL == 0 {
                    assert!(
                        name >= 1 && name <= reach,
                        "a symbol names byte {name} back of its part, past its reach {reach}"
                    );
                }
                let from = history[(WINDOW - name) & (WINDOW - 1)];
                *out = if symbol & Window::SYMBOL_LITERAL != 0 {
                    symbol as u8
                } else {
                    from
                };
            }
        }
    }

    /// The widest fixed view [`Window::put_symbols_wide`] borrows: half the
    /// ring floor, so a view and the part it serves both fit a floor ring,
    /// and every name of a 512 KiB member fits it. Larger dictionaries
    /// never reach the gather ([`super::symbols::fits`]).
    #[cfg(feature = "parallel")]
    pub(crate) const WIDE_VIEW: usize = RING_FLOOR / 2;

    /// [`Window::put_symbols`] for a part whose names reach past
    /// [`Window::GATHER_WINDOW`], which is the 256 KiB and 512 KiB
    /// dictionaries.
    /// Two forms, both writing the part straight into the ring, and
    /// neither holding a byte of history anywhere but the ring:
    ///
    /// - **THE FIXED VIEW.** Where the part starts at least a view's length
    ///   into the ring, the view (256 KiB, or 512 KiB for a reach past
    ///   that) is one run of the ring just behind the part, borrowed as a
    ///   fixed-size array and read under its mask: the 128 KiB fast form's
    ///   gather at a larger power of two, with no scratch, because a
    ///   history that wraps is not given this form.
    /// - **DIRECT BORROWING.** Otherwise, which is where the history wraps
    ///   the ring's end (its two runs, the ring's tail and its head) or the
    ///   part began on the lap before, each name is read from the ring at
    ///   its own index, taken across the ring's end by one subtraction,
    ///   and each byte is written in place. The ring is borrowed as cells
    ///   so one view both reads and writes, in safe code.
    ///
    /// **Why a read never sees a byte of this part.** The caller admits a
    /// part only when its length plus its farthest name fits the ring
    /// (`symbols::apply`), so every name lands in the `reach` slots behind
    /// the part's first byte and every write lands in the part's own slots,
    /// and the two ranges are disjoint around the ring. Both forms read
    /// exactly the byte the general walk would.
    ///
    /// **What it replaced**, and why it is not `#[cold]`: a general form
    /// that reduced each index into the ring into a 4 KiB stack buffer and
    /// copied the buffer into the ring after, which was priced
    /// at about 29 percent of these members' decode work
    /// and which is their hot path, not a fallback.
    #[cfg(feature = "parallel")]
    #[inline(never)]
    fn put_symbols_wide(&mut self, symbols: &[u32], origin: usize, reach: usize) {
        const NARROW: usize = Window::WIDE_VIEW / 2;
        const WIDE: usize = Window::WIDE_VIEW;
        let ring_len = self.ring.len();
        debug_assert!(origin + symbols.len() + reach <= ring_len);
        let mut done = 0usize;
        while done < symbols.len() {
            let at = self.at;
            let origin = origin + done;
            // Up to the ring's end: the write side never wraps inside a run.
            let n = (symbols.len() - done).min(ring_len - at);
            let part = &symbols[done..done + n];
            // The ring index of the part's first byte, which every name
            // counts back from.
            let start = if at >= origin {
                at - origin
            } else {
                at + ring_len - origin
            };
            let view = if reach <= NARROW {
                NARROW
            } else if reach <= WIDE {
                WIDE
            } else {
                usize::MAX
            };
            if at >= origin && start >= view {
                let (front, back) = self.ring.split_at_mut(at);
                let history = &front[start - view..start];
                if view == NARROW {
                    let history: &[u8; NARROW] = history
                        .try_into()
                        .expect("a slice of exactly the view's length");
                    #[cfg(test)]
                    WIDE_FORMS.with(|c| c.set((c.get().0 + 1, c.get().1)));
                    gather_view(history, part, &mut back[..n], reach);
                } else {
                    let history: &[u8; WIDE] = history
                        .try_into()
                        .expect("a slice of exactly the view's length");
                    #[cfg(test)]
                    WIDE_FORMS.with(|c| c.set((c.get().0 + 1, c.get().1)));
                    gather_view(history, part, &mut back[..n], reach);
                }
            } else {
                #[cfg(test)]
                WIDE_FORMS.with(|c| c.set((c.get().0, c.get().1 + 1)));
                let ring = std::cell::Cell::from_mut(&mut self.ring[..]).as_slice_of_cells();
                gather_direct(ring, start, part, at);
            }
            self.advance(n);
            done += n;
        }
    }
}

#[cfg(all(test, feature = "parallel"))]
thread_local! {
    /// How many runs [`Window::put_symbols_wide`] gave the fixed view and
    /// how many it borrowed directly, in test builds, so a test can show
    /// which form a case took and not only that its bytes came out right.
    pub(crate) static WIDE_FORMS: std::cell::Cell<(u64, u64)> =
        const { std::cell::Cell::new((0, 0)) };
}

/// [`Window::put_symbols_wide`]'s fixed view: one symbol, one masked read
/// of a `W`-byte history ending at the part's first byte and one select a
/// byte, no bounds check and no branch. Out of line for the reason the
/// 128 KiB form's `gather` is (the partition finding): its loop is
/// compiled on its own, whatever else the module holds. That form is left
/// as it is rather than made this one at `W` = 128 KiB, so md128k's code
/// does not move.
#[cfg(feature = "parallel")]
#[inline(never)]
fn gather_view<const W: usize>(history: &[u8; W], part: &[u32], out: &mut [u8], reach: usize) {
    let _ = reach;
    for (out, &symbol) in out.iter_mut().zip(part) {
        let name = (symbol & !Window::SYMBOL_LITERAL) as usize;
        #[cfg(debug_assertions)]
        if symbol & Window::SYMBOL_LITERAL == 0 {
            assert!(
                name >= 1 && name <= reach,
                "a symbol names byte {name} back of its part, past its reach {reach}"
            );
        }
        let from = history[(W - name) & (W - 1)];
        *out = if symbol & Window::SYMBOL_LITERAL != 0 {
            symbol as u8
        } else {
            from
        };
    }
}

/// [`Window::put_symbols_wide`]'s direct borrowing: the part's bytes read
/// from the ring's cells at their own indices, `start` being the ring
/// index of the part's first byte, and written at `at` onward. A literal
/// reads at its byte's value back, at most 255, which is inside the ring
/// after the wrap too, and discards what it read.
///
/// **THE MASKED FORM.** A ring of exactly [`RING_FLOOR`] bytes, which is
/// every dictionary the symbol pass takes unless a stated budget made the
/// ring smaller, is viewed as a fixed-size array and a name is taken across
/// its end under the power of two's mask: no compare, no select and no
/// bounds check. Any other ring reduces the index by one conditional
/// subtraction and is bounds checked. Both read the same byte.
#[cfg(feature = "parallel")]
#[inline(always)]
fn gather_direct(ring: &[std::cell::Cell<u8>], start: usize, part: &[u32], at: usize) {
    let ring_len = ring.len();
    if let Ok(whole) = <&[std::cell::Cell<u8>; RING_FLOOR]>::try_from(ring) {
        let byte = |symbol: u32| {
            let name = direct_name(symbol, ring_len);
            let from = whole[start.wrapping_sub(name) & (RING_FLOOR - 1)].get();
            direct_select(symbol, from)
        };
        direct_steps(ring, part, at, byte);
    } else {
        let base = start + ring_len;
        let byte = |symbol: u32| {
            let t = base - direct_name(symbol, ring_len);
            let index = if t >= ring_len { t - ring_len } else { t };
            direct_select(symbol, ring[index].get())
        };
        direct_steps(ring, part, at, byte);
    }
}

/// A symbol's name, the literal's byte for a literal.
#[cfg(feature = "parallel")]
#[inline(always)]
fn direct_name(symbol: u32, ring_len: usize) -> usize {
    let name = (symbol & !Window::SYMBOL_LITERAL) as usize;
    #[cfg(debug_assertions)]
    if symbol & Window::SYMBOL_LITERAL == 0 {
        assert!(
            name >= 1 && name < ring_len,
            "a symbol names byte {name} back of its part, outside the ring"
        );
    }
    let _ = ring_len;
    name
}

/// The literal, or the byte its name read.
#[cfg(feature = "parallel")]
#[inline(always)]
fn direct_select(symbol: u32, from: u8) -> u8 {
    if symbol & Window::SYMBOL_LITERAL != 0 {
        symbol as u8
    } else {
        from
    }
}

/// FOUR SYMBOLS A STEP, all four read before any is written. Through cells
/// the compiler may not move a read above an earlier write, so a plain loop
/// is one read, select and store after another; a step that reads first
/// gives four independent reads (nothing a step reads is in the part, so
/// the order changes no byte).
#[cfg(feature = "parallel")]
#[inline(always)]
fn direct_steps(ring: &[std::cell::Cell<u8>], part: &[u32], at: usize, byte: impl Fn(u32) -> u8) {
    let out = &ring[at..at + part.len()];
    let (steps, part_tail) = part.as_chunks::<4>();
    let (outs, out_tail) = out.as_chunks::<4>();
    for (out, &[a, b, c, d]) in outs.iter().zip(steps) {
        let bytes = [byte(a), byte(b), byte(c), byte(d)];
        for (out, b) in out.iter().zip(bytes) {
            out.set(b);
        }
    }
    for (out, &symbol) in out_tail.iter().zip(part_tail) {
        out.set(byte(symbol));
    }
}
