//! The window a RAR 3 stream produces into (SPEC-H1 3.6): one ring of the
//! declared dictionary size, allocated once per stream, never cleared
//! between members of a solid chain and never grown or shrunk.

use crate::error::{Corruption, Rar3Fault};
use crate::ppmd::StreamWindow;
use crate::rar3_lz::tables::MAX_DISTANCE;
use crate::{Error, ErrorKind, Result};

/// The bytes a stream has produced, most recent last.
#[derive(Debug)]
pub(crate) struct Window {
    ring: Box<[u8]>,
    /// Where the next byte is written.
    head: usize,
    /// Bytes produced since the stream started; never wraps.
    produced: u64,
}

fn out_of_range() -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::Rar3(
        Rar3Fault::DistanceOutOfRange,
    )))
}

// ---------------------------------------------------------------------
// The COPY CENSUS (bench-internals only, and OFF unless asked for).
//
// The profile of `rar3_text_64m_lz` puts 12.09 percent of rarkit's arm in
// `_platform_memmove` plus 2.77 in its stub, and `Window::copy` has two
// paths that could be issuing those calls: the NON-OVERLAPPING one, whose
// fixed-width ladder answers the call cost up to 64 bytes and falls
// through to a variable length `copy_within` above it, and the
// OVERLAPPING one, whose doubling chunk loop copies a VARIABLE length at
// every chunk and so is a call every time. A leaf census cannot tell them
// apart; this counts them.
//
// Counting is a COUNTING instrument and never a timing one. It is behind
// `bench-internals`, it is off unless `RARKIT_H1_COPY_CENSUS` is set, and
// the timed arm therefore pays one already-resolved bool load. Nothing
// here is read by a gate row.
#[cfg(feature = "copy-census")]
pub mod census {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::OnceLock;

    /// Where a copy went, and whether it was a `memmove` CALL.
    pub const BUCKETS: [&str; 6] = [
        "overlap-chunks (variable copy_within, a CALL each)",
        "overlap-calls-total (chunks issued by the loop above)",
        "ladder-fixed (a load and a store, NO call)",
        "ladder-bytewise (1 to 3 bytes, NO call)",
        "ladder-fallthrough (len > 64, variable copy_within, a CALL)",
        "other (wrapping or behind-start, variable copy_within, a CALL)",
    ];
    pub const OVERLAP: usize = 0;
    pub const OVERLAP_CALLS: usize = 1;
    pub const LADDER_FIXED: usize = 2;
    pub const LADDER_BYTEWISE: usize = 3;
    pub const LADDER_FALLTHROUGH: usize = 4;
    pub const OTHER: usize = 5;

    static COUNTS: [AtomicU64; 6] = [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ];
    static BYTES: [AtomicU64; 6] = [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ];
    static ON: OnceLock<AtomicBool> = OnceLock::new();

    pub(crate) fn on() -> bool {
        ON.get_or_init(|| AtomicBool::new(std::env::var_os("RARKIT_H1_COPY_CENSUS").is_some()))
            .load(Ordering::Relaxed)
    }

    #[inline]
    pub(crate) fn hit(bucket: usize, bytes: u64) {
        COUNTS[bucket].fetch_add(1, Ordering::Relaxed);
        BYTES[bucket].fetch_add(bytes, Ordering::Relaxed);
    }

    /// (calls, bytes) per bucket, in `BUCKETS` order.
    pub fn read() -> [(u64, u64); 6] {
        let mut out = [(0u64, 0u64); 6];
        for i in 0..6 {
            out[i] = (
                COUNTS[i].load(Ordering::Relaxed),
                BYTES[i].load(Ordering::Relaxed),
            );
        }
        out
    }

    pub fn reset() {
        for i in 0..6 {
            COUNTS[i].store(0, Ordering::Relaxed);
            BYTES[i].store(0, Ordering::Relaxed);
        }
    }
}

#[cfg(feature = "copy-census")]
macro_rules! census {
    ($bucket:expr, $bytes:expr) => {
        if $crate::rar3_lz::window::census::on() {
            $crate::rar3_lz::window::census::hit($bucket, $bytes as u64);
        }
    };
}
#[cfg(not(feature = "copy-census"))]
macro_rules! census {
    ($bucket:expr, $bytes:expr) => {};
}

impl Window {
    /// A window of `capacity` bytes, which spec F has already checked
    /// against [`MemoryPolicy::max_window`](crate::MemoryPolicy).
    ///
    /// The RAR 3 family declares `65,536 << n` for `n` in 0 to 6; a
    /// capacity above [`MAX_DISTANCE`] can never be reached by a match, so
    /// it is held down to it.
    pub(crate) fn new(capacity: u32) -> Window {
        let capacity = capacity.clamp(1, MAX_DISTANCE) as usize;
        Window {
            ring: vec![0; capacity].into_boxed_slice(),
            head: 0,
            produced: 0,
        }
    }

    /// Start a new stream in the same allocation.
    pub(crate) fn reset(&mut self) {
        self.head = 0;
        self.produced = 0;
    }

    /// The declared dictionary size.
    pub(crate) fn capacity(&self) -> u32 {
        self.ring.len() as u32
    }

    /// Bytes produced since the stream started.
    pub(crate) fn produced(&self) -> u64 {
        self.produced
    }

    /// Bytes of working memory this window holds.
    pub(crate) fn held_bytes(&self) -> u64 {
        self.ring.len() as u64
    }

    /// Append one byte.
    #[inline(always)]
    pub(crate) fn put(&mut self, byte: u8) -> Result<()> {
        self.ring[self.head] = byte;
        self.head += 1;
        if self.head == self.ring.len() {
            self.head = 0;
        }
        self.produced += 1;
        Ok(())
    }

    /// The window's own room for the next literals, from the write point
    /// to the ring's end: the burst of SPEC-H1 7.3 item 5 decodes
    /// straight into it and says how much it used with
    /// [`Window::commit`].
    #[inline]
    pub(crate) fn free_run(&mut self) -> &mut [u8] {
        let head = self.head;
        &mut self.ring[head..]
    }

    /// Take `count` bytes written into [`Window::free_run`].
    #[inline]
    pub(crate) fn commit(&mut self, count: usize) {
        self.head += count;
        if self.head == self.ring.len() {
            self.head = 0;
        }
        self.produced += count as u64;
    }

    /// `length` bytes from `distance` back, overlapping allowed.
    ///
    /// The result is always the byte at a time result: every chunk copied
    /// is at most `distance` long, so a source byte is never read before
    /// it is written (SPEC-H1 3.6, pinned by the property test of 5.5).
    ///
    /// # The write invariant, in this window's own terms
    ///
    /// This ring is EXACTLY the declared dictionary (SPEC-H1 3.6): it is
    /// allocated once at `capacity`, never grown, never cleared between
    /// members of a solid chain, and it carries NO MARGIN. So the byte at
    /// ring index `head + j` is the one the stream produced
    /// `ring.len() - j` ago, and it is the SOURCE a match at distance
    /// `ring.len() - j` names. Not one slot past the write point is dead.
    ///
    /// **A copy owns `[head, head + length)` around the ring and nothing
    /// else, and no slot past it may be dirtied**, because the range check
    /// above admits every distance up to `ring.len()` and so every one of
    /// them is nameable the moment the stream has produced that many
    /// bytes. There is no filter span and no PPM hand-over that changes
    /// this: spec J's filters read the window through
    /// [`Window::slices`], which lends `&[u8]`, and spec I's PPM decoder
    /// writes through [`Window::put`] and this very method (spec I
    /// section 2), so both are inside the same invariant.
    ///
    /// The mechanism that keeps it is EXACTNESS: every `run` below is
    /// `left.min(..)`, so no branch of this function ever writes a byte it
    /// was not asked for. `crate::window_guard` is what says so on every
    /// copy in a test build rather than in this comment alone; with a
    /// margin of zero here, EVERY watched slot is reachable once the
    /// stream has lapped, so any spill at all fails.
    ///
    /// The literal paths need no guard of their own: [`Window::put`]
    /// writes one byte and [`Window::commit`] takes only what the burst
    /// counted into [`Window::free_run`], which is bounded by that
    /// slice's own length.
    ///
    /// # The one shape that is answered without the loop
    ///
    /// A match whose source lies whole behind the write point, whose
    /// destination stops short of the ring's end, and which is no longer
    /// than its own distance, is ONE copy of disjoint bytes: the loop
    /// below would run exactly one iteration and compute three `min`s and
    /// two wrap tests to discover that. It is taken out because it is not
    /// a special case in practice but the ordinary one - **3,132,923 of
    /// the 3,135,516 copies, 99.9%,** over the RAR 4 `-m3` corpus of
    /// `two_arm.rs`, mean length 9.67 bytes. The write is the same width
    /// either way, so the invariant above is untouched and the guard still
    /// brackets it.
    ///
    /// # Why the common shape is inlined and the rest is not
    ///
    /// Until 22 Sep 2026 this whole function was one `#[inline]` body of
    /// 364 instructions in the release build and the compiler declined to
    /// inline it, so EVERY match paid a call: the decoder's hot state went
    /// to memory and came back, around a copy whose mean length on the
    /// text leg is 20 bytes. Removing the copy's body outright took 276
    /// million instructions a round off `rar3_text_64m_lz`, 83 a match
    /// (the RAR 3 rows against the FIXED old
    /// arm), which is far more than a 20 byte ladder costs; most of it
    /// was the call.
    ///
    /// So the ONE shape the census says is 92.9 percent of that leg's
    /// copies - behind the write point, no wrap, no overlap, at most 64
    /// bytes, the fixed width rungs - is answered here, inline, and every
    /// other shape goes to [`Window::copy_general`], out of line, which is
    /// the function this used to be, unchanged. The rungs are the same
    /// rungs and write the same bytes; only the call boundary moves.
    #[inline(always)]
    pub(crate) fn copy(&mut self, distance: u32, length: u32) -> Result<()> {
        let step = distance as usize;
        let len = length as usize;
        let to = self.head;
        // Every condition the general path's range check and its ladder
        // arm ask, and nothing looser: `distance` is nonzero and within
        // what the stream has produced; `step <= to` puts the source
        // whole behind the write point, which also makes `distance` no
        // larger than the ring; `len <= step` makes the two ranges
        // disjoint; `to + len < size` keeps the write off the ring's end.
        // Anything else, including every refusal, is the general path's.
        if distance != 0
            && u64::from(distance) <= self.produced
            && len <= step
            && step <= to
            && len <= 64
            && to + len < self.ring.len()
        {
            #[cfg(debug_assertions)]
            let watch = crate::window_guard::SpillWatch::take(&self.ring, self.head, len);
            let from = to - step;
            self.rungs(from, to, len);
            self.head = to + len;
            self.produced += u64::from(length);
            #[cfg(debug_assertions)]
            watch.check(
                &self.ring,
                self.produced,
                self.ring.len(),
                "SPEC-H1 3.6 RAR 3 window",
            );
            return Ok(());
        }
        self.copy_general(distance, length)
    }

    /// The fixed width rungs: `[to, to + len)` from `[from, from + len)`,
    /// for `len` at most 64 and `from + len <= to`, as a pair of
    /// overlapping fixed width copies that covers the match and nothing
    /// else. See [`Window::copy_general`] for why each rung is shaped as
    /// it is; this is that ladder, moved so both paths share one text.
    #[inline(always)]
    fn rungs(&mut self, from: usize, to: usize, len: usize) {
        let ring = &mut self.ring[..];
        if len < 16 {
            if len >= 8 {
                fixed_pair::<8>(ring, from, to, len);
                census!(census::LADDER_FIXED, len);
            } else if len >= 4 {
                fixed_pair::<4>(ring, from, to, len);
                census!(census::LADDER_FIXED, len);
            } else {
                for i in 0..len {
                    ring[to + i] = ring[from + i];
                }
                census!(census::LADDER_BYTEWISE, len);
            }
        } else if len < 32 {
            fixed_pair::<16>(ring, from, to, len);
            census!(census::LADDER_FIXED, len);
        } else {
            fixed_pair::<32>(ring, from, to, len);
            census!(census::LADDER_FIXED, len);
        }
    }

    /// Every copy [`Window::copy`] does not answer inline: an overlapping
    /// match, one that wraps the ring or reaches behind its start, one
    /// longer than the ladder, and every refusal.
    #[inline(never)]
    fn copy_general(&mut self, distance: u32, length: u32) -> Result<()> {
        let size = self.ring.len();
        if distance == 0 || u64::from(distance) > self.produced || distance as usize > size {
            return Err(out_of_range());
        }
        #[cfg(debug_assertions)]
        let watch = crate::window_guard::SpillWatch::take(&self.ring, self.head, length as usize);
        let step = distance as usize;
        let len = length as usize;
        let to = self.head;
        // `len <= step` is what makes the bytes disjoint, and it is the
        // condition a single `copy_within` needs: `memmove` semantics
        // would take the source as it was BEFORE the write, where an
        // overlapping match must replicate what it has just written
        // (SPEC-H1 3.6). The loop below is what answers that.
        if len > step && step > 1 && step <= to && to + len < size {
            // An OVERLAPPING match that neither wraps the ring nor reaches
            // behind its start: the source is `step` bytes back and the
            // copy must replicate what it has just written (SPEC-H1 3.6).
            //
            // The loop at the end of this function answers it in chunks of
            // `step`, which is `len / step` iterations: at `step` 3 and
            // the 253 byte mean match SPEC-H1 7.5's census reads off
            // `rar3_vm_1m`, that is 85 of them. It need not be.
            //
            // After `w` bytes have been written, `[to - step, to + w)` is
            // final AND periodic with period `step`, because every byte
            // in it was set equal to the one `step` before. So the byte
            // at any position may be read from `step`, `2 * step`,
            // `3 * step` ... back with the same answer, as long as the
            // read stays at or after `to - step`. Taking `d` as the
            // largest multiple of `step` that is at most `w + step`, a
            // chunk of up to `d` bytes may be copied from `to + w - d`:
            // its last source byte is at `to + w - 1`, which is written,
            // and its first is at or after `to - step`, which is in the
            // final region. `d` doubles as `w` grows, so 253 bytes at
            // step 3 take SEVEN chunks - 3, 6, 12, 24, 48, 96, 64 -
            // against 85.
            //
            // Every chunk is a `copy_within` whose source ends at or
            // before its destination starts, so `memmove` semantics give
            // the byte at a time answer exactly; the property test of
            // SPEC-H1 5.5 walks every distance 1 to 4096 against every
            // length 1 to 300 and pins it. The writes cover
            // `[to, to + len)` and nothing else, so the zero margin
            // invariant and its guard are untouched.
            let mut written = 0usize;
            // Counted only where the census is compiled in, so the arm the
            // bench times has no counter to keep.
            #[cfg(feature = "copy-census")]
            let mut chunks = 0u64;
            while written < len {
                let reach = step * ((written + step) / step);
                let run = reach.min(len - written);
                let src = to + written - reach;
                self.ring.copy_within(src..src + run, to + written);
                written += run;
                #[cfg(feature = "copy-census")]
                {
                    chunks += 1;
                }
            }
            census!(census::OVERLAP, len);
            census!(census::OVERLAP_CALLS, chunks);
            self.head = to + len;
            self.produced += u64::from(length);
            #[cfg(debug_assertions)]
            watch.check(&self.ring, self.produced, size, "SPEC-H1 3.6 RAR 3 window");
            return Ok(());
        }
        if len <= step && step <= to && to + len < size {
            let from = to - step;
            // The copy itself, without a call. A `copy_within` whose
            // length is a CONSTANT is a load and a store; one whose
            // length is a variable is a `memmove` call, and at a mean
            // match length of 9.67 bytes the call is most of the cost -
            // 3.14 million of them, about a quarter of this arm's
            // samples. A pair of overlapping fixed width copies covers
            // `[to, to + len)` EXACTLY: the first writes the front, the
            // second the back, and they overlap in the middle where the
            // match is shorter than twice the width. Nothing outside the
            // match is written, so the zero margin invariant above is
            // untouched and the guard still brackets the call.
            //
            // The widths answer the corpus. Over the RAR 4 `-m3` archives
            // of `two_arm.rs` 67% of copies are 8 to 15 bytes and 32% are
            // 4 to 7; but that corpus is not the whole of what this
            // decoder meets. SPEC-H1 7.5's census, run 20 Sep 2026 on the
            // 7.4 legs, reads 19.66 bytes a symbol on the 64 MiB text
            // member at level 3 and 6.40 on the 32 MiB code member, which
            // is a MEAN MATCH of 26.2 bytes on the first: the whole of
            // that leg's match traffic fell through this ladder into the
            // variable length `copy_within` below, which is a `memmove`
            // CALL. So the ladder runs to 64, and the rungs below 4
            // answer the length 2 a short match always names (3.5).
            //
            // Every rung writes `[to, to + len)` and nothing else: a pair
            // of fixed width copies at `to` and at `to + len - width`
            // covers it exactly, and the second's SOURCE ends at
            // `from + len <= to`, so it reads bytes the first cannot have
            // touched. That is what `len <= step` buys, and it is why the
            // zero margin invariant above is untouched.
            //
            // The rungs are NESTED rather than chained, and the nesting
            // is not cosmetic: chained, with 32 tested first, the 32 MiB
            // code leg got 6% SLOWER on an Apple M3 Mac even as the
            // oversubscribed leg got 15% faster, because that leg's mean
            // match is 19 bytes and its many short ones then paid three
            // failed compares each. Nested, no rung is more than three
            // compares deep and the two the corpus is made of are one and
            // two.
            if len <= 64 {
                self.rungs(from, to, len);
            } else {
                // Above the ladder the length is a VARIABLE again, so this
                // is a `memmove` CALL: one of the two candidates the census
                // is here to separate.
                self.ring.copy_within(from..from + len, to);
                census!(census::LADDER_FALLTHROUGH, len);
            }
            self.head = to + len;
            self.produced += u64::from(length);
            #[cfg(debug_assertions)]
            watch.check(&self.ring, self.produced, size, "SPEC-H1 3.6 RAR 3 window");
            return Ok(());
        }
        // Everything that reaches here took neither fast path: a copy that
        // WRAPS the ring, or reaches behind its start, or has step 1. The
        // census counts it as one bucket because no lever tried here
        // is aimed at it; what matters is how much traffic never reached
        // the two paths above.
        census!(census::OTHER, len);
        let mut left = len;
        let mut from = if self.head >= step {
            self.head - step
        } else {
            self.head + size - step
        };
        let mut to = self.head;
        if step == 1 {
            // A run of one byte, the common overlapping case.
            let byte = self.ring[from];
            while left > 0 {
                let run = left.min(size - to);
                self.ring[to..to + run].fill(byte);
                to = if to + run == size { 0 } else { to + run };
                left -= run;
            }
        } else {
            while left > 0 {
                let run = left.min(step).min(size - from).min(size - to);
                self.ring.copy_within(from..from + run, to);
                from = if from + run == size { 0 } else { from + run };
                to = if to + run == size { 0 } else { to + run };
                left -= run;
            }
        }
        self.head = to;
        self.produced += u64::from(length);
        #[cfg(debug_assertions)]
        watch.check(&self.ring, self.produced, size, "SPEC-H1 3.6 RAR 3 window");
        Ok(())
    }

    /// The bytes of stream range `from..to` as one or two slices, or
    /// `None` when the window no longer holds all of them.
    pub(crate) fn slices(&self, from: u64, to: u64) -> Option<(&[u8], &[u8])> {
        let size = self.ring.len() as u64;
        if to > self.produced || from > to || self.produced - from > size {
            return None;
        }
        let length = (to - from) as usize;
        let back = (self.produced - from) as usize;
        let start = (self.head + self.ring.len() - back) % self.ring.len();
        let first = (self.ring.len() - start).min(length);
        Some((
            &self.ring[start..start + first],
            &self.ring[..length - first],
        ))
    }

    /// Copy the bytes of stream range `from..from + out.len()` into `out`.
    /// The window must still hold them.
    pub(crate) fn copy_out(&self, from: u64, out: &mut [u8]) -> Result<()> {
        let to = from + out.len() as u64;
        let (head, tail) = self.slices(from, to).ok_or_else(out_of_range)?;
        out[..head.len()].copy_from_slice(head);
        out[head.len()..].copy_from_slice(tail);
        Ok(())
    }
}

/// One rung: `[to, to + len)` from `[from, from + len)`, for `W <= len <=
/// 2 * W` and `from + len <= to`, as two fixed width `W` byte blocks, one
/// at the front of the match and one at its back, overlapping in the
/// middle when the match is shorter than `2 * W`.
///
/// Both blocks are LOADED before either is stored, into arrays of a
/// CONSTANT width, so each is a register load and a register store and
/// never a `memmove` call. `copy_within` was the first form here; once
/// the rungs were inlined into the decoder its range check stayed out of
/// line, the constant width did not survive it, and every rung compiled
/// to a call - ten of them - which is the cost this inlining exists to
/// remove. Nothing outside `[to, to + len)` is written: the front block
/// ends at `to + W <= to + len` and the back block starts at
/// `to + len - W >= to`, so the zero margin invariant is untouched.
///
/// Each block is read and written as a `[u8; W]` VALUE through
/// `first_chunk`, not with `copy_from_slice`, and that is the point of
/// this text rather than a style. `copy_from_slice` reaches the compiler's
/// back end as a call to a library function it then has to choose to
/// expand, and a profile-use build sometimes chose not to: the decode loop
/// then carried 52 calls, four for each of its 13 rungs, and retired 1.20
/// of the plain build's instructions where a build that expanded them
/// retires 0.95 (1 Oct 2026, both architectures). An array assignment is a
/// load and a store with nothing left to call, whatever the profile says.
/// The four ranges are the ones the slices always carried, so every bound
/// is checked exactly as before; a range of `W` bytes always holds a `W`
/// byte block, so the `else` arms are never taken.
#[inline(always)]
fn fixed_pair<const W: usize>(ring: &mut [u8], from: usize, to: usize, len: usize) {
    let (Some(&front), Some(&back)) = (
        ring[from..from + W].first_chunk::<W>(),
        ring[from + len - W..from + len].first_chunk::<W>(),
    ) else {
        unreachable!("a range of W bytes holds a W byte block");
    };
    let Some(slot) = ring[to..to + W].first_chunk_mut::<W>() else {
        unreachable!("a range of W bytes holds a W byte block");
    };
    *slot = front;
    let Some(slot) = ring[to + len - W..to + len].first_chunk_mut::<W>() else {
        unreachable!("a range of W bytes holds a W byte block");
    };
    *slot = back;
}

/// Spec I writes into the same window through the same two calls
/// (spec I section 2).
impl StreamWindow for Window {
    fn put(&mut self, byte: u8) -> Result<()> {
        Window::put(self, byte)
    }

    fn copy(&mut self, distance: u32, length: u32) -> Result<()> {
        Window::copy(self, distance, length)
    }
}
