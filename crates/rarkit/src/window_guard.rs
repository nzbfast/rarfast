//! THE WRITE SIDE GUARD FOR EVERY RING IN THIS CRATE.
//!
//! One shared helper for the window edge class found in the H2 package
//! on 19 Sep 2026, stated then as a rule for the other packages
//! and applied here to all of them. The shape of the defect, in four
//! points, is repeated so a reader of this module
//! needs nothing else:
//!
//! 1. a copy that writes MORE than it was asked to is free only where the
//!    bytes past the write point are DEAD, and in a ring none of them
//!    are: they are the oldest history, which is exactly what the LONGEST
//!    legal references read;
//! 2. the mistake to hunt is a copy helper that MOVED BETWEEN BUFFER
//!    SHAPES - one written for a buffer that SLIDES, where rounding a
//!    length up is free, dropped into a ring where it is not;
//! 3. either repair is legitimate: make the write EXACT, give the ring a
//!    MARGIN past what a distance may name, or BRACKET the copy by saving
//!    the bytes it will overrun and putting them back. Every window in
//!    this crate uses one of the three;
//! 4. guard the WRITE, not the output. A spill that the stream's own next
//!    bytes overwrite before anything reads it back changes no output at
//!    all, so whether the defect is ever VISIBLE is a property of the
//!    archive and not of the decoder. Only an assertion on the write side
//!    turns it into an immediate, loud failure.
//!
//! [`WINDOW-INVARIANTS.md`](../../WINDOW-INVARIANTS.md) lists every window
//! this guards, its invariant, its mechanism and how its guard was shown
//! to FAIL as well as pass.
//!
//! # What it checks
//!
//! A copy of `length` bytes starting at ring index `at` may write
//! `[at, at + length)` around the ring and NOTHING ELSE. A slot past that
//! range may differ only if no distance the decoder admits can name it.
//!
//! The whole of the arithmetic: after the copy the write point sits at
//! `at + length`, so the slot `i` further on is `ring_len - i` BACK from
//! it. That slot is nameable when `ring_len - i` is within the decoder's
//! own distance range check, which is `distance <= limit` (the declared
//! dictionary) and `distance <= produced` (the stream has got that far).
//! Both come from the caller, so the guard is written against each
//! window's own range check rather than against any one ring's geometry.
//!
//! # Why the watch is as wide as it is
//!
//! A guard that watches no further than a ring's margin is VACUOUS: every
//! slot in the margin is unreachable BY CONSTRUCTION, so the check passes
//! whatever the copy does. That was the first version of H2's guard, and
//! the reason it now watches `STRIDE_MAX + SPILL` rather than `SPILL`.
//!
//! Every ring this module serves has a margin of ZERO - the H1 and RAR
//! 2.0 rings write exactly what they owe, the two 64 KiB rings bracket
//! their overrun and put it back - so on all four, once the stream has
//! lapped, EVERY watched slot is reachable and any spill at all fails.
//! On these four, any watch at all would be non-vacuous.
//!
//! [`WATCH`] is nevertheless 128, and the reason is worth keeping because
//! this module's own test suite is what forced it. At 64 the guard was
//! vacuous against a ring carrying H2's 64 slot margin: the 64 watched
//! slots were EXACTLY the margin, every one unreachable by construction,
//! so `a_spill_one_byte_past_the_margin_fails` did not fail. That is the
//! same mistake H2's first guard made, reproduced here from the same
//! reasoning, and caught only because the suite demands that every guard
//! be shown to FAIL as well as pass. At 128 the slots past a 64 slot
//! margin are reachable again and the test fails as it must. So the rule
//! is not "wider than the widest block" but **wider than the widest
//! MARGIN this guard could ever be pointed at, plus the widest block**.
//!
//! # Cost
//!
//! Test builds only: the module is `#[cfg(debug_assertions)]` entire and
//! every call site is too, so a release build carries no snapshot, no
//! compare and no branch. Debug builds pay a copy and a compare of
//! [`WATCH`] bytes per match.

/// How many slots past a match every window in this crate watches.
///
/// Twice H2's `SPILL` margin, and four times the widest block any window
/// here copies (32 bytes, the RAR 1.5 family's `WILD`). The margin is
/// zero on all four rings this module serves, so the width is not what
/// makes the guard bite on them; it is what stops the guard going quiet
/// if one of them is ever given a margin. See the module comment: at 64
/// this was vacuous against a 64 slot margin, and the suite caught it.
pub(crate) const WATCH: usize = 128;

/// The widest block any window in this crate copies in one go: the RAR 1.5
/// family's `WILD`. [`WATCH`] must exceed it, or a copy that grew to a
/// whole block past its match would land outside the watch unseen.
const WIDEST_BLOCK: usize = 32;

/// H2's spill margin, the widest this guard could be pointed at today.
/// [`WATCH`] must exceed it too, or every watched slot on such a ring is
/// unreachable BY CONSTRUCTION and the guard passes whatever the copy
/// does. That is not hypothetical: it is what this guard did at 64.
const WIDEST_MARGIN: usize = 64;

// Compile time, not a test: a vacuous guard must not be BUILDABLE.
const _: () = assert!(WATCH > WIDEST_BLOCK);
const _: () = assert!(WATCH > WIDEST_MARGIN);

/// The bytes just past where a copy is allowed to write, kept across the
/// copy so [`SpillWatch::check`] can say whether it touched them.
///
/// `at` is the ring index the copy STARTS at, before it runs, and
/// `length` is the number of bytes it owes. Both are in the ring's own
/// index space, and a copy that wraps is handled by the modulo: nothing
/// here assumes the ring's length is a power of two.
pub(crate) struct SpillWatch {
    at: usize,
    length: usize,
    /// How many slots are really watched: [`WATCH`], or fewer on a ring
    /// too short to hold that many past the write point.
    slots: usize,
    bytes: [u8; WATCH],
}

impl SpillWatch {
    /// Snapshot the slots past `[at, at + length)`. Call immediately
    /// before the copy.
    pub(crate) fn take(ring: &[u8], at: usize, length: usize) -> SpillWatch {
        let ring_len = ring.len();
        let mut bytes = [0u8; WATCH];
        // A copy that covers the whole ring has no "past" to watch, and a
        // ring shorter than the watch would compare a slot with itself.
        let slots = if length >= ring_len {
            0
        } else {
            WATCH.min(ring_len - length)
        };
        for (index, slot) in bytes.iter_mut().enumerate().take(slots) {
            *slot = ring[(at + length + index) % ring_len];
        }
        SpillWatch {
            at,
            length,
            slots,
            bytes,
        }
    }

    /// Fail if the copy changed a slot past its own range that a legal
    /// distance can still name. Call immediately after the copy.
    ///
    /// `produced` is the count of bytes the stream has produced INCLUDING
    /// this copy, and `limit` is the largest distance the caller's own
    /// range check admits - for a ring with no margin, its length. `site`
    /// names the window in the message, because these four rings are
    /// reached through very different decoders and the first thing a
    /// reader of a failure needs is which one it is.
    pub(crate) fn check(&self, ring: &[u8], produced: u64, limit: usize, site: &str) {
        let ring_len = ring.len();
        for (index, &was) in self.bytes.iter().enumerate().take(self.slots) {
            let slot = (self.at + self.length + index) % ring_len;
            if ring[slot] == was {
                continue;
            }
            // Slot `at + length + index` is `ring_len - index` back from
            // the write point this copy has just left behind.
            let distance = ring_len - index;
            if distance <= limit && distance as u64 <= produced {
                panic!(
                    "{site}: a copy of {} bytes at {} wrote slot {slot}, which is \
                     {distance} back and READABLE: the window is {ring_len} bytes, \
                     the longest distance it admits is {limit}, and the stream has \
                     produced {produced}. A copy may write only [{}, {}).",
                    self.length,
                    self.at,
                    self.at,
                    self.at + self.length,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SpillWatch, WATCH};

    /// A ring with every slot distinct, so a spill is always visible as a
    /// CHANGE and never masked by the byte that was already there.
    fn ring(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251 + 1) as u8).collect()
    }

    /// THE FALSIFICATION. A copy that writes one byte past what it owes,
    /// onto a slot a legal distance still names, must fail loudly.
    #[test]
    #[should_panic(expected = "wrote slot")]
    fn a_spill_onto_a_reachable_slot_fails() {
        let mut ring = ring(4_096);
        let (at, length) = (100, 9);
        let watch = SpillWatch::take(&ring, at, length);
        // The over-wide copy, in its smallest form: one byte past the end.
        ring[at + length] ^= 0xff;
        // A lapped stream on a margin-free ring: every slot is nameable.
        watch.check(&ring, 10_000, 4_096, "test");
    }

    /// The same spill, at the far edge of the watch, so the check is not
    /// quietly only looking at the first slot.
    #[test]
    #[should_panic(expected = "wrote slot")]
    fn a_spill_at_the_far_edge_of_the_watch_fails() {
        let mut ring = ring(4_096);
        let (at, length) = (100, 9);
        let watch = SpillWatch::take(&ring, at, length);
        ring[at + length + WATCH - 1] ^= 0xff;
        watch.check(&ring, 10_000, 4_096, "test");
    }

    /// A spill that WRAPS the ring's end fails too: the ring index is
    /// taken modulo its length and not assumed to be a power of two.
    #[test]
    #[should_panic(expected = "wrote slot")]
    fn a_spill_that_wraps_the_ring_fails() {
        let len = 4_099;
        let mut ring = ring(len);
        let (at, length) = (len - 4, 3);
        let watch = SpillWatch::take(&ring, at, length);
        ring[2] ^= 0xff;
        watch.check(&ring, 10_000, len, "test");
    }

    #[test]
    fn writing_inside_the_copy_s_own_range_is_not_a_spill() {
        let mut ring = ring(4_096);
        let (at, length) = (100, 9);
        let watch = SpillWatch::take(&ring, at, length);
        for slot in &mut ring[at..at + length] {
            *slot ^= 0xff;
        }
        watch.check(&ring, 10_000, 4_096, "test");
    }

    /// Below one lap the slot ahead of the write point holds a byte the
    /// stream never produced, so no legal distance names it and a spill
    /// there is not a defect. The guard must say so rather than fire: a
    /// guard that cried wolf here would be loosened, and a loosened guard
    /// is how this class comes back.
    #[test]
    fn a_spill_the_stream_has_not_reached_yet_is_not_a_defect() {
        let mut ring = ring(4_096);
        let (at, length) = (100, 9);
        let watch = SpillWatch::take(&ring, at, length);
        ring[at + length] ^= 0xff;
        // Slot `at + length` is 4,096 back; only 109 bytes exist.
        watch.check(&ring, 109, 4_096, "test");
    }

    /// The reason a MARGIN is a legitimate repair, stated as something the
    /// guard checks rather than as an argument: on a ring longer than the
    /// dictionary, the slots in the margin sit at distances the decoder
    /// refuses, so a spill onto them is sound. This is H2's shape, and
    /// [`WATCH`] must be wider than the margin or this test and the one
    /// below it are both vacuous.
    #[test]
    fn a_spill_onto_a_margin_the_decoder_refuses_is_not_a_defect() {
        let len = 4_096 + 64;
        let mut ring = ring(len);
        let (at, length) = (100, 9);
        let watch = SpillWatch::take(&ring, at, length);
        // The first 64 slots past the match are `len` to `len - 63` back,
        // and the longest distance admitted is 4,096.
        for slot in &mut ring[at + length..at + length + 64] {
            *slot ^= 0xff;
        }
        watch.check(&ring, 1_000_000, 4_096, "test");
    }

    /// And the other half of the same fact, which is what stops a margin
    /// from being an excuse: one byte PAST the margin is reachable again
    /// and fails. A watch no wider than the margin could not see this.
    #[test]
    #[should_panic(expected = "wrote slot")]
    fn a_spill_one_byte_past_the_margin_fails() {
        let len = 4_096 + 64;
        let mut ring = ring(len);
        let (at, length) = (100, 9);
        let watch = SpillWatch::take(&ring, at, length);
        ring[at + length + 64] ^= 0xff;
        watch.check(&ring, 1_000_000, 4_096, "test");
    }

    /// A ring shorter than the watch must not compare a slot with itself
    /// and report a phantom spill.
    #[test]
    fn a_ring_shorter_than_the_watch_is_handled() {
        let len = 16;
        let mut ring = ring(len);
        let (at, length) = (2, 4);
        let watch = SpillWatch::take(&ring, at, length);
        for slot in &mut ring[at..at + length] {
            *slot ^= 0xff;
        }
        watch.check(&ring, 1_000_000, len, "test");
    }
}
