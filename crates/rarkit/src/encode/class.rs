//! Which finder a member is worth: FAR LINKS A BYTE (SPEC-H3 8.1).
//!
//! The hash chains search only where the lazy parse asks, and the tree
//! searches at every position. So the chains win wherever a search is
//! cheap, and a chain search is cheap while the links it follows stay
//! near: each link that leads far back is a cache miss. On synthetic code
//! almost no link does, and the chains at level 5 were timed at 1.9 to 3.6
//! times the tree's speed; on prose a third of a search's links lead far,
//! the searches of several threads fight for one cache, and the chains
//! were timed at half the tree's speed at four threads
//! (measured 1 Oct 2026).
//!
//! This reads which of the two a member is, from its HEAD alone and before
//! a byte of it is encoded: the first megabyte, as sixteen windows of
//! 64 KiB. For every position of every window with four bytes after it:
//!
//! - `near`: the earlier copies of its four bytes in its OWN window, at
//!   most [`LINKS`] (the links a chain follows first, all within 64 KiB);
//! - `other`: the copies of its four bytes in the fifteen OTHER windows,
//!   scaled by 31/15, which is what fifteen windows are of a 2 MiB reach
//!   less a window: the copies a chain would meet farther back, were the
//!   member alike throughout;
//! - `far = min(LINKS - near, other * 31 / 15)`: the links past 64 KiB
//!   that a chain [`LINKS`] deep follows there.
//!
//! A chain is searched only where the parse asks, so `far` is summed over
//! the positions a GREEDY parse of the window stops at (a position with a
//! copy earlier in its window takes the match its most recent copy gives,
//! four bytes or more, and jumps it; any other position is a literal), and
//! the sum is divided by the positions looked at. That quotient is the
//! reading: about 0.1 on generated code, 3 on a source tree, 7 on real
//! source in one file, 8 to 9 on prose.
//!
//! Three properties it has to have, as `encode::sample` has them:
//!
//! - **It cannot move a byte with the machine, the thread count or an
//!   option.** It is integer arithmetic over the head's bytes and nothing
//!   else: the scale is the fixed 31/15 and not the dictionary in force,
//!   so a member's class is the member's.
//! - **It is the same for bytes in memory and for a reader**, which is why
//!   it reads the head and not windows spread across the member: a reader
//!   is read once, and the store rule's sampler (spec G 3.8.3) has pulled
//!   only two of its sixteen windows by the time a member that compresses
//!   is settled.
//! - **It has to be cheap.** One megabyte is read whatever the member's
//!   size, through tables of [`SLOTS`] counters.
//!
//! The counts are kept in [`SLOTS`] hash slots, each OWNED by the first
//! four byte string that reaches it: a string that finds its slot owned by
//! another is not counted, and reads no copy anywhere. With 2^20 slots for
//! at most 2^20 positions the strings that recur own their slots almost
//! always (they come early and often), so this moves the reading by a few
//! parts in a hundred, always downwards, and bytes that repeat nothing
//! read nothing whatever they collide with. The slots are part of the
//! definition, so the reading is the same everywhere.

/// How many windows the head is read as.
pub(crate) const WINDOWS: usize = 16;
/// The bytes of one window.
pub(crate) const WINDOW_BYTES: usize = 64 << 10;
/// The head a reading is taken from: the member's first megabyte. A
/// shorter member has no reading.
pub(crate) const HEAD_BYTES: usize = WINDOWS * WINDOW_BYTES;
/// The chain depth the reading is taken for.
const LINKS: u32 = 64;
/// `other` is scaled by `SCALE_UP / SCALE_DOWN`: a 2 MiB reach less one
/// window, over the fifteen other windows.
const SCALE_UP: u64 = 31;
const SCALE_DOWN: u64 = 15;
/// The counters' slots, one per head position at most.
const SLOTS_LOG2: u32 = 20;
const SLOTS: usize = 1 << SLOTS_LOG2;
/// The greedy parse's table of most recent positions, direct mapped.
const RECENT_LOG2: u32 = 16;
/// A match of the greedy parse this long or longer is a LONG one
/// ([`Reading::long_matches`]).
const LONG_MATCH: usize = 16;

/// A position in a window, in the low bits of a `recent` entry; the
/// window's tag sits above it.
const RECENT_AT: u32 = (1 << RECENT_LOG2) - 1;
/// A window's own count, in the low bits of [`Slot::own`]; the window's
/// tag sits above it.
const OWN_COUNT: u32 = (1 << 20) - 1;

const HASH_MULTIPLIER: u32 = 0x9E37_79B1;

/// One hash slot's counts: together, so a position touches one line.
#[derive(Clone, Copy, Default)]
struct Slot {
    /// The four bytes the slot is counted for: the first to reach it.
    owner: u32,
    /// Their copies in every window; zero is an empty slot.
    total: u32,
    /// Their copies in ONE window so far, under that window's tag.
    own: u32,
}

impl Slot {
    /// Count one more copy of `word` in the window tagged `tag`, and
    /// answer how many came before it there; none where the slot is
    /// another string's, which is not counted.
    #[inline]
    fn visit(&mut self, word: u32, tag: u32) -> Option<u32> {
        if self.owner != word {
            return None;
        }
        let before = if self.own >> 20 == tag {
            self.own & OWN_COUNT
        } else {
            0
        };
        self.own = (tag << 20) | (before + 1);
        Some(before)
    }
}

/// The four bytes at `at`, and the slot they hash to.
#[inline]
fn slot_at(bytes: &[u8; WINDOW_BYTES], at: usize) -> (u32, usize) {
    let word = u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"));
    (
        word,
        (word.wrapping_mul(HASH_MULTIPLIER) >> (32 - SLOTS_LOG2)) as usize & (SLOTS - 1),
    )
}

/// How far the bytes at `at` repeat the bytes at `earlier`, to the
/// window's end at most, where the first four are known to: the greedy
/// parse's extension, eight bytes a step.
#[inline]
fn match_length(window: &[u8; WINDOW_BYTES], earlier: usize, at: usize) -> usize {
    let mut length = 4;
    while at + length + 8 <= WINDOW_BYTES {
        let word = |from: usize| {
            u64::from_le_bytes(window[from..from + 8].try_into().expect("eight bytes"))
        };
        let differ = word(earlier + length) ^ word(at + length);
        if differ != 0 {
            return length + (differ.trailing_zeros() / 8) as usize;
        }
        length += 8;
    }
    while at + length < WINDOW_BYTES && window[earlier + length] == window[at + length] {
        length += 1;
    }
    length
}

/// What the head of a member read: [`Reading::per_mille`] is the figure
/// the cut-offs are stated in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reading {
    /// `far`, in fifteenths of a link, summed over the greedy parse's
    /// token positions.
    far: u64,
    /// The positions looked at: every one with four bytes after it inside
    /// its window.
    positions: u64,
    /// How many of them the greedy parse stopped at.
    #[cfg_attr(not(any(test, feature = "bench-internals")), allow(dead_code))]
    tokens: u64,
    /// How many matches of [`LONG_MATCH`] bytes or more the greedy parse
    /// took.
    long: u64,
}

impl Reading {
    /// Far links a byte, in thousandths, rounded down.
    pub(crate) fn per_mille(self) -> u32 {
        if self.positions == 0 {
            return 0;
        }
        u32::try_from(self.far * 1000 / (SCALE_DOWN * self.positions)).unwrap_or(u32::MAX)
    }

    /// LONG MATCHES: how many matches of [`LONG_MATCH`] bytes or more the
    /// greedy parse took in the head.
    ///
    /// The second statistic of the class. Far links a byte says what a
    /// chain search costs where it is made; this says how much of the
    /// member is never searched at all. The chains search only where the
    /// lazy parse asks, and a long match is skipped through unsearched, so
    /// a member that has them (a library, a font, a shader archive, prose)
    /// is cheap on the chains whatever its far links read. A word list, a
    /// dictionary or a model's table has next to none: every match is a
    /// few bytes, every stop a full search, and the tree is the faster
    /// finder (measured 2 Oct 2026). It
    /// is one counter in the walk the reading already makes.
    pub(crate) fn long_matches(self) -> u32 {
        u32::try_from(self.long).unwrap_or(u32::MAX)
    }

    /// The greedy parse's tokens a thousand positions, for the probe.
    #[cfg(feature = "bench-internals")]
    pub(crate) fn tokens_per_mille(self) -> u32 {
        if self.positions == 0 {
            return 0;
        }
        (self.tokens * 1000 / self.positions) as u32
    }
}

/// Where window `index` of a span of `len` bytes starts: the span is cut
/// into [`WINDOWS`] equal segments and the window is centred in its
/// segment, as the store rule places its samples (spec G 3.8.3). Over a
/// head of exactly [`HEAD_BYTES`] the windows are the head, end to end.
fn window_start(len: usize, index: usize) -> usize {
    let start = index * len / WINDOWS;
    let end = (index + 1) * len / WINDOWS;
    start + (end - start - WINDOW_BYTES) / 2
}

/// The reading of `span`, or none where it is shorter than
/// [`HEAD_BYTES`].
///
/// The writer hands this a member's first [`HEAD_BYTES`] ([`of_head`]). A
/// longer span is read through sixteen windows spread across it, which is
/// the form the rule was first counted in and what `examples/class_probe`
/// prints beside the head's.
pub(crate) fn of_span(span: &[u8]) -> Option<Reading> {
    of_span_parsing(span, 1, 0)
}

/// [`of_span`] with the greedy parse run over every `stride`th window
/// only, from window `first`: every window is still counted. A probe's
/// form, to price a cheaper reading.
pub(crate) fn of_span_parsing(span: &[u8], stride: usize, first: usize) -> Option<Reading> {
    if span.len() < HEAD_BYTES {
        return None;
    }
    let starts: [usize; WINDOWS] = std::array::from_fn(|index| window_start(span.len(), index));
    // Every window's four byte strings, counted together: a slot is its
    // first string's, and a total of zero is an empty slot.
    // (Both tables are borrowed at their fixed lengths, and a slot is at
    // most twenty bits, so no access is checked against a length.)
    let mut slots = vec![Slot::default(); SLOTS];
    let slots: &mut [Slot; SLOTS] = slots.as_mut_slice().try_into().expect("the slots");
    for &start in &starts {
        let window: &[u8; WINDOW_BYTES] = span[start..start + WINDOW_BYTES]
            .try_into()
            .expect("a window");
        for at in 0..WINDOW_BYTES - 3 {
            let (word, slot) = slot_at(window, at);
            let held = &mut slots[slot];
            if held.total == 0 {
                held.owner = word;
                held.total = 1;
            } else if held.owner == word {
                held.total += 1;
            }
        }
    }
    // One pass a window: the greedy parse, which visits every position
    // once (the ones it stops at and the ones inside the matches it
    // takes), counts each string's copies in the window as it goes, so a
    // position's count before it is `near`; a stop is kept with that
    // count, and priced once the window's own counts are whole.
    let mut recent = vec![0u32; 1 << RECENT_LOG2];
    let recent: &mut [u32; 1 << RECENT_LOG2] = recent.as_mut_slice().try_into().expect("the table");
    let mut stops: Vec<(u32, u32)> = Vec::with_capacity(WINDOW_BYTES);
    let mut reading = Reading {
        far: 0,
        positions: 0,
        tokens: 0,
        long: 0,
    };
    let end = WINDOW_BYTES - 3;
    for (index, &start) in starts.iter().enumerate() {
        let window: &[u8; WINDOW_BYTES] = span[start..start + WINDOW_BYTES]
            .try_into()
            .expect("a window");
        // Both tables are the window's by a tag in their high bits, so
        // neither is cleared between windows.
        let tag = index as u32 + 1;
        if index % stride != first {
            continue;
        }
        stops.clear();
        let mut long = 0u32;
        let mut at = 0;
        while at < end {
            let (word, slot) = slot_at(window, at);
            if let Some(near) = slots[slot].visit(word, tag) {
                stops.push((slot as u32, near));
            }
            reading.tokens += 1;
            let lately = &mut recent[slot >> (SLOTS_LOG2 - RECENT_LOG2)];
            let held = *lately;
            *lately = (tag << RECENT_LOG2) | at as u32;
            let earlier = (held & RECENT_AT) as usize;
            if held >> RECENT_LOG2 != tag || window[earlier..earlier + 4] != window[at..at + 4] {
                at += 1;
                continue;
            }
            let length = match_length(window, earlier, at);
            long += u32::from(length >= LONG_MATCH);
            for inside in at + 1..(at + length).min(end) {
                let (word, slot) = slot_at(window, inside);
                slots[slot].visit(word, tag);
                recent[slot >> (SLOTS_LOG2 - RECENT_LOG2)] = (tag << RECENT_LOG2) | inside as u32;
            }
            at += length;
        }
        for &(slot, near) in &stops {
            let held = slots[slot as usize];
            let other = u64::from(held.total - (held.own & OWN_COUNT));
            let near = near.min(LINKS);
            reading.far += (SCALE_DOWN * u64::from(LINKS - near)).min(SCALE_UP * other);
        }
        reading.positions += end as u64;
        reading.long += u64::from(long);
    }
    Some(reading)
}

/// The reading of a member whose first bytes are `head`: over its first
/// [`HEAD_BYTES`], or none where the member is shorter. The serial form,
/// which [`of_head_wide`] is held to.
#[cfg(test)]
pub(crate) fn of_head(head: &[u8]) -> Option<Reading> {
    of_span(head.get(..HEAD_BYTES)?)
}

/// [`of_head`] by a form that stays in cache, on up to `workers` threads of
/// the pool the caller runs on: THE SAME READING, field for field, at any
/// width and on one thread.
///
/// The reading is taken before a member's first byte is encoded, so its
/// wall stands in front of the whole encode, and a member that keeps the
/// tree gets nothing back for it
/// (measured 1 Oct 2026). The serial form above
/// makes two passes of scattered reads and writes over a 12 MB table, which
/// a cache of a megabyte or two does not hold. This form deals the work so
/// that no step leaves a few hundred kilobytes:
///
/// 1. **Deal** (a window a task): every position's word and slot, sorted
///    by the slot's top bits into [`RANGES`] ranges, in position order
///    within a range.
/// 2. **Count** (a range a task): one table part of [`PART_SLOTS`] slots.
///    A range's words reach it window by window in the head's order, which
///    is the order the serial pass meets them in, so a slot's owner, its
///    total and the copies before each position in its window are the
///    serial ones. Once the totals are whole, each owned position's term
///    `min(15 * (64 - near), 31 * other)` is written beside the position.
/// 3. **Parse** (a window a task): the greedy parse, which needs no slot
///    any more: it sums the terms of the positions it stops at.
///
/// Every position of a window is passed exactly once by the greedy parse
/// (as a stop or inside a match it takes), which is why the copies before
/// a position, as the serial form counts them while it parses, do not
/// depend on the parse and can be counted in step 2.
///
/// ON ONE THREAD the serial form is the reading: dealt and counted in turn
/// this form takes 2.5 times the instructions for half the cache misses
/// and is the slower (counted on a Zen 5: 10.7 ms against 8.5 a reading;
/// on four threads and more it is 1.1 to 1.9 ms).
pub(crate) fn of_head_wide(head: &[u8], workers: usize) -> Option<Reading> {
    let head = head.get(..HEAD_BYTES)?;
    if workers <= 1 || !cfg!(feature = "parallel") {
        return of_span(head);
    }
    Some(dealt::reading(head, workers))
}

/// The dealt form whatever the width, for the tests that hold it to the
/// serial one and for the probe that counts it.
#[cfg(any(test, feature = "bench-internals"))]
pub(crate) fn of_head_dealt(head: &[u8], workers: usize) -> Option<Reading> {
    Some(dealt::reading(head.get(..HEAD_BYTES)?, workers))
}

mod dealt {
    use super::*;
    use std::sync::atomic::{AtomicU16, Ordering};

    /// The slot ranges the head's words are dealt into.
    const RANGES_LOG2: u32 = 5;
    const RANGES: usize = 1 << RANGES_LOG2;
    /// One range's slots: 32,768 of twelve bytes, 384 KiB.
    const PART_LOG2: u32 = SLOTS_LOG2 - RANGES_LOG2;
    const PART_SLOTS: usize = 1 << PART_LOG2;
    /// The positions of one window that have a word.
    const END: usize = WINDOW_BYTES - 3;
    /// `near` for a position whose word does not own its slot.
    const UNOWNED: u8 = u8::MAX;

    /// One window's positions, dealt by range: `(word, slot in its part
    /// shifted over the position)`, a range's entries in position order.
    struct Dealt {
        entries: Vec<(u32, u32)>,
        /// Where each range's entries start; one past the last at the end.
        starts: [u32; RANGES + 1],
    }

    impl Dealt {
        fn of(window: &[u8; WINDOW_BYTES]) -> Dealt {
            let mut counts = [0u32; RANGES + 1];
            for at in 0..END {
                let (_, slot) = slot_at(window, at);
                counts[(slot >> PART_LOG2) + 1] += 1;
            }
            for range in 0..RANGES {
                counts[range + 1] += counts[range];
            }
            let starts = counts;
            let mut next = counts;
            let mut entries = vec![(0u32, 0u32); END];
            for at in 0..END {
                let (word, slot) = slot_at(window, at);
                let range = slot >> PART_LOG2;
                let part_slot = (slot & (PART_SLOTS - 1)) as u32;
                entries[next[range] as usize] = (word, (part_slot << 16) | at as u32);
                next[range] += 1;
            }
            Dealt { entries, starts }
        }

        fn range(&self, range: usize) -> &[(u32, u32)] {
            &self.entries[self.starts[range] as usize..self.starts[range + 1] as usize]
        }
    }

    /// `count` results of `work(index)`, in index order: on the caller's
    /// pool where more workers than one are asked for and the build has
    /// one, in turn otherwise.
    fn each<T: Send>(count: usize, workers: usize, work: impl Fn(usize) -> T + Sync) -> Vec<T> {
        #[cfg(feature = "parallel")]
        if workers > 1 {
            use rayon::prelude::*;
            return (0..count).into_par_iter().map(&work).collect();
        }
        let _ = workers;
        (0..count).map(work).collect()
    }

    /// One range counted: its owned positions' terms written into `far`.
    fn count_range(range: usize, dealt: &[Dealt], far: &[AtomicU16]) {
        let mut part = vec![Slot::default(); PART_SLOTS];
        let entries: usize = dealt.iter().map(|window| window.range(range).len()).sum();
        // The copies before each position in its own window, capped; and
        // which positions own their slot at all.
        let mut near: Vec<u8> = Vec::with_capacity(entries);
        for (index, window) in dealt.iter().enumerate() {
            let tag = index as u32 + 1;
            for &(word, packed) in window.range(range) {
                let slot = &mut part[(packed >> 16) as usize];
                if slot.total == 0 {
                    slot.owner = word;
                    slot.total = 1;
                } else if slot.owner == word {
                    slot.total += 1;
                }
                near.push(match slot.visit(word, tag) {
                    Some(before) => before.min(LINKS) as u8,
                    None => UNOWNED,
                });
            }
        }
        // The totals are whole now. A window at a time: its own counts
        // again, to their end, and then each owned position's term.
        let mut near = near.iter();
        for (index, window) in dealt.iter().enumerate() {
            let tag = (WINDOWS + index) as u32 + 1;
            let entries = window.range(range);
            for &(word, packed) in entries {
                part[(packed >> 16) as usize].visit(word, tag);
            }
            for &(_, packed) in entries {
                let near = *near.next().expect("a count a position");
                if near == UNOWNED {
                    continue;
                }
                let slot = part[(packed >> 16) as usize];
                let other = u64::from(slot.total - (slot.own & OWN_COUNT));
                let term = (SCALE_DOWN * u64::from(LINKS - u32::from(near))).min(SCALE_UP * other);
                far[index * WINDOW_BYTES + (packed & 0xFFFF) as usize]
                    .store(term as u16, Ordering::Relaxed);
            }
        }
    }

    /// One window's greedy parse: the sum of the terms at its stops, how
    /// many stops it made, and how many of them were long matches.
    fn parse(window: &[u8; WINDOW_BYTES], far: &[AtomicU16]) -> [u64; 3] {
        // The most recent position under each entry, plus one.
        let mut recent = vec![0u32; 1 << RECENT_LOG2];
        let (mut sum, mut tokens) = (0u64, 0u64);
        let mut long = 0u64;
        let mut at = 0;
        while at < END {
            let (_, slot) = slot_at(window, at);
            sum += u64::from(far[at].load(Ordering::Relaxed));
            tokens += 1;
            let lately = &mut recent[slot >> (SLOTS_LOG2 - RECENT_LOG2)];
            let held = *lately;
            *lately = at as u32 + 1;
            let earlier = (held as usize).wrapping_sub(1);
            if held == 0 || window[earlier..earlier + 4] != window[at..at + 4] {
                at += 1;
                continue;
            }
            let length = match_length(window, earlier, at);
            long += u64::from(length >= LONG_MATCH);
            for inside in at + 1..(at + length).min(END) {
                let (_, slot) = slot_at(window, inside);
                recent[slot >> (SLOTS_LOG2 - RECENT_LOG2)] = inside as u32 + 1;
            }
            at += length;
        }
        [sum, tokens, long]
    }

    pub(super) fn reading(head: &[u8], workers: usize) -> Reading {
        debug_assert_eq!(head.len(), HEAD_BYTES);
        let windows: Vec<&[u8; WINDOW_BYTES]> = head.as_chunks::<WINDOW_BYTES>().0.iter().collect();
        let dealt = each(WINDOWS, workers, |index| Dealt::of(windows[index]));
        // A term is at most 15 * 64, and zero where the word owns no slot.
        let far: Vec<AtomicU16> = (0..HEAD_BYTES).map(|_| AtomicU16::new(0)).collect();
        each(RANGES, workers, |range| count_range(range, &dealt, &far));
        let [far, tokens, long] = each(WINDOWS, workers, |index| {
            parse(
                windows[index],
                &far[index * WINDOW_BYTES..(index + 1) * WINDOW_BYTES],
            )
        })
        .into_iter()
        .fold([0; 3], |sum, window| {
            std::array::from_fn(|i| sum[i] + window[i])
        });
        Reading {
            far,
            positions: (WINDOWS * END) as u64,
            tokens,
            long,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic byte stream with no structure.
    fn noise(len: usize, seed: u64) -> Vec<u8> {
        rarkit_testdata::scramble(seed, len)
    }

    #[test]
    fn a_span_under_a_megabyte_has_no_reading() {
        assert_eq!(of_span(&vec![7u8; HEAD_BYTES - 1]), None);
        assert_eq!(of_head(&vec![7u8; HEAD_BYTES - 1]), None);
        assert!(of_head(&vec![7u8; HEAD_BYTES]).is_some());
    }

    #[test]
    fn the_head_is_read_as_its_sixteen_windows_end_to_end() {
        for index in 0..WINDOWS {
            assert_eq!(window_start(HEAD_BYTES, index), index * WINDOW_BYTES);
        }
        // A longer span: centred in its sixteenths, as the store rule's
        // samples are, and inside the span.
        let len = 5 * HEAD_BYTES + 12_345;
        for index in 0..WINDOWS {
            let start = window_start(len, index);
            let segment = index * len / WINDOWS;
            let next = (index + 1) * len / WINDOWS;
            assert_eq!(start, segment + (next - segment - WINDOW_BYTES) / 2);
            assert!(start + WINDOW_BYTES <= len);
        }
    }

    #[test]
    fn of_head_reads_the_first_megabyte_and_nothing_after_it() {
        let mut member = noise(HEAD_BYTES, 3);
        let alone = of_head(&member).expect("a megabyte reads");
        member.extend(std::iter::repeat_n(b'a', 3 * HEAD_BYTES));
        assert_eq!(of_head(&member), Some(alone));
        assert_ne!(of_span(&member), Some(alone));
    }

    #[test]
    fn noise_and_one_repeated_byte_follow_no_far_link() {
        // Noise repeats nothing: no copy in another window to follow.
        let reading = of_head(&noise(HEAD_BYTES, 1)).expect("a megabyte reads");
        assert!(reading.per_mille() < 10, "{reading:?}");
        // One byte repeated: the greedy parse asks twice a window, so the
        // links those two searches would follow are spread over 64 KiB.
        let reading = of_head(&vec![0u8; HEAD_BYTES]).expect("a megabyte reads");
        assert!(reading.per_mille() <= 2, "{reading:?}");
        assert_eq!(reading.tokens, 2 * WINDOWS as u64);
    }

    #[test]
    fn text_whose_words_recur_across_the_head_reads_far_above_code_like_runs() {
        // Prose-like text: 4,096 words, each met again all over the head.
        let text = rarkit_testdata::chatter_of(0x636c_6173, 4_096, HEAD_BYTES);
        let prose = of_head(&text).expect("a megabyte reads").per_mille();
        // The same line over and over with a counter in it: most searches
        // end at the line before.
        let mut lines = Vec::with_capacity(HEAD_BYTES + 64);
        let mut line = 0u32;
        while lines.len() < HEAD_BYTES {
            lines.extend_from_slice(
                format!("    let value_{line:08} = table[{line}];\n").as_bytes(),
            );
            line += 1;
        }
        let code = of_head(&lines).expect("a megabyte reads").per_mille();
        assert!(prose > 5_000, "prose-like text read {prose}");
        assert!(
            code * 2 < prose,
            "code-like lines read {code}, prose {prose}"
        );
    }

    #[test]
    fn a_reading_is_a_function_of_the_bytes() {
        let head = noise(HEAD_BYTES, 9);
        assert_eq!(of_head(&head), of_head(&head.clone()));
    }

    #[test]
    fn the_reading_is_the_same_on_one_thread_and_on_a_pool() {
        // `of_head_wide` is `of_head`, field for field (the sum, the
        // positions and the stops), whatever the width asked for and
        // whatever the pool it runs on: on noise, on text that recurs
        // near and far, on runs, and on a head with more behind it.
        let mut source = rarkit_testdata::Seeded::new(0x6d69_7865);
        let mut mixed = Vec::with_capacity(HEAD_BYTES + 5_000);
        while mixed.len() < HEAD_BYTES + 5_000 {
            let state = source.next_u64();
            match state % 5 {
                0 => mixed.extend_from_slice(b"the quick brown fox jumps over the lazy dog\n"),
                1 => mixed.extend((0..(state >> 8) % 300).map(|i| (i % 7) as u8 + b'a')),
                2 => mixed.extend_from_slice(&state.to_le_bytes()),
                3 => {
                    let from = (state >> 16) as usize % mixed.len().max(1);
                    let run = (40 + (state >> 40) % 2_000) as usize;
                    let copy: Vec<u8> = mixed[from..(from + run).min(mixed.len())].to_vec();
                    mixed.extend_from_slice(&copy);
                }
                _ => mixed.extend(std::iter::repeat_n(
                    (state >> 24) as u8,
                    1 + (state >> 32) as usize % 90,
                )),
            }
        }
        let heads: [Vec<u8>; 4] = [
            noise(HEAD_BYTES, 3),
            vec![9u8; HEAD_BYTES],
            noise(100_000, 1)
                .iter()
                .copied()
                .cycle()
                .take(HEAD_BYTES)
                .collect(),
            mixed,
        ];
        for (index, head) in heads.iter().enumerate() {
            let serial = of_head(head).expect("a megabyte reads");
            for workers in [1usize, 2, 3, 4, 7, 8, 16, 20, 32, 96] {
                assert_eq!(
                    of_head_wide(head, workers),
                    Some(serial),
                    "head {index} at {workers} workers"
                );
                assert_eq!(
                    of_head_dealt(head, workers),
                    Some(serial),
                    "head {index} dealt at {workers} workers"
                );
            }
        }
        assert_eq!(of_head_wide(&heads[0][..HEAD_BYTES - 1], 8), None);
        #[cfg(feature = "parallel")]
        for threads in [1usize, 2, 5] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("a pool");
            for head in &heads {
                assert_eq!(pool.install(|| of_head_wide(head, 16)), of_head(head));
            }
        }
    }

    #[test]
    fn a_match_is_extended_to_where_a_byte_at_a_time_would_stop() {
        // The greedy parse's extension takes eight bytes a step; the
        // definition is a byte at a time, to the window's end at most.
        let mut window = Box::new([0u8; WINDOW_BYTES]);
        window.copy_from_slice(&noise(WINDOW_BYTES, 7));
        let slow = |window: &[u8; WINDOW_BYTES], earlier: usize, at: usize| {
            let mut length = 4;
            while at + length < WINDOW_BYTES && window[earlier + length] == window[at + length] {
                length += 1;
            }
            length
        };
        // Copies of every length from 4 to 40, in the middle and run up
        // against the window's end, each with a byte after it that differs
        // (the noise's own, or one flipped).
        for length in 4..=40usize {
            for at in [5_000, WINDOW_BYTES - length, WINDOW_BYTES - length - 1] {
                let mut copy = window.clone();
                let earlier = 100 + length;
                copy.copy_within(earlier..earlier + length, at);
                if at + length < WINDOW_BYTES {
                    copy[at + length] = !copy[earlier + length];
                }
                assert_eq!(
                    match_length(&copy, earlier, at),
                    slow(&copy, earlier, at),
                    "a copy of {length} at {at}"
                );
                assert_eq!(match_length(&copy, earlier, at), length);
            }
        }
        // One byte repeated: to the window's last byte.
        let zeros = Box::new([0u8; WINDOW_BYTES]);
        for at in [1, 9, WINDOW_BYTES - 5, WINDOW_BYTES - 4] {
            assert_eq!(match_length(&zeros, 0, at), WINDOW_BYTES - at);
        }
    }

    /// SPEC-H3 8.1's vectors, read from the files the specification keeps
    /// (`specs/vectors-H/h3-class-reading`): six heads of exactly a
    /// megabyte, and for each, in `readings.tsv`, its SHA-256, the sum of
    /// far links in fifteenths, the positions the greedy parse stops at,
    /// the reading in thousandths, the long matches (the matches of
    /// sixteen bytes or more that the parse takes), and the class those
    /// give. This test holds no generator: the bytes are the files'.
    #[cfg(feature = "repo-tests")]
    #[test]
    fn the_six_vectors_read_what_the_specification_states() {
        use crate::encode::drive::{LEVEL5_CHAINS_LONG, LEVEL5_CHAINS_UNDER};
        use sha2::{Digest, Sha256};
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../specs/vectors-H/h3-class-reading"
        );
        let table = std::fs::read_to_string(format!("{dir}/readings.tsv")).expect("the table");
        let mut rows = 0;
        for line in table.lines().skip(1) {
            let field: Vec<&str> = line.split('\t').collect();
            let (name, sha) = (field[0], field[2]);
            let number = |at: usize| field[at].parse::<u64>().expect("a figure");
            let bytes = std::fs::read(format!("{dir}/{name}")).expect("a vector");
            assert_eq!(bytes.len(), HEAD_BYTES, "{name}");
            assert_eq!(bytes.len() as u64, number(1), "{name}");
            let digest: String = Sha256::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(digest, sha, "{name}: not the bytes the table was taken on");
            let reading = of_head(&bytes).expect("a megabyte reads");
            assert_eq!(
                of_head_wide(&bytes, 16),
                Some(reading),
                "{name}, on the pool"
            );
            assert_eq!(
                of_head_dealt(&bytes, 1),
                Some(reading),
                "{name}, dealt in turn"
            );
            assert_eq!(reading.positions, 16 * 65_533, "{name}");
            assert_eq!(
                (
                    reading.far,
                    reading.tokens,
                    u64::from(reading.per_mille()),
                    u64::from(reading.long_matches())
                ),
                (number(3), number(4), number(5), number(6)),
                "{name}"
            );
            let chains = reading.per_mille() < LEVEL5_CHAINS_UNDER
                || reading.long_matches() >= LEVEL5_CHAINS_LONG;
            assert_eq!(if chains { "chains" } else { "tree" }, field[7], "{name}");
            rows += 1;
        }
        assert_eq!(rows, 6);
    }
}
