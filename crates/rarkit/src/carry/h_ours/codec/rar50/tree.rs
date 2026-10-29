//! Carried from the predecessor's `codec/rar50/tree.rs` at an earlier revision: items ours from birth
//! per the provenance census (and clean-room outputs, clean by provenance).

#[cfg(feature = "tree-walk-census")]
use crate::encode::tree_census as census;
use std::ops::Range;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
#[cfg(feature = "parallel")]
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
/// Comparisons stop here, as LZMA's stop at `numFastBytes`: the caller
/// recomputes the real length from the distance, so the only thing a
/// deeper comparison buys is a different ORDER among candidates that
/// already agree for this many bytes. That order is worth real bytes
/// where the content has long near-identical records: through the
/// production writer at `-m3 -mo -md33554432` the twelve Silesia files
/// total 52,781,726 bytes at 64 and 52,584,521 at 256 (-0.374%, no file
/// larger), `nci` alone 1,889,776 against 1,719,988 (-8.99%) and `xml`
/// 477,508 against 469,878 (-1.60%). Swept in the lab, `nci` is
/// 1,889,785 at 64, 1,752,618 at 128 and 1,720,004 at 256, so most but
/// not all of it is there by 128. The synthetic corpora and the poster's
/// own 400-file set are SHA256 identical at every cap, solid and not -
/// the shapes we benchmark on could not have found this, and would not
/// have caught a regression in it either.
///
/// ## Why the depth cannot be split away from the anti-degeneracy exit
///
/// The cap does a second job: on reaching it a position takes the
/// candidate's place in the tree wholesale and the descent STOPS, which
/// keeps a long run of identical bytes from turning a bucket into a
/// list. It is tempting to keep that exit shallow and let the comparison
/// run deeper for ranking only, so a repetitive payload keeps the cheap
/// exit. It does not work, because the exit IS the ranking decision:
/// ending the descent is what discards the candidates a deeper
/// comparison was meant to rank. Measured 7 Sep 2026 on `nci` with the
/// two depths split, comparing to 256 and replacing at 64: 1,889,785
/// bytes, the 64-byte figure to the byte, for more CPU than either flat
/// cap. Measured again after the parse's candidate list landed, on a
/// rebuilt binary: the same three figures. Do not re-derive this.
///
/// What the depth costs is therefore the comparison itself, and that is
/// answered in [`common_prefix`] rather than by a shallower cap: a word
/// at a time, 256 is cheaper than 64 was byte at a time. Paired on an
/// idle box over a 256 MiB slice of the repeated corpus, all arms
/// writing the same 1,058,474 bytes: 28.50 s at 64 and 57.39 s at 256
/// comparing byte at a time, against 26.41 s at 256 comparing a word at
/// a time. On `nci`, 15.40 s at 64 byte-wise against 13.75 s at 256
/// word-wise - deeper, smaller and faster at once, because taking a
/// longer match advances the parse further. Through the production
/// writer the twelve Silesia files go 100.41 to 93.29 user seconds and
/// every other shape is cheaper too, the solid 400-file set included.
/// Measured 7 Sep 2026.
pub(crate) const TREE_NICE_LENGTH: usize = 256;
/// The most nodes one position's descent looks at before it gives up and
/// leaves both ends of its split empty. Set high on purpose: a crowded
/// bucket is the case the tree exists for, so this bound is only there to
/// stop a hostile input making one position cost without limit.
pub(crate) const TREE_CUT_VALUE: u32 = 64;
/// How many window positions share one bucket head on average: the head
/// table is the ring's length over this, rounded up to a power of two, so
/// one head for every two positions.
pub(crate) const TREE_HEADS_PER_WINDOW: usize = 2;
/// The tree never reaches farther back than this, whatever the dictionary
/// says: the structure is eight bytes per byte of window (two `u32` per
/// position), so a 64 MiB window is 512 MiB of tree and a dictionary past
/// that keeps its ring and long-table reach beyond this horizon rather
/// than growing the tree to match.
pub(crate) const TREE_MAX_WINDOW: usize = 64 << 20;
/// The multiplier the ring index hashes with; the tree keeps the HIGH bits
/// of the same product, so a bucket here is not a bucket there.
pub(crate) const TREE_WORD_SCATTER: u32 = 0x9E37_79B1;
/// No distance: an empty result slot, and an empty tree slot (slots hold
/// `position + 1`).
pub(crate) const TREE_NO_MATCH: u32 = 0;
/// The most candidates one position's result may hold, and so the widest
/// stride a caller may ask for (local change, 7 Sep 2026).
pub(crate) const TREE_MAX_CANDIDATE_SLOTS: usize = 8;
/// How many candidates the cost-based parse asks for at each position.
///
/// The descent already visits exactly the pairs a `bt4` yields (strictly
/// increasing length, and for each length the NEAREST distance reaching
/// it), because a node's descendants are older than it is, so the subtree
/// a step discards holds only positions that are both farther away and
/// agree for no more bytes. Keeping the whole list is what the parse
/// wants and the list is short; the bound is here because the result
/// costs four bytes per slot per position of the wave in flight.
///
/// When a descent records more pairs than this, the ones kept are the
/// first `TREE_CANDIDATE_SLOTS - 1` (the nearest, whose distance bits are
/// cheapest) and the LAST (the longest), which is what the parse prices
/// at the two ends. Swept on the 256 MiB mixed slice at `-md32m`.
pub(crate) const TREE_CANDIDATE_SLOTS: usize = 4;
/// How many positions ahead of the walk a hash head is touched, and how
/// many ahead the root it names is (see `BucketTrees::warm_head`).
pub(crate) const TREE_WARM_HEAD_AHEAD: usize = 12;
pub(crate) const TREE_WARM_ROOT_AHEAD: usize = 6;
/// How far apart two walkers' positions may drift, and so how much of the
/// cyclic buffer is held back from the window.
///
/// The buffer gives position `p` the slot `p & mask`, so `p` and
/// `p + cyclic` share one. Serially that is safe: by the time
/// `p + cyclic` is inserted, `p` is farther back than the window, and a
/// descent that meets a position outside the window stops there WITHOUT
/// reading its slots. In parallel the walkers stand at different
/// positions, so one running ahead could overwrite the slots of a
/// position another walker still counts as live - and then the answers
/// would depend on the timing, which is the one thing they may not do.
/// So the walkers are barriered every `TREE_SKEW_BOUND` positions and the
/// window is held that far below the buffer: an overwriting position is
/// at least `cyclic - window` ahead of every walker, which the barrier
/// forbids. The comparison limit is passed separately from the chunk, so
/// the chunking changes no answer - it is scheduling and nothing else.
pub(crate) const TREE_SKEW_BOUND: usize = 1 << 18;
/// The most chunks the parallel walk has in flight at once
/// ([`BucketTrees::advance_ranges`]), where the ring leaves room for
/// them.
///
/// With one, every chunk ends at a barrier, and the barrier waits on the
/// chunk's busiest BIN: measured 28 Sep 2026 on tree5k at -m5 (the solid
/// -m5 work), the biggest bin averaged 9.7 per cent of a chunk where a
/// walker's fair share at twelve is 8.3, and the last walker to finish WAS
/// the chunk's wall, 1.2 ms after the mean walker. With several in flight
/// a bin of the next chunk waits only for the same bin of this one, so the
/// hot bucket's walker goes straight on and the others fill in around it.
/// Eight, which a 2 MiB solid dictionary's ring holds seven of: swept on
/// an M3 Mac (untimed, -m5 -s -mt32, three reps, the same bytes at every
/// point), tree5k at twelve walkers 2.379 s with four and 2.341 s with
/// eight, and at sixteen to twenty-four walkers 2.40 to 2.47 s either way.
/// Each chunk in flight holds one deal, a chunk's positions.
// Live with the `parallel` feature only, which the default build has.
#[allow(dead_code)]
pub(crate) const TREE_CHUNKS_AHEAD: usize = 8;
/// How many BINS of buckets a chunk is dealt into per walker, before any
/// walker claims one.
///
/// A walker may not split a bucket - a bucket's tree is walked in
/// increasing position order by one thread, which is what makes the
/// parallel walk's answers the serial walk's - so the only freedom the
/// deal has is which walker gets which bucket. Dealing by
/// `bucket % walkers` gives that freedom away: four-byte prefixes are
/// enormously skewed in real input, and the walker holding the hot ones
/// runs long while the rest wait at the chunk barrier. Measured on the
/// 5.29 MB real corpus at a 4 MiB dictionary, positions per walker per
/// chunk, busiest over mean: 1.57x at four walkers, 2.41x at eight,
/// **2.62x at twelve**. The walk is barriered per chunk, so the busiest
/// walker IS the chunk's wall.
///
/// So the chunk is dealt into this many bins per walker instead, the bins
/// are offered biggest first, and a walker takes the next one when it has
/// finished the last. Eight, because that is where the bins are fine
/// enough for the offer to balance and still coarse enough that the deal
/// keeps every bin's tail in L1: at twelve walkers the same corpus's
/// busiest walker falls from 2.62x the mean to 1.15x, and the floor
/// underneath that is the single busiest BUCKET, which no deal can split
/// and which is 5.7% of a chunk (so about 1.4x at sixteen walkers and
/// less below that).
// Live with the `parallel` feature only, which the default build has.
#[allow(dead_code)]
pub(crate) const TREE_BINS_PER_WALKER: usize = 32;
/// The fewest positions a bin is aimed at, which is what stops a SHORT
/// chunk being cut into bins of nothing.
///
/// A full chunk is [`TREE_SKEW_BOUND`] positions and divides into bins of
/// several hundred, so this never binds on one; a chunk at the end of a
/// short member can be a few thousand positions, and cutting THAT into
/// hundreds of bins would leave each walker a handful of positions at a
/// time, where the descent's prefetch reads
/// [`TREE_WARM_HEAD_AHEAD`] positions ahead inside a bin and has nothing
/// to read. So the bin count follows the chunk, down to one bin per
/// walker.
// Live with the `parallel` feature only, which the default build has.
#[allow(dead_code)]
pub(crate) const TREE_BIN_LEAST: usize = 512;
/// TEST ONLY. While this is not zero, the parallel walk sleeps before it
/// walks the smallest bin of a call's first chunk that holds a position,
/// which is the last of that chunk to be claimed: one walker is held in
/// it while every other runs on through the chunks after it. That is the
/// schedule a loaded box gives by chance, and the one that shows a bucket
/// walked out of order (`walk_pipelined`'s rule 1). A count, so tests
/// that ask for it at once do not turn each other's off.
#[cfg(all(test, feature = "parallel"))]
pub(crate) static WALK_STALLS: AtomicUsize = AtomicUsize::new(0);
/// How far the suffixes at `candidate` and `pos` agree, resuming the
/// comparison at `start` bytes - which both ends of the descent's split
/// already agree on - and stopping at `limit`.
///
/// Eight bytes at a time, because this loop IS the descent's cost: at the
/// wholesale-replacement exit a position compares the full cap before it
/// stops, so a payload of one buffer replayed pays the cap on every
/// position for matches the parse takes through repeat distances anyway.
/// Byte-at-a-time that made the cap's depth the dominant term; a word at
/// a time makes a 256-byte cap cheaper than the 64-byte one was, which is
/// what pays for the depth [`TREE_NICE_LENGTH`] now has.
///
/// The answer is the byte-at-a-time answer: `from_le_bytes` puts array
/// byte `i` at bit `8 * i` on either endianness, so the first differing
/// byte is `trailing_zeros() / 8` wherever this runs.
///
/// **Never inlined**: a call from the chain finder, the parse and the
/// filter scan, in every build, which is what the builds before this
/// attribute did (levels 1 to 4 retire the same instructions with it, to
/// the fourth digit, in the plain and the `pinned` build). Left to
/// `#[inline]` it was the inliner's to decide caller by caller, and once
/// the tree walk stopped calling it the inliner took it into those
/// callers: fewer instructions at levels 1 and 2, but 1.5 and 3.8 percent
/// MORE at levels 3 and 4 on text in the x86-64 plain build (counted 1 Oct
/// 2026).
/// The tree walk's descent does not call this: it has
/// [`common_prefix_inlined`]. Nor, off x86-64, do the chain finder and the
/// parse (`encode::chain`'s `common_prefix` says which form each
/// architecture takes, and why); the fast parse's choice takes the inlined
/// form on every architecture.
#[inline(never)]
pub(crate) fn common_prefix(
    span: &[u8],
    candidate: usize,
    pos: usize,
    start: usize,
    limit: usize,
) -> usize {
    common_prefix_inlined(span, candidate, pos, start, limit)
}
/// [`common_prefix`]'s body, always inlined into its caller: the form the
/// tree walk's descent calls, a compare a node. Out of line it cost the
/// walk 12 percent more instructions on x86-64 and 15 on aarch64 (level 5
/// at one thread), and whether it was out of line was the inliner's
/// choice build by build ([`BucketTrees::walk_range`]). The chain
/// finder and the parse take it too, where their architecture is the
/// faster for it (`encode::chain`).
#[inline(always)]
pub(crate) fn common_prefix_inlined(
    span: &[u8],
    candidate: usize,
    pos: usize,
    start: usize,
    limit: usize,
) -> usize {
    let mut length = start;
    // `limit` never reaches past the span (it is capped at `limit - pos`
    // by the caller, and `candidate` is below `pos`), so a whole word at
    // `length` is in bounds whenever `length + 8` is within it.
    while length + 8 <= limit {
        let left = u64::from_le_bytes(span[candidate + length..][..8].try_into().unwrap());
        let right = u64::from_le_bytes(span[pos + length..][..8].try_into().unwrap());
        let difference = left ^ right;
        if difference != 0 {
            return length + (difference.trailing_zeros() >> 3) as usize;
        }
        length += 8;
    }
    while length != limit && span[candidate + length] == span[pos + length] {
        length += 1;
    }
    length
}
/// A position's `stride` result slots at `at`: the `kept` distances found,
/// then [`TREE_NO_MATCH`] in the rest. Every slot of every position a walk
/// visits is written, so a caller's buffer needs no clearing first except
/// for the positions no walk visits: the last three of the span, which
/// have no four bytes ahead of them and are never dealt.
#[inline(always)]
fn store_found(
    out: &[AtomicU32],
    at: usize,
    found: &[u32; TREE_MAX_CANDIDATE_SLOTS],
    kept: usize,
    stride: usize,
) {
    for (index, slot) in out[at..at + stride].iter().enumerate() {
        let distance = if index < kept {
            found[index]
        } else {
            TREE_NO_MATCH
        };
        #[cfg(feature = "tree-walk-census")]
        {
            census::store(slot, census::Kind::Hint);
            census::with(|t| t.hint_stores += 1);
        }
        slot.store(distance, Ordering::Relaxed);
    }
}
/// `count` empty slots. `AtomicU32` is not `Clone`, so `vec!` cannot.
pub(crate) fn empty_slots(count: usize) -> Vec<AtomicU32> {
    let mut slots = Vec::new();
    // Before the fill writes them: a descent reads its nodes' slots at
    // random, and 2 MiB pages keep those loads off the page walker
    // (`crate::pages`). Only where the advice exists, so that every other
    // target compiles what it always did.
    #[cfg(target_os = "linux")]
    {
        slots.reserve(count);
        crate::pages::advise_huge_of(slots.spare_capacity_mut());
    }
    slots.resize_with(count, || AtomicU32::new(TREE_NO_MATCH));
    slots
}
/// One chunk's positions dealt into bins by bucket
/// ([`BucketTrees::share_chunk`]): every position once, bin after bin,
/// each bin's in increasing order.
///
/// ONE buffer of the chunk's positions and not a list a bin, and that is a
/// memory decision (the -m4 and -m5 memory work, 28 Sep 2026). Lists
/// grown one push at a time each kept the capacity of the busiest share
/// they had ever held, and real input's hot buckets land in a different
/// bin each chunk, so every list drifted up to a hot share: at eight
/// walkers the 512 lists of a -m5 run held about 20 MiB where a chunk is
/// 1 MiB of positions. Counted first and then placed, the deal holds
/// exactly the chunk. The bins, their order and the order inside each
/// are the lists', so the walkers see what they saw.
#[cfg(feature = "parallel")]
#[derive(Default)]
pub(crate) struct Deal {
    /// The chunk's positions, bin by bin.
    positions: Vec<u32>,
    /// Where each bin starts in `positions`, and where the last ends.
    starts: Vec<u32>,
    /// Where the next position of each bin goes, while it is dealt.
    cursor: Vec<u32>,
}

#[cfg(feature = "parallel")]
impl Deal {
    /// The positions of bin `bin`, in increasing order.
    pub(crate) fn bin(&self, bin: usize) -> &[u32] {
        &self.positions[self.starts[bin] as usize..self.starts[bin + 1] as usize]
    }

    /// How many bins the last deal made, for the walk probe.
    #[cfg(feature = "bench-internals")]
    pub(crate) fn bins(&self) -> usize {
        self.starts.len().saturating_sub(1)
    }

    /// The bytes this deal holds, at the most it has held.
    pub(crate) fn held_bytes(&self) -> u64 {
        ((self.positions.capacity() + self.starts.capacity() + self.cursor.capacity()) * 4) as u64
    }
}

/// A binary tree per four-byte hash bucket over a sliding window of the
/// member's span, walked once per position.
///
/// ## Why the slots are atomic, and why that is not a lock
///
/// The walk is parallel BY BUCKET ([`BucketTrees::advance_range`]):
/// bucket trees are independent, so a thread that owns a set of buckets
/// walks their positions in increasing order and never touches another
/// thread's nodes. Every node a descent reads belongs to the bucket it is
/// descending, so the answers are exactly the serial walk's, at any
/// thread count.
///
/// The one place two threads touch the same slot is the cyclic buffer's
/// own wrap: positions `p` and `p + cyclic` share a slot pair, and one of
/// them is always outside the window - a descent that meets a node
/// farther back than the window stops at it WITHOUT reading its slots, so
/// the stale half is never read. `Relaxed` is therefore the whole of the
/// ordering this needs (and compiles to a plain load and store); the
/// atomics are here to make that sharing well defined rather than to
/// synchronise anything.
pub(crate) struct BucketTrees {
    /// Two entries per window slot: the subtree of positions whose suffix
    /// sorts BELOW this one, and the subtree of those above. Both hold
    /// `position + 1`; zero is empty.
    pub(crate) subtrees: Vec<AtomicU32>,
    /// The newest position of each hash bucket, `position + 1`.
    pub(crate) newest: Vec<AtomicU32>,
    /// `position & cyclic_mask` is a position's slot pair in `subtrees`.
    pub(crate) cyclic_mask: usize,
    /// The largest distance a candidate may be at: one less than the
    /// cyclic size, so two live positions never share a slot.
    pub(crate) window: usize,
    pub(crate) bucket_shift: u32,
    /// How many nodes one descent may visit.
    pub(crate) cut: u32,
    /// The chunks in flight's deals, one slot each, and each one's bins in
    /// the order they are offered to the walkers (biggest first), refilled
    /// per chunk and kept between calls so the walk allocates nothing once
    /// it has walked a chunk of every size. Only `advance_ranges`'s
    /// `parallel`-gated arm touches these.
    #[cfg(feature = "parallel")]
    pub(crate) slots: Vec<std::sync::RwLock<(Deal, Vec<u32>)>>,
    /// Each slot's bins' states (`advance_ranges`): which chunk the slot
    /// holds, and whether each bin of it is waiting, taken or walked.
    #[cfg(feature = "parallel")]
    pub(crate) states: Vec<AtomicU64>,
    /// The next position the finder expects; positions are presented in
    /// increasing order and every one of them is inserted.
    pub(crate) next: usize,
    /// The RUN position of `span[0]`. What the slots hold, and which slot
    /// pair a position takes, count from the start of the run and not
    /// from the span: a position `pos` of the span is `origin + pos`.
    /// So a carried history that drops its oldest bytes moves this and
    /// leaves every slot as it is ([`BucketTrees::slide`], spec H3
    /// section 4). Zero for a span that starts its run.
    pub(crate) origin: usize,
}
impl BucketTrees {
    /// A finder over a window of `max_distance` bytes, capped at
    /// [`TREE_MAX_WINDOW`]. The window is rounded UP to a power of two and
    /// one position is kept back from it so no two live positions share a
    /// slot, which costs the single farthest distance of a power-of-two
    /// dictionary (33,554,431 rather than 33,554,432 at `-md32m`) and
    /// nothing at all otherwise.
    ///
    /// The size depends on the DICTIONARY alone and never on the span,
    /// because a window's answers must be the whole member's answers and a
    /// window is shorter than its member.
    pub(crate) fn new(max_distance: usize) -> Self {
        let cyclic = Self::new_cyclic(max_distance);
        let heads = (cyclic / TREE_HEADS_PER_WINDOW)
            .max(1 << 10)
            .next_power_of_two();
        Self {
            subtrees: empty_slots(2 * cyclic),
            newest: empty_slots(heads),
            cyclic_mask: cyclic - 1,
            window: max_distance.min(cyclic - 1 - TREE_SKEW_BOUND),
            bucket_shift: 32 - heads.trailing_zeros(),
            cut: TREE_CUT_VALUE,
            #[cfg(feature = "parallel")]
            slots: Vec::new(),
            #[cfg(feature = "parallel")]
            states: Vec::new(),
            next: 0,
            origin: 0,
        }
    }
    /// The cyclic length, in positions, of a finder built by
    /// [`BucketTrees::new`] over `max_distance`.
    pub(crate) fn new_cyclic(max_distance: usize) -> usize {
        // min-then-max rather than `clamp`: `clamp` PANICS when the
        // ceiling is below the floor, and these are two independent
        // constants. Saturating to the floor is the wanted behaviour if
        // they are ever set that way; a panic in a decoder is not.
        #[allow(clippy::manual_clamp)]
        max_distance
            .min(TREE_MAX_WINDOW)
            .max(4 * TREE_SKEW_BOUND)
            .next_power_of_two()
    }
    /// The span lost its first `dropped` bytes and nothing else: every
    /// position the index holds keeps its slot and its value, and the
    /// ones that were dropped are farther back than any window can reach
    /// from what the span still holds, so a descent stops at them without
    /// reading them. `span_most` is the longest the span may grow to
    /// before the next slide, which is what the `u32` slots must still
    /// have room for ([`BucketTrees::rebase`]).
    ///
    /// Only for a caller that keeps at least the window's bytes: a
    /// candidate is read from the span only once it is inside the window,
    /// and that is what keeps it inside the span.
    pub(crate) fn slide(&mut self, dropped: usize, span_most: usize) {
        debug_assert!(dropped <= self.next, "a slide drops only indexed bytes");
        self.next -= dropped;
        self.origin += dropped;
        if self.origin.saturating_add(span_most) >= u32::MAX as usize {
            self.rebase();
        }
    }
    /// Count the run from a later start: take the largest whole number of
    /// cyclic lengths not past [`BucketTrees::origin`] off it and off
    /// every slot, a slot naming a position before that becoming empty.
    ///
    /// **Why no answer moves.** A whole number of cyclic lengths leaves
    /// every position in its own slot pair. A slot that empties named a
    /// position before the span, farther back than the window, and a
    /// descent that meets one stops there and empties the two ends of its
    /// split, exactly as it does on meeting an empty slot. A slide calls
    /// it once a long run's positions near `u32::MAX`; the tree's own
    /// test pins it.
    pub(crate) fn rebase(&mut self) {
        let by = self.origin & !self.cyclic_mask;
        if by == 0 {
            return;
        }
        let by = u32::try_from(by).expect("an origin inside the u32 slots");
        for slot in self.subtrees.iter().chain(self.newest.iter()) {
            let value = slot.load(Ordering::Relaxed);
            slot.store(
                if value > by {
                    value - by
                } else {
                    TREE_NO_MATCH
                },
                Ordering::Relaxed,
            );
        }
        self.origin -= by as usize;
    }
    /// Empty every head that inserting any position of `span` could have
    /// written: the buckets of its four byte words, and no other. Answers
    /// whether it did; `false` leaves the heads alone and the caller
    /// clears them all.
    ///
    /// The cheap form of storing [`TREE_NO_MATCH`] in every head, for a
    /// span much shorter than the table. [`Self::advance`] writes a head
    /// only for a position with four bytes ahead of it, at the bucket
    /// those four bytes hash to, so these are all the heads a walk over
    /// any prefix of `span` can have written.
    pub(crate) fn forget(&self, span: &[u8]) -> bool {
        for pos in 0..span.len().saturating_sub(3) {
            let word = u32::from_le_bytes(span[pos..pos + 4].try_into().unwrap());
            let bucket = (word.wrapping_mul(TREE_WORD_SCATTER) >> self.bucket_shift) as usize;
            self.newest[bucket].store(TREE_NO_MATCH, Ordering::Relaxed);
        }
        true
    }
    /// Start the next walk at `pos`, the positions before it absent from
    /// the tree: a window's history begins where the caller says, not at
    /// the start of the span it is a window onto.
    ///
    /// Unreferenced in the shipped builds: the encoder reaches the finder
    /// through `walk_range`, which starts where it is told. Kept under
    /// SPEC-H3 section 5, which names the binary tree match finder and its
    /// window sharing as carried capability.
    #[allow(dead_code)]
    pub(crate) fn skip_to(&mut self, pos: usize) {
        debug_assert_eq!(self.next, 0);
        self.next = pos;
    }
    /// Whether a span's positions and this finder's slots fit the `u32`
    /// the tree stores. A span at or past `u32::MAX` positions takes the
    /// ring alone.
    ///
    /// Unreferenced in the shipped builds; kept under SPEC-H3 section 5
    /// with [`BucketTrees::skip_to`].
    #[allow(dead_code)]
    pub(crate) fn fits(span_len: usize) -> bool {
        u32::try_from(span_len).is_ok_and(|len| len != u32::MAX)
    }
    /// The window this finder reaches over: a candidate farther back than
    /// this is pruned, and the caller's own distance limit should not
    /// exceed it.
    pub(crate) fn window(&self) -> usize {
        self.window
    }
    /// Walk `range` of `span`, inserting every position and writing the
    /// best distance found at it into `out[pos - range.start]` (zero where
    /// there is none). `out` is `range.len()` long, and `range.start` must
    /// be where the previous call left off. Passing `None` for `out`
    /// inserts without recording, which is how a window's history reaches
    /// the tree.
    ///
    /// COMPARISONS STOP AT `range.end`, and the caller's ranges are
    /// therefore part of the answer: a tokenizer whose matches may not
    /// reach past a block boundary hands the finder one range per block,
    /// so the tree ranks candidates by exactly the prefix the encoder can
    /// emit - and a window of a member, splitting on the same boundaries,
    /// builds the same tree the whole-member walk builds. The cost is the
    /// last three positions of every range, which have no four bytes
    /// within it and are not indexed.
    ///
    /// `threads` walkers split the range BY BUCKET, each taking whole
    /// buckets and walking their positions in order. The answers do not
    /// depend on how many walkers there are, nor on WHICH buckets each
    /// one took: see the note on the struct.
    /// The bytes the walkers' bins hold now: the deals in flight, their
    /// offers and the bins' states, at the most they have held.
    pub(crate) fn bins_bytes(&self) -> u64 {
        #[cfg(feature = "parallel")]
        {
            let slots: u64 = self
                .slots
                .iter()
                .map(|slot| {
                    let held = slot.read().unwrap_or_else(|e| e.into_inner());
                    held.0.held_bytes() + (held.1.capacity() * 4) as u64
                })
                .sum();
            slots + (self.states.capacity() * 8) as u64
        }
        #[cfg(not(feature = "parallel"))]
        0
    }

    /// The most [`BucketTrees::bins_bytes`] reads for walks of
    /// `walkers` walkers over at most `positions` positions at a time: a
    /// deal of one chunk ([`TREE_SKEW_BOUND`] positions at most) for each
    /// chunk in flight and the one dealt ahead of them, with their bins'
    /// offsets, their offers and their bins' states.
    pub(crate) fn bins_most(walkers: usize, positions: usize) -> u64 {
        let bins = walkers * TREE_BINS_PER_WALKER;
        let chunk = positions.min(TREE_SKEW_BOUND);
        let slots = TREE_CHUNKS_AHEAD + 1;
        (slots * ((chunk + 2 * (bins + 1)) * 4 + bins * 4 + bins * 8)) as u64
    }

    pub(crate) fn advance_range(
        &mut self,
        span: &[u8],
        range: Range<usize>,
        out: Option<&[AtomicU32]>,
        stride: usize,
        threads: usize,
    ) {
        let end = [range.end];
        self.advance_ranges(span, range.start, &end, out, stride, threads);
    }

    /// [`BucketTrees::advance_range`] over several CONTIGUOUS ranges
    /// in one walk: from `start` to `ends[0]`, then to `ends[1]`, and so
    /// on, each position's comparisons stopping at the end of its OWN
    /// range, so every answer is the one `advance_range` gives when the
    /// ranges are walked one call apiece, in order. `out` covers them all
    /// from `start`.
    ///
    /// **Why that holds at any walker count.** A bucket's positions are
    /// still walked in increasing order by one walker, and a descent
    /// reads its own bucket's tree and its own position's limit and
    /// nothing else, so whether the ranges are walked one call apiece or
    /// dealt together into one set of bins moves no answer. What it buys
    /// is width: a solid set's small members are each a range shorter
    /// than a walk worth dealing, and walked together they are one.
    pub(crate) fn advance_ranges(
        &mut self,
        span: &[u8],
        start: usize,
        ends: &[usize],
        out: Option<&[AtomicU32]>,
        stride: usize,
        threads: usize,
    ) {
        let end = *ends.last().expect("at least one range");
        let range = start..end;
        debug_assert_eq!(self.next, range.start);
        debug_assert!((1..=TREE_MAX_CANDIDATE_SLOTS).contains(&stride));
        debug_assert!(out.is_none_or(|out| out.len() == range.len() * stride));
        debug_assert!(ends.windows(2).all(|pair| pair[0] <= pair[1]) && start <= ends[0]);
        self.next = range.end;
        let threads = threads.max(1);
        let base = range.start;
        if threads == 1 {
            let mut from = start;
            for &limit in ends {
                self.walk_range(span, from..limit, limit, base, out, stride);
                from = limit;
            }
            return;
        }
        #[cfg(feature = "parallel")]
        self.walk_pipelined(span, range, ends, out, stride, threads);
        #[cfg(not(feature = "parallel"))]
        {
            let mut from = start;
            for &limit in ends {
                self.walk_range(span, from..limit, limit, base, out, stride);
                from = limit;
            }
        }
    }
    /// `advance_ranges`'s parallel walk: the range cut into chunks of
    /// [`TREE_SKEW_BOUND`] positions, each chunk DEALT into bins by bucket
    /// (`share_chunk`), and every bin of every chunk walked by whichever
    /// walker claims it.
    ///
    /// **What keeps the answers the serial walk's.** Two rules, and the
    /// scheduling is free inside them:
    ///
    /// 1. A bucket's positions are walked in increasing order by one
    ///    thread at a time. The bin count is fixed for the whole call, so
    ///    bin `b` holds the same buckets in every chunk, and bin `b` of a
    ///    chunk is claimed only once bin `b` of the chunk before it has
    ///    been walked. That is an induction along a bin's chunks, so it
    ///    holds for EVERY bin, one with no position in it too: an empty
    ///    bin waits its turn and is walked (nothing) like any other.
    ///    (Until 1 Oct 2026 the deal marked an empty bin walked at once.
    ///    Then bin `b` of chunk `k + 1` could be claimed while bin `b` of
    ///    chunk `k - 1` was still under a walker, wherever chunk `k` had
    ///    no position for it, and two threads walked one bucket's tree
    ///    out of order: a few bytes of archive that differed run to run
    ///    on a loaded box, wherever the ring left room for three chunks.)
    /// 2. No two walkers stand further apart than the ring leaves room
    ///    for: [`TREE_SKEW_BOUND`] says why that is the whole of what the
    ///    cyclic buffer asks. A chunk is walked only while every chunk
    ///    more than `ahead` before it is finished, and `ahead` chunks fit
    ///    in the room between the tree's window and its ring, so at least
    ///    one and at most [`TREE_CHUNKS_AHEAD`]. At one this is a barrier
    ///    at every chunk, which is the walk this replaces.
    ///
    /// **Why several.** With a barrier each chunk waited on its busiest
    /// bin, a hot bucket no deal can split ([`TREE_CHUNKS_AHEAD`] has the
    /// figures). Here the walker that finishes a bin goes straight on to
    /// the same bin of the next chunk, so the hot bucket's walker never
    /// waits and the others fill in around it.
    ///
    /// This thread deals the chunks ahead of the walk, into
    /// `ahead + 1` slots, and walks bins between deals; the other
    /// walkers only walk. It can finish the walk alone, so a walker that
    /// never gets a thread holds nothing up.
    ///
    /// **Never inlined**, and that is for the SERIAL walk's sake. Inlined
    /// into `advance_ranges`, this function's setup shared one body with
    /// the serial descent, and an edit here moved the registers THERE: on
    /// 1 Oct 2026 one boolean added to this function left the serial
    /// loop's source untouched and its x86-64 code reloading the candidate
    /// from the stack twice a step, 0.89x to 0.96x of the wall at `-mt1`
    /// on two Zen 4 machines (K=3 and K=5, level 5, the same bytes).
    /// Out of line, the serial walk's code depends on its own source: the
    /// same rows read 1.02x to 1.05x of the parent's, and aarch64 level
    /// (measured 1 Oct 2026). It is
    /// one call a walk, whose own work is millions of positions.
    #[cfg(feature = "parallel")]
    #[inline(never)]
    fn walk_pipelined(
        &mut self,
        span: &[u8],
        range: Range<usize>,
        ends: &[usize],
        out: Option<&[AtomicU32]>,
        stride: usize,
        threads: usize,
    ) {
        use std::sync::RwLock;
        // A bin's state: the chunk it belongs to, plus one, above two bits
        // saying whether it waits, is taken or is walked.
        const WAITING: u64 = 0;
        const TAKEN: u64 = 1;
        const WALKED: u64 = 2;
        let chunk_len = TREE_SKEW_BOUND;
        let chunks = range.len().div_ceil(chunk_len);
        if chunks == 0 {
            return;
        }
        let base = range.start;
        #[cfg(feature = "tree-walk-census")]
        let walk_began = std::time::Instant::now();
        // The room between the window and the ring, `cyclic - 1 - window`.
        let room = self.cyclic_mask - self.window.min(self.cyclic_mask);
        let ahead = (room / chunk_len).clamp(1, TREE_CHUNKS_AHEAD).min(chunks);
        let slot_count = ahead + 1;
        let bins = (range.len().min(chunk_len) / TREE_BIN_LEAST)
            .clamp(threads, threads * TREE_BINS_PER_WALKER);
        let mut slots = std::mem::take(&mut self.slots);
        while slots.len() < slot_count {
            slots.push(RwLock::new((Deal::default(), Vec::new())));
        }
        let mut states = std::mem::take(&mut self.states);
        states.clear();
        states.resize_with(slot_count * bins, || AtomicU64::new(0));
        {
            let finder = &*self;
            // One answer for the whole call: the walkers are this call's.
            let skip = skips_same_stores(threads);
            let slots = &slots[..slot_count];
            let states = &states[..];
            let chunk_of = |k: usize| {
                let at = range.start + k * chunk_len;
                at..(at + chunk_len).min(range.end)
            };
            let tag = |k: usize| (k as u64 + 1) << 2;
            // Per slot: its bins not yet walked, and the claim cursor over
            // its offer, the chunk plus one in the high half.
            let left: Vec<AtomicUsize> = (0..slot_count).map(|_| AtomicUsize::new(0)).collect();
            let cursor: Vec<AtomicU64> = (0..slot_count).map(|_| AtomicU64::new(0)).collect();
            // Chunks dealt, and the first chunk not yet walked whole.
            let published = AtomicUsize::new(0);
            let lowest = AtomicUsize::new(0);
            let settle = || loop {
                let low = lowest.load(Ordering::Acquire);
                if low >= published.load(Ordering::Acquire)
                    || left[low % slot_count].load(Ordering::Acquire) != 0
                {
                    break;
                }
                // A slot is dealt again only once `lowest` has passed its
                // chunk, so the count read is chunk `low`'s own.
                let _ = lowest.compare_exchange(low, low + 1, Ordering::AcqRel, Ordering::Acquire);
            };
            let deal = |k: usize| {
                let slot = k % slot_count;
                {
                    let mut held = slots[slot].write().unwrap_or_else(|e| e.into_inner());
                    let (dealt, offer) = &mut *held;
                    #[cfg(feature = "tree-walk-census")]
                    let dealt_at = std::time::Instant::now();
                    finder.share_chunk(span, chunk_of(k), bins, dealt);
                    #[cfg(feature = "tree-walk-census")]
                    census::with(|t| t.deal_ns += dealt_at.elapsed().as_nanos() as u64);
                    // Biggest bin first: see [`TREE_BINS_PER_WALKER`]. An
                    // EMPTY bin is offered and waits like any other, last:
                    // rule 1 is an induction along a bin's chunks, and a
                    // bin marked walked here, at the deal, would be
                    // walked before the same bin of the chunk before it,
                    // which lets the one after it be claimed while that
                    // one is still under a walker.
                    offer.clear();
                    offer.extend(0..bins as u32);
                    offer.sort_unstable_by_key(|&bin| !(dealt.bin(bin as usize).len() as u64));
                    for bin in 0..bins {
                        states[slot * bins + bin].store(tag(k) | WAITING, Ordering::Release);
                    }
                    left[slot].store(offer.len(), Ordering::Release);
                    cursor[slot].store((k as u64 + 1) << 32, Ordering::Release);
                }
                published.store(k + 1, Ordering::Release);
                settle();
            };
            let walked_before = |k: usize, bin: usize| {
                if k == 0 {
                    return true;
                }
                let state = states[((k - 1) % slot_count) * bins + bin].load(Ordering::Acquire);
                // The slot holding a LATER chunk means chunk `k - 1` was
                // walked whole before it was dealt again.
                state >> 2 > k as u64 || (state >> 2 == k as u64 && state & 3 == WALKED)
            };
            let claim = |k: usize, bin: usize| {
                states[(k % slot_count) * bins + bin]
                    .compare_exchange(
                        tag(k) | WAITING,
                        tag(k) | TAKEN,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
            };
            let walk_bin = |k: usize, bin: usize| {
                let slot = k % slot_count;
                {
                    let held = slots[slot].read().unwrap_or_else(|e| e.into_inner());
                    #[cfg(test)]
                    if WALK_STALLS.load(Ordering::Relaxed) != 0 && k == 0 {
                        let smallest = held
                            .1
                            .iter()
                            .rev()
                            .find(|&&b| !held.0.bin(b as usize).is_empty());
                        if smallest == Some(&(bin as u32)) {
                            std::thread::sleep(std::time::Duration::from_millis(25));
                        }
                    }
                    #[cfg(feature = "tree-walk-census")]
                    let bin_began = std::time::Instant::now();
                    finder.walk(span, held.0.bin(bin), ends, base, out, stride, skip);
                    #[cfg(feature = "tree-walk-census")]
                    {
                        census::with(|t| t.bin_ns += bin_began.elapsed().as_nanos() as u64);
                        census::fold();
                    }
                }
                states[slot * bins + bin].store(tag(k) | WALKED, Ordering::Release);
                if left[slot].fetch_sub(1, Ordering::AcqRel) == 1 {
                    settle();
                }
            };
            // A walker that panics leaves its bin taken for good, and the
            // rest would wait on that bin for ever: it says so on its way
            // out and they stop, which leaves the panic for the scope to
            // raise instead of a walk that never ends.
            let failed = AtomicBool::new(false);
            struct Unwound<'a>(&'a AtomicBool);
            impl Drop for Unwound<'_> {
                fn drop(&mut self) {
                    if std::thread::panicking() {
                        self.0.store(true, Ordering::Release);
                    }
                }
            }
            let work = |dealer: bool| {
                let _unwound = Unwound(&failed);
                // The same bin of the next chunk, which the walker that
                // walked this one takes first.
                let mut next: Option<(usize, usize)> = None;
                let mut idle = 0u32;
                loop {
                    if failed.load(Ordering::Relaxed) {
                        break;
                    }
                    if dealer {
                        let n = published.load(Ordering::Acquire);
                        if n < chunks && n < lowest.load(Ordering::Acquire) + slot_count {
                            deal(n);
                            continue;
                        }
                    }
                    if let Some((k, bin)) = next.take() {
                        if k < chunks
                            && k < published.load(Ordering::Acquire)
                            && k < lowest.load(Ordering::Acquire) + ahead
                            && claim(k, bin)
                        {
                            walk_bin(k, bin);
                            next = Some((k + 1, bin));
                            idle = 0;
                            continue;
                        }
                    }
                    let low = lowest.load(Ordering::Acquire);
                    if low >= chunks {
                        break;
                    }
                    let top = published.load(Ordering::Acquire).min(low + ahead);
                    let mut took = None;
                    'chunks: for k in low..top {
                        let slot = k % slot_count;
                        let held = slots[slot].read().unwrap_or_else(|e| e.into_inner());
                        loop {
                            let at = cursor[slot].load(Ordering::Acquire);
                            if at >> 32 != k as u64 + 1 {
                                // The slot has moved on to a later chunk.
                                break;
                            }
                            let index = (at & 0xFFFF_FFFF) as usize;
                            let Some(&bin) = held.1.get(index) else {
                                break;
                            };
                            if cursor[slot]
                                .compare_exchange(at, at + 1, Ordering::AcqRel, Ordering::Acquire)
                                .is_err()
                            {
                                continue;
                            }
                            let bin = bin as usize;
                            // A bin whose predecessor is not walked yet is
                            // passed over: the walker of that predecessor
                            // takes it next (`next` above), because the
                            // predecessor was taken or is still to be
                            // taken, and either way is walked.
                            if walked_before(k, bin) && claim(k, bin) {
                                took = Some((k, bin));
                                break 'chunks;
                            }
                        }
                    }
                    match took {
                        Some((k, bin)) => {
                            walk_bin(k, bin);
                            next = Some((k + 1, bin));
                            idle = 0;
                        }
                        None => {
                            idle += 1;
                            if idle < 64 {
                                std::hint::spin_loop();
                            } else {
                                std::thread::yield_now();
                            }
                        }
                    }
                }
            };
            let work = &work;
            rayon::in_place_scope(|scope| {
                for _ in 1..threads {
                    scope.spawn(move |_| work(false));
                }
                work(true);
            });
        }
        #[cfg(feature = "tree-walk-census")]
        census::with(|t| {
            let ns = walk_began.elapsed().as_nanos() as u64;
            t.walk_ns += ns;
            t.walker_ns += ns * threads as u64;
            t.walks += 1;
        });
        self.slots = slots;
        self.states = states;
    }
    /// Deal a chunk's positions into `bins` BINS by bucket, each bin
    /// keeping its own positions in order. The chunk's bytes are passed
    /// over twice, once to count each bin and once to place its positions
    /// (`Deal`), which deals every bin: the first cut had each walker scan
    /// the whole chunk and skip what was not its own, which is the same
    /// hash computed once per walker and measured 234 user seconds against
    /// the serial walk's 103 on the 256 MiB slice.
    ///
    /// There are [`TREE_BINS_PER_WALKER`] bins per walker rather than one,
    /// and the caller offers them biggest first; that constant says why.
    #[cfg(feature = "parallel")]
    pub(crate) fn share_chunk(
        &self,
        span: &[u8],
        chunk: Range<usize>,
        bins: usize,
        deal: &mut Deal,
    ) {
        let bucket_shift = self.bucket_shift;
        let tail = 3;
        let end = chunk.end.min(span.len().saturating_sub(tail));
        let bin_of = |pos: usize| {
            let word = u32::from_le_bytes(span[pos..pos + 4].try_into().unwrap());
            let hash = word.wrapping_mul(TREE_WORD_SCATTER);
            let bucket = (hash >> bucket_shift) as usize;
            bucket % bins
        };
        let starts = &mut deal.starts;
        starts.clear();
        starts.resize(bins + 1, 0);
        for pos in chunk.start..end.max(chunk.start) {
            starts[bin_of(pos) + 1] += 1;
        }
        for bin in 0..bins {
            starts[bin + 1] += starts[bin];
        }
        let cursor = &mut deal.cursor;
        cursor.clear();
        cursor.extend_from_slice(&starts[..bins]);
        let positions = &mut deal.positions;
        positions.clear();
        positions.resize(starts[bins] as usize, 0);
        for pos in chunk.start..end.max(chunk.start) {
            let bin = bin_of(pos);
            positions[cursor[bin] as usize] = pos as u32;
            cursor[bin] += 1;
        }
    }
    /// One BIN of a chunk: the positions dealt to it, in order. Only
    /// called from `advance_ranges`'s `parallel`-gated arm, once by
    /// whichever walker claimed the bin. A position compares up to the
    /// first of `ends` past it, its own range's end; the bin's positions
    /// increase, so that end is found by a cursor that only moves on.
    ///
    /// With `skip`, which the caller reads once a walk from
    /// [`skips_same_stores`], the descent skips the son stores that would
    /// write back the value their slot already holds
    /// ([`Self::advance_with`] says which, and why that moves no answer).
    ///
    /// **Never inlined**, with both forms of [`Self::walk_bin`] inlined
    /// into it: the binned walk is this one symbol in every build. Left to
    /// the inliner it was a symbol in some builds and folded into
    /// `walk_pipelined`'s closure in others ([`Self::walk_range`]).
    #[cfg(feature = "parallel")]
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn walk(
        &self,
        span: &[u8],
        share: &[u32],
        ends: &[usize],
        base: usize,
        out: Option<&[AtomicU32]>,
        stride: usize,
        skip: bool,
    ) {
        if skip {
            self.walk_bin::<true>(span, share, ends, base, out, stride);
        } else {
            self.walk_bin::<false>(span, share, ends, base, out, stride);
        }
    }
    /// [`Self::walk`] with the store skip fixed, so each form is compiled
    /// without the other's test in its descent.
    ///
    /// **Always inlined into [`Self::walk`]**, both forms: one symbol holds
    /// the binned walk. As two symbols of their own the same two bodies
    /// retired 2 percent more instructions at sixteen threads than the
    /// build before this change and lost 1.6 percent of wall on 4 GiB of
    /// binaries on a Zen 4; inlined into one `walk` they retire 3 percent
    /// fewer than it (counted and timed 1 Oct 2026; no mechanism is
    /// claimed). [`Self::walk_range`] says what the attributes are for.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    fn walk_bin<const SKIP: bool>(
        &self,
        span: &[u8],
        share: &[u32],
        ends: &[usize],
        base: usize,
        out: Option<&[AtomicU32]>,
        stride: usize,
    ) {
        let mut found = [TREE_NO_MATCH; TREE_MAX_CANDIDATE_SLOTS];
        let mut leg = 0;
        #[cfg(feature = "tree-walk-census")]
        census::set_walker();
        for (index, &pos) in share.iter().enumerate() {
            if let Some(&far) = share.get(index + TREE_WARM_HEAD_AHEAD) {
                self.warm_head(span, far as usize);
            }
            if let Some(&near) = share.get(index + TREE_WARM_ROOT_AHEAD) {
                self.warm_root(span, near as usize);
            }
            let pos = pos as usize;
            while pos >= ends[leg] {
                leg += 1;
            }
            let kept = self.advance_with::<SKIP>(span, pos, ends[leg], &mut found, stride);
            if let Some(out) = out {
                store_found(out, (pos - base) * stride, &found, kept, stride);
            }
        }
    }
    /// The whole of a range, in order: the serial walk.
    ///
    /// **Never inlined, and everything a position runs is always inlined
    /// into it** (the warming, the descent, its compare, the hints'
    /// store), so the serial walk is ONE compiled body whatever the rest
    /// of the crate looks like; `walk` is the same for the binned walk
    /// (a plain name: it exists with the `parallel` feature only). Left to the inliner, these bodies were re-rolled by every
    /// land: the walk sat inside `advance_ranges` at 1,002 instructions in
    /// one plain build and 1,142 in the next commit's, the compare in or
    /// out of line, and a different body in each of five profile-guided
    /// draws of ONE commit, with 2 to 5 percent of level 5's wall moving
    /// beside it, and 4 to 11 percent once (the walker cap's first tree).
    /// With these attributes the body is 515 instructions and one digest
    /// in the plain builds of five commits. It retires 1 to 3 percent
    /// fewer instructions than the build before it on x86-64 and 4 to 6
    /// fewer on aarch64; in wall it is level on a Zen 4 (0.986 to 0.996 at
    /// one thread) and 1 to 3 percent ahead on an M3 Ultra.
    #[inline(never)]
    pub(crate) fn walk_range(
        &self,
        span: &[u8],
        range: Range<usize>,
        limit: usize,
        base: usize,
        out: Option<&[AtomicU32]>,
        stride: usize,
    ) {
        let mut found = [TREE_NO_MATCH; TREE_MAX_CANDIDATE_SLOTS];
        #[cfg(feature = "tree-walk-census")]
        let serial_began = std::time::Instant::now();
        #[cfg(feature = "tree-walk-census")]
        {
            census::set_walker();
            census::with(|t| t.serial_positions += range.len() as u64);
        }
        for pos in range {
            self.warm_head(span, pos + TREE_WARM_HEAD_AHEAD);
            self.warm_root(span, pos + TREE_WARM_ROOT_AHEAD);
            let kept = self.advance(span, pos, limit, &mut found, stride);
            if let Some(out) = out {
                store_found(out, (pos - base) * stride, &found, kept, stride);
            }
        }
        #[cfg(feature = "tree-walk-census")]
        {
            census::with(|t| t.serial_ns += serial_began.elapsed().as_nanos() as u64);
            census::fold();
        }
    }
    /// Touch the hash head a position about to be walked will load, so
    /// the load is in flight before the walk needs it (rarkit H3 follow-up,
    /// 18 Sep 2026). A descent is a chain of dependent loads over a
    /// structure far larger than the cache, and its first two, the head
    /// and the root's pair, are the only ones whose address is known ahead
    /// of time. The value is thrown away: by the time the walk reaches the
    /// position the head may have moved, and the walk reads it again. It
    /// changes no answer.
    #[inline(always)]
    pub(crate) fn warm_head(&self, span: &[u8], pos: usize) {
        if pos + 4 <= span.len() {
            let word = u32::from_le_bytes(span[pos..pos + 4].try_into().unwrap());
            let bucket = (word.wrapping_mul(TREE_WORD_SCATTER) >> self.bucket_shift) as usize;
            std::hint::black_box(self.newest[bucket].load(Ordering::Relaxed));
        }
    }
    /// ...and, nearer the walk, the root that head names: its pair of
    /// slots and its first bytes. See [`Self::warm_head`].
    #[inline(always)]
    pub(crate) fn warm_root(&self, span: &[u8], pos: usize) {
        if pos + 4 <= span.len() {
            let word = u32::from_le_bytes(span[pos..pos + 4].try_into().unwrap());
            let bucket = (word.wrapping_mul(TREE_WORD_SCATTER) >> self.bucket_shift) as usize;
            let root = self.newest[bucket].load(Ordering::Relaxed);
            if root != TREE_NO_MATCH {
                let older = (root - 1) as usize;
                std::hint::black_box(
                    self.subtrees[2 * (older & self.cyclic_mask)].load(Ordering::Relaxed),
                );
                // A root a slide dropped is before the span.
                if let Some(byte) = span.get(older.wrapping_sub(self.origin)) {
                    std::hint::black_box(*byte);
                }
            }
        }
    }
    /// One position: insert it into its bucket's tree, and record up to
    /// `keep` of the matches found on the way into `found`, returning how
    /// many were written.
    ///
    /// The descent visits its bucket's positions in increasing DISTANCE
    /// (a node's descendants are older than it is) and records a candidate
    /// only when it agrees for strictly more bytes than any before it, so
    /// what it writes is the frontier the cost-based parse consumes:
    /// increasing length, and the nearest distance reaching each. `keep`
    /// of 1 keeps only the longest, which is the lazy parser's single
    /// hint and what this returned before the parse consumed lists.
    #[inline(always)]
    pub(crate) fn advance(
        &self,
        span: &[u8],
        pos: usize,
        limit: usize,
        found: &mut [u32; TREE_MAX_CANDIDATE_SLOTS],
        keep: usize,
    ) -> usize {
        self.advance_with::<false>(span, pos, limit, found, keep)
    }
    /// [`Self::advance`], and with `SKIP` the descent leaves out every son
    /// store that would write back the value its slot already holds.
    ///
    /// **Which stores those are.** A step stores the node it leaves into
    /// the slot at its own end of the split, then moves that end to the
    /// node's child slot and loads the next node FROM it. When the next
    /// step goes the same way, the slot it stores into is the one it has
    /// just loaded from, and the value it would store is the value it
    /// loaded. Likewise an empty subtree reached by a step is already
    /// empty in the slot that step loaded it from. Skipping those stores
    /// leaves every slot holding exactly what it held, so the tree, and
    /// every answer read from it, is the same; `tests/tree_walk_answers.rs`
    /// and this file's tests pin it. They are 40 to 52 percent of the
    /// walk's son stores (the 28 Sep census).
    ///
    /// **Why only where the CPUs span several L3s.** A 64-byte line of
    /// `subtrees` holds eight consecutive positions, whose buckets belong to
    /// different walkers, so a store is usually a line taken from another
    /// core. Across L3 caches that transfer is the walk's largest cost and
    /// a store not made is worth more than the test that avoids it; within
    /// one L3 it is not, and the test costs more than it saves. Counted,
    /// not timed: on an EPYC 9R14, two L3s, 16 walkers, code32 -m5 2.66 to
    /// 2.39 s and text64 -m5 2.76 to 2.59 s; on one L3, and on the one-CCD
    /// Ryzen 7 7700, level to 2 percent slower.
    ///
    /// **And on Apple silicon, from twelve walkers up.** Its cores sit in
    /// clusters of a few, each cluster under an L2 of its own, and no L3
    /// joins them, so a line of `subtrees` taken from a walker in another
    /// cluster crosses caches as it does between two L3s; a few walkers
    /// mostly share a cluster and there the test is the dearer. Timed 1
    /// Oct 2026 on an M3 Ultra (K=5 and K=3, level 5, the same bytes in
    /// every arm, one binary): with the skip, twelve walkers read text64
    /// 1.05x, code32 1.02x and a solid tree of small files level; 24
    /// walkers text64 1.60x where they read 1.46x without it, and code32
    /// 1.03x where they read 0.93x; but four walkers read 0.97x to 0.98x
    /// on all three and eight 0.98x on two of them. An M1 Ultra at twelve
    /// had read 1.04x and 1.05x. It costs 3 to 8 percent more
    /// instructions wherever it is on. [`skips_same_stores`] is the rule.
    ///
    /// **Always inlined** into the walks that call it, a position at a
    /// time. Left to `#[inline]`, whether it was depended on the crate's
    /// codegen partition, and where it stayed out of line the call cost 6
    /// to 11 percent of all instructions at level 5 (non-solid text64 and
    /// code32
    /// `-m5 -mt1`: x86-64 at the `pinned` profile, aarch64 at both).
    #[inline(always)]
    pub(crate) fn advance_with<const SKIP: bool>(
        &self,
        span: &[u8],
        pos: usize,
        limit: usize,
        found: &mut [u32; TREE_MAX_CANDIDATE_SLOTS],
        keep: usize,
    ) -> usize {
        // A position with fewer than four bytes ahead of it can neither be
        // matched against nor start a match, and is not indexed - the same
        // rule the ring index applies.
        debug_assert!(limit <= span.len());
        let nice_length = TREE_NICE_LENGTH;
        let len_limit = nice_length.min(limit - pos);
        if len_limit < 4 {
            return 0;
        }
        let word = u32::from_le_bytes(span[pos..pos + 4].try_into().unwrap());
        let scattered = word.wrapping_mul(TREE_WORD_SCATTER);
        let bucket = (scattered >> self.bucket_shift) as usize;
        #[cfg(feature = "tree-walk-census")]
        {
            census::load(&self.newest[bucket], census::Kind::Head);
            census::store(&self.newest[bucket], census::Kind::Head);
            census::with(|t| t.positions += 1);
        }
        // The run position, which is what the slots hold and what picks
        // this position's slot pair; `pos` is where its bytes are.
        let run = pos + self.origin;
        let mut node = self.newest[bucket].load(Ordering::Relaxed);
        self.newest[bucket].store((run + 1) as u32, Ordering::Relaxed);
        let cyclic = run & self.cyclic_mask;
        // The oldest run position inside the window, and where the span
        // starts in run positions. The descent carries these two and not
        // this position's own: a candidate older than `floor` is out of
        // the window, and one at `floor` or newer is at `older - origin`
        // in the span. Two values as the buffer's positions carried two
        // (the position and the window), so the loop holds no more than
        // it did before positions counted from the run.
        let floor = run.saturating_sub(self.window);
        let origin = self.origin;
        // The two ends of the split this descent performs: `low` collects
        // the positions whose suffix sorts below this one, `high` those
        // above. Each holds the slot to write the next such position into.
        let mut low = 2 * cyclic;
        let mut high = 2 * cyclic + 1;
        let mut low_len = 0usize;
        let mut high_len = 0usize;
        let mut best_length = 0usize;
        let mut kept = 0usize;
        let mut cut = self.cut;
        // Which way the last step went, for `SKIP`: 0 none yet, 1 low, 2
        // high.
        let mut way = 0u8;
        // Which way the last step went, for the census's same-value count:
        // 0 none yet, 1 low, 2 high.
        #[cfg(feature = "tree-walk-census")]
        let mut last = 0u8;
        #[cfg(feature = "tree-walk-census")]
        let son_store = |slot: usize, same: bool| {
            census::store(&self.subtrees[slot], census::Kind::Son);
            census::with(|t| {
                t.son_stores += 1;
                t.son_same += u64::from(same);
            });
        };
        loop {
            if node == TREE_NO_MATCH || cut == 0 {
                #[cfg(feature = "tree-walk-census")]
                {
                    son_store(low, last == 1 && node == TREE_NO_MATCH);
                    son_store(high, last == 2 && node == TREE_NO_MATCH);
                    census::with(|t| {
                        if node == TREE_NO_MATCH {
                            t.exit_empty += 1;
                        } else {
                            t.exit_cut += 1;
                        }
                    });
                }
                let empty = SKIP && node == TREE_NO_MATCH;
                if !(empty && way == 1) {
                    self.subtrees[low].store(TREE_NO_MATCH, Ordering::Relaxed);
                }
                if !(empty && way == 2) {
                    self.subtrees[high].store(TREE_NO_MATCH, Ordering::Relaxed);
                }
                break;
            }
            let older = (node - 1) as usize;
            if older < floor {
                // Out of the window, and so is everything below it: a
                // position a slide dropped among them.
                #[cfg(feature = "tree-walk-census")]
                {
                    son_store(low, false);
                    son_store(high, false);
                    census::with(|t| t.exit_window += 1);
                }
                self.subtrees[low].store(TREE_NO_MATCH, Ordering::Relaxed);
                self.subtrees[high].store(TREE_NO_MATCH, Ordering::Relaxed);
                break;
            }
            cut -= 1;
            // Inside the window, so inside the span.
            let candidate = older - origin;
            let node_slots = 2 * (older & self.cyclic_mask);
            // Both branches already agree with this position for their own
            // count of bytes, so the compare starts at the smaller.
            let mut length = low_len.min(high_len);
            let matched = common_prefix_inlined(span, candidate, pos, length, len_limit);
            #[cfg(feature = "tree-walk-census")]
            census::with(|t| {
                t.visits += 1;
                t.compares += 1;
                t.compared_bytes += (matched - length) as u64;
                t.compared_words += ((matched - length) / 8 + 1) as u64;
            });
            if matched > length {
                length = matched;
                if length > best_length {
                    best_length = length;
                    // A match shorter than four bytes is not emittable and
                    // is not reported, but it still routes the descent.
                    if length >= 4 {
                        // The first `keep - 1` recorded are the nearest,
                        // and the last slot always holds the newest and so
                        // the longest: a descent with more pairs than
                        // slots gives up the middle of its frontier, never
                        // an end of it.
                        let distance = pos - candidate;
                        if kept < keep {
                            found[kept] = distance as u32;
                            kept += 1;
                        } else {
                            found[keep - 1] = distance as u32;
                        }
                    }
                }
                if length == len_limit {
                    // Agreement to the comparison cap: this position takes
                    // the candidate's place in the tree wholesale, which is
                    // what keeps a long run of identical bytes from
                    // degenerating the bucket into a list.
                    #[cfg(feature = "tree-walk-census")]
                    {
                        son_store(low, false);
                        son_store(high, false);
                        census::load(&self.subtrees[node_slots], census::Kind::Son);
                        census::with(|t| t.exit_nice += 1);
                    }
                    self.subtrees[low].store(
                        self.subtrees[node_slots].load(Ordering::Relaxed),
                        Ordering::Relaxed,
                    );
                    self.subtrees[high].store(
                        self.subtrees[node_slots + 1].load(Ordering::Relaxed),
                        Ordering::Relaxed,
                    );
                    break;
                }
            }
            if span[candidate + length] < span[pos + length] {
                #[cfg(feature = "tree-walk-census")]
                {
                    son_store(low, last == 1);
                    last = 1;
                    census::load(&self.subtrees[node_slots + 1], census::Kind::Son);
                }
                if !(SKIP && way == 1) {
                    self.subtrees[low].store(node, Ordering::Relaxed);
                }
                way = 1;
                low = node_slots + 1;
                node = self.subtrees[low].load(Ordering::Relaxed);
                low_len = length;
            } else {
                #[cfg(feature = "tree-walk-census")]
                {
                    son_store(high, last == 2);
                    last = 2;
                    census::load(&self.subtrees[node_slots], census::Kind::Son);
                }
                if !(SKIP && way == 2) {
                    self.subtrees[high].store(node, Ordering::Relaxed);
                }
                way = 2;
                high = node_slots;
                node = self.subtrees[high].load(Ordering::Relaxed);
                high_len = length;
            }
        }
        kept
    }
}
#[cfg(feature = "tree-walk-census")]
impl Drop for BucketTrees {
    fn drop(&mut self) {
        census::report();
    }
}
/// The fewest walkers a walk on Apple silicon takes the same-value store
/// skip with ([`BucketTrees::advance_with`] has the rows).
#[cfg(feature = "parallel")]
pub(crate) const SKIP_WALKERS_LEAST: usize = 12;

/// Whether a parallel walk of `walkers` walkers skips its same-value son
/// stores ([`BucketTrees::advance_with`]): on Apple silicon from
/// [`SKIP_WALKERS_LEAST`] walkers up, elsewhere where [`cpus_span_l3s`]
/// says the process's CPUs span several L3 caches. It moves no byte
/// either way. A build with the `reach-knob` feature takes
/// `RARKIT_TREE_STORE_SKIP=1` or `=0` in its place, read once, so both
/// arms are timed inside one binary; no shipped build reads it.
#[cfg(feature = "parallel")]
pub(crate) fn skips_same_stores(walkers: usize) -> bool {
    #[cfg(feature = "reach-knob")]
    {
        static FORCED: std::sync::OnceLock<Option<bool>> = std::sync::OnceLock::new();
        let forced = *FORCED.get_or_init(|| {
            std::env::var("RARKIT_TREE_STORE_SKIP")
                .ok()
                .map(|v| v == "1")
        });
        if let Some(on) = forced {
            return on;
        }
    }
    (cfg!(all(target_os = "macos", target_arch = "aarch64")) && walkers >= SKIP_WALKERS_LEAST)
        || cpus_span_l3s()
}

/// Whether the CPUs this process may run on sit under more than one L3
/// cache, read once per process. Linux reads it from `/proc/self/status`
/// and `/sys`, without `unsafe`; anything it cannot read, and every other
/// system, answers `false`, which is the walk as it was.
#[cfg(feature = "parallel")]
pub(crate) fn cpus_span_l3s() -> bool {
    static SPANS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SPANS.get_or_init(|| {
        #[cfg(target_os = "linux")]
        {
            allowed_cpus_span_l3s().unwrap_or(false)
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    })
}

/// [`cpus_span_l3s`]'s Linux reading: the `Cpus_allowed_list` of this
/// process, and for each CPU in it the set of CPUs sharing its level 3
/// cache. `None` where either cannot be read or parsed.
#[cfg(all(feature = "parallel", target_os = "linux"))]
fn allowed_cpus_span_l3s() -> Option<bool> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let list = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))?
        .trim();
    let mut first: Option<String> = None;
    for part in list.split(',') {
        let (from, to) = match part.split_once('-') {
            Some((from, to)) => (
                from.trim().parse::<usize>().ok()?,
                to.trim().parse::<usize>().ok()?,
            ),
            None => {
                let cpu = part.trim().parse::<usize>().ok()?;
                (cpu, cpu)
            }
        };
        for cpu in from..=to {
            let dir = format!("/sys/devices/system/cpu/cpu{cpu}/cache/index3");
            if std::fs::read_to_string(format!("{dir}/level")).ok()?.trim() != "3" {
                return None;
            }
            let shared = std::fs::read_to_string(format!("{dir}/shared_cpu_list")).ok()?;
            let shared = shared.trim();
            match &first {
                None => first = Some(shared.to_owned()),
                Some(seen) if seen != shared => return Some(true),
                Some(_) => {}
            }
        }
    }
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `len` bytes that reach every exit of a descent, by turns: long
    /// records that agree for 5,000 bytes and then differ, text of a
    /// vocabulary so small that every bucket is deep, a run of one byte,
    /// and noise.
    fn input(len: usize) -> Vec<u8> {
        let record = rarkit_testdata::chatter(1, 5_000);
        let mut out = Vec::with_capacity(len + (128 << 10));
        let mut turn = 0u64;
        while out.len() < len {
            turn += 1;
            match turn % 4 {
                0 => {
                    for copy in 0..6 {
                        out.extend_from_slice(&record);
                        out.extend_from_slice(&rarkit_testdata::scramble(turn * 8 + copy, 96));
                    }
                }
                1 => out.extend_from_slice(&rarkit_testdata::chatter_of(turn, 12, 120_000)),
                2 => out.resize(out.len() + 20_000, 0x5a),
                _ => out.extend_from_slice(&rarkit_testdata::scramble(turn, 50_000)),
            }
        }
        out.truncate(len);
        out
    }

    /// The skipping descent leaves the tree exactly as the plain one does
    /// and finds exactly the same candidates at every position, with a
    /// window shorter than the input so some descents stop at nodes that
    /// have fallen out of it.
    #[test]
    fn skipping_same_value_stores_moves_no_answer_and_no_slot() {
        let span = input(3 << 20);
        for keep in [1, TREE_CANDIDATE_SLOTS] {
            let plain = BucketTrees::new(1 << 20);
            let skipping = BucketTrees::new(1 << 20);
            for pos in 0..span.len() {
                let mut a = [TREE_NO_MATCH; TREE_MAX_CANDIDATE_SLOTS];
                let mut b = [TREE_NO_MATCH; TREE_MAX_CANDIDATE_SLOTS];
                let kept_a = plain.advance_with::<false>(&span, pos, span.len(), &mut a, keep);
                let kept_b = skipping.advance_with::<true>(&span, pos, span.len(), &mut b, keep);
                assert_eq!(
                    (kept_a, &a[..kept_a]),
                    (kept_b, &b[..kept_b]),
                    "position {pos}"
                );
            }
            let slots = |t: &BucketTrees| -> Vec<u32> {
                t.subtrees
                    .iter()
                    .chain(&t.newest)
                    .map(|v| v.load(Ordering::Relaxed))
                    .collect()
            };
            assert!(slots(&plain) == slots(&skipping), "the trees differ");
        }
    }

    /// The same through the PARALLEL walk's own form: each chunk dealt
    /// into bins by bucket and walked bin after bin
    /// ([`BucketTrees::walk_bin`]), with the skip and without, leaves
    /// the same hints and the same tree. Several ranges, so a bin's
    /// positions compare up to different ends.
    #[cfg(feature = "parallel")]
    #[test]
    fn the_binned_walk_skipping_same_value_stores_moves_no_hint_and_no_slot() {
        let span = input(3 << 20);
        let ends = [1_000_003usize, 1_000_006, 2_222_222, span.len()];
        let stride = TREE_CANDIDATE_SLOTS;
        let bins = 40 * TREE_BINS_PER_WALKER;
        let walked = |skip: bool| {
            let tree = BucketTrees::new(1 << 20);
            let out = empty_slots(span.len() * stride);
            let mut deal = Deal::default();
            for start in (0..span.len()).step_by(TREE_SKEW_BOUND) {
                let chunk = start..(start + TREE_SKEW_BOUND).min(span.len());
                tree.share_chunk(&span, chunk, bins, &mut deal);
                for bin in 0..bins {
                    if skip {
                        tree.walk_bin::<true>(&span, deal.bin(bin), &ends, 0, Some(&out), stride);
                    } else {
                        tree.walk_bin::<false>(&span, deal.bin(bin), &ends, 0, Some(&out), stride);
                    }
                }
            }
            out.iter()
                .chain(&tree.subtrees)
                .chain(&tree.newest)
                .map(|v| v.load(Ordering::Relaxed))
                .collect::<Vec<u32>>()
        };
        let plain = walked(false);
        assert!(
            plain[..span.len() * stride]
                .iter()
                .filter(|&&distance| distance != TREE_NO_MATCH)
                .count()
                > 100_000,
            "the walk found almost nothing, so the comparison would prove nothing"
        );
        assert!(plain == walked(true), "the skip moved a hint or a slot");
    }

    /// A span that drops its oldest bytes as it grows, keeping more than
    /// the window, gives every position the answers the whole run gives
    /// in one span ([`BucketTrees::slide`]); and a rebase after each
    /// slide moves none of them either ([`BucketTrees::rebase`]).
    /// Walked in chunks, each position compared up to its chunk's end, in
    /// both arms.
    #[test]
    fn a_slide_and_a_rebase_move_no_answer() {
        let run = input(3 << 20);
        let chunk = 64 << 10;
        let keep = 1 << 20;
        let cap = keep + (512 << 10);
        let whole = BucketTrees::new(1 << 20);
        let mut arms = [BucketTrees::new(1 << 20), BucketTrees::new(1 << 20)];
        assert!(whole.window() < keep, "the slide keeps the window");
        let mut span: Vec<u8> = Vec::new();
        let mut dropped = 0;
        let mut rebased = 0;
        for start in (0..run.len()).step_by(chunk) {
            let end = (start + chunk).min(run.len());
            if span.len() + (end - start) > cap {
                let stale = span.len() - keep;
                for (index, arm) in arms.iter_mut().enumerate() {
                    // `advance` alone does not move it; the ranged walk does.
                    arm.next = span.len();
                    arm.slide(stale, cap);
                    if index == 1 {
                        let before = arm.origin;
                        arm.rebase();
                        rebased += usize::from(arm.origin != before);
                    }
                }
                span.drain(..stale);
                dropped += stale;
            }
            span.extend_from_slice(&run[start..end]);
            for pos in start..end {
                let mut a = [TREE_NO_MATCH; TREE_MAX_CANDIDATE_SLOTS];
                let kept = whole.advance(&run, pos, end, &mut a, TREE_CANDIDATE_SLOTS);
                for arm in &arms {
                    let mut b = [TREE_NO_MATCH; TREE_MAX_CANDIDATE_SLOTS];
                    let at = pos - dropped;
                    let kept_b =
                        arm.advance(&span, at, end - dropped, &mut b, TREE_CANDIDATE_SLOTS);
                    assert_eq!(
                        (kept, &a[..kept]),
                        (kept_b, &b[..kept_b]),
                        "position {pos}, origin {}",
                        arm.origin
                    );
                }
            }
        }
        assert!(
            dropped > 0 && rebased > 0,
            "no slide or no rebase was walked"
        );
    }
}
