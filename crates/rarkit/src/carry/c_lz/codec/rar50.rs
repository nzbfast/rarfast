//! Carried from the predecessor's `codec/rar50.rs` at an earlier revision: items ours from birth
//! per the provenance census (and clean-room outputs, clean by provenance).
//!
//! EIGHTY-SIX UNREFERENCED ITEMS, AND KEPT ON PURPOSE. Every carried item
//! in this file that nothing calls belongs to a capability a specification
//! names as carried, to be used rather than rewritten:
//!
//! * SPEC-H3 section 5: the hash chain match index (`MATCH_INDEX_*`,
//!   `MatchIndex`, `MatchPosition`, `LONG_*`, `long_anchor`, `long_hash`,
//!   `index_geometry*`, `index_keep`, `insert_match_range`,
//!   `compact_match_index_fits`, `MemberAnchors`, `MemberWindow`,
//!   `LongSeed`, `member_base_of`, `member_block_history`); the price model
//!   (`PriceModel`, `LiteralPrices`, `TokenPrices`, `LengthSlots`,
//!   `DistanceArm`, `FAR_DISTANCE_SURCHARGE_*`, `far_distance_surcharge`,
//!   `price_from_frequencies`, `P_ZERO_U32`, `observe_literals`); the
//!   optimal parse's window and budgets (`TREE_WALKER_CAP`,
//!   `TREE_HINT_BUDGET_BYTES`, `tree_walkers`, `LITERAL_SKIP_*`,
//!   `TOKENIZER_SHORT_HORIZON`); and the parallel encode wave policy
//!   (`ENCODE_WAVE_*`, `encode_block_wave_width_*`).
//! * SPEC-H2 section 1.3: the flat output path (`FLAT_SLACK_*`,
//!   `flat_slack_with`), the primary lookup table's entry layout
//!   (`HUFF_LUT_LENGTH_MASK`), the streaming window's caps
//!   (`STREAM_INITIAL_WINDOW_CAP`, `STREAMED_WINDOWS_IN_FLIGHT`) and the
//!   block tape's operation encoding (`LITS`, `MATCH`, `REP`, `REP_LAST`,
//!   `FILTER`, `EncoderTable`).
//!
//! That encoder work is not finished: it either wires these or deletes
//! them. (Pruned carried tree, 19 Sep 2026.)
#![allow(dead_code)]

use crate::carry::c_lz::codec::filters;
use crate::carry::h_ours::codec::address_filters;
use crate::carry::h_ours::codec::address_filters::Direction;
use std::io::Read;
use std::ops::Range;
#[cfg(feature = "ratio-lab")]
macro_rules! probe_stat {
    ($stat:ident) => {
        probe_stats::bump(probe_stats::Stat::$stat, 1)
    };
    ($stat:ident, $by:expr) => {
        probe_stats::bump(probe_stats::Stat::$stat, $by as u64)
    };
}
#[cfg(not(feature = "ratio-lab"))]
macro_rules! probe_stat {
    ($stat:ident) => {};
    ($stat:ident, $by:expr) => {
        let _ = $by;
    };
}
// Up-front size ceiling for the streaming ring. The match window reaches back
// the archive's full declared dictionary, but a large declared dictionary must
// not force a large allocation from a tiny archive, so the ring starts no
// bigger than this and grows lazily (see `StreamingOutput::reserve`) toward the
// full dictionary only as decoded output actually reaches further back.
pub(crate) const STREAM_INITIAL_WINDOW_CAP: usize = 64 * 1024 * 1024;
// Streaming filter support: a filter may hold back at most this many bytes
// from the sink while its range materializes (2x unrar's 4MB legal maximum;
// genuine WinRAR filters are <= MAX_FILTER_BLOCK_LENGTH). Longer or
// overlapping-but-not-identical filters fall back via FilteredMember.
pub(crate) const STREAM_FILTER_HOLD_LIMIT: usize = 8 * 1024 * 1024;
// local change, 5 Sep 2026 - flat ring match index; see VENDORING.md.
// Bucket count is sized to the indexed span (about one bucket per `depth`
// positions) inside these bounds; the ring depth follows the candidate
// budget inside its own, so `EncodeOptions::new(n)` reaches exactly its n
// newest same-hash positions for n up to MATCH_INDEX_MAX_DEPTH.
pub(crate) const MATCH_INDEX_MIN_BUCKETS: usize = 1 << 10;
pub(crate) const MATCH_INDEX_MAX_BUCKETS: usize = 1 << 16;
pub(crate) const MATCH_INDEX_MIN_DEPTH: usize = 4;
/// At most this many tag bits per ring slot (see `MatchIndex::tag_bits`).
pub(crate) const MATCH_TAG_BITS_MAX: u32 = 8;
/// The long-match table (see `MatchIndex::long`): one position per entry,
/// keyed by a hash of the 32 bytes at an ANCHOR position, an anchor being
/// a position whose four-byte hash has these low bits clear (one in 32).
pub(crate) const LONG_INDEX_MIN_ENTRIES: usize = 1 << 10;
pub(crate) const LONG_INDEX_MAX_ENTRIES: usize = 1 << 20;
pub(crate) const LONG_ANCHOR_MASK: u32 = 31;
pub(crate) const LONG_ANCHOR_SPACING: usize = 32;
/// A long-table candidate must match at least this far to be considered;
/// shorter matches are the ring's business.
pub(crate) const LONG_MATCH_MIN_LENGTH: usize = 32;
pub(crate) const LONG_HASH_BYTES: usize = 32;
pub(crate) const MATCH_INDEX_MAX_DEPTH: usize = 64;
// A match at least this long ends the candidate walk: the remaining
// candidates can only trade a few bits of distance against the cost of
// visiting them (7-Zip's `nice_len`, zstd's `targetLength`).
pub(crate) const MATCH_NICE_LENGTH: usize = 64;
// local change, 5 Sep 2026 - literal-run acceleration; see VENDORING.md.
// Once a run of literals has gone LITERAL_SKIP_STRENGTH-scaled bytes without a
// match, the tokenizer probes every 2nd, then 3rd, ... position instead of
// every one (the LZ4 / zstd fast-level rule), capped at LITERAL_SKIP_MAX.
// Every position is still INSERTED into the index, so a later match can still
// point back into a skipped run; only the probe at the skipped position is
// saved. Compressible data almost never runs 32 literals without a match, so
// this does not fire there; incompressible data fires it at once and stops
// paying the candidate walk on every byte.
pub(crate) const LITERAL_SKIP_STRENGTH: u32 = 5;
pub(crate) const LITERAL_SKIP_MAX: usize = 16;
// local change, 5 Sep 2026 - the blocks of one member are encoded in
// parallel; see VENDORING.md.
//
// A member longer than one compressed block is cut into 4 MiB blocks whose
// tokenizers depend on RAW INPUT only: block k sees the `max_match_distance`
// bytes before it as history, and those bytes are the member's own input (or
// the incoming solid history) - never a previous block's OUTPUT. So the blocks
// are independent, and with the `parallel` feature a bounded pool tokenizes
// and entropy-codes them concurrently, then concatenates them in order. The output is
// byte-identical to the serial walk because each block is handed exactly the
// history the serial walk carried into it (`member_block_history`).
//
// The pool is bounded by memory as well as by cores: every block in flight
// holds its own bounded match index and token vector. Large-dictionary blocks
// borrow ordinary member history/input; only an incoming solid-history seam
// needs a buffer. Smaller dictionaries keep the original copy path.
// The original estimate is retained whenever it is lower. For wide
// dictionaries, account for the bounded index instead of charging four
// index bytes for every byte of history. The shared 1 GiB worker budget stays
// unchanged. Wide dictionaries can use four workers without incoming history;
// an owned solid-history seam still narrows the pool for very wide dictionaries.
#[cfg(feature = "parallel")]
// The budget scales with the box: 128 MiB per pool thread, never under
// 1 GiB. A flat 1 GiB held a 32 MiB-dictionary encode to FOUR workers on a
// 32-core desktop (measured 5 Sep 2026: 26.5 s wall for 102 CPU-seconds on
// the mixed 1 GiB corpus, against rar's 14.5 s for 276), because the
// per-block estimate below is what the workers actually hold and 1 GiB
// buys few of them.
pub(crate) const ENCODE_WAVE_MEMORY_BUDGET_PER_THREAD: usize = 128 << 20;
#[cfg(feature = "parallel")]
pub(crate) const ENCODE_WAVE_MEMORY_BUDGET_MIN: usize = 1 << 30;
// Both callers left are `cfg(all(test, feature = "parallel"))` -
// `encode_block_wave_width` above and
// one assertion in the wave tests - so the non-test build sees no use.
// Kept as the named two-argument form the tests read against; the
// production path calls `encode_block_wave_width_for_budget` directly.
#[allow(dead_code)]
pub(crate) fn encode_block_wave_width_for_history(
    dictionary: usize,
    incoming_history: bool,
) -> usize {
    encode_block_wave_width_for_budget(dictionary, incoming_history, None)
}
/// [`encode_block_wave_width_for_history`] against an explicit working-memory
/// allowance: `None` keeps the host-sized default below.
/// (local change, 8 Sep 2026; see VENDORING.md.)
pub(crate) fn encode_block_wave_width_for_budget(
    dictionary: usize,
    incoming_history: bool,
    working_memory: Option<usize>,
) -> usize {
    #[cfg(feature = "parallel")]
    {
        // What one block in flight holds, measured rather than feared: the
        // ring index (16 MiB at the default depth), the literal price prefix
        // (16 MiB), the token vector (up to 32 MiB), the block's output and
        // its input copy (4 MiB each) - 72 MiB - plus a copy of the history
        // when the block does not borrow it: below 32 MiB dictionaries the
        // tokenizer copies history and input into one span, and at any size
        // an incoming solid history is copied at the seam.
        let copied_history = if dictionary < (32 << 20) || incoming_history {
            dictionary
        } else {
            0
        };
        let per_block = (72usize << 20).saturating_add(copied_history);
        let threads = rayon::current_num_threads();
        // A caller-set allowance is not floored at the default's gibibyte,
        // which is larger than the whole budget of the targets that set
        // this; but it is capped by the default, because an allowance is a
        // limit and never a request for a wider wave than the host would
        // run. Half of the allowance goes here and a quarter to the hints.
        let host = (ENCODE_WAVE_MEMORY_BUDGET_PER_THREAD.saturating_mul(threads))
            .max(ENCODE_WAVE_MEMORY_BUDGET_MIN);
        let budget = working_memory.map_or(host, |bytes| (bytes / 2).min(host));
        let by_memory = (budget / per_block).max(1);
        threads.clamp(1, by_memory)
    }
    #[cfg(not(feature = "parallel"))]
    {
        let _ = (dictionary, incoming_history, working_memory);
        1
    }
}
/// The history the block starting at `start` sees: the last `dictionary`
/// bytes before it, drawn from the member's incoming history and then from
/// `data` itself - exactly what the serial block walk carried into it.
pub(crate) fn member_block_history<'a>(
    data: &'a [u8],
    history_tail: &'a [u8],
    start: usize,
    dictionary: usize,
) -> std::borrow::Cow<'a, [u8]> {
    if start >= dictionary {
        std::borrow::Cow::Borrowed(&data[start - dictionary..start])
    } else if start == 0 {
        std::borrow::Cow::Borrowed(history_tail)
    } else {
        let from_history = &history_tail[history_tail.len().saturating_sub(dictionary - start)..];
        let mut combined = Vec::with_capacity(from_history.len() + start);
        combined.extend_from_slice(from_history);
        combined.extend_from_slice(&data[..start]);
        std::borrow::Cow::Owned(combined)
    }
}
/// The tokenizer horizon the SHORT arm of the per-region choice encodes
/// at: a quarter of the 4 MiB region, which is the arm the ratio lab
/// measured as `opt-horizon-balanced`.
/// Narrower arms (256 KiB, and the seven-way power-of-two screen down to
/// 64 KiB) buy a further 0.03 to 0.07% for two to five times this arm's
/// CPU, which is the wrong end of the trade for a mode anyone runs.
/// (local change, 7 Sep 2026; see VENDORING.md.)
pub(crate) const TOKENIZER_SHORT_HORIZON: usize = 1 << 20;
/// The long-table ANCHORS of a member's blocks (see `MatchIndex::long`),
/// computed once per block by the first worker that needs them and shared
/// read-only after. Every block's tokenizer used to rescan its whole history
/// for anchors - up to 32 MiB per 4 MiB block, eight times over the member,
/// about 9% of a large-dictionary encode - where the anchors of a block are a
/// property of its bytes alone. Each list holds offsets within the block
/// (ascending), and the pool's drain loop releases lists no block in flight
/// can still need. (local change, 6 Sep 2026; see VENDORING.md.)
pub(crate) struct MemberAnchors<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) lists: Vec<std::sync::Mutex<Option<std::sync::Arc<Vec<u32>>>>>,
}
/// Where a block's history sits in the member, for `MatchIndex::seed_history`
/// to take its long-table seed from [`MemberAnchors`] instead of a scan.
#[derive(Clone, Copy)]
pub(crate) struct LongSeed<'a> {
    pub(crate) anchors: &'a MemberAnchors<'a>,
    /// The block's first position in the member.
    pub(crate) range_start: usize,
}
impl<'a> MemberAnchors<'a> {
    /// Anchors in `range` with the 32 hashed bytes inside the member, as
    /// offsets from `range.start`, ascending - the same positions a scan
    /// of the member would anchor.
    pub(crate) fn compute(data: &[u8], range: Range<usize>) -> Vec<u32> {
        let mut out = Vec::new();
        let end = range
            .end
            .min(data.len().saturating_sub(LONG_HASH_BYTES - 1));
        let mut pos = range.start;
        while pos + 8 <= data.len() && pos + 4 <= end {
            let words = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            for (i, word) in [
                words as u32,
                (words >> 8) as u32,
                (words >> 16) as u32,
                (words >> 24) as u32,
            ]
            .into_iter()
            .enumerate()
            {
                if long_anchor(word) {
                    out.push((pos + i - range.start) as u32);
                }
            }
            pos += 4;
        }
        while pos < end {
            let word = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            if long_anchor(word) {
                out.push((pos - range.start) as u32);
            }
            pos += 1;
        }
        out
    }
    /// Drop the lists of every block below `block`: none in flight reads them.
    pub(crate) fn release_below(&self, block: usize) {
        for list in &self.lists[..block.min(self.lists.len())] {
            *list.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        }
    }
}
/// Which blocks of a member's span an encode covers: all of them, or the
/// blocks from `first_block` on, with the earlier ones standing in for the
/// member bytes before them (local change, 6 Sep 2026; see
/// VENDORING.md and [`encode_lz_member_window`]).
#[derive(Clone, Copy)]
pub(crate) struct MemberWindow {
    /// The first block to encode; the blocks before it are history.
    pub(crate) first_block: usize,
    /// Whether the span ends where the member does, so the span's last
    /// block carries the member's `is_last`.
    pub(crate) final_segment: bool,
}
/// How many windows of one member the streamed writer encodes at once: it
/// reads the next window while the one before it encodes, and one more
/// buffer is the window being filled. (local change, 15 Sep 2026;
/// see VENDORING.md.)
pub(crate) const STREAMED_WINDOWS_IN_FLIGHT: usize = 2;
/// How many walkers split the finder's ranges (local change,
/// 7 Sep 2026; see VENDORING.md).
///
/// The blocks behind the finder are idle while it runs, so the pool's
/// whole width is available - and taking it is the wrong trade. A tree
/// descent is a chain of dependent loads over a structure far larger than
/// the last-level cache, so walkers past a handful spend their time
/// stalled on memory rather than working, and the stall is charged as
/// user CPU. Measured on the 256 MiB slice at `-md32m`, on an idle
/// twenty-core Apple silicon desktop, same bytes at every width:
///
/// | walkers | wall s | user s |
/// |---|---:|---:|
/// | 1 | 73.2 | 102.8 |
/// | 4 | 29.9 | 112.3 |
/// | 8 | 25.2 | 155.0 |
/// | 12 | 20.4 | 174.2 |
/// | 20 | 17.5 | 211.2 |
///
/// Four is where the wall is most of the way down and the CPU has barely
/// moved.
#[cfg(feature = "parallel")]
pub(crate) const TREE_WALKER_CAP: usize = 4;
/// The most the finder's answers may hold for the blocks in flight at
/// once (local change, 7 Sep 2026; see VENDORING.md).
///
/// A wave's hints are four bytes per slot per position and the whole wave
/// is walked before any of its blocks encodes, so at a stride of
/// [`TREE_CANDIDATE_SLOTS`] the buffer is 64 MiB per block in flight -
/// and the pool's own width is chosen by core count, so on a wide box the
/// buffer would grow with the box rather than with the work. Measured on
/// the 256 MiB slice at `-md32m` on a twenty-core M1 Ultra, peak RSS by
/// stride: 2.26 GB at one slot, 2.61 at two, 2.99 at three, 3.49 at four,
/// 4.28 at six, 5.15 at eight. This holds the hints to half a gigabyte,
/// which is eight blocks at the shipped stride.
///
/// The wave width is a memory decision and nothing else - the same bytes
/// come out at any width (`the_hint_budget_narrows_a_wave_without_moving_
/// its_bytes` holds that), so narrowing here costs wall time on a wide
/// box and no ratio.
pub(crate) const TREE_HINT_BUDGET_BYTES: usize = 512 << 20;
pub(crate) fn tree_walkers() -> usize {
    #[cfg(feature = "parallel")]
    {
        rayon::current_num_threads().clamp(1, TREE_WALKER_CAP)
    }
    #[cfg(not(feature = "parallel"))]
    {
        1
    }
}
/// How much INPUT one set of Huffman tables covers. The tokenizer's work
/// item stays the 4 MiB block (one history seed, one pool task); its token
/// stream is then cut into entropy blocks of about this many input bytes,
/// each written as its own RAR 5 compressed block with fresh tables, so a
/// stretch of text and the already-compressed bytes after it are not priced
/// with one shared code. One table set per 4 MiB was the larger half of the
/// size gap to `rar` at equal dictionary: on the 1 GiB mixed corpus at a
/// 1 MiB dictionary 663.6 MB -> 587.1 MB at 256 KiB (rar 7.23: 590.1 MB),
/// 580.2 MB at 64 KiB; at 32 MiB 585.6 -> 527.4 MB (rar 468.9, the rest
/// being long-range matches the index does not reach). A table set costs a
/// few hundred bytes and the reader a table decode per block: extracting
/// the 32 MiB-dictionary archive took 0.39 s with one table per 4 MiB,
/// 0.38-0.40 s at 256 KiB and 0.48-0.50 s at 64 KiB, which is why the cut
/// is not finer. The rep-distance state carries across entropy
/// blocks exactly as the reader's does across every block of a file.
/// (local change, 6 Sep 2026; see VENDORING.md.)
pub(crate) const ENTROPY_BLOCK_BYTES: usize = 256 << 10;
/// ...and at least this many tokens per table: a stretch of 4 KiB matches
/// has 64 tokens per 256 KiB, and a table set for 64 symbols costs more
/// than it can save (the repeated-payload corpus grew 1.3% on tables
/// alone before this floor).
pub(crate) const ENTROPY_BLOCK_MIN_TOKENS: usize = 1024;
// Match positions are offsets into the combined history/input buffer. Keep
// full-width storage available for spans that do not fit in u32.
// (local change, 5 Sep 2026; see VENDORING.md.)
trait MatchPosition: Copy {
    /// Bits a slot holds - what is left above a position is the tag.
    const BITS: u32;
    fn from_position(pos: usize) -> Self;
    fn position(self) -> usize;
}
impl MatchPosition for usize {
    const BITS: u32 = usize::BITS;
    fn from_position(pos: usize) -> Self {
        pos
    }
    fn position(self) -> usize {
        self
    }
}
impl MatchPosition for u32 {
    const BITS: u32 = u32::BITS;
    fn from_position(pos: usize) -> Self {
        // Dispatch checked the whole indexed span before choosing u32.
        // Insertions only use positions within that span (a tagged slot
        // value keeps its tag inside the 32 bits, by `tag_bits`).
        debug_assert!(u32::try_from(pos).is_ok());
        pos as u32
    }
    fn position(self) -> usize {
        self as usize
    }
}
pub(crate) fn compact_match_index_fits(
    input_len: usize,
    history_len: usize,
    max_distance: usize,
) -> bool {
    input_len
        .checked_add(history_len.min(max_distance))
        .is_some_and(|len| u32::try_from(len).is_ok())
}
/// What the block's literals cost, byte by byte: the order-0 Huffman code
/// length of each byte value over the block's own input, prefix-summed so
/// the literal cost of any range is two loads. A match is worth taking only
/// when its estimated bits are fewer than the literals it replaces, and its
/// score is the bits it saves; the old rule (`16 * length - cost`) accepted
/// every match of four bytes or more, so on text, where a literal costs five
/// bits, a four-byte match at a new distance costing ~30 bits was taken over
/// ~20 bits of literals. The final table differs from this estimate (it
/// counts emitted literals only), but the estimate is the same one the
/// block's frequencies would give before any match is chosen.
/// (local change, 5 Sep 2026; see VENDORING.md.)
pub(crate) struct LiteralPrices {
    /// Offset of the block's input inside the combined history/input span.
    pub(crate) base: usize,
    pub(crate) prefix: Vec<u32>,
    /// The per-byte code lengths the prefix was summed from, which the
    /// cost-based parse starts its price model from (see
    /// [`TokenPrices::constant`]).
    pub(crate) byte_price: [u8; 256],
}
impl LiteralPrices {
    /// The literal cost, in bits, of `length` bytes at `pos` (combined
    /// coordinates; `pos` is at or past the block's start).
    #[inline]
    pub(crate) fn bits(&self, pos: usize, length: usize) -> usize {
        let start = pos - self.base;
        (self.prefix[start + length] - self.prefix[start]) as usize
    }
}
/// What a match farther back than a megabyte is charged on top of
/// [`estimated_match_cost`], in bits (local change, 7 Sep 2026;
/// see VENDORING.md).
///
/// The cost estimate spends one flat ten-bit constant on the two Huffman
/// symbols a match writes - the main symbol and the distance slot - and
/// counts the slot's extra bits exactly. That is close enough while every
/// match comes from a ring that reaches a few megabytes, and it stops
/// being close enough once the tree finder offers a match from anywhere
/// in a 32 MiB dictionary at nearly every position: the parser then takes
/// the LONGEST match on offer, which is usually the farthest, and pays
/// for it in distance bits. Measured on the first 256 MiB of the mixed
/// corpus at `-md32m` (7 Sep 2026): without the surcharge the encoder
/// emits 4.44 M matches eight or more MiB back and 27.30 bits a match,
/// where rar 7.23 emits 2.21 M and 25.1 bits - and it is 117,291,644
/// bytes against rar's 116,751,028. With it: 116,493,016, under rar's
/// own. The surcharge was swept: 4 bits 116,576,488, 6 bits
/// 116,493,016, 8 bits 116,517,992, 10 bits 116,564,428, 16 bits
/// 116,692,584.
///
/// It is a stand-in for prices read off the real tables. **It is the LAZY
/// walk's stand-in, and the cost-based parse is not what retires it** -
/// measured 7 Sep 2026 in the work that gave the parse its own candidate
/// list, with this constant set to zero: the `-mo` archive is 112,865,011
/// bytes either way, bit for bit, because the parse prices `MatchRun`s
/// that carry no score and never reaches `consider_match_candidate`,
/// while the LAZY level goes 115,617,428 to 116,416,233, +0.69%. What
/// retires it is real prices inside `estimated_match_cost`, whose flat
/// ten-bit constant for a match's two Huffman symbols is what it corrects
/// for. It is zero below a megabyte, so the writer's own default was
/// untouched by it while that default was 128 KiB; the 2 MiB default of
/// 8 Sep 2026 is above the threshold and does reach it. (local
/// change, 7 Sep 2026.)
pub(crate) const FAR_DISTANCE_SURCHARGE_BITS: usize = 6;
pub(crate) const FAR_DISTANCE_SURCHARGE_FROM: usize = 1 << 20;
#[inline]
pub(crate) fn far_distance_surcharge(distance: usize) -> usize {
    if distance > FAR_DISTANCE_SURCHARGE_FROM {
        FAR_DISTANCE_SURCHARGE_BITS
    } else {
        0
    }
}
// local change, 7 Sep 2026 - cost-based optimal parse; see
// VENDORING.md.
//
// `walk_tokens` is greedy with a one-position lazy re-probe: it takes the
// best-scoring token at each position and never reconsiders. A cost-based
// parse instead prices EVERY reachable token over a window of positions
// and keeps the cheapest total path, which is where LZMA's `GetOptimum`,
// 7-Zip's and zstd's `btultra` levels get their last few percent. RAR 5's
// token set is what makes the difference worth a dynamic program rather
// than a deeper greedy search: four repeat distances that ROTATE on use,
// a two-bit length-repeat token, and a length bonus that depends on the
// distance, so a match three bits dearer now can be eight bits cheaper two
// tokens later by leaving a repeat slot in place. Only a parse that
// carries the repeat state through the search sees that, so every node of
// the program carries its own [`EncoderMatchState`].
//
// Measured on 256 MiB of mixed text, fixed-width records and a replayed
// 32 MiB pool, at a 32 MiB dictionary: 118,507,983 bytes greedy against
// 115,238,274 here, which is 2.76% smaller and under what `rar 7.23`
// writes at either `-m3` (116,751,028) or `-m5` (116,003,986). It costs
// 3.7x the greedy walk's CPU on an idle 20-core box, because it probes
// every position where the greedy walk probes about one in ten, so it
// is the top of the level ladder and not a default.

/// How many input positions one dynamic-programming window decides at a
/// time. The window is solved exactly and then committed, so a longer one
/// is a better parse and a shorter one is less memory and less work thrown
/// away at a forced jump; 16 Ki positions is about 1.2 MB of nodes and puts
/// a window boundary every 16 KiB of input, where the boundary costs
/// nothing at all (the window is allowed to end on any node up to a full
/// match past its limit, so no match is ever cut by the boundary itself).
pub(crate) const OPTIMAL_WINDOW_POSITIONS: usize = 1 << 14;
/// A match at least this long is taken without pricing what else the
/// window could do with those bytes: the parse commits its path up to that
/// position, emits the match, and starts a fresh window after it (LZMA's
/// `numFastBytes` rule, which exists for exactly this reason). Without it
/// a repeated-payload shape prices 4,096 positions inside every 4,096-byte
/// match, and the parse costs many times what the shape can pay back.
/// Measured on the 256 MiB mixed slice at a 32 MiB dictionary (7 Sep
/// 2026, on the tree before the length-limited Huffman codes landed):
/// 64 gives 115,914,564 bytes for 98 user s, 512 gives 115,917,624 for
/// 105 - the shorter threshold is both smaller and cheaper, so a match
/// this long is not worth deliberating over. It is the same length the
/// candidate walk already stops at ([`MATCH_NICE_LENGTH`]).
pub(crate) const OPTIMAL_SUFFICIENT_LENGTH: usize = 64;
/// Per position, at most this many SHORTER lengths are priced beyond each
/// candidate's own full length. Cutting a match short to land on a cheaper
/// token pays near the bottom of the length ladder, so the budget is spent
/// from the shortest candidate upward and the full length of every
/// candidate is always priced.
pub(crate) const OPTIMAL_SHORT_LENGTH_BUDGET: usize = 64;
/// ...and per repeat distance, at most this many rungs from length two up.
/// A repeat is priced from every node, four of them, so its ladder is the
/// parse's most repeated inner loop; the rungs that pay are at the bottom,
/// where a two-byte repeat undercuts two literals.
pub(crate) const OPTIMAL_REPEAT_LENGTH_BUDGET: usize = 16;
/// Prices are in sixteenths of a bit. Huffman code lengths are whole bits,
/// but a token's price is a sum of several of them plus raw bits, and the
/// entropy price of a symbol is not an integer: sixteenths keep the
/// program's comparisons from collapsing into ties.
pub(crate) const PRICE_SHIFT: u32 = 4;
/// A symbol no table entry would reach costs the deepest code a RAR 5
/// table can hold. Nothing is priced free.
pub(crate) const PRICE_MAX: u16 = 15 << PRICE_SHIFT;
/// ...and nothing is priced below one bit, which is a Huffman code's floor.
pub(crate) const PRICE_MIN: u16 = 1 << PRICE_SHIFT;
/// How much input the FIRST price region waits for, against
/// [`ENTROPY_BLOCK_BYTES`] for every region after it. A region is priced
/// by the region before it, so the first one has nothing of its own and
/// runs on the constant model; a short first region gets real code
/// lengths in front of the parse sooner, and on a MEMBER SET that is the
/// difference between a member being parsed on real prices and never
/// leaving the constant model at all.
///
/// Measured 7 Sep 2026 (400 files of about 2.7 MB, and the first 256 MiB
/// of the mixed corpus), user CPU flat to noise across the column:
///
/// | first region | 400 files, 32 MiB | slice, 32 MiB | slice, 128 KiB |
/// |---|---|---|---|
/// | 256 KiB (none) | 492,385,336 | 114,684,633 | 152,021,538 |
/// | 128 KiB | 489,415,177 | 114,597,054 | |
/// | 64 KiB | 488,452,656 | 114,461,903 | 151,615,812 |
/// | **32 KiB** | **488,399,398** | **114,407,187** | **151,473,395** |
/// | 16 KiB | | 114,452,648 | |
///
/// 32 KiB is an optimum and not the end of a trend: 16 KiB is worse
/// again, and below it the region is too small a sample to price from.
///
/// **This dial was 64 KiB for a few hours and had to be RE-TUNED when the
/// adaptive entropy-block splitter landed on by default**, because the
/// splitter cuts the very blocks this model prices for; on the tree
/// before it, 64 KiB was the optimum and 32 KiB measurably worse. Re-run
/// the sweep whenever the block cutter changes: it is four archives, and
/// it has moved the answer once already.
pub(crate) const OPTIMAL_FIRST_REGION_BYTES: usize = 32 << 10;
// A first region at or past a full one would settle nothing early, which
// is the whole point of it; a build error is the right place to say so.
const _: () = assert!(OPTIMAL_FIRST_REGION_BYTES < ENTROPY_BLOCK_BYTES);
/// The base 2 logarithm of `value`, which must not be zero, in sixteenths of a bit rounded down.
/// Integers only, so the answer, and every byte priced from it, is the same on every machine.
///
/// A value under [`LOG2_TABLE_LEN`] is read from [`LOG2_TABLE`], which the
/// compiler fills from [`log2_sixteenths_squared`] itself, so every answer
/// is the routine's own. The cut's entropy estimate takes it for every
/// symbol a stretch uses, which on media is nearly every byte value: the
/// four rounds of squaring are a chain of dependent multiplies, where a
/// load from a 4 KiB table is one.
#[inline]
pub(crate) fn log2_sixteenths(value: u64) -> u32 {
    debug_assert!(value != 0);
    if value < LOG2_TABLE_LEN as u64 {
        return u32::from(LOG2_TABLE[value as usize]);
    }
    log2_sixteenths_squared(value)
}

/// How many values [`LOG2_TABLE`] answers: every one under 4,096, whose
/// answer is at most `11 << PRICE_SHIFT | 15` and so fits a byte.
const LOG2_TABLE_LEN: usize = 1 << 12;

/// [`log2_sixteenths_squared`] of every value under [`LOG2_TABLE_LEN`];
/// zero for zero, which no caller asks.
static LOG2_TABLE: [u8; LOG2_TABLE_LEN] = {
    let mut table = [0u8; LOG2_TABLE_LEN];
    let mut value = 1;
    while value < LOG2_TABLE_LEN {
        table[value] = log2_sixteenths_squared(value as u64) as u8;
        value += 1;
    }
    table
};

/// [`log2_sixteenths`] by integer log plus four rounds of mantissa
/// squaring.
pub(crate) const fn log2_sixteenths_squared(value: u64) -> u32 {
    let integer = 63 - value.leading_zeros();
    // The mantissa in Q30, so [2^30, 2^31) and a square still fits a u64.
    let mut mantissa = if integer >= 30 {
        value >> (integer - 30)
    } else {
        value << (30 - integer)
    };
    let mut fraction = 0u32;
    let mut bit = PRICE_SHIFT;
    while bit > 0 {
        bit -= 1;
        mantissa = (mantissa * mantissa) >> 30;
        if mantissa >= 1 << 31 {
            fraction |= 1 << bit;
            mantissa >>= 1;
        }
    }
    (integer << PRICE_SHIFT) | fraction
}
/// What each token symbol costs, in sixteenths of a bit, under one set of
/// Huffman tables. The four tables are the four the writer emits, so a
/// token's price here is the bits `encode_token_block` would actually
/// write for it, align symbol included.
#[derive(Clone)]
pub(crate) struct TokenPrices {
    pub(crate) main: Vec<u16>,
    pub(crate) length: Vec<u16>,
    pub(crate) distance: Vec<u16>,
    pub(crate) align: Vec<u16>,
}
/// Sixteenths of a bit for each symbol, from the frequencies a completed
/// region of the token stream actually had. A symbol the region never used
/// is priced at the table's deepest code rather than free; a table the
/// region never used at all keeps the constant model's price, so a region
/// with no far matches does not make the next one's far matches
/// unaffordable.
pub(crate) fn price_from_frequencies(prices: &mut [u16], frequencies: &[usize], absent: u16) {
    let total: usize = frequencies.iter().sum();
    if total == 0 {
        prices.fill(absent);
        return;
    }
    let log_total = log2_sixteenths(total as u64);
    for (price, &frequency) in prices.iter_mut().zip(frequencies) {
        *price = if frequency == 0 {
            PRICE_MAX
        } else {
            let bits = log_total - log2_sixteenths(frequency as u64);
            (bits as u16).clamp(PRICE_MIN, PRICE_MAX)
        };
    }
}
/// The parse's price model: the prices in force, and the token frequencies
/// of the region being parsed. Every [`ENTROPY_BLOCK_BYTES`] of committed
/// input the frequencies become the prices and reset, so each region is
/// priced by the one before it - the reader's tables are per region too,
/// so those are the codes the writer is about to build. (zstd's
/// `btultra2` re-parses the same block with the first pass's statistics;
/// pricing from the previous region instead costs one pass rather than
/// two and follows the input where a whole-block statistic cannot.)
pub(crate) struct PriceModel {
    pub(crate) prices: TokenPrices,
    pub(crate) main: Vec<usize>,
    pub(crate) length: Vec<usize>,
    pub(crate) distance: Vec<usize>,
    pub(crate) align: Vec<usize>,
    pub(crate) bytes: usize,
    /// How much committed input the next rebuild waits for: the short
    /// first region ([`OPTIMAL_FIRST_REGION_BYTES`]), then a full one.
    pub(crate) threshold: usize,
    pub(crate) distance_size: usize,
}
impl PriceModel {
    pub(crate) fn observe_literals(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.main[usize::from(byte)] += 1;
        }
        self.bytes += bytes.len();
    }
    /// Rebuild the prices when a region's worth of input has been
    /// committed. Called only between windows, so a window's prices, and
    /// the literal price prefix built from them, never move under it.
    pub(crate) fn settle(&mut self) {
        if self.bytes < self.threshold {
            return;
        }
        self.threshold = ENTROPY_BLOCK_BYTES;
        price_from_frequencies(&mut self.prices.main, &self.main, PRICE_MAX);
        price_from_frequencies(&mut self.prices.length, &self.length, 0);
        price_from_frequencies(&mut self.prices.distance, &self.distance, 0);
        price_from_frequencies(&mut self.prices.align, &self.align, 4 << PRICE_SHIFT);
        self.main.fill(0);
        self.length.fill(0);
        self.distance.fill(0);
        self.align.fill(0);
        self.bytes = 0;
    }
}
/// Every match length's length slot and that slot's extra-bit count, so
/// pricing a length down a ladder is two array reads. `slot` is 0xff where
/// the length has no slot. Built once per parse; 4 KiB of tables.
pub(crate) struct LengthSlots {
    pub(crate) slot: Vec<u8>,
    pub(crate) extra: Vec<u8>,
}
/// What a fixed distance costs a fixed node, with only the length left to
/// vary. The arm a distance takes (a repeat slot or a new distance) and
/// everything the distance itself pays (its slot code, its raw bits and
/// its align symbol) depend on the node's repeat state and not on the
/// length, so they are decided ONCE per (node, distance) and the ladder of
/// lengths below costs two array reads and an add each. Pricing every
/// length through [`EncoderMatchState::encode_match`] instead re-derived
/// the distance slot, the align symbol and the length bonus for every rung
/// (measured 7 Sep 2026: 126 user s over the 256 MiB slice, against 28 for
/// the lazy parser).
#[derive(Debug, Clone, Copy)]
pub(crate) enum DistanceArm {
    /// One of the four repeat distances, at `main` bits for its symbol;
    /// `repeat_at` is the one length that takes the two-bit length-repeat
    /// token instead (zero when this slot cannot reach it).
    Repeat {
        main: u32,
        repeat_at: usize,
        repeat_price: u32,
    },
    /// A distance the state does not hold: `paid` is everything the
    /// distance costs, `bonus` the length the format gives back for it.
    New { paid: u32, bonus: usize },
}
impl DistanceArm {
    /// The bits this arm spends on `length`, or `None` where the format
    /// cannot express it.
    #[inline]
    pub(crate) fn price(
        &self,
        prices: &TokenPrices,
        slots: &LengthSlots,
        length: usize,
    ) -> Option<u32> {
        match *self {
            Self::Repeat {
                main,
                repeat_at,
                repeat_price,
            } => {
                if length == repeat_at {
                    return Some(repeat_price);
                }
                let slot = slots.slot[length];
                if slot == 0xff {
                    return None;
                }
                Some(
                    main + u32::from(prices.length[usize::from(slot)])
                        + (u32::from(slots.extra[length]) << PRICE_SHIFT),
                )
            }
            Self::New { paid, bonus } => {
                let encoded = length.checked_sub(bonus)?;
                if encoded < 2 {
                    return None;
                }
                let slot = slots.slot[encoded];
                if slot == 0xff {
                    return None;
                }
                Some(
                    paid + u32::from(prices.main[262 + usize::from(slot)])
                        + (u32::from(slots.extra[encoded]) << PRICE_SHIFT),
                )
            }
        }
    }
}
// local change, 5 Sep 2026 - share an eight-byte load across four
// adjacent hashes. Insert every position in its original order, including
// repeated-prefix collisions, and use the scalar path at the input tail.
// See VENDORING.md.
pub(crate) fn insert_match_range<P: MatchPosition>(
    input: &[u8],
    range: Range<usize>,
    index: &mut MatchIndex<P>,
) {
    let mut pos = range.start;
    let end = range.end.min(input.len().saturating_sub(3));
    while end.saturating_sub(pos) >= 4 && input.len().saturating_sub(pos) >= 8 {
        let words = u64::from_le_bytes(input[pos..pos + 8].try_into().unwrap());
        index.insert_word(words as u32, pos);
        index.insert_word((words >> 8) as u32, pos + 1);
        index.insert_word((words >> 16) as u32, pos + 2);
        index.insert_word((words >> 24) as u32, pos + 3);
        index.long_insert(input, words as u32, pos, true);
        index.long_insert(input, (words >> 8) as u32, pos + 1, true);
        index.long_insert(input, (words >> 16) as u32, pos + 2, true);
        index.long_insert(input, (words >> 24) as u32, pos + 3, true);
        pos += 4;
    }
    for at in pos..end {
        index.insert(input, at);
    }
}
// local change, 5 Sep 2026 - flat ring match index; see VENDORING.md.
//
// Every bucket is a fixed ring of `depth` position slots in one flat
// vector, addressed by a multiplicative hash of the FOUR bytes at a
// position (a match must be four bytes long to be emitted, so a shorter
// hash only manufactures collisions). Insertion overwrites the oldest slot;
// a probe reads the newest `depth` back. No per-bucket allocation, no
// growth, a bounded and cache-local walk. The previous index was 4,096
// growable vectors under a three-byte hash, where most of a probe's
// candidates were other trigrams' positions rejected by the prefix
// compare, and the walk was bounded only by the candidate budget.
pub(crate) struct MatchIndex<P> {
    pub(crate) slots: Vec<P>,
    pub(crate) counts: Vec<u32>,
    pub(crate) hash_shift: u32,
    pub(crate) depth_bits: u32,
    /// Positions in the span need `pos_bits`; the bits above them in a
    /// slot hold a TAG, `tag_bits` of the position's four-byte hash (bits
    /// the bucket does not use), so a candidate whose tag differs is
    /// rejected without loading its history - at a 32 MiB dictionary the
    /// buckets are full and every one of a probe's 64 candidates used to
    /// cost a scattered load for the one-byte filter alone. A tag can only
    /// reject a candidate the prefix compare would have rejected, and a
    /// rejection still spends the candidate, so the walk stops where it
    /// did and the output is byte-identical. Zero `tag_bits` (a span past
    /// 2^32 in a u32 index cannot happen; usize spans get 8) means no tags.
    /// (local change, 6 Sep 2026; see VENDORING.md.)
    pub(crate) pos_bits: u32,
    pub(crate) tag_bits: u32,
    /// The long-match table: at every anchor position (one in 32, chosen by
    /// the four-byte hash so the same bytes anchor the same way wherever
    /// they recur) the position, plus one, under a hash of its next 32
    /// bytes; zero is empty. The ring above keeps the newest `depth`
    /// positions per bucket, which on a 32 MiB dictionary is the newest
    /// four megabytes or so of any common prefix - a repeat farther back
    /// than that was invisible. This table reaches the whole dictionary
    /// at one slot per 32 bytes: a repeated span is found at its first
    /// anchor, and the rep-distance probe carries the match on from there.
    /// Measured on the 1 GiB mixed corpus at a 32 MiB dictionary, where a
    /// third of the bytes are a 32 MiB pool replayed: see the research
    /// record for the round. (local change, 6 Sep 2026; see
    /// VENDORING.md.)
    pub(crate) long: Vec<P>,
    pub(crate) long_shift: u32,
}
#[inline]
pub(crate) fn long_anchor(word: u32) -> bool {
    (word.wrapping_mul(0x9E37_79B1) >> 8) & LONG_ANCHOR_MASK == 0
}
/// Hash of the 32 bytes at `pos`; the caller checks they exist.
#[inline]
pub(crate) fn long_hash(input: &[u8], pos: usize) -> u64 {
    let mut hash = 0u64;
    for chunk in input[pos..pos + LONG_HASH_BYTES].chunks_exact(8) {
        let word = u64::from_le_bytes(chunk.try_into().unwrap());
        hash = (hash ^ word).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        hash ^= hash >> 29;
    }
    hash
}
pub(crate) fn index_keep(slot: &mut Option<MatchIndex<u32>>, index: MatchIndex<u32>) {
    *slot = Some(index);
}
pub(crate) const P_ZERO_U32: u32 = 0;
/// The shipped rule for `(buckets, depth)`: the ring holds the candidate
/// budget's positions (inside its own bounds) and the span gets about one
/// bucket per `depth` positions.
#[inline]
pub(crate) fn index_geometry_default(
    indexed_len: usize,
    max_match_candidates: usize,
) -> (usize, usize) {
    let depth = max_match_candidates
        .max(1)
        .next_power_of_two()
        .clamp(MATCH_INDEX_MIN_DEPTH, MATCH_INDEX_MAX_DEPTH);
    let buckets = (indexed_len / depth)
        .max(1)
        .next_power_of_two()
        .clamp(MATCH_INDEX_MIN_BUCKETS, MATCH_INDEX_MAX_BUCKETS);
    (buckets, depth)
}
/// Production: the shipped rule, and nothing else. This is the whole of
/// `shape`'s body in a build without `ratio-lab`, so no production binary
/// carries a branch, a lookup or a symbol for the research override below.
#[cfg(not(feature = "ratio-lab"))]
#[inline]
pub(crate) fn index_geometry(indexed_len: usize, max_match_candidates: usize) -> (usize, usize) {
    index_geometry_default(indexed_len, max_match_candidates)
}
/// `ratio-lab` only (local change, 8 Sep 2026; see VENDORING.md):
/// force either axis of the
/// index geometry from the environment, so bucket count and ring depth can
/// be swept INDEPENDENTLY. The 8 Sep ring-probe census found 69.6% of a
/// bucket's candidates are foreign four-byte words, which is a property of
/// this shape rather than of the walk, and the one screen that followed it
/// moved both axes at once.
///
/// `RARKIT_INDEX_DEPTH` and `RARKIT_INDEX_BUCKETS` each force their axis
/// exactly; an axis left unset follows the shipped rule GIVEN the other,
/// so a depth-only arm keeps "about one bucket per `depth` positions".
/// With neither set this is `index_geometry_default` by construction, which
/// is what makes the research control reproduce ordinary bytes.
#[cfg(feature = "ratio-lab")]
pub(crate) fn index_geometry(indexed_len: usize, max_match_candidates: usize) -> (usize, usize) {
    let (forced_buckets, forced_depth) = index_geometry_override();
    if forced_buckets.is_none() && forced_depth.is_none() {
        // The research CONTROL is the shipped function itself, not a
        // re-derivation of it that could drift away from it silently.
        return index_geometry_default(indexed_len, max_match_candidates);
    }
    let depth = forced_depth.unwrap_or_else(|| {
        max_match_candidates
            .max(1)
            .next_power_of_two()
            .clamp(MATCH_INDEX_MIN_DEPTH, MATCH_INDEX_MAX_DEPTH)
    });
    let buckets = forced_buckets.unwrap_or_else(|| {
        (indexed_len / depth)
            .max(1)
            .next_power_of_two()
            .clamp(MATCH_INDEX_MIN_BUCKETS, MATCH_INDEX_MAX_BUCKETS)
    });
    (buckets, depth)
}
/// The parsed overrides, read once. A malformed value ABORTS the process
/// rather than falling back to the default: an arm that silently measured
/// the baseline under an arm's label is the one failure this harness cannot
/// detect from its own output, and every reading in this campaign is a
/// paired delta. It aborts rather than panicking because `shape` is reached
/// from an encoder WORKER - a panic there unwinds one rayon thread and
/// leaves the process alive with no output and no exit, which reads as a
/// slow arm rather than as a refusal (observed, 8 Sep 2026).
#[cfg(feature = "ratio-lab")]
pub(crate) fn index_geometry_override() -> (Option<usize>, Option<usize>) {
    static OVERRIDE: std::sync::OnceLock<(Option<usize>, Option<usize>)> =
        std::sync::OnceLock::new();
    *OVERRIDE.get_or_init(|| {
        fn refuse(message: String) -> ! {
            eprintln!("ratio-lab: {message}");
            std::process::abort();
        }
        fn read(name: &str, max: usize) -> Option<usize> {
            let raw = std::env::var(name).ok()?;
            let Ok(value) = raw.trim().parse::<usize>() else {
                refuse(format!("{name}: not a number: {raw:?}"));
            };
            if !value.is_power_of_two() || value > max {
                refuse(format!("{name}: want a power of two in 1..={max}, got {value}"));
            }
            Some(value)
        }
        let depth = read("RARKIT_INDEX_DEPTH", 1 << 12);
        let buckets = read("RARKIT_INDEX_BUCKETS", 1 << 24);
        // One index is allocated per encoder worker, so a careless pair is
        // gigabytes rather than a slow run.
        let slots =
            buckets.unwrap_or(MATCH_INDEX_MAX_BUCKETS) * depth.unwrap_or(MATCH_INDEX_MAX_DEPTH);
        if slots > 1 << 26 {
            refuse(format!(
                "RARKIT_INDEX_BUCKETS * RARKIT_INDEX_DEPTH = {slots} slots is over the lab's 2^26 ceiling"
            ));
        }
        (buckets, depth)
    })
}
impl<P: MatchPosition> MatchIndex<P> {
    /// Entries in the long-match table for a span: one per anchor spacing.
    pub(crate) fn long_entries(indexed_len: usize) -> usize {
        (indexed_len / LONG_ANCHOR_SPACING)
            .max(1)
            .next_power_of_two()
            .clamp(LONG_INDEX_MIN_ENTRIES, LONG_INDEX_MAX_ENTRIES)
    }
    /// `(buckets, depth)` for a span and a candidate budget.
    pub(crate) fn shape(indexed_len: usize, max_match_candidates: usize) -> (usize, usize) {
        index_geometry(indexed_len, max_match_candidates)
    }
    pub(crate) fn new(indexed_len: usize, max_match_candidates: usize) -> Self {
        Self::new_shaped(indexed_len, indexed_len, max_match_candidates)
    }
    /// An index shaped for a span `shape_len` long whose positions are
    /// offsets below `span_len`: the live solid encoder shapes its index
    /// as the per-member walk would (history plus member) while its
    /// positions are offsets in the whole group span.
    pub(crate) fn new_shaped(
        shape_len: usize,
        span_len: usize,
        max_match_candidates: usize,
    ) -> Self {
        let (buckets, depth) = Self::shape(shape_len, max_match_candidates);
        let long_entries = Self::long_entries(shape_len);
        let mut index = Self {
            slots: vec![P::from_position(0); buckets * depth],
            counts: vec![0; buckets],
            hash_shift: 32 - buckets.trailing_zeros(),
            depth_bits: depth.trailing_zeros(),
            long: vec![P::from_position(0); long_entries],
            long_shift: 64 - long_entries.trailing_zeros(),
            pos_bits: 0,
            tag_bits: 0,
        };
        index.set_span(span_len);
        index
    }
    /// The position/tag split for a span whose positions are below
    /// `indexed_len`: only valid on an index with every bucket count zero.
    pub(crate) fn set_span(&mut self, indexed_len: usize) {
        debug_assert!(self.counts.iter().all(|&count| count == 0));
        self.pos_bits = (usize::BITS - indexed_len.max(1).leading_zeros()).max(1);
        self.tag_bits = P::BITS
            .saturating_sub(self.pos_bits)
            .min(MATCH_TAG_BITS_MAX);
    }
    /// The tag of a four-byte word: hash bits below the bucket's.
    #[inline]
    pub(crate) fn tag(&self, word: u32) -> usize {
        ((word.wrapping_mul(0x9E37_79B1) >> 8) as usize) & ((1usize << self.tag_bits) - 1)
    }
    /// A slot value: the position with the word's tag above it.
    #[inline]
    pub(crate) fn slot_value(&self, word: u32, pos: usize) -> P {
        P::from_position(pos | (self.tag(word) << self.pos_bits))
    }
    /// A slot's position, without its tag.
    ///
    /// The read half of `slot_value` above, which IS used: kept as the
    /// statement of how a slot is packed, so the two halves of that
    /// encoding stay next to each other. No caller today.
    #[allow(dead_code)]
    #[inline]
    pub(crate) fn slot_position(&self, slot: P) -> usize {
        slot.position() & ((1usize << self.pos_bits) - 1)
    }
    #[inline]
    pub(crate) fn long_slot(&self, input: &[u8], pos: usize) -> usize {
        // Exact on a 32-bit `usize`: `long_shift` is `64 - log2(long_entries)`
        // and `long_entries` is at most `LONG_INDEX_MAX_ENTRIES` (2^20), so
        // the shifted hash is below 2^20 whatever the width.
        (long_hash(input, pos) >> self.long_shift) as usize
    }
    /// Record `pos` in the long table if it is an anchor with 32 bytes after
    /// it. Forward insertion overwrites (the newest position wins); reverse
    /// seeding keeps the first write, which is the newest there too.
    #[inline]
    pub(crate) fn long_insert(&mut self, input: &[u8], word: u32, pos: usize, overwrite: bool) {
        if long_anchor(word) && pos + LONG_HASH_BYTES <= input.len() {
            let slot = self.long_slot(input, pos);
            if overwrite || self.long[slot].position() == 0 {
                self.long[slot] = P::from_position(pos + 1);
            }
        }
    }
    /// The long table's position for `pos`, if `pos` is an anchor and the
    /// table has one: the caller verifies the bytes.
    #[inline]
    pub(crate) fn long_candidate(&self, input: &[u8], pos: usize) -> Option<usize> {
        if pos + LONG_HASH_BYTES > input.len() {
            return None;
        }
        let word = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
        if !long_anchor(word) {
            return None;
        }
        let entry = self.long[self.long_slot(input, pos)].position();
        (entry != 0).then(|| entry - 1)
    }
    /// Anchors of the whole history into the long table, newest first, so
    /// the nearest occurrence of a span is the one kept. Runs over ALL of
    /// the history where the ring's seeding stops once every bucket is
    /// full - reach is the point of this table.
    pub(crate) fn seed_long_history(&mut self, input: &[u8], history_len: usize) {
        let mut end = history_len.min(input.len().saturating_sub(LONG_HASH_BYTES - 1));
        while end >= 4 {
            end -= 4;
            let words = u64::from_le_bytes(input[end..end + 8].try_into().unwrap());
            self.long_insert(input, (words >> 24) as u32, end + 3, false);
            self.long_insert(input, (words >> 16) as u32, end + 2, false);
            self.long_insert(input, (words >> 8) as u32, end + 1, false);
            self.long_insert(input, words as u32, end, false);
        }
        while end != 0 {
            end -= 1;
            let word = u32::from_le_bytes(input[end..end + 4].try_into().unwrap());
            self.long_insert(input, word, end, false);
        }
    }
    #[inline]
    pub(crate) fn depth(&self) -> usize {
        1 << self.depth_bits
    }
    #[inline]
    pub(crate) fn bucket(&self, input: &[u8], pos: usize) -> usize {
        let word = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
        (word.wrapping_mul(0x9E37_79B1) >> self.hash_shift) as usize
    }
    /// Positions with fewer than four bytes after them can never start a
    /// match and are not indexed.
    #[inline]
    pub(crate) fn insert(&mut self, input: &[u8], pos: usize) {
        if pos + 3 < input.len() {
            let word = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
            self.insert_word(word, pos);
            self.long_insert(input, word, pos, true);
        }
    }
    #[inline]
    pub(crate) fn insert_word(&mut self, word: u32, pos: usize) {
        let bucket = (word.wrapping_mul(0x9E37_79B1) >> self.hash_shift) as usize;
        let count = self.counts[bucket];
        let slot = (bucket << self.depth_bits) | (count as usize & (self.depth() - 1));
        self.slots[slot] = self.slot_value(word, pos);
        self.counts[bucket] = count.wrapping_add(1);
    }
    pub(crate) fn seed_history_reverse(&mut self, input: &[u8], history_len: usize) {
        // Batch scanning helps low-diversity history; the scalar scan is
        // faster when its bucket accesses are dense and irregular. A small
        // projected-bucket sample selects the scan, never the candidates.
        let end = history_len.min(input.len().saturating_sub(3));
        let mut seen = [0u64; 16];
        let mut distinct = 0;
        for pos in (end.saturating_sub(512)..end).rev() {
            let bucket = self.bucket(input, pos) & 1023;
            let bit = 1u64 << (bucket & 63);
            if seen[bucket >> 6] & bit == 0 {
                seen[bucket >> 6] |= bit;
                distinct += 1;
                if distinct > 128 {
                    self.seed_history_reverse_scalar(input, history_len);
                    return;
                }
            }
        }
        self.seed_history_reverse_batched(input, history_len);
    }
    pub(crate) fn seed_history_reverse_scalar(&mut self, input: &[u8], history_len: usize) {
        debug_assert!(self.counts.iter().all(|&count| count == 0));
        let depth = self.depth();
        let mut unfilled = self.counts.len();
        let end = history_len.min(input.len().saturating_sub(3));
        for pos in (0..end).rev() {
            let word = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
            let bucket = (word.wrapping_mul(0x9E37_79B1) >> self.hash_shift) as usize;
            let count = self.counts[bucket] as usize;
            if count == depth {
                continue;
            }
            // Store from the back: after normalization, the newest entry
            // sits immediately before the next insertion slot.
            let slot = (bucket << self.depth_bits) + depth - 1 - count;
            self.slots[slot] = self.slot_value(word, pos);
            self.counts[bucket] += 1;
            if count + 1 == depth {
                unfilled -= 1;
                if unfilled == 0 {
                    break;
                }
            }
        }
        for (bucket, &count) in self.counts.iter().enumerate() {
            let count = count as usize;
            if count != 0 && count < depth {
                let base = bucket << self.depth_bits;
                self.slots
                    .copy_within(base + depth - count..base + depth, base);
            }
        }
    }
    pub(crate) fn seed_history_reverse_batched(&mut self, input: &[u8], history_len: usize) {
        debug_assert!(self.counts.iter().all(|&count| count == 0));
        let depth = self.depth();
        let mut unfilled = self.counts.len();
        let mut end = history_len.min(input.len().saturating_sub(3));
        // An eight-byte load covers four overlapping prefixes. One scalar
        // prefix handles a history ending at the last valid input prefix.
        if end != 0 && input.len() - end < 4 {
            end -= 1;
            let word = u32::from_le_bytes(input[end..end + 4].try_into().unwrap());
            self.seed_history_word(word, end, depth, &mut unfilled);
        }
        while end >= 4 && unfilled != 0 {
            end -= 4;
            let words = u64::from_le_bytes(input[end..end + 8].try_into().unwrap());
            self.seed_history_word((words >> 24) as u32, end + 3, depth, &mut unfilled);
            self.seed_history_word((words >> 16) as u32, end + 2, depth, &mut unfilled);
            self.seed_history_word((words >> 8) as u32, end + 1, depth, &mut unfilled);
            self.seed_history_word(words as u32, end, depth, &mut unfilled);
        }
        while end != 0 && unfilled != 0 {
            end -= 1;
            let word = u32::from_le_bytes(input[end..end + 4].try_into().unwrap());
            self.seed_history_word(word, end, depth, &mut unfilled);
        }
        for (bucket, &count) in self.counts.iter().enumerate() {
            let count = count as usize;
            if count != 0 && count < depth {
                let base = bucket << self.depth_bits;
                self.slots
                    .copy_within(base + depth - count..base + depth, base);
            }
        }
    }
    #[inline(always)]
    pub(crate) fn seed_history_word(
        &mut self,
        word: u32,
        pos: usize,
        depth: usize,
        unfilled: &mut usize,
    ) {
        let bucket = (word.wrapping_mul(0x9E37_79B1) >> self.hash_shift) as usize;
        let count = self.counts[bucket] as usize;
        if count < depth {
            let slot = (bucket << self.depth_bits) + depth - 1 - count;
            self.slots[slot] = self.slot_value(word, pos);
            self.counts[bucket] += 1;
            if count + 1 == depth {
                *unfilled -= 1;
            }
        }
    }
    /// The bucket's inserted positions, newest first, at most `depth` of them.
    ///
    /// The untagged view of `candidates_tagged` below, which IS what the
    /// walkers call. No caller today; kept as the plain reading of a
    /// bucket, next to the tagged one it is defined from.
    #[allow(dead_code)]
    #[inline]
    pub(crate) fn candidates(&self, input: &[u8], pos: usize) -> impl Iterator<Item = usize> + '_ {
        self.candidates_tagged(input, pos)
            .map(|(candidate, _)| candidate)
    }
    /// The bucket's inserted positions, newest first, each with whether its
    /// tag matches the word at `pos` - `false` means the prefix cannot.
    #[inline]
    pub(crate) fn candidates_tagged(
        &self,
        input: &[u8],
        pos: usize,
    ) -> impl Iterator<Item = (usize, bool)> + '_ {
        let word = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
        let bucket = (word.wrapping_mul(0x9E37_79B1) >> self.hash_shift) as usize;
        let tag = self.tag(word);
        let count = self.counts[bucket];
        let available = (count as usize).min(self.depth());
        let base = bucket << self.depth_bits;
        let mask = self.depth() - 1;
        let pos_mask = (1usize << self.pos_bits) - 1;
        (1..=available).map(move |back| {
            let value =
                self.slots[base | (count.wrapping_sub(back as u32) as usize & mask)].position();
            (value & pos_mask, (value >> self.pos_bits) == tag)
        })
    }
}
// ---------------------------------------------------------------------------
// Parallel block decode.
//
// A RAR 5 compressed stream is a chain of blocks whose boundaries (and table
// sections) are parseable without decoding any symbols, and whose symbol
// streams depend only on the active Huffman tables - never on the LZ window
// or the repeat-distance state. Those facts split member decode into:
//
//   scan (serial, cheap)  - read block payloads, thread table sets through
//   decode (parallel)     - Huffman-decode each block into an op tape,
//                           leaving rep distances and last-length symbolic
//   apply (serial)        - resolve rep state, run the window, feed the sink
//
// The apply stage reproduces the serial decoder's observable behavior
// exactly: same output bytes, same early stop at the member size, same
// errors at the same output positions. Work the serial decoder would never
// have reached (bits past the output limit, blocks read ahead) has its
// errors deferred and swallowed unless the member genuinely needs them.
// ---------------------------------------------------------------------------

/// The engine's own ceiling on the tape lanes ONE member may open, which
/// API section 8.4.3 requires to be A MEASURED CONSTANT rather than a
/// derived one: whichever width measures the lowest wall inside the
/// caller's memory ceiling.
///
/// **It was 8 until 20 Sep 2026, and that 8 was the defect.** It came
/// from the era when the read path had no width dial of its own and the
/// memory policy's `max_workers` (8 at the default 512 MiB budget) was
/// the only thing that bounded decode threads, so a hard 8 here "must not
/// sit under what the policy would grant" and did not. The measurement
/// behind it - 4 workers to 8 took a 1 GiB -m3 member from 1.44 s to
/// 1.32 s on a 20-core M1 Ultra, 12 was no better (2 Sep 2026) - was taken at a time when
/// nothing above 8 could be asked for, so "12 was no better" was measured
/// against a pool the policy had already narrowed.
///
/// Section 8.4.2 gave the read side `ReadOptions::workers`, and the 8.4.3
/// ladder on an M3 Mac then showed the many-member shapes gaining up to
/// 3.311x at a width of 32 while `one-big-many-small` and `solid-vol`
/// stayed FLAT at every width: this constant, not the dial and not the
/// pool, was what held one member's lanes at 8. Peak working memory in
/// that ladder never passed 97.0 MiB of a 512 MiB budget at any width, so
/// it was not memory that held it either.
///
/// **What it is now: 8, and it is now MEASURED.** The number did not
/// move; what moved is that it is no longer an arbitrary one, and the
/// reason it stays is the opposite of what was expected when it was
/// measured.
///
/// Measured on an M3 Mac, 32 cores, aarch64, 20 Sep 2026, on an otherwise
/// idle machine, one binary with the tape width driven by
/// `RAYON_NUM_THREADS` through `pool_width` and the pre-touch base gated
/// at BOTH ends (the one member width ladder).
/// Nine pairs per cell. Widths 8, 16, 24, 32 on the two single member
/// shapes:
///
/// | | w8 | w16 | w24 | w32 | base again |
/// |---|---|---|---|---|---|
/// | `rar5_text_64m_m3` wall s | 0.05805 | 0.05860 | 0.05813 | 0.05859 | 0.05866 |
/// | its peak RSS MiB | 149 | 153 | 161 | 162 | 149 |
/// | its CPU s | 0.1673 | 0.1697 | 0.1703 | 0.1716 | 0.1673 |
/// | `rar5_incompressible_64m` wall s | 0.2345 | 0.2325 | 0.2327 | 0.2327 | 0.2339 |
/// | its peak RSS MiB | 216 | 218 | 226 | 228 | 216 |
///
/// **The wall is FLAT from 8 lanes to 31 and the cost is not.** Every
/// width's interval overlaps every other's, and the spread across the
/// whole ladder is smaller than the box's own drift between the two base
/// gatings. Peak RSS and CPU seconds rise MONOTONICALLY with the width
/// and come back down at the closing gate, which is also the proof that
/// the dial reached the engine at all rather than sweeping a number
/// nothing read. So a width above 8 on ONE member buys nothing and is
/// paid for in memory and CPU, and a tie in wall is broken by CPU and
/// peak RSS, which picks 8.
///
/// **Why, and this is the part worth keeping.** The tape decode's APPLY
/// stage is serial by construction (section 3.8: the window, the repeat
/// distances, the last length and the filter queue all live on one
/// thread), so per member lane width saturates against it. The work that
/// took this constant expected the opposite: API 8.4.3's ladder found the
/// many member shapes gaining up to 3.311x at width 32 while
/// `one-big-many-small` and `solid-vol` stayed flat, and read this cap as
/// the reason. **It was not.** Lifting it entirely and re-measuring left
/// the wall exactly where it was. A one member shape is flat in the width
/// because it is apply bound, and the many member shapes gain through
/// BREADTH, which `read::lanes` shares and which this constant never
/// touched.
///
/// So this satisfies API 8.4.3's demand for a MEASURED constant rather
/// than a derived one, and the figure it measures happens to be the one
/// that was already here. What a reader should NOT do is take the
/// number as untested because it did not change. The 2026-09-02 figure it
/// replaces was taken when nothing above 8 could be asked for; this one
/// was taken with the ceiling removed.
///
/// `tape::workers` lowers this to the host's count, to the read width
/// `ReadOptions::workers` resolved, to the lane budget the members in
/// flight share, and to the blocks the chain actually has. Worst-case
/// tape memory stays bounded per lane by `TAPE_OPS_CAP` / `TAPE_LITS_CAP`
/// through the park-and-resume boundary, and what a lane RETAINS between
/// blocks by `TAPE_RECYCLE_BYTES_MAX`, which is the term
/// `tape::lanes_within_budget` prices the width against so that a
/// caller's `working_limit` bounds it too.
///
/// NOT DONE YET: an x86-64 measurement, which 8.4.3 says cannot be substituted, and a
/// member far larger than 64 MiB, where the serial apply stage's share is
/// the same by Amdahl but the absolute figures are not.
#[cfg(feature = "parallel")]
pub(crate) const MT_MAX_WORKERS: usize = 8;
/// Members below this size decode serially: thread spinup and tape overhead
/// only pay for themselves on bulk decodes.
#[cfg(all(feature = "parallel", not(test)))]
pub(crate) const MT_MIN_OUTPUT: usize = 16 << 20;
/// Tests force the parallel path onto every streaming decode so the whole
/// suite differentially exercises it (mirrors the BUFFERED_DECODE_LIMIT
/// override in rar50/extract.rs).
#[cfg(all(feature = "parallel", test))]
pub(crate) const MT_MIN_OUTPUT: usize = 0;
/// Per-tape bounds: a worker that exceeds either parks the block at its
/// current bit position and the apply stage finishes it with the serial
/// decoder. Keeps adversarial streams (1-bit codes, giant blocks) from
/// ballooning tape memory; realistic blocks never get near these. Tests
/// shrink them so the park-and-resume boundary is crossed constantly.
#[cfg(all(feature = "parallel", not(test)))]
pub(crate) const TAPE_OPS_CAP: usize = 1 << 21;
#[cfg(all(feature = "parallel", test))]
pub(crate) const TAPE_OPS_CAP: usize = 1 << 10;
#[cfg(all(feature = "parallel", not(test)))]
pub(crate) const TAPE_LITS_CAP: usize = 4 << 20;
#[cfg(all(feature = "parallel", test))]
pub(crate) const TAPE_LITS_CAP: usize = 16 << 10;
/// A hostile block can grow a tape bundle far beyond useful steady-state
/// sizes. The channel retains at most one 4 MiB bundle per worker, while
/// normal smaller blocks remain reusable.
///
/// This used to read "32 MiB at the eight-worker ceiling", which stopped
/// being a fixed figure on 20 Sep 2026 when `MT_MAX_WORKERS` stopped being
/// eight. What the product now bounds is stated once, as
/// `tape::TAPE_BYTES_PER_LANE`, and `tape::lanes_within_budget` is what
/// keeps it inside a caller's `MemoryPolicy::working_limit` at any width.
#[cfg(feature = "parallel")]
pub(crate) const TAPE_RECYCLE_BYTES_MAX: usize = 4 << 20;
#[cfg(feature = "parallel")]
// `MT_MIN_OUTPUT` is cfg-dependent and deliberately 0 under `test`, so the
// suite forces every streaming decode down the parallel path. In that build
// the comparison is trivially false - which is correct, not a mistake - and
// clippy's absurd-comparison lint would otherwise deny the whole crate.
#[allow(clippy::absurd_extreme_comparisons)]
pub(crate) fn mt_worker_count(output_size: usize) -> usize {
    if output_size < MT_MIN_OUTPUT {
        return 0;
    }
    std::thread::available_parallelism()
        .map(|cores| cores.get().saturating_sub(1))
        .unwrap_or(0)
        .min(MT_MAX_WORKERS)
}
/// Tape op kinds. `TapeOp` is a plain struct rather than a Rust enum, so
/// the kind is a field; see the type's comment for why.
#[cfg(feature = "parallel")]
mod tape_kind {
    /// Emit the next `length` bytes from the tape's literal buffer.
    pub(crate) const LITS: u32 = 0;
    /// Fully resolved match (symbol 262..).
    pub(crate) const MATCH: u32 = 1;
    /// Repeat-distance match (symbols 258..=261); `distance` carries the rep
    /// INDEX (0..=3), resolved against the live rep state at apply.
    pub(crate) const REP: u32 = 2;
    /// Symbol 257: reuse the last distance and length (no-op when none yet).
    pub(crate) const REP_LAST: u32 = 3;
    /// Symbol 256: filter declaration; the payload is the next entry of
    /// `BlockTape::filters` and its start offset resolves at apply.
    pub(crate) const FILTER: u32 = 4;
}
/// Bit position of the kind inside `TapeOp::kind_length`.
#[cfg(feature = "parallel")]
pub(crate) const TAPE_KIND_SHIFT: u32 = 29;
#[cfg(feature = "parallel")]
pub(crate) const TAPE_LENGTH_MASK: u32 = (1 << TAPE_KIND_SHIFT) - 1;
/// What applying a block's tape came to.
pub(crate) enum TapeApplied {
    /// Every operation of the tape was applied. There is no other answer:
    /// since SPEC-H2's change of 28 Sep 2026 a member decodes every symbol
    /// of every block it owns, and the window caps its output (3.1).
    BlockDone,
}
/// Emit granularity: keep the writer-thread pipe fed in ~1 MB batches while
/// decode continues, matching the streaming path's flush cadence.
pub(crate) const FLAT_EMIT_THRESHOLD: usize = 1 << 20;
/// Longest literal run `push_bytes` copies with the inline power-of-two
/// ladder instead of `copy_from_slice`'s `memcpy` libcall. Fifteen is the
/// widest length the four-step ladder covers exactly, and it is far past
/// the measured distribution: 99.0-99.2% of runs on the census -m3 shapes
/// are at most fifteen bytes. (local change, 3 Sep 2026; see
/// VENDORING.md.)
pub(crate) const LITERAL_INLINE_MAX: usize = 15;
/// MOST slack past the retained window in a SLIDING flat buffer: the plan
/// never reaches further than this past the window, so the memmove that
/// slides the window to the front runs at least once per this many output
/// bytes. Tests shrink it so the differential suite crosses slides
/// constantly.
///
/// This was the LEAST slack - the name is the old one - until 16 Sep 2026,
/// when `flat_slack` below made the slack a function of the member and the
/// dictionary and left this as its ceiling. The bound the old floor carried
/// (slack at least the dictionary, so at most one byte moved per byte
/// emitted) is now the rule's own lower clamp and did not move.
#[cfg(not(test))]
pub(crate) const FLAT_SLACK_MIN: usize = 64 << 20;
/// Test builds shrink it to the floor so the suite crosses a slide
/// constantly, which is what the doc comment above describes and what the
/// differential tests of SPEC-H2 section 5.5 rest on.
#[cfg(test)]
pub(crate) const FLAT_SLACK_MIN: usize = FLAT_SLACK_FLOOR;
/// Smallest slack the sliding buffer runs with at all, whatever the two
/// terms below say: a slide has to leave room for the longest single match
/// or literal run the walk can append. This is the value test builds have
/// always used for `FLAT_SLACK_MIN`, so it is the one that is proven by the
/// differential suite. (local change, 16 Sep 2026; see VENDORING.md.)
pub(crate) const FLAT_SLACK_FLOOR: usize = 4096;
/// `flat_slack` with the ceiling named, so a test can ask what a PRODUCTION
/// build plans: `FLAT_SLACK_MIN` is a sixteen-thousandth of its shipped value
/// under `cfg(test)`, which would otherwise leave the rule untested at every
/// size it was fitted on.
pub(crate) fn flat_slack_with(output_size: usize, history_limit: usize, slack_min: usize) -> usize {
    // Today's slack, and the ceiling: this rule only ever plans less.
    let ceiling = history_limit.max(slack_min);
    // `u128::isqrt` is not stable on the pinned toolchain, and the product
    // reaches 2^77, so the root is taken in f64: a 53-bit mantissa is worth
    // about one part in 2^24 of it, far inside the flat region around the
    // optimum. A non-finite product would saturate to zero, which the
    // clamps below then lift to the old floor.
    // f64 to usize saturates, and `ceiling` bounds the result, so the cast
    // is exact on a 32-bit `usize` too.
    let ideal = ((output_size as f64) * (history_limit as f64) / 3.0).sqrt() as usize;
    ideal.max(history_limit).max(FLAT_SLACK_FLOOR).min(ceiling)
}
/// Append a SHORT literal run at `pos` with constant-length copies. A run
/// ends at the next match and matches are 86% of tape ops, so runs are
/// overwhelmingly tiny: on the census -m3 shapes 67.8-69.4% of runs are a
/// single byte and 97.1-97.7% are three bytes or fewer, while the long
/// incompressible runs that carry most of the literal BYTES are a rounding
/// error in COUNT. `copy_from_slice` on a runtime length is a `memcpy`
/// libcall whatever that length is, and a `sample` of the 4 GiB fixture put
/// 9.6% of the apply thread - the pipeline's wall - at the return address
/// of exactly that call. Every copy below has a constant length, so it
/// lowers to inline load/store pairs; past `LITERAL_INLINE_MAX` the caller
/// keeps the libcall, which is the right shape for a long run.
///
/// Caller guarantees `bytes.len() <= LITERAL_INLINE_MAX` and that
/// `buf[pos..pos + bytes.len()]` is in bounds. (local change,
/// 3 Sep 2026; see VENDORING.md.)
#[inline(always)]
pub(crate) fn flat_literal_ladder(buf: &mut [u8], pos: usize, bytes: &[u8]) {
    let count = bytes.len();
    debug_assert!(count <= LITERAL_INLINE_MAX);
    if count == 1 {
        buf[pos] = bytes[0];
        return;
    }
    let mut src = bytes;
    let mut at = pos;
    if count & 8 != 0 {
        let (head, rest) = src.split_at(8);
        buf[at..at + 8].copy_from_slice(head);
        src = rest;
        at += 8;
    }
    if count & 4 != 0 {
        let (head, rest) = src.split_at(4);
        buf[at..at + 4].copy_from_slice(head);
        src = rest;
        at += 4;
    }
    if count & 2 != 0 {
        let (head, rest) = src.split_at(2);
        buf[at..at + 2].copy_from_slice(head);
        src = rest;
        at += 2;
    }
    if count & 1 != 0 {
        buf[at] = src[0];
    }
}
/// Group-relative output offset where the member containing `start` begins.
/// `member_ends` holds the group-relative end of each member in order and is
/// empty for a single-member decode, where the base is always zero.
pub(crate) fn member_base_of(member_ends: &[usize], start: usize) -> usize {
    let index = member_ends.partition_point(|&end| end <= start);
    if index == 0 {
        0
    } else {
        member_ends[index - 1]
    }
}
// local change, 5 Sep 2026 - RAR5 encoder hot paths; see VENDORING.md.
// Encoding has a different lookup direction from decoding. Keep these
// symbol-indexed codes separate so decoder tables and caches do not grow.
pub(crate) struct EncoderTable {
    pub(crate) codes: Vec<(u16, u8)>,
}
// local change, 3 Sep 2026 - nine bits keep the primary decode table
// in 2 KiB per role while the rare wider codes use the outlined canonical
// fallback. See VENDORING.md.
pub(crate) const HUFF_LUT_BITS: usize = 9;
// Symbol ids occupy bits 8..=23 and code lengths the low byte. Marking every
// literal in the otherwise-unused top bit turns the burst's per-symbol
// `wrapping_sub` + shift + branch into one bit-test branch while preserving
// zero as the generic decoder's cheap miss sentinel. Masked symbol extraction
// still lowers to one bitfield instruction. (local change, 3 Sep 2026;
// see VENDORING.md.)
pub(crate) const HUFF_LUT_LITERAL_BIT: u32 = 1 << 31;
pub(crate) const HUFF_LUT_LENGTH_MASK: u32 = 0xff;
pub(crate) const HUFF_LUT_MISS: u32 = 0;
// A distance-only LUT build caches its validated extra-bit count in bits
// 24..=28 and marks an invalid slot in bit 30. The shared symbol extractor
// masks both away. (local change, 3 Sep 2026; see VENDORING.md.)
pub(crate) const HUFF_LUT_DISTANCE_BITS_SHIFT: u32 = 24;
pub(crate) const HUFF_LUT_DISTANCE_BITS_MASK: u32 = 0x1f;
pub(crate) const HUFF_LUT_DISTANCE_INVALID_BIT: u32 = 1 << 30;
/// Literal entries set bit 31; controls and the miss sentinel leave it clear.
/// RAR control symbols begin at 256. Every other table's symbols are below
/// that boundary and carry the bit too, but the shared canonical decoder masks
/// it during symbol extraction and otherwise ignores it.
#[inline(always)]
pub(crate) fn lut_entry_is_literal(entry: u32) -> bool {
    entry & HUFF_LUT_LITERAL_BIT != 0
}
#[inline(always)]
pub(crate) fn lut_entry_symbol(entry: u32) -> usize {
    ((entry >> 8) & u32::from(u16::MAX)) as usize
}
/// What a distance table's entry carries beside its symbol and code
/// length (SPEC-H2 3.5): the slot's count of extra bits, none for the
/// first four slots and then one more for each pair of slots, or the
/// invalid mark alone for a slot whose count the entry's field cannot
/// hold, which a reader refuses.
#[inline]
pub(crate) fn distance_lut_metadata(slot: u16) -> u32 {
    let count = (u32::from(slot) / 2).saturating_sub(1);
    if count > HUFF_LUT_DISTANCE_BITS_MASK {
        return HUFF_LUT_DISTANCE_INVALID_BIT;
    }
    count << HUFF_LUT_DISTANCE_BITS_SHIFT
}
#[cfg(test)]
mod pointer_width_tests {
    use super::*;

    /// The long table's slot is a `u64` hash shifted down to below
    /// `long_entries`, so it fits a 32-bit `usize` for any span up to and
    /// past `u32::MAX` bytes. The span is a parameter of `long_entries`
    /// alone, so no 4 GiB input is built.
    #[test]
    fn the_long_slot_bound_holds_at_a_32_bit_pointer_width() {
        for span in [
            0usize,
            1 << 20,
            u32::MAX as usize - 1,
            u32::MAX as usize,
            // One past `u32::MAX` where a `usize` can state it; on a
            // 32-bit target that sum does not exist and this row is
            // `usize::MAX` again.
            (u32::MAX as usize).saturating_add(1),
            usize::MAX,
        ] {
            let entries = MatchIndex::<u32>::long_entries(span);
            assert!(entries <= LONG_INDEX_MAX_ENTRIES);
            let shift = 64 - entries.trailing_zeros();
            // The largest a shifted hash can be, on the widest hash.
            let widest = u64::MAX >> shift;
            assert!(widest < entries as u64);
            assert!(
                usize::try_from(widest).is_ok() && widest <= u64::from(u32::MAX),
                "span {span}: slot {widest} would not fit a 32-bit usize"
            );
        }
    }

    /// `flat_slack_with` at sizes just under and over `u32::MAX` stays at or
    /// under its ceiling, which is what makes its f64 to usize cast safe.
    #[test]
    fn the_flat_slack_never_passes_its_ceiling_near_4_gib() {
        let edge = u32::MAX as usize;
        // `edge + 1` where a `usize` can state it; on a 32-bit target the
        // row over the edge is the edge again.
        let over = edge.saturating_add(1);
        for output in [edge - 1, edge, over] {
            for history in [1 << 20, edge - 1, edge, over] {
                let slack = flat_slack_with(output, history, 1 << 16);
                assert!(slack <= history.max(1 << 16));
            }
        }
    }
}
