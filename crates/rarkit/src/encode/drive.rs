//! Driving a member through the finder, the parse and the entropy coder
//! (spec H3 section 8.3's structural requirements).
//!
//! The member is cut into PARSE BLOCKS of a fixed size. Two things happen
//! to each, and they are the only two that cost anything:
//!
//! 1. the carried binary tree match finder walks the block's positions and
//!    leaves its answers, a few distances per position, in a hint buffer;
//! 2. a parse turns the block and its hints into tokens, the boundary
//!    search cuts those into entropy blocks, and each is entropy coded.
//!
//! The finder is one structure shared by the whole member, walked by a
//! handful of threads that split its hash buckets between them; the parse
//! of a block touches nothing but its own hints, so blocks parse on every
//! other thread while the finder walks the blocks after them. Neither
//! split can move a byte of output: the finder's answers are the serial
//! walk's at any walker count (its own documentation says why), a parse
//! block's size is a constant, and a block's parse starts from an empty
//! repeated distance model. The number of blocks in flight is a memory
//! decision and nothing else.
//!
//! Working memory, stated in bytes as section 8.3 requires: the finder is
//! ten bytes per byte of dictionary (capped at the member's own length),
//! the hints are `4 * candidates` bytes per position of the blocks in
//! flight, held to [`HINT_BUDGET_BYTES`], and each block in flight holds
//! its tokens (eight bytes each) and its output. The member itself is
//! borrowed and never copied.

#[cfg(feature = "parallel")]
use super::chain::{Build, Piece, PIECE_MOST};
use super::chain::{Chains, Links, Pairing, EMPTY_ASK_EVERY, EMPTY_STRIDE, KEY_SHORT, KEY_WIDE};
use super::class;
use super::cut;
use super::filter::{encode_in_place, records_for, BlockRecord, FilterSpan, Placed};
use super::lz::{
    fast_parse, floor_scan, lazy_parse, optimal_parse, thin_scan as lz_thin_scan, Block, Format,
    OptimalDials, OptimalScratch, PriceModel, Source, Token, BACK_LIMIT, SCAN_LEAST, SCAN_STRIDE,
    THIN_SCAN_LEAST, THIN_SCAN_LINKS, THIN_SCAN_STRIDE,
};
use super::sample;
use crate::carry::h_ours::codec::rar50::tree::{
    empty_slots, BucketTrees, TREE_CANDIDATE_SLOTS, TREE_HEADS_PER_WINDOW, TREE_MAX_WINDOW,
    TREE_SKEW_BOUND,
};
use std::ops::Range;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

// The drive's parts, one module a seam.
#[cfg(all(feature = "bench-internals", feature = "parallel"))]
mod probe;
#[cfg(all(feature = "bench-internals", feature = "parallel"))]
pub use probe::*;
mod dials;
#[cfg(any(test, feature = "bench-internals"))]
#[allow(unused_imports)]
pub(crate) use dials::SLID_FLUSHES;
use dials::*;
#[allow(unused_imports)]
pub(crate) use dials::{
    batch_blocks, packed_most, tree_walkers_by_class, tree_walkers_most, BATCH_BLOCKS_MOST,
    BATCH_MEMBERS_MOST, BLOCK_ROOM_BYTES, FILTER_PIECE_BYTES, HINT_BUDGET_BYTES,
    HISTORY_SLACK_MULTIPLE, PARSE_BLOCK_BYTES, STREAMED_SLACK_LEAST_DICTIONARY,
    STREAMED_SLACK_MULTIPLE, TREE_WALKERS_FLOOR, WALK_BLOCKS, WIDE_WALK_LONG_LEAST,
};
#[cfg(feature = "bench-internals")]
#[allow(unused_imports)]
pub(crate) use dials::{slid_flushes, wave_arms};
#[cfg(feature = "parallel")]
#[allow(unused_imports)]
pub(crate) use dials::{CHAIN_BUILDERS_ENV, CHAIN_BUILD_ENV};
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use dials::{WIDE_WALKS, WIDE_WALK_FOR_TEST};
mod plan;
use plan::*;
#[allow(unused_imports)]
pub(crate) use plan::{
    LEVEL3_LINKS, LEVEL4_LINKS, LEVEL4_TREE_CUT, LEVEL5_CHAINS_LONG, LEVEL5_CHAINS_UNDER,
    LEVEL5_CUT, LEVEL5_LINKS, LEVEL5_SOLID_LINKS,
};
mod emit;
#[allow(unused_imports)]
pub(crate) use emit::{Emit, CARRY_MEMBERS_MOST, CARRY_MEMBER_BYTES};
mod block;
mod region;
mod sizing;
mod stage;
use block::*;
#[cfg(test)]
pub(crate) use stage::history_room;
mod chains;
mod tree;

/// One STAGED chunk of a carried run: where its bytes sit in the span the
/// finder walks, and whether the member ends with them.
///
/// A batch of these is what keeps the parse WIDE across the member
/// boundaries of a solid set. The two ends are there for different
/// reasons, and the second one is the whole of the byte identity:
///
/// - `start` is where tokens begin. Everything before it is HISTORY,
///   which the finder indexes and the parse never enters.
/// - `end` is where the SLICE the finder and the parse are handed stops,
///   and it is this member's own end even when the buffer already holds
///   the members after it. Both finders read a little way past a
///   position - `Links::insert` links nothing in the last three,
///   `Chains::search` answers nothing in them, the tree's descent
///   compares forward - so a member walked over a span that also held
///   the member AFTER it would answer differently. Truncated here, its
///   answers are the ones it had when it was the last thing in the
///   buffer, which is what a member at a time gave. A match cannot
///   reach past its own block's end either way (`lz`'s `room`), so no
///   parse wants a byte this hides.
#[derive(Clone, Copy)]
struct Segment {
    start: usize,
    end: usize,
    /// The member ends with this segment's last block.
    last: bool,
    /// The segment is a WHOLE member: it starts where a member starts
    /// and ends it. Only such a member may open on a carried table set.
    whole: bool,
}

impl Segment {
    /// How many parse blocks it is cut into.
    fn blocks(self) -> usize {
        (self.end - self.start).div_ceil(PARSE_BLOCK_BYTES)
    }

    /// Block `index` of it, as a byte range in the span.
    fn block(self, index: usize) -> Range<usize> {
        self.start + index * PARSE_BLOCK_BYTES
            ..(self.start + (index + 1) * PARSE_BLOCK_BYTES).min(self.end)
    }
}

/// One parse block of one flush, in the order the blocks are walked.
#[derive(Clone)]
struct Job {
    /// Which segment's block it is.
    segment: usize,
    /// Which of the flush's output buffers the block's packed bytes go
    /// to: its own segment's, or where the segments before it are earlier
    /// windows of the same member, the first of those
    /// ([`Engine::lend_first`] says why).
    out: usize,
    /// Which block of that segment, counted from the segment's own start,
    /// so the walk groups a batch of one member exactly as a member at a
    /// time grouped it.
    within: usize,
    bytes: Range<usize>,
    /// The member ends with this block.
    last: bool,
    /// The filter records this block writes ahead of its first token, in
    /// the flush's record list.
    records: Range<usize>,
}

/// What one call over a span covers apart from the segments it emits:
/// which of the span's positions the finder already holds, and how large
/// the span may grow before the run ends.
#[derive(Clone, Copy)]
struct Region {
    /// The first position the finder has NOT taken. Equal to the first
    /// segment's `start` when an index carried from an earlier call
    /// already holds all the history, which is the whole point of
    /// carrying one.
    indexed: usize,
    /// The finder starts empty and `indexed` is zero.
    fresh: bool,
    /// The largest this span reaches over the whole run, which is what
    /// the finder's structures are sized from: a carried index must not
    /// be thrown away merely because its span grew.
    sizing: usize,
}

impl Region {
    /// The same region over a finder that had to be built again, so
    /// nothing is indexed and the walk starts at the span's first
    /// position.
    fn rebuilt(self) -> Region {
        Region {
            indexed: 0,
            fresh: true,
            ..self
        }
    }
}

/// Which parse a level runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Parse {
    /// The fast parse (`lz::fast_parse`), level 1's since 1 Oct 2026: the
    /// held distances and one link of chains keyed on six bytes
    /// (`chain::KEY_WIDE`), taken greedily by a static price, with the
    /// entropy blocks cut blind (`cut::cut_blind`). It reads the chains
    /// only; no plan pairs it with the tree.
    Fast,
    Lazy,
    Optimal,
    /// The floor scan (`lz::floor_scan`): what a block the incompressible
    /// sample calls empty is parsed by. Never a level's own parse.
    Scan,
    /// The thin scan (`lz::floor_scan` at `lz::THIN_SCAN_STRIDE` and
    /// `lz::THIN_SCAN_LEAST`): what a block the sample reads thin is
    /// parsed by at level 3 ([`Plan::for_thin_block`]). Never a level's
    /// own parse.
    ThinScan,
}

/// Which match finder feeds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Finder {
    /// The hash chains of `chain`.
    Chain,
    /// The carried binary tree.
    Tree,
}

/// What a level asks of the finder and the parse.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Plan {
    pub(crate) parse: Parse,
    pub(crate) finder: Finder,
    /// How many candidates one position's search may visit: chain links,
    /// or tree nodes.
    pub(crate) depth: u32,
    /// How many distances the tree keeps per position.
    pub(crate) candidates: usize,
    /// A match this long ends a chain search.
    pub(crate) enough: usize,
    /// The optimal parse's own dials; the lazy parse reads neither.
    pub(crate) dials: OptimalDials,
    /// What a LONE member is parsed at instead: see [`Lone`].
    pub(crate) lone: Option<Lone>,
    /// Whether the tree's ring is widened so that its window is the whole
    /// dictionary ([`tree_ring`]) AND a slide keeps the tree's index
    /// ([`Engine::slide_keeps_index`]): set by the writer for a
    /// SOLID run only.
    pub(crate) wide_ring: bool,
    /// Whether the tree's ring is widened so that its window is the whole
    /// dictionary for a NON-SOLID run too, the slide untouched: levels 4
    /// and 5 (the non-solid wide ring, decided 30 Sep 2026:
    /// "whatever is the fastest is usually
    /// the right answer"). Without it a non-solid member's window is the
    /// dictionary less [`TREE_SKEW_BOUND`] while level 3's chains reach
    /// all of it, and a member that repeats 3.75 to 4 MiB back at a 4 MiB
    /// dictionary was written up to six times larger at level 5 than at
    /// level 3: counted on bin4g, the whole set at levels 4 and 5 went from
    /// MORE bytes than level 3 to fewer (measured 30 Sep 2026).
    /// It reaches only a member LONGER than that narrow reach
    /// ([`Engine::long`], SPEC-H3 section 4): a member at or under it keeps
    /// the narrow ring and its bytes, and a member short enough to be lone
    /// walks the chains, so the worker team's small members build no wider
    /// ring. [`Plan::optimal_tree`] clears it: the options keep their old
    /// bytes.
    pub(crate) full_reach: bool,
    /// Whether a block the incompressible sample calls empty is parsed by
    /// the FLOOR SCAN rather than the floor's lazy parse
    /// ([`Plan::for_empty_block`]): the chain levels 1 to 3,
    /// cleared at level 3 by [`Plan::lazy_floor`], never
    /// read from the parse or the finder.
    pub(crate) scans_floor: bool,
    /// Whether a block the incompressible sample reads THIN, worth
    /// searching but under `sample::THIN_UNDER_PER_MILLE`, is parsed by the
    /// THIN SCAN rather than the level's own parse
    /// ([`Plan::for_thin_block`]): level 3 of RAR 5 only (the RAR 2.9
    /// writer clears it), cleared by the options that keep level 3's
    /// earlier bytes.
    pub(crate) scans_thin: bool,
    /// Whether an empty block may be linked at the EMPTY STRIDE
    /// (`chain::EMPTY_STRIDE`): true but in level 1's priced form
    /// ([`Plan::without_empty_stride`]).
    pub(crate) empty_stride: bool,
    /// How far back the parse may begin a match the finder offered (the
    /// BACKWARD EXTENSION, `lz::BACK_LIMIT`), or 0 for none: on at level 3
    /// over the chains and at the lazy tree plans of levels 4 and 5
    /// ([`back_for`]), off at [`Plan::floor`], in a lone member's effort and
    /// in the optimal plans the options keep.
    pub(crate) back: usize,
    /// The FAR-LINK BUDGET of a chain search (`chain::FAR_FROM`,
    /// `WriteOptions::far_link_budget`): how many candidates farther than
    /// 2 MiB back one search may follow, or `None` for no budget, every
    /// link to the dictionary's end followed alike, which is every plan
    /// as built. Only [`Plan::far_links`] sets it, and the engine hands it
    /// to its chains at every flush (`Links::set_far_budget`). The tree
    /// and the fast parse's one link read nothing of it.
    pub(crate) far_links: Option<u32>,
    /// Which positions the lazy parse asks the chains at together
    /// (`chain::Pairing`): time only, never a byte, so every effort of a
    /// level keeps the level's.
    pub(crate) pair: Pairing,
    /// The level's OTHER effort, which a member takes by its class
    /// ([`Other`], `encode::class`): level 5 outside a solid run.
    pub(crate) other: Option<Other>,
}

/// The effort a level gives a member of the OTHER class (SPEC-H3 8.1,
/// "level 5 by class"): the lazy parse over the finder the level's own
/// plan does not walk.
///
/// The chains search only where the lazy parse asks and the tree searches
/// at every position, so which is the faster wall is a property of the
/// member's bytes: how many of a chain search's links lead far back, each
/// a cache miss (`encode::class`, far links a byte, read from the member's
/// first megabyte). Timed on aarch64 (20 cores, K=3, to the archive on
/// disk, 1 Oct 2026), level 5 over the
/// chains at 128 links against the tree, at one thread, four and the
/// default width: generated code (a head reading of 0.12) 1.83, 2.06
/// and 3.32 times faster; two real libraries of 83 and 139 MB (5.07 and
/// 5.48) 1.63, 1.33, 1.58 and 1.74, 1.58, 2.46; real source in one file
/// (5.6) 1.50, 1.15, 1.88; a sorted word list (7.20) 0.61, 0.50, 0.55;
/// real prose (7.56) 1.16, 0.85, 1.06 and (9.36) 1.02, 0.70, 0.86;
/// generated text (12.83) 1.02, 0.53, 0.61. Those rows set the cut-off;
/// the depth the chains' class then took is [`LEVEL5_LINKS`].
///
/// So LEVEL 5's own plan is the tree and its other effort the chains at
/// [`LEVEL5_LINKS`] links, taken by a member whose head reads UNDER
/// [`LEVEL5_CHAINS_UNDER`] and by a member too short to be read. A SOLID
/// run has one plan, since its finder carries its index from member to
/// member, and it is its FIRST member's class, with the chains at
/// [`LEVEL5_SOLID_LINKS`] ([`Plan::solid_run`]): the members after the
/// first are not read. A LONE member keeps its lone effort whichever
/// class it is.
///
/// **Level 4 has no other effort.** The tree at level 4 for a member
/// reading high was counted and timed for it (the remedy for generated
/// text at four threads) and not built: on aarch64 it was 22 percent
/// faster there at four threads and 53 percent slower at one, on x86-64
/// the other way round, and it would have charged the reading to every
/// member (decided 1 Oct 2026 on those rows).
/// `WriteOptions::level4_tree` stays the user's way to the tree.
///
/// **What a head cannot see.** A member whose first megabyte is unlike the
/// rest takes its head's class: 8 MiB of a library in front of 56 MiB of
/// generated text read 5.48 and took the chains, at [`LEVEL5_LINKS`] links
/// 1.43, 0.80 and 0.95 of the tree's speed on aarch64 at one thread, four
/// and the default width, and 0.86, 1.10 and 1.20 on x86-64. A named risk
/// of the rule; a second reading further into the member is not done yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Other {
    pub(crate) finder: Finder,
    pub(crate) depth: u32,
    pub(crate) candidates: usize,
    pub(crate) enough: usize,
    pub(crate) full_reach: bool,
    pub(crate) scans_floor: bool,
    pub(crate) back: usize,
    /// Who takes it.
    pub(crate) takes: Takes,
    /// The class's SECOND statistic: a head that holds this many long
    /// matches or more (`class::Reading::long_matches`) is the chains'
    /// whatever its far links read. None: the far links alone decide
    /// ([`Plan::far_links_only_level5`]).
    pub(crate) long: Option<u32>,
}

/// Who takes a level's other effort, by the reading of a head in
/// thousandths of a far link a byte (`encode::class`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Takes {
    /// A member whose head reads UNDER the cut-off, and a member with no
    /// reading (it is shorter than the head).
    Under(u32),
    /// A SOLID RUN whose first member's head reads AT OR OVER the cut-off:
    /// the run's own plan is the chains, which a run whose first member
    /// reads under it or has no reading keeps, and every member after the
    /// first follows its run ([`Plan::solid_run`]).
    RunAtOrOver(u32),
}

/// The effort a level gives a LONE member: a whole non-solid member short
/// enough to be one parse block, encoded from no history in one call. It
/// is the lazy parse over the level's own finder, searched `depth` links
/// deep and stopped at a match of `enough`.
///
/// **Why level 3 has one.** Measured 27 Sep 2026 on the rivals round's
/// small set (9,681 members of at most 16 KiB, 41.7 MB) one encoder a
/// member, RAR 5, 128 KiB dictionary, an Apple M3 Mac untimed: level 3's optimal
/// parse over chains took 43.3 G instructions for 12,386,234 packed bytes,
/// and the lazy parse 64 links deep 16.6 G for 12,408,807, 0.18% more. The
/// optimal parse visits every position of a member, where the lazy one
/// skips the inside of every match it takes, and on members this short its
/// pricing has little to work with: the gap is 0.13% to 0.27% for members
/// of 4 to 16 KiB and none below 4 KiB. It widens past 16 KiB (1.46% on
/// 32 KiB members, 1.01% on 64 KiB), which is where the ceiling first sat.
///
/// **One parse block since 28 Sep 2026** (SPEC-H3
/// 8.1). Level 3's optimal parse on the members between 16 and 256 KiB was
/// what a non-solid set of small files paid for: counted on 5,000 small
/// files of this repository's own tree (95 MB, members at most 256 KiB),
/// 18 cores, level 3 took 9.3 CPU seconds against the old engine's 1.66,
/// and with the bound at a parse block 1.82, for 2.06% more archive that
/// was still 5.1% under the old engine's.
/// Solid sets never take it (the writer clears it), so a member's bytes
/// cannot depend on the batch it was staged in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lone {
    /// The longest member that is lone.
    pub(crate) bytes: usize,
    pub(crate) parse: Parse,
    /// The finder the lone effort walks, which need not be the level's:
    /// at levels 4 and 5 it is the chains, so a small member
    /// is never walked by the tree.
    pub(crate) finder: Finder,
    pub(crate) depth: u32,
    pub(crate) enough: usize,
}

/// The table set in force when a member of a solid run ends: the code
/// lengths of every alphabet, in the format's own symbol order, from
/// which the canonical codes follow; and the symbol counts
/// of the members written since the chain's forced opener, which a set
/// opened inside the chain is built from. Both are state the encoder
/// carries from member to member in order, as it carries the history.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CarriedSet {
    pub(crate) lengths: Vec<u8>,
    pub(crate) counts: Vec<u32>,
    /// The canonical codes of `lengths`, built once when the set opens
    /// (or by the first member that carries it) and reused by every
    /// member after; empty until then.
    pub(crate) codes: Vec<super::bits::Code>,
}

/// A whole small member of a solid run, parsed and cut but not yet
/// written, held until the members before it are:
/// whether its first block may carry a set depends on theirs.
#[derive(Default)]
struct Deferred {
    tokens: Vec<Token>,
    cuts: Vec<Range<usize>>,
    records: Vec<BlockRecord>,
    /// Its symbol counts ([`Emit::add_counts`]), taken where it was
    /// parsed, so the chains read them without walking the tokens again.
    counts: Vec<u32>,
}

/// One carried-set chain, laid out before the parse
/// ([`Engine::plan_chains`]).
struct ChainPlan {
    /// Its members, as segments of the flush.
    start: usize,
    end: usize,
    /// The set carried into it from the flush before, where it continues
    /// that flush's last chain; `None` for a forced opener.
    carried: Option<CarriedSet>,
    /// The members on that set on entry.
    members: usize,
    /// A member that is not a whole small one stands before it, so the
    /// window starts empty.
    clear_window: bool,
}

/// A flush's chains while the parse feeds them.
struct ChainWork {
    chains: Vec<ChainPlan>,
    /// The next chain to take, in member order.
    next: usize,
    /// The counts of the whole small members before the next chain.
    window: std::collections::VecDeque<Vec<u32>>,
    window_on: bool,
    lookahead: bool,
    /// The set in force and the members on it after the last chain.
    end: Option<(Option<CarriedSet>, usize)>,
    /// The flush ends with a whole small member.
    trailing: bool,
    /// The flush ends with something else, so the window is emptied.
    gap_after: bool,
}

/// A chain taken for writing, its members in order.
struct ChainJob {
    chain: usize,
    members: Vec<(usize, Deferred)>,
    carried: Option<CarriedSet>,
    on_set: usize,
    seed: Option<Vec<u32>>,
}

/// What one worker keeps between blocks, so a block allocates nothing the
/// block before it already paid for.
struct Scratch {
    optimal: Option<OptimalScratch>,
    model: PriceModel,
    tokens: Vec<Token>,
    cuts: Vec<Range<usize>>,
    /// The fast parse's symbol counts, a table an entropy block
    /// (`lz::fast_parse`); empty after any other parse.
    counts: Vec<u32>,
    /// The most tokens `tokens` has held: what of its capacity is
    /// touched, and so resident (the stated figure counts lengths).
    tokens_most: usize,
}

impl Scratch {
    /// The bytes this scratch holds between blocks.
    fn held_bytes(&self) -> u64 {
        let optimal = self.optimal.as_ref().map_or(0, OptimalScratch::held_bytes);
        (self.tokens_most * std::mem::size_of::<Token>()
            + self.cuts.capacity() * std::mem::size_of::<Range<usize>>()
            + self.counts.capacity() * std::mem::size_of::<u32>()) as u64
            + optimal
            + self.model.held_bytes()
    }
}

/// Everything an encoder allocates, kept between members (section 8.3,
/// structural requirement 2). Its ceiling is set by the dictionary and the
/// plan alone (requirement 3); a member shorter than the dictionary is
/// given structures sized for it instead, because clearing 100 MiB to
/// encode 100 KiB is most of that member's wall. Nothing kept can reach a
/// member's bytes: `encode_span` says why for each structure.
pub(crate) struct Engine {
    /// The plan of the member being encoded: the level's own, or its other
    /// effort where the member's class takes it ([`Engine::start_member`]).
    plan: Plan,
    /// The level's plan, as the engine was built with it: what every run
    /// starts from ([`Engine::reset_history`]) and what the charges are
    /// computed from.
    own: Plan,
    /// The farthest back a match may reach.
    dictionary: usize,
    tree: Option<BucketTrees>,
    chains: Option<Chains>,
    hints: Vec<AtomicU32>,
    /// One per parse this engine has had in flight at once, kept between
    /// blocks and members: SPEC-API 8.2's parse waves' units.
    scratches: Mutex<Vec<Scratch>>,
    /// The block output buffers of the widest wave so far, given back
    /// once a wave's blocks are appended and handed out again, so a block
    /// allocates no output of its own ([`block_out_bytes`]).
    spare_outs: Mutex<Vec<Vec<u8>>>,
    /// The most blocks the tree's walk has PARSED at once, where a
    /// caller's memory budget holds it ([`Engine::hold_parses`]);
    /// `usize::MAX`, the pool's width, otherwise.
    parses: usize,
    /// The most blocks of a chains' wave, where the writer holds it
    /// ([`Engine::hold_chain_width`]); `usize::MAX`, the wave's own width,
    /// otherwise.
    chain_width: usize,
    /// The most parse blocks one flush of this run will stage, as the
    /// writer planned it ([`Engine::plan_flush`]): the tree's hints are
    /// built for that many at once rather than grown member by member.
    flush_blocks: usize,
    /// The most tree walkers this engine may put to work:
    /// `WriteOptions::workers` (API 7.2 and 8.2), the encoder's own width
    /// dial and the only thing `-mt<n>` moves on the create path.
    /// `usize::MAX` means "no ceiling of my own", and the box's own width
    /// still applies. It is not a memory figure: the memory ceiling is
    /// `MemoryPolicy::max_workers` and bounds other stages.
    workers: usize,
    /// The chains' pass built across the pool ([`Build`]), kept between
    /// waves; and the width from which it is, [`chain_build_from`].
    #[cfg(feature = "parallel")]
    build: Mutex<Build>,
    #[cfg(feature = "parallel")]
    build_from: usize,
    /// Whether this engine's chain waves slide, where a test says
    /// (`Engine::set_waves_slide`); the shipped setting otherwise.
    #[cfg(all(test, feature = "parallel"))]
    slide: Option<bool>,
    /// The carried history of spec H3 section 4: the bytes the decoder's
    /// window already holds when the next region is decoded, with the
    /// finder's index live over them. Empty outside a carried run.
    history: Vec<u8>,
    /// The most bytes `history` has held: what of its capacity is
    /// touched (the stated figure counts lengths), which [`Engine::held_bytes`]
    /// reports. Its capacity may run ahead of it (`Engine::stage`).
    history_most: usize,
    /// How many of `history`'s positions the finder has taken.
    indexed: usize,
    /// Whether the finder holds an index over `history`.
    carried: bool,
    /// How far the history may run past the dictionary before it is slid
    /// down. Set once from the dictionary; a test shrinks it so that a
    /// slide happens over bytes a test can afford.
    slack: usize,
    /// The largest capacity this run has asked for, which is what the
    /// finder's structures are sized from. It only grows inside a run,
    /// so a carried index is never thrown away because a later chunk
    /// asked for less.
    sized_for: usize,
    /// The chunks staged for the next flush, in staging order: a BATCH,
    /// which is what keeps the parse wide across the member boundaries of
    /// a solid set. Empty outside a batch.
    staged: Vec<Segment>,
    /// One packed output per staged chunk, in staging order. Owned here
    /// and reused, so a batch allocates nothing per member once it has
    /// held a batch that long (spec G 7.3).
    outs: Vec<Vec<u8>>,
    /// The blocks of one flush. Reused.
    jobs: Vec<Job>,
    /// Whether each finder's HEADS are already empty, so that a fresh run
    /// need not clear them (`Engine::forget`). False once any walk has
    /// inserted a position, until a forget or a clear empties them again.
    /// One flag a finder, since one engine may walk both.
    tree_clean: bool,
    chains_clean: bool,
    /// The finder the last span was walked by, whose heads a forget
    /// empties.
    walked: Finder,
    /// The stride an empty block is linked at under this engine: the
    /// shipped [`EMPTY_STRIDE`] (`dials::empty_stride`), or 1 for none,
    /// under a plan without it ([`Plan::without_empty_stride`]) and under
    /// the RAR 2.9 method's encoder ([`Engine::without_empty_stride`]).
    empty_stride: usize,
    /// Whether the call in progress encodes one LONE member ([`Lone`]).
    lone: bool,
    /// Whether the member of the run in progress is LONGER than the tree's
    /// narrow reach, the dictionary less [`TREE_SKEW_BOUND`]: the members
    /// [`Plan::full_reach`] widens the ring for (the non-solid wide ring,
    /// SPEC-H3 section 4). Set where a member starts a run and kept for
    /// its later windows.
    long: bool,
    /// The filter spans of the chunks staged for the next flush, by their
    /// positions in `history`, already transformed there. Empty outside a
    /// batch and wherever no filter runs.
    placed: Vec<Placed>,
    /// A copy the delta transform reads from. Reused.
    filter_scratch: Vec<u8>,
    /// The carried tree's index outlived a slide
    /// ([`Engine::stage_filtered`]), so it holds positions of bytes the
    /// history no longer has, and a forget over the history would miss
    /// the heads they wrote: the run's end clears every head instead.
    slid: bool,
    /// The carried state between the members of a solid run: the table
    /// set in force after the last member written, where it is known.
    carry: Option<CarriedSet>,
    /// How many members share `carry`'s chain so far, the one that
    /// opened it included; at [`CARRY_MEMBERS_MOST`] the next opens.
    carry_members: usize,
    /// A chunk staged last did not end its member, so the next one does
    /// not start one.
    mid_member: bool,
    /// Which segments of the flush in progress are whole small members
    /// written by the carried-set chains rather than as they are parsed.
    defers: Vec<bool>,
    /// The flush's chains, fed by the parse as members finish
    /// ([`Engine::member_parsed`]).
    chain_work: Mutex<Option<ChainWork>>,
    /// Which chain each segment's member is in, for the flush in progress.
    chain_of: Vec<Option<usize>>,
    /// Each deferred member's parse, left by the worker that parsed it.
    chain_cells: Vec<Mutex<Option<Deferred>>>,
    /// How many of each chain's members are not parsed yet: the worker
    /// that brings one to zero takes the ordered lock, and no other does.
    chain_missing: Vec<AtomicUsize>,
    /// Carried sets off: every member opens a fresh set, as at first (a
    /// count build's control arm, [`carry_off`]).
    carry_off: bool,
    /// A count's LOOKAHEAD arm ([`carry_lookahead`]): a chain's forced
    /// opener builds its set from every member of its chain.
    carry_lookahead: bool,
    /// The symbol counts of the whole small members written last in this
    /// run, at most [`CARRY_MEMBERS_MOST`] of them, oldest first: what a
    /// chain's forced opener builds its set from beside its own counts
    /// (the WINDOW form). Emptied where the chain is broken.
    carry_window: std::collections::VecDeque<Vec<u32>>,
    /// The window form on ([`carry_window_on`]).
    carry_window_on: bool,
    /// The most bytes of blocks one flush parses at once, about, which
    /// sizes the finder's in-flight structures: `usize::MAX`, the widest
    /// the finder allows, unless a caller's memory budget holds it lower
    /// ([`Engine::hold_wave`]).
    wave: usize,
    /// How many engines' flushes run on this engine's pool at the same
    /// time, its own among them (the writer's segment team,
    /// [`Engine::share_pool`]); zero or one, alone.
    #[cfg(feature = "parallel")]
    shares_pool: usize,
    /// Whether the member in progress keeps the tree BY ITS OWN CLASS: a
    /// whole non-solid member whose head [`Engine::start_member`] read and
    /// found over the cut-off, with [`WIDE_WALK_LONG_LEAST`] long matches
    /// or more. Its walk takes [`tree_walkers_by_class`];
    /// every other walk takes [`tree_walkers_most`]. A width, never a byte.
    tree_by_class: bool,
}

impl Engine {
    /// This engine with no empty stride: the RAR 2.9 method's encoder's.
    ///
    /// Counted 16 Oct 2026 (FROM-STUDIO 496 A): on a member of text,
    /// 600,000 bytes of noise and text again, every stride from 2 to 16
    /// left the parse a few matches short in the block where the noise
    /// meets the text, and the RAR 2.9 method's entropy cut then took
    /// two cuts there where it had taken three, about 1,500 bytes more,
    /// 0.18 to 0.22 percent of the member at levels 2 to 5. RAR 5's cut
    /// does not flip there, and a media set is a RAR 5 archive.
    pub(crate) fn without_empty_stride(mut self) -> Engine {
        self.empty_stride = 1;
        self
    }

    /// An engine that has allocated nothing yet: the first member pays.
    pub(crate) fn new(plan: Plan, dictionary: usize, workers: usize) -> Engine {
        Engine {
            plan,
            own: plan,
            dictionary: dictionary.max(1),
            workers: workers.max(1),
            empty_stride: if plan.empty_stride { empty_stride() } else { 1 },
            #[cfg(feature = "parallel")]
            build: Mutex::new(Build::default()),
            #[cfg(feature = "parallel")]
            build_from: chain_build_from(),
            #[cfg(all(test, feature = "parallel"))]
            slide: None,
            tree: None,
            chains: None,
            hints: Vec::new(),
            scratches: Mutex::new(Vec::new()),
            spare_outs: Mutex::new(Vec::new()),
            flush_blocks: 0,
            parses: usize::MAX,
            chain_width: usize::MAX,
            history: Vec::new(),
            history_most: 0,
            indexed: 0,
            carried: false,
            slack: dictionary
                .saturating_mul(HISTORY_SLACK_MULTIPLE)
                .min(HISTORY_SLACK_CEIL),
            sized_for: 0,
            staged: Vec::new(),
            outs: Vec::new(),
            jobs: Vec::new(),
            tree_clean: true,
            chains_clean: true,
            walked: plan.finder,
            slid: false,
            carry: None,
            carry_members: 0,
            mid_member: false,
            defers: Vec::new(),
            chain_work: Mutex::new(None),
            chain_of: Vec::new(),
            chain_cells: Vec::new(),
            chain_missing: Vec::new(),
            carry_off: carry_off(),
            carry_lookahead: carry_lookahead(),
            carry_window: std::collections::VecDeque::new(),
            carry_window_on: carry_window_on(),
            lone: false,
            long: false,
            placed: Vec::new(),
            filter_scratch: Vec::new(),
            wave: usize::MAX,
            #[cfg(feature = "parallel")]
            shares_pool: 0,
            tree_by_class: false,
        }
    }

    /// Hold every flush to about `bytes` of blocks in flight, and size
    /// the finder's in-flight structures to that rather than to the
    /// widest the finder allows. At least one parse block.
    ///
    /// For a writer under a CALLER'S memory budget, which is
    /// hard. Neither structure's size can reach a byte of output; what it
    /// sets is how many blocks are parsed at once, and so the wall. Never
    /// called at the default policy, whose path is the one it was.
    ///
    /// - The CHAINS' cyclic buffer holds the reach and one such wave
    ///   ([`Chains::new`]): at a 2 MiB dictionary the floor keeps 16 Mi
    ///   links, 64 MiB, where a windowed member's 2 MiB flush is parsed in
    ///   one wave of eight blocks by 4 Mi (`Chains::wave_bytes`).
    /// - The TREE'S hints are held to whole walk groups of [`WALK_BLOCKS`]
    ///   and only in a flush of ONE segment ([`Engine::hint_width`]). A
    ///   wave's end cuts the walk's groups and a walk's hints follow its
    ///   group, so a width that cut a group differently would move bytes
    ///   (a width of one block did, at level 5, in the test that pins
    ///   this). In one segment the groups start at its multiples of
    ///   [`WALK_BLOCKS`], and so does every wave of a whole number of
    ///   groups: the cut is the unheld one. A solid batch spans segments
    ///   and is not held.
    pub(crate) fn hold_wave(&mut self, bytes: usize) {
        self.wave = bytes.max(PARSE_BLOCK_BYTES);
    }

    /// Parse at most `parses` of the tree's blocks at once, at least one.
    ///
    /// For a writer under a CALLER'S memory budget, where a
    /// hold of the hints to one walk group is not narrow enough: each
    /// parse in flight holds a block's tokens and the optimal parse's
    /// window, about 2.6 MiB. A block's parse reads its own block and its
    /// own hints and nothing another parse writes, so how many run at once
    /// moves no byte. Never called at the default policy, whose path is
    /// the one it was; the chains are held by [`Engine::hold_chain_width`].
    pub(crate) fn hold_parses(&mut self, parses: usize) {
        self.parses = parses.max(1);
    }

    /// Hold the CHAINS' wave to `blocks` blocks, at least one: at most that
    /// many linked ahead of the oldest still being parsed
    /// (`Engine::with_chains`), so at most that many parses in flight. How
    /// many blocks make a wave moves no byte, as that function says.
    ///
    /// A held wave ([`Engine::hold_wave`]) does not bound them at a long
    /// dictionary: at 32 MiB the cyclic buffer is 64 Mi links held or not,
    /// a wave is every block of an 8 MiB window, and on 96 threads the
    /// parses in flight stood at 69 to 72 MiB (counted 3 Oct 2026 under
    /// real cgroup limits). The
    /// writer holds them only where an environment's cap binds and no plan
    /// fits it (`Run::parses_under_cap`); nothing else calls this.
    pub(crate) fn hold_chain_width(&mut self, blocks: usize) {
        self.chain_width = blocks.max(1);
    }

    /// The walkers a walk of this engine takes: the pool's width, the cap
    /// ([`tree_walkers_most`], or [`tree_walkers_by_class`] for a member
    /// that keeps the tree by its own class) and `WriteOptions::workers`,
    /// whichever is least.
    ///
    /// No walk is held under the cap. A solid volume set's was, at
    /// [`TREE_WALKERS_FLOOR`], from the cap's land of 1 Oct 2026 until such
    /// a set was batched the same day: a member at a time, 24 walkers read
    /// 0.97x of 12 on an M3 Ultra; batched, 1.04x at level 5 and level at
    /// level 4.
    pub(crate) fn walkers(&self) -> usize {
        let cap = if self.tree_by_class {
            tree_walkers_by_class()
        } else {
            tree_walkers_most()
        };
        threads().min(cap).min(self.workers)
    }

    /// The most walkers any walk of this engine may take, whatever its
    /// member's class: what the writer is CHARGED for
    /// ([`Engine::flight_term_over`]), since the charge is taken before a
    /// member's head is read.
    fn walkers_charged(&self) -> usize {
        threads().min(tree_walkers_by_class()).min(self.workers)
    }

    /// Tell the engine the most bytes one flush of this run will stage:
    /// the tree's hints are then built ONCE, for that many blocks, the
    /// first time a flush needs any.
    ///
    /// Without it the hints grew with the members: a member of one block
    /// built 4 MiB of them, one of two dropped those and built 8, then 12,
    /// then 32, and on macOS 27.0 the allocator keeps a freed block that
    /// large RESIDENT in its large-block cache, so the 24 MiB dropped on
    /// the way stayed in the process's RSS beside the 32 in use (tree5k
    /// at -m5 -mm96: RSS 113 MiB against 91 of live heap, 90 with the
    /// cache switched off). The width a flush
    /// walks is [`Engine::hint_width`]'s either way, so no byte moves;
    /// what changes is only how often the buffer is rebuilt.
    pub(crate) fn plan_flush(&mut self, bytes: usize) {
        self.flush_blocks = bytes.div_ceil(PARSE_BLOCK_BYTES);
    }

    /// How many builders the chains' pass takes for a wave of `width`
    /// blocks: one, the pass as it always ran, below [`chain_build_from`]
    /// and for a wave of one block; else the pool's width, held to
    /// `WriteOptions::workers` and to [`chain_builders_most`], whatever
    /// the wave, so that what the build keeps does not follow the member
    /// ([`Build::held_bytes`]). A caller's memory budget holds the pass to
    /// one.
    fn chain_builders(&self, width: usize) -> usize {
        #[cfg(feature = "parallel")]
        {
            let threads = threads().min(self.workers);
            if width < 2 || threads < self.build_from || self.wave != usize::MAX {
                return 1;
            }
            threads.min(chain_builders_most())
        }
        #[cfg(not(feature = "parallel"))]
        {
            let _ = width;
            1
        }
    }

    /// Slide this engine's chain waves or not, for a test to take either
    /// arm in one binary ([`Engine::chains_sliding`]).
    #[cfg(all(test, feature = "parallel"))]
    pub(crate) fn set_waves_slide(&mut self, on: bool) {
        self.slide = Some(on);
    }

    /// Whether this engine's chain waves slide: [`waves_slide`], or what a
    /// test set.
    #[cfg(feature = "parallel")]
    fn slides(&self) -> bool {
        #[cfg(test)]
        if let Some(on) = self.slide {
            return on;
        }
        waves_slide()
    }

    /// Build the chains' pass across the pool from `width` threads up,
    /// for a test to take either arm in one binary.
    #[cfg(all(test, feature = "parallel"))]
    pub(crate) fn set_chain_build_from(&mut self, width: usize) {
        self.build_from = width.max(2);
    }

    /// Never build the chains' pass across the pool: for an encoder that
    /// runs beside a worker team (`Run::lead_builds` in the writer), whose
    /// crews already have the width and whose ceiling the build's tables
    /// would narrow. It moves no byte.
    pub(crate) fn no_chain_build(&mut self) {
        #[cfg(feature = "parallel")]
        {
            self.build_from = usize::MAX;
        }
    }

    /// Whether this run's tree index has outlived a slide, for the test
    /// that holds a slid solid run to its archive.
    #[cfg(test)]
    pub(crate) fn slid_for_test(&self) -> bool {
        self.slid
    }

    /// Turn the carried sets off (every member opens a fresh
    /// set, as at first) or on, for the tests that compare the
    /// two.
    #[cfg(test)]
    pub(crate) fn carry_off_for_test(&mut self, off: bool) {
        self.carry_off = off;
    }

    /// Slide the carried history after this many bytes past the
    /// dictionary rather than after the shipped slack, so a test can pay
    /// for a slide. A slide keeps the dictionary and, outside a solid
    /// run's tree, rebuilds the index over it. That rebuild links the
    /// positions no call had linked, a chunk's last three, so where a run
    /// slides can move a few bytes of a run streamed in chunks
    /// ([`STREAMED_SLACK_MULTIPLE`] has the count); what the test this is
    /// for holds is the rest of the slide.
    #[cfg(feature = "bench-internals")]
    pub(crate) fn set_history_slack(&mut self, bytes: usize) {
        self.slack = bytes.max(1);
    }

    /// Let the carried history run `multiple` dictionaries past the
    /// dictionary before it slides (at most [`HISTORY_SLACK_CEIL`]), from
    /// the next staged chunk on. [`HISTORY_SLACK_MULTIPLE`] is what every
    /// engine starts at; [`STREAMED_SLACK_MULTIPLE`] says who sets another
    /// and what it moves. It is set with nothing staged, and where it
    /// changes a run's slides, before the run's first chunk.
    pub(crate) fn set_slack_multiple(&mut self, multiple: usize) {
        debug_assert!(self.staged.is_empty(), "a slack set with nothing staged");
        self.slack = self
            .dictionary
            .saturating_mul(multiple)
            .min(HISTORY_SLACK_CEIL);
    }

    /// Forget the carried history: the next chunk starts a run of its
    /// own, as the first member of a solid set does and as every member
    /// of a NON-solid set does (spec H3 section 4). The buffer's memory
    /// is kept, so nothing allocates per member.
    pub(crate) fn reset_history(&mut self) {
        debug_assert!(
            self.staged.is_empty(),
            "a batch is flushed before a run ends"
        );
        // A carried index covers exactly the history's own positions, so
        // the heads it wrote are the history's words' buckets: unless it
        // outlived a slide, whose dropped bytes wrote heads too. Then the
        // heads stay unclean and the next run clears them all.
        if self.carried && !self.slid {
            let history = std::mem::take(&mut self.history);
            self.forget(&history);
            self.history = history;
        }
        self.staged.clear();
        self.placed.clear();
        self.history.clear();
        self.indexed = 0;
        self.carried = false;
        self.sized_for = 0;
        self.slid = false;
        // A run's first member has its solid bit clear, and a reader
        // starts its stream there, with no set in force.
        self.carry = None;
        self.carry_members = 0;
        self.carry_window.clear();
        self.mid_member = false;
        // And it starts from the level's own plan: a member's class is the
        // member's, set after this where the run is one member
        // ([`Engine::start_member`]).
        self.plan = self.own;
        self.tree_by_class = false;
    }

    /// Start a run that is ONE whole member of `size` bytes, encoded from
    /// no history: forget the carried history ([`Engine::reset_history`])
    /// and take the plan the member's class gives it
    /// ([`Plan::for_member`]). `head` is the member's first bytes as they
    /// are BEFORE any filter, at least `class::HEAD_BYTES` of them where
    /// [`Plan::reads_head`] says they are read.
    ///
    /// The entries that are handed a whole member in one call
    /// ([`Engine::encode_region`], [`Engine::encode_whole_run`]) do this
    /// themselves. A writer that feeds a member a window at a time calls it
    /// where it would have called [`Engine::reset_history`]. In a SOLID run
    /// it is the run's first member that is started this way, and the plan
    /// it takes is the run's ([`Plan::solid_run`]): the members after it
    /// are never started, and follow it.
    pub(crate) fn start_member(&mut self, head: &[u8], size: u64) {
        self.reset_history();
        // The reading stands in front of the member's whole encode, so it
        // is taken on the pool the encode will run on.
        let workers = threads().min(self.workers);
        let (plan, kept) = self.own.for_member_read(head, size, workers);
        self.plan = plan;
        // The member keeps the tree by its own class, and its head holds
        // long matches enough for a wide walk to gain
        // ([`WIDE_WALK_LONG_LEAST`]): its head was read, the level has
        // another effort and the member did not take it, and the plan is
        // no solid run's (a run's later members are not read).
        self.tree_by_class = !self.own.wide_ring
            && self.plan.finder == Finder::Tree
            && self.plan.parse == Parse::Lazy
            && kept.is_some_and(|reading| reading.long_matches() >= WIDE_WALK_LONG_LEAST);
    }

    /// Whether [`Engine::start_member`] reads the head of a member of
    /// `size` bytes.
    pub(crate) fn reads_head(&self, size: u64) -> bool {
        self.own.reads_head(size)
    }

    /// Say whether other engines flush on this engine's pool while it does
    /// (the writer's segment team). It changes one thing, and no byte:
    /// what the thread that drives a sliding flush does while it waits for
    /// a block ([`Engine::chains_sliding`]). Alone on its pool it sleeps
    /// unless a pool's worth of parses is queued, so that its pass is
    /// never kept from the next block by a parse it took; the other
    /// threads run what it queued. With several engines on one pool each
    /// has such a thread, and were they all to sleep, their queued parses
    /// would have nobody: so a sharing engine's driver runs a queued
    /// parse whenever there is one, and sleeps only when every parse it
    /// spawned is already running, each of which wakes it when it ends.
    #[cfg(feature = "parallel")]
    pub(crate) fn share_pool(&mut self, engines: usize) {
        self.shares_pool = engines;
    }

    /// Put this engine where an engine that has just SLID its history
    /// stands, in the middle of a member, with `kept` the dictionary the
    /// slide kept: no index, nothing staged, the next staged chunk a later
    /// window of the member the kept bytes end.
    ///
    /// **What it is for.** Outside a solid run's tree a slide drops the
    /// index with the bytes it named ([`Engine::stage_filtered`]), and the
    /// next flush builds one over the kept dictionary alone. So what an
    /// engine writes between two slides is a function of the dictionary
    /// the first one kept and of the bytes staged since, and of nothing
    /// before them: every parse block starts from an empty repeat model,
    /// every flush's first block of a member carries its tables, and a
    /// search follows no link farther back than the dictionary. A member
    /// streamed a window at a time is therefore a row of such stretches
    /// ([`Engine::streamed_period`] says where each ends), and an engine
    /// resumed here writes the stretch that follows `kept` byte for byte
    /// as the one engine that slid there does. The writer's segment team
    /// runs several of them at once (`write::engine`).
    ///
    /// Not for a solid run's tree, which keeps its index across a slide
    /// ([`Engine::slide_keeps_index`]); the writer resumes chain levels
    /// outside a solid run only.
    pub(crate) fn resume_slid(&mut self, kept: &[u8]) {
        debug_assert!(!self.plan.wide_ring, "a solid run is never resumed");
        debug_assert!(kept.len() <= self.dictionary, "a slide keeps a dictionary");
        self.reset_history();
        self.history.extend_from_slice(kept);
        self.history_most = self.history_most.max(self.history.len());
        self.mid_member = true;
    }

    /// Transform, in the history an engine was just resumed with
    /// ([`Engine::resume_slid`]), the filter spans `plan` names in the
    /// window that begins `at` bytes into it, `base` that window's offset
    /// in its member: what [`Engine::stage_filtered`] did to the same
    /// window when the one engine staged it, so the resumed history holds
    /// the bytes the decoder's window will, as the slid one did. No record
    /// is placed: the window's own flush wrote its records.
    pub(crate) fn filter_kept(&mut self, at: usize, plan: &[FilterSpan], base: u64) {
        debug_assert!(
            self.staged.is_empty(),
            "a history resumed and not yet staged on"
        );
        for filter in plan {
            let from = at + filter.start;
            encode_in_place(
                filter.kind,
                &mut self.history[from..from + filter.len],
                base + filter.start as u64,
                &mut self.filter_scratch,
            );
        }
    }

    /// How many of the next `left` bytes of a member, staged in windows of
    /// `window` (the last one shorter), this engine takes before its
    /// history slides, from a history of `history` bytes: the arithmetic
    /// of [`Engine::stage_filtered`]'s slide, which reads the lengths and
    /// nothing of the bytes. At least one window, since a chunk is never
    /// split and a slide makes room for the chunk it is for.
    #[cfg(feature = "parallel")]
    pub(crate) fn streamed_period(&self, window: usize, history: usize, left: u64) -> u64 {
        let window = window.max(1);
        let mut held = history;
        let mut taken = 0u64;
        while taken < left {
            let chunk = (left - taken).min(window as u64) as usize;
            if taken > 0 && held + chunk > self.history_cap(chunk) {
                break;
            }
            held += chunk;
            taken += chunk as u64;
        }
        taken
    }

    /// How many bytes a slide keeps of a history of `history` bytes: the
    /// dictionary, or all of a shorter history.
    #[cfg(feature = "parallel")]
    pub(crate) fn kept_by_slide(&self, history: usize) -> usize {
        self.dictionary.min(history)
    }

    /// The finder the call in progress walks: the lone effort's while one
    /// LONE member is encoded, else the level's.
    fn finder_now(&self) -> Finder {
        match self.plan.lone {
            Some(lone) if self.lone => lone.finder,
            _ => self.plan.finder,
        }
    }

    /// Whether this engine's finder is the binary tree (levels 4 and 5)
    /// rather than the hash chains.
    ///
    /// True too where only the level's OTHER effort walks the tree (level
    /// 4 by class): a run of that level may build one, and what a writer
    /// charges and holds for the tree has to allow for it.
    pub(crate) fn walks_tree(&self) -> bool {
        self.own.finder == Finder::Tree
            || self
                .own
                .other
                .is_some_and(|other| other.finder == Finder::Tree)
    }

    /// The effort the member in progress is encoded by: the level's own
    /// plan, or its other effort where the member's class took that
    /// ([`Engine::start_member`]). What an engine handed a later stretch of
    /// the same member is to walk it by ([`Engine::walk_member_by`]).
    #[cfg(feature = "parallel")]
    pub(crate) fn member_effort(&self) -> Plan {
        self.plan
    }

    /// Encode what follows by `effort`, a plan another engine of the same
    /// level read off the member's head ([`Engine::member_effort`]). Called
    /// after [`Engine::reset_history`] or [`Engine::resume_slid`], which put
    /// the level's own plan back.
    pub(crate) fn walk_member_by(&mut self, effort: Plan) {
        self.plan = effort;
    }

    /// Whether the member in progress is parsed lazily over the hash
    /// chains, whatever the level's own plan walks: the effort the writer's
    /// segment team may split by stretches.
    #[cfg(feature = "parallel")]
    pub(crate) fn member_walks_lazy_chains(&self) -> bool {
        self.plan.finder == Finder::Chain && self.plan.parse == Parse::Lazy
    }

    /// The plan this engine walks the TREE by: the member's in progress
    /// where that is the tree's, else whichever of the level's own plan
    /// and its other effort walks it. What the tree's geometry and its
    /// hints are sized from, by the encode and by the charges alike.
    fn tree_effort(&self) -> Plan {
        if self.plan.finder == Finder::Tree {
            return self.plan;
        }
        if self.own.finder == Finder::Tree {
            return self.own;
        }
        match self.own.other() {
            Some(other) if other.finder == Finder::Tree => other,
            _ => self.plan,
        }
    }
}

/// What [`Engine::chains_sliding`] links with: the heads and links, and
/// where the pass is built across the pool ([`Engine::chain_builders`]),
/// the build, its width and the history's pieces not yet linked.
#[cfg(feature = "parallel")]
struct Pass<'a> {
    heads: &'a mut [u32],
    links: &'a super::chain::Links,
    builders: usize,
    build: &'a mut Build,
    history: Vec<Piece>,
}

/// Adds one to its counter when dropped (`Engine::with_tree_overlapped`).
#[cfg(feature = "parallel")]
struct Counted<'a>(&'a AtomicUsize);

#[cfg(feature = "parallel")]
impl Drop for Counted<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Release);
    }
}
