//! What the two encoders share above the wire: the token, the decoder's
//! repeated distance model, and the two parses (spec H3 sections 6.4,
//! 7.3 and 8.3).
//!
//! A parse turns one PARSE BLOCK of the member into tokens. Parse blocks
//! are a fixed size and each starts from an empty repeated distance model,
//! so a block's tokens depend on the member's raw bytes alone and never on
//! another block's output: that is what lets blocks be parsed on any
//! number of threads and still give byte identical output (API promise 6).
//! The decoder's own model is NOT empty at a block's start, and that is
//! sound: the encoder only ever names a repeat slot it filled itself, the
//! filled slots are always a prefix of the four, and both a push and a
//! rotation keep a prefix a prefix.
//!
//! The parses, by level:
//!
//! - **fast**: the held distances and the one nearest position of a six
//!   byte chain, scored by a static price, taken greedily. Level 1.
//! - **lazy**: the finder's candidates scored against the repeated
//!   distances in bits saved, with one byte of lookahead.
//! - **optimal**: every reachable token over a window of positions priced
//!   from the previous region's own symbol statistics, cheapest path kept.
//!   Section 8.3 says what it optimises: the bits the entropy coder will
//!   write, with the repeated distance model carried through the search.

use super::chain::{common_prefix, Found, Links, Pairing, FOUND_MAX, KEY_WIDE};
use super::cut::BLIND_CUT_BYTES;
use crate::carry::c_lz::codec::rar50::{
    log2_sixteenths, ENTROPY_BLOCK_BYTES, ENTROPY_BLOCK_MIN_TOKENS, OPTIMAL_FIRST_REGION_BYTES,
    OPTIMAL_REPEAT_LENGTH_BUDGET, OPTIMAL_SHORT_LENGTH_BUDGET, OPTIMAL_SUFFICIENT_LENGTH,
    OPTIMAL_WINDOW_POSITIONS, PRICE_MAX, PRICE_MIN, PRICE_SHIFT,
};
use crate::carry::h_ours::codec::rar50::tree::common_prefix_inlined;
use std::ops::Range;
use std::sync::atomic::{AtomicU32, Ordering};

/// Repeated distances both formats remember.
pub(crate) const REPEATS: usize = 4;

/// Which arm of the format a token takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arm {
    Literal,
    /// A match at a distance the model does not hold.
    Fresh,
    /// A match at repeated distance `k`.
    Repeat(u8),
    /// The last match again: the same distance and the same length, for
    /// the price of one main symbol.
    Last,
    /// RAR 2.9 only: exactly two bytes at a distance of at most 256.
    Short,
}

/// One token of the stream, as the decoder will read it back. `length` is
/// the TRUE length: a bonus comes off when the slot is chosen.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Token {
    pub(crate) arm: Arm,
    pub(crate) length: u16,
    /// The distance, or the byte of a literal.
    pub(crate) distance: u32,
}

impl Token {
    #[inline]
    pub(crate) fn literal(byte: u8) -> Token {
        Token {
            arm: Arm::Literal,
            length: 1,
            distance: u32::from(byte),
        }
    }
}

/// The decoder's repeated distance model, tracked on the encode side so
/// the two never disagree.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Repeats {
    pub(crate) distance: [u32; REPEATS],
    pub(crate) last_length: u16,
}

impl Repeats {
    /// The model after `arm` at `distance` and `length`.
    #[inline]
    pub(crate) fn after(mut self, arm: Arm, distance: u32, length: u16) -> Repeats {
        match arm {
            Arm::Literal | Arm::Last => {}
            Arm::Fresh | Arm::Short => {
                self.distance = [
                    distance,
                    self.distance[0],
                    self.distance[1],
                    self.distance[2],
                ];
                self.last_length = length;
            }
            Arm::Repeat(k) => {
                // The chosen distance moves to the front and the ones
                // before it shift back; the ones after it do not move.
                let k = k as usize;
                let chosen = self.distance[k];
                self.distance.copy_within(0..k, 1);
                self.distance[0] = chosen;
                self.last_length = length;
            }
        }
        self
    }

    /// Which slot holds `distance`, if one does.
    #[inline]
    pub(crate) fn slot_of(&self, distance: u32) -> Option<u8> {
        self.distance
            .iter()
            .position(|&held| held == distance && held != 0)
            .map(|k| k as u8)
    }
}

/// A price no path takes.
pub(crate) const UNPRICED: u32 = u32::MAX / 2;

/// What a format tells the parses about itself. Every price is in
/// sixteenths of a bit, read from one flat array that lays the format's
/// alphabets end to end.
pub(crate) trait Format: Sync {
    /// Symbols in all the alphabets together.
    fn symbols(&self) -> usize;
    /// Where each alphabet sits in the flat array.
    fn alphabets(&self) -> &[Range<usize>];
    /// What a symbol of alphabet `index` costs before any statistics exist.
    fn opening_price(&self, index: usize) -> u16;
    /// The longest match the fresh arm can name, as a true length.
    fn longest(&self) -> usize;
    /// The longest the repeated distance arm can name.
    fn longest_repeat(&self) -> usize;
    /// The length bonus a fresh match's distance earns.
    fn bonus(&self, distance: u32) -> u32;
    /// Everything a fresh match at `distance` pays apart from its length.
    fn fresh_distance_price(&self, prices: &[u16], distance: u32) -> u32;
    /// What the fresh arm pays for a length, the bonus already taken off;
    /// [`UNPRICED`] where the ladder cannot name it.
    fn fresh_length_price(&self, prices: &[u16], encoded: u32) -> u32;
    /// What repeated distance `k` pays for `length`.
    fn repeat_price(&self, prices: &[u16], k: usize, length: u32) -> u32;
    /// What the last match again pays.
    fn last_price(&self, prices: &[u16]) -> u32;
    /// What a two byte match at `distance` pays, where the format has one.
    fn short_price(&self, prices: &[u16], distance: u32) -> u32;
    /// Call `symbol` for each flat symbol `token` writes, and return the
    /// plain bits it writes beside them. A literal writes ONE symbol, its
    /// byte, and no plain bit, in every format: the cut counts literals by
    /// that rule without asking (`cut::Running::new`), and
    /// `encode::tests` holds each format to it.
    fn visit(&self, token: Token, symbol: &mut dyn FnMut(usize)) -> u32;
    /// The most bits the cut may price one entropy block at, where the
    /// format caps a block's packed size; `None` where it does not.
    fn block_bits_most(&self) -> Option<u64> {
        None
    }
}

/// The parse's price model: the prices in force and the symbol counts of
/// the region being parsed. Every region of committed input the counts
/// become the prices and reset, so each region is priced by the one before
/// it, which is how the decoder's tables arrive too.
pub(crate) struct PriceModel {
    pub(crate) prices: Vec<u16>,
    pub(super) counts: Vec<u32>,
    pub(super) bytes: usize,
    pub(super) threshold: usize,
}

impl PriceModel {
    pub(crate) fn new(format: &dyn Format) -> PriceModel {
        let mut model = PriceModel {
            prices: vec![0; format.symbols()],
            counts: vec![0; format.symbols()],
            bytes: 0,
            threshold: OPTIMAL_FIRST_REGION_BYTES,
        };
        model.open(format);
        model
    }

    /// The bytes this model's two tables hold, which are written whole
    /// when it is built.
    pub(crate) fn held_bytes(&self) -> u64 {
        (self.prices.len() * std::mem::size_of::<u16>() + self.counts.len() * 4) as u64
    }

    /// Back to the prices in force before any statistics.
    pub(crate) fn open(&mut self, format: &dyn Format) {
        for (index, range) in format.alphabets().iter().enumerate() {
            self.prices[range.clone()].fill(format.opening_price(index));
        }
        self.counts.fill(0);
        self.bytes = 0;
        self.threshold = OPTIMAL_FIRST_REGION_BYTES;
    }

    /// Generic rather than `&dyn Format`, so each parse calls its own
    /// format's `visit` inline: it runs once for every token of every
    /// member.
    #[inline]
    fn observe<F: Format + ?Sized>(&mut self, format: &F, token: Token) {
        let counts = &mut self.counts;
        format.visit(token, &mut |symbol| counts[symbol] += 1);
        self.bytes += token.length as usize;
    }

    /// Undo [`PriceModel::observe`] of a token observed since the counts
    /// last settled, which the lazy parse takes back when it begins a
    /// match earlier.
    #[inline]
    fn unobserve<F: Format + ?Sized>(&mut self, format: &F, token: Token) {
        let counts = &mut self.counts;
        format.visit(token, &mut |symbol| counts[symbol] -= 1);
        self.bytes -= token.length as usize;
    }

    /// Whether the first, short region has been priced yet.
    fn first_region_pending(&self) -> bool {
        self.threshold == OPTIMAL_FIRST_REGION_BYTES
    }

    /// Turn the counts into prices once a region's worth of input has been
    /// committed. Called only between windows, so a window's prices never
    /// move under it. An alphabet the region never used keeps the prices it
    /// had, so a region with no far matches does not make the next one's
    /// unaffordable.
    pub(super) fn settle(&mut self, format: &dyn Format) -> bool {
        if self.bytes < self.threshold {
            return false;
        }
        self.threshold = ENTROPY_BLOCK_BYTES;
        for range in format.alphabets() {
            let counts = &self.counts[range.clone()];
            let total: u64 = counts.iter().map(|&c| u64::from(c)).sum();
            if total == 0 {
                continue;
            }
            let log_total = log2_sixteenths(total);
            for (price, &count) in self.prices[range.clone()].iter_mut().zip(counts) {
                *price = if count == 0 {
                    PRICE_MAX
                } else {
                    let bits = log_total - log2_sixteenths(u64::from(count));
                    (bits as u16).clamp(PRICE_MIN, PRICE_MAX)
                };
            }
        }
        self.counts.fill(0);
        self.bytes = 0;
        true
    }
}

/// One parse block: the member's bytes, where the block sits in them, and
/// the farthest a match may reach back.
#[derive(Clone, Copy)]
pub(crate) struct Block<'a> {
    pub(crate) span: &'a [u8],
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) dictionary: usize,
}

/// Where a parse's match candidates come from.
#[derive(Clone, Copy)]
pub(crate) enum Source<'a> {
    /// The carried tree finder's answers for this parse block: `stride`
    /// distances per position, nearest first and each reaching farther
    /// than the last, zero where there is none.
    Hints {
        slots: &'a [AtomicU32],
        stride: usize,
    },
    /// The hash chains, searched `depth` links deep.
    Chains {
        chains: &'a Links,
        depth: u32,
        /// A match this long ends a search.
        enough: usize,
        /// Which positions the lazy parse asks at together. No other parse
        /// reads it, and it reaches no token ([`Asked`]).
        pair: Pairing,
    },
}

impl Source<'_> {
    /// The matches at `at` no longer than `limit`: nearest first, each
    /// strictly longer than the one before.
    ///
    /// **Always inlined** into the parse that asks, in every build; the
    /// chain search it reaches is pinned beside it ([`Links::search`]). Left
    /// to `#[inline]` the plain and the `pinned` build kept this out of line
    /// and the profile-use build took it into the lazy parse at as many
    /// sites as that draw's inliner chose: a few bytes more in the search
    /// moved the count of sites, and small members, where this is every
    /// position's path, retired 1 to 3 percent more instructions for it and
    /// lost 6 to 12 percent of wall at sixteen threads (the far-link work's
    /// shipped pair, 2 Oct 2026). Inlined by attribute it is 1.8 to 2.0
    /// percent fewer instructions on small members on x86-64 in the plain
    /// and the `pinned` build, level on the binary sets (0.998 to 1.000),
    /// and at most 0.6 percent more on text and code.
    #[inline(always)]
    fn candidates(
        &self,
        block: Block<'_>,
        at: usize,
        limit: usize,
        found: &mut [Found; FOUND_MAX],
    ) -> usize {
        match *self {
            Source::Chains {
                chains,
                depth,
                enough,
                ..
            } => chains.search(block.span, at, limit, depth, enough, found),
            Source::Hints { slots, stride } => {
                let offset = at - block.start;
                let mut kept = 0;
                let mut best = 0;
                for slot in &slots[offset * stride..(offset + 1) * stride] {
                    let distance = slot.load(Ordering::Relaxed);
                    if distance == 0 {
                        break;
                    }
                    if distance as usize > block.dictionary {
                        continue;
                    }
                    let length = common_prefix(block.span, at - distance as usize, at, 0, limit);
                    if length > best {
                        best = length;
                        found[kept] = Found {
                            distance,
                            length: length as u32,
                        };
                        kept += 1;
                    }
                }
                kept
            }
        }
    }
}

// ---------------------------------------------------------------------
// The lazy parse.
// ---------------------------------------------------------------------

/// How many of a match's first bytes the lazy parse prices as the literals
/// they would otherwise be, one by one.
pub(super) const LAZY_EXACT_LITERALS: usize = 16;

/// A match the lazy parse may take, and the bits it saves over literals.
#[derive(Clone, Copy)]
pub(super) struct Scored {
    pub(super) arm: Arm,
    pub(super) distance: u32,
    pub(super) length: usize,
    pub(super) gain: i64,
}

/// No position: what [`Asked`] holds while its second list answers none.
const NOWHERE: usize = usize::MAX;

/// Where [`best_scored`] gets a position's hints. It is a type parameter,
/// so the parse that asks the source there and then (every parse until 1
/// Oct 2026, and every position that is not paired since) compiles to the
/// code it was.
trait Hinted {
    /// The matches at `at` no longer than `limit`, nearest first, each
    /// strictly longer than the one before; `found` is there to hold them.
    fn hints<'a>(
        self,
        block: Block<'_>,
        at: usize,
        limit: usize,
        found: &'a mut [Found; FOUND_MAX],
    ) -> &'a [Found]
    where
        Self: 'a;
}

impl Hinted for Source<'_> {
    #[inline(always)]
    fn hints<'a>(
        self,
        block: Block<'_>,
        at: usize,
        limit: usize,
        found: &'a mut [Found; FOUND_MAX],
    ) -> &'a [Found]
    where
        Self: 'a,
    {
        let kept = self.candidates(block, at, limit, found);
        &found[..kept]
    }
}

/// A position's hints asked for ahead of its scoring ([`Asked::pair`]).
#[derive(Clone, Copy)]
struct Ready<'r>(&'r [Found]);

impl Hinted for Ready<'_> {
    #[inline(always)]
    fn hints<'a>(
        self,
        _block: Block<'_>,
        _at: usize,
        _limit: usize,
        _found: &'a mut [Found; FOUND_MAX],
    ) -> &'a [Found]
    where
        Self: 'a,
    {
        self.0
    }
}

/// The candidate lists the lazy parse asked the chains for at two
/// positions together ([`Links::search_pair`]): the first position's,
/// scored at once, and the second's, kept until the parse scores that
/// position or asks again.
///
/// A list is a function of its position alone: the block, the chains, the
/// depth and the length that ends a search are the same all block long,
/// and a position's limit is the room it has. So the list asked early is
/// the list asked late, a list never used costs time and nothing else, and
/// which positions are asked together cannot reach a token. That is all
/// the pairing rests on, and `encode::tests` holds the parse to it token
/// for token.
struct Asked {
    lists: [[Found; FOUND_MAX]; 2],
    kept: [usize; 2],
    /// The position the second list answers, or [`NOWHERE`].
    ready: usize,
}

impl Asked {
    fn new() -> Asked {
        Asked {
            lists: [[Found::default(); FOUND_MAX]; 2],
            kept: [0; 2],
            ready: NOWHERE,
        }
    }

    /// The second list, if it answers `at`.
    #[inline(always)]
    fn ready_at(&self, at: usize) -> Option<Ready<'_>> {
        (self.ready == at).then(|| Ready(&self.lists[1][..self.kept[1]]))
    }

    /// The matches at `at`, as [`Source::candidates`] gives them under the
    /// limit `at` has (its room, or `longest`, the format's longest fresh
    /// match): the list in hand where it answers `at`; else the chains
    /// asked at `at` and at the position after it together, that one's
    /// list kept. `None` where `at` is the block's last position: the
    /// caller asks at it alone.
    #[inline(always)]
    fn pair(
        &mut self,
        chains: &Links,
        depth: u32,
        enough: usize,
        block: Block<'_>,
        at: usize,
        longest: usize,
    ) -> Option<Ready<'_>> {
        #[cfg(feature = "pair-census")]
        super::chain::census::add(&super::chain::census::ASKED, 1);
        if self.ready == at {
            #[cfg(feature = "pair-census")]
            super::chain::census::add(&super::chain::census::IN_HAND, 1);
            return Some(Ready(&self.lists[1][..self.kept[1]]));
        }
        let also = at + 1;
        if also >= block.end {
            return None;
        }
        let limits = [
            (block.end - at).min(longest),
            (block.end - also).min(longest),
        ];
        self.kept = chains.search_pair(
            block.span,
            [at, also],
            limits,
            depth,
            enough,
            &mut self.lists,
        );
        self.ready = also;
        Some(Ready(&self.lists[0][..self.kept[0]]))
    }
}

/// The best scoring match at `at`: each repeated distance and each hint,
/// priced by the model in force against the literals it replaces. The
/// hints are asked of the source here, or are the ones the parse asked
/// for ahead ([`Hinted`]).
///
/// **This scoring has a second copy, `floor_count::floor_score`**, which
/// the store rule's samples are counted by (spec G 3.8.3,
/// `floor_count::FloorCount`): the same
/// arms in the same order with the chains' one candidate handed in. A
/// change here that reaches the floor effort's answers (`Plan::floor`: one
/// link, no extension) moves a member's verdict unless it is made there
/// too; `rar5`'s test `the_counted_sample_is_the_packed_sample` holds the
/// two together and fails when they part.
///
/// Always inlined on x86-64: with the lazy parse compiled twice (with the
/// backward extension and without), a plain `#[inline]` left levels 1 and
/// 2 at 1.010 to 1.013 of their parent's instructions for the same bytes,
/// and always inlined 0.993 to 0.999 (x86-64). On aarch64 always inlining
/// cost 1.041 to 1.047 where plain inlining reads 1.012 to 1.014, so there
/// it is not inlined (counted 30 Sep 2026).
///
/// **Never inlined off x86-64, by attribute.** Left to `#[inline]` there,
/// the plain build kept every call out of line and the profile-use build
/// took the paired hints' scoring into the lazy parse at as many sites as
/// that draw's inliner chose: one of four in one tree's draw and two of
/// four in the next tree's, whose plain builds were level (0.998 to
/// 1.003 by instructions on a 1 GiB binary set). The draw with two
/// retired 1.3 to 2.2 percent more instructions on that set and lost 1.0
/// to 1.9 percent of wall at levels 3 to 5, outside its null, on an M3
/// Ultra (the far-link work's aarch64 shipped pair, 2 Oct 2026). A scoring
/// the inliner may or may not take in is a parse whose body moves with
/// the draw.
#[cfg_attr(target_arch = "x86_64", inline(always))]
#[cfg_attr(not(target_arch = "x86_64"), inline(never))]
fn best_scored<F: Format, H: Hinted>(
    format: &F,
    prices: &[u16],
    literal_price: u32,
    block: Block<'_>,
    hints: H,
    repeats: &Repeats,
    at: usize,
) -> Option<Scored> {
    let span = block.span;
    let room = block.end - at;
    let mut best: Option<Scored> = None;
    let mut consider = |arm: Arm, distance: u32, length: usize, price: u32| {
        if price >= UNPRICED {
            return;
        }
        // What the literals it replaces would cost: exactly for the first
        // few, where a rare byte can decide the matter, and at the mean
        // beyond them.
        let exact = length.min(LAZY_EXACT_LITERALS);
        let literals: i64 = span[at..at + exact]
            .iter()
            .map(|&byte| i64::from(prices[byte as usize]))
            .sum::<i64>()
            + i64::from(literal_price) * (length - exact) as i64;
        let gain = literals - i64::from(price);
        if gain > 0 && best.is_none_or(|b| gain > b.gain) {
            best = Some(Scored {
                arm,
                distance,
                length,
                gain,
            });
        }
    };
    let limit = room.min(format.longest_repeat());
    if limit >= 2 {
        for k in 0..REPEATS {
            let held = repeats.distance[k];
            if held == 0 || repeats.distance[..k].contains(&held) {
                continue;
            }
            let source = at - held as usize;
            if span[source] != span[at] || span[source + 1] != span[at + 1] {
                continue;
            }
            let length = common_prefix(span, source, at, 2, limit);
            let mut price = format.repeat_price(prices, k, length as u32);
            if k == 0 && length == repeats.last_length as usize {
                price = price.min(format.last_price(prices));
            }
            consider(Arm::Repeat(k as u8), held, length, price);
        }
    }
    let limit = room.min(format.longest());
    let mut found = [Found::default(); FOUND_MAX];
    for &Found { distance, length } in hints.hints(block, at, limit, &mut found) {
        if repeats.slot_of(distance).is_some() {
            continue;
        }
        let bonus = format.bonus(distance);
        if length < 2 + bonus {
            continue;
        }
        let price = format
            .fresh_distance_price(prices, distance)
            .saturating_add(format.fresh_length_price(prices, length - bonus));
        consider(Arm::Fresh, distance, length as usize, price);
    }
    best
}

/// The mean price of a literal under `prices`, weighted by nothing: the
/// lazy parse's yardstick for what a match saves.
pub(super) fn mean_literal_price(prices: &[u16]) -> u32 {
    let cheap: u32 = prices[..256]
        .iter()
        .map(|&p| u32::from(p))
        .filter(|&p| p < u32::from(PRICE_MAX))
        .sum();
    let used = prices[..256].iter().filter(|&&p| p < PRICE_MAX).count();
    if used == 0 {
        8 << PRICE_SHIFT
    } else {
        cheap / used as u32
    }
}

/// How far back a parse may begin a match the finder offered: the
/// BACKWARD EXTENSION's limit, where a plan has it on.
///
/// A chain is ordered by nearness, so where a match's first four bytes are
/// a common word its first links are all near copies, and the far copy is
/// found only a few bytes into the match, where the four bytes are rarer.
/// The parse is then offered the match without its head. Where the bytes
/// before an offered match agree at its distance, the match really began
/// there, and the parse is given that. Counted 30 Sep 2026 in the text
/// reach research: 4 bytes get two thirds to four fifths of what 32 get, 32 all but
/// 0.06 of a point of 64, and the price does not move with the limit.
pub(crate) const BACK_LIMIT: usize = 32;

/// A match the lazy parse sent since its prices last settled: where its
/// token sits, and the repeated distance model before it, so the match can
/// be taken back whole.
#[derive(Clone, Copy, Default)]
struct Sent {
    index: usize,
    repeats: Repeats,
}

/// The newest matches the lazy parse sent, as many as can lie within
/// [`BACK_LIMIT`] bytes of a position: a match is at least two bytes, so
/// the newest sixteen hold every match an extension can reach, and the
/// parse keeps no more than that whatever the block.
struct SentRing {
    entries: [Sent; BACK_LIMIT / 2],
    start: usize,
    len: usize,
}

impl SentRing {
    fn new() -> SentRing {
        SentRing {
            entries: [Sent::default(); BACK_LIMIT / 2],
            start: 0,
            len: 0,
        }
    }

    #[inline]
    fn push(&mut self, sent: Sent) {
        let size = self.entries.len();
        if self.len == size {
            self.start = (self.start + 1) % size;
            self.len -= 1;
        }
        self.entries[(self.start + self.len) % size] = sent;
        self.len += 1;
    }

    #[inline]
    fn last(&self) -> Option<Sent> {
        (self.len != 0).then(|| self.entries[(self.start + self.len - 1) % self.entries.len()])
    }

    #[inline]
    fn pop(&mut self) -> Option<Sent> {
        let last = self.last()?;
        self.len -= 1;
        Some(last)
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

/// The lazy parse: the best scoring match, deferred one byte when the next
/// position's saves more.
///
/// With `back` above zero a fresh match whose bytes also agree BEFORE it,
/// at its own distance, begins up to `back` bytes earlier: it takes back
/// the literals just sent over those bytes and, where the agreement covers
/// a whole match sent just before them, that match too (one token fewer),
/// with the price counts and the repeated distance model as they were
/// before the tokens taken back. Where the restored model holds the
/// distance the match goes out on the repeated arm. Nothing is taken back
/// past the block's start or past the point the prices last settled.
///
/// The parse is compiled twice, with the extension and without, so a plan
/// without it runs the loop it ran before the extension existed.
///
/// Over the chains, a block that reaches past the pairing's start
/// ([`Pairing::From`]) is parsed asking two positions together: a position
/// the parse reaches with nothing in hand, together with the one after
/// it, which it scores next whether this one has a match (the look one
/// byte on) or not (the next position), unless the match here is long
/// enough to be taken without that look. No token moves with it
/// ([`Asked`]). That loop is compiled apart as well (`PAIR`), so every
/// other block (the tree's hints, a member too short to pair, a plan that
/// asks one position a search) runs the loop and the scoring it ran
/// before the pair existed: a first build that shared one loop cost such
/// blocks 1 to 4 percent of instructions on x86-64.
///
/// A second form was counted and dropped (1 Oct 2026): a look one byte on
/// that is not in hand, asked together with the position the match in hand
/// ends at. It put 86 to 93 percent of links in turn where this one puts
/// 78 to 82, but a tenth of its second lists went unused (the look wins
/// one time in six), and it took more cycles than this form on every row
/// of both architectures (the same file, section 6).
///
/// **The loop without the extension has a second copy,
/// `floor_count::FloorCount::count`**, which counts the symbols of the tokens this
/// writes at the floor effort and writes none (the store rule's samples,
/// spec G 3.8.3). See [`best_scored`]'s note: the two are held together by
/// a test, and a change to one that the other does not take fails it.
pub(crate) fn lazy_parse<F: Format>(
    format: &F,
    block: Block<'_>,
    source: Source<'_>,
    model: &mut PriceModel,
    tokens: &mut Vec<Token>,
    back: usize,
) {
    let paired = matches!(
        source,
        Source::Chains { pair: Pairing::From(from), .. } if from < block.end
    );
    match (back == 0, paired) {
        (true, false) => lazy_parse_as::<F, false, false>(format, block, source, model, tokens, 0),
        (false, false) => {
            lazy_parse_as::<F, true, false>(format, block, source, model, tokens, back)
        }
        (true, true) => lazy_parse_as::<F, false, true>(format, block, source, model, tokens, 0),
        (false, true) => lazy_parse_as::<F, true, true>(format, block, source, model, tokens, back),
    }
}

fn lazy_parse_as<F: Format, const EXTEND: bool, const PAIR: bool>(
    format: &F,
    block: Block<'_>,
    source: Source<'_>,
    model: &mut PriceModel,
    tokens: &mut Vec<Token>,
    back: usize,
) {
    model.open(format);
    let first = tokens.len();
    // The newest matches sent since the prices last settled.
    let mut sent = SentRing::new();
    let mut repeats = Repeats::default();
    let mut literal_price = mean_literal_price(&model.prices);
    let mut at = block.start;
    let mut held: Option<Scored> = None;
    // The paired loop's own: the chains, and the first position asked
    // together with the one after it.
    let pairing = match source {
        Source::Chains {
            chains,
            depth,
            enough,
            pair: Pairing::From(from),
        } if PAIR => Some((chains, depth, enough, from)),
        _ => None,
    };
    let mut asked = Asked::new();
    let longest = format.longest();
    while at < block.end {
        let found = held.take().or_else(|| {
            if PAIR {
                if let Some((chains, depth, enough, from)) = pairing {
                    if at >= from {
                        if let Some(ready) = asked.pair(chains, depth, enough, block, at, longest) {
                            return best_scored(
                                format,
                                &model.prices,
                                literal_price,
                                block,
                                ready,
                                &repeats,
                                at,
                            );
                        }
                    }
                }
            }
            best_scored(
                format,
                &model.prices,
                literal_price,
                block,
                source,
                &repeats,
                at,
            )
        });
        let Some(found) = found else {
            let token = Token::literal(block.span[at]);
            tokens.push(token);
            model.observe(format, token);
            at += 1;
            continue;
        };
        if found.length < OPTIMAL_SUFFICIENT_LENGTH && at + 1 < block.end {
            let ready = if PAIR { asked.ready_at(at + 1) } else { None };
            let next = match ready {
                Some(ready) => best_scored(
                    format,
                    &model.prices,
                    literal_price,
                    block,
                    ready,
                    &repeats,
                    at + 1,
                ),
                None => best_scored(
                    format,
                    &model.prices,
                    literal_price,
                    block,
                    source,
                    &repeats,
                    at + 1,
                ),
            };
            if let Some(next) = next {
                if next.gain > found.gain + i64::from(literal_price) / 2 {
                    let token = Token::literal(block.span[at]);
                    tokens.push(token);
                    model.observe(format, token);
                    at += 1;
                    held = Some(next);
                    continue;
                }
            }
        }
        let arm = if found.arm == Arm::Repeat(0)
            && found.length == repeats.last_length as usize
            && format.last_price(&model.prices)
                <= format.repeat_price(&model.prices, 0, found.length as u32)
        {
            Arm::Last
        } else {
            found.arm
        };
        let end = at + found.length;
        let (arm, length) = if EXTEND && arm == Arm::Fresh {
            extend_back(
                format,
                block,
                model,
                tokens,
                &mut sent,
                &mut repeats,
                first,
                at,
                found.distance,
                found.length,
                back,
            )
        } else {
            (arm, found.length)
        };
        if EXTEND {
            sent.push(Sent {
                index: tokens.len(),
                repeats,
            });
        }
        let token = Token {
            arm,
            length: length as u16,
            distance: found.distance,
        };
        tokens.push(token);
        model.observe(format, token);
        repeats = repeats.after(arm, found.distance, length as u16);
        at = end;
        if model.settle(format) {
            literal_price = mean_literal_price(&model.prices);
            sent.clear();
        }
    }
}

/// The lazy parse's backward extension of a fresh match at `at`: take back
/// what was sent over the bytes before it that agree at its distance, and
/// return the arm and the length it goes out with.
#[allow(clippy::too_many_arguments)]
#[inline]
fn extend_back<F: Format>(
    format: &F,
    block: Block<'_>,
    model: &mut PriceModel,
    tokens: &mut Vec<Token>,
    sent: &mut SentRing,
    repeats: &mut Repeats,
    first: usize,
    at: usize,
    distance: u32,
    length: usize,
    back: usize,
) -> (Arm, usize) {
    let span = block.span;
    let far = distance as usize;
    let most = back
        .min(at - block.start)
        .min(at - far)
        .min(format.longest() - length);
    let mut agree = 0;
    while agree < most && span[at - agree - 1] == span[at - agree - 1 - far] {
        agree += 1;
    }
    let mut length = length;
    let mut took_match = false;
    while agree != 0 && tokens.len() > first {
        let token = *tokens.last().expect("a token was sent");
        let size = token.length as usize;
        if token.arm != Arm::Literal {
            // A match goes back only whole, and only one sent since the
            // prices settled, whose model before it is kept.
            let newest = sent.last().is_some_and(|s| s.index == tokens.len() - 1);
            if size > agree || !newest {
                break;
            }
            *repeats = sent.pop().expect("the match's model").repeats;
            took_match = true;
        }
        tokens.pop();
        model.unobserve(format, token);
        length += size;
        agree -= size;
    }
    if took_match {
        if let Some(k) = repeats.slot_of(distance) {
            if length <= format.longest_repeat() {
                return (Arm::Repeat(k), length);
            }
        }
    }
    (Arm::Fresh, length)
}

// ---------------------------------------------------------------------
// The floor scan.
// ---------------------------------------------------------------------

/// How far apart the floor scan asks the finder: every sixteenth position.
///
/// A match of [`SCAN_LEAST`] bytes or more spans at least one asked
/// position whatever its alignment, and the scan extends it back over the
/// literals before that position, so what the gap drops is only the
/// short matches: the ones that, in bytes the sample calls empty, cost
/// more to code than the literals they replace. Counted 30 Sep 2026 on the
/// ladder's `media16` and on 1 GiB of a 12 GiB member at level 1 (stride and
/// least): 4 and 16 left `media16` 0.49 percent over the lazy floor, 16
/// and 32 0.73, 32 and 64 0.85, and on the big member 16 and 32 was already
/// four times cheaper than the lazy floor and smaller than it, with 32
/// and 64 cheaper still by 14 percent but 15 KB larger
/// (measured 30 Sep 2026).
pub(crate) const SCAN_STRIDE: usize = 16;
// The empty stride links the positions the floor scan asks at.
const _: () = assert!(SCAN_STRIDE == super::chain::EMPTY_ASK_EVERY);
/// The shortest match the floor scan keeps.
pub(crate) const SCAN_LEAST: usize = 32;

/// The THIN SCAN's stride: [`floor_scan`] asking the finder at every
/// position, for a block the sample reads thin (`sample::thin`).
///
/// Such a block has a little to find, mostly short: on 1 GiB of a big member at
/// level 3 on one CPU (counted 14 Oct 2026 on a Zen 4 rental, x86-64), a
/// quarter of the blocks sampled at 24 to 248 per mille, and their full
/// lazy parse took about half the create's wall.
///
/// Screened there 14 Oct 2026 (plain builds, K=3 medians, stride and
/// links, against the lazy parse's 12.93 s at one thread and 3.89 s at
/// sixteen): 1 and 4 took 11.50 s and 3.97 s for 0.13 percent more
/// archive, 1 and 2 9.96 s and 3.22 s for 0.17 percent, 2 and 4 9.65 s
/// and 3.08 s for 0.19 percent, 2 and 2 8.78 s and 2.73 s for 0.25
/// percent. One and two is the form chosen (decided 14 Oct 2026).
pub(crate) const THIN_SCAN_STRIDE: usize = 1;
/// The shortest match the thin scan keeps: five, where six took as long
/// and wrote more.
pub(crate) const THIN_SCAN_LEAST: usize = 5;
/// How many chain links the thin scan follows a position.
pub(crate) const THIN_SCAN_LINKS: u32 = 2;

/// The first position at or after `at` the floor scan asks: one in every
/// `stride`, its offset turning through `0..phases` from one stride to the
/// next (16k + k mod 4 at the shipped stride and four phases), or every
/// `stride`th position at one phase. The turning offset is what lets the
/// scan meet a source in a block linked at the empty stride
/// (`chain::empty_takes`, which links these positions): the asks cover
/// every residue modulo `phases` within `phases` strides.
#[inline]
fn next_ask(at: usize, stride: usize, phases: usize) -> usize {
    let window = at / stride;
    let ask = window * stride + window % phases;
    if ask >= at {
        ask
    } else {
        (window + 1) * stride + (window + 1) % phases
    }
}

/// The floor scan: how a block with nothing in it to find is parsed.
///
/// Literals, except where the finder, asked at one position in every
/// `stride` ([`SCAN_STRIDE`] shipped; [`next_ask`] with `phases`), answers with a match of at least
/// `least` bytes ([`SCAN_LEAST`]): that match is taken, first extended
/// back over the literals the scan emitted since its last match, and the
/// scan resumes after it. A match at a distance the decoder already holds
/// is coded on the repeated arm, and where a match ends the scan first
/// asks whether the bytes go on at the same distance, so a long copy is
/// coded as one fresh match and repeats rather than as a fresh match per
/// longest length (which on the RAR 2.9 method, whose longest is 258
/// bytes, cost 1.7 percent of a 512 KiB member). There is no price model:
/// a block the sample calls empty has no statistics worth steering by,
/// and what the scan is for is the long duplicate (the same asset twice in
/// a media set, a stored member inside a container) rather than the few
/// bits a short match can win or lose.
///
/// It is a pure function of the block and of the finder's answers, as
/// the other parses are, so it moves no byte with the thread count.
pub(crate) fn floor_scan<F: Format>(
    format: &F,
    block: Block<'_>,
    source: Source<'_>,
    tokens: &mut Vec<Token>,
    stride: usize,
    least: usize,
    phases: usize,
) {
    debug_assert!(phases >= 1 && phases <= stride);
    let span = block.span;
    let longest = format.longest();
    let mut found = [Found::default(); FOUND_MAX];
    let mut repeats = Repeats::default();
    // The literals emitted since the last match, which a match may take
    // back by extending over them.
    let mut literals = 0usize;
    let mut at = block.start;
    let mut ask = next_ask(at, stride, phases);
    while at < block.end {
        let room = block.end - at;
        // Where the last match ended: do the bytes go on at its distance?
        let held = repeats.distance[0] as usize;
        if literals == 0 && held != 0 && held <= at {
            let length = common_prefix(span, at - held, at, 0, room.min(format.longest_repeat()));
            if length >= SCAN_GOES_ON {
                push_match(tokens, &mut repeats, Arm::Repeat(0), held as u32, length);
                at += length;
                continue;
            }
        }
        if at > ask {
            ask = next_ask(at, stride, phases);
        }
        if at == ask {
            let limit = room.min(longest);
            let kept = if limit >= least {
                source.candidates(block, at, limit, &mut found)
            } else {
                0
            };
            if let Some(&Found { distance, length }) = found[..kept].last() {
                let slot = repeats.slot_of(distance);
                let most = if slot.is_some() {
                    format.longest_repeat()
                } else {
                    longest
                };
                let mut length = (length as usize).min(most);
                if length >= least && length >= 2 + format.bonus(distance) as usize {
                    let back = distance as usize;
                    let mut start = at;
                    while literals > 0
                        && start > back
                        && length < most
                        && span[start - 1 - back] == span[start - 1]
                    {
                        start -= 1;
                        length += 1;
                        literals -= 1;
                        tokens.pop();
                    }
                    let arm = slot.map_or(Arm::Fresh, Arm::Repeat);
                    push_match(tokens, &mut repeats, arm, distance, length);
                    literals = 0;
                    at = start + length;
                    continue;
                }
            }
        }
        // A literal, and so is every position up to the next one the
        // finder is asked at: after a literal the run at the last match's
        // distance is not looked for again until a match, and only the
        // positions [`next_ask`] names are asked. They go out together,
        // the tokens the scan took one position a turn. The next ask, not
        // the next multiple of `stride`: at more than one phase the asks
        // turn through each stride, and a run to the stride's end would
        // pass the ask inside it (every window but one in `phases` unasked,
        // so a duplicate at three distances in four was lost again at
        // level 2). At one phase the two are the same position.
        let next = if ask > at {
            ask
        } else {
            next_ask(at + 1, stride, phases)
        }
        .min(block.end);
        tokens.extend(span[at..next].iter().map(|&byte| Token::literal(byte)));
        literals += next - at;
        at = next;
    }
}

/// The THIN SCAN as shipped: [`floor_scan`] at a stride of one, its
/// finder asked two positions at a time ([`Links::search_pair`]) where
/// the source is the chains.
///
/// At a stride of one the scan asks at every position a match does not
/// cover, and in a thin block nearly every ask finds nothing worth taking,
/// so the next ask is at the very next position. Each walk is bound by
/// memory, and two walks in turn wait on their loads together, as the lazy
/// parse's pairs do. The second answer is used only where the scan asks
/// next at that position, which is after a literal; anywhere else it is
/// dropped and asked again. `search_pair` answers each of its positions as
/// `search` does, so this takes exactly the tokens `floor_scan` takes at a
/// stride of one (held by a test), and the tree's hints, which no thin
/// block reads, go to `floor_scan` itself.
///
/// Screened 14 Oct 2026 on an EPYC 4345P (x86-64, plain builds, K=3, a
/// 1 GiB member at level 3, two links): 9.53 s against 9.86 s alone at one
/// thread, 3.11 s against 3.21 s at sixteen; at four links 10.84 s
/// against 11.49 s and 3.53 s against 3.95 s.
pub(crate) fn thin_scan<F: Format>(
    format: &F,
    block: Block<'_>,
    source: Source<'_>,
    tokens: &mut Vec<Token>,
    least: usize,
) {
    let Source::Chains {
        chains,
        depth,
        enough,
        ..
    } = source
    else {
        return floor_scan(format, block, source, tokens, 1, least, 1);
    };
    let span = block.span;
    let longest = format.longest();
    let mut pair = [[Found::default(); FOUND_MAX]; 2];
    // The longest answer at a position, asked together with the one before.
    let mut ahead: Option<(usize, Option<Found>)> = None;
    let mut repeats = Repeats::default();
    let mut literals = 0usize;
    let mut at = block.start;
    while at < block.end {
        let room = block.end - at;
        // Where the last match ended: do the bytes go on at its distance?
        let held = repeats.distance[0] as usize;
        if literals == 0 && held != 0 && held <= at {
            let length = common_prefix(span, at - held, at, 0, room.min(format.longest_repeat()));
            if length >= SCAN_GOES_ON {
                push_match(tokens, &mut repeats, Arm::Repeat(0), held as u32, length);
                at += length;
                continue;
            }
        }
        let limit = room.min(longest);
        let answer = match ahead.take() {
            Some((asked, answer)) if asked == at => answer,
            _ if limit < least => None,
            _ => {
                let second = (room - 1).min(longest);
                if second >= least {
                    let kept = chains.search_pair(
                        span,
                        [at, at + 1],
                        [limit, second],
                        depth,
                        enough,
                        &mut pair,
                    );
                    ahead = Some((at + 1, kept[1].checked_sub(1).map(|k| pair[1][k])));
                    kept[0].checked_sub(1).map(|k| pair[0][k])
                } else {
                    let kept = chains.search(span, at, limit, depth, enough, &mut pair[0]);
                    kept.checked_sub(1).map(|k| pair[0][k])
                }
            }
        };
        if let Some(Found { distance, length }) = answer {
            let slot = repeats.slot_of(distance);
            let most = if slot.is_some() {
                format.longest_repeat()
            } else {
                longest
            };
            let mut length = (length as usize).min(most);
            if length >= least && length >= 2 + format.bonus(distance) as usize {
                let back = distance as usize;
                let mut start = at;
                while literals > 0
                    && start > back
                    && length < most
                    && span[start - 1 - back] == span[start - 1]
                {
                    start -= 1;
                    length += 1;
                    literals -= 1;
                    tokens.pop();
                }
                let arm = slot.map_or(Arm::Fresh, Arm::Repeat);
                push_match(tokens, &mut repeats, arm, distance, length);
                literals = 0;
                at = start + length;
                continue;
            }
        }
        tokens.push(Token::literal(span[at]));
        literals += 1;
        at += 1;
    }
}

/// [`floor_scan`] as it was written before its literals went out a stride
/// at a time: one position a turn. Kept for the test that holds the two to
/// the same tokens.
#[cfg(test)]
pub(crate) fn floor_scan_a_position_a_turn<F: Format>(
    format: &F,
    block: Block<'_>,
    source: Source<'_>,
    tokens: &mut Vec<Token>,
    stride: usize,
    least: usize,
) {
    let span = block.span;
    let longest = format.longest();
    let mut found = [Found::default(); FOUND_MAX];
    let mut repeats = Repeats::default();
    let mut literals = 0usize;
    let mut at = block.start;
    while at < block.end {
        let room = block.end - at;
        let held = repeats.distance[0] as usize;
        if literals == 0 && held != 0 && held <= at {
            let length = common_prefix(span, at - held, at, 0, room.min(format.longest_repeat()));
            if length >= SCAN_GOES_ON {
                push_match(tokens, &mut repeats, Arm::Repeat(0), held as u32, length);
                at += length;
                continue;
            }
        }
        if at.is_multiple_of(stride) {
            let limit = room.min(longest);
            let kept = if limit >= least {
                source.candidates(block, at, limit, &mut found)
            } else {
                0
            };
            if let Some(&Found { distance, length }) = found[..kept].last() {
                let slot = repeats.slot_of(distance);
                let most = if slot.is_some() {
                    format.longest_repeat()
                } else {
                    longest
                };
                let mut length = (length as usize).min(most);
                if length >= least && length >= 2 + format.bonus(distance) as usize {
                    let back = distance as usize;
                    let mut start = at;
                    while literals > 0
                        && start > back
                        && length < most
                        && span[start - 1 - back] == span[start - 1]
                    {
                        start -= 1;
                        length += 1;
                        literals -= 1;
                        tokens.pop();
                    }
                    let arm = slot.map_or(Arm::Fresh, Arm::Repeat);
                    push_match(tokens, &mut repeats, arm, distance, length);
                    literals = 0;
                    at = start + length;
                    continue;
                }
            }
        }
        tokens.push(Token::literal(span[at]));
        literals += 1;
        at += 1;
    }
}

/// How long a run at the last match's distance must be for the floor scan
/// to take it where that match ended: short enough to catch the tail of a
/// copy, long enough that noise never offers one (a chance in 2^32).
const SCAN_GOES_ON: usize = 4;

/// Push a match and move the decoder's repeat model past it.
#[inline]
fn push_match(
    tokens: &mut Vec<Token>,
    repeats: &mut Repeats,
    arm: Arm,
    distance: u32,
    length: usize,
) {
    tokens.push(Token {
        arm,
        length: length as u16,
        distance,
    });
    *repeats = repeats.after(arm, distance, length as u16);
}

// ---------------------------------------------------------------------
// The fast parse.
// ---------------------------------------------------------------------

/// The shortest fresh match the fast parse takes: the chains' key. A
/// candidate that shares fewer bytes than the key with its position is two
/// keys meeting in one head, and on text a match that short costs more
/// bits than the literals it replaces.
///
/// It is also what keeps every fresh match inside both formats' length
/// ladders with nothing more asked of [`Format`]: a distance's bonus is at
/// most three, and the shortest length either ladder names is three.
pub(crate) const FAST_LEAST: usize = KEY_WIDE;

/// A held distance that already gives this many bytes is taken without the
/// chain being asked.
const FAST_HELD_ENOUGH: usize = 16;

/// What a match on a held distance is taken to pay, in sixteenths of a
/// bit: one main symbol and one length slot.
const FAST_HELD_PRICE: i32 = 8 << PRICE_SHIFT;

/// What a fresh match at `distance` is taken to pay whatever its length,
/// in sixteenths of a bit: a main symbol of seven bits, a distance slot of
/// five, and the plain bits under the slot.
#[inline(always)]
fn fast_fresh_price(distance: u32) -> i32 {
    let under = (32 - distance.leading_zeros()).saturating_sub(2) as i32;
    (12 + under) << PRICE_SHIFT
}

/// What a literal of `bytes` is taken to cost, in sixteenths of a bit: the
/// order 0 entropy of the bytes themselves, held between three and eight
/// bits. One histogram a parse block is all the statistics the fast parse
/// keeps.
///
/// The bytes are counted into four tables in turn and the tables summed:
/// a run of one byte value otherwise makes every count wait on the store
/// of the one before it. The sums are the counts one table would hold.
fn fast_literal_price(bytes: &[u8]) -> i32 {
    let total = bytes.len() as u64;
    if total == 0 {
        return 8 << PRICE_SHIFT;
    }
    let mut counts = [[0u32; 256]; 4];
    let (quads, rest) = bytes.as_chunks::<4>();
    for quad in quads {
        counts[0][quad[0] as usize] += 1;
        counts[1][quad[1] as usize] += 1;
        counts[2][quad[2] as usize] += 1;
        counts[3][quad[3] as usize] += 1;
    }
    for &byte in rest {
        counts[0][byte as usize] += 1;
    }
    let log_total = u64::from(log2_sixteenths(total));
    let sum: u64 = (0..256)
        .map(|byte| counts[0][byte] + counts[1][byte] + counts[2][byte] + counts[3][byte])
        .filter(|&count| count != 0)
        .map(|count| u64::from(count) * (log_total - u64::from(log2_sixteenths(u64::from(count)))))
        .sum();
    ((sum / total) as i32).clamp(3 << PRICE_SHIFT, 8 << PRICE_SHIFT)
}

/// How many positions one [`held_ahead`] answers: the eight bytes of a
/// word less the one whose second byte lies outside it.
const HELD_AHEAD: usize = 7;

const BYTE_LANES: u64 = 0x0101_0101_0101_0101;

/// For each of the [`HELD_AHEAD`] positions from `at`, whether SOME held
/// distance repeats the two bytes that begin there: bit `8 * i + 7` is
/// set for position `at + i`. That is exactly where the fast parse's
/// held distance compares can find anything, so a position whose bit is
/// clear is one they would all fail at. Where fewer than eight bytes are
/// left in `span` every bit is set, and each position is compared as
/// before.
///
/// Eight bytes at `at` are XORed with the eight at each held distance; a
/// byte lane of the result is zero where the two agree, the zero lanes
/// are found exactly (no carry leaves a lane), and a lane and the one
/// after it both zero is two bytes repeated.
#[inline(always)]
fn held_ahead(span: &[u8], at: usize, held: &Repeats) -> u64 {
    let Some(here) = span.get(at..at + 8) else {
        return u64::MAX;
    };
    let here = u64::from_le_bytes(here.try_into().unwrap());
    let mut any = 0u64;
    for &back in &held.distance {
        if back == 0 {
            // The filled slots are a prefix of the four.
            break;
        }
        let from = at - back as usize;
        let there = u64::from_le_bytes(span[from..from + 8].try_into().unwrap());
        let differ = here ^ there;
        let agree =
            !(((differ & (0x7f * BYTE_LANES)) + 0x7f * BYTE_LANES) | differ) & (0x80 * BYTE_LANES);
        any |= agree & (agree >> 8);
    }
    any
}

/// The fast parse, level 1's since 1 Oct 2026 (set 30 Sep 2026: a
/// cheaper level 1 is the default where timed rows on both architectures
/// show the faster wall, with an option for the other form; decided 1 Oct
/// 2026 on rows measured 30 Sep).
///
/// At each position, in this order:
///
/// 1. The four held distances, each tried by a two byte compare. A held
///    distance is the cheapest arm there is, and on a long copy broken by
///    a changed byte it is the one that goes on.
/// 2. Unless a held distance already gives [`FAST_HELD_ENOUGH`] bytes, the
///    ONE nearest earlier position of the six byte chain
///    ([`Links::nearest`]): a fresh match of at least [`FAST_LEAST`] bytes,
///    at a distance the model does not hold.
///
/// The better of them by a STATIC price is taken at once: a literal costs
/// the block's own order 0 entropy a byte ([`fast_literal_price`]), a
/// fresh match [`fast_fresh_price`], a held distance [`FAST_HELD_PRICE`].
/// There is no price model, no symbol statistics and no deferral, which is
/// where the lazy parse three links deep spent 77 percent of level 1's
/// instructions (the same file, section 3): on text64 at one thread that
/// level 1 retired 20.9 G instructions and this parse 7.1 G, for 0.2
/// percent more archive.
///
/// It is a pure function of the block's bytes and of the links, as the
/// other parses are, so it moves no byte with the thread count.
///
/// The paired search of the lazy parse has nothing to give it: it follows
/// one link a position, so there is no walk to take in turn. What it can
/// be given is a cache hint at the bytes its link leads to, some positions
/// ahead, and that was counted and declined (1 Oct 2026): 3.5 to 6 percent
/// more instructions, 4 to 6 percent fewer cycles on text64 and code32 at
/// one thread on x86-64, and MORE cycles on every other row of both
/// architectures (measured 1 Oct 2026).
#[inline(never)]
pub(crate) fn fast_parse<F: Format>(
    format: &F,
    block: Block<'_>,
    links: &Links,
    tokens: &mut Vec<Token>,
    cuts: &mut Vec<Range<usize>>,
    counts: &mut Vec<u32>,
) {
    debug_assert_eq!(links.key(), KEY_WIDE);
    debug_assert!(tokens.is_empty());
    // The block's end is the slice's: a position with four bytes of the
    // block after it is then one whose four byte load is in bounds, by
    // one test, and nothing here reads past the block.
    let span = &block.span[..block.end];
    let literal = fast_literal_price(&span[block.start..]);
    let mut blind = Blind::new(format.symbols(), block.start, cuts, counts);
    // The open entropy block's literals, counted as they go out.
    let mut bytes = [0u32; 256];
    let mut held = Repeats::default();
    let mut at = block.start;
    // Which of the positions from `ahead_from` begin two bytes that some
    // held distance repeats ([`held_ahead`]); none until the first fill.
    let mut ahead = 0u64;
    let mut ahead_from = usize::MAX;
    while let Some(word) = span.get(at..at + 4) {
        let word = u32::from_le_bytes(word.try_into().unwrap());
        // The held distances are asked a stretch of positions at a time:
        // they do not move while literals go out, so one fill answers the
        // next seven positions, and a position none of them repeats two
        // bytes at skips the four compares it would fail one by one.
        let mut lane = at.wrapping_sub(ahead_from);
        if lane >= HELD_AHEAD {
            ahead = held_ahead(span, at, &held);
            ahead_from = at;
            lane = 0;
        }
        let held_asked = ahead >> (8 * lane + 7) & 1 != 0;
        // The chain's one candidate, where it begins with this position's
        // four bytes: nothing else of the chain can become a match.
        //
        // Asked without a branch: where the chain offers nothing the
        // distance is zero and the bytes compared are the position's own,
        // so one test, of the held distances and the chain together,
        // decides the common case. Whether a bucket is empty, its newest
        // position out of reach or its bytes another key's all turn on
        // the input, and a branch on each was guessed wrong too often.
        let back = links.nearest_back(at);
        let from = at - back;
        let there = u32::from_le_bytes(span[from..from + 4].try_into().unwrap());
        let chain_asked = (back != 0) & (there == word);
        // Most positions end here, with neither on offer: a literal, by
        // the same test [`fast_choose`] would make of them, and the loop
        // that reaches it calls nothing.
        if !(held_asked | chain_asked) {
            bytes[usize::from(word as u8)] += 1;
            tokens.push(Token::literal(word as u8));
            at += 1;
            continue;
        }
        let chained = chain_asked.then_some(from);
        let room = span.len() - at;
        let (mut arm, distance, length) =
            fast_choose(format, span, at, room, &held, held_asked, chained, literal);
        if arm == Arm::Literal {
            bytes[usize::from(word as u8)] += 1;
            tokens.push(Token::literal(word as u8));
            at += 1;
            continue;
        }
        blind.literals(&mut bytes, tokens.len(), span, at);
        if arm == Arm::Repeat(0) && length == held.last_length as usize {
            arm = Arm::Last;
        }
        push_match(tokens, &mut held, arm, distance, length);
        at += length;
        blind.matched(format, &mut bytes, tokens, at);
        // The model moved: the stretch is asked again.
        ahead_from = usize::MAX;
    }
    // The positions with under four bytes after them: no match begins
    // there.
    for &byte in &span[at..] {
        bytes[usize::from(byte)] += 1;
        tokens.push(Token::literal(byte));
    }
    blind.literals(&mut bytes, tokens.len(), span, span.len());
    blind.finish(&bytes, tokens.len());
}

/// The fast parse's entropy blocks, cut and counted as its tokens go out:
/// what [`super::cut::cut_blind`] and the emitter's own count would make
/// of the same tokens in two more passes over them.
///
/// A block ends with the token that takes it to [`BLIND_CUT_BYTES`] of
/// input. The parse knows where each token ends, so a match is one
/// compare; literals are not asked one by one, but when the run of them
/// ends ([`Blind::literals`]). `counts` holds one table of the format's
/// flat symbols a block, in block order; the open block's literals are
/// counted by the parse into a table of its own, by their bytes, and
/// join it when the block closes.
struct Blind<'a> {
    cuts: &'a mut Vec<Range<usize>>,
    counts: &'a mut Vec<u32>,
    symbols: usize,
    /// The open block's first token.
    first: usize,
    /// The position its first token begins at.
    base: usize,
}

impl<'a> Blind<'a> {
    fn new(
        symbols: usize,
        start: usize,
        cuts: &'a mut Vec<Range<usize>>,
        counts: &'a mut Vec<u32>,
    ) -> Blind<'a> {
        cuts.clear();
        counts.clear();
        counts.resize(symbols, 0);
        Blind {
            cuts,
            counts,
            symbols,
            first: 0,
            base: start,
        }
    }

    /// The run of literals that ends at position `to`, already pushed
    /// (`tokens` tokens in all) and counted into `bytes`, is where a
    /// block may have ended: each literal that completed one closes it,
    /// and the literals after it are the next block's.
    ///
    #[inline]
    fn literals(&mut self, bytes: &mut [u32; 256], tokens: usize, span: &[u8], to: usize) {
        while to - self.base >= BLIND_CUT_BYTES {
            let end = self.base + BLIND_CUT_BYTES;
            let after = &span[end..to];
            for &byte in after {
                bytes[usize::from(byte)] -= 1;
            }
            self.close(bytes, tokens - after.len(), end);
            for &byte in after {
                bytes[usize::from(byte)] += 1;
            }
        }
    }

    /// Count the match just pushed, which ends at position `end`.
    #[inline]
    fn matched<F: Format>(
        &mut self,
        format: &F,
        bytes: &mut [u32; 256],
        tokens: &[Token],
        end: usize,
    ) {
        let table = self.counts.len() - self.symbols;
        let counts = &mut self.counts[table..];
        let token = *tokens.last().expect("a match was pushed");
        format.visit(token, &mut |symbol| counts[symbol] += 1);
        if end - self.base >= BLIND_CUT_BYTES {
            self.close(bytes, tokens.len(), end);
        }
    }

    /// The open block's table, its literals added.
    fn settle(&mut self, bytes: &[u32; 256]) {
        let table = self.counts.len() - self.symbols;
        for (count, &literals) in self.counts[table..].iter_mut().zip(bytes) {
            *count += literals;
        }
    }

    fn close(&mut self, bytes: &mut [u32; 256], tokens: usize, position: usize) {
        self.settle(bytes);
        *bytes = [0; 256];
        self.cuts.push(self.first..tokens);
        self.first = tokens;
        self.base = position;
        self.counts.resize(self.counts.len() + self.symbols, 0);
    }

    /// End the last block, and take back every cut that left the block
    /// after it [`ENTROPY_BLOCK_MIN_TOKENS`] tokens or fewer: the blind
    /// cut makes none there, and once it refuses one it makes no other,
    /// since fewer tokens still are left after each later one.
    fn finish(mut self, bytes: &[u32; 256], tokens: usize) {
        self.settle(bytes);
        self.cuts.push(self.first..tokens);
        let keep = self
            .cuts
            .iter()
            .position(|cut| tokens - cut.end <= ENTROPY_BLOCK_MIN_TOKENS)
            .expect("the last block ends with the tokens");
        if keep + 1 < self.cuts.len() {
            let (kept, merged) = self.counts.split_at_mut((keep + 1) * self.symbols);
            let into = &mut kept[keep * self.symbols..];
            for table in merged.chunks_exact(self.symbols) {
                for (sum, &count) in into.iter_mut().zip(table) {
                    *sum += count;
                }
            }
            self.counts.truncate((keep + 1) * self.symbols);
            self.cuts.truncate(keep + 1);
            self.cuts[keep].end = tokens;
        }
    }
}

/// The fast parse's choice at a position where a held distance or the
/// chain has something on offer: the arm, its distance and its length,
/// [`Arm::Literal`] where neither pays. `held_asked` says some held
/// distance repeats the position's first two bytes; `chained` is the
/// chain's candidate, where it begins with the position's four.
///
/// Kept out of line: positions with nothing on offer are most of a parse
/// block, and the loop over them keeps its state in registers only while
/// it holds no call.
///
/// Its own two compares are INLINED into it on every architecture
/// ([`common_prefix_inlined`]): this function is the call, so a second one
/// inside it buys nothing. Counted 2 Oct 2026 at one thread, level 1
/// retires 2.3 to 2.4 percent fewer instructions for it on x86-64 and 3.7
/// to 4.2 on aarch64, in the plain and the `pinned` build alike.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn fast_choose<F: Format>(
    format: &F,
    span: &[u8],
    at: usize,
    room: usize,
    held: &Repeats,
    held_asked: bool,
    chained: Option<usize>,
    literal: i32,
) -> (Arm, u32, usize) {
    let first_two = u16::from_le_bytes([span[at], span[at + 1]]);
    let mut gain = 0i32;
    let mut length = 0usize;
    let mut distance = 0u32;
    let mut arm = Arm::Literal;
    let asked = if held_asked { REPEATS } else { 0 };
    for k in 0..asked {
        let back = held.distance[k];
        if back == 0 {
            // The filled slots are a prefix of the four.
            break;
        }
        let from = at - back as usize;
        if u16::from_le_bytes([span[from], span[from + 1]]) != first_two
            || held.distance[..k].contains(&back)
        {
            continue;
        }
        let agree = common_prefix_inlined(span, from, at, 2, room.min(format.longest_repeat()));
        let saves = literal * agree as i32 - FAST_HELD_PRICE;
        if saves > gain {
            gain = saves;
            length = agree;
            distance = back;
            arm = Arm::Repeat(k as u8);
        }
    }
    if length < FAST_HELD_ENOUGH {
        if let Some(from) = chained {
            let back = (at - from) as u32;
            let agree = common_prefix_inlined(span, from, at, 4, room.min(format.longest()));
            if agree >= FAST_LEAST
                && agree >= 2 + format.bonus(back) as usize
                && held.slot_of(back).is_none()
                && literal * agree as i32 - fast_fresh_price(back) > gain
            {
                length = agree;
                distance = back;
                arm = Arm::Fresh;
            }
        }
    }
    (arm, distance, length)
}

// ---------------------------------------------------------------------
// The optimal parse.
// ---------------------------------------------------------------------

/// One position of the window: the cheapest known way to reach it, and the
/// decoder's model on arriving that way.
#[derive(Clone, Copy)]
struct Node {
    price: u32,
    /// The token that arrives here.
    arm: Arm,
    length: u16,
    distance: u32,
    repeats: Repeats,
}

const UNREACHED: Node = Node {
    price: u32::MAX,
    arm: Arm::Literal,
    length: 1,
    distance: 0,
    repeats: Repeats {
        distance: [0; REPEATS],
        last_length: 0,
    },
};

/// The optimal parse's scratch, one per worker and reused by every block.
pub(crate) struct OptimalScratch {
    nodes: Vec<Node>,
    path: Vec<Token>,
}

impl OptimalScratch {
    pub(crate) fn new() -> OptimalScratch {
        OptimalScratch {
            // A window may end on any node up to one sufficient match
            // past its limit, so no match is cut by the limit itself.
            nodes: vec![UNREACHED; OPTIMAL_WINDOW_POSITIONS + OPTIMAL_SUFFICIENT_LENGTH + 1],
            path: Vec::new(),
        }
    }

    /// The bytes this scratch holds: the window's nodes, written whole
    /// when it is built, and the path at the most it has held.
    pub(crate) fn held_bytes(&self) -> u64 {
        (self.nodes.len() * std::mem::size_of::<Node>()
            + self.path.capacity() * std::mem::size_of::<Token>()) as u64
    }

    /// The most [`OptimalScratch::held_bytes`] can read: every node, and
    /// a path of one token a position of the window, at the capacity a
    /// path grown one push at a time reaches for that many.
    pub(crate) fn most_bytes() -> u64 {
        let path = (OPTIMAL_WINDOW_POSITIONS + OPTIMAL_SUFFICIENT_LENGTH).next_power_of_two();
        ((OPTIMAL_WINDOW_POSITIONS + OPTIMAL_SUFFICIENT_LENGTH + 1) * std::mem::size_of::<Node>()
            + path * std::mem::size_of::<Token>()) as u64
    }
}

/// The optimal parse's two effort dials, which a level sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OptimalDials {
    /// A match at least this long is taken without deliberating, and the
    /// next window starts after it. At most [`OPTIMAL_SUFFICIENT_LENGTH`],
    /// which is what the window's nodes are sized for.
    pub(crate) jump: usize,
    /// How many shorter lengths one position may price beyond each
    /// candidate's own full length.
    pub(crate) rungs: usize,
}

impl OptimalDials {
    /// The dials every level ran at before a level could set them.
    pub(crate) const FULL: OptimalDials = OptimalDials {
        jump: OPTIMAL_SUFFICIENT_LENGTH,
        rungs: OPTIMAL_SHORT_LENGTH_BUDGET,
    };
}

#[inline]
fn relax(nodes: &mut [Node], to: usize, price: u32, arm: Arm, length: usize, distance: u32) {
    let node = &mut nodes[to];
    if price < node.price && price < UNPRICED {
        node.price = price;
        node.arm = arm;
        node.length = length as u16;
        node.distance = distance;
    }
}

/// The optimal parse of one block.
///
/// The block's first region is parsed twice: once on the opening prices to
/// learn what its symbols cost, and again from the block's start on those
/// prices. Without that a block's first 32 KiB is parsed on guesses, and a
/// parse block is short enough for that to show.
///
/// With `back` above zero a candidate the finder did not offer at the
/// node before is also priced begun up to `back` bytes earlier, where the
/// bytes before it agree at its distance (the backward extension, as the
/// lazy parse has it). The window is compiled twice, with the extension
/// and without, as the lazy parse is.
#[allow(clippy::too_many_arguments)]
pub(crate) fn optimal_parse<F: Format>(
    format: &F,
    block: Block<'_>,
    source: Source<'_>,
    model: &mut PriceModel,
    scratch: &mut OptimalScratch,
    dials: OptimalDials,
    back: usize,
    tokens: &mut Vec<Token>,
) {
    model.open(format);
    let first = tokens.len();
    let mut repeats = Repeats::default();
    let mut at = block.start;
    while at < block.end {
        let (next, after) = if back == 0 {
            optimal_window::<F, false>(
                format, block, source, model, scratch, dials, 0, tokens, at, repeats,
            )
        } else {
            optimal_window::<F, true>(
                format, block, source, model, scratch, dials, back, tokens, at, repeats,
            )
        };
        at = next;
        repeats = after;
        let rehearsal = model.first_region_pending();
        if model.settle(format) && rehearsal {
            tokens.truncate(first);
            at = block.start;
            repeats = Repeats::default();
        }
    }
}

/// Solve one window starting at `from` and commit its path. Returns where
/// the next window starts and the model there.
#[allow(clippy::too_many_arguments)]
fn optimal_window<F: Format, const EXTEND: bool>(
    format: &F,
    block: Block<'_>,
    source: Source<'_>,
    model: &mut PriceModel,
    scratch: &mut OptimalScratch,
    dials: OptimalDials,
    back: usize,
    tokens: &mut Vec<Token>,
    from: usize,
    repeats: Repeats,
) -> (usize, Repeats) {
    let span = block.span;
    let prices = &model.prices[..];
    let nodes = &mut scratch.nodes[..];
    let width = (block.end - from).min(OPTIMAL_WINDOW_POSITIONS);
    // Nodes past the width exist only while the block has bytes for them.
    let reach = (block.end - from).min(width + OPTIMAL_SUFFICIENT_LENGTH);
    nodes[..=reach].fill(UNREACHED);
    nodes[0].price = 0;
    nodes[0].repeats = repeats;
    let longest = format.longest();
    let longest_repeat = format.longest_repeat();
    let last_price = format.last_price(prices);

    // A match long enough to take without deliberating: where it starts,
    // and what it is.
    let mut jump: Option<(usize, Arm, u32, usize)> = None;
    let mut found = [Found::default(); FOUND_MAX];
    // The distances the finder offered at the node before, so a candidate
    // is begun earlier only from where it was first offered: one it was
    // already offered there, that node priced itself.
    let mut offered = [0u32; FOUND_MAX];
    let mut offered_kept = 0usize;
    let mut index = 0;
    while index < width {
        let here = nodes[index];
        let at = from + index;
        // This node's model is its predecessor's after the token between
        // them; the predecessor is behind this one and already final.
        let state = if index == 0 {
            here.repeats
        } else {
            let before = nodes[index - here.length as usize].repeats;
            let state = before.after(here.arm, here.distance, here.length);
            nodes[index].repeats = state;
            state
        };
        let room = block.end - at;
        relax(
            nodes,
            index + 1,
            here.price + u32::from(prices[span[at] as usize]),
            Arm::Literal,
            1,
            u32::from(span[at]),
        );
        if room < 2 {
            if EXTEND {
                offered_kept = 0;
            }
            index += 1;
            continue;
        }
        let first_two = u16::from_le_bytes([span[at], span[at + 1]]);

        // The repeated distances, from every node: a two byte repeat can
        // undercut two literals, so the ladder starts at the bottom.
        let limit = room.min(longest_repeat);
        let mut longest_held = 0usize;
        for k in 0..REPEATS {
            let held = state.distance[k];
            if held == 0 || state.distance[..k].contains(&held) {
                continue;
            }
            let source = at - held as usize;
            if u16::from_le_bytes([span[source], span[source + 1]]) != first_two {
                continue;
            }
            let length = common_prefix(span, source, at, 2, limit);
            if length >= dials.jump {
                jump = Some((index, Arm::Repeat(k as u8), held, length));
                break;
            }
            longest_held = longest_held.max(length);
            let rungs = length.min(1 + OPTIMAL_REPEAT_LENGTH_BUDGET);
            for rung in (2..=rungs).chain((rungs < length).then_some(length)) {
                let price = format.repeat_price(prices, k, rung as u32);
                relax(
                    nodes,
                    index + rung,
                    here.price.saturating_add(price),
                    Arm::Repeat(k as u8),
                    rung,
                    held,
                );
            }
            if k == 0 && state.last_length as usize <= length && state.last_length >= 2 {
                relax(
                    nodes,
                    index + state.last_length as usize,
                    here.price + last_price,
                    Arm::Last,
                    state.last_length as usize,
                    held,
                );
            }
        }
        if jump.is_some() {
            break;
        }

        // The finder's candidates: nearest first, each longer than the
        // last, so a candidate is priced only over the lengths the nearer
        // ones could not reach, and down from its own top.
        let limit = room.min(longest);
        let mut covered = 1usize;
        let mut budget = dials.rungs;
        let kept = source.candidates(block, at, limit, &mut found);
        for &Found { distance, length } in &found[..kept] {
            let length = length as usize;
            if length <= covered {
                continue;
            }
            if state.slot_of(distance).is_some() {
                // Already priced above, on the cheaper arm.
                covered = covered.max(length);
                continue;
            }
            if length >= dials.jump {
                jump = Some((index, Arm::Fresh, distance, length));
                break;
            }
            let bonus = format.bonus(distance) as usize;
            let distance_price = format.fresh_distance_price(prices, distance);
            let paid = here.price.saturating_add(distance_price);
            if EXTEND && index != 0 && !offered[..offered_kept].contains(&distance) {
                // The backward extension: the same match begun up to
                // `back` bytes earlier, where the bytes before it agree at
                // its distance, priced from those nodes, which are behind
                // this one and final. Only its full length: the shorter
                // rungs stay this node's. A node that holds the distance
                // in its model priced it on the repeated arm already.
                let far = at - distance as usize;
                let most = back.min(index).min(far).min(longest - length);
                let mut step = 0;
                while step < most && span[at - step - 1] == span[far - step - 1] {
                    step += 1;
                    let origin = nodes[index - step];
                    if origin.price == u32::MAX
                        || origin.repeats.slot_of(distance).is_some()
                        || length + step < 2 + bonus
                    {
                        continue;
                    }
                    let price = format.fresh_length_price(prices, (length + step - bonus) as u32);
                    relax(
                        nodes,
                        index + length,
                        origin
                            .price
                            .saturating_add(distance_price)
                            .saturating_add(price),
                        Arm::Fresh,
                        length + step,
                        distance,
                    );
                }
            }
            let bottom = (covered + 1).max(2 + bonus);
            let mut rung = length;
            while rung >= bottom {
                let price = format.fresh_length_price(prices, (rung - bonus) as u32);
                relax(
                    nodes,
                    index + rung,
                    paid.saturating_add(price),
                    Arm::Fresh,
                    rung,
                    distance,
                );
                if rung < length {
                    if budget == 0 {
                        break;
                    }
                    budget -= 1;
                }
                rung -= 1;
            }
            if bottom == 2 && covered < 2 {
                let price = format.short_price(prices, distance);
                relax(
                    nodes,
                    index + 2,
                    here.price.saturating_add(price),
                    Arm::Short,
                    2,
                    distance,
                );
            }
            covered = length;
        }
        if jump.is_some() {
            break;
        }
        if EXTEND {
            offered_kept = kept;
            for (slot, entry) in offered.iter_mut().zip(&found[..kept]) {
                *slot = entry.distance;
            }
        }
        index += 1;
    }

    // Where the window ends: at the jump, or on the node at or past the
    // width that is cheapest for the bytes it covers.
    let stop = match jump {
        Some((index, ..)) => index,
        None => {
            let per_byte = u64::from(nodes[width].price) / width.max(1) as u64;
            (width..=reach)
                .filter(|&node| nodes[node].price != u32::MAX)
                .min_by_key(|&node| {
                    (
                        u64::from(nodes[node].price) + per_byte * (reach - node) as u64,
                        node,
                    )
                })
                .unwrap_or(width)
        }
    };

    // Walk the cheapest path back, then commit it forwards.
    let path = &mut scratch.path;
    path.clear();
    let mut node = stop;
    while node != 0 {
        let arrived = nodes[node];
        path.push(Token {
            arm: arrived.arm,
            length: arrived.length,
            distance: arrived.distance,
        });
        node -= arrived.length as usize;
    }
    let mut state = repeats;
    for &token in path.iter().rev() {
        state = state.after(token.arm, token.distance, token.length);
        tokens.push(token);
        model.observe(format, token);
    }
    let mut next = from + stop;
    if let Some((_, arm, distance, length)) = jump {
        let arm = if arm == Arm::Repeat(0) && length == state.last_length as usize {
            Arm::Last
        } else {
            arm
        };
        let token = Token {
            arm,
            length: length as u16,
            distance,
        };
        state = state.after(arm, distance, length as u16);
        tokens.push(token);
        model.observe(format, token);
        next += length;
    }
    (next, state)
}
