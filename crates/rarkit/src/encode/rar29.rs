//! The RAR 2.9 encoder (spec H3 section 7).
//!
//! It produces a byte sequence that H1's decoder reads back as the input,
//! and that reference `unrar` 7.23 extracts. As in section 6.1, the third
//! is the test that matters.
//!
//! Three things here have no analogue in the RAR 5 encoder and are the
//! ones most likely to be written as a copy of it:
//!
//! - a block header begins at a BYTE BOUNDARY, and carries a mode bit and
//!   a keep bit rather than a length and a checksum;
//! - the code lengths are ADDITIVE, so the value emitted for a position is
//!   `(wanted - stored) mod 16`, not `wanted`;
//! - a block ends with main symbol 256 and then a field saying which of
//!   H1 section 3.7's three ends it is.
//!
//! This file is the WIRE. The match finders, the parses and the block
//! boundary search are shared with the RAR 5 encoder and live in `drive`,
//! `lz` and `cut`; `drive` states the working memory.

use super::bits::{BitWriter, Code};
use super::drive::{Emit, Engine, Plan};
use super::filter::BlockRecord;
use super::huffman::{canonical, code_lengths};
use super::lz::{Arm, Format, Token, UNPRICED};
use crate::carry::c_lz::codec::rar50::PRICE_SHIFT;
use std::ops::Range;

/// Symbols in the main alphabet.
const MAIN_SYMBOLS: usize = 299;
/// Slots in the distance ladder.
const DISTANCE_SLOTS: usize = 60;
/// Symbols in the low distance alphabet: sixteen low parts and the run.
const LOW_SYMBOLS: usize = 17;
/// Slots in the length ladder.
const LENGTH_SLOTS: usize = 28;
/// Symbols in the code length alphabet.
const LEVEL_SYMBOLS: usize = 20;

/// The alphabets laid end to end, in the order one table read carries
/// them: main, distance, low distance, length.
const MAIN: Range<usize> = 0..MAIN_SYMBOLS;
const DISTANCE: Range<usize> = MAIN.end..MAIN.end + DISTANCE_SLOTS;
const LOW: Range<usize> = DISTANCE.end..DISTANCE.end + LOW_SYMBOLS;
const LENGTH: Range<usize> = LOW.end..LOW.end + LENGTH_SLOTS;
const ALPHABETS: [Range<usize>; 4] = [MAIN, DISTANCE, LOW, LENGTH];

/// The first main symbol of each arm.
const SYMBOL_BLOCK_END: usize = 256;
const SYMBOL_LAST_MATCH: usize = 258;
const SYMBOL_REPEAT: usize = 259;
const SYMBOL_SHORT: usize = 263;
const SYMBOL_FRESH: usize = 271;

/// The slot from which a distance's low part goes through the low
/// distance alphabet.
const LOW_FROM_SLOT: usize = 10;
/// The low distance symbol that says "the remembered low part, for this
/// match and the fifteen after it".
const LOW_RUN: usize = 16;
/// How many far matches one run symbol serves after its own.
const LOW_RUN_FOLLOWERS: usize = 15;
/// The longest match the fresh arm can name before the bonus: the ladder
/// reaches 255 over a base of 3 (section 7.4).
const MAX_MATCH: u32 = 258;
/// The longest the repeated distance arm can name, whose base is 2.
const MAX_REPEAT_MATCH: u32 = 257;
/// The longest distance the short arm can name.
const MAX_SHORT_DISTANCE: u32 = 256;

/// The extra bits of the short distance ladder's eight slots, H1 section
/// 3.5, and their bases.
const SHORT_BASE: [u32; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SHORT_EXTRA: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

/// Which of H1 section 3.7's three ends a block has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockEnd {
    /// The block ends and another header follows in the same member.
    SameMemberNewTables,
    /// This member's data ends here and the next starts at a header.
    NewMemberNewTables,
}

/// What the writers hand down for a RAR 4 member.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EncodeOptions {
    /// The dictionary in bytes, at most 4 MiB (section 7.4).
    pub(crate) dictionary: u32,
    /// Which parse runs and how hard the finder looks.
    pub(crate) plan: Plan,
    /// `WriteOptions::workers` (API 7.2 and 8.2), the encoder's width
    /// dial. `usize::MAX` leaves the box's own width in charge, which is
    /// what `for_level` gives a caller that has no options to hand and
    /// what a `workers` of `None` resolves to.
    pub(crate) workers: usize,
}

impl EncodeOptions {
    /// The options spec G's level `level` maps to.
    pub(crate) fn for_level(level: u8, dictionary: u32) -> EncodeOptions {
        EncodeOptions {
            // Section 7.4: the encoder's match distance is bounded by the
            // dictionary the writer declared, at most 4 MiB.
            dictionary: dictionary.min(4 << 20),
            // The thin scan (`Plan::for_thin_block`) is RAR 5's alone: its
            // rows are the ones it was measured on.
            plan: Plan {
                scans_thin: false,
                ..Plan::for_level(level)
            },
            workers: usize::MAX,
        }
    }

    /// The same, with the plan SPELLED OUT rather than taken from the
    /// level: the level ladder's sweeps, and nothing a shipped build can
    /// reach. See [`Plan::spelled`].
    #[cfg(feature = "bench-internals")]
    pub(crate) fn spelled(plan: &str, dictionary: u32) -> Option<EncodeOptions> {
        Some(EncodeOptions {
            dictionary: dictionary.min(4 << 20),
            plan: Plan::spelled(plan)?,
            // A sweep hands the encoder every core it has; the level
            // ladder's dial sweeps set the width through the pool they
            // run in, not through the policy.
            workers: usize::MAX,
        })
    }
}

/// The RAR 2.9 encoder. One per member.
pub(crate) struct Rar29Encoder {
    engine: Engine,
}

impl Rar29Encoder {
    /// An encoder for `options`. Its working memory is sized from the
    /// dictionary and the plan when the first member arrives, never from a
    /// member, and kept for the members after it.
    pub(crate) fn new(options: EncodeOptions) -> Rar29Encoder {
        Rar29Encoder {
            engine: Engine::new(options.plan, options.dictionary as usize, options.workers)
                .without_empty_stride(),
        }
    }

    /// Encode one member's bytes, returning its packed data.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub(crate) fn encode(&mut self, input: &[u8]) -> Vec<u8> {
        self.engine.encode(&Wire, input)
    }

    /// Encode the bytes of `span` from `emit_from` on, appending their
    /// blocks to `out` and flagging the last only when the member ends
    /// here. `span[..emit_from]` is history the decoder already holds:
    /// spec G 3.7.3's window before this one, or spec G 3.9's member
    /// before this one. `Engine::encode_region` has the whole rule.
    pub(crate) fn encode_region(
        &mut self,
        span: &[u8],
        emit_from: usize,
        last: bool,
        out: &mut Vec<u8>,
    ) {
        self.engine.encode_region(&Wire, span, emit_from, last, out);
    }

    /// Encode `chunk` as the continuation of what this encoder carries:
    /// spec G 3.7.3's next window, or spec G 3.9's next solid member.
    /// `Engine::encode_chunk` has the whole rule.
    /// Never build the chains' pass across the pool.
    /// `Engine::no_chain_build`.
    pub(crate) fn no_chain_build(&mut self) {
        self.engine.no_chain_build();
    }

    /// Build the chains' pass across the pool from `width` threads up,
    /// `usize::MAX` for never. `Engine::set_chain_build_from`.
    #[cfg(all(test, feature = "parallel"))]
    pub(crate) fn set_chain_build_from(&mut self, width: usize) {
        self.engine.set_chain_build_from(width);
    }

    pub(crate) fn encode_chunk(&mut self, chunk: &[u8], last: bool, out: &mut Vec<u8>) {
        self.engine.encode_chunk(&Wire, chunk, last, out);
    }

    /// Stage one chunk of a carried run, whose packed bytes the next
    /// [`Rar29Encoder::flush`] hands back. `Engine::stage` has the whole rule,
    /// and `Engine::may_stage` says when a chunk may join the batch.
    pub(crate) fn may_stage(&self, chunk: usize) -> bool {
        self.engine.may_stage(chunk)
    }

    /// Stage one chunk of a carried run. See [`Rar29Encoder::may_stage`].
    pub(crate) fn stage(&mut self, chunk: &[u8], last: bool) {
        self.engine.stage(chunk, last);
    }

    /// Parse the whole batch as one wave and hand back each staged
    /// chunk's packed bytes, in staging order. `Engine::flush` says why
    /// the bytes are the same as one call per chunk.
    pub(crate) fn flush(&mut self) -> &mut [Vec<u8>] {
        self.engine.flush(&Wire)
    }

    /// Give the chunk staged last `out` to write its packed bytes into,
    /// in place of the buffer this encoder would have used. `Engine::lend_out`.
    pub(crate) fn lend_out(&mut self, out: Vec<u8>) {
        self.engine.lend_out(out);
    }

    /// Lend the first chunk staged `out` to append to. `Engine::lend_first`.
    pub(crate) fn lend_first(&mut self, out: Vec<u8>) {
        self.engine.lend_first(out);
    }

    /// End the carried run: the next chunk starts from no history, as a
    /// member of a non-solid set does (spec H3 section 4).
    pub(crate) fn reset_history(&mut self) {
        self.engine.reset_history();
    }

    /// Stand where an engine that has just slid stands, mid-member, with
    /// `kept` its kept dictionary. `Engine::resume_slid` has the rule.
    pub(crate) fn resume_slid(&mut self, kept: &[u8]) {
        self.engine.resume_slid(kept);
    }

    /// Whether other engines flush on this encoder's pool while it does.
    /// `Engine::share_pool`.
    #[cfg(feature = "parallel")]
    pub(crate) fn share_pool(&mut self, engines: usize) {
        self.engine.share_pool(engines);
    }

    /// How many of a streamed member's next `left` bytes come before the
    /// next slide. `Engine::streamed_period`.
    #[cfg(feature = "parallel")]
    pub(crate) fn streamed_period(&self, window: usize, history: usize, left: u64) -> u64 {
        self.engine.streamed_period(window, history, left)
    }

    /// How many bytes a slide keeps. `Engine::kept_by_slide`.
    #[cfg(feature = "parallel")]
    pub(crate) fn kept_by_slide(&self, history: usize) -> usize {
        self.engine.kept_by_slide(history)
    }

    /// End the carried run and start ONE whole member of `size` bytes from
    /// no history, by the plan its class gives it
    /// (`encode::drive::Engine::start_member`): `head` is the member's
    /// first bytes, unfiltered.
    pub(crate) fn start_member(&mut self, head: &[u8], size: u64) {
        self.engine.start_member(head, size);
    }

    /// Whether [`Self::start_member`] reads the head of a member of `size`
    /// bytes.
    pub(crate) fn reads_head(&self, size: u64) -> bool {
        self.engine.reads_head(size)
    }

    /// The carried history's slack, in dictionaries.
    /// `Engine::set_slack_multiple` has the rule.
    pub(crate) fn set_slack_multiple(&mut self, multiple: usize) {
        self.engine.set_slack_multiple(multiple);
    }

    /// The carried history's own bytes, which spec G's writer counts as
    /// working memory.
    pub(crate) fn held_bytes(&self) -> u64 {
        self.engine.held_bytes()
    }

    /// The finder's structures and hints, in bytes. `Engine::structure_bytes`.
    pub(crate) fn structure_bytes(&self) -> u64 {
        self.engine.structure_bytes()
    }

    /// What one fresh member of at most one parse block leaves this
    /// encoder holding. `Engine::one_block_structure_bytes`.
    pub(crate) fn one_block_structure_bytes(&self, whole_run: bool) -> u64 {
        self.engine.one_block_structure_bytes(whole_run)
    }

    /// Whether a lone member is walked by another finder than the level's.
    /// `Engine::lone_finder_differs`.
    pub(crate) fn lone_finder_differs(&self) -> bool {
        self.engine.lone_finder_differs()
    }

    /// What one fresh member of `len` bytes leaves this encoder holding.
    /// `Engine::member_structure_bytes`.
    pub(crate) fn member_structure_bytes(&self, len: usize, whole_run: bool) -> u64 {
        self.engine.member_structure_bytes(len, whole_run)
    }

    /// The most this encoder holds while it encodes one member of `len`
    /// bytes. `Engine::member_held_bytes`.
    pub(crate) fn member_held_bytes(&self, len: usize, window: Option<usize>) -> u64 {
        self.engine.member_held_bytes(len, window)
    }

    /// The same with one finder charged, the larger.
    /// `Engine::member_one_finder_bytes`.
    pub(crate) fn member_one_finder_bytes(&self, len: usize, window: Option<usize>) -> u64 {
        self.engine.member_one_finder_bytes(len, window)
    }

    /// The same for a caller's named ceiling.
    /// `Engine::member_named_finder_bytes`.
    pub(crate) fn member_named_finder_bytes(
        &self,
        len: usize,
        window: Option<usize>,
        head: Option<&[u8]>,
    ) -> u64 {
        self.engine.member_named_finder_bytes(len, window, head)
    }

    /// The same where the chains walk the member. `Engine::member_chain_bytes`.
    pub(crate) fn member_chain_bytes(&self, len: usize, window: Option<usize>) -> u64 {
        self.engine.member_chain_bytes(len, window)
    }

    /// Spec G 3.5's finder term for a run over `span` positions.
    /// `Engine::finder_term`.
    pub(crate) fn finder_term(&self, span: usize) -> u64 {
        self.engine.finder_term(span)
    }

    /// Whether the finder is the tree. `Engine::walks_tree`.
    pub(crate) fn walks_tree(&self) -> bool {
        self.engine.walks_tree()
    }

    /// The member's effort. `Engine::member_effort`.
    #[cfg(feature = "parallel")]
    pub(crate) fn member_effort(&self) -> crate::encode::drive::Plan {
        self.engine.member_effort()
    }

    /// Walk the member by `effort`. `Engine::walk_member_by`.
    pub(crate) fn walk_member_by(&mut self, effort: crate::encode::drive::Plan) {
        self.engine.walk_member_by(effort);
    }

    /// Whether the member in progress is parsed lazily over the chains.
    /// `Engine::member_walks_lazy_chains`.
    #[cfg(feature = "parallel")]
    pub(crate) fn member_walks_lazy_chains(&self) -> bool {
        self.engine.member_walks_lazy_chains()
    }

    /// Hold every flush to `bytes` in flight. `Engine::hold_wave`.
    pub(crate) fn hold_wave(&mut self, bytes: usize) {
        self.engine.hold_wave(bytes);
    }

    /// Parse at most `parses` blocks at once. `Engine::hold_parses`.
    pub(crate) fn hold_parses(&mut self, parses: usize) {
        self.engine.hold_parses(parses);
    }

    /// Hold the chains' wave to `blocks` blocks. `Engine::hold_chain_width`.
    pub(crate) fn hold_chain_width(&mut self, blocks: usize) {
        self.engine.hold_chain_width(blocks);
    }

    /// The walkers a walk of this encoder takes. `Engine::walkers`.
    #[cfg(test)]
    pub(crate) fn walkers_for_test(&self) -> usize {
        self.engine.walkers()
    }

    /// The most bytes one flush of this run will stage.
    /// `Engine::plan_flush`.
    pub(crate) fn plan_flush(&mut self, bytes: usize) {
        self.engine.plan_flush(bytes);
    }

    /// What the parses hold now. `Engine::flight_bytes`.
    pub(crate) fn flight_bytes(&self) -> u64 {
        self.engine.flight_bytes()
    }

    /// The most the parses hold for a flush of `bytes`.
    /// `Engine::flight_term`.
    pub(crate) fn flight_term(&self, bytes: usize) -> u64 {
        self.engine.flight_term(bytes)
    }

    /// `Engine::flight_term_over`.
    pub(crate) fn flight_term_over(&self, bytes: usize, span: usize) -> u64 {
        self.engine.flight_term_over(bytes, span)
    }

    /// Encode `chunk` as a whole member from a fresh history, in one
    /// chunk. `Engine::encode_whole_run` has the whole rule.
    pub(crate) fn encode_whole_run(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        self.engine.encode_whole_run(&Wire, chunk, out, &[]);
    }

    /// Slide the carried history sooner than the shipped slack would, so
    /// a test can pay for a slide. `Engine::set_history_slack` says why.
    #[cfg(feature = "bench-internals")]
    pub(crate) fn set_history_slack(&mut self, bytes: usize) {
        self.engine.set_history_slack(bytes);
    }
}

/// The RAR 2.9 wire format, as the parses and the entropy coder see it.
struct Wire;

/// The wire, for the shared pieces' tests.
#[cfg(test)]
pub(super) fn wire_for_tests() -> impl super::drive::Emit {
    Wire
}

impl Format for Wire {
    fn symbols(&self) -> usize {
        LENGTH.end
    }

    fn alphabets(&self) -> &[Range<usize>] {
        &ALPHABETS
    }

    fn opening_price(&self, index: usize) -> u16 {
        let bits = match index {
            0 => 8,
            1 => 5,
            2 => 4,
            _ => 3,
        };
        bits << PRICE_SHIFT
    }

    fn longest(&self) -> usize {
        MAX_MATCH as usize
    }

    fn longest_repeat(&self) -> usize {
        MAX_REPEAT_MATCH as usize
    }

    #[inline]
    fn bonus(&self, distance: u32) -> u32 {
        gained(distance)
    }

    #[inline]
    fn fresh_distance_price(&self, prices: &[u16], distance: u32) -> u32 {
        let (slot, extra, bits) = distance_fields(distance);
        let slot_price = u32::from(prices[DISTANCE.start + slot]);
        if slot >= LOW_FROM_SLOT {
            slot_price
                + (u32::from(bits - 4) << PRICE_SHIFT)
                + u32::from(prices[LOW.start + (extra & 0xf) as usize])
        } else {
            slot_price + (u32::from(bits) << PRICE_SHIFT)
        }
    }

    #[inline]
    fn fresh_length_price(&self, prices: &[u16], encoded: u32) -> u32 {
        if !(3..=MAX_MATCH).contains(&encoded) {
            return UNPRICED;
        }
        let (slot, _, bits) = length_fields(encoded - 3);
        u32::from(prices[SYMBOL_FRESH + slot]) + (u32::from(bits) << PRICE_SHIFT)
    }

    #[inline]
    fn repeat_price(&self, prices: &[u16], k: usize, length: u32) -> u32 {
        let (slot, _, bits) = length_fields(length - 2);
        u32::from(prices[SYMBOL_REPEAT + k])
            + u32::from(prices[LENGTH.start + slot])
            + (u32::from(bits) << PRICE_SHIFT)
    }

    #[inline]
    fn last_price(&self, prices: &[u16]) -> u32 {
        u32::from(prices[SYMBOL_LAST_MATCH])
    }

    #[inline]
    fn short_price(&self, prices: &[u16], distance: u32) -> u32 {
        if distance > MAX_SHORT_DISTANCE {
            return UNPRICED;
        }
        let (slot, _, bits) = short_fields(distance);
        u32::from(prices[SYMBOL_SHORT + slot]) + (u32::from(bits) << PRICE_SHIFT)
    }

    #[inline]
    fn visit(&self, token: Token, symbol: &mut dyn FnMut(usize)) -> u32 {
        match token.arm {
            Arm::Literal => {
                symbol(token.distance as usize);
                0
            }
            Arm::Fresh => {
                let wanted = u32::from(token.length) - gained(token.distance) - 3;
                let (slot, _, length_bits) = length_fields(wanted);
                symbol(SYMBOL_FRESH + slot);
                let (slot, extra, bits) = distance_fields(token.distance);
                symbol(DISTANCE.start + slot);
                if slot >= LOW_FROM_SLOT {
                    // The run form is decided when the block is written;
                    // the statistics count the low part it stands for.
                    symbol(LOW.start + (extra & 0xf) as usize);
                    u32::from(length_bits) + u32::from(bits - 4)
                } else {
                    u32::from(length_bits) + u32::from(bits)
                }
            }
            Arm::Repeat(k) => {
                symbol(SYMBOL_REPEAT + k as usize);
                let (slot, _, bits) = length_fields(u32::from(token.length) - 2);
                symbol(LENGTH.start + slot);
                u32::from(bits)
            }
            Arm::Last => {
                symbol(SYMBOL_LAST_MATCH);
                0
            }
            Arm::Short => {
                let (slot, _, bits) = short_fields(token.distance);
                symbol(SYMBOL_SHORT + slot);
                u32::from(bits)
            }
        }
    }
}

impl Emit for Wire {
    fn emit(
        &self,
        tokens: &[Token],
        cuts: &[Range<usize>],
        last: bool,
        records: &[BlockRecord],
        out: &mut Vec<u8>,
    ) {
        // RAR 4 writes no filter record, so none reaches here.
        debug_assert!(records.is_empty(), "no RAR 2.9 filter record");
        let mut bits = BitWriter::new();
        let mut frequency = vec![0u32; self.symbols()];
        let mut lengths = vec![0u8; self.symbols()];
        let mut codes = vec![Code::default(); self.symbols()];
        let mut lows: Vec<u8> = Vec::new();
        for (index, cut) in cuts.iter().enumerate() {
            let tokens = &tokens[cut.clone()];
            low_forms(tokens, &mut lows);
            frequency.fill(0);
            for &token in tokens {
                self.visit(token, &mut |symbol| {
                    if !LOW.contains(&symbol) {
                        frequency[symbol] += 1;
                    }
                });
            }
            for &form in &lows {
                if usize::from(form) <= LOW_RUN {
                    frequency[LOW.start + usize::from(form)] += 1;
                }
            }
            // Every block this encoder writes ends with symbol 256, so it
            // always has a code.
            frequency[SYMBOL_BLOCK_END] += 1;
            for range in &ALPHABETS {
                code_lengths(&frequency[range.clone()], &mut lengths[range.clone()]);
                canonical(&lengths[range.clone()], &mut codes[range.clone()]);
            }

            // A block header begins at a byte boundary; bits left in the
            // partly used byte are discarded.
            bits.align();
            bits.push(0, 1); // mode bit: an LZ block, not a PPM one
                             // The keep bit is always clear here, which makes every table
                             // read absolute and so every emitted length equal to the one
                             // wanted (section 7.2). Emitting a set one is a ratio choice
                             // this encoder does not take.
            bits.push(0, 1);
            write_length_table(&mut bits, &lengths);
            write_tokens(&mut bits, tokens, &codes, &lows);
            bits.push_code(codes[SYMBOL_BLOCK_END]);
            let ending = if last && index + 1 == cuts.len() {
                BlockEnd::NewMemberNewTables
            } else {
                BlockEnd::SameMemberNewTables
            };
            match ending {
                BlockEnd::SameMemberNewTables => bits.push(1, 1),
                BlockEnd::NewMemberNewTables => {
                    bits.push(0, 1);
                    bits.push(1, 1);
                }
            }
        }
        // The next parse block's first header is at a byte boundary too,
        // so the blocks' bytes join end to end.
        let (bytes, _) = bits.finish();
        out.extend_from_slice(bytes);
    }
}

/// A far match whose low part rides on a run symbol before it.
pub(super) const LOW_IN_RUN: u8 = 17;

/// How each far match of one block sends its low four bits, in order: a
/// low part (0 to 15), the run symbol (16), or nothing because a run is in
/// force ([`LOW_IN_RUN`]).
///
/// H1 section 3.5: the remembered low part and the run counter are zero
/// after every table read, and every block here reads tables, so the
/// decision is the block's own. The run symbol serves this match and the
/// fifteen after it WHETHER OR NOT they agree, so it is used only where
/// every one of them, or every one the block has left, carries the
/// remembered part (section 7.3: "the run form used when it pays").
pub(super) fn low_forms(tokens: &[Token], forms: &mut Vec<u8>) {
    forms.clear();
    for &token in tokens {
        if token.arm == Arm::Fresh {
            let (slot, extra, _) = distance_fields(token.distance);
            if slot >= LOW_FROM_SLOT {
                forms.push((extra & 0xf) as u8);
            }
        }
    }
    let mut remembered = 0u8;
    let mut at = 0;
    while at < forms.len() {
        let served = (forms.len() - at).min(1 + LOW_RUN_FOLLOWERS);
        if served > 2 && forms[at..at + served].iter().all(|&low| low == remembered) {
            forms[at] = LOW_RUN as u8;
            forms[at + 1..at + served].fill(LOW_IN_RUN);
            at += served;
        } else {
            remembered = forms[at];
            at += 1;
        }
    }
}

/// Write a block's tokens with the tables just emitted.
fn write_tokens(out: &mut BitWriter, tokens: &[Token], codes: &[Code], lows: &[u8]) {
    let mut lows = lows.iter();
    for &token in tokens {
        match token.arm {
            Arm::Literal => out.push_code(codes[token.distance as usize]),
            Arm::Fresh => {
                // The bonus is subtracted before the slot is chosen, with
                // H1's two thresholds rather than H2's three.
                let wanted = u32::from(token.length) - gained(token.distance) - 3;
                let (slot, extra, bits) = length_fields(wanted);
                out.push_code(codes[SYMBOL_FRESH + slot]);
                out.push(extra, bits);
                let (slot, extra, bits) = distance_fields(token.distance);
                out.push_code(codes[DISTANCE.start + slot]);
                if slot >= LOW_FROM_SLOT {
                    // The high part as plain bits when the slot has more
                    // than four, then the low four through the low
                    // distance alphabet, or through a run already paid.
                    if bits > 4 {
                        out.push(extra >> 4, bits - 4);
                    }
                    let form = *lows.next().expect("a form for every far match");
                    if form != LOW_IN_RUN {
                        out.push_code(codes[LOW.start + usize::from(form)]);
                    }
                } else {
                    out.push(extra, bits);
                }
            }
            Arm::Repeat(k) => {
                out.push_code(codes[SYMBOL_REPEAT + k as usize]);
                let (slot, extra, bits) = length_fields(u32::from(token.length) - 2);
                out.push_code(codes[LENGTH.start + slot]);
                out.push(extra, bits);
            }
            Arm::Last => out.push_code(codes[SYMBOL_LAST_MATCH]),
            Arm::Short => {
                let (slot, extra, bits) = short_fields(token.distance);
                out.push_code(codes[SYMBOL_SHORT + slot]);
                out.push(extra, bits);
            }
        }
    }
}

/// The length slot for `value`, a length less its arm's base, with the
/// slot's extra bits and their count (H1 section 3.4). The ladder is eight
/// single slots and then four to each power of two.
#[inline]
pub(super) fn length_fields(value: u32) -> (usize, u32, u8) {
    debug_assert!(value < 256);
    if value < 8 {
        return (value as usize, 0, 0);
    }
    let extra_bits = (u32::BITS - value.leading_zeros() - 3) as u8;
    let slot = 4 * (extra_bits as usize + 1) + ((value >> extra_bits) & 3) as usize;
    (slot, value & ((1 << extra_bits) - 1), extra_bits)
}

/// The distance slot, its extra bits' value and their count (H1 section
/// 3.5): two slots to each power of two up to slot 35, then twelve slots
/// of 16 bits 65,536 apart, then twelve of 18 bits 262,144 apart.
#[inline]
pub(super) fn distance_fields(distance: u32) -> (usize, u32, u8) {
    debug_assert!((1..=4 << 20).contains(&distance));
    let value = distance - 1;
    if value < 4 {
        (value as usize, 0, 0)
    } else if value < 262_144 {
        let extra_bits = (u32::BITS - value.leading_zeros() - 2) as u8;
        let slot = 2 * extra_bits as usize + 2 + ((value >> extra_bits) & 1) as usize;
        (slot, value & ((1 << extra_bits) - 1), extra_bits)
    } else if value < 1_048_576 {
        (32 + (value >> 16) as usize, value & 0xffff, 16)
    } else {
        (44 + (value >> 18) as usize, value & 0x3_ffff, 18)
    }
}

/// The short distance ladder, H1 section 3.5: eight slots tiling 1 to 256.
#[inline]
pub(super) fn short_fields(distance: u32) -> (usize, u32, u8) {
    let value = distance - 1;
    let slot = SHORT_BASE.partition_point(|&base| base <= value) - 1;
    (slot, value - SHORT_BASE[slot], SHORT_EXTRA[slot])
}

/// Distances from which a fresh RAR 3 match is one byte longer than its
/// slot and extra bits say, a byte for each (SPEC-H1 3.5). The distance
/// itself counts, where RAR 5's rule wants it passed.
const LONGER_FROM: [u32; 2] = [0x2000, 0x4_0000];

/// The bytes a fresh match at `distance` gains by [`LONGER_FROM`].
#[inline]
fn gained(distance: u32) -> u32 {
    LONGER_FROM
        .iter()
        .map(|&edge| u32::from(distance >= edge))
        .sum()
}

/// One code length run, as the code length alphabet frames it.
#[derive(Clone, Copy)]
struct LevelRun {
    symbol: u8,
    extra: u32,
    bits: u8,
}

/// Write `lengths` through the 20 symbol code length alphabet.
///
/// The keep bit is clear in every block this encoder writes, so the stored
/// array the decoder adds to is zero and the value emitted for a position
/// is the length wanted there. That is the ONE place this differs from an
/// encoder that sets the keep bit, where the value would be
/// `(wanted - stored) mod 16`; the additive form is why this emitter is
/// deliberately not shared with the RAR 5 one.
fn write_length_table(out: &mut BitWriter, lengths: &[u8]) {
    let mut runs: Vec<LevelRun> = Vec::with_capacity(lengths.len());
    let mut at = 0;
    while at < lengths.len() {
        let value = lengths[at];
        let mut run = 1;
        while at + run < lengths.len() && lengths[at + run] == value {
            run += 1;
        }
        let (long, short) = if value == 0 { (19u8, 18u8) } else { (17, 16) };
        // A nonzero value is written once and then repeated; a zero run is
        // written by the zero run symbols alone.
        let mut left = if value == 0 {
            run
        } else {
            runs.push(LevelRun {
                symbol: value,
                extra: 0,
                bits: 0,
            });
            run - 1
        };
        while left >= 11 {
            let take = left.min(11 + 127);
            runs.push(LevelRun {
                symbol: long,
                extra: (take - 11) as u32,
                bits: 7,
            });
            left -= take;
        }
        while left >= 3 {
            let take = left.min(3 + 7);
            runs.push(LevelRun {
                symbol: short,
                extra: (take - 3) as u32,
                bits: 3,
            });
            left -= take;
        }
        for _ in 0..left {
            runs.push(LevelRun {
                symbol: value,
                extra: 0,
                bits: 0,
            });
        }
        at += run;
    }

    let mut frequency = [0u32; LEVEL_SYMBOLS];
    for run in &runs {
        frequency[run.symbol as usize] += 1;
    }
    let mut level_lengths = [0u8; LEVEL_SYMBOLS];
    code_lengths(&frequency, &mut level_lengths);
    let mut level_codes = [Code::default(); LEVEL_SYMBOLS];
    canonical(&level_lengths, &mut level_codes);

    // The alphabet's own lengths: 4 bits each, with 15 escaping to four
    // more, where zero means a length of 15 and anything else would skip
    // symbols. This emitter never skips.
    for &length in &level_lengths {
        if length == 15 {
            out.push(15, 4);
            out.push(0, 4);
        } else {
            out.push(u32::from(length), 4);
        }
    }
    for run in &runs {
        out.push_code(level_codes[run.symbol as usize]);
        out.push(run.extra, run.bits);
    }
}
