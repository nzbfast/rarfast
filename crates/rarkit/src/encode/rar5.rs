//! The RAR 5 encoder (spec H3 sections 6 and 8.3).
//!
//! It produces a byte sequence that H2's decoder reads back as the input,
//! and that reference `unrar` extracts. The third is the test that
//! matters: an encoder and a decoder that agree with each other and not
//! with the format is exactly the defect open question 1 records on the
//! RAR 2.0 side, and it went unnoticed for as long as the fixtures came
//! from the same engine.
//!
//! This file is the WIRE: the alphabets, what each token costs and writes,
//! the tables and the block header. The match finder, the parses and the
//! block boundary search are shared with the RAR 2.9 encoder and live in
//! `drive`, `lz` and `cut`; `drive` states the working memory.

use super::bits::{BitWriter, Code, Push};
use super::drive::{CarriedSet, Emit, Engine, Plan};
use super::filter::{write_record, BlockRecord, FilterSpan};
use super::huffman::{canonical, code_lengths, code_lengths_dense};
use super::lz::{Arm, Format, Token, UNPRICED};
use crate::carry::c_lz::codec::rar50::PRICE_SHIFT;
use std::ops::Range;

/// Symbols in the main alphabet.
const MAIN_SYMBOLS: usize = 306;
/// Slots in the distance ladder, by algorithm version (spec H2 3.3).
const DISTANCE_SLOTS_V0: usize = 64;
const DISTANCE_SLOTS_V1: usize = 80;
/// Symbols in the alignment alphabet.
const ALIGN_SYMBOLS: usize = 16;
/// Slots in the length ladder.
const LENGTH_SLOTS: usize = 44;
/// Symbols in the code length alphabet.
const LEVEL_SYMBOLS: usize = 20;

/// The first main symbol of each arm.
/// Main symbol 256 frames a filter record (H2 section 3.6).
const SYMBOL_FILTER: usize = 256;
const SYMBOL_LAST_LENGTH: usize = 257;
const SYMBOL_REPEAT: usize = 258;
const SYMBOL_FRESH: usize = 262;

/// The longest length the ladder can name: slot 43 reaches
/// `(7 << 9 | 511) + 2`.
const MAX_MATCH: u32 = 4_097;
/// A distance slot with at least this many extra bits sends its low four
/// through the alignment alphabet.
const ALIGN_BITS: u8 = 4;

/// The most bytes one entropy block packs to, its header included.
///
/// Reference `unrar` 7.23 decodes a member's blocks on several threads
/// only while every block is at most about 128 KiB packed: counted black
/// box on aarch64 and x86-64,
/// blocks of
/// 129,189 bytes decode in parallel and blocks of 131,092 do not, and from
/// the first larger block to the member's end it decodes serially. A 256
/// KiB parse block of incompressible bytes packs to about 262 KB as one
/// block, which made unrar extract a 4 GiB mixed member 2.1x slower than
/// rar's archive of it. The ceiling sits under the line with room to
/// spare; the format itself allows far larger blocks, so this is a
/// choice for the reader, not a rule of the format.
const BLOCK_BYTES_MOST: usize = 120 << 10;

/// What the writers hand down (spec G section 1.2).
#[derive(Debug, Clone, Copy)]
pub(crate) struct EncodeOptions {
    /// The dictionary in bytes, which bounds a match's distance.
    pub(crate) dictionary: u32,
    /// The algorithm version the member's header declares: 0 gives a 64
    /// slot distance alphabet, 1 gives 80.
    pub(crate) version: u8,
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
            dictionary,
            version: 0,
            plan: Plan::for_level(level),
            workers: usize::MAX,
        }
    }

    /// The same, with the plan SPELLED OUT rather than taken from the
    /// level: the level ladder's sweeps, and nothing a shipped build can
    /// reach. See [`Plan::spelled`].
    #[cfg(feature = "bench-internals")]
    pub(crate) fn spelled(plan: &str, dictionary: u32) -> Option<EncodeOptions> {
        Some(EncodeOptions {
            dictionary,
            version: 0,
            plan: Plan::spelled(plan)?,
            // A sweep hands the encoder every core it has; the level
            // ladder's dial sweeps set the width through the pool they
            // run in, not through the policy.
            workers: usize::MAX,
        })
    }
}

/// The RAR 5 encoder. One per member.
pub(crate) struct Rar5Encoder {
    wire: Wire,
    engine: Engine,
}

impl Rar5Encoder {
    /// An encoder for `options`. Its working memory is sized from the
    /// dictionary and the plan when the first member arrives, never from a
    /// member, and kept for the members after it.
    pub(crate) fn new(options: EncodeOptions) -> Rar5Encoder {
        Rar5Encoder {
            wire: Wire::new(options.version),
            engine: Engine::new(options.plan, options.dictionary as usize, options.workers),
        }
    }

    /// Encode one member's bytes, returning its packed data: a chain of
    /// blocks, the last of them flagged.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub(crate) fn encode(&mut self, input: &[u8]) -> Vec<u8> {
        self.engine.encode(&self.wire, input)
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
        self.engine
            .encode_region(&self.wire, span, emit_from, last, out);
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

    /// Slide the chain waves or not. `Engine::set_waves_slide`.
    #[cfg(all(test, feature = "parallel"))]
    pub(crate) fn set_waves_slide(&mut self, on: bool) {
        self.engine.set_waves_slide(on);
    }

    pub(crate) fn encode_chunk(&mut self, chunk: &[u8], last: bool, out: &mut Vec<u8>) {
        self.engine.encode_chunk(&self.wire, chunk, last, out);
    }

    /// [`Rar5Encoder::encode_region`] with spec G's filter plan for
    /// `span[emit_from..]`, whose first byte sits `base` bytes into its
    /// member. `Engine::encode_region_filtered` has the whole rule.
    pub(crate) fn encode_region_filtered(
        &mut self,
        span: &[u8],
        emit_from: usize,
        last: bool,
        out: &mut Vec<u8>,
        plan: &[FilterSpan],
        base: u64,
    ) {
        self.engine
            .encode_region_filtered(&self.wire, span, emit_from, last, out, plan, base);
    }

    /// [`Rar5Encoder::encode_chunk`] with spec G's filter plan for
    /// `chunk`, whose first byte sits `base` bytes into its member.
    pub(crate) fn encode_chunk_filtered(
        &mut self,
        chunk: &[u8],
        last: bool,
        out: &mut Vec<u8>,
        plan: &[FilterSpan],
        base: u64,
    ) {
        self.engine
            .encode_chunk_filtered(&self.wire, chunk, last, out, plan, base);
    }

    /// [`Rar5Encoder::stage`] with spec G's filter plan for `chunk`.
    pub(crate) fn stage_filtered(
        &mut self,
        chunk: &[u8],
        last: bool,
        plan: &[FilterSpan],
        base: u64,
    ) {
        self.engine.stage_filtered(chunk, last, plan, base);
    }

    /// Stage one chunk of a carried run, whose packed bytes the next
    /// [`Rar5Encoder::flush`] hands back. `Engine::stage` has the whole rule,
    /// and `Engine::may_stage` says when a chunk may join the batch.
    pub(crate) fn may_stage(&self, chunk: usize) -> bool {
        self.engine.may_stage(chunk)
    }

    /// Stage one chunk of a carried run. See [`Rar5Encoder::may_stage`].
    pub(crate) fn stage(&mut self, chunk: &[u8], last: bool) {
        self.engine.stage(chunk, last);
    }

    /// Parse the whole batch as one wave and hand back each staged
    /// chunk's packed bytes, in staging order. `Engine::flush` says why
    /// the bytes are the same as one call per chunk.
    pub(crate) fn flush(&mut self) -> &mut [Vec<u8>] {
        self.engine.flush(&self.wire)
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

    /// Transform one kept window's filter spans in the resumed history.
    /// `Engine::filter_kept`.
    pub(crate) fn filter_kept(&mut self, at: usize, plan: &[FilterSpan], base: u64) {
        self.engine.filter_kept(at, plan, base);
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

    /// The finder a member's class takes, read from its head.
    /// `Engine::member_finder`.
    #[cfg(test)]
    pub(crate) fn member_finder(&self, head: &[u8], size: u64) -> super::drive::Finder {
        self.engine.member_finder(head, size)
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
    pub(crate) fn encode_whole_run(
        &mut self,
        chunk: &[u8],
        out: &mut Vec<u8>,
        plan: &[FilterSpan],
    ) {
        self.engine.encode_whole_run(&self.wire, chunk, out, plan);
    }

    /// `Engine::carry_off_for_test`.
    #[cfg(test)]
    pub(crate) fn carry_off_for_test(&mut self, off: bool) {
        self.engine.carry_off_for_test(off);
    }

    /// Weigh a counted symbol `smooth` times the floor when a member opens
    /// a carried set, in place of [`CARRY_SMOOTH`], for the sweep that
    /// chose it.
    #[cfg(test)]
    pub(crate) fn carry_smooth_for_test(&mut self, smooth: u32) {
        self.wire.smooth = smooth;
    }

    /// `Engine::slid_for_test`.
    #[cfg(test)]
    pub(crate) fn slid_for_test(&self) -> bool {
        self.engine.slid_for_test()
    }

    /// Slide the carried history sooner than the shipped slack would, so
    /// a test can pay for a slide. `Engine::set_history_slack` says why.
    #[cfg(feature = "bench-internals")]
    pub(crate) fn set_history_slack(&mut self, bytes: usize) {
        self.engine.set_history_slack(bytes);
    }
}

/// The RAR 5 alphabets laid end to end: main, distance, alignment, length,
/// which is the order H2 section 3.3 reads their code lengths in.
struct Wire {
    alphabets: [Range<usize>; 4],
    /// The most bytes one entropy block may pack to, header included.
    block_bytes_most: usize,
    /// [`CARRY_SMOOTH`], which a test may sweep.
    smooth: u32,
}

const MAIN: usize = 0;
const DISTANCE: usize = 1;
const ALIGN: usize = 2;
const LENGTH: usize = 3;

impl Wire {
    fn new(version: u8) -> Wire {
        let slots = if version == 0 {
            DISTANCE_SLOTS_V0
        } else {
            DISTANCE_SLOTS_V1
        };
        let distance = MAIN_SYMBOLS..MAIN_SYMBOLS + slots;
        let align = distance.end..distance.end + ALIGN_SYMBOLS;
        let length = align.end..align.end + LENGTH_SLOTS;
        Wire {
            alphabets: [0..MAIN_SYMBOLS, distance, align, length],
            block_bytes_most: BLOCK_BYTES_MOST,
            smooth: carry_smooth(),
        }
    }
}

/// The version 0 wire, for the shared pieces' tests.
#[cfg(test)]
pub(super) fn wire_for_tests() -> impl super::drive::Emit {
    Wire::new(0)
}

/// The version 0 wire with its packed block ceiling at `most` bytes, so a
/// test can reach the split that the cut's own ceiling leaves unreached.
#[cfg(test)]
pub(super) fn wire_with_ceiling_for_tests(most: usize) -> impl super::drive::Emit {
    Wire {
        block_bytes_most: most,
        ..Wire::new(0)
    }
}

/// [`BLOCK_BYTES_MOST`], for the tests.
#[cfg(test)]
pub(super) const BLOCK_BYTES_MOST_FOR_TESTS: usize = BLOCK_BYTES_MOST;

impl Format for Wire {
    fn symbols(&self) -> usize {
        self.alphabets[LENGTH].end
    }

    fn alphabets(&self) -> &[Range<usize>] {
        &self.alphabets
    }

    fn opening_price(&self, index: usize) -> u16 {
        // Near what real text settles at, so the rehearsal of a block's
        // first region starts from somewhere sensible.
        let bits = match index {
            MAIN => 8,
            DISTANCE => 5,
            ALIGN => 4,
            _ => 3,
        };
        bits << PRICE_SHIFT
    }

    fn longest(&self) -> usize {
        MAX_MATCH as usize
    }

    fn longest_repeat(&self) -> usize {
        MAX_MATCH as usize
    }

    #[inline]
    fn bonus(&self, distance: u32) -> u32 {
        gained(distance)
    }

    #[inline]
    fn fresh_distance_price(&self, prices: &[u16], distance: u32) -> u32 {
        let (slot, extra, bits) = distance_fields(distance);
        let slot_price = u32::from(prices[self.alphabets[DISTANCE].start + slot]);
        if bits >= ALIGN_BITS {
            slot_price
                + (u32::from(bits - ALIGN_BITS) << PRICE_SHIFT)
                + u32::from(prices[self.alphabets[ALIGN].start + (extra & 0xf) as usize])
        } else {
            slot_price + (u32::from(bits) << PRICE_SHIFT)
        }
    }

    #[inline]
    fn fresh_length_price(&self, prices: &[u16], encoded: u32) -> u32 {
        if !(2..=MAX_MATCH).contains(&encoded) {
            return UNPRICED;
        }
        let (slot, _, bits) = length_fields(encoded);
        u32::from(prices[SYMBOL_FRESH + slot]) + (u32::from(bits) << PRICE_SHIFT)
    }

    #[inline]
    fn repeat_price(&self, prices: &[u16], k: usize, length: u32) -> u32 {
        let (slot, _, bits) = length_fields(length);
        u32::from(prices[SYMBOL_REPEAT + k])
            + u32::from(prices[self.alphabets[LENGTH].start + slot])
            + (u32::from(bits) << PRICE_SHIFT)
    }

    #[inline]
    fn last_price(&self, prices: &[u16]) -> u32 {
        u32::from(prices[SYMBOL_LAST_LENGTH])
    }

    fn short_price(&self, _prices: &[u16], _distance: u32) -> u32 {
        UNPRICED
    }

    #[inline(always)]
    fn block_bits_most(&self) -> Option<u64> {
        // An eighth under the ceiling, so the cut's entropy estimate and
        // the block header stay inside it; `emit_split` is the guarantee.
        let most = self.block_bytes_most as u64;
        Some((most - most / 8) * 8)
    }

    #[inline(always)]
    fn visit(&self, token: Token, symbol: &mut dyn FnMut(usize)) -> u32 {
        match token.arm {
            Arm::Literal => {
                symbol(token.distance as usize);
                0
            }
            Arm::Fresh | Arm::Short => {
                let wanted = u32::from(token.length) - gained(token.distance);
                let (slot, _, length_bits) = length_fields(wanted);
                symbol(SYMBOL_FRESH + slot);
                let (slot, extra, bits) = distance_fields(token.distance);
                symbol(self.alphabets[DISTANCE].start + slot);
                if bits >= ALIGN_BITS {
                    symbol(self.alphabets[ALIGN].start + (extra & 0xf) as usize);
                    u32::from(length_bits) + u32::from(bits - ALIGN_BITS)
                } else {
                    u32::from(length_bits) + u32::from(bits)
                }
            }
            Arm::Repeat(k) => {
                symbol(SYMBOL_REPEAT + k as usize);
                let (slot, _, bits) = length_fields(u32::from(token.length));
                symbol(self.alphabets[LENGTH].start + slot);
                u32::from(bits)
            }
            Arm::Last => {
                symbol(SYMBOL_LAST_LENGTH);
                0
            }
        }
    }
}

impl Emit for Wire {
    const CARRIES: bool = true;

    fn emit(
        &self,
        tokens: &[Token],
        cuts: &[Range<usize>],
        last: bool,
        records: &[BlockRecord],
        out: &mut Vec<u8>,
    ) {
        let mut scratch = self.emit_scratch();
        self.emit_with(tokens, cuts, &[], false, last, records, &mut scratch, out);
    }

    fn emit_counted(
        &self,
        tokens: &[Token],
        cuts: &[Range<usize>],
        counts: &[u32],
        steady: bool,
        last: bool,
        records: &[BlockRecord],
        out: &mut Vec<u8>,
    ) {
        let mut scratch = self.emit_scratch();
        self.emit_with(
            tokens,
            cuts,
            counts,
            steady,
            last,
            records,
            &mut scratch,
            out,
        );
    }

    /// Spec H3 section 4. A member of ONE entropy block is
    /// written under the carried set, its block's table bit clear, where
    /// that costs no more bits than a fresh set of its own would with the
    /// set's code lengths written ahead of it (the carried codes for its
    /// symbols, against its own optimal codes and their table). Where it
    /// does not, the member OPENS a set, built from the counts the chain
    /// has carried (or the window before a forced opener) plus its own
    /// with every symbol floored at one ([`CARRY_SMOOTH`]), so that the
    /// members after it find a code for whatever they use; only an opener
    /// pays for that dense set. A member with no counts before it (every
    /// member of a non-solid set, a solid run's first) opens with its own
    /// set, byte for byte as [`Emit::emit`] writes it. A member
    /// of several entropy blocks opens as [`Emit::emit`] writes it (its cut
    /// already chose its sets), and its last block's set is the one in
    /// force after it. The choice reads this member's tokens and the
    /// carried state and nothing else, so it cannot move with the thread
    /// count.
    fn emit_member(
        &self,
        tokens: &[Token],
        cuts: &[Range<usize>],
        records: &[BlockRecord],
        counts: &[u32],
        carried: &mut Option<CarriedSet>,
        may_carry: bool,
        out: &mut Vec<u8>,
    ) {
        let mut lent = self.lend_scratch();
        let scratch: &mut EmitScratch = &mut lent;
        let [only] = cuts else {
            self.emit_with(tokens, cuts, &[], false, true, records, scratch, out);
            *carried = Some(CarriedSet {
                lengths: scratch.lengths.clone(),
                counts: Vec::new(),
                codes: Vec::new(),
            });
            return;
        };
        let tokens = &tokens[only.clone()];
        let carry = if may_carry { carried.take() } else { None };
        if tokens.is_empty() && records.is_empty() {
            if let Some(set) = carry {
                // A member of no bytes under a carried set owns no block
                // at all, as reference rar writes it (spec H2 3.2's zero
                // byte members): the set stays in force for the next.
                *carried = Some(set);
                return;
            }
        }
        if counts.len() == self.symbols() {
            scratch.frequency.copy_from_slice(counts);
        } else {
            self.count(tokens, records, &mut scratch.frequency);
        }
        let mut set = carry.unwrap_or_default();
        if set.counts.iter().all(|&count| count == 0) {
            // Nothing before it in the chain and no window: the member opens
            // with its own set, exactly as [`Emit::emit`] writes it, which
            // is every member of a non-solid set and a solid run's first.
            let whole = 0..tokens.len();
            self.emit_with(
                tokens,
                std::slice::from_ref(&whole),
                &[],
                false,
                true,
                records,
                scratch,
                out,
            );
            set.lengths.clear();
            set.lengths.extend_from_slice(&scratch.lengths);
            set.counts.clear();
            set.counts.extend_from_slice(&scratch.frequency);
            set.codes.clear();
            *carried = Some(set);
            return;
        }
        let carries = set.lengths.len() == self.symbols()
            && self
                .bits_under(&scratch.frequency, &set.lengths)
                .is_some_and(|carried_bits| {
                    for range in &self.alphabets {
                        code_lengths(
                            &scratch.frequency[range.clone()],
                            &mut scratch.lengths[range.clone()],
                        );
                    }
                    let own_bits = self
                        .bits_under(&scratch.frequency, &scratch.lengths)
                        .expect("its own set codes every symbol it uses");
                    carried_bits
                        <= own_bits + self.table_bits(&scratch.lengths, &mut scratch.payload)
                });
        // The chain's counts, this member's among them.
        if set.counts.len() != self.symbols() {
            set.counts = vec![0; self.symbols()];
        }
        for (count, &own) in set.counts.iter_mut().zip(scratch.frequency.iter()) {
            *count = count.saturating_add(own);
        }
        if carries {
            if set.codes.len() != self.symbols() {
                set.codes.resize(self.symbols(), Code::default());
                for range in &self.alphabets {
                    canonical(&set.lengths[range.clone()], &mut set.codes[range.clone()]);
                }
            }
            self.emit_coded(
                tokens,
                records,
                &set.lengths,
                &set.codes,
                false,
                scratch,
                out,
            );
        } else {
            let smooth = self.smooth;
            let mut weighted = std::mem::take(&mut scratch.weights);
            weighted.clear();
            weighted.extend(
                set.counts
                    .iter()
                    .map(|&count| count.saturating_mul(smooth).saturating_add(1)),
            );
            for range in &self.alphabets {
                code_lengths_dense(
                    &weighted[range.clone()],
                    &mut scratch.lengths[range.clone()],
                );
            }
            scratch.weights = weighted;
            set.lengths.clear();
            set.lengths.extend_from_slice(&scratch.lengths);
            set.codes.resize(self.symbols(), Code::default());
            for range in &self.alphabets {
                canonical(&set.lengths[range.clone()], &mut set.codes[range.clone()]);
            }
            self.emit_coded(
                tokens,
                records,
                &set.lengths,
                &set.codes,
                true,
                scratch,
                out,
            );
        }
        *carried = Some(set);
    }

    fn add_counts(
        &self,
        tokens: &[Token],
        cuts: &[Range<usize>],
        records: &[BlockRecord],
        counts: &mut Vec<u32>,
    ) {
        let [only] = cuts else { return };
        if counts.len() != self.symbols() {
            counts.resize(self.symbols(), 0);
        }
        for &token in &tokens[only.clone()] {
            self.visit(token, &mut |symbol| {
                counts[symbol] = counts[symbol].saturating_add(1);
            });
        }
        counts[SYMBOL_FILTER] = counts[SYMBOL_FILTER].saturating_add(records.len() as u32);
    }
}

/// [`CARRY_SMOOTH`], or under the `carry-sets-knob` feature a count's
/// `RARKIT_CARRY_SMOOTH`, for the sweep that chose it.
fn carry_smooth() -> u32 {
    #[cfg(feature = "carry-sets-knob")]
    if let Some(smooth) = std::env::var("RARKIT_CARRY_SMOOTH")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
    {
        return smooth.max(1);
    }
    CARRY_SMOOTH
}

/// The weight of a counted symbol against the floor of one every symbol
/// gets when a member opens a carried set: a count of `n`
/// stands for `n * CARRY_SMOOTH + 1`.
pub(super) const CARRY_SMOOTH: u32 = 4;

thread_local! {
    /// The scratch [`Emit::emit_member`] writes each member with, kept on
    /// the thread between members (carried-set chains write thousands of
    /// small members, one after another).
    static MEMBER_SCRATCH: std::cell::RefCell<Option<EmitScratch>> =
        const { std::cell::RefCell::new(None) };
}

/// A thread's member scratch, given back when dropped.
struct Lent(Option<EmitScratch>);

impl Drop for Lent {
    fn drop(&mut self) {
        if let Some(scratch) = self.0.take() {
            MEMBER_SCRATCH.with(|slot| *slot.borrow_mut() = Some(scratch));
        }
    }
}

impl std::ops::Deref for Lent {
    type Target = EmitScratch;
    fn deref(&self) -> &EmitScratch {
        self.0.as_ref().expect("lent")
    }
}

impl std::ops::DerefMut for Lent {
    fn deref_mut(&mut self) -> &mut EmitScratch {
        self.0.as_mut().expect("lent")
    }
}

impl Wire {
    /// This thread's member scratch, or a new one where it has none of
    /// this wire's alphabet size. Every field is written before it is
    /// read by each use, so nothing of the member before shows through.
    fn lend_scratch(&self) -> Lent {
        let kept = MEMBER_SCRATCH
            .with(|slot| slot.borrow_mut().take())
            .filter(|scratch| scratch.frequency.len() == self.symbols());
        Lent(Some(kept.unwrap_or_else(|| self.emit_scratch())))
    }

    fn emit_scratch(&self) -> EmitScratch {
        EmitScratch {
            payload: BitWriter::new(),
            frequency: vec![0u32; self.symbols()],
            lengths: vec![0u8; self.symbols()],
            codes: vec![Code::default(); self.symbols()],
            weights: Vec::new(),
        }
    }

    /// [`Emit::emit`] with the caller's scratch, which holds the last
    /// block's code lengths afterwards. `counts` is a table of every
    /// block's symbol counts where the parse or the cut took them
    /// ([`Emit::emit_counted`]), or empty; `steady` takes the steady
    /// writer for the tokens ([`Wire::write_tokens`]).
    #[allow(clippy::too_many_arguments)]
    fn emit_with(
        &self,
        tokens: &[Token],
        cuts: &[Range<usize>],
        counts: &[u32],
        steady: bool,
        last: bool,
        records: &[BlockRecord],
        scratch: &mut EmitScratch,
        out: &mut Vec<u8>,
    ) {
        let symbols = self.symbols();
        let counted = counts.len() == cuts.len() * symbols;
        for (index, cut) in cuts.iter().enumerate() {
            // The block's records go out in its FIRST entropy block, ahead
            // of its first token, so what the decoder has produced when it
            // reads one is the parse block's start (spec H3 section 6.6).
            let records = if index == 0 { records } else { &[] };
            let last = last && index + 1 == cuts.len();
            let at = out.len();
            let given = counted.then(|| &counts[index * symbols..][..symbols]);
            self.emit_one(
                &tokens[cut.clone()],
                records,
                last,
                given,
                steady,
                scratch,
                out,
            );
            if out.len() - at > self.block_bytes_most && cut.len() > 1 {
                out.truncate(at);
                self.emit_split(tokens, cut.clone(), records, last, scratch, out);
            }
        }
    }

    /// Count `tokens`' symbols (and `records`' frame symbol) into
    /// `frequency`.
    fn count(&self, tokens: &[Token], records: &[BlockRecord], frequency: &mut [u32]) {
        frequency.fill(0);
        // A literal's symbol is its byte, and most tokens of a fast level
        // are literals: they are counted into the table's first 256 slots
        // by a byte index, which no check guards, ahead of the arms that
        // work a slot out. The same counts.
        let (literals, others) = frequency
            .split_first_chunk_mut::<SYMBOL_FILTER>()
            .expect("the main alphabet holds every byte");
        for &token in tokens {
            if token.arm == Arm::Literal {
                literals[usize::from(token.distance as u8)] += 1;
            } else {
                self.visit(token, &mut |symbol| others[symbol - SYMBOL_FILTER] += 1);
            }
        }
        frequency[SYMBOL_FILTER] += records.len() as u32;
    }

    /// The bits `frequency`'s symbols take under code `lengths`, or `None`
    /// where one it uses has no code. Extra bits and records' own fields
    /// are the same under any set and are left out.
    fn bits_under(&self, frequency: &[u32], lengths: &[u8]) -> Option<u64> {
        let mut bits = 0u64;
        for (&count, &length) in frequency.iter().zip(lengths) {
            if count != 0 {
                if length == 0 {
                    return None;
                }
                bits += u64::from(count) * u64::from(length);
            }
        }
        Some(bits)
    }

    /// The bits `lengths` take written as a table set (H2 3.3).
    fn table_bits(&self, lengths: &[u8], payload: &mut BitWriter) -> u64 {
        payload.clear();
        write_length_table(payload, lengths);
        let (bytes, valid_bits) = payload.finish();
        (bytes.len() as u64 * 8).saturating_sub(8 - u64::from(valid_bits))
    }

    /// Write `tokens` as the member's one and last block under code
    /// `lengths`, whose canonical codes are `codes`: with them as its
    /// table set (`tables`), or with its table bit clear, decoding under
    /// the set in force.
    #[allow(clippy::too_many_arguments)]
    fn emit_coded(
        &self,
        tokens: &[Token],
        records: &[BlockRecord],
        lengths: &[u8],
        codes: &[Code],
        tables: bool,
        scratch: &mut EmitScratch,
        out: &mut Vec<u8>,
    ) {
        let EmitScratch {
            payload, frequency, ..
        } = scratch;
        // `frequency` is this member's. A far distance reads an alignment
        // symbol whatever the set (H2 3.5), and the set has a code for
        // every one this member uses.
        let aligned = self.alphabets[ALIGN]
            .clone()
            .any(|symbol| frequency[symbol] != 0);
        payload.clear();
        if tables {
            write_length_table(payload, lengths);
        }
        for &record in records {
            write_record(payload, codes[SYMBOL_FILTER], record);
        }
        self.write_tokens(payload, tokens, codes, aligned, false);
        let (bytes, valid_bits) = payload.finish();
        write_block_with(out, bytes, valid_bits, true, tables);
    }
}

/// How long one sample packs, for spec G 3.8.3's store rule: the bytes
/// [`Rar5Encoder::encode_region`] would append for `sample` alone, from
/// no history, as a member's last region, at level 1's floor, WITHOUT
/// writing them.
///
/// The rule packed each 64 KiB sample in full and read only the length of
/// what came out. Counted 1 Oct 2026:
/// 19 to 23 million instructions a sample, two thirds of them the lazy
/// parse, the rest the pass through a 4 MiB head table, the priced cut,
/// the codes, every token through the bit writer and a second hash of the
/// sample to empty the heads again.
///
/// The length is exact, and here is the whole of why. (1) The tokens are
/// the floor's lazy parse's, counted as they are chosen and never kept
/// (`floor_count::FloorCount`). (2) The priced cut of a span no longer than its
/// coarse grid has one candidate boundary, the span's end, so the sample
/// is ONE entropy block whatever its tokens. (3) A block is its two header
/// bytes, its size field, and its payload: the table set, then each
/// token's symbols under the block's own codes and its plain bits, padded
/// to a byte. The table set is built here by the emitter's own functions
/// and its bits counted; a symbol's bits are its count times its code
/// length. No code is assigned and no token written.
///
/// `None` where this form does not cover the sample: it is empty or longer
/// than the cut's coarse grid, or it packs to more than the block ceiling,
/// which the emitter answers by splitting the block. The caller packs such
/// a sample in full (`write::store`'s judge), so the length it reads is
/// the packed one in every case and not only the measured ones. No sample
/// the rule takes is either: they are 64 KiB, and 64 KiB packs to at most
/// about 74 KiB.
///
/// What one holds is the parse's head table, 2 MiB, touched as the
/// samples' words reach it, and a few KiB beside it. It is built by the
/// judge that owns it and kept as long as the judge is.
pub(crate) struct SampleLength {
    wire: Wire,
    counter: super::floor_count::FloorCount,
    lengths: Vec<u8>,
    table: BitWriter,
}

impl SampleLength {
    pub(crate) fn new() -> SampleLength {
        let wire = Wire::new(0);
        SampleLength {
            counter: super::floor_count::FloorCount::new(&wire),
            lengths: vec![0u8; wire.symbols()],
            table: BitWriter::new(),
            wire,
        }
    }

    /// The same, with the packed block ceiling at `most` bytes, so a test
    /// can reach the sample this form hands back.
    #[cfg(test)]
    fn with_ceiling_for_tests(most: usize) -> SampleLength {
        let mut length = SampleLength::new();
        length.wire.block_bytes_most = most;
        length
    }

    pub(crate) fn packed_len(&mut self, sample: &[u8]) -> Option<usize> {
        // One entropy block, whatever the tokens: `cut::cut` puts a
        // candidate boundary at each coarse grid line a span crosses
        // before its end, and a span this long crosses none.
        const _: () = assert!(
            super::floor_count::FLOOR_COUNT_MOST
                <= crate::carry::h_ours::codec::rar50::boundaries::COARSE_GRID_BYTES
        );
        if sample.is_empty() || sample.len() > super::floor_count::FLOOR_COUNT_MOST {
            return None;
        }
        #[cfg(test)]
        if SAMPLE_UNCOVERED.with(std::cell::Cell::get) {
            return None;
        }
        let plain = self.counter.count(&self.wire, sample);
        let frequency = &self.counter.frequency;
        for range in &self.wire.alphabets {
            code_lengths(&frequency[range.clone()], &mut self.lengths[range.clone()]);
        }
        let coded = self
            .wire
            .bits_under(frequency, &self.lengths)
            .expect("its own set codes every symbol it uses");
        let bits = self.wire.table_bits(&self.lengths, &mut self.table) + coded + plain;
        // `write_block_with`: the flags, the checksum, the payload's byte
        // length in the narrowest of one to three bytes, the payload.
        let payload = bits.div_ceil(8) as usize;
        let width = if payload < 0x100 {
            1
        } else if payload < 0x1_0000 {
            2
        } else {
            3
        };
        let len = 2 + width + payload;
        (len <= self.wire.block_bytes_most).then_some(len)
    }
}

#[cfg(test)]
thread_local! {
    /// A test's switch: [`SampleLength::packed_len`] answers `None` on
    /// this thread, as it does for a sample its form does not cover.
    static SAMPLE_UNCOVERED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run `work` with [`SampleLength::packed_len`] answering `None` on this
/// thread, so a test can hold the caller's fallback to account.
#[cfg(test)]
pub(crate) fn with_samples_uncovered<T>(work: impl FnOnce() -> T) -> T {
    SAMPLE_UNCOVERED.with(|flag| flag.set(true));
    let result = work();
    SAMPLE_UNCOVERED.with(|flag| flag.set(false));
    result
}

/// What [`Wire::emit`] reuses from one entropy block to the next.
struct EmitScratch {
    payload: BitWriter,
    frequency: Vec<u32>,
    lengths: Vec<u8>,
    codes: Vec<Code>,
    /// The floored counts a carried set is built from.
    weights: Vec<u32>,
}

impl Wire {
    /// Write the entropy block `range` of `tokens` as two halves split at
    /// its middle token, each split again while it packs larger than
    /// [`BLOCK_BYTES_MOST`]. The cut already prices blocks under that
    /// ceiling, so this is the guarantee rather than the rule, and it is
    /// kept out of line: the loop in `emit` is the one that must stay
    /// tight, with `emit_one` and the symbol count inlined into it.
    #[cold]
    #[inline(never)]
    fn emit_split(
        &self,
        tokens: &[Token],
        range: Range<usize>,
        records: &[BlockRecord],
        last: bool,
        scratch: &mut EmitScratch,
        out: &mut Vec<u8>,
    ) {
        let middle = range.start + range.len() / 2;
        for (half, records, last) in [
            (range.start..middle, records, false),
            (middle..range.end, &[][..], last),
        ] {
            let at = out.len();
            self.emit_one(
                &tokens[half.clone()],
                records,
                last,
                None,
                false,
                scratch,
                out,
            );
            if out.len() - at > self.block_bytes_most && half.len() > 1 {
                out.truncate(at);
                self.emit_split(tokens, half, records, last, scratch, out);
            }
        }
    }

    /// Write one entropy block: its tables, its records, its tokens.
    /// `given` is the tokens' symbol counts where the parse or the cut
    /// took them; `steady` as [`Wire::emit_with`] takes it.
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    fn emit_one(
        &self,
        tokens: &[Token],
        records: &[BlockRecord],
        last: bool,
        given: Option<&[u32]>,
        steady: bool,
        scratch: &mut EmitScratch,
        out: &mut Vec<u8>,
    ) {
        let EmitScratch {
            payload,
            frequency,
            lengths,
            codes,
            ..
        } = scratch;
        match given {
            Some(given) => {
                frequency.copy_from_slice(given);
                frequency[SYMBOL_FILTER] += records.len() as u32;
            }
            None => self.count(tokens, records, frequency),
        }
        for range in &self.alphabets {
            code_lengths(&frequency[range.clone()], &mut lengths[range.clone()]);
        }
        // Spec H2 3.3 and 3.5 (settled 19 Sep 2026): there is no
        // alignment mode. A far distance ALWAYS reads an alignment
        // symbol and an empty alphabet is `EmptyTable`, so a block
        // that emits a far distance must carry a table for it, and
        // here `aligned` is exactly that. Reference `unrar` 7.23 agrees.
        let aligned = self.alphabets[ALIGN]
            .clone()
            .any(|symbol| frequency[symbol] != 0);
        for range in &self.alphabets {
            canonical(&lengths[range.clone()], &mut codes[range.clone()]);
        }

        payload.clear();
        write_length_table(payload, lengths);
        for &record in records {
            write_record(payload, codes[SYMBOL_FILTER], record);
        }
        self.write_tokens(payload, tokens, codes, aligned, steady);
        let (bytes, valid_bits) = payload.finish();
        write_block(out, bytes, valid_bits, last);
    }
}

impl Wire {
    /// Write a block's tokens with the tables just emitted. `steady`
    /// takes the writer with no branch on the bits held
    /// ([`BitWriter::steady`]): for the fast parse's blocks, where nearly
    /// every token is a literal.
    fn write_tokens(
        &self,
        out: &mut BitWriter,
        tokens: &[Token],
        codes: &[Code],
        aligned: bool,
        steady: bool,
    ) {
        if steady {
            self.write_tokens_through(&mut out.steady(), tokens, codes, aligned);
        } else {
            self.write_tokens_through(&mut out.hold(), tokens, codes, aligned);
        }
    }

    #[inline(always)]
    fn write_tokens_through<P: Push>(
        &self,
        out: &mut P,
        tokens: &[Token],
        codes: &[Code],
        aligned: bool,
    ) {
        let distance_codes = &codes[self.alphabets[DISTANCE].clone()];
        let align_codes = &codes[self.alphabets[ALIGN].clone()];
        let length_codes = &codes[self.alphabets[LENGTH].clone()];
        // A literal's code is found by its byte, with no check, and the
        // writer's accumulator stays in registers across the loop (`out`
        // is a [`BitWriter`] held for it). The same fields in the same
        // order.
        let (literal_codes, _) = codes
            .split_first_chunk::<SYMBOL_FILTER>()
            .expect("the main alphabet holds every byte");
        let mut tokens = tokens.iter();
        while let Some(&token) = tokens.next() {
            match token.arm {
                Arm::Literal => {
                    let code = literal_codes[usize::from(token.distance as u8)];
                    // Two literals in a row go out as one field, the
                    // first's code ahead of the second's: the same bits in
                    // the same order, and half the writer's checks on a
                    // block of literals. Two codes of at most
                    // `MAX_CODE_LEN` bits fit one push.
                    match tokens.as_slice().first() {
                        Some(next) if next.arm == Arm::Literal => {
                            tokens.next();
                            let second = literal_codes[usize::from(next.distance as u8)];
                            out.push(code.bits << second.len | second.bits, code.len + second.len);
                        }
                        _ => out.push_code(code),
                    }
                }
                Arm::Fresh | Arm::Short => {
                    // The bonus is subtracted BEFORE the slot is chosen,
                    // so the decoder's addition restores the length. An
                    // encoder that forgets this writes matches three bytes
                    // short at large distances.
                    let wanted = u32::from(token.length) - gained(token.distance);
                    let (slot, extra, bits) = length_fields(wanted);
                    out.push_code(codes[SYMBOL_FRESH + slot]);
                    out.push(extra, bits);
                    let (slot, extra, bits) = distance_fields(token.distance);
                    out.push_code(distance_codes[slot]);
                    if bits >= ALIGN_BITS && aligned {
                        // H2 section 3.5: the high part as plain bits,
                        // then one alignment symbol as the low four.
                        out.push(extra >> ALIGN_BITS, bits - ALIGN_BITS);
                        out.push_code(align_codes[(extra & 0xf) as usize]);
                    } else {
                        out.push(extra, bits);
                    }
                }
                Arm::Repeat(k) => {
                    out.push_code(codes[SYMBOL_REPEAT + k as usize]);
                    let (slot, extra, bits) = length_fields(u32::from(token.length));
                    out.push_code(length_codes[slot]);
                    out.push(extra, bits);
                }
                Arm::Last => out.push_code(codes[SYMBOL_LAST_LENGTH]),
            }
        }
    }
}

// Two literal codes go out as one field (`Wire::write_tokens_through`).
const _: () = assert!(2 * super::huffman::MAX_CODE_LEN as u32 <= 32);

/// One block: the header H2 section 3.2 specifies, then the payload.
fn write_block(out: &mut Vec<u8>, payload: &[u8], valid_bits: u8, last: bool) {
    write_block_with(out, payload, valid_bits, last, true);
}

/// [`write_block`], with the table bit (flags `0x80`) set only where the
/// payload begins with a table set: clear, the block decodes under the
/// set in force (H2 3.2; a carried set for a member's first block).
fn write_block_with(out: &mut Vec<u8>, payload: &[u8], valid_bits: u8, last: bool, tables: bool) {
    // The payload's byte length goes in the narrowest of 1, 2 or 3 bytes
    // that holds it.
    let size = payload.len() as u32;
    let width: u8 = if size < 0x100 {
        1
    } else if size < 0x1_0000 {
        2
    } else {
        3
    };
    let mut flags = (((width - 1) & 3) << 3) | (valid_bits - 1);
    if tables {
        flags |= 0x80;
    }
    if last {
        flags |= 0x40;
    }
    let size_bytes = &size.to_le_bytes()[..width as usize];
    let checksum = size_bytes
        .iter()
        .fold(0x5au8 ^ flags, |acc, &byte| acc ^ byte);
    out.push(flags);
    out.push(checksum);
    out.extend_from_slice(size_bytes);
    out.extend_from_slice(payload);
}

/// The length slot, its extra bits' value and their count, for a length
/// the decoder must read back exactly (spec H2 section 3.5).
pub(super) fn length_fields(length: u32) -> (usize, u32, u8) {
    debug_assert!((2..=MAX_MATCH).contains(&length));
    let value = length - 2;
    if value < 8 {
        return (value as usize, 0, 0);
    }
    // Past the first eight slots, four slots share each count of extra
    // bits and their four runs are the lengths of one binary width (H2
    // 3.5, counted from the ladder's first length): the width gives the
    // count, and the two bits under the top one pick the slot of the four.
    let extra_bits = (u32::BITS - value.leading_zeros() - 3) as u8;
    let slot = 4 * (extra_bits as usize + 1) + ((value >> extra_bits) & 3) as usize;
    let extra = value & ((1 << extra_bits) - 1);
    (slot, extra, extra_bits)
}

/// The distance slot, its extra bits' value and their count.
pub(super) fn distance_fields(distance: u32) -> (usize, u32, u8) {
    debug_assert!(distance >= 1);
    let value = distance - 1;
    if value < 4 {
        return (value as usize, 0, 0);
    }
    let extra_bits = (u32::BITS - value.leading_zeros() - 2) as u8;
    let slot = 2 * extra_bits as usize + 2 + ((value >> extra_bits) & 1) as usize;
    let extra = value & ((1 << extra_bits) - 1);
    (slot, extra, extra_bits)
}

/// Distances a fresh RAR 5 match must lie PAST to be one byte longer
/// than its slot and extra bits say, a byte for each (SPEC-H2 3.5).
const LONGER_PAST: [u32; 3] = [0x100, 0x2000, 0x4_0000];

/// The bytes a fresh match at `distance` gains by [`LONGER_PAST`].
///
/// No inlining attribute, and that is measured: the match search asks
/// this once a candidate, and on x86-64 the same body marked `#[inline]`
/// cost a create of poorly compressible data half a percent of its
/// instructions, where left to the compiler it costs none.
fn gained(distance: u32) -> u32 {
    LONGER_PAST
        .iter()
        .map(|&edge| u32::from(distance > edge))
        .sum()
}

/// One code length run, as the code length alphabet frames it.
#[derive(Clone, Copy)]
struct LevelRun {
    symbol: u8,
    extra: u32,
    bits: u8,
}

/// Write `lengths` through the 20 symbol code length alphabet: the
/// alphabet's own lengths as 4 bit fields with the escape H1 section 3.3
/// uses, then the runs.
///
/// A RAR 5 code length REPLACES, where a RAR 3 one is a delta on the
/// length the stream already held. This emitter is deliberately not shared
/// with the RAR 2.9 one for that reason.
fn write_length_table(out: &mut BitWriter, lengths: &[u8]) {
    let mut runs: Vec<LevelRun> = Vec::with_capacity(lengths.len());
    let mut at = 0;
    while at < lengths.len() {
        let value = lengths[at];
        let mut run = 1;
        while at + run < lengths.len() && lengths[at + run] == value {
            run += 1;
        }
        if value == 0 {
            // Zero runs: symbol 19 carries 11 + 7 bits, symbol 18 carries
            // 3 + 3 bits, and anything shorter goes out one at a time.
            let mut left = run;
            while left >= 11 {
                let take = left.min(11 + 127);
                runs.push(LevelRun {
                    symbol: 19,
                    extra: (take - 11) as u32,
                    bits: 7,
                });
                left -= take;
            }
            while left >= 3 {
                let take = left.min(3 + 7);
                runs.push(LevelRun {
                    symbol: 18,
                    extra: (take - 3) as u32,
                    bits: 3,
                });
                left -= take;
            }
            for _ in 0..left {
                runs.push(LevelRun {
                    symbol: 0,
                    extra: 0,
                    bits: 0,
                });
            }
        } else {
            // The value itself, then repeats of it.
            runs.push(LevelRun {
                symbol: value,
                extra: 0,
                bits: 0,
            });
            let mut left = run - 1;
            while left >= 11 {
                let take = left.min(11 + 127);
                runs.push(LevelRun {
                    symbol: 17,
                    extra: (take - 11) as u32,
                    bits: 7,
                });
                left -= take;
            }
            while left >= 3 {
                let take = left.min(3 + 7);
                runs.push(LevelRun {
                    symbol: 16,
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
    // more, where zero means a length of 15.
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

/// The store rule's sample (spec G 3.8.3), a STAGE at a time, for the
/// count of 1 Oct 2026: what one 64
/// KiB sample packed at the floor spends in the chains' pass, the lazy
/// parse, the cut, the tables, the bit writer and the forget. It runs the
/// engine's own pieces in the order `Engine::encode_region` runs them for
/// one block, so a stage's cost here is its cost there; what it leaves
/// out is the engine's bookkeeping around them, which the whole sample
/// (`write::store::probe_whole`) carries.
#[cfg(feature = "bench-internals")]
pub(crate) mod stages {
    use super::super::chain::{Chains, KEY_SHORT};
    use super::super::cut;
    use super::super::lz::{lazy_parse, Block, PriceModel, Source};
    use super::*;

    /// Build the chains anew for this sample, as a vote's first does.
    pub(crate) const ALLOC: u32 = 1;
    /// Link the sample's positions.
    pub(crate) const INSERT: u32 = 2;
    /// The floor's lazy parse (needs [`INSERT`]).
    pub(crate) const PARSE: u32 = 4;
    /// The priced cut.
    pub(crate) const CUT: u32 = 8;
    /// Count the symbols and build the four codes' lengths.
    pub(crate) const COUNT: u32 = 16;
    /// The canonical codes and the table set written.
    pub(crate) const TABLE: u32 = 32;
    /// The tokens written and the block framed (the whole emit).
    pub(crate) const TOKENS: u32 = 64;
    /// Empty the heads the sample's words reach.
    pub(crate) const FORGET: u32 = 128;

    /// The length alone ([`SampleLength`]), and no other stage.
    pub(crate) const LENGTH: u32 = 256;

    pub(crate) struct Stages {
        length: SampleLength,
        wire: Wire,
        dictionary: usize,
        chains: Chains,
        model: PriceModel,
        tokens: Vec<Token>,
        cuts: Vec<Range<usize>>,
        scratch: EmitScratch,
        out: Vec<u8>,
    }

    impl Stages {
        pub(crate) fn new(dictionary: usize, sample: usize) -> Stages {
            let wire = Wire::new(0);
            Stages {
                length: SampleLength::new(),
                dictionary,
                chains: Chains::new(dictionary, sample, usize::MAX, KEY_SHORT),
                model: PriceModel::new(&wire),
                tokens: Vec::new(),
                cuts: Vec::new(),
                scratch: wire.emit_scratch(),
                out: Vec::new(),
                wire,
            }
        }

        /// Run the stages of `mask` over `sample`; the packed length where
        /// the mask reaches the whole emit, else a figure that keeps the
        /// stage's work from being dropped.
        pub(crate) fn run(&mut self, sample: &[u8], mask: u32) -> u64 {
            if mask == LENGTH {
                return self.length.packed_len(sample).map_or(0, |len| len as u64);
            }
            let mut kept = 0u64;
            if mask & ALLOC != 0 {
                self.chains = Chains::new(self.dictionary, sample.len(), usize::MAX, KEY_SHORT);
            }
            if mask & INSERT != 0 {
                let (heads, links) = (&mut self.chains.heads, &self.chains.links);
                links.insert(heads, sample, 0..sample.len());
                kept += u64::from(heads[0]);
            }
            if mask & PARSE != 0 {
                self.tokens.clear();
                let block = Block {
                    span: sample,
                    start: 0,
                    end: sample.len(),
                    dictionary: self.chains.links.reach(),
                };
                let source = Source::Chains {
                    chains: &self.chains.links,
                    depth: 1,
                    enough: 32,
                    // A sample is parsed asking one position a search, as
                    // it was counted: the pairing is the level plans'.
                    pair: crate::encode::chain::Pairing::Single,
                };
                lazy_parse(
                    &self.wire,
                    block,
                    source,
                    &mut self.model,
                    &mut self.tokens,
                    0,
                );
                kept += self.tokens.len() as u64;
            }
            if mask & CUT != 0 {
                cut::cut(&self.wire, &self.tokens, &mut self.cuts);
                kept += self.cuts.len() as u64;
            }
            if mask & TOKENS != 0 {
                self.out.clear();
                self.wire.emit_with(
                    &self.tokens,
                    &self.cuts,
                    &[],
                    false,
                    true,
                    &[],
                    &mut self.scratch,
                    &mut self.out,
                );
                kept = self.out.len() as u64;
            } else if mask & (COUNT | TABLE) != 0 {
                let EmitScratch {
                    payload,
                    frequency,
                    lengths,
                    codes,
                    ..
                } = &mut self.scratch;
                self.wire.count(&self.tokens, &[], frequency);
                for range in &self.wire.alphabets {
                    code_lengths(&frequency[range.clone()], &mut lengths[range.clone()]);
                }
                kept += u64::from(lengths[0]);
                if mask & TABLE != 0 {
                    for range in &self.wire.alphabets {
                        canonical(&lengths[range.clone()], &mut codes[range.clone()]);
                    }
                    payload.clear();
                    write_length_table(payload, lengths);
                    kept += payload.finish().0.len() as u64;
                }
            }
            if mask & FORGET != 0 {
                self.chains.forget(sample);
                kept += u64::from(self.chains.heads[0]);
            }
            kept
        }
    }
}

#[cfg(test)]
mod sample_tests {
    use super::super::chain::{Chains, KEY_SHORT};
    use super::super::drive::{Finder, Parse};
    use super::super::floor_count::FLOOR_COUNT_MOST;
    use super::super::lz::{lazy_parse, Block, PriceModel, Source};
    use super::*;
    use crate::memory::MemoryPolicy;

    /// The plan the store rule's samples are packed at (`write::store`'s
    /// packed sampler builds its encoder from exactly this).
    fn floor() -> Plan {
        let mut plan = Plan::for_level(1).floor();
        plan.lone = None;
        plan
    }

    /// One sample as the rule packed it before 1 Oct 2026: its symbol
    /// counts and plain bits by the chains' pass and [`lazy_parse`], and
    /// its length by the encoder itself.
    fn packed(sample: &[u8]) -> (Vec<u32>, u64, usize) {
        let plan = floor();
        let wire = Wire::new(0);
        let dictionary = MemoryPolicy::MIN_DICTIONARY as usize;
        let mut chains = Chains::new(dictionary, sample.len(), usize::MAX, KEY_SHORT);
        chains
            .links
            .insert(&mut chains.heads, sample, 0..sample.len());
        let mut tokens = Vec::new();
        let mut model = PriceModel::new(&wire);
        lazy_parse(
            &wire,
            Block {
                span: sample,
                start: 0,
                end: sample.len(),
                dictionary: chains.links.reach(),
            },
            Source::Chains {
                chains: &chains.links,
                depth: plan.depth,
                enough: plan.enough,
                pair: plan.pair,
            },
            &mut model,
            &mut tokens,
            plan.back,
        );
        let mut frequency = vec![0u32; wire.symbols()];
        let mut plain = 0u64;
        for &token in &tokens {
            plain += u64::from(wire.visit(token, &mut |symbol| frequency[symbol] += 1));
        }
        let mut encoder = Rar5Encoder::new(EncodeOptions {
            dictionary: dictionary as u32,
            version: 0,
            plan,
            workers: 1,
        });
        let mut out = Vec::new();
        encoder.encode_region(sample, 0, true, &mut out);
        (frequency, plain, out.len())
    }

    /// Noise with `copies` earlier stretches copied forward, each of 2 to
    /// `longest` bytes from a distance drawn around the format's bonus
    /// lines and the ladder's first slots.
    fn planted(
        rng: &mut rarkit_testdata::Seeded,
        len: usize,
        copies: usize,
        longest: usize,
    ) -> Vec<u8> {
        let mut out = rng.bytes(len);
        let lines = [
            1usize, 2, 3, 4, 5, 8, 16, 255, 256, 257, 258, 0x1fff, 0x2000, 0x2001, 0x2002, 30_000,
            65_000,
        ];
        for _ in 0..copies {
            let distance = lines[rng.index(lines.len())] + rng.index(3);
            let length = 2 + rng.index(longest - 1);
            if distance + length >= len {
                continue;
            }
            let at = distance + rng.index(len - distance - length);
            for i in 0..length {
                out[at + i] = out[at + i - distance];
            }
        }
        out
    }

    /// Records of a fixed width with a counter, a few constant fields and
    /// some noise: what a table in an executable or an index looks like.
    fn records(rng: &mut rarkit_testdata::Seeded, len: usize, width: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + width);
        let mut counter = rng.next_u64() as u32;
        while out.len() < len {
            let mut record = vec![0u8; width];
            record[..4].copy_from_slice(&counter.to_le_bytes());
            counter = counter.wrapping_add(1 + rng.index(3) as u32);
            for byte in record.iter_mut().skip(4).step_by(3) {
                *byte = (rng.next_u64() >> 40) as u8 & 0x0f;
            }
            out.extend_from_slice(&record);
        }
        out.truncate(len);
        out
    }

    /// The samples the two samplers are held together on: generated ones
    /// of every kind a member is made of, at every length around the
    /// form's edges, and real bytes (this crate's own source and this
    /// test binary's machine code).
    fn samples() -> Vec<Vec<u8>> {
        let mut rng = rarkit_testdata::Seeded::new(0x9E37_79B9_7F4A_7C15);
        let most = FLOOR_COUNT_MOST;
        let mut all = Vec::new();
        // Every short length: the positions with no four bytes after them,
        // and spans the chains never key at all.
        for len in 1..=40 {
            all.push(rng.bytes(len));
            all.push(vec![b'a'; len]);
            all.push(rarkit_testdata::chatter(rng.next_u64(), len));
        }
        for len in [
            most,
            most - 1,
            most - 3,
            4_096,
            4_097,
            4_098,
            32_768,
            32_769,
            1_000,
        ] {
            all.push(rng.bytes(len));
            all.push(rarkit_testdata::chatter(rng.next_u64(), len));
            all.push(vec![0u8; len]);
            all.push(planted(&mut rng, len, len / 64, 12));
            all.push(planted(&mut rng, len, len / 512, 300));
        }
        for width in [8, 12, 16, 24, 40, 64, 100] {
            all.push(records(&mut rng, most, width));
        }
        // Two and three byte periods and long runs: the repeated distance
        // arms, the last-match arm, and matches at the ladder's longest.
        for period in [1usize, 2, 3, 4, 5, 7, 9, 31, 255, 256, 257, 4_096, 5_000] {
            let unit = rng.bytes(period);
            let mut sample: Vec<u8> = unit.iter().copied().cycle().take(most).collect();
            all.push(sample.clone());
            // The same with a byte flipped now and then.
            for _ in 0..200 {
                let at = rng.index(most);
                sample[at] ^= 1 << rng.index(8);
            }
            all.push(sample);
        }
        // Few symbols: short matches everywhere, and a price region that
        // settles early.
        for symbols in [2u8, 3, 4, 16] {
            all.push(
                (0..most)
                    .map(|_| b'a' + (rng.next_u64() >> 40) as u8 % symbols)
                    .collect(),
            );
        }
        // Text, then noise, then text: the model's regions change under it.
        let mut mixed = rarkit_testdata::chatter(rng.next_u64(), 20_000);
        mixed.extend(rng.bytes(25_000));
        mixed.extend(rarkit_testdata::chatter(rng.next_u64(), 20_536));
        all.push(mixed);
        // Real bytes.
        let source = concat!(env!("CARGO_MANIFEST_DIR"), "/src/encode/drive.rs");
        let mut real = vec![std::fs::read(source).expect("this crate's own source")];
        if let Ok(binary) = std::env::current_exe().and_then(std::fs::read) {
            real.push(binary);
        }
        for bytes in &real {
            let step = (bytes.len() / 24).max(1);
            for start in (0..bytes.len()).step_by(step).take(24) {
                all.push(bytes[start..(start + most).min(bytes.len())].to_vec());
            }
        }
        all
    }

    /// The store rule's sampler counts what the packed sampler writes: the
    /// same symbol counts, the same plain bits and the same length, on
    /// every sample, with one sampler kept across all of them (so every
    /// sample after the first meets a head table the samples before it
    /// wrote), in two orders, and again by a sampler built for the sample.
    ///
    /// This is what holds `floor_count::floor_score` to `lz::best_scored`, and
    /// `floor_count::FloorCount::count` to `lz::lazy_parse`: alter a line of either
    /// copy that reaches the floor's answers and this fails.
    #[test]
    fn the_counted_sample_is_the_packed_sample() {
        // The form `FloorCount` is written for. A floor that looks deeper
        // or extends backward is another parse.
        let plan = floor();
        assert_eq!(
            (plan.parse, plan.finder, plan.depth, plan.back),
            (Parse::Lazy, Finder::Chain, 1, 0)
        );
        assert_eq!(plan.chain_key(), KEY_SHORT);
        let samples = samples();
        assert!(samples.len() >= 250, "{}", samples.len());
        let wanted: Vec<(Vec<u32>, u64, usize)> = samples.iter().map(|s| packed(s)).collect();
        let mut kept = SampleLength::new();
        let forward: Vec<usize> = (0..samples.len()).collect();
        let backward: Vec<usize> = forward.iter().rev().copied().collect();
        let (mut under, mut matched) = (0, 0);
        for order in [forward, backward] {
            for index in order {
                let sample = &samples[index];
                let (frequency, plain, len) = &wanted[index];
                let what = format!("sample {index} of {} bytes", sample.len());
                assert_eq!(kept.packed_len(sample), Some(*len), "{what}");
                assert_eq!(&kept.counter.frequency, frequency, "{what}");
                assert_eq!(kept.counter.count(&kept.wire, sample), *plain, "{what}");
                assert_eq!(&kept.counter.frequency, frequency, "{what}, counted again");
                under += usize::from(*len * 1000 < sample.len() * 995);
                matched += usize::from(frequency[SYMBOL_LAST_LENGTH..].iter().any(|&c| c != 0));
            }
        }
        for (sample, (_, _, len)) in samples.iter().zip(&wanted) {
            assert_eq!(SampleLength::new().packed_len(sample), Some(*len));
        }
        // The samples are on both sides of the rule's bar, and most hold
        // matches: the equality is tested where a verdict is decided.
        let over = 2 * samples.len() - under;
        assert!(under >= 60 && over >= 60, "{under} under, {over} over");
        assert!(matched >= 200, "{matched}");
        eprintln!(
            "{} samples, twice: {under} under the bar, {over} at or over it, {matched} with matches",
            samples.len()
        );
    }

    /// The two cases the counted form hands back, forced: a sample longer
    /// than the cut's coarse grid, where the cut may choose a boundary,
    /// and a block over the packed ceiling, which the emitter splits.
    #[test]
    fn a_sample_the_form_does_not_cover_is_handed_back() {
        let mut rng = rarkit_testdata::Seeded::new(7);
        let mut length = SampleLength::new();
        assert_eq!(length.packed_len(&[]), None);
        assert_eq!(length.packed_len(&rng.bytes(FLOOR_COUNT_MOST + 1)), None);
        assert_eq!(
            length.packed_len(&rarkit_testdata::chatter(
                rng.next_u64(),
                FLOOR_COUNT_MOST + 1
            )),
            None
        );
        // At the ceiling the length is the packed one; a byte under it the
        // sample is handed back, for the emitter to split.
        let sample = rng.bytes(20_000);
        let (_, _, len) = packed(&sample);
        assert_eq!(
            SampleLength::with_ceiling_for_tests(len).packed_len(&sample),
            Some(len)
        );
        assert_eq!(
            SampleLength::with_ceiling_for_tests(len - 1).packed_len(&sample),
            None
        );
        // And the switch the writer's own test forces the fallback with.
        assert_eq!(length.packed_len(&sample), Some(len));
        assert_eq!(with_samples_uncovered(|| length.packed_len(&sample)), None);
        assert_eq!(length.packed_len(&sample), Some(len));
    }

    /// A span of exactly the coarse grid is one entropy block under the
    /// priced cut, whatever it holds: the one fact of the cut the counted
    /// length rests on.
    #[test]
    fn the_cut_of_a_sample_is_one_block() {
        let wire = Wire::new(0);
        for sample in samples() {
            let mut tokens = Vec::new();
            let mut chains = Chains::new(1 << 17, sample.len(), usize::MAX, KEY_SHORT);
            chains
                .links
                .insert(&mut chains.heads, &sample, 0..sample.len());
            lazy_parse(
                &wire,
                Block {
                    span: &sample,
                    start: 0,
                    end: sample.len(),
                    dictionary: chains.links.reach(),
                },
                Source::Chains {
                    chains: &chains.links,
                    depth: 1,
                    enough: 32,
                    pair: crate::encode::chain::Pairing::Single,
                },
                &mut PriceModel::new(&wire),
                &mut tokens,
                0,
            );
            let mut cuts = Vec::new();
            super::super::cut::cut(&wire, &tokens, &mut cuts);
            assert_eq!(cuts, vec![0..tokens.len()]);
        }
    }
}

#[cfg(test)]
mod length_rule {
    /// The writer's statement of SPEC-H2 3.5's rule and the reader's are
    /// two, for speed, and must be one rule: at each distance, one below
    /// and one past it, and at the ends. Single threaded.
    #[test]
    fn the_writer_and_the_reader_gain_the_same_bytes() {
        for edge in super::LONGER_PAST {
            for distance in [edge - 1, edge, edge + 1] {
                assert_eq!(
                    super::gained(distance) as usize,
                    crate::rar5_lz::ladders::fresh_match_length(0, distance as usize),
                    "distance {distance:#x}"
                );
            }
        }
        assert_eq!((super::gained(1), super::gained(u32::MAX)), (0, 3));
        assert_eq!(super::gained(0), 0);
        assert!(super::LONGER_PAST.iter().all(|edge| edge.is_power_of_two()));
    }
}
