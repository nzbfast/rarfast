//! Spec H1: the RAR 2.9 / 3.x / 4.x LZ codec, decoding side.
//!
//! One [`Rar3Lz`] and one [`Window`] serve a whole STREAM: a solid chain,
//! or a non solid member on its own. Members are cut out of the byte
//! sequence the stream's blocks produce, so a member boundary is not a
//! block boundary and a member's first bit is never sniffed for a header
//! (SPEC-H1 3.1): which state a member starts in is carried here.
//!
//! [`Rar3Stream`] drives the three packages a RAR 3 stream needs: this
//! decoder, spec I's text model on the other side of the mode bit, and
//! spec J's filters, whose spans replace bytes on the way out while the
//! window keeps the unfiltered ones.

pub(crate) mod bits;
#[cfg(feature = "bench-internals")]
pub(crate) mod burst;
#[cfg(feature = "bench-internals")]
pub(crate) mod ladder;
mod prefix;
mod stream;
mod tables;
#[cfg(test)]
mod tests;
// The window's COPY CENSUS is reached from `internals::window_census`
// under the `copy-census` feature, which nothing but an explicit counting
// run turns on. The module is crate-visible rather than re-exported,
// because a re-export of a crate-private module reads as unused to
// clippy even where the census itself is used.
pub(crate) mod window;

use bits::BitSource;
use prefix::{PrefixTable, LITERAL_TOP, WIDE};
use tables::{
    DISTANCE_BASE, DISTANCE_EXTRA, DISTANCE_SYMBOLS, FAR_BONUS_ONE, FAR_BONUS_TWO,
    FRESH_LENGTH_BONUS, LENGTH_BASE, LENGTH_EXTRA, LENGTH_SYMBOLS, LEVEL_SYMBOLS, LOW_REPEAT,
    LOW_REPEAT_RUN, LOW_SYMBOLS, MAIN_SYMBOLS, REPEAT_LENGTH_BONUS, SHORT_BASE, SHORT_EXTRA,
    TABLE_LENGTHS,
};

#[allow(unused_imports)]
pub(crate) use stream::{MemberSpan, Rar3Stream, StreamOut};
pub(crate) use window::Window;

use crate::error::{Corruption, Rar3Fault};
use crate::{Error, ErrorKind, Result};

/// Where each alphabet's code lengths sit in the 404 (SPEC-H1 3.3).
const MAIN_AT: usize = 0;
const DISTANCE_AT: usize = MAIN_AT + MAIN_SYMBOLS;
const LOW_AT: usize = DISTANCE_AT + DISTANCE_SYMBOLS;
const LENGTH_AT: usize = LOW_AT + LOW_SYMBOLS;

/// Main alphabet symbols with a meaning of their own (SPEC-H1 3.4).
const END_OF_BLOCK: u16 = 256;
const FILTER_RECORD: u16 = 257;
const REPEAT_LAST_MATCH: u16 = 258;
const FIRST_REPEATED: u16 = 259;
const FIRST_SHORT: u16 = 263;
const FIRST_FRESH: u16 = 271;

/// The longest match the ladders can name, with both length bonuses
/// (SPEC-H1 4.1).
pub(crate) const MAX_MATCH: u32 = 260;

/// One of this package's faults, as an [`Error`].
#[inline]
fn fault(which: Rar3Fault) -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::Rar3(which)))
}

/// What one [`Rar3Lz::run`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LzStep {
    /// Bytes written to the window, having reached the member's declared
    /// end or the caller's flush budget.
    Produced(u32),
    /// Main symbol 257: a filter record follows in the same bit stream.
    /// The caller hands the reader to spec J's record parser, which reads
    /// the record's bytes as the next 8 bits each (SPEC-H1 3.9).
    FilterRecord,
    /// The block ended and said what follows (SPEC-H1 3.7).
    BlockEnded(BlockEnd),
}

/// The three ways a block ends (SPEC-H1 3.7), which names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum BlockEnd {
    /// A block header follows, in the same member.
    SameMemberNewTables,
    /// This member's data ends here; the next member starts at a header.
    NewMemberNewTables,
    /// This member's data ends here; the next member resumes inside this
    /// block, with these tables and these stored code lengths.
    NewMemberKeepTables,
}

/// The RAR 3 LZ decoder of one stream: the tables, the stored code
/// lengths, the repeated distances and the low distance run state.
#[derive(Debug)]
pub(crate) struct Rar3Lz {
    level: PrefixTable,
    main: PrefixTable,
    distance: PrefixTable,
    low: PrefixTable,
    length: PrefixTable,
    /// The 404 stored code lengths: main, distance, low distance, length.
    lengths: [u8; TABLE_LENGTHS],
    /// The four repeated distances, most recent first.
    repeats: [u32; 4],
    /// The last match's length; zero until a match has run.
    last_length: u32,
    /// The remembered low distance part and its run counter (3.5).
    low_part: u32,
    low_run: u32,
    /// Main symbols decoded since the stream began.
    ///
    /// SPEC-H1 7.5 asks for the per SYMBOL cost split from the per
    /// OUTPUT BYTE cost before any target is claimed, and says plainly
    /// that no such split exists for this codec. It cannot be measured
    /// from outside: a literal run and a long match produce the same
    /// bytes and cost wildly different numbers of symbols. What it costs
    /// to keep is one add per literal RUN - the burst loop below knows
    /// its own length - and one per match, against a loop that is
    /// already tens of instructions a symbol.
    symbols: u64,
    /// Of those, the ones that were LITERALS. 7.5's split needs the two
    /// apart: a literal and a match are the same symbol to a counter and
    /// nothing like it to a clock.
    literals: u64,
    /// Unit tests only: override [`PAIR_LITERALS`], so ONE stream can be
    /// decoded both ways and the two results compared.
    ///
    /// The field exists only under `cfg(test)` of this crate, so no
    /// shipped build, no bench binary and no integration test carries it
    /// or the branch that reads it: the loop a gate times is the loop
    /// that ships.
    #[cfg(test)]
    pair_forced: Option<bool>,
    /// Unit tests only: override the main table's
    /// [`PrefixTable::literal_guess`], so ONE stream can be decoded with
    /// the guess declined, taken, and taken WRONG, and the three results
    /// compared. Same `cfg(test)` rule as `pair_forced`: no shipped
    /// build, bench binary or integration test carries it.
    #[cfg(test)]
    guess_forced: Option<u8>,
}

impl Default for Rar3Lz {
    fn default() -> Rar3Lz {
        Rar3Lz::new()
    }
}

impl Rar3Lz {
    /// A decoder for a fresh stream: every stored code length zero, every
    /// repeated distance zero.
    pub(crate) fn new() -> Rar3Lz {
        Rar3Lz {
            level: PrefixTable::new(LEVEL_SYMBOLS),
            main: PrefixTable::new(MAIN_SYMBOLS),
            distance: PrefixTable::new(DISTANCE_SYMBOLS),
            low: PrefixTable::new(LOW_SYMBOLS),
            length: PrefixTable::new(LENGTH_SYMBOLS),
            lengths: [0; TABLE_LENGTHS],
            repeats: [0; 4],
            last_length: 0,
            low_part: 0,
            low_run: 0,
            symbols: 0,
            literals: 0,
            #[cfg(test)]
            pair_forced: None,
            #[cfg(test)]
            guess_forced: None,
        }
    }

    /// Unit tests only: decode from here on with the burst's pair forced
    /// on or off, whatever [`PAIR_LITERALS`] says.
    #[cfg(test)]
    pub(crate) fn force_pair(&mut self, forced: Option<bool>) {
        self.pair_forced = forced;
    }

    /// Unit tests only: decode from here on with the pair loop's guessed
    /// width forced to `forced`, whatever the main table says. Zero
    /// declines the guess; a width the table's literals do not have is a
    /// guess that is always wrong, which the bytes must survive.
    #[cfg(test)]
    pub(crate) fn force_guess(&mut self, forced: Option<u8>) {
        debug_assert!(forced.is_none_or(|guess| guess <= PrefixTable::DIRECT_BITS));
        self.guess_forced = forced;
    }

    /// Main symbols decoded since the stream began (SPEC-H1 7.5).
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub(crate) fn symbols(&self) -> u64 {
        self.symbols
    }

    /// Of those, the literals (SPEC-H1 7.5).
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub(crate) fn literals(&self) -> u64 {
        self.literals
    }

    /// Start a new stream in the same allocations.
    pub(crate) fn reset_stream(&mut self) {
        self.lengths = [0; TABLE_LENGTHS];
        self.repeats = [0; 4];
        self.last_length = 0;
        self.low_part = 0;
        self.low_run = 0;
        self.symbols = 0;
        self.literals = 0;
    }

    /// Bytes of working memory this decoder holds, tables included.
    pub(crate) fn held_bytes(&self) -> u64 {
        self.level.held_bytes()
            + self.main.held_bytes()
            + self.distance.held_bytes()
            + self.low.held_bytes()
            + self.length.held_bytes()
            + TABLE_LENGTHS as u64
    }

    /// Read a block header at a header expected point (SPEC-H1 3.2).
    ///
    /// The reader is aligned up to the next byte boundary first. The
    /// answer is `Some(first)` for a PPM block, whose whole first byte is
    /// spec I's, and `None` for an LZ block, whose header and tables this
    /// call has read.
    pub(crate) fn begin_block(&mut self, input: &mut impl BitSource) -> Result<Option<u8>> {
        input.align_to_byte();
        if input.peek(1) == 1 {
            let first = input.read(8)? as u8;
            return Ok(Some(first));
        }
        input.consume(1);
        self.read_tables(input)?;
        Ok(None)
    }

    /// The code length alphabet, the 404 code lengths and the five tables
    /// (SPEC-H1 3.3).
    fn read_tables(&mut self, input: &mut impl BitSource) -> Result<()> {
        if input.read(1)? == 0 {
            self.lengths = [0; TABLE_LENGTHS];
        }
        // The low distance run state is cleared at every table read,
        // whatever the keep bit said (SPEC-H1 3.2, question 4).
        self.low_part = 0;
        self.low_run = 0;

        let mut level = [0u8; LEVEL_SYMBOLS];
        let mut at = 0usize;
        while at < LEVEL_SYMBOLS {
            let value = input.read(4)? as u8;
            if value < 15 {
                level[at] = value;
                at += 1;
                continue;
            }
            let more = input.read(4)?;
            if more == 0 {
                level[at] = 15;
                at += 1;
            } else {
                at += more as usize + 2;
            }
        }
        self.level.build(&level);

        let mut at = 0usize;
        while at < TABLE_LENGTHS {
            let symbol = self.level.decode(input)?;
            match symbol {
                0..=15 => {
                    self.lengths[at] = (self.lengths[at] + symbol as u8) & 15;
                    at += 1;
                }
                16 | 17 => {
                    if at == 0 {
                        return Err(fault(Rar3Fault::RepeatAtStart));
                    }
                    let (bits, base) = if symbol == 16 { (3, 3) } else { (7, 11) };
                    let count = input.read(bits)? as usize + base;
                    let repeated = self.lengths[at - 1];
                    let end = (at + count).min(TABLE_LENGTHS);
                    self.lengths[at..end].fill(repeated);
                    at = end;
                }
                18 | 19 => {
                    let (bits, base) = if symbol == 18 { (3, 3) } else { (7, 11) };
                    let count = input.read(bits)? as usize + base;
                    let end = (at + count).min(TABLE_LENGTHS);
                    self.lengths[at..end].fill(0);
                    at = end;
                }
                _ => return Err(fault(Rar3Fault::LevelSymbol)),
            }
        }

        self.main.build(&self.lengths[MAIN_AT..DISTANCE_AT]);
        self.distance.build(&self.lengths[DISTANCE_AT..LOW_AT]);
        self.low.build(&self.lengths[LOW_AT..LENGTH_AT]);
        self.length.build(&self.lengths[LENGTH_AT..]);
        Ok(())
    }

    /// Decode symbols until `room` bytes have been produced, the caller's
    /// `budget` is spent, the block ends, or a record is reached (SPEC-H1
    /// 3.4 to 3.6).
    ///
    /// `room` is what the member still needs. A literal never passes it. A
    /// match is never cut against it: the match enters the window whole
    /// and the caller decides which of its bytes are the member's (SPEC-H1
    /// 3.8, B3). `budget` is how many bytes the caller can take before it
    /// must drain the window. Either may be overshot by one match, less
    /// than [`MAX_MATCH`] bytes, which is the margin the caller leaves.
    pub(crate) fn run(
        &mut self,
        input: &mut impl BitSource,
        out: &mut Window,
        room: u64,
        budget: u64,
    ) -> Result<LzStep> {
        // Whether this run's literals are decoded two a turn. A shipped
        // build has no choice here and the compiler knows it; the unit
        // tests have one, so ONE stream can be decoded both ways and the
        // two results compared (`force_pair`).
        #[cfg(not(test))]
        let pair = PAIR_LITERALS;
        #[cfg(test)]
        let pair = self.pair_forced.unwrap_or(PAIR_LITERALS);
        // The width the pair loop may GUESS a pair's second code has, or
        // zero for a block it must not guess on ([`PrefixTable::
        // literal_guess`]). Read ONCE a call: it is a property of the
        // main table, so it changes only when a block header rebuilds
        // one, and a read a pair would be a load the guess exists to
        // remove.
        #[cfg(not(test))]
        let guess = self.main.literal_guess();
        #[cfg(test)]
        let guess = self.guess_forced.unwrap_or(self.main.literal_guess());
        // The shift that puts the guessed second code's index in place,
        // made OPAQUE to the optimiser, once a call and not once a pair.
        //
        // Without this there is no speculation in the binary at all. The
        // guessed load is used only under `width == guess`, and inside
        // that branch the optimiser knows `guess` IS `width`, so it
        // rewrites the guessed index `bits >> (DIRECT_BITS - guess)` as
        // `bits >> (DIRECT_BITS - width)`, finds the two loads identical,
        // keeps one, and the one it keeps is the DEPENDENT one. The first
        // build of this arm disassembled to the dependent loop twice
        // over, instruction for instruction, and would have measured as
        // a change of nothing. A value the optimiser cannot see through
        // cannot be equated with `width`, so the guessed load keeps its
        // own address and its own place beside the first load, which is
        // the whole of what the arm is for. The cost is one value forced
        // through memory per call of this function, against millions of
        // pairs a call on the leg that wants it.
        let guess_shift = std::hint::black_box(u32::from(PrefixTable::DIRECT_BITS - guess));
        let start = out.produced();
        let mut left = room;
        let limit = budget.min(room);
        let produced = |out: &Window| (out.produced() - start) as u32;

        loop {
            // A literal run is decoded in a burst, straight into the
            // window's own room, without the dispatch a match arm needs
            // (SPEC-H1 7.3 item 5). The symbol that ends the run is kept
            // in hand, so no symbol is ever looked up twice.
            let mut in_hand: Option<u16> = None;
            loop {
                let want = left.min(limit.saturating_sub(out.produced() - start));
                let into = out.free_run();
                // Clamped in `u64` and THEN narrowed, for the reason
                // `read::walk::MemberReader::read_inner` gives: `want` is
                // a member-relative count and may be past 4 GiB.
                let room = want.min(into.len() as u64) as usize;
                // How many symbols may be taken before SPEC-D 3.2.4's tail
                // rule can apply, settled ONCE for the run rather than
                // tested once a literal, and settled with a SHIFT.
                //
                // A code is at most fifteen bits, so after `k` of them
                // the member still holds `available() - 15k` bits, and
                // `k <= available() / 16` keeps that at or above
                // `available() / 16 + 15`, which clears the fifteen
                // `PrefixTable::decode`'s direct arm asks for. Sixteen
                // rather than fifteen costs a sixteenth of the run's
                // length and only where the input, not the window, is
                // what binds; it buys a shift in place of a divide.
                //
                // That matters because this burst is entered once per
                // MATCH as well as once per run of literals, and
                // SPEC-H1 7.5's census says how often: 1.57 million
                // matches a round on the 32 MiB code member and 2.53
                // million on the 64 MiB text member at level 3, against
                // sixteen entries a round on the 64 MiB random member,
                // which is one long run. A 64 bit division here cost the
                // 21 Sep run on an Apple M3 Mac `rar3_code_32m` 0.966x to
                // 0.929x and `rar3_text_64m_lz` 0.953x to 0.938x. The
                // multiply that replaced it recovered the text leg but
                // only half of the code leg (0.953x to 0.933x), because
                // `15 * room` on a four megabyte window is 63 million
                // bits and a member with fewer left than that took the
                // divide anyway - which is most of a member, most of the
                // time. A shift has no such edge.
                let room = room.min((input.available() >> 4) as usize);
                // The bound is taken ONCE for the run. Indexing `into`
                // per literal leaves the compiler to prove the index in
                // range through a chain of `min`s that crosses a `u64`
                // narrowing, which is not a proof worth relying on on
                // the hottest path this package has.
                let into = &mut into[..room];
                let mut count = 0usize;
                // `room` symbols may be taken with no further test of the
                // input: `cap` is `available() / 15` and a code is at
                // most fifteen bits, so at the symbol with `k` behind it
                // there are at least `15 * (room - k)` bits left. That is
                // 15 for the last one and 30 whenever two remain, which
                // is what makes the pair loop's single peek sound.
                // Every loop below walks the destination as an ITERATOR.
                // Indexed, each literal asks the compiler to prove the
                // index in range through a chain of `min`s that crosses a
                // `u64` narrowing and a function boundary; the iterator
                // states it once instead.
                'burst: {
                    // The first [`WARM_LITERALS`] symbols go one at a
                    // time, and only a run that outlives them pairs up.
                    for slot in into[..room.min(WARM_LITERALS)].iter_mut() {
                        match one_literal(&self.main, input, slot) {
                            None => count += 1,
                            Some(entry) => {
                                in_hand = hand_over(input, entry);
                                break 'burst;
                            }
                        }
                    }
                    // What a run takes when the pair is declined is the
                    // odd tail loop below, over the whole run: one
                    // literal a turn through `lookup_direct`, which is
                    // the shape an earlier revision shipped. In a shipped build
                    // `pair` is a constant and this branch is not one:
                    // it folds away and the loop is the loop that was
                    // gated.
                    if pair {
                        // TWO literals a turn. A `peek_ready` of 24 bits
                        // refills at most once and then answers both codes,
                        // and one `consume_ready` of their two widths moves
                        // the cache once: the per symbol cache test and the
                        // per symbol shift of the window are halved. Neither
                        // code can be wider than the direct table's twelve
                        // bits, so 24 always holds the pair.
                        let paired = count;
                        let (pairs, _odd) = into[paired..].as_chunks_mut::<2>();
                        // The pair loop comes in TWO arms, chosen once a
                        // block and not once a pair, and a local macro is
                        // what keeps the two arms one text. The DEPENDENT
                        // arm (`speculate` false) is the loop that was
                        // gated before the guess existed, with nothing
                        // added to it: its guess load and its guess test
                        // fold away at compile time. The SPECULATIVE arm
                        // differs from it in ONE place, the second lookup.
                        //
                        // Why the second arm exists: the dependent arm's
                        // two loads are in SERIES, the second's index
                        // waiting on the first's width, and the 21 Sep
                        // 2026 ladder (the
                        // literal loop subtracted) puts that chain at 63
                        // to 79 percent of the loop, with the table's
                        // size, the reader and the window writes each
                        // excluded as the lever by subtraction. The
                        // speculative arm takes the second index at
                        // `guess`, a block constant, so its ADDRESS is
                        // ready before the first load lands and the two
                        // loads issue together; the loop carried chain is
                        // one load deep instead of two. On the
                        // incompressible leg's real alphabet that read
                        // 13.8 to 17.1 percent faster a literal on the
                        // ladder, and on the code leg's 24 to 29 percent
                        // SLOWER, which is why the arm is a per block
                        // choice on the table's own mass and not a
                        // constant (`PrefixTable::literal_guess`).
                        //
                        // The guess is USED only where the first code's
                        // own decoded width says it is right, so a block
                        // whose draw is not what its table's mass says
                        // pays a wasted load and NEVER a wrong literal.
                        // That test is what makes this a speculation and
                        // not an assumption, and `tests.rs` holds it to
                        // the bytes with the guess forced wrong.
                        //
                        // The reader's word, its live bit count and its
                        // position are held in LOCALS for the length of
                        // the pair loop and handed back at every refill
                        // and every exit (`BitSource::take_cache`). Held
                        // in the reader, the compiler kept them in memory
                        // because the literal stores into the window might
                        // alias them, so the word was stored and reloaded
                        // every pair on the loop's carried chain. The
                        // peeks, the lookups and the consumes are the
                        // same ones, in the same order.
                        macro_rules! pair_loop {
                            ($speculate:expr, $burst:lifetime) => {
                                let (mut window, mut have, mut at) = input.take_cache();
                                for pair in pairs.iter_mut() {
                                    // `peek_ready(24)`'s refill, taken through
                                    // the reader and read back.
                                    // In locals where the bytes are held
                                    // and the word is whole, which is every
                                    // refill but those near a buffer's or
                                    // a member's end; those go through the
                                    // reader, which pulls or zero fills.
                                    if have < 2 * PrefixTable::DIRECT_BITS {
                                        if let Some((word, live)) = input.refill_word(at) {
                                            window = word;
                                            have = live;
                                        } else {
                                            input.put_cache(window, have, at);
                                            let _ = input.peek_ready(2 * PrefixTable::DIRECT_BITS);
                                            (window, have, at) = input.take_cache();
                                        }
                                    }
                                    let bits = (window
                                        >> (64 - 2 * u32::from(PrefixTable::DIRECT_BITS)))
                                        as u32;
                                    let first =
                                        self.main.lookup_direct(bits >> PrefixTable::DIRECT_BITS);
                                    if $speculate {
                                        // The guessed second lookup, whose
                                        // index depends on nothing the first
                                        // load answers, issued beside it. Its
                                        // answer is part of the TEST below and
                                        // not only of the taken side, and the
                                        // dependent text after this block is
                                        // the whole fall back rather than a
                                        // second load in an `else`: both are
                                        // load bearing. A guessed value used
                                        // only on the taken side was sunk by
                                        // the optimiser into a select of the
                                        // two loads' indices and ONE load whose
                                        // address depended on `width` again,
                                        // which is the chain this arm exists
                                        // to break. This is the shape the
                                        // ladder measured, and the release
                                        // disassembly is read for the two
                                        // independent loads rather than
                                        // trusted.
                                        let guessed = self.main.lookup_direct(bits >> guess_shift);
                                        let width = first as u8 & 15;
                                        if width == guess
                                            && first < LITERAL_TOP
                                            && guessed < LITERAL_TOP
                                        {
                                            pair[0] = (first >> 4) as u8;
                                            pair[1] = (guessed >> 4) as u8;
                                            let taken = width + (guessed as u8 & 15);
                                            window <<= taken;
                                            have -= taken;
                                            at += u64::from(taken);
                                            count += 2;
                                            continue;
                                        }
                                    }
                                    // One unsigned compare for both exits: an entry
                                    // below `LITERAL_TOP` is a symbol in 0 to 255
                                    // whose width the direct table knows, and every
                                    // other answer - `WIDE`, and every symbol from
                                    // 256 up - is above it.
                                    if first >= LITERAL_TOP {
                                        input.put_cache(window, have, at);
                                        in_hand = hand_over(input, first);
                                        break $burst;
                                    }
                                    let width = first as u8 & 15;
                                    // A direct entry's width is 1 to `DIRECT_BITS` by
                                    // construction, which is what keeps the shift
                                    // below in range and the pair inside 24 bits.
                                    debug_assert!((1..=PrefixTable::DIRECT_BITS).contains(&width));
                                    // The second code starts `width` bits in, and
                                    // `lookup_direct` masks the index itself.
                                    let second = self.main.lookup_direct(
                                        bits >> u32::from(PrefixTable::DIRECT_BITS - width),
                                    );
                                    if second >= LITERAL_TOP {
                                        pair[0] = (first >> 4) as u8;
                                        count += 1;
                                        input.put_cache(
                                            window << width,
                                            have - width,
                                            at + u64::from(width),
                                        );
                                        in_hand = hand_over(input, second);
                                        break $burst;
                                    }
                                    pair[0] = (first >> 4) as u8;
                                    pair[1] = (second >> 4) as u8;
                                    let taken = width + (second as u8 & 15);
                                    window <<= taken;
                                    have -= taken;
                                    at += u64::from(taken);
                                    count += 2;
                                }
                                input.put_cache(window, have, at);
                            };
                        }
                        if guess != 0 {
                            pair_loop!(true, 'burst);
                        } else {
                            pair_loop!(false, 'burst);
                        }
                    }
                    // The odd last symbol of the run.
                    let done = count;
                    for slot in into[done..].iter_mut() {
                        match one_literal(&self.main, input, slot) {
                            None => count += 1,
                            Some(entry) => {
                                in_hand = hand_over(input, entry);
                                break 'burst;
                            }
                        }
                    }
                }
                out.commit(count);
                // One add for the whole run, not one per literal.
                self.symbols += count as u64;
                self.literals += count as u64;
                left -= count as u64;
                if in_hand.is_some() || count == 0 {
                    break;
                }
            }

            let symbol = match in_hand {
                Some(symbol) => symbol,
                None => {
                    if left == 0 || out.produced() - start >= limit {
                        return Ok(LzStep::Produced(produced(out)));
                    }
                    self.main.decode(input)?
                }
            };
            self.symbols += 1;
            match symbol {
                0..=255 => {
                    self.literals += 1;
                    out.put(symbol as u8)?;
                    left -= 1;
                }
                END_OF_BLOCK => return Ok(LzStep::BlockEnded(self.read_block_end(input)?)),
                FILTER_RECORD => return Ok(LzStep::FilterRecord),
                REPEAT_LAST_MATCH => {
                    // A pure repeat: no state is touched, and a 258 before
                    // any match produces nothing (SPEC-H1 3.4).
                    if self.last_length != 0 {
                        let (distance, length) = (self.repeats[0], self.last_length);
                        if copy_match(out, distance, length, &mut left)? {
                            return Ok(LzStep::Produced(produced(out)));
                        }
                    }
                }
                FIRST_REPEATED..FIRST_SHORT => {
                    let slot = usize::from(symbol - FIRST_REPEATED);
                    let distance = self.repeats[slot];
                    if distance == 0 {
                        return Err(fault(Rar3Fault::UninitialisedRepeat));
                    }
                    let length = self.read_length(input)? + REPEAT_LENGTH_BONUS;
                    // The chosen distance moves to the front; the ones
                    // before it shift back, the ones after it do not move.
                    // Written out per slot rather than as a slice rotate:
                    // these are the four shapes SPEC-H1 3.5 names, the
                    // symbol admits no others, and `slice::rotate_right`
                    // over a `[u32; 4]` does not fold away - it reaches
                    // `memmove` and cost 9% of this decoder's samples.
                    let r = &mut self.repeats;
                    match slot {
                        0 => {}
                        1 => r.swap(0, 1),
                        2 => *r = [r[2], r[0], r[1], r[3]],
                        _ => *r = [r[3], r[0], r[1], r[2]],
                    }
                    self.last_length = length;
                    if copy_match(out, distance, length, &mut left)? {
                        return Ok(LzStep::Produced(produced(out)));
                    }
                }
                FIRST_SHORT..FIRST_FRESH => {
                    let slot = usize::from(symbol - FIRST_SHORT);
                    let extra = SHORT_EXTRA[slot];
                    let distance = SHORT_BASE[slot] + 1 + input.read(extra)?;
                    self.push_distance(distance);
                    self.last_length = 2;
                    if copy_match(out, distance, 2, &mut left)? {
                        return Ok(LzStep::Produced(produced(out)));
                    }
                }
                FIRST_FRESH..=298 => {
                    let slot = usize::from(symbol - FIRST_FRESH);
                    let base = u32::from(LENGTH_BASE[slot]) + FRESH_LENGTH_BONUS;
                    let extra = LENGTH_EXTRA[slot];
                    let length = base + if extra > 0 { input.read(extra)? } else { 0 };
                    let distance = self.read_distance(input)?;
                    let length = length + gained_at(distance);
                    self.push_distance(distance);
                    self.last_length = length;
                    if copy_match(out, distance, length, &mut left)? {
                        return Ok(LzStep::Produced(produced(out)));
                    }
                }
                _ => return Err(fault(Rar3Fault::MainSymbol)),
            }
        }
    }

    /// The two field decision after symbol 256 (SPEC-H1 3.7).
    fn read_block_end(&mut self, input: &mut impl BitSource) -> Result<BlockEnd> {
        if input.read(1)? == 1 {
            return Ok(BlockEnd::SameMemberNewTables);
        }
        Ok(match input.read(1)? {
            1 => BlockEnd::NewMemberNewTables,
            _ => BlockEnd::NewMemberKeepTables,
        })
    }

    /// A length slot and its extra bits, without either arm's bonus (3.4).
    #[inline]
    fn read_length(&self, input: &mut impl BitSource) -> Result<u32> {
        let slot = usize::from(self.length.decode(input)?);
        if slot >= LENGTH_SYMBOLS {
            return Err(fault(Rar3Fault::LengthSlot));
        }
        let extra = LENGTH_EXTRA[slot];
        let more = if extra > 0 { input.read(extra)? } else { 0 };
        Ok(u32::from(LENGTH_BASE[slot]) + more)
    }

    /// A fresh match's distance, low distance rule included (3.5).
    #[inline]
    fn read_distance(&mut self, input: &mut impl BitSource) -> Result<u32> {
        let slot = usize::from(self.distance.decode(input)?);
        if slot >= DISTANCE_SYMBOLS {
            return Err(fault(Rar3Fault::DistanceSlot));
        }
        let extra = DISTANCE_EXTRA[slot];
        let mut distance = DISTANCE_BASE[slot] + 1;
        if extra == 0 {
            return Ok(distance);
        }
        if slot <= 9 {
            return Ok(distance + input.read(extra)?);
        }
        if extra > 4 {
            distance += input.read(extra - 4)? * 16;
        }
        if self.low_run > 0 {
            self.low_run -= 1;
            return Ok(distance + self.low_part);
        }
        let symbol = self.low.decode(input)?;
        match symbol {
            LOW_REPEAT => {
                // One symbol 16 serves this distance and the next fifteen;
                // the remembered value is not changed.
                self.low_run = LOW_REPEAT_RUN;
            }
            0..LOW_REPEAT => self.low_part = u32::from(symbol),
            _ => return Err(fault(Rar3Fault::LowDistanceSymbol)),
        }
        Ok(distance + self.low_part)
    }

    /// Push a fresh distance, discarding the oldest (3.5).
    #[inline]
    fn push_distance(&mut self, distance: u32) {
        // "the four become `[d, r0, r1, r2]`" (SPEC-H1 3.5), written as
        // that array rather than as a rotate and a store: the rotate does
        // not fold away over a `[u32; 4]` and reaches `memmove`, on the
        // hottest path this decoder has.
        let r = &self.repeats;
        self.repeats = [distance, r[0], r[1], r[2]];
    }
}

/// Copy a match whole, and count it against what the member still needs:
/// the answer is whether that is now nothing. A match that passes the
/// member's end is not cut (SPEC-H1 3.8, B3); the caller stops there with
/// the window ahead of the member's end.
///
/// The answer is a BRANCH the caller returns on, and not a subtraction
/// that stops at zero: counted on 6 Oct 2026 against the parent, the
/// saturating form cost every RAR 3 LZ row 1.2 percent in instructions,
/// and this form costs none.
///
/// `#[inline(always)]` for the reason [`Window::copy`] gives: every match
/// reaches this, and once the copy's common shape was inlined into it the
/// compiler kept THIS as the out of line call instead, which is the call
/// the inlining exists to remove.
#[inline(always)]
fn copy_match(out: &mut Window, distance: u32, length: u32, left: &mut u64) -> Result<bool> {
    out.copy(distance, length)?;
    let length = u64::from(length);
    if length >= *left {
        return Ok(true);
    }
    *left -= length;
    Ok(false)
}

/// Literals the burst takes one at a time before it starts pairing them.
///
/// The wider lookahead a pair needs is worth a refill only on a run that
/// USES it. SPEC-H1 7.5's census says how far apart the streams are:
/// 1.00 bytes a symbol on the 64 MiB random member, so its runs are the
/// whole window; 2.79 on the 204 KiB code member and 6.40 on the 32 MiB
/// one, so about two literals a match; and 19.66 on the 64 MiB text
/// member at level 3, which is one literal for every three matches. The
/// 20 Sep run on an Apple M3 Mac measured what pairing from the first symbol
/// costs those last two - `rar3_text_64m_lz` 0.951x to 0.915x and
/// `rar3_code_32m` 0.963x to 0.906x - against what it buys the first,
/// and four is the figure that leaves the mixed streams entirely in the
/// single step loop while costing a run of millions four symbols.
const WARM_LITERALS: usize = 4;

/// Whether the burst decodes literals TWO A TURN.
///
/// This is a CONSTANT and not a per block decision, and both halves of
/// that were measured rather than assumed.
///
/// That the pair is worth asking about at all is the 21 Sep subtractive
/// ladder's: it reproduced this loop and the one an earlier revision shipped over
/// two literal alphabets on two boxes and they disagree IN SIGN, the
/// single loop about 7 percent faster on flat eight bit codes and the
/// pair 4.75 to 4.90 percent faster on a code of widths four to twelve,
/// with the twelve bit peek that landed beside the pair worth only 0.14
/// to 1.91 percent. Its own section says an arm reproduces a LOOP and
/// not a binary and that a two-arm gate of the real thing is still to do.
///
/// That it cannot be a per block decision is the 21 Sep census of the
/// real corpora. The obvious conditional -
/// pair where the block's literal code widths vary, take the single
/// loop where they are flat - cannot be built, because no such
/// threshold separates the legs: `rar3_incompressible_64m` reads a
/// width span of 2 under every one of its 64 tables and
/// `rar3_text_64m_lz` reads spans of 2 and 3. Whatever line is drawn,
/// both fall the same side of it.
///
/// So the arm is a constant, flipped at build time
/// to build the two binaries a gate
/// compares. `false` is the EARLIER SHAPE: the odd tail loop below
/// takes the whole run, one literal a turn through `lookup_direct`.
const PAIR_LITERALS: bool = true;

/// One literal of the burst, straight into `into[*count]`.
///
/// `None` means a literal was written into `slot`. `Some(entry)` is the
/// direct table's answer for a symbol that is NOT a literal, which the
/// caller hands to [`hand_over`]; nothing has been consumed for it.
#[inline(always)]
fn one_literal(table: &PrefixTable, input: &mut impl BitSource, slot: &mut u8) -> Option<u16> {
    let entry = table.lookup_direct(input.peek_ready(PrefixTable::DIRECT_BITS));
    // One unsigned compare for both exits: an entry below `LITERAL_TOP`
    // is a symbol in 0 to 255 whose width the direct table knows, and
    // every other answer - `WIDE`, and every symbol from 256 up - is
    // above it.
    if entry >= LITERAL_TOP {
        return Some(entry);
    }
    *slot = (entry >> 4) as u8;
    input.consume_ready(entry as u8 & 15);
    None
}

/// What the literal burst does with an entry that is not a literal.
///
/// A symbol of 256 or more is taken IN HAND, its width consumed, and the
/// caller dispatches on it without looking it up twice. [`WIDE`] consumes
/// nothing: the code is wider than the direct table and the general step
/// of `PrefixTable::decode` answers it.
#[inline]
fn hand_over(input: &mut impl BitSource, entry: u16) -> Option<u16> {
    if entry == WIDE {
        return None;
    }
    input.consume_ready(entry as u8 & 15);
    Some(entry >> 4)
}

/// The distances from which a fresh match is a byte longer than its length
/// symbol says: one byte from 8,192, and a second from 262,144 (section
/// 3.5, F5). A repeated distance match and a short match gain nothing.
const LONGER_FROM: [u32; 2] = [FAR_BONUS_ONE, FAR_BONUS_TWO];

/// The bytes a fresh match at `distance` gains under F5.
#[inline(always)]
fn gained_at(distance: u32) -> u32 {
    LONGER_FROM
        .iter()
        .map(|&from| u32::from(distance >= from))
        .sum()
}
