//! The literal loop of SPEC-H1 7.3 item 5, with one STAGE removed at a
//! time, so a measurement can name the critical path by CONSTRUCTION
//! rather than by sampling.
//!
//! # Why this exists
//!
//! Two attempts have taken this loop's named next step and both regressed:
//! the 64 bit peek in two forms, and the reader-state-in-locals hoist
//! whose four removed instructions carried 56.8 percent of a sampled
//! profile and made the leg three percent SLOWER. The conclusion
//! drawn from the second is the premise here: on
//! this core a sampled profile's SELF TIME over a dependency-bound loop
//! does not identify the MARGINAL instruction, because the work it
//! attributes time to may be overlapped rather than on the critical
//! path.
//!
//! A subtraction answers the question sampling cannot. Each variant
//! below runs the same number of symbols over the same bytes with the
//! same loop structure, and removes ONE stage. A stage whose removal
//! moves the wall is on the critical path. A stage whose removal moves
//! nothing is overlapped, and no lever aimed at it can pay - which is
//! what both failed attempts needed to know before they built anything.
//!
//! # What is under test, and what is not
//!
//! The loop, in isolation: a [`Bits`] reader over real packed bytes, a
//! real [`PrefixTable`] built from real code lengths, and a real
//! [`Window`] written straight into. Everything the shipped burst does
//! per pair is here and nothing else is: no member walk, no CRC, no
//! block boundary, no match path.
//!
//! That is the incompressible leg almost exactly, and the measured profile
//! is why: 95 percent of `rar3_incompressible_64m` is
//! self time in one frame, and that frame is this loop. It is NOT the
//! text leg, whose own profile puts more than half of its decode in the
//! match path and 20.5 percent in `PrefixTable::decode`; [`Shape::Text`]
//! below reproduces that leg's literal ALPHABET and its run LENGTH, and
//! says what it can and cannot speak for in its own comment.
//!
//! # The one thing every variant must keep
//!
//! The same number of symbols, the same destination, the same window
//! wraps. A variant that ran fewer pairs, or wrote fewer bytes, would
//! be measuring its own arithmetic. [`Ladder::symbols`] is fixed by the
//! caller and every variant returns it, which is what
//! `tests::ladder_variants_all_walk_the_same_symbol_count` checks.

use std::hint::black_box;

use super::bits::{BitSource, Bits};
use super::prefix::{literal_mode, PairTable, PrefixTable, PAIR_BITS};
use super::window::Window;

/// Literal alphabet and run shape to build a stream for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shape {
    /// The incompressible leg: 256 literal values of equal frequency, so
    /// the canonical code is 256 codes of eight bits and every run is
    /// the whole window. `rar3_incompressible_64m` is 1.00 bytes a
    /// symbol by SPEC-H1 7.5's census, which is this.
    Random,
    /// The text leg's literal alphabet: a skewed frequency over 256
    /// values giving code widths from four to twelve bits, the spread
    /// that makes the pair's second lookup depend on the first's width
    /// rather than staying at a fixed offset.
    ///
    /// **It reproduces that leg's literal loop and NOT that leg.**
    /// `rar3_text_64m_lz` is 19.66 bytes a symbol, one literal for every
    /// three matches, so its burst is entered once per match and the
    /// pair loop is reached rarely. What this shape can say is what a
    /// varying width costs the loop; what it cannot say is anything
    /// about that leg's wall, which the match path owns.
    Text,
    /// What an incompressible member's main alphabet actually looks
    /// like, as against [`Shape::Random`]'s convenient fiction.
    ///
    /// [`Shape::Random`] is 256 literals of exactly eight bits, which
    /// spends the whole Kraft budget on literals and leaves none for the
    /// end of block symbol, the filter record symbol or a single match.
    /// No real block can be shaped that way. A complete code that admits
    /// sixteen non literal symbols has to demote sixteen literals with
    /// them: 240 literals at eight bits, 16 at nine, and 16 non literals
    /// at nine sums to exactly one.
    ///
    /// The difference matters to the speculative lookup and to nothing else in the
    /// ladder. A speculative second lookup guesses ONE width, so what it
    /// is worth is the share of literals that have it: 100 percent on
    /// [`Shape::Random`] by construction, which would flatter the form,
    /// and 93.75 percent here, which is a number a real alphabet could
    /// produce. Read the two rows together or neither.
    NearFlat,
    /// **`rar3_incompressible_64m`'s literal alphabet as MEASURED**, not
    /// as constructed: widths 7 to 9.
    ///
    /// The pair-loop gate work
    /// decoded the real gate corpora through `decode_stream_symbols` on
    /// 21 Sep 2026 and counted 67,080,651 literals over 64 table reads,
    /// **100 percent of them under a width SPAN of 2 with the narrowest
    /// width 7**. So that leg's literals are 7, 8 and 9 bits, uniformly
    /// in span across every block of it.
    ///
    /// That matters because [`Shape::Random`] named this leg as the one
    /// it reproduces and is 256 codes of exactly eight bits, and
    /// [`Shape::NearFlat`] is 8 and 9. Neither is this alphabet. The
    /// ladder's standing caveats say an arm reproduces a LOOP and not a
    /// binary, and a shape reproduces an ALPHABET and not a leg; this is
    /// a third, which neither attempt had: a shape can fail to reproduce
    /// the alphabet too. A form measured only on the constructed shapes
    /// would be answering for an alphabet the corpus does not hold.
    Incomp,
    /// **`rar3_code_32m`'s literal alphabet as MEASURED**: widths 5 to
    /// 9, one table read, 4,221,334 literals, span 4 throughout. The
    /// widest real spread the four rar3 legs show, and the hardest case
    /// for any form that guesses a width.
    Code,
}

impl Shape {
    /// The REALIZED width draw of this shape, as `(width, slots of
    /// 256)`, measured rather than assumed.
    ///
    /// The pair-loop gate work decoded each real gate corpus on 21 Sep
    /// 2026 with the pair forced OFF, so every literal went through the
    /// one-at-a-time path in decode order, and counted the widths. The
    /// marginal first-code distributions it found:
    ///
    /// | leg | 5 | 6 | 7 | 8 | 9 |
    /// |---|---|---|---|---|---|
    /// | `rar3_incompressible_64m` | | | 14.62% | 84.95% | 0.43% |
    /// | `rar3_code_32m` | 8.53% | 25.47% | 4.28% | 11.35% | 50.37% |
    ///
    /// **This is the DRAW and not the alphabet, and the difference is
    /// the whole point of having it.** An earlier cut of these shapes
    /// drew each symbol at the frequency an optimal code implies,
    /// `2^-w`, which is the honest guess when nothing has been
    /// measured; the measured draw is far MORE concentrated than that on
    /// both legs. On the incompressible leg the guessed draw put 57.60
    /// percent of literals at the modal width where the real one puts
    /// **84.95**, which would have understated a form that guesses a
    /// width by a wide margin and might well have condemned it.
    fn draw(self) -> &'static [(u8, usize)] {
        match self {
            // 37 + 218 + 1 is 256.
            Shape::Incomp => &[(7, 37), (8, 218), (9, 1)],
            // 22 + 65 + 11 + 29 + 129 is 256.
            Shape::Code => &[(5, 22), (6, 65), (7, 11), (8, 29), (9, 129)],
            _ => &[],
        }
    }
}

/// A 256 entry pick table realizing `draw`, spreading each width's slots
/// round robin over the symbols that HAVE that width.
///
/// The emitter is independent from symbol to symbol, which reproduces
/// the measured JOINT distribution exactly on the incompressible leg and
/// NOT on the code leg. The gate work's joint tables say so: that leg's
/// pairs are 8+8 at 72.171 percent against 0.8495 squared, which is
/// 0.72165, and 7+7 at 2.138 against 0.1462 squared, which is 0.02137,
/// so its widths are independent to three places. `rar3_code_32m`'s are
/// NOT: its 9+9 is 36.251 percent against an independent 25.4, and its
/// 5+6 is 16.128 against 2.17, so that leg's literals cluster by width
/// in runs. An independent emitter therefore models the incompressible
/// leg's stream faithfully and UNDERSTATES what a pair table can do on
/// the code leg, whose measured `w1 + w2 <= 14` mass is 40.71 percent.
/// Said here rather than discovered later from a row that disagrees with
/// the corpus.
fn draw(lengths: &[u8], want: &[(u8, usize)]) -> Vec<u8> {
    let mut picks: Vec<u8> = Vec::with_capacity(256);
    for &(width, slots) in want {
        let symbols: Vec<u8> = lengths
            .iter()
            .enumerate()
            .take(256)
            .filter(|(_, &have)| have == width)
            .map(|(symbol, _)| symbol as u8)
            .collect();
        if symbols.is_empty() {
            continue;
        }
        for slot in 0..slots {
            #[allow(clippy::indexing_slicing)] // the modulus is its length
            picks.push(symbols[slot % symbols.len()]);
        }
    }
    // A shape whose draw does not sum to 256 is a shape whose realized
    // widths are not what it says, so it is padded at the modal width
    // rather than left short.
    let fill = picks.last().copied().unwrap_or(0);
    while picks.len() < 256 {
        picks.push(fill);
    }
    picks.truncate(256);
    picks
}

/// A complete code over 256 literals and 16 non literal symbols, given
/// as `(width, count)` for the literals.
///
/// The counts are checked against Kraft rather than trusted: a shape
/// whose code is not complete is not an alphabet any block can carry,
/// and the whole point of these two shapes is that they are the
/// corpus's and not a construction's.
fn widths_to_lengths(literals: &[(u8, usize)], others: &[(u8, usize)]) -> Vec<u8> {
    let mut lengths = vec![0u8; super::MAIN_SYMBOLS];
    let mut at = 0usize;
    for &(width, count) in literals {
        for _ in 0..count {
            if let Some(slot) = lengths.get_mut(at) {
                *slot = width;
            }
            at += 1;
        }
    }
    // A literal symbol the table does not USE keeps length zero, which
    // is what an alphabet of fewer than 256 used literals means: the
    // incompressible member's table carries 224, so 32 byte values never
    // appear in that member at all. That is the corpus generator's doing
    // and not RAR's, and it is why "incompressible" is uniform over 224
    // symbols rather than over 256.
    debug_assert!(at <= 256);
    let mut at = 256usize;
    for &(width, count) in others {
        for _ in 0..count {
            if let Some(slot) = lengths.get_mut(at) {
                *slot = width;
            }
            at += 1;
        }
    }
    debug_assert!(at <= super::MAIN_SYMBOLS);
    // Checked, not trusted: a shape whose code is not complete is not an
    // alphabet any block can carry.
    debug_assert_eq!(kraft_numerator(&lengths), 1u64 << 15);
    lengths
}

impl Shape {
    /// Code lengths for the 256 literal values of this shape, as the
    /// 404 length vector's main-alphabet prefix.
    fn lengths(self) -> Vec<u8> {
        match self {
            // Flat: 256 symbols of equal length is eight bits each, and
            // the code is complete.
            Shape::Random => vec![8u8; 256],
            Shape::NearFlat => {
                // 240 literals at eight, 16 at nine, and the 16 non
                // literal symbols at nine. Kraft: 240/256 + 16/512 +
                // 16/512 is exactly one.
                let mut lengths = vec![8u8; super::MAIN_SYMBOLS];
                for length in lengths.iter_mut().skip(240).take(16) {
                    *length = 9;
                }
                for length in lengths.iter_mut().skip(256).take(16) {
                    *length = 9;
                }
                for length in lengths.iter_mut().skip(272) {
                    *length = 0;
                }
                debug_assert_eq!(kraft_numerator(&lengths), 1u64 << 15);
                lengths
            }
            // 4*32 + 2*144 + 80 + 16 is 512, so the code is complete.
            // THE REAL TABLE, read off the member by the pair-loop gate
            // probe on 21 Sep 2026: 32 symbols at width 7, 191 at
            // 8 and 1 at 9, which is 224 of the 256 literal values, with
            // Kraft mass 0.2500, 0.7461 and 0.0020. One non literal at 9
            // completes the code.
            Shape::Incomp => widths_to_lengths(&[(7, 32), (8, 191), (9, 1)], &[(9, 1)]),
            // THE REAL TABLE: 3 symbols at width 5, 11 at 6, 5 at 7, 23
            // at 8 and 214 at 9, all 256 literal values used, with Kraft
            // mass 0.0938, 0.1719, 0.0391, 0.0898 and 0.4180. Width 9
            // carries two and a half times the runner up and there is NO
            // TIE. An earlier cut of this shape INVENTED counts that
            // tied at 8 and 9 and made `PrefixTable::literal_mode` pick
            // the wrong width; the tie was the construction's and not
            // the corpus's, and the statistic is right on the real
            // table. The non literals carry the remaining 0.1875.
            Shape::Code => widths_to_lengths(
                &[(5, 3), (6, 11), (7, 5), (8, 23), (9, 214)],
                &[(4, 2), (5, 1), (6, 1), (7, 1), (8, 1), (9, 2)],
            ),
            Shape::Text => {
                // A COMPLETE code (Kraft exactly one) with widths four
                // to twelve, built by compensation from the flat eight:
                // promoting one symbol from eight to `8 - k` costs
                // `2^-(8-k) - 2^-8`, and demoting `2^k` symbols from
                // eight to `8 + k` frees exactly that. So one symbol at
                // each of 4, 5, 6 and 7, two at 9, four at 10, eight at
                // 11, sixteen at 12, and the rest at eight.
                //
                // A skew wider than this is not available over 256
                // symbols: a complete code's mean width over an
                // alphabet of 256 is at least eight, so what makes the
                // realized widths VARY is the emitter, which draws the
                // narrow symbols far more often than uniform
                // ([`Shape::picks`]).
                let mut lengths = vec![8u8; 256];
                let mut at = 0usize;
                let mut take = |count: usize, width: u8, at: &mut usize| {
                    for _ in 0..count {
                        lengths[*at] = width;
                        *at += 1;
                    }
                };
                take(1, 4, &mut at);
                take(1, 5, &mut at);
                take(1, 6, &mut at);
                take(1, 7, &mut at);
                // The wide tail goes at the top of the alphabet, so the
                // narrow symbols keep the low indices and the pick table
                // below reads plainly.
                let mut at = 256 - 30;
                take(2, 9, &mut at);
                take(4, 10, &mut at);
                take(8, 11, &mut at);
                take(16, 12, &mut at);
                debug_assert_eq!(kraft_numerator(&lengths), 1u64 << 15);
                lengths
            }
        }
    }
}

impl Shape {
    /// A uniform byte to a symbol of this shape, as a 256 entry table.
    ///
    /// [`Shape::Random`] is the identity, which is what makes its stream
    /// 256 equally frequent literals of eight bits each. [`Shape::Text`]
    /// draws the four NARROW symbols 40 percent of the time and the wide
    /// tail 15 percent, so the realized width varies from symbol to
    /// symbol and its mean falls below eight - which is the property the
    /// pair loop's second lookup depends on, its index being offset by
    /// the FIRST code's width.
    fn picks(self) -> Vec<u8> {
        match self {
            // Uniform over all 256 literals, so 240 of every 256
            // symbols are eight bits wide and 16 are nine: the 93.75
            // percent the doc comment names is the emitter's doing as
            // much as the code's.
            Shape::Random | Shape::NearFlat => (0..=255u8).collect(),
            // Drawn at the frequency an OPTIMAL code implies, which is
            // `2^-w` for a symbol of width `w`. A canonical code is
            // built FOR frequencies, so this is the distribution that
            // produced these widths, and it is the honest guess where
            // the realized distribution has not been measured. The
            // histogram this shape comes from gives each block's width
            // RANGE and not its realized draw, so this is stated as the
            // assumption it is: the per pair realized distribution is
            // not measured yet.
            Shape::Incomp | Shape::Code => draw(&self.lengths(), self.draw()),
            Shape::Text => {
                let wide: Vec<u8> = (256 - 30..256).map(|value| value as u8).collect();
                let middle: Vec<u8> = (4..256 - 30).map(|value| value as u8).collect();
                let mut picks = Vec::with_capacity(256);
                for index in 0..256usize {
                    let pick = if index < 102 {
                        (index % 4) as u8
                    } else if index < 217 {
                        middle[index % middle.len()]
                    } else {
                        wide[index % wide.len()]
                    };
                    picks.push(pick);
                }
                picks
            }
        }
    }
}

/// Kraft's sum over `lengths`, as a numerator over `2^15`, so a complete
/// code is exactly `1 << 15` and the check is integer.
fn kraft_numerator(lengths: &[u8]) -> u64 {
    lengths
        .iter()
        .filter(|&&width| width > 0)
        .map(|&width| 1u64 << (15 - u32::from(width)))
        .sum()
}

/// The canonical code a length list gives each symbol: codes of each
/// length assigned in symbol order, shorter lengths first, which is the
/// inverse of SPEC-H1 3.10's decoding function.
fn canonical(lengths: &[u8]) -> Vec<(u32, u8)> {
    let mut codes = vec![(0u32, 0u8); lengths.len()];
    let mut next = 0u32;
    for width in 1..=15u8 {
        for (symbol, &length) in lengths.iter().enumerate() {
            if length == width {
                codes[symbol] = (next, width);
                next += 1;
            }
        }
        next <<= 1;
    }
    codes
}

/// Which stage of the loop a variant runs. The names say what is IN it,
/// and [`Stage::Full`] is the shipped loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    /// Everything: refill, two dependent lookups, two window writes,
    /// one consume. The shipped pair loop of `Rar3Lz::run`.
    Full,
    /// Full without the two window WRITES. The decoded bytes go to a
    /// register the caller black boxes, so the decode chain and the bit
    /// positions are untouched and only the stores are gone.
    NoWrite,
    /// Full without the two table LOOKUPS. The refill and the writes
    /// stay, and the width consumed per pair is the shape's own so the
    /// refill RATE is unchanged; the bytes written come from the peeked
    /// word by a shift, so the store still depends on the reader.
    NoLookup,
    /// The reader ALONE: peek and consume at the shape's own rate, no
    /// lookup and no write.
    RefillOnly,
    /// The two dependent LOOKUPS and the writes, with no reader at all:
    /// the index of the first lookup is carried from the previous pair's
    /// answer, so the load to load chain is the same shape it is in the
    /// full loop.
    LookupOnly,
    /// The two window WRITES alone, with no reader and no table.
    WriteOnly,
    /// The literal loop AS IT WAS at an earlier revision: one literal a turn, a
    /// SIXTEEN bit peek, and the index taken through `PrefixTable::
    /// lookup` rather than `lookup_direct`.
    ///
    /// It is here because the text-lz discrepancy work traced a 5.6 to
    /// 7.0 percent move in rarkit's OWN wall to the revisions
    /// after that one, which is where both halves of this loop's present
    /// shape landed: the pair, and the twelve bit peek. Attributing that
    /// to one of them needs the two measured apart, which is the next
    /// stage as well as this one.
    SinglePeek16,
    /// One literal a turn, but the TWELVE bit peek of the shipped loop.
    /// Against [`Stage::SinglePeek16`] it isolates the peek width, and
    /// against [`Stage::Full`] it isolates the pairing.
    SinglePeek12,
    /// [`Stage::LookupOnly`] over a NINE bit table instead of the
    /// twelve bit one, and nothing else changed.
    ///
    /// It is a diagnostic rather than a proposal: `PrefixTable`'s direct
    /// table is 4,096 entries of `u16`, which is eight kibibytes, and
    /// the question this arm asks is whether the chain that bounds the
    /// loop is bound by the LATENCY of those two loads - in which case a
    /// table that fits a cache level better is a lever - or by something
    /// the size cannot touch. A nine bit table is one kibibyte and
    /// answers every code of the `random` shape, all of which are eight
    /// bits wide.
    LookupOnlySmall,
    /// The lever this ladder's subtraction named: ONE load answers BOTH
    /// codes, out of a [`PairTable`] indexed by [`PAIR_BITS`] of
    /// lookahead, falling back to the two dependent lookups for a pair
    /// the table cannot answer.
    ///
    /// It is a DECODING stage and not a subtraction: it produces the
    /// same bytes as [`Stage::Full`] and `tests/h1_ladder.rs` checks
    /// that it does, because a loop that is faster and wrong is not a
    /// result.
    ///
    /// Fourteen bits is SPEC-H1 4.2's ceiling and not a choice (see
    /// [`PAIR_BITS`]), so on an eight bit literal alphabet this stage
    /// resolves NOTHING and measures the cost of asking. That is the
    /// point of having it beside [`Stage::PairTable16`].
    PairTable14,
    /// [`Stage::PairTable14`] at a SIXTEEN bit index, which answers a
    /// pair of eight bit codes and is 262,144 bytes.
    ///
    /// **This stage cannot ship.** SPEC-H1 4.2 caps this package at the
    /// window plus under 128 KiB and 5.6 asserts the figure, and this
    /// table alone is twice that. It is here as EVIDENCE, to answer
    /// whether the form would pay at all before anybody argues about the
    /// ceiling, and the write-up says so beside its row.
    PairTable16,
    /// One SPECULATIVE second lookup: its index is taken at the width
    /// the table's literals most often have, which is known before the
    /// first load issues, so the two loads go together instead of in
    /// series. A first code of any other width takes the dependent
    /// lookup as today.
    ///
    /// This is the form that costs no memory and no build, so it is the
    /// one that can ship whatever the ceiling says. What it is worth is
    /// the share of literals that HAVE the guessed width, which is 100
    /// percent on [`Shape::Random`] by construction and 93.75 on
    /// [`Shape::NearFlat`].
    PairSpec1,
    /// TWO speculative second lookups, at the modal width and the one
    /// above it, both independent of the first load.
    ///
    /// A canonical code over a near uniform alphabet has exactly two
    /// literal widths, `w` and `w + 1` ([`Shape::NearFlat`] is 240 at
    /// eight and 16 at nine), so two guesses cover every literal of it
    /// and the dependent lookup becomes unreachable on that shape. The
    /// cost is one more load in flight per pair.
    PairSpec2,
}

impl Stage {
    /// Every stage, in ladder order.
    pub(crate) const ALL: [Stage; 13] = [
        Stage::Full,
        Stage::NoWrite,
        Stage::NoLookup,
        Stage::RefillOnly,
        Stage::LookupOnly,
        Stage::WriteOnly,
        Stage::SinglePeek16,
        Stage::SinglePeek12,
        Stage::LookupOnlySmall,
        Stage::PairTable14,
        Stage::PairTable16,
        Stage::PairSpec1,
        Stage::PairSpec2,
    ];

    /// The name a table row carries.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Stage::Full => "full",
            Stage::NoWrite => "no-write",
            Stage::NoLookup => "no-lookup",
            Stage::RefillOnly => "refill-only",
            Stage::LookupOnly => "lookup-only",
            Stage::WriteOnly => "write-only",
            Stage::SinglePeek16 => "single-peek16",
            Stage::SinglePeek12 => "single-peek12",
            Stage::LookupOnlySmall => "lookup-only-1k",
            Stage::PairTable14 => "pair-table-14",
            Stage::PairTable16 => "pair-table-16",
            Stage::PairSpec1 => "pair-spec1",
            Stage::PairSpec2 => "pair-spec2",
        }
    }

    /// Whether this stage DECODES: whether it must produce the stream's
    /// own literals byte for byte.
    ///
    /// The subtractive stages do not and must not - a stage with the
    /// lookups removed writes shifted input bytes on purpose - so the
    /// check is worth nothing applied to them. Every stage that is a
    /// candidate LOOP rather than a subtraction answers true here, and
    /// `tests/h1_ladder.rs` holds each of those to the same byte
    /// comparison the full stage takes.
    pub(crate) fn decodes(self) -> bool {
        matches!(
            self,
            Stage::Full
                | Stage::SinglePeek16
                | Stage::SinglePeek12
                | Stage::PairTable14
                | Stage::PairTable16
                | Stage::PairSpec1
                | Stage::PairSpec2
        )
    }
}

/// One shape's packed bytes, its table, and what the stream decodes to.
pub(crate) struct Ladder {
    packed: Vec<u8>,
    table: PrefixTable,
    /// What [`Stage::Full`] must produce, byte for byte.
    expected: Vec<u8>,
    /// Symbols every variant walks.
    symbols: usize,
    /// A NINE bit direct table over the same code, one kibibyte against
    /// the twelve bit table's eight, for [`Stage::LookupOnlySmall`].
    /// Entries are `symbol << 4 | width` exactly as `PrefixTable`'s are,
    /// and a code too wide for nine bits gets the first entry it
    /// overlaps, which is enough for a latency diagnostic and is not a
    /// decoder.
    small: Vec<u16>,
    /// The mean code width of this shape, in bits, times 256. The
    /// no-lookup variants consume this rate rather than a decoded width,
    /// which is what keeps their refill rate the shape's own.
    width_q8: u32,
    /// The shipped [`PairTable`], for [`Stage::PairTable14`].
    pairs: PairTable,
    /// The same composition at a SIXTEEN bit index, for
    /// [`Stage::PairTable16`]. It is a `Vec` and not a [`PairTable`]
    /// because no [`PairTable`] this package may hold is this wide: 4.2
    /// caps the package at the window plus under 128 KiB and this is
    /// 262,144 bytes. A diagnostic, like `small` above, and not a
    /// decoder in waiting.
    wide: Vec<u32>,
    /// The width this shape's literals most often have, which is what
    /// the speculative stages guess ([`PrefixTable::literal_mode`]).
    mode: u8,
    /// The share of this stream's literals that HAVE `mode`, and the
    /// share that have `mode` or `mode + 1`: the hit rates
    /// [`Stage::PairSpec1`] and [`Stage::PairSpec2`] get on it.
    mode_hit: (f64, f64),
    /// The shape this was built from, for [`Ladder::best_mode`].
    shape: Shape,
}

/// The index width [`Stage::PairTable16`] runs at. Outside SPEC-H1
/// 4.2's ceiling, and measured only to say whether the form would pay if
/// the ceiling moved.
const WIDE_BITS: u8 = 16;

/// [`PairTable::build`]'s rule at an arbitrary index width, for the over
/// ceiling arm. Kept beside the real one rather than sharing it, because
/// the real one is shipped code whose index width is a constant the
/// compiler folds and this is a bench diagnostic.
fn build_wide(table: &PrefixTable, bits: u8) -> Vec<u32> {
    let len = 1usize << bits;
    let mut entries = vec![0u32; len];
    for (index, slot) in entries.iter_mut().enumerate() {
        let index = index as u32;
        let first = table.lookup_direct(index >> (bits - PrefixTable::DIRECT_BITS));
        if first >= super::LITERAL_TOP {
            continue;
        }
        let width = first as u8 & 15;
        let rest = (index << width) & (len as u32 - 1);
        let second = table.lookup_direct(rest >> (bits - PrefixTable::DIRECT_BITS));
        if second >= super::LITERAL_TOP || second as u8 & 15 > bits - width {
            continue;
        }
        let total = u32::from(width) + u32::from(second as u8 & 15);
        *slot = u32::from(first >> 4) | (u32::from(second >> 4) << 8) | (total << 16);
    }
    entries
}

/// The shipped pair of dependent lookups, for the fall back arm of every
/// speculative stage below and for the stages that measure it whole.
///
/// It is ONE function so that a candidate loop's fall back is the same
/// code as the loop it is a candidate against, rather than the same code
/// by inspection.
#[inline(always)]
fn dependent_pair(table: &PrefixTable, bits: u32, input: &mut Bits<'_>, pair: &mut [u8; 2]) {
    let first = table.lookup_direct(bits >> PrefixTable::DIRECT_BITS);
    let width = first as u8 & 15;
    let second = table.lookup_direct(bits >> u32::from(PrefixTable::DIRECT_BITS - width));
    pair[0] = (first >> 4) as u8;
    pair[1] = (second >> 4) as u8;
    input.consume_ready(width + (second as u8 & 15));
}

/// One pair through a SPECULATIVE second lookup, falling back to
/// [`dependent_pair`].
///
/// `mode` is the width the second code is guessed at, which is a block
/// constant, so the guessed load's index does not wait on the first
/// load's answer and the two issue together. `TWO` adds a second guess
/// at `mode + 1`, which is the other width a canonical code over a near
/// uniform alphabet has.
///
/// **The guess is USED only where it is right.** `width == mode` is
/// tested against the first code's own answer before either symbol is
/// written, so a block whose widths are not what the table's mode says
/// pays a wasted load and never a wrong literal. That is deliberate and
/// is the difference between a speculation and an assumption: this
/// function cannot decode a stream incorrectly, whatever `mode` is.
///
/// One definition, called from both the timed loop and the correctness
/// check, so the two cannot drift apart.
#[inline(always)]
fn spec_pair<const TWO: bool>(
    table: &PrefixTable,
    bits: u32,
    mode: u8,
    input: &mut Bits<'_>,
    pair: &mut [u8; 2],
) {
    let first = table.lookup_direct(bits >> PrefixTable::DIRECT_BITS);
    let low = table.lookup_direct(bits >> u32::from(PrefixTable::DIRECT_BITS - mode));
    let width = first as u8 & 15;
    let guess = if TWO {
        let high = table.lookup_direct(bits >> u32::from(PrefixTable::DIRECT_BITS - mode - 1));
        if width == mode {
            low
        } else {
            high
        }
    } else {
        low
    };
    let guessed = width == mode || (TWO && width == mode + 1);
    if guessed && first < super::LITERAL_TOP && guess < super::LITERAL_TOP {
        pair[0] = (first >> 4) as u8;
        pair[1] = (guess >> 4) as u8;
        input.consume_ready(width + (guess as u8 & 15));
        return;
    }
    dependent_pair(table, bits, input, pair);
}

/// One pair through a table that answers both codes, falling back to
/// [`dependent_pair`].
#[inline(always)]
fn table_pair(
    table: &PrefixTable,
    entry: u32,
    bits: u32,
    input: &mut Bits<'_>,
    pair: &mut [u8; 2],
) {
    if PairTable::answered(entry) {
        let (first, second, width) = PairTable::unpack(entry);
        pair[0] = first;
        pair[1] = second;
        input.consume_ready(width);
        return;
    }
    dependent_pair(table, bits, input, pair);
}

/// The window every variant writes into. One RAR 3 dictionary step
/// (SPEC-H1 3.6's smallest), so the ring wraps many times over a run and
/// every variant wraps at the same places.
const LADDER_WINDOW: u32 = 1 << 16;

impl Ladder {
    /// Build `symbols` literals of `shape` as a packed RAR 3 literal
    /// stream, with the table that decodes them.
    ///
    /// There is no block header: the loop under test is entered with the
    /// tables already built and the reader already at the first symbol,
    /// which is where `Rar3Lz::run` enters it, so a header here would be
    /// bytes no variant reads.
    pub(crate) fn build(shape: Shape, symbols: usize) -> Ladder {
        let lengths = shape.lengths();
        let codes = canonical(&lengths);
        let picks = shape.picks();
        let mut noise = crate::bench_bytes::ByteRun::new(0x1add_e500);
        let mut expected = Vec::with_capacity(symbols);
        let mut packed: Vec<u8> = Vec::with_capacity(symbols * 2);
        let mut word = 0u64;
        let mut have = 0u32;
        let mut bits_out = 0u64;
        for _ in 0..symbols {
            let value = usize::from(picks[usize::from(noise.byte())]);
            let (code, width) = codes[value];
            expected.push(value as u8);
            word = (word << u32::from(width)) | u64::from(code);
            have += u32::from(width);
            bits_out += u64::from(width);
            while have >= 8 {
                have -= 8;
                packed.push((word >> have) as u8);
            }
        }
        if have > 0 {
            packed.push((word << (8 - have)) as u8);
        }
        // ROOM, not data. Two things need it. The reader may read an
        // eight byte word at the position; and the burst's own input
        // bound is `available() >> 4`, so a stream whose bits run out
        // exactly at its last symbol would stop the loop a sixteenth
        // short. The variants that do not DECODE a width consume the
        // shape's mean instead, which drifts from the real rate by a
        // fraction of a bit a pair, so the pad must cover that drift
        // too: a quarter of a byte a symbol is four times the widest
        // drift a rounded mean can have.
        packed.resize(packed.len() + symbols / 4 + 64, 0);
        let mut table = PrefixTable::new(super::MAIN_SYMBOLS);
        let mut full = vec![0u8; super::MAIN_SYMBOLS];
        // A shape may name the non literal symbols as well as the 256
        // literals ([`Shape::NearFlat`] does, because a complete code
        // that has no room for an end of block symbol is not a code any
        // block can carry), so the prefix copied is the shape's own
        // length and not a fixed 256.
        full[..lengths.len()].copy_from_slice(&lengths);
        table.build(&full);
        let width_q8 = ((bits_out * 256) / symbols as u64) as u32;
        let mut small = vec![0u16; 1 << 9];
        for (symbol, &(code, width)) in codes.iter().enumerate() {
            if width == 0 {
                continue;
            }
            let entry = ((symbol as u16) << 4) | u16::from(width);
            if width <= 9 {
                let base = (code as usize) << (9 - u32::from(width));
                let span = 1usize << (9 - u32::from(width));
                for slot in small.iter_mut().skip(base).take(span) {
                    *slot = entry;
                }
            } else {
                let at = (code as usize) >> (u32::from(width) - 9);
                if small[at] == 0 {
                    small[at] = entry;
                }
            }
        }
        // No entry may be zero: a zero width would advance the chain by
        // nothing and the arm would measure an infinite loop's shape
        // rather than a lookup's.
        for entry in small.iter_mut() {
            if *entry & 15 == 0 {
                *entry = 8;
            }
        }
        let mut pairs = PairTable::new();
        pairs.build(&table);
        let wide = build_wide(&table, WIDE_BITS);
        // From the LENGTHS, not from the table: see `literal_mode`'s own
        // comment for why it must not live inside `PrefixTable::build`.
        let mode = literal_mode(&full);
        // Over the STREAM's symbols, not over the alphabet: it is how
        // often a guess is right that the speculative stages are worth,
        // and a rare symbol of the guessed width flatters the alphabet
        // and not the loop.
        let mut one = 0usize;
        let mut two = 0usize;
        for &value in expected.iter() {
            let width = lengths.get(usize::from(value)).copied().unwrap_or(0);
            if width == mode {
                one += 1;
            }
            if width == mode || width == mode + 1 {
                two += 1;
            }
        }
        let denominator = expected.len().max(1) as f64;
        let mode_hit = (one as f64 / denominator, two as f64 / denominator);
        Ladder {
            packed,
            table,
            small,
            expected,
            symbols,
            width_q8,
            pairs,
            wide,
            mode,
            mode_hit,
            shape,
        }
    }

    /// Entries of the fourteen bit pair table that answer a pair, and
    /// the same for the sixteen bit one, each of its own length.
    ///
    /// This is the number that says whether a pair table is worth
    /// building for a shape at all, and it is a property of the
    /// ALPHABET rather than of the box, so it belongs beside the timing
    /// rather than in it.
    pub(crate) fn pair_cover(&self) -> (f64, f64) {
        let narrow = f64::from(self.pairs.resolved()) / (1u32 << PAIR_BITS) as f64;
        let wide =
            self.wide.iter().filter(|entry| **entry != 0).count() as f64 / self.wide.len() as f64;
        (narrow, wide)
    }

    /// The width the speculative stages guess, and the share of this
    /// shape's literal SYMBOLS that have it.
    ///
    /// The share is over the stream's own symbols and not over the
    /// alphabet, so it is the hit rate the speculation actually gets.
    pub(crate) fn mode_cover(&self) -> (u8, f64, f64) {
        (self.mode, self.mode_hit.0, self.mode_hit.1)
    }

    /// The width that WOULD have been the best guess on this stream, and
    /// the share of its literals that have it.
    ///
    /// This is the headroom in [`PrefixTable::literal_mode`] itself, as
    /// against the headroom in the form that uses it, and the two are
    /// different findings. That statistic is computed from the code
    /// LENGTHS, which are all a decoder has, and it is only as good as
    /// the assumption that the encoder built a code matched to its
    /// frequencies. Where the realized draw agrees with the code's own
    /// Kraft mass the two coincide; where it does not, a form that
    /// guesses the right width could pay while the one that guesses THIS
    /// width does not, and a row that reported only the second would
    /// read as a verdict on the form.
    pub(crate) fn best_mode(&self) -> (u8, f64) {
        let lengths = self.shape.lengths();
        let mut seen = [0usize; 16];
        for &value in self.expected.iter() {
            let width = lengths.get(usize::from(value)).copied().unwrap_or(0);
            if let Some(slot) = seen.get_mut(usize::from(width & 15)) {
                *slot += 1;
            }
        }
        let mut best = 0u8;
        let mut most = 0usize;
        for (width, &count) in seen.iter().enumerate() {
            if count > most {
                most = count;
                best = width as u8;
            }
        }
        (best, most as f64 / self.expected.len().max(1) as f64)
    }

    /// Symbols every variant walks.
    pub(crate) fn symbols(&self) -> usize {
        self.symbols
    }

    /// What [`Stage::Full`] must produce.
    pub(crate) fn expected(&self) -> &[u8] {
        &self.expected
    }

    /// Run one variant over the whole stream, and answer the symbols it
    /// walked together with a value derived from everything it did, so
    /// that nothing in the loop is dead code.
    ///
    /// The destination is a fresh [`Window`] each call, so a variant
    /// never reads a previous one's cache state.
    pub(crate) fn run(&self, stage: Stage) -> (usize, u64) {
        let mut out = Window::new(LADDER_WINDOW);
        let mut input = Bits::new(&self.packed);
        let mut done = 0usize;
        let mut sink = 0u64;
        // A pair of widths in bits, for the variants that do not decode
        // one. Rounded from the shape's own mean, so the refill rate is
        // the shape's rather than a guess; `Shape::Random` is exactly
        // eight and rounds to itself.
        let pair_width = (((self.width_q8 * 2) + 128) >> 8) as u8;
        // The width the speculative stages guess, held to a range that
        // keeps both their shifts in it: a mode of zero (no literal the
        // direct table answers) or one at the table's own width would
        // put `DIRECT_BITS - mode - 1` out of range, and the guess would
        // then be nonsense rather than merely wrong.
        let mode = self.mode.clamp(1, PrefixTable::DIRECT_BITS - 1);
        let mut carry = 0x5bd1_e995u32;
        while done < self.symbols {
            let into = out.free_run();
            let room = (self.symbols - done).min(into.len());
            // The burst's own input bound, taken once for the run and
            // with a SHIFT, exactly as `Rar3Lz::run` takes it.
            let room = room.min((input.available() >> 4) as usize);
            if room == 0 {
                break;
            }
            // EVEN, so the single-literal stages walk exactly what the
            // pair stages do and no row is a different measurement.
            let into = &mut into[..room & !1];
            let mut count = 0usize;
            let (pairs, _odd) = into.as_chunks_mut::<2>();
            match stage {
                Stage::Full => {
                    for pair in pairs.iter_mut() {
                        let bits = input.peek_ready(2 * PrefixTable::DIRECT_BITS);
                        let first = self.table.lookup_direct(bits >> PrefixTable::DIRECT_BITS);
                        let width = first as u8 & 15;
                        let second = self
                            .table
                            .lookup_direct(bits >> u32::from(PrefixTable::DIRECT_BITS - width));
                        pair[0] = (first >> 4) as u8;
                        pair[1] = (second >> 4) as u8;
                        input.consume_ready(width + (second as u8 & 15));
                        count += 2;
                    }
                }
                Stage::NoWrite => {
                    for _ in pairs.iter_mut() {
                        let bits = input.peek_ready(2 * PrefixTable::DIRECT_BITS);
                        let first = self.table.lookup_direct(bits >> PrefixTable::DIRECT_BITS);
                        let width = first as u8 & 15;
                        let second = self
                            .table
                            .lookup_direct(bits >> u32::from(PrefixTable::DIRECT_BITS - width));
                        sink = sink.wrapping_add(u64::from(first >> 4));
                        sink = sink.wrapping_add(u64::from(second >> 4));
                        input.consume_ready(width + (second as u8 & 15));
                        count += 2;
                    }
                }
                Stage::NoLookup => {
                    for pair in pairs.iter_mut() {
                        let bits = input.peek_ready(2 * PrefixTable::DIRECT_BITS);
                        // The store still depends on the reader, by a
                        // shift rather than by a table load.
                        pair[0] = bits as u8;
                        pair[1] = (bits >> 8) as u8;
                        input.consume_ready(pair_width);
                        count += 2;
                    }
                }
                Stage::RefillOnly => {
                    for _ in pairs.iter_mut() {
                        let bits = input.peek_ready(2 * PrefixTable::DIRECT_BITS);
                        sink = sink.wrapping_add(u64::from(bits));
                        input.consume_ready(pair_width);
                        count += 2;
                    }
                }
                Stage::LookupOnlySmall => {
                    for pair in pairs.iter_mut() {
                        let first = self.small[(carry >> 9) as usize & 511];
                        let width = first as u8 & 15;
                        let second =
                            self.small[(carry >> (9 - u32::from(width.min(9)))) as usize & 511];
                        pair[0] = (first >> 4) as u8;
                        pair[1] = (second >> 4) as u8;
                        carry = carry.rotate_left(7) ^ u32::from(second);
                        count += 2;
                    }
                }
                Stage::LookupOnly => {
                    for pair in pairs.iter_mut() {
                        // The index is carried from the last pair's
                        // answer, so the two lookups here sit on a load
                        // to load chain of the same shape the full loop
                        // has, with no reader in it.
                        let first = self.table.lookup_direct(carry >> PrefixTable::DIRECT_BITS);
                        let width = first as u8 & 15;
                        let second = self
                            .table
                            .lookup_direct(carry >> u32::from(PrefixTable::DIRECT_BITS - width));
                        pair[0] = (first >> 4) as u8;
                        pair[1] = (second >> 4) as u8;
                        carry = carry.rotate_left(7) ^ u32::from(second);
                        count += 2;
                    }
                }
                Stage::WriteOnly => {
                    for pair in pairs.iter_mut() {
                        pair[0] = carry as u8;
                        pair[1] = (carry >> 8) as u8;
                        carry = carry.wrapping_add(0x0001_0001);
                        count += 2;
                    }
                }
                Stage::SinglePeek16 => {
                    // One literal a turn through the SIXTEEN bit peek
                    // and the `lookup` accessor, which is the loop
                    // an earlier revision shipped.
                    for slot in into.iter_mut() {
                        let entry = self.table.lookup(input.peek_ready(16));
                        *slot = (entry >> 4) as u8;
                        input.consume_ready(entry as u8 & 15);
                        count += 1;
                    }
                }
                Stage::SinglePeek12 => {
                    for slot in into.iter_mut() {
                        let entry = self
                            .table
                            .lookup_direct(input.peek_ready(PrefixTable::DIRECT_BITS));
                        *slot = (entry >> 4) as u8;
                        input.consume_ready(entry as u8 & 15);
                        count += 1;
                    }
                }
                Stage::PairTable14 => {
                    for pair in pairs.iter_mut() {
                        let bits = input.peek_ready(2 * PrefixTable::DIRECT_BITS);
                        // ONE load answers both codes. The index is the
                        // top `PAIR_BITS` of the same 24 bit peek the
                        // shipped loop takes, so the reader is untouched
                        // and only the chain changes.
                        let entry = self
                            .pairs
                            .lookup(bits >> (2 * PrefixTable::DIRECT_BITS - PAIR_BITS));
                        table_pair(&self.table, entry, bits, &mut input, pair);
                        count += 2;
                    }
                }
                Stage::PairTable16 => {
                    for pair in pairs.iter_mut() {
                        let bits = input.peek_ready(2 * PrefixTable::DIRECT_BITS);
                        let at = (bits >> (2 * PrefixTable::DIRECT_BITS - WIDE_BITS)) as usize;
                        let entry = self.wide[at & ((1usize << WIDE_BITS) - 1)];
                        table_pair(&self.table, entry, bits, &mut input, pair);
                        count += 2;
                    }
                }
                Stage::PairSpec1 => {
                    for pair in pairs.iter_mut() {
                        let bits = input.peek_ready(2 * PrefixTable::DIRECT_BITS);
                        spec_pair::<false>(&self.table, bits, mode, &mut input, pair);
                        count += 2;
                    }
                }
                Stage::PairSpec2 => {
                    for pair in pairs.iter_mut() {
                        let bits = input.peek_ready(2 * PrefixTable::DIRECT_BITS);
                        spec_pair::<true>(&self.table, bits, mode, &mut input, pair);
                        count += 2;
                    }
                }
            }
            // The odd last byte of a run is not the loop under test, and
            // is skipped rather than decoded: every variant skips the
            // same one.
            out.commit(count);
            done += count;
            if count == 0 {
                break;
            }
        }
        sink = sink.wrapping_add(u64::from(carry));
        sink = sink.wrapping_add(out.produced());
        (done, black_box(sink))
    }

    /// What the window holds after a [`Stage::Full`] run, from the
    /// start, for the correctness check the variants are worth nothing
    /// without.
    ///
    /// Only the last [`LADDER_WINDOW`] bytes survive a long run, so the
    /// caller compares the tail.
    pub(crate) fn decode_tail(&self, stage: Stage, want: usize) -> Vec<u8> {
        let mode = self.mode.clamp(1, PrefixTable::DIRECT_BITS - 1);
        let mut out = Window::new(LADDER_WINDOW);
        let mut input = Bits::new(&self.packed);
        let mut done = 0usize;
        while done < self.symbols {
            let into = out.free_run();
            let room = (self.symbols - done).min(into.len());
            let room = room.min((input.available() >> 4) as usize);
            if room == 0 {
                break;
            }
            let into = &mut into[..room];
            let mut count = 0usize;
            let (pairs, odd) = into.as_chunks_mut::<2>();
            for pair in pairs.iter_mut() {
                let bits = input.peek_ready(2 * PrefixTable::DIRECT_BITS);
                match stage {
                    Stage::PairTable14 => {
                        let entry = self
                            .pairs
                            .lookup(bits >> (2 * PrefixTable::DIRECT_BITS - PAIR_BITS));
                        table_pair(&self.table, entry, bits, &mut input, pair);
                    }
                    Stage::PairTable16 => {
                        let at = (bits >> (2 * PrefixTable::DIRECT_BITS - WIDE_BITS)) as usize;
                        let entry = self.wide[at & ((1usize << WIDE_BITS) - 1)];
                        table_pair(&self.table, entry, bits, &mut input, pair);
                    }
                    Stage::PairSpec1 => {
                        spec_pair::<false>(&self.table, bits, mode, &mut input, pair);
                    }
                    Stage::PairSpec2 => {
                        spec_pair::<true>(&self.table, bits, mode, &mut input, pair);
                    }
                    // `full`, and the two single-literal loops, which
                    // decode a pair's worth the same way here: what the
                    // tail checks is the BYTES, and a loop that takes
                    // one literal a turn produces the same ones.
                    _ => dependent_pair(&self.table, bits, &mut input, pair),
                }
                count += 2;
            }
            let _ = odd;
            out.commit(count);
            done += count;
            if count == 0 {
                break;
            }
        }
        let to = out.produced();
        let from = to.saturating_sub(want as u64);
        let mut tail = vec![0u8; (to - from) as usize];
        if out.copy_out(from, &mut tail).is_err() {
            tail.clear();
        }
        tail
    }
}
