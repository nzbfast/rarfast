//! The decoding function every RAR 3 table is read through: `D` of
//! SPEC-D part 3 section 3.2, which answers complete, incomplete,
//! oversubscribed and all zero code length lists alike.
//!
//! One component serves all five alphabets (SPEC-H1 3.10). RAR 5's tables
//! are a different function and must not share this one: RAR 5 refuses an
//! oversubscribed list when it builds it and refuses a code in an
//! incomplete list's unused space (SPEC-H2 3.4).

use crate::rar3_lz::bits::BitSource;
use crate::{Error, ErrorKind, Result};

/// Lookahead bits the direct table answers. A code of at most this width
/// costs one load; a wider one, and a lookahead no symbol owns, is worked
/// out from the runs by [`PrefixTable::by_runs`].
const LUT_BITS: u8 = 12;
/// Entries in the direct table.
const LUT_LEN: usize = 1 << LUT_BITS;
/// Bits of a 16 bit lookahead that the direct table's index drops.
const LUT_DROP: u8 = 16 - LUT_BITS;

/// The direct table's answer for a lookahead whose code is wider than
/// [`LUT_BITS`] or which no symbol owns: [`PrefixTable::by_runs`] answers
/// it.
///
/// An entry is `(symbol << 4) | width`, the alphabets here are at most 299
/// symbols and a width is 1 to 15, so the largest entry a table can hold
/// is `(298 << 4) | 15`, which is 4,783. `u16::MAX` is therefore not a
/// value any code can produce, which is what lets one unsigned compare do
/// the work of two on the burst path below.
pub(crate) const WIDE: u16 = u16::MAX;

/// The first entry that is NOT a literal answer. An entry below it is a
/// symbol in 0 to 255 with a width the direct table knows, so the literal
/// burst of SPEC-H1 7.3 item 5 tests `entry < LITERAL_TOP` and needs no
/// second test: [`WIDE`] and every symbol from 256 up are above it.
pub(crate) const LITERAL_TOP: u16 = 256 << 4;

/// The share of a code's probability mass, in percent, that one literal
/// width must hold before the literal burst SPECULATES that the second
/// code of a pair has that width (see [`PrefixTable::literal_guess`]).
///
/// The number is a measured break-even and not a taste. The 21 Sep 2026
/// ladder (one load for both codes) timed the
/// speculative pair loop against the dependent one on the two REAL
/// literal alphabets of the RAR 3 gate corpora: on
/// `rar3_incompressible_64m`, whose modal width holds 0.746 of the mass
/// and 85 percent of the literals drawn, the guess is 13.8 (an Apple M1 Mac,
/// timed) and 17.1 percent (an Apple M3 Mac) FASTER a literal; on
/// `rar3_code_32m`, whose modal width holds 0.418 of the mass and 50
/// percent of the draw, the same loop is 29.4 and 23.7 percent SLOWER,
/// because a guess right half the time is the worst input a branch
/// predictor can be given. A cost model fitted to those two points, gain
/// per pair `a * hit - b * (1 - hit)` with `b` a mispredict and `a` a load
/// latency, puts the break-even at a hit rate of 0.708 (M3) to 0.742
/// (M1), and predicts the ladder's two constructed shapes (hit 0.9375
/// and 1.0) within three points. A block whose modal width holds more
/// mass than this is speculated on; every other block takes the
/// dependent loop that was gated before, with nothing added to it.
const SPECULATE_MASS_PERCENT: u32 = 72;

/// What the code lengths from 1 up to and including one length come to
/// (SPEC-D 3.2.1): how much of the lookahead their symbols own between
/// them, and how many symbols that is.
#[derive(Debug, Clone, Copy, Default)]
struct Through {
    /// Values of the 15 bit lookahead `v` owned, a symbol of length `L`
    /// owning `2^(15 - L)`. Past 32,768 on an oversubscribed list.
    values: u32,
    /// Ranked symbols.
    symbols: u16,
}

/// One alphabet's code lengths, answering `D` of SPEC-D 3.2.1.
///
/// The tables are built once per stream and rewritten in place at every
/// table read, so a decode allocates nothing (SPEC-H1 7.3 item 3).
#[derive(Debug)]
pub(crate) struct PrefixTable {
    /// The answer for each [`LUT_BITS`] bit start of a lookahead that
    /// settles one: `(symbol << 4) | length`. [`WIDE`] where it does not.
    by_prefix: Box<[u16; LUT_LEN]>,
    /// The symbols that have a codeword, in rank order: the shorter
    /// length first, the lower symbol first within a length. As long as
    /// the alphabet; only the ranked symbols' places are ever read.
    ranked: Box<[u16]>,
    /// [`Through`] for each length, so entry 15 is the whole list: `T`
    /// and `m` of 3.2.1. Entry 0 is nothing and stays zero.
    through: [Through; 16],
    /// The width the literal burst may GUESS a literal's code has, or
    /// zero when it must not guess: see [`PrefixTable::literal_guess`].
    literal_guess: u8,
}

impl PrefixTable {
    /// A table for an alphabet of `size` symbols, all lengths zero.
    ///
    /// This is the package's only allocation for tables; `build` never
    /// allocates again.
    pub(crate) fn new(size: usize) -> PrefixTable {
        let mut table = PrefixTable {
            by_prefix: vec![0u16; LUT_LEN]
                .into_boxed_slice()
                .try_into()
                .expect("the table's own length"),
            ranked: vec![0; size].into_boxed_slice(),
            through: [Through::default(); 16],
            literal_guess: 0,
        };
        table.build(&vec![0u8; size]);
        table
    }

    /// The width the literal burst may guess a pair's SECOND code has,
    /// 1 to [`LUT_BITS`], or zero when it must not guess at all.
    ///
    /// The pair loop of `Rar3Lz::run` costs two table loads in SERIES:
    /// the second code's index is offset by the first code's width, so
    /// the second load cannot issue until the first has landed, and the
    /// 21 Sep 2026 subtractive ladder puts that chain at 63 to 79
    /// percent of the loop with the table's SIZE excluded as the cause.
    /// Taking the second index at a width known BEFORE the first load
    /// issues lets the two loads go together; the guess is then checked
    /// against the first code's own decoded width and used only where it
    /// is right, so a wrong guess costs a wasted load and never a wrong
    /// byte.
    ///
    /// What the guess is worth is how often it is right, and the only
    /// thing a decoder can read is the code lengths, so the guess is the
    /// width whose literals carry the most of the code's probability
    /// mass, `count(w) << (15 - w)` over the symbols below 256: an
    /// optimal code gives a symbol of width `w` about `2^-w` of the
    /// stream, so this is the width a literal most often HAS rather than
    /// the width the most symbols have. It is zero, and the loop does
    /// not guess, unless that width holds more than
    /// [`SPECULATE_MASS_PERCENT`] of the mass, which is where the
    /// measured break-even sits.
    ///
    /// Computed once per table read inside [`PrefixTable::build`], from
    /// the pass that already walks every symbol's length, at about one
    /// add per symbol plus twelve compares: a small fraction of the 4,096
    /// entry direct fill the same call makes.
    #[inline(always)]
    pub(crate) fn literal_guess(&self) -> u8 {
        self.literal_guess
    }

    /// Bytes this table holds.
    pub(crate) fn held_bytes(&self) -> u64 {
        (self.by_prefix.len() * 2 + self.ranked.len() * 2) as u64
    }

    /// Rebuild from `lengths`, which must be as long as the alphabet and
    /// hold values of at most 15 (SPEC-H1 3.10: every length comes from a
    /// four bit field, so a larger one cannot arise).
    pub(crate) fn build(&mut self, lengths: &[u8]) {
        debug_assert_eq!(lengths.len(), self.ranked.len());
        let mut tally = [0u16; 16];
        for &length in lengths {
            debug_assert!(length <= 15);
            tally[usize::from(length & 15)] += 1;
        }
        let mut sum = Through::default();
        for ((length, upto), &count) in self.through.iter_mut().enumerate().zip(&tally).skip(1) {
            sum.symbols += count;
            sum.values += u32::from(count) << (15 - length);
            *upto = sum;
        }
        // Rank order. Each length's symbols take the places that end where
        // its `Through` does, and going down the alphabet fills those
        // places from the last one back, which leaves the lower symbol
        // first. The literals at each length are counted on the way, for
        // the guess.
        let mut place = self.through.map(|upto| upto.symbols);
        let mut literals = [0u16; 16];
        for (symbol, &length) in lengths.iter().enumerate().rev() {
            let length = usize::from(length & 15);
            if length == 0 {
                continue;
            }
            place[length] -= 1;
            self.ranked[usize::from(place[length])] = symbol as u16;
            literals[length] += u16::from(symbol < 256);
        }
        self.literal_guess = literal_guess(&literals);
        // R1 for the short codes: the runs lie end to end from zero in
        // rank order, and a symbol no longer than `LUT_BITS` owns
        // `LUT_LEN >> length` whole prefixes. The walk ends at the first
        // longer symbol or where the lookahead does; every prefix after it
        // is one `by_runs` answers.
        let mut settled = 0usize;
        for &symbol in &self.ranked[..usize::from(sum.symbols)] {
            let length = lengths[usize::from(symbol)] & 15;
            if length > LUT_BITS || settled == LUT_LEN {
                break;
            }
            let end = LUT_LEN.min(settled + (LUT_LEN >> length));
            let answer = (symbol << 4) | u16::from(length);
            debug_assert_ne!(answer, WIDE);
            self.by_prefix[settled..end].fill(answer);
            settled = end;
        }
        self.by_prefix[settled..].fill(WIDE);
    }

    /// `D(x)` of 3.2.1 as symbol and width, for any 16 bit lookahead,
    /// from the runs themselves.
    ///
    /// R1: the first length whose [`Through`] reaches past `v` holds the
    /// owner, and the owner is found from that length's END: the values
    /// between `v` and the end, in runs of that length, are how many
    /// places before the length's last symbol it ranks. R2: no length
    /// reaches past `v`, the width is 15, and the symbol is 0 or, from
    /// `k = n` on, the first ranked one.
    #[inline]
    pub(crate) fn by_runs(&self, lookahead: u32) -> (u16, u8) {
        debug_assert!(lookahead <= 0xffff);
        let v = lookahead >> 1;
        for length in 1..16usize {
            let upto = self.through[length];
            if v < upto.values {
                let back = ((upto.values - 1 - v) >> (15 - length)) as usize;
                let symbol = self.ranked[usize::from(upto.symbols) - 1 - back];
                return (symbol, length as u8);
            }
        }
        let whole = self.through[15];
        let k = usize::from(whole.symbols) + (v - whole.values) as usize;
        let symbol = if k >= self.ranked.len() && whole.symbols > 0 {
            self.ranked[0]
        } else {
            0
        };
        (symbol, 15)
    }

    /// The direct table's answer for a 16 bit lookahead, or [`WIDE`] when
    /// it has none.
    #[inline(always)]
    pub(crate) fn lookup(&self, lookahead: u32) -> u16 {
        self.lookup_direct(lookahead >> LUT_DROP)
    }

    /// The same answer from the top [`LUT_BITS`] bits alone, which is all
    /// the index ever uses.
    ///
    /// The literal burst peeks exactly [`LUT_BITS`] bits rather than
    /// sixteen, because a code the direct table answers is never wider
    /// than that: the bit cache then runs four bits longer between
    /// refills, which is about one symbol in seven fewer on a stream of
    /// eight bit literals.
    #[inline(always)]
    pub(crate) fn lookup_direct(&self, index: u32) -> u16 {
        // The mask is what tells the compiler the index is in range: the
        // table's length is a constant, so the bound goes away.
        self.by_prefix[(index as usize) & (LUT_LEN - 1)]
    }

    /// Lookahead bits the literal burst peeks, which is what the direct
    /// table indexes on.
    pub(crate) const DIRECT_BITS: u8 = LUT_BITS;

    /// One symbol from `input`, consuming its width.
    ///
    /// With fewer than 15 bits left the answer is returned when its width
    /// fits and is [`ErrorKind::Truncated`] with nothing consumed when it
    /// does not (SPEC-D 3.2.4).
    ///
    /// # Why the two arms are split, and why the head is `inline(always)`
    ///
    /// This is the MATCH path's decode (SPEC-H1 3.4 and 3.5), and a fresh
    /// match reaches it up to three times in a SERIAL chain: the main
    /// symbol, the distance symbol and the low distance symbol, with the
    /// length's and the distance's extra bits read between them. Until 22
    /// Sep 2026 the whole function was one `#[inline]` body of 248
    /// instructions in the release build and the compiler declined to
    /// inline it, so each of those three was a call that spilled the
    /// reader's `window` and `have` to memory and reloaded them
    /// afterwards. The text-leg profile reads
    /// `PrefixTable::decode` at 20.5 percent of that leg's decode and
    /// `Bits::read` at 8.8, and SPEC-H1 7.2's own baseline puts "prefix
    /// decode" at 30 percent of the same leg, which is the same number
    /// from the other side.
    ///
    /// What made the body too big to inline is the arm that almost never
    /// runs: [`PrefixTable::by_runs`] for a code wider than the direct
    /// table, which is a loop over fifteen lengths.
    /// It moves to [`PrefixTable::decode_wide`], `#[cold]` and
    /// `#[inline(never)]`, so what inlines into a caller is the direct
    /// hit alone: one peek, one load, one compare, one consume. The
    /// arithmetic is unchanged and every arm answers exactly what it
    /// answered before; only the call boundary moves.
    #[inline(always)]
    pub(crate) fn decode(&self, input: &mut impl BitSource) -> Result<u16> {
        if input.available() >= 15 {
            let lookahead = input.peek_ready(16);
            let entry = self.lookup(lookahead);
            if entry != WIDE {
                input.consume(entry as u8 & 15);
                return Ok(entry >> 4);
            }
            return Ok(self.decode_wide(input, lookahead));
        }
        self.decode_tail(input)
    }

    /// The direct table's [`WIDE`] answer resolved by
    /// [`PrefixTable::by_runs`], out of line so that
    /// [`PrefixTable::decode`]'s head is small enough to inline.
    ///
    /// It cannot fail: fifteen bits are known to be available at the one
    /// call site, and `by_runs` answers every lookahead.
    #[cold]
    #[inline(never)]
    fn decode_wide(&self, input: &mut impl BitSource, lookahead: u32) -> u16 {
        let (symbol, width) = self.by_runs(lookahead);
        input.consume(width);
        symbol
    }

    #[cold]
    fn decode_tail(&self, input: &mut impl BitSource) -> Result<u16> {
        let left = input.available();
        if left == 0 {
            return Err(Error::new(ErrorKind::Truncated));
        }
        let (symbol, width) = self.by_runs(input.peek(16));
        if u64::from(width) > left {
            return Err(Error::new(ErrorKind::Truncated));
        }
        input.consume(width);
        Ok(symbol)
    }
}

/// [`PrefixTable::literal_guess`] from the count of literal symbols at
/// each width: the width holding the most mass, `count << (15 - width)`,
/// when that is more than [`SPECULATE_MASS_PERCENT`] of a complete
/// code's `1 << 15`, and zero otherwise.
///
/// Only widths the direct table answers, 1 to [`LUT_BITS`], are
/// candidates: the burst's guessed index is `bits >> (LUT_BITS - guess)`
/// and a wider guess would have no direct entry to load. The mass can
/// exceed `1 << 15` on an oversubscribed list (SPEC-D 3.2 admits one);
/// the comparison is in `u32` with room for 299 symbols at width 1
/// times 100, so no length list overflows it.
fn literal_guess(literals: &[u16; 16]) -> u8 {
    let mut best = 0u8;
    let mut most = 0u32;
    for (width, &count) in literals
        .iter()
        .enumerate()
        .take(usize::from(LUT_BITS) + 1)
        .skip(1)
    {
        let mass = u32::from(count) << (15 - width);
        if mass > most {
            most = mass;
            best = width as u8;
        }
    }
    if most * 100 > SPECULATE_MASS_PERCENT << 15 {
        best
    } else {
        0
    }
}

/// The width whose LITERALS carry the most of an optimal code's
/// probability mass: `argmax_w count(w) << (15 - w)` over the symbols
/// below 256, and zero when none of them is a width a direct lookup
/// answers.
///
/// A canonical code built for frequencies gives a symbol of width `w`
/// about `2^-w` of the stream, so weighting the count by `2^-w` answers
/// "what width is a literal most likely to HAVE", where an unweighted
/// count answers "what width do the most symbols have". Those differ on
/// any skewed alphabet and it is the first that the speculative loop
/// needs, its whole value being how often a guessed width is right.
///
/// **It is NOT computed in [`PrefixTable::build`], and that is
/// deliberate.** `crates/rarkit/Cargo.toml` makes `rarkit` a dev
/// dependency of itself WITH `bench-internals`, so every bench and
/// integration test links a build that has this feature on, and
/// the bench is the gate. A per table read loop of 256
/// iterations inside `build` would therefore run inside the MEASURED
/// arm: `rar3_small_solid_20k` reads 20,000 tables, so it would add
/// real work to a leg other work is gated against, invisibly and in the
/// rarkit arm only. The ladder calls this once per shape with the
/// lengths it already holds, and `build` stays byte for byte what it is
/// without the feature.
#[cfg(feature = "bench-internals")]
pub(crate) fn literal_mode(lengths: &[u8]) -> u8 {
    let upto = lengths.len().min(256);
    let mut mass = [0u32; 16];
    #[allow(clippy::indexing_slicing)] // `upto <= lengths.len()`
    for &length in &lengths[..upto] {
        let width = usize::from(length & 15);
        if width == 0 || width > usize::from(LUT_BITS) {
            continue;
        }
        mass[width] += 1u32 << (15 - width);
    }
    let mut best = 0u8;
    let mut most = 0u32;
    for (width, &weight) in mass.iter().enumerate() {
        if weight > most {
            most = weight;
            best = width as u8;
        }
    }
    best
}

// ---- breaking the chain: one load for two codes ------------------------------
//
// BENCH ONLY. The shipped loop does not hold a [`PairTable`] and on this
// package's own arithmetic it never can: see [`PAIR_BITS`]. What is
// here is the form measured on the ladder, kept so the arm that closed
// the direction can be re-run rather than re-argued, and so the day
// SPEC-H1 4.2's ceiling moves the table is a measurement away rather
// than a rewrite. It goes behind `bench-internals` with the ladder that
// is its only caller.

/// Lookahead bits a [`PairTable`] indexes on.
///
/// Fourteen, and the ceiling is SPEC-H1 4.2's rather than this loop's.
/// That section caps this package at "the window plus under 128 KiB" and
/// section 5.6 asserts the figure as a number: the five decoding
/// components and the stored code lengths are 42,212 bytes today, so
/// 88,860 are left. A pair table of `1 << bits` entries of `u32` is
/// 65,536 bytes at fourteen and 262,144 at sixteen, so fourteen is the
/// widest index this package may hold and sixteen is outside the
/// specification rather than merely large.
///
/// What that costs is stated here because it is the design's binding
/// constraint: two codes are only answered together when their widths
/// SUM to at most this, so an alphabet of flat eight bit literals, which
/// is what `rar3_incompressible_64m` decodes, needs sixteen and is never
/// answered by a table this package is allowed to hold.
#[cfg(feature = "bench-internals")]
pub(crate) const PAIR_BITS: u8 = 14;
/// Entries in a [`PairTable`].
#[cfg(feature = "bench-internals")]
const PAIR_LEN: usize = 1 << PAIR_BITS;

/// An entry that answers no pair: either the first code is not a literal
/// the direct table knows, or the two widths do not fit [`PAIR_BITS`].
///
/// Zero is free for this because a resolved entry carries a combined
/// width of at least two in its top bits, so no pair can produce it.
#[cfg(feature = "bench-internals")]
const PAIR_NONE: u32 = 0;

/// Two literal codes answered by ONE load.
///
/// # Why this shape
///
/// The pair loop of SPEC-H1 7.3 item 5 costs two loads in SERIES: it
/// peeks, looks up the first code, and takes the second code's index at
/// an offset given by the FIRST code's width, so the second load cannot
/// issue until the first has landed. A measurement puts
/// that chain at 63 to 79 percent of the loop by subtraction on two
/// boxes and two shapes, with the reader at an eighth to a third and the
/// window writes at 1 to 2 percent, and its nine bit table arm came back
/// 5.6 to 5.8 percent SLOWER, so the chain is not bound by the table's
/// SIZE. What is left is the DEPENDENCE, and the only way to remove it
/// is to make one load answer both codes.
///
/// An entry is `sym1 | sym2 << 8 | (w1 + w2) << 16`, so the two symbols
/// are one sixteen bit store into the window and the consume is one
/// shift. [`PAIR_NONE`] falls back to the two dependent lookups, which
/// stay the correct path for every pair this table cannot answer.
#[cfg(feature = "bench-internals")]
#[derive(Debug)]
pub(crate) struct PairTable {
    entries: Box<[u32; PAIR_LEN]>,
    /// Entries that answer a pair, of [`PAIR_LEN`]. A diagnostic: it is
    /// what says whether a table is worth building for an alphabet at
    /// all, and it is read by the ladder rather than by the loop.
    resolved: u32,
}

#[cfg(feature = "bench-internals")]
impl PairTable {
    /// An empty table, answering no pair. This is the allocation; [`PairTable::build`] never
    /// allocates again.
    pub(crate) fn new() -> PairTable {
        PairTable {
            entries: vec![PAIR_NONE; PAIR_LEN]
                .into_boxed_slice()
                .try_into()
                .expect("the table's own length"),
            resolved: 0,
        }
    }

    /// Bytes this table holds.
    ///
    /// Not yet read by `Rar3Lz::held_bytes`: nothing in a shipped build
    /// holds a [`PairTable`] until this form wins its timed run, and the
    /// figure SPEC-H1 5.6 asserts is the one without it. It is here
    /// because the ceiling is the design's binding constraint and a
    /// table that cannot say its own size cannot be checked against one.
    #[allow(dead_code)]
    pub(crate) fn held_bytes(&self) -> u64 {
        (self.entries.len() * 4) as u64
    }

    /// Entries that answer a pair, of [`PAIR_LEN`].
    pub(crate) fn resolved(&self) -> u32 {
        self.resolved
    }

    /// Rebuild from `table`, whose direct answers this one composes.
    ///
    /// An index is [`PAIR_BITS`] of lookahead. The first code's own
    /// index is its top twelve bits. The second code begins `w1` bits in,
    /// so `PAIR_BITS - w1` of its bits are known and the rest of the
    /// twelve the direct table wants are zero: its answer is therefore
    /// determined only when its width fits in what is KNOWN, which is
    /// the `w2 <= PAIR_BITS - w1` test below and the reason a pair of
    /// eight bit codes never resolves at fourteen.
    pub(crate) fn build(&mut self, table: &PrefixTable) {
        let mut resolved = 0u32;
        for (index, slot) in self.entries.iter_mut().enumerate() {
            let index = index as u32;
            let first = table.lookup_direct(index >> (PAIR_BITS - LUT_BITS));
            // One unsigned compare rejects `WIDE` and every symbol from
            // 256 up together, exactly as the burst's own test does.
            if first >= LITERAL_TOP {
                *slot = PAIR_NONE;
                continue;
            }
            let width = first as u8 & 15;
            let known = PAIR_BITS - width;
            // The second code's twelve bit index, left aligned, with the
            // bits this lookahead does not reach left zero.
            let rest = (index << width) & (PAIR_LEN as u32 - 1);
            let second = table.lookup_direct(rest >> (PAIR_BITS - LUT_BITS));
            if second >= LITERAL_TOP || second as u8 & 15 > known {
                *slot = PAIR_NONE;
                continue;
            }
            let total = u32::from(width) + u32::from(second as u8 & 15);
            *slot = u32::from(first >> 4) | (u32::from(second >> 4) << 8) | (total << 16);
            resolved += 1;
        }
        self.resolved = resolved;
    }

    /// The pair a [`PAIR_BITS`] index answers, or [`PAIR_NONE`].
    #[inline(always)]
    pub(crate) fn lookup(&self, index: u32) -> u32 {
        // The mask is what tells the compiler the index is in range: the
        // table's length is a constant, so the bound goes away.
        self.entries[(index as usize) & (PAIR_LEN - 1)]
    }

    /// Whether an entry answers a pair.
    #[inline(always)]
    pub(crate) fn answered(entry: u32) -> bool {
        entry != PAIR_NONE
    }

    /// The first symbol, the second, and the two widths together.
    #[inline(always)]
    pub(crate) fn unpack(entry: u32) -> (u8, u8, u8) {
        (entry as u8, (entry >> 8) as u8, (entry >> 16) as u8)
    }
}
