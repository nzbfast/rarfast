//! Unit vectors for this package: the decoding function of SPEC-D part 3
//! (3.3.1), the ladders of `specs/vectors-H/ladders.tsv`, the window
//! property test of SPEC-H1 5.5, and the hand vectors of SPEC-H1 5.4 built
//! with the test bit writer.

use super::bits::Bits;
use super::prefix::PrefixTable;
use super::tables::*;
use super::window::Window;
use super::*;
use crate::memory::MemoryPolicy;
use crate::rar3_lz::stream::{MemberSpan, Rar3Stream, StreamOut};
use std::ops::Range;
use std::path::PathBuf;

// ---- helpers ---------------------------------------------------------------

/// Bits out, most significant first: the test bit writer of SPEC-H1 5.4.
#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    used: u32,
}

impl BitWriter {
    fn put(&mut self, value: u32, count: u32) {
        for index in (0..count).rev() {
            if self.used.is_multiple_of(8) {
                self.bytes.push(0);
            }
            let bit = ((value >> index) & 1) as u8;
            let at = self.bytes.len() - 1;
            self.bytes[at] |= bit << (7 - self.used % 8);
            self.used += 1;
        }
    }

    fn align(&mut self) {
        while !self.used.is_multiple_of(8) {
            self.put(0, 1);
        }
    }

    fn bit_len(&self) -> u32 {
        self.used
    }
}

/// The canonical code a length list gives each symbol: codes of each
/// length assigned in symbol order, shorter lengths first. It is the
/// inverse of the decoding function for every length list that names a
/// code (`round_trip` checks that against [`PrefixTable`]).
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

/// Equal lengths for `symbols`, the smallest width that fits them.
fn flat(size: usize, symbols: &[u16]) -> Vec<u8> {
    let mut width = 1u8;
    while (1usize << width) < symbols.len() {
        width += 1;
    }
    let mut lengths = vec![0u8; size];
    for &symbol in symbols {
        lengths[usize::from(symbol)] = width;
    }
    lengths
}

/// One block's five alphabets, as code lengths.
#[derive(Clone)]
struct Alphabets {
    main: Vec<u8>,
    distance: Vec<u8>,
    low: Vec<u8>,
    length: Vec<u8>,
}

impl Alphabets {
    /// Tables that name exactly the symbols given, so no unintended arm
    /// can fire (SPEC-H1 5.4).
    fn of(main: &[u16], distance: &[u16], low: &[u16], length: &[u16]) -> Alphabets {
        Alphabets {
            main: flat(MAIN_SYMBOLS, main),
            distance: flat(DISTANCE_SYMBOLS, distance),
            low: flat(LOW_SYMBOLS, low),
            length: flat(LENGTH_SYMBOLS, length),
        }
    }

    fn lengths(&self) -> Vec<u8> {
        let mut all = Vec::with_capacity(TABLE_LENGTHS);
        all.extend_from_slice(&self.main);
        all.extend_from_slice(&self.distance);
        all.extend_from_slice(&self.low);
        all.extend_from_slice(&self.length);
        all
    }
}

/// A block being written: the tables, then symbols under them.
struct BlockWriter {
    codes: Vec<(u32, u8)>,
    distance: Vec<(u32, u8)>,
    low: Vec<(u32, u8)>,
    length: Vec<(u32, u8)>,
}

impl BlockWriter {
    /// Write a block header and its tables. `stored` is what the stream's
    /// stored code lengths hold, which the keep bit carries in.
    fn start(out: &mut BitWriter, tables: &Alphabets, stored: &[u8], keep: bool) -> BlockWriter {
        out.align();
        out.put(0, 1); // an LZ block
        out.put(u32::from(keep), 1);
        // A level alphabet of twenty five-bit codes, so a level symbol is
        // its own five-bit value.
        for _ in 0..LEVEL_SYMBOLS {
            out.put(5, 4);
        }
        let wanted = tables.lengths();
        for (at, &length) in wanted.iter().enumerate() {
            let held = if keep { stored[at] } else { 0 };
            out.put(u32::from((16 + length - held) % 16), 5);
        }
        BlockWriter {
            codes: canonical(&tables.main),
            distance: canonical(&tables.distance),
            low: canonical(&tables.low),
            length: canonical(&tables.length),
        }
    }

    fn main(&self, out: &mut BitWriter, symbol: u16) {
        let (code, width) = self.codes[usize::from(symbol)];
        assert!(width > 0, "main symbol {symbol} has no code");
        out.put(code, u32::from(width));
    }

    fn slot(&self, out: &mut BitWriter, table: &[(u32, u8)], symbol: u16) {
        let (code, width) = table[usize::from(symbol)];
        assert!(width > 0, "symbol {symbol} has no code");
        out.put(code, u32::from(width));
    }

    /// A fresh match: its main symbol, extra length bits, distance slot and
    /// extra distance bits (SPEC-H1 3.4, 3.5).
    fn fresh(&self, out: &mut BitWriter, slot: usize, extra: u32, distance: u32) {
        self.main(out, FIRST_FRESH + slot as u16);
        if LENGTH_EXTRA[slot] > 0 {
            out.put(extra, u32::from(LENGTH_EXTRA[slot]));
        }
        self.distance_bits(out, distance);
    }

    /// The distance slot and bits that name `distance`, low part included.
    fn distance_bits(&self, out: &mut BitWriter, distance: u32) {
        let value = distance - 1;
        let slot = (0..DISTANCE_SYMBOLS)
            .rev()
            .find(|&slot| DISTANCE_BASE[slot] <= value)
            .expect("a distance slot");
        self.slot(out, &self.distance, slot as u16);
        let extra = DISTANCE_EXTRA[slot];
        let rest = value - DISTANCE_BASE[slot];
        if extra == 0 {
            return;
        }
        if slot <= 9 {
            out.put(rest, u32::from(extra));
            return;
        }
        if extra > 4 {
            out.put(rest >> 4, u32::from(extra) - 4);
        }
        self.slot(out, &self.low, (rest & 15) as u16);
    }

    /// The end of block field of SPEC-H1 3.7.
    fn end(&self, out: &mut BitWriter, how: BlockEnd) {
        self.main(out, END_OF_BLOCK);
        match how {
            BlockEnd::SameMemberNewTables => out.put(1, 1),
            BlockEnd::NewMemberNewTables => {
                out.put(0, 1);
                out.put(1, 1);
            }
            BlockEnd::NewMemberKeepTables => {
                out.put(0, 1);
                out.put(0, 1);
            }
        }
    }
}

/// A sink that keeps every byte.
#[derive(Default)]
struct Kept(Vec<u8>);

impl StreamOut for Kept {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.0.extend_from_slice(bytes);
        Ok(())
    }
}

fn policy() -> MemoryPolicy {
    MemoryPolicy {
        max_window: 1 << 22,
        max_dictionary: 1 << 22,
        max_workers: 1,
        ..MemoryPolicy::from_limit(1 << 30)
    }
}

/// Decode a stream whose members are `(packed span, declared size)`.
fn decode_spans(
    packed: &[u8],
    dictionary: u32,
    members: &[(Range<usize>, u64)],
) -> Result<Vec<Vec<u8>>> {
    decode_spans_forced(packed, dictionary, members, None)
}

/// The same, with the literal burst's PAIR forced on or off whatever the
/// block's own alphabet says (see `Rar3Lz::force_pair`).
///
/// `None` is what every other caller here gets: the block decides, which
/// is what ships. `Some` is for the invariance vectors below, which
/// decode ONE stream both ways and compare the two results.
fn decode_spans_forced(
    packed: &[u8],
    dictionary: u32,
    members: &[(Range<usize>, u64)],
    forced: Option<bool>,
) -> Result<Vec<Vec<u8>>> {
    decode_spans_guessed(packed, dictionary, members, forced, None)
}

/// The same again, with the pair loop's GUESSED width forced as well
/// (see `Rar3Lz::force_guess`): `None` lets the main table decide, which
/// is what ships; `Some(0)` declines the guess; `Some(w)` guesses `w`
/// whether or not the alphabet's literals have that width.
fn decode_spans_guessed(
    packed: &[u8],
    dictionary: u32,
    members: &[(Range<usize>, u64)],
    forced: Option<bool>,
    guess: Option<u8>,
) -> Result<Vec<Vec<u8>>> {
    let mut stream = Rar3Stream::new(dictionary, &policy())?;
    stream.force_pair(forced);
    stream.force_guess(guess);
    let mut input = Bits::new(packed);
    let mut out = Vec::new();
    for (span, unpacked) in members {
        let mut kept = Kept::default();
        stream.member(
            &mut input,
            &MemberSpan {
                packed: span.clone(),
                unpacked: *unpacked,
            },
            &mut kept,
        )?;
        out.push(kept.0);
    }
    Ok(out)
}

/// One member that owns the whole of `packed`.
fn decode_one(packed: &[u8], dictionary: u32, unpacked: u64) -> Result<Vec<u8>> {
    decode_one_forced(packed, dictionary, unpacked, None)
}

/// One member, with the literal burst's pair forced (see
/// [`decode_spans_forced`]).
fn decode_one_forced(
    packed: &[u8],
    dictionary: u32,
    unpacked: u64,
    forced: Option<bool>,
) -> Result<Vec<u8>> {
    Ok(
        decode_spans_forced(packed, dictionary, &[(0..packed.len(), unpacked)], forced)?
            .pop()
            .unwrap(),
    )
}

/// The three ways a stream is decoded by the vectors that care which
/// literal loop ran: as it ships, pairing forced ON, pairing forced OFF.
const BOTH_LOOPS: [Option<bool>; 3] = [None, Some(true), Some(false)];

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../specs/vectors-H")
}

// ---- SPEC-D part 3: the decoding function ----------------------------------

/// `D` of SPEC-D 3.2.1 read off the page, as a second witness to
/// [`PrefixTable`]: the ranked symbols with their lengths, and for each
/// lookahead a walk along their runs from value zero.
struct SpecD {
    /// (symbol, length) in rank order.
    ranked: Vec<(u16, u8)>,
    /// `n`, the alphabet's size.
    alphabet: usize,
}

impl SpecD {
    fn new(lengths: &[u8]) -> SpecD {
        let mut ranked: Vec<(u16, u8)> = lengths
            .iter()
            .enumerate()
            .filter(|&(_, &length)| length != 0)
            .map(|(symbol, &length)| (symbol as u16, length))
            .collect();
        ranked.sort_by_key(|&(symbol, length)| (length, symbol));
        SpecD {
            ranked,
            alphabet: lengths.len(),
        }
    }

    fn answer(&self, lookahead: u32) -> (u16, u8) {
        let v = lookahead / 2;
        // R1: the runs lie end to end from zero.
        let mut owned = 0u32;
        for &(symbol, length) in &self.ranked {
            owned += 1 << (15 - length);
            if v < owned {
                return (symbol, length);
            }
        }
        // R2: `owned` is now `T`.
        let k = self.ranked.len() + (v - owned) as usize;
        match self.ranked.first() {
            Some(&(first, _)) if k >= self.alphabet => (first, 15),
            _ => (0, 15),
        }
    }
}

/// Both decoders agree on every one of the 65,536 lookaheads.
fn agrees_everywhere(lengths: &[u8]) {
    let table = table_of(lengths);
    let reference = SpecD::new(lengths);
    for lookahead in 0..=0xffffu32 {
        assert_eq!(
            answer(&table, lookahead),
            reference.answer(lookahead),
            "lengths {lengths:?} lookahead {lookahead:#06x}"
        );
    }
}

fn table_of(lengths: &[u8]) -> PrefixTable {
    let mut table = PrefixTable::new(lengths.len());
    table.build(lengths);
    table
}

/// The answer the table gives for one lookahead, by whichever path.
fn answer(table: &PrefixTable, lookahead: u32) -> (u16, u8) {
    let entry = table.lookup(lookahead);
    if entry != crate::rar3_lz::prefix::WIDE {
        (entry >> 4, entry as u8 & 15)
    } else {
        table.by_runs(lookahead)
    }
}

/// One row of SPEC-D 3.3.1: a lookahead range and the answer it gives.
type Row = (u32, u32, u16, u8);
/// One of its lists, with the rows it names.
type ListCase = (&'static [u8], &'static [Row]);
/// A tail vector: a list, one byte of input, and what it answers.
type TailCase = (&'static [u8], u8, Option<(u16, u8)>);

#[test]
fn spec_d_small_lists() {
    // SPEC-D 3.3.1 A to P: (lengths, [(from, to, symbol, width)]).
    let cases: &[ListCase] = &[
        (
            &[2, 3, 1, 3],
            &[
                (0x0000, 0x7fff, 2, 1),
                (0x8000, 0xbfff, 0, 2),
                (0xc000, 0xdfff, 1, 3),
                (0xe000, 0xffff, 3, 3),
            ],
        ),
        (
            &[0, 0, 1],
            &[
                (0x0000, 0x7fff, 2, 1),
                (0x8000, 0x8003, 0, 15),
                (0x8004, 0xffff, 2, 15),
            ],
        ),
        (
            &[1, 0, 2, 15, 0],
            &[
                (0x0000, 0x7fff, 0, 1),
                (0x8000, 0xbfff, 2, 2),
                (0xc000, 0xc001, 3, 15),
                (0xc002, 0xffff, 0, 15),
            ],
        ),
        (
            &[2, 2, 2, 2, 2],
            &[
                (0x0000, 0x3fff, 0, 2),
                (0x4000, 0x7fff, 1, 2),
                (0x8000, 0xbfff, 2, 2),
                (0xc000, 0xffff, 3, 2),
            ],
        ),
        (
            &[1, 2, 2, 2, 0, 3],
            &[
                (0x0000, 0x7fff, 0, 1),
                (0x8000, 0xbfff, 1, 2),
                (0xc000, 0xffff, 2, 2),
            ],
        ),
        (&[0, 0, 0, 0, 0], &[(0x0000, 0xffff, 0, 15)]),
        (
            &[4, 0, 4, 4],
            &[
                (0x0000, 0x0fff, 0, 4),
                (0x1000, 0x1fff, 2, 4),
                (0x2000, 0x2fff, 3, 4),
                (0x3000, 0xffff, 0, 15),
            ],
        ),
        (
            &[0, 15],
            &[
                (0x0000, 0x0001, 1, 15),
                (0x0002, 0x0003, 0, 15),
                (0x0004, 0xffff, 1, 15),
            ],
        ),
        (
            &[0, 2, 2, 3, 0, 0, 0, 0],
            &[
                (0x0000, 0x3fff, 1, 2),
                (0x4000, 0x7fff, 2, 2),
                (0x8000, 0x9fff, 3, 3),
                (0xa000, 0xa009, 0, 15),
                (0xa00a, 0xffff, 1, 15),
            ],
        ),
        (
            &[0, 1, 0, 0],
            &[
                (0x0000, 0x7fff, 1, 1),
                (0x8000, 0x8005, 0, 15),
                (0x8006, 0xffff, 1, 15),
            ],
        ),
        (&[0; 20], &[(0x0000, 0xffff, 0, 15)]),
    ];
    for (lengths, rows) in cases {
        let table = table_of(lengths);
        for &(from, to, symbol, width) in *rows {
            for lookahead in [from, to, (from + to) / 2] {
                assert_eq!(
                    answer(&table, lookahead),
                    (symbol, width),
                    "lengths {lengths:?} lookahead {lookahead:#06x}"
                );
                assert_eq!(answer(&table, lookahead | 1), (symbol, width));
            }
        }
        // Every lookahead agrees with the specification's own function.
        agrees_everywhere(lengths);
    }
}

#[test]
fn spec_d_list_l_and_m() {
    for lengths in [
        vec![1u8, 1, 1],
        vec![1, 1, 3, 3, 4, 5, 6, 6, 7, 8, 9, 11, 12, 12, 14, 14, 14],
    ] {
        let table = table_of(&lengths);
        for lookahead in 0..=0xffffu32 {
            assert_eq!(answer(&table, lookahead), ((lookahead >> 15) as u16, 1));
        }
    }
}

#[test]
fn spec_d_junk_length_does_not_change_a_complete_list() {
    let complete = table_of(&[2, 2, 3, 3, 3, 3]);
    let with_junk = table_of(&[2, 2, 3, 3, 3, 3, 15]);
    for lookahead in 0..=0xffffu32 {
        assert_eq!(answer(&complete, lookahead), answer(&with_junk, lookahead));
    }
}

#[test]
fn spec_d_tail_vectors() {
    // A byte of input, a code that fits and one that does not (3.2.4).
    let cases: &[TailCase] = &[
        (&[2, 3, 1, 3], 0xc0, Some((1, 3))),
        (&[0, 0, 1], 0x80, None),
        (&[1, 1, 1], 0x80, Some((1, 1))),
        (&[0, 0, 0, 0, 0], 0xff, None),
    ];
    for &(lengths, byte, want) in cases {
        let table = table_of(lengths);
        let data = [byte];
        let mut input = Bits::new(&data);
        match want {
            Some((symbol, width)) => {
                assert_eq!(table.decode(&mut input).unwrap(), symbol);
                assert_eq!(input.position(), u64::from(width));
            }
            None => {
                assert!(matches!(
                    table.decode(&mut input).unwrap_err().kind(),
                    ErrorKind::Truncated
                ));
                assert_eq!(input.position(), 0, "nothing is consumed");
            }
        }
    }
}

/// SPEC-D 3.3.2 corpus items 2, 3 and 5, against the specification's own
/// function: every short list over the lengths that matter, seeded random
/// lists at every real alphabet size, and every single-code list. It is
/// 65,536 lookaheads per list, so a debug run takes the smaller half and
/// a release run takes it whole (SPEC-D 3.3.2's own advice).
#[test]
fn spec_d_over_the_real_alphabets() {
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let small = cfg!(debug_assertions);
    let mut lists: Vec<Vec<u8>> = Vec::new();
    for a in [0u8, 1, 2, 3, 15] {
        for b in [0u8, 1, 2, 3, 15] {
            for c in [0u8, 1, 2, 3, 15] {
                lists.push(vec![a, b, c]);
                lists.push(vec![a, b, c, 0]);
            }
        }
    }
    for size in [LOW_SYMBOLS, LEVEL_SYMBOLS, LENGTH_SYMBOLS, DISTANCE_SYMBOLS] {
        for _ in 0..if small { 4 } else { 50 } {
            lists.push((0..size).map(|_| (next() % 16) as u8).collect());
        }
    }
    for size in [LOW_SYMBOLS, LENGTH_SYMBOLS] {
        for symbol in 0..size {
            for width in 1..=15u8 {
                if small && (symbol + usize::from(width)) % 4 != 0 {
                    continue;
                }
                let mut lengths = vec![0u8; size];
                lengths[symbol] = width;
                lists.push(lengths);
            }
        }
    }
    for _ in 0..if small { 2 } else { 8 } {
        lists.push((0..MAIN_SYMBOLS).map(|_| (next() % 16) as u8).collect());
    }
    for lengths in lists {
        agrees_everywhere(&lengths);
    }
}

#[test]
fn canonical_codes_round_trip_through_the_table() {
    for size in [LOW_SYMBOLS, LEVEL_SYMBOLS, LENGTH_SYMBOLS, DISTANCE_SYMBOLS] {
        for used in [2usize, 3, 4, 8, 16] {
            let symbols: Vec<u16> = (0..used.min(size) as u16).collect();
            let lengths = flat(size, &symbols);
            let codes = canonical(&lengths);
            let table = table_of(&lengths);
            for &symbol in &symbols {
                let (code, width) = codes[usize::from(symbol)];
                let mut writer = BitWriter::default();
                writer.put(code, u32::from(width));
                writer.put(0, 32);
                let mut input = Bits::new(&writer.bytes);
                assert_eq!(table.decode(&mut input).unwrap(), symbol);
                assert_eq!(input.position(), u64::from(width));
            }
        }
    }
}

/// SPEC-D 3.2.1 says R2 was probed on the main, distance and level
/// alphabets and is "not established" for the low distance and length
/// alphabets apart. This pins what the decoder does there today, which is
/// R2 as written: width 15, symbol 0 while `k < n`, the first ranked
/// symbol from `k = n` on. Single threaded; a few kilobytes.
#[test]
fn an_unowned_lookahead_on_the_low_and_length_alphabets_follows_r2_as_today() {
    for size in [LOW_SYMBOLS, LENGTH_SYMBOLS] {
        // One ranked symbol, 3, of length 2: `T` is 8,192 and `m` is 1.
        let mut lengths = vec![0u8; size];
        lengths[3] = 2;
        let table = table_of(&lengths);
        let v_at = |k: usize| 8_192 + (k as u32 - 1);
        for (k, want) in [(1, 0u16), (size - 1, 0), (size, 3), (size + 40, 3)] {
            for low_bit in [0, 1] {
                assert_eq!(
                    answer(&table, 2 * v_at(k) + low_bit),
                    (want, 15),
                    "{size} symbols, k = {k}"
                );
            }
        }
        assert_eq!(answer(&table, 2 * 8_191), (3, 2), "{size} symbols, owned");
    }
}

/// SPEC-D 3.2.1: a decoder accepts a length of 15, though no genuine
/// table with one was observed. This pins it: two symbols of length 15
/// own one value each after the short one, in symbol order, and R2
/// begins straight after them. Single threaded; a few kilobytes.
#[test]
fn a_length_of_fifteen_is_accepted_and_owns_one_value() {
    let table = table_of(&[0, 15, 1, 15]);
    for (v, want) in [
        (0u32, (2u16, 1u8)),
        (16_383, (2, 1)),
        (16_384, (1, 15)),
        (16_385, (3, 15)),
        // `T` is 16,386 and `m` is 3: `k = 3` is under `n = 4`.
        (16_386, (0, 15)),
        (16_387, (2, 15)),
        (32_767, (2, 15)),
    ] {
        assert_eq!(answer(&table, 2 * v), want, "v = {v}");
        assert_eq!(answer(&table, 2 * v + 1), want, "v = {v}, low bit set");
    }
    // The same through the reader, which is the path a stream takes.
    let mut writer = BitWriter::default();
    writer.put(0b100_0000_0000_0001, 15);
    writer.put(0, 32);
    let mut input = Bits::new(&writer.bytes);
    assert_eq!(table.decode(&mut input).unwrap(), 3);
    assert_eq!(input.position(), 15);
}

// ---- the ladders -----------------------------------------------------------

#[cfg(feature = "repo-tests")]
#[test]
fn ladders_match_the_committed_table() {
    let path = vectors_dir().join("ladders.tsv");
    let text = std::fs::read_to_string(&path).expect("ladders.tsv");
    let mut rows = 0usize;
    for line in text.lines().skip(1) {
        let cell: Vec<&str> = line.split('\t').collect();
        if cell.len() < 7 || cell[0] != "rar3" {
            continue;
        }
        let slot: usize = cell[2].parse().unwrap();
        let extra: u8 = cell[3].parse().unwrap();
        let base: u32 = cell[4].parse().unwrap();
        let first: u32 = cell[5].parse().unwrap();
        let last: u32 = cell[6].parse().unwrap();
        let (mine, wide) = match cell[1] {
            // The fresh arm's base; the repeated arm is one less (3.4).
            "length" => (
                u32::from(LENGTH_BASE[slot]) + FRESH_LENGTH_BONUS,
                LENGTH_EXTRA[slot],
            ),
            "repeat_length" => (
                u32::from(LENGTH_BASE[slot]) + REPEAT_LENGTH_BONUS,
                LENGTH_EXTRA[slot],
            ),
            "distance" => (DISTANCE_BASE[slot] + 1, DISTANCE_EXTRA[slot]),
            "short_distance" => (SHORT_BASE[slot] + 1, SHORT_EXTRA[slot]),
            _ => continue,
        };
        assert_eq!(mine, base, "{} slot {slot} base", cell[1]);
        assert_eq!(wide, extra, "{} slot {slot} extra bits", cell[1]);
        assert_eq!(mine, first, "{} slot {slot} first value", cell[1]);
        assert_eq!(
            mine + (1u32 << extra) - 1,
            last,
            "{} slot {slot} last value",
            cell[1]
        );
        rows += 1;
    }
    assert_eq!(rows, 124, "every RAR 3 row of ladders.tsv");
}

#[test]
fn the_ladders_tile_their_ranges() {
    // Short distances tile 1 to 256 exactly (3.5).
    let mut at = 1u32;
    for slot in 0..8 {
        assert_eq!(SHORT_BASE[slot] + 1, at);
        at += 1 << SHORT_EXTRA[slot];
    }
    assert_eq!(at, 257);
    // The distance ladder reaches exactly the 4 MiB dictionary ceiling.
    let top =
        DISTANCE_BASE[DISTANCE_SYMBOLS - 1] + 1 + (1u32 << DISTANCE_EXTRA[DISTANCE_SYMBOLS - 1])
            - 1;
    assert_eq!(top, MAX_DISTANCE);
    // The two wide bands tile their ranges.
    for slot in 36..47 {
        assert_eq!(DISTANCE_BASE[slot] + (1 << 16), DISTANCE_BASE[slot + 1]);
    }
    for slot in 48..59 {
        assert_eq!(DISTANCE_BASE[slot] + (1 << 18), DISTANCE_BASE[slot + 1]);
    }
    // A fresh match is 3 to 258 before the bonuses, a repeated one 2 to 257.
    let longest =
        u32::from(LENGTH_BASE[LENGTH_SYMBOLS - 1]) + (1 << LENGTH_EXTRA[LENGTH_SYMBOLS - 1]) - 1;
    assert_eq!(longest + FRESH_LENGTH_BONUS, 258);
    assert_eq!(longest + REPEAT_LENGTH_BONUS, 257);
    assert_eq!(258 + 2, MAX_MATCH);
}

// ---- the window ------------------------------------------------------------

#[test]
fn window_copy_equals_the_byte_at_a_time_result() {
    // Every distance in 1 to 4096 against every length in 1 to 300, over a
    // window seeded with a fixed pseudo random run, compared with the byte
    // at a time result (SPEC-H1 5.5). This is the test that catches a
    // strided copy that is right for distance 16 and wrong for distance 3.
    // A debug run walks every distance and a quarter of the lengths; a
    // release run walks the whole grid.
    let mut seed = 0x0123_4567u32;
    let mut random = move || {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (seed >> 24) as u8
    };
    let mut window = Window::new(1 << 16);
    // The same bytes, as a model that keeps only what a distance can reach.
    let mut model: std::collections::VecDeque<u8> = std::collections::VecDeque::new();
    for _ in 0..8192 {
        let byte = random();
        window.put(byte).unwrap();
        model.push_back(byte);
    }
    let step = if cfg!(debug_assertions) { 4 } else { 1 };
    let mut got = vec![0u8; 300];
    for distance in 1..=4096usize {
        for length in (1..=300usize).step_by(step) {
            let at = window.produced();
            window.copy(distance as u32, length as u32).unwrap();
            let want: Vec<u8> = {
                let mut want = Vec::with_capacity(length);
                for index in 0..length {
                    let byte = match index.checked_sub(distance) {
                        Some(back) => want[back],
                        None => model[model.len() - distance + index],
                    };
                    want.push(byte);
                }
                want
            };
            let out = &mut got[..length];
            window.copy_out(at, out).unwrap();
            assert_eq!(out, &want[..], "distance {distance} length {length}");
            for &byte in &want {
                model.push_back(byte);
            }
            while model.len() > 8192 {
                model.pop_front();
            }
        }
    }
}

#[test]
fn window_fixed_rungs_copy_every_length_exactly() {
    // The inline shape of `Window::copy` (source whole behind the write
    // point, no overlap, at most 64 bytes) at EVERY length from 1 to 64,
    // each rung's two edges included, in a debug run as well: the grid
    // above steps its lengths by four there and never lands on 4, 8, 16,
    // 32 or 64. Each copy is compared with the bytes the distance names
    // and the history before it must be untouched; a rung that wrote wide
    // of `[to, to + len)` on the far side is `window_guard`'s to catch,
    // which watches every copy of a debug run.
    let mut seed = 0x89ab_cdefu32;
    let mut random = move || {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (seed >> 24) as u8
    };
    for length in 1..=64usize {
        for distance in [length, length + 1, length + 7, 64, 65, 200, 255] {
            if distance < length {
                continue;
            }
            let mut window = Window::new(1 << 12);
            let mut history = Vec::with_capacity(256);
            for _ in 0..256 {
                let byte = random();
                window.put(byte).unwrap();
                history.push(byte);
            }
            window.copy(distance as u32, length as u32).unwrap();
            let want = &history[256 - distance..256 - distance + length];
            let mut got = vec![0u8; length];
            window.copy_out(256, &mut got).unwrap();
            assert_eq!(got, want, "distance {distance} length {length}");
            let mut before = [0u8; 256];
            window.copy_out(0, &mut before).unwrap();
            assert_eq!(&before[..], &history[..], "history, length {length}");
            assert_eq!(window.produced(), 256 + length as u64);
        }
    }
}

#[test]
fn window_copy_wraps_and_refuses_what_it_cannot_reach() {
    let mut window = Window::new(1 << 16);
    assert!(window.copy(1, 1).is_err(), "nothing produced yet");
    for byte in 0..=255u8 {
        window.put(byte).unwrap();
    }
    assert!(matches!(
        window.copy(257, 1).unwrap_err().kind(),
        ErrorKind::Corrupt(Corruption::Rar3(Rar3Fault::DistanceOutOfRange))
    ));
    // Past the wrap, the same run comes back.
    for _ in 0..70_000 {
        window.copy(256, 1).unwrap();
    }
    let mut got = [0u8; 256];
    window.copy_out(window.produced() - 256, &mut got).unwrap();
    for (at, &byte) in got.iter().enumerate() {
        assert_eq!(byte, ((window.produced() - 256 + at as u64) % 256) as u8);
    }
    assert!(
        window.slices(0, 16).is_none(),
        "history that has fallen out"
    );
}

// ---- SPEC-H1 5.4: the hand vectors -----------------------------------------

/// The main alphabet a hand vector uses: the literals it needs, the end of
/// block symbol, and whichever match symbols the vector fires.
fn main_alphabet(literals: &[u8], extra: &[u16]) -> Vec<u16> {
    let mut symbols: Vec<u16> = literals.iter().map(|&b| u16::from(b)).collect();
    symbols.push(END_OF_BLOCK);
    symbols.extend_from_slice(extra);
    symbols.sort_unstable();
    symbols.dedup();
    symbols
}

/// Tables naming exactly those symbols, with every low distance symbol and
/// every length slot a vector might use.
fn tables_for(main: &[u16], distances: &[u16], lengths: &[u16]) -> Alphabets {
    let low: Vec<u16> = (0..LOW_SYMBOLS as u16).collect();
    Alphabets::of(main, distances, &low, lengths)
}

/// The same, but the MAIN alphabet's codes have widths that VARY, four to
/// twelve bits, instead of one width for every symbol.
///
/// `flat` is what every other vector here uses. A vector that means to
/// exercise the PAIR loop over a realistic alphabet has to name one
/// whose widths span, and four to twelve is the range the 21 Sep
/// ladder's text shape used.
///
/// The widths are assigned by position, so the list is prefix free by
/// Kraft with a wide margin; the assertion below states it rather than
/// trusting the arithmetic.
fn tables_for_varied(main: &[u16], distances: &[u16], lengths: &[u16]) -> Alphabets {
    let mut lengths_main = vec![0u8; MAIN_SYMBOLS];
    for (at, &symbol) in main.iter().enumerate() {
        lengths_main[usize::from(symbol)] = 4 + (at % 9) as u8;
    }
    let kraft: f64 = lengths_main
        .iter()
        .filter(|&&width| width > 0)
        .map(|&width| 0.5f64.powi(i32::from(width)))
        .sum();
    assert!(kraft <= 1.0, "the varied main alphabet is prefix free");
    let low: Vec<u16> = (0..LOW_SYMBOLS as u16).collect();
    let mut tables = Alphabets::of(main, distances, &low, lengths);
    tables.main = lengths_main;
    tables
}

/// The distance slots a list of distances needs.
fn slots_for(distances: &[u32]) -> Vec<u16> {
    let mut slots: Vec<u16> = distances
        .iter()
        .map(|&distance| {
            (0..DISTANCE_SYMBOLS)
                .rev()
                .find(|&slot| DISTANCE_BASE[slot] < distance)
                .expect("a distance slot") as u16
        })
        .collect();
    slots.sort_unstable();
    slots.dedup();
    slots
}

/// End a member's packed span, as a writer does: the bits left in the
/// last byte are padding, and the next member's span starts at the next
/// byte (SPEC-H1 3.8).
fn span_end(out: &mut BitWriter) -> usize {
    out.align();
    out.bit_len() as usize / 8
}

#[test]
fn a_match_past_a_members_end_enters_the_window_whole_and_opens_no_member() {
    // SPEC-H1 3.8, B3: member 1 declares 4 bytes and its match names 11.
    // The match enters the window whole; the 8 bytes past the member's end
    // are no member's output and member 2 opens with its own symbol.
    let mut out = BitWriter::default();
    let main = main_alphabet(b"A", &[FIRST_FRESH + 7]);
    let tables = tables_for(&main, &slots_for(&[1]), &[]);
    let block = BlockWriter::start(&mut out, &tables, &[0; TABLE_LENGTHS], false);
    block.main(&mut out, u16::from(b'A'));
    // Length slot 7 is base 7 plus the fresh arm's 3: eleven bytes.
    block.fresh(&mut out, 7, 0, 1);
    // A writer ends the block where the member's packed data ends and
    // says the next member resumes inside it (SPEC-H1 3.7, 3.8).
    block.end(&mut out, BlockEnd::NewMemberKeepTables);
    let first = span_end(&mut out);
    block.main(&mut out, u16::from(b'A'));
    block.end(&mut out, BlockEnd::NewMemberNewTables);
    out.align();
    let members = decode_spans(
        &out.bytes,
        1 << 16,
        &[(0..first, 4), (first..out.bytes.len(), 1)],
    )
    .unwrap();
    assert_eq!(members[0], b"AAAA", "the member stops at its declared size");
    assert_eq!(members[1], b"A", "the next member's own literal alone");
    // Declared as 8 bytes, member 2 has one byte and then its data ends
    // at an end of block: it comes out short (3.7, E4), and the bytes the
    // match left past member 1's end are not among its output.
    let short = decode_spans(
        &out.bytes,
        1 << 16,
        &[(0..first, 4), (first..out.bytes.len(), 8)],
    )
    .unwrap();
    assert_eq!(short[1], b"A");
}

#[test]
fn v_rep0_an_uninitialised_repeated_distance_is_refused() {
    // SPEC-H1 question 3: the repeat table still holds its initial zero.
    let mut out = BitWriter::default();
    let main = main_alphabet(b"A", &[FIRST_REPEATED]);
    let tables = tables_for(&main, &[0], &[0]);
    let block = BlockWriter::start(&mut out, &tables, &[0; TABLE_LENGTHS], false);
    block.main(&mut out, FIRST_REPEATED);
    block.slot(&mut out, &block.length, 0);
    out.align();
    let error = decode_one(&out.bytes, 1 << 16, 8).unwrap_err();
    assert!(
        matches!(
            error.kind(),
            ErrorKind::Corrupt(Corruption::Rar3(Rar3Fault::UninitialisedRepeat))
        ),
        "{error}"
    );
}

#[test]
fn v_win3_a_distance_past_the_declared_dictionary_is_refused() {
    // SPEC-H1 question 2: 70,000 bytes produced, a 64 KiB dictionary, and a
    // match at distance 70,000, which the stream has produced but the
    // dictionary no longer holds.
    let far = 70_000u32;
    let mut out = BitWriter::default();
    let main = main_alphabet(b"A", &[FIRST_FRESH + 27]);
    let tables = tables_for(&main, &slots_for(&[1, far]), &[]);
    let block = BlockWriter::start(&mut out, &tables, &[0; TABLE_LENGTHS], false);
    block.main(&mut out, u16::from(b'A'));
    // Length slot 27 with all its extra bits is 224 + 31 + 3 = 258, plus
    // one for a distance of at least 0x2000; runs of 259 reach 70,000.
    let mut produced = 1u64;
    while produced + 259 < u64::from(far) {
        block.fresh(&mut out, 27, 31, 1);
        produced += 258;
    }
    while produced < u64::from(far) {
        block.main(&mut out, u16::from(b'A'));
        produced += 1;
    }
    assert_eq!(produced, u64::from(far));
    block.fresh(&mut out, 27, 31, far);
    block.end(&mut out, BlockEnd::NewMemberNewTables);
    out.align();
    let error = decode_one(&out.bytes, 1 << 16, u64::from(far) + 1).unwrap_err();
    assert!(
        matches!(
            error.kind(),
            ErrorKind::Corrupt(Corruption::Rar3(Rar3Fault::DistanceOutOfRange))
        ),
        "{error}"
    );
    // The same stream with a dictionary that holds those bytes decodes.
    assert!(decode_one(&out.bytes, 1 << 17, u64::from(far) + 1).is_ok());
}

#[test]
fn v_low_a_table_read_clears_the_low_distance_run() {
    // SPEC-H1 question 4: symbol 16 sets a run of fifteen, and a table read
    // clears it even when the keep bit carries the lengths in.
    let far = 0x4321u32;
    let main = main_alphabet(b"AB", &[FIRST_FRESH]);
    let tables = tables_for(&main, &slots_for(&[far, far + 5]), &[]);
    let stored = tables.lengths();
    let mut out = BitWriter::default();
    let block = BlockWriter::start(&mut out, &tables, &[0; TABLE_LENGTHS], false);
    for _ in 0..far {
        block.main(&mut out, u16::from(b'A'));
    }
    // A far match whose low part is the run symbol 16, so the remembered
    // low part (zero) is used and a run of fifteen is set.
    block.main(&mut out, FIRST_FRESH);
    let value = far - 1;
    let slot = usize::from(slots_for(&[far])[0]);
    block.slot(&mut out, &block.distance, slot as u16);
    out.put(
        (value - DISTANCE_BASE[slot]) >> 4,
        u32::from(DISTANCE_EXTRA[slot]) - 4,
    );
    block.slot(&mut out, &block.low, LOW_REPEAT);
    block.end(&mut out, BlockEnd::SameMemberNewTables);
    // The same tables again, carried in by the keep bit.
    let block = BlockWriter::start(&mut out, &tables, &stored, true);
    // A second far match, whose low part is 5. It is read as a symbol only
    // because the table read cleared the run; a decoder that kept the run
    // would take the remembered zero and leave those bits in the stream.
    let near = DISTANCE_BASE[slot] + 5 + 1;
    block.fresh(&mut out, 0, 0, near);
    block.main(&mut out, u16::from(b'B'));
    block.end(&mut out, BlockEnd::NewMemberNewTables);
    out.align();
    // Each fresh match is length slot 0 (three bytes) plus one for a
    // distance of at least 0x2000.
    let produced = u64::from(far) + 4 + 4 + 1;
    let bytes = decode_one(&out.bytes, 1 << 17, produced).unwrap();
    assert_eq!(bytes.len() as u64, produced);
    assert_eq!(bytes[bytes.len() - 1], b'B', "the stream stayed in step");
    assert!(
        bytes[..bytes.len() - 1].iter().all(|&b| b == b'A'),
        "every other byte came from the run of As"
    );
}

#[test]
fn v_258_repeats_the_last_match_and_touches_nothing() {
    // SPEC-H1 3.4: a 258 before any match produces nothing and is not an
    // error; a later one repeats the last match without rotating the
    // repeated distances.
    let mut out = BitWriter::default();
    let main = main_alphabet(
        b"ABCDEFGH",
        &[REPEAT_LAST_MATCH, FIRST_FRESH + 4, FIRST_REPEATED + 1],
    );
    let tables = tables_for(&main, &slots_for(&[3, 5]), &[0]);
    let block = BlockWriter::start(&mut out, &tables, &[0; TABLE_LENGTHS], false);
    // A 258 as the first symbol of the stream: nothing at all.
    block.main(&mut out, REPEAT_LAST_MATCH);
    for byte in b"ABCDEFGH" {
        block.main(&mut out, u16::from(*byte));
    }
    // A fresh match of length 7 at distance 3, then a 258 that repeats it.
    block.fresh(&mut out, 4, 0, 3);
    block.main(&mut out, REPEAT_LAST_MATCH);
    // A fresh match at distance 5, then a repeated distance match with
    // k = 1, which names 3 only because the 258 pushed nothing.
    block.fresh(&mut out, 4, 0, 5);
    block.main(&mut out, FIRST_REPEATED + 1);
    block.slot(&mut out, &block.length, 0);
    block.end(&mut out, BlockEnd::NewMemberNewTables);
    out.align();
    let bytes = decode_one(&out.bytes, 1 << 16, 8 + 7 + 7 + 7 + 2).unwrap();
    let mut want = b"ABCDEFGH".to_vec();
    for distance in [3, 3, 5] {
        for _ in 0..7 {
            want.push(want[want.len() - distance]);
        }
    }
    for _ in 0..2 {
        want.push(want[want.len() - 3]);
    }
    assert_eq!(bytes, want);
}

#[test]
fn v_rot_a_repeated_distance_moves_to_the_front() {
    // SPEC-H1 3.5: with k = 2 and [a, b, c, d] the result is [c, a, b, d].
    let mut out = BitWriter::default();
    let main = main_alphabet(
        b"ABCDEFGHIJKLMNOP",
        &[FIRST_FRESH, FIRST_REPEATED + 2, FIRST_REPEATED + 1],
    );
    let tables = tables_for(&main, &slots_for(&[4, 5, 6, 7]), &[0]);
    let block = BlockWriter::start(&mut out, &tables, &[0; TABLE_LENGTHS], false);
    for byte in b"ABCDEFGHIJKLMNOP" {
        block.main(&mut out, u16::from(*byte));
    }
    // Four fresh matches leave the repeated distances as [4, 5, 6, 7].
    for distance in [7u32, 6, 5, 4] {
        block.fresh(&mut out, 0, 0, distance);
    }
    // k = 2 names 6 and reorders to [6, 4, 5, 7]; k = 1 then names 4.
    block.main(&mut out, FIRST_REPEATED + 2);
    block.slot(&mut out, &block.length, 0);
    block.main(&mut out, FIRST_REPEATED + 1);
    block.slot(&mut out, &block.length, 0);
    block.end(&mut out, BlockEnd::NewMemberNewTables);
    out.align();
    let bytes = decode_one(&out.bytes, 1 << 16, 16 + 4 * 3 + 2 + 2).unwrap();
    let mut want = b"ABCDEFGHIJKLMNOP".to_vec();
    for distance in [7usize, 6, 5, 4] {
        for _ in 0..3 {
            want.push(want[want.len() - distance]);
        }
    }
    for distance in [6usize, 4] {
        for _ in 0..2 {
            want.push(want[want.len() - distance]);
        }
    }
    assert_eq!(bytes, want);
}

#[test]
fn v_keep_a_code_length_is_a_delta_on_the_stored_one() {
    // SPEC-H1 3.3: the new length is `(stored + symbol) mod 16`, wrap
    // included. Block 1 gives main symbol 0 a length of 15; block 2 keeps
    // the lengths and writes delta 1 there, which wraps it to zero, so
    // symbol 0 leaves the table and every other code shifts.
    let mut first = Alphabets::of(&[0, u16::from(b'A'), END_OF_BLOCK], &[0], &[0], &[0]);
    first.main[0] = 15;
    let mut second = first.clone();
    second.main[0] = 0;
    let stored = first.lengths();
    let mut out = BitWriter::default();
    let block = BlockWriter::start(&mut out, &first, &[0; TABLE_LENGTHS], false);
    block.main(&mut out, u16::from(b'A'));
    block.main(&mut out, 0);
    block.end(&mut out, BlockEnd::SameMemberNewTables);
    let block = BlockWriter::start(&mut out, &second, &stored, true);
    block.main(&mut out, u16::from(b'A'));
    block.end(&mut out, BlockEnd::NewMemberNewTables);
    out.align();
    let bytes = decode_one(&out.bytes, 1 << 16, 3).unwrap();
    assert_eq!(bytes, b"A\0A");
}

#[test]
fn v_end_all_three_block_ends() {
    // SPEC-H1 3.7: the member after a `NewMemberNewTables` end starts at a
    // header, the member after a `NewMemberKeepTables` end starts inside
    // the block, and a `SameMemberNewTables` end keeps the same member.
    let main = main_alphabet(b"AB", &[]);
    let tables = tables_for(&main, &[0], &[0]);
    let mut out = BitWriter::default();
    // Member 1: two blocks, the first ending in the same member.
    let block = BlockWriter::start(&mut out, &tables, &[0; TABLE_LENGTHS], false);
    block.main(&mut out, u16::from(b'A'));
    block.end(&mut out, BlockEnd::SameMemberNewTables);
    let block = BlockWriter::start(&mut out, &tables, &tables.lengths(), true);
    block.main(&mut out, u16::from(b'B'));
    block.end(&mut out, BlockEnd::NewMemberNewTables);
    let first = span_end(&mut out);
    // Member 2 starts at a header, and ends inside its block by size.
    let block = BlockWriter::start(&mut out, &tables, &tables.lengths(), true);
    block.main(&mut out, u16::from(b'A'));
    block.main(&mut out, u16::from(b'A'));
    block.end(&mut out, BlockEnd::NewMemberKeepTables);
    let second = span_end(&mut out);
    // Member 3 resumes inside that block: its first bit is data.
    block.main(&mut out, u16::from(b'B'));
    block.end(&mut out, BlockEnd::NewMemberNewTables);
    out.align();
    let members = decode_spans(
        &out.bytes,
        1 << 16,
        &[
            (0..first, 2),
            (first..second, 2),
            (second..out.bytes.len(), 1),
        ],
    )
    .unwrap();
    assert_eq!(members, vec![b"AB".to_vec(), b"AA".to_vec(), b"B".to_vec()]);
}

#[test]
fn v_bonus_the_length_bonus_boundaries() {
    // SPEC-H1 3.5: a fresh match gains one byte at 0x2000 and one more at
    // 0x40000, and a repeated distance match gains neither.
    for (distance, bonus) in [(0x1FFFu32, 0u64), (0x2000, 1), (0x3FFFF, 1), (0x40000, 2)] {
        let mut out = BitWriter::default();
        let main = main_alphabet(b"AB", &[FIRST_FRESH + 27]);
        let tables = tables_for(&main, &slots_for(&[1, distance]), &[]);
        let block = BlockWriter::start(&mut out, &tables, &[0; TABLE_LENGTHS], false);
        // Fill the history with a distance of one, which earns no bonus.
        block.main(&mut out, u16::from(b'A'));
        let mut produced = 1u64;
        while produced + 258 <= u64::from(distance) {
            block.fresh(&mut out, 27, 31, 1);
            produced += 258;
        }
        while produced < u64::from(distance) {
            block.main(&mut out, u16::from(b'A'));
            produced += 1;
        }
        // One fresh match at the boundary: 258 plus the bonus. The literal
        // after it lands one byte further for each bonus byte, so its
        // position is what pins the rule.
        block.fresh(&mut out, 27, 31, distance);
        block.main(&mut out, u16::from(b'B'));
        block.end(&mut out, BlockEnd::NewMemberNewTables);
        out.align();
        let want = produced + 258 + bonus;
        let bytes = decode_one(&out.bytes, 1 << 20, want + 1).unwrap();
        assert_eq!(bytes.len() as u64, want + 1, "distance {distance:#x}");
        assert_eq!(bytes[want as usize], b'B', "distance {distance:#x}");
        assert!(
            bytes[..want as usize].iter().all(|&byte| byte == b'A'),
            "distance {distance:#x}"
        );
    }
}

#[test]
fn v_short_every_short_distance_slot() {
    // SPEC-H1 3.5: eight slots, each at its first and last value, each
    // producing exactly two bytes.
    for slot in 0..8usize {
        for extra in [0u32, (1 << SHORT_EXTRA[slot]) - 1] {
            let distance = SHORT_BASE[slot] + 1 + extra;
            let mut out = BitWriter::default();
            let main = main_alphabet(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", &[FIRST_SHORT + slot as u16]);
            let tables = tables_for(&main, &[0], &[0]);
            let block = BlockWriter::start(&mut out, &tables, &[0; TABLE_LENGTHS], false);
            let history: Vec<u8> = (0..256u32).map(|at| b'A' + (at % 26) as u8).collect();
            for &byte in &history {
                block.main(&mut out, u16::from(byte));
            }
            block.main(&mut out, FIRST_SHORT + slot as u16);
            out.put(extra, u32::from(SHORT_EXTRA[slot]));
            block.end(&mut out, BlockEnd::NewMemberNewTables);
            out.align();
            let bytes = decode_one(&out.bytes, 1 << 16, history.len() as u64 + 2).unwrap();
            let mut want = history.clone();
            for _ in 0..2 {
                want.push(want[want.len() - distance as usize]);
            }
            assert_eq!(bytes, want, "short slot {slot} distance {distance}");
        }
    }
}

#[test]
fn v_trail_the_next_member_s_tables_sit_in_this_member() {
    // SPEC-H1 3.8: the declared size is met, then a 256 with a
    // `SameMemberNewTables` end and a whole table read, and the next
    // member decodes under the NEW tables.
    let first_tables = tables_for(&main_alphabet(b"AB", &[]), &[0], &[0]);
    let second_tables = tables_for(&main_alphabet(b"XY", &[]), &[0], &[0]);
    let mut out = BitWriter::default();
    let block = BlockWriter::start(&mut out, &first_tables, &[0; TABLE_LENGTHS], false);
    block.main(&mut out, u16::from(b'A'));
    block.main(&mut out, u16::from(b'B'));
    block.end(&mut out, BlockEnd::SameMemberNewTables);
    let block = BlockWriter::start(&mut out, &second_tables, &first_tables.lengths(), false);
    // The member's packed data ends after the tables, with the end that
    // says the next member resumes inside this block, under them.
    block.end(&mut out, BlockEnd::NewMemberKeepTables);
    let first = span_end(&mut out);
    block.main(&mut out, u16::from(b'X'));
    block.main(&mut out, u16::from(b'Y'));
    block.end(&mut out, BlockEnd::NewMemberNewTables);
    out.align();
    let members = decode_spans(
        &out.bytes,
        1 << 16,
        &[(0..first, 2), (first..out.bytes.len(), 2)],
    )
    .unwrap();
    assert_eq!(members, vec![b"AB".to_vec(), b"XY".to_vec()]);
}

#[test]
fn a_literal_after_the_declared_size_enters_the_window_and_is_no_output() {
    // SPEC-H1 3.8, B1 and B2: member 1 declares one byte and holds two
    // literals. The second is in the window, where member 2's match at
    // distance 1 finds it, and is in neither member's output.
    let main = main_alphabet(b"ABC", &[FIRST_SHORT]);
    let tables = tables_for(&main, &[0], &[0]);
    let mut out = BitWriter::default();
    let block = BlockWriter::start(&mut out, &tables, &[0; TABLE_LENGTHS], false);
    block.main(&mut out, u16::from(b'A'));
    block.main(&mut out, u16::from(b'B'));
    block.end(&mut out, BlockEnd::NewMemberKeepTables);
    let first = span_end(&mut out);
    // Short distance slot 0 with its field zero: distance 1, two bytes.
    block.main(&mut out, FIRST_SHORT);
    out.put(0, u32::from(SHORT_EXTRA[0]));
    block.main(&mut out, u16::from(b'C'));
    block.end(&mut out, BlockEnd::NewMemberNewTables);
    out.align();
    let members = decode_spans(
        &out.bytes,
        1 << 16,
        &[(0..first, 1), (first..out.bytes.len(), 3)],
    )
    .unwrap();
    assert_eq!(members, vec![b"A".to_vec(), b"BBC".to_vec()]);
}

#[test]
fn v_runpast_a_code_length_run_stops_at_the_end() {
    // SPEC-H1 3.3: a run of 19 at position 400 writes 11 + k zeros and
    // stops at 404, which is not an error, and the tables build.
    let tables = tables_for(&main_alphabet(b"A", &[]), &[0], &[0]);
    let wanted = tables.lengths();
    let mut out = BitWriter::default();
    out.put(0, 1);
    out.put(0, 1);
    for _ in 0..LEVEL_SYMBOLS {
        out.put(5, 4);
    }
    for &length in wanted.iter().take(400) {
        out.put(u32::from(length), 5);
    }
    assert!(
        wanted[400..].iter().all(|&length| length == 0),
        "the last four lengths are zero, so the run says nothing new"
    );
    out.put(19, 5);
    out.put(127, 7); // 11 + 127 = 138 zeros, from position 400
    let block = BlockWriter {
        codes: canonical(&tables.main),
        distance: canonical(&tables.distance),
        low: canonical(&tables.low),
        length: canonical(&tables.length),
    };
    block.main(&mut out, u16::from(b'A'));
    block.end(&mut out, BlockEnd::NewMemberNewTables);
    out.align();
    assert_eq!(decode_one(&out.bytes, 1 << 16, 1).unwrap(), b"A");
}

// ---- SPEC-H1 5.6: memory ---------------------------------------------------

/// A stream of `members` members, each a run of literals and one match,
/// with the member boundaries a writer would flush at.
fn many_members(members: usize, each: u64) -> (Vec<u8>, Vec<(Range<usize>, u64)>) {
    let mut out = BitWriter::default();
    let main = main_alphabet(b"ABCDEFGH", &[FIRST_FRESH + 27]);
    let tables = tables_for(&main, &slots_for(&[8]), &[]);
    let mut spans = Vec::with_capacity(members);
    let mut at = 0usize;
    for index in 0..members {
        let block = BlockWriter::start(&mut out, &tables, &tables.lengths(), index > 0);
        let mut produced = 0u64;
        while produced + 8 < each {
            for byte in b"ABCDEFGH" {
                block.main(&mut out, u16::from(*byte));
            }
            produced += 8;
        }
        while produced < each {
            block.main(&mut out, u16::from(b'A'));
            produced += 1;
        }
        block.end(&mut out, BlockEnd::NewMemberNewTables);
        let end = span_end(&mut out);
        spans.push((at..end, each));
        at = end;
    }
    (out.bytes, spans)
}

#[test]
fn no_allocation_once_the_stream_exists() {
    // SPEC-H1 5.6 and 7.3 item 3: no heap allocation inside `run`, and
    // none per member.
    //
    // 5.6's THIRD case asks for this at the scale of the bench corpus's
    // 20,000 member solid archive, and it is here rather than at eight
    // members because a cost that is a fraction of an allocation per
    // member - a buffer that doubles every thousand, say - does not show
    // up in eight. A debug run takes the smaller count; the shape of the
    // stream is the same either way.
    let members = if cfg!(debug_assertions) { 500 } else { 20_000 };
    let (packed, spans) = many_members(members, 500);
    let mut stream = Rar3Stream::new(1 << 16, &policy()).unwrap();
    let mut input = Bits::new(&packed);
    let mut counted = 0u64;
    let mut sink = Counted(0);
    for (index, (span, unpacked)) in spans.iter().enumerate() {
        let before = crate::rar3_filters::tests::counting::count();
        stream
            .member(
                &mut input,
                &MemberSpan {
                    packed: span.clone(),
                    unpacked: *unpacked,
                },
                &mut sink,
            )
            .unwrap();
        let spent = crate::rar3_filters::tests::counting::count() - before;
        if index > 0 {
            assert_eq!(spent, 0, "member {index} allocated {spent} times");
        }
        counted += 1;
    }
    assert_eq!(counted, members as u64);
    assert_eq!(sink.0, members as u64 * 500);
}

/// SPEC-H1 3.8, B1, and its bound (4.3, N5): the packed data a member
/// holds after its declared size is decoded into the window the stream
/// already has, however much it produces. Member 2 declares 2 bytes and
/// then holds 5,000 matches of 258 bytes, about twenty laps of the 64 KiB
/// window: nothing is allocated for them, the stream holds what it held,
/// none of them is any member's output, and member 3 copies the last of
/// them from distance 1.
///
/// One thread, no pool; under 1 MiB of memory.
#[test]
fn bytes_produced_after_the_declared_size_cost_no_memory() {
    let mut out = BitWriter::default();
    let main = main_alphabet(b"ABC", &[FIRST_SHORT, FIRST_FRESH + 27]);
    let tables = tables_for(&main, &slots_for(&[1]), &[]);
    let block = BlockWriter::start(&mut out, &tables, &[0; TABLE_LENGTHS], false);
    block.main(&mut out, u16::from(b'C'));
    block.end(&mut out, BlockEnd::NewMemberKeepTables);
    let first = span_end(&mut out);
    block.main(&mut out, u16::from(b'A'));
    block.main(&mut out, u16::from(b'B'));
    for _ in 0..5_000 {
        // Length slot 27 with every extra bit set: 224 + 31 + 3 bytes.
        block.fresh(&mut out, 27, 31, 1);
    }
    block.end(&mut out, BlockEnd::NewMemberKeepTables);
    let second = span_end(&mut out);
    block.main(&mut out, FIRST_SHORT);
    out.put(0, u32::from(SHORT_EXTRA[0]));
    block.main(&mut out, u16::from(b'A'));
    block.end(&mut out, BlockEnd::NewMemberNewTables);
    out.align();
    let spans = [
        (0..first, 1u64),
        (first..second, 2),
        (second..out.bytes.len(), 3),
    ];

    let mut stream = Rar3Stream::new(1 << 16, &policy()).unwrap();
    let mut input = Bits::new(&out.bytes);
    let mut outputs = Vec::new();
    for (index, (span, unpacked)) in spans.iter().enumerate() {
        let mut kept = Kept(Vec::with_capacity(8));
        let held = stream.held_bytes();
        let before = crate::rar3_filters::tests::counting::count();
        stream
            .member(
                &mut input,
                &MemberSpan {
                    packed: span.clone(),
                    unpacked: *unpacked,
                },
                &mut kept,
            )
            .unwrap();
        let spent = crate::rar3_filters::tests::counting::count() - before;
        if index > 0 {
            assert_eq!(spent, 0, "member {index} allocated {spent} times");
            assert_eq!(stream.held_bytes(), held, "member {index}");
        }
        outputs.push(kept.0);
    }
    assert_eq!(
        outputs,
        vec![b"C".to_vec(), b"AB".to_vec(), b"BBA".to_vec()]
    );
}

/// A sink that counts bytes and allocates nothing.
struct Counted(u64);

impl StreamOut for Counted {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.0 += bytes.len() as u64;
        Ok(())
    }
}

#[test]
fn working_memory_is_the_window_plus_under_128_kib() {
    // SPEC-H1 4.2 and 5.6, as a number.
    for dictionary in [1u32 << 16, 1 << 20, 1 << 22] {
        let stream = Rar3Stream::new(dictionary, &policy()).unwrap();
        let held = stream.codec_bytes();
        let over = held - u64::from(dictionary);
        assert!(
            over < 128 * 1024,
            "a {dictionary} byte dictionary holds {over} bytes beside the window"
        );
        // The five tables are a constant, not a function of the data.
        assert_eq!(over, 42_212, "the tables and the stored code lengths");
    }
}

// ---- the filter span the window cannot lend ---------------------------------

/// A stream of `total` bytes with one filter record at position 0 naming a
/// delta span of `span` bytes from the start, and the bytes it produces
/// before the filter runs.
fn stream_with_one_span(total: usize, span: u32) -> (Vec<u8>, Vec<u8>) {
    use crate::rar3_filters::{Params, RecordBuilder, StandardProgram};

    let mut out = BitWriter::default();
    let main = main_alphabet(b"ABCDEFGH", &[FILTER_RECORD, FIRST_FRESH + 27]);
    let tables = tables_for(&main, &slots_for(&[8]), &[]);
    let block = BlockWriter::start(&mut out, &tables, &[0; TABLE_LENGTHS], false);
    // The record first, at position 0, as the next 8 bits each (3.9).
    let mut record = Vec::new();
    RecordBuilder::new()
        .record(
            StandardProgram::Delta,
            0,
            span,
            0,
            Params::Channels(3),
            &mut record,
        )
        .expect("a record");
    block.main(&mut out, FILTER_RECORD);
    for byte in &record {
        out.put(u32::from(*byte), 8);
    }
    // Then the bytes: a run of literals, then matches of 258 at distance 8.
    let mut want = Vec::with_capacity(total);
    while want.len() < 8 {
        for byte in b"ABCDEFGH" {
            block.main(&mut out, u16::from(*byte));
            want.push(*byte);
        }
    }
    while want.len() + 258 <= total {
        block.fresh(&mut out, 27, 31, 8);
        for _ in 0..258 {
            want.push(want[want.len() - 8]);
        }
    }
    while want.len() < total {
        block.main(&mut out, u16::from(b'A'));
        want.push(b'A');
    }
    block.end(&mut out, BlockEnd::NewMemberNewTables);
    out.align();
    (out.bytes, want)
}

#[test]
fn a_span_longer_than_the_window_is_staged_and_gives_the_same_bytes() {
    // Spec J 3.6: the window may be smaller than a span, and the decoder
    // must still hand the transform the span's bytes in stream order. No
    // genuine archive reaches it (the longest genuine span is 65,536 and
    // the smallest dictionary is 65,536), so this is the vector for it.
    let (packed, unfiltered) = stream_with_one_span(40_000, 20_000);
    let mut want = unfiltered.clone();
    crate::rar3_filters::delta_decode(&unfiltered[..20_000], &mut want[..20_000], 3);

    // A window that can lend the span, and three that cannot.
    for dictionary in [1u32 << 16, 1 << 15, 1 << 13, 4096] {
        let got = decode_one(&packed, dictionary, unfiltered.len() as u64).unwrap();
        assert_eq!(
            got.len(),
            want.len(),
            "a {dictionary} byte window gave the wrong length"
        );
        assert!(
            got == want,
            "a {dictionary} byte window gave different bytes"
        );
    }
}

#[test]
fn v_cache_the_burst_leaves_the_reader_in_step_at_every_exit() {
    // SPEC-H1 3.1 and 3.10, as an INVARIANT of the literal burst: the
    // burst holds the reader's cache in locals for the length of a run
    // (see `BitSource::take_cache`), and the position it hands back must
    // name the first bit of the symbol that ENDS the run, whichever of
    // the burst's exits it leaves by.
    //
    // A run can end in four places, and which one it ends in is a
    // function of its LENGTH alone: inside the warming symbols that go
    // one at a time, on the FIRST symbol of a pair, on the SECOND symbol
    // of a pair, or in the odd tail after the pairs. So this sweeps the
    // length rather than naming one: every run from nothing to past the
    // window's own room, each followed by a match and by more literals,
    // decoded and compared byte for byte.
    //
    // It falsifies. A burst that skips the hand back at ONE of its exits
    // leaves the reader a few bits behind, the next symbol is read from
    // the middle of the last code, and the run length that reaches that
    // exit fails here while its neighbours pass.
    let literals: Vec<u8> = (b'a'..=b'z').collect();
    let main = main_alphabet(&literals, &[FIRST_FRESH + 4]);
    let tables = tables_for(&main, &slots_for(&[1, 4]), &[0]);
    for run in 0..=48usize {
        let mut out = BitWriter::default();
        let block = BlockWriter::start(&mut out, &tables, &[0; TABLE_LENGTHS], false);
        let mut want: Vec<u8> = Vec::new();
        // The run itself, every byte a different code width as the
        // alphabet's canonical codes run from four to five bits, so the
        // cache runs out at a different symbol for every length here.
        for i in 0..run {
            let byte = literals[i % literals.len()];
            block.main(&mut out, u16::from(byte));
            want.push(byte);
        }
        // The symbol that ENDS the run: a fresh match of length seven,
        // at distance four where the run is long enough to name it and
        // at distance one where it is not. Runs of one, two and three
        // are what reach the burst's WARMING loop, which takes its
        // symbols one at a time before any pairing, so they are the
        // only ones that exercise that exit; runs of four and up end
        // inside the pairs. A run of nothing at all has no match.
        if run >= 1 {
            let distance = if run >= 4 { 4 } else { 1 };
            block.fresh(&mut out, 4, 0, distance as u32);
            for _ in 0..7 {
                want.push(want[want.len() - distance]);
            }
        }
        // And a long tail of literals after it, so a reader left out of
        // step by the exit shows up in the bytes rather than only in a
        // length.
        //
        // The tail's LENGTH is load bearing and not padding. The burst
        // takes at most `available() >> 4` symbols in one turn (SPEC-D
        // 3.2.4's tail rule, settled once for the run), so on a stream
        // of a few hundred bits the burst runs out of INPUT ROOM before
        // it ever meets the symbol that ends the run, every exit is the
        // ordinary one, and the pair loop's own two exits are never
        // reached at all. Six hundred trailing literals put about three
        // thousand bits behind the run, which is two hundred symbols of
        // room, so the run ends where the stream says it ends.
        for i in 0..600usize {
            let byte = literals[(run + i) % literals.len()];
            block.main(&mut out, u16::from(byte));
            want.push(byte);
        }
        block.end(&mut out, BlockEnd::NewMemberNewTables);
        out.align();
        // Both loops, at every run length. The alphabet here is FLAT,
        // which is a block the shipped decoder now takes one literal a
        // turn, so without the forcing this sweep would no longer reach
        // the pair loop's own two exits at all - the ones the paragraph
        // above names. `Some(true)` is what keeps them covered.
        for forced in BOTH_LOOPS {
            let bytes = decode_one_forced(&out.bytes, 1 << 16, want.len() as u64, forced)
                .unwrap_or_else(|error| {
                    panic!("a run of {run} literals decodes ({forced:?}): {error:?}")
                });
            assert_eq!(
                bytes, want,
                "a run of {run} literals, then a match, pair forced {forced:?}"
            );
        }
    }
}

#[test]
fn v_pair_the_two_literal_loops_decode_the_same_bytes() {
    // SPEC-H1 3.4 and 3.10 as an INVARIANT of the burst: which literal
    // loop a block is decoded by is a performance decision and NOTHING
    // else, so the bytes out must not move with it.
    //
    // `PAIR_LITERALS` decides which loop runs, and the two alphabets
    // below are the two shapes the 21 Sep ladder measured them over:
    // flat codes, and codes of four to twelve bits. Both are decoded
    // three ways -
    // as they ship, pairing forced on, pairing forced off - and all
    // three must agree with the bytes the vector was written from.
    //
    // It falsifies. Reaching the second code of a pair at the wrong
    // offset, consuming one width where two were decoded, or letting the
    // pair run past the symbol that ends the run leaves the forced-on
    // result differing from the forced-off one, and the run length that
    // does it prints here.
    let literals: Vec<u8> = (b'a'..=b'z').collect();
    let main = main_alphabet(&literals, &[FIRST_FRESH + 4]);
    let distances = slots_for(&[1, 4]);
    let shapes = [
        ("flat", tables_for(&main, &distances, &[0])),
        ("varied", tables_for_varied(&main, &distances, &[0])),
    ];
    for (shape, tables) in shapes {
        // Run lengths past the warming symbols, past the first pairs,
        // and long enough that a run is cut by the window's own room
        // rather than by the symbol that ends it.
        for run in [
            0usize, 1, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 100, 4095, 4096, 4097,
        ] {
            let mut out = BitWriter::default();
            let block = BlockWriter::start(&mut out, &tables, &[0; TABLE_LENGTHS], false);
            let mut want: Vec<u8> = Vec::new();
            for i in 0..run {
                let byte = literals[i % literals.len()];
                block.main(&mut out, u16::from(byte));
                want.push(byte);
            }
            // A match ends the run wherever the run is long enough to
            // name a distance of its own, so the burst is left by its
            // symbol-in-hand exit and not only by running out of room.
            if run >= 4 {
                block.fresh(&mut out, 4, 0, 4);
                for _ in 0..7 {
                    want.push(want[want.len() - 4]);
                }
            }
            // The tail that puts input room behind the run, for the
            // reason the vector above gives at length.
            for i in 0..600usize {
                let byte = literals[(run + i) % literals.len()];
                block.main(&mut out, u16::from(byte));
                want.push(byte);
            }
            block.end(&mut out, BlockEnd::NewMemberNewTables);
            out.align();
            for forced in BOTH_LOOPS {
                let bytes = decode_one_forced(&out.bytes, 1 << 16, want.len() as u64, forced)
                    .unwrap_or_else(|error| {
                        panic!("{shape}, a run of {run}, pair {forced:?}: {error:?}")
                    });
                assert_eq!(
                    bytes, want,
                    "{shape} alphabet, a run of {run} literals, pair forced {forced:?}"
                );
            }
        }
    }
}

#[test]
fn v_wide_every_arm_of_the_match_path_decode_answers_the_same() {
    // SPEC-D 3.2 and SPEC-H1 3.10 as an INVARIANT of
    // `PrefixTable::decode`: which of its three arms answers a code is a
    // performance decision and NOTHING else, so the symbol and the width
    // consumed must not move with it.
    //
    // The three arms are the DIRECT hit, which the table answers; the
    // WIDE arm, for a code the direct table cannot hold, which is
    // `decode_wide` and the canonical walk behind it; and the TAIL arm
    // of SPEC-D 3.2.4, for a code read with fewer than fifteen bits
    // left. On 22 Sep 2026 the wide arm moved OUT of `decode`'s body so
    // that the direct hit could inline into the match path's serial
    // chain of three decodes, and this vector is what says the move
    // changed no answer.
    //
    // The alphabet is built so that all three arms RUN. The direct table
    // holds twelve bits, so widths 1 to 12 are direct hits and 13, 14
    // and 15 are not, and a length list of 1 to 15 with the last width
    // doubled is complete by Kraft: the widths 1 to 14 carry
    // `1 - 2^-14` and the two fifteens carry the `2^-14` that is left.
    // Without the wide widths this vector would pass over a `decode`
    // whose wide arm was never entered.
    let lengths: Vec<u8> = (1..=15u8).chain(std::iter::once(15)).collect();
    assert_eq!(lengths.len(), 16);
    let table = table_of(&lengths);
    let codes = canonical(&lengths);
    // Every symbol is checked, and the wide ones are checked against the
    // table's own general step as well, so a wrong WIDTH is caught and
    // not only a wrong symbol.
    let reference = SpecD::new(&lengths);

    // The symbols in an order that puts a wide code before, between and
    // after direct ones, so no arm is only ever entered from itself.
    // The three width-1 symbols at the END are what reach the TAIL arm:
    // each is decoded with fewer than fifteen bits left, which is the
    // condition SPEC-D 3.2.4 names. Without them every symbol in this
    // stream is answered with fifteen bits in hand and the tail arm is
    // never entered, which is how the first draft of this vector failed
    // its own coverage assertion below.
    let order: Vec<u16> = vec![
        0, 15, 3, 14, 7, 12, 1, 13, 11, 2, 15, 14, 8, 4, 13, 9, 5, 12, 10, 6, 14, 15, 0, 0, 0,
    ];
    let mut out = BitWriter::default();
    for &symbol in &order {
        let (code, width) = codes[usize::from(symbol)];
        out.put(code, u32::from(width));
    }
    // The tail arm is reached by the symbols at the END of the stream,
    // where fewer than fifteen bits are left: nothing is padded past
    // them, so the last few codes are answered by `decode_tail`. That is
    // the arm SPEC-D 3.2.4 describes and it is load bearing here - a
    // vector that padded the stream would test two arms and claim three.
    out.align();
    let bytes = out.bytes.clone();
    let bit_len = out.bit_len();

    let mut input = Bits::new(&bytes);
    input.begin_member(0..bytes.len());
    let mut direct = 0usize;
    let mut wide = 0usize;
    let mut tail = 0usize;
    for (at, &symbol) in order.iter().enumerate() {
        // Which arm this symbol WILL take, read before it is decoded, so
        // the counts below are a statement about coverage rather than a
        // restatement of what happened.
        let left = input.available();
        let width = codes[usize::from(symbol)].1;
        if left < 15 {
            tail += 1;
        } else if u32::from(width) > u32::from(PrefixTable::DIRECT_BITS) {
            wide += 1;
        } else {
            direct += 1;
        }
        let before = input.position();
        let got = table
            .decode(&mut input)
            .unwrap_or_else(|error| panic!("symbol {at} ({symbol}) of the stream: {error:?}"));
        let consumed = input.position() - before;
        assert_eq!(got, symbol, "symbol {at} of the stream");
        assert_eq!(
            consumed,
            u64::from(width),
            "symbol {at} ({symbol}) consumed the wrong width"
        );
        // The same answer the reference decoder of SPEC-D gives for the
        // lookahead this symbol was read at, which is what makes a wrong
        // ANSWER visible and not only a wrong position.
        assert_eq!(
            reference.answer(peek_at(&bytes, before, bit_len)),
            (symbol, width),
            "the reference disagrees at symbol {at}"
        );
    }
    // All three arms ran. A vector that silently covered two of them
    // would pass while saying nothing about the arm that moved.
    assert!(direct > 0, "no direct hit in this stream");
    assert!(
        wide > 0,
        "the WIDE arm never ran, so this vector proves nothing about it"
    );
    assert!(tail > 0, "the TAIL arm never ran");

    // SPEC-D 3.2.4's own boundary, which the arms above walk past rather
    // than stand on: a code that does NOT fit in what is left is
    // `Truncated` with NOTHING consumed. It needs a stream of its own
    // because it is the one case where the answer is not a symbol, and
    // it is what holds `decode`'s fifteen bit test in place - a test
    // relaxed by one bit answers a symbol here instead of refusing, and
    // no vector that only reads narrow codes at the tail can see it.
    //
    // A member's limit is a BYTE range, so the stream is built to land
    // on a byte boundary exactly: two one bit codes and then fourteen
    // bits of a fifteen bit one is sixteen bits, two whole bytes, with
    // no padding for the short code to borrow.
    let mut short = BitWriter::default();
    let (code, width) = codes[0];
    assert_eq!(width, 1);
    short.put(code, 1);
    short.put(code, 1);
    let (wide_code, wide_width) = codes[15];
    assert_eq!(wide_width, 15);
    short.put(wide_code >> 1, 14);
    assert_eq!(
        short.bit_len(),
        16,
        "the member must end on a byte boundary"
    );
    let bytes = short.bytes.clone();
    let mut input = Bits::new(&bytes);
    input.begin_member(0..bytes.len());
    for _ in 0..2 {
        assert_eq!(
            table.decode(&mut input).expect("the direct code answers"),
            0
        );
    }
    let before = input.position();
    let left = input.available();
    assert_eq!(left, 14, "the wide code must be one bit short of fitting");
    let refused = table.decode(&mut input);
    assert!(
        matches!(&refused, Err(error) if matches!(error.kind(), ErrorKind::Truncated)),
        "a fifteen bit code with fourteen bits left must be Truncated, got {refused:?}"
    );
    assert_eq!(
        input.position(),
        before,
        "a refused code must consume NOTHING (SPEC-D 3.2.4)"
    );
}

/// Sixteen bits of `bytes` at bit offset `at`, zero filled past
/// `bit_len`: the lookahead SPEC-D's decoding function is defined on.
fn peek_at(bytes: &[u8], at: u64, bit_len: u32) -> u32 {
    let mut value = 0u32;
    for i in 0..16u64 {
        let bit = at + i;
        let got = if bit >= u64::from(bit_len) {
            0
        } else {
            let byte = bytes[(bit / 8) as usize];
            (byte >> (7 - (bit % 8))) & 1
        };
        value = (value << 1) | u32::from(got);
    }
    value
}

#[test]
fn v_entry_a_match_is_dispatched_the_same_from_either_side_of_the_burst() {
    // SPEC-H1 3.4, 3.5 and 3.10, as an INVARIANT of the run loop rather
    // than of any one arm: WHICH PATH a main symbol is recognised on is
    // a performance decision and nothing else, so the bytes out must not
    // move with it.
    //
    // `Rar3Lz::run` used to reach every symbol through the literal
    // burst's first `one_literal`, paying the whole run's setup even for
    // a stream that is 93 percent matches. It now tests the next main
    // symbol before that setup and dispatches a match without entering
    // the burst at all. There are therefore two ways into the same
    // dispatch, and three answers the direct table can give at the test:
    // a LITERAL, which must fall into the burst unchanged; a symbol of
    // 256 or more, which is taken in hand with its width consumed; and
    // `WIDE`, which consumes NOTHING and must fall through to
    // `PrefixTable::decode`'s general step.
    //
    // The third is the one with no other witness, so this vector names a
    // main alphabet whose MATCH symbol is thirteen bits, wider than the
    // direct table's twelve, and fires it after every run length from
    // nothing to past the burst's warming symbols. It is run beside a
    // flat alphabet, whose match symbol the direct table does answer, so
    // the two ways in are compared over the same shape.
    //
    // It falsifies, and every break below was RUN rather than reasoned
    // about:
    //
    // | break | caught as |
    // |---|---|
    // | the pre-test takes `WIDE` as a symbol | main symbol 4,095 |
    // | `WIDE` consumes a width before falling through | the next symbol is read out of the middle of the match's own code |
    //
    // AND ONE BREAK THIS VECTOR DOES NOT CATCH, said here rather than
    // left to be discovered: removing the exit test that stays AFTER the
    // burst, on the argument that the hoisted one covers it, passes this
    // vector. It is still wrong and the copy still stays. A burst that
    // wrote literals can spend the member's `left` INSIDE its own loop,
    // and the next turn of that loop breaks with nothing in hand; the
    // hoisted test has already run by then. Without the copy the decoder
    // dispatches one symbol too many, and where that symbol is a match
    // `Rar3Lz::emit` clamps it to nothing and sets `pending` - so the
    // BYTES of this member are unchanged and only the next member of a
    // SOLID CHAIN sees it. A vector that catches it has to cut this
    // stream into two member spans at a byte boundary inside the block
    // (SPEC-H1 3.8) with the first member's room ending exactly at a
    // match, and that is not written yet.
    let literals: Vec<u8> = (b'a'..=b'h').collect();
    let main = main_alphabet(&literals, &[FIRST_FRESH + 4]);
    let flat_tables = tables_for(&main, &slots_for(&[4]), &[0]);
    // The same alphabet with the MATCH symbol alone pushed past the
    // direct table. Thirteen bits is the narrowest width the direct
    // table cannot answer, so this is the boundary case and not a
    // comfortable one. Kraft is asserted rather than assumed.
    let mut wide_tables = flat_tables.clone();
    for (symbol, width) in wide_tables.main.iter_mut().enumerate() {
        if *width > 0 {
            *width = if symbol as u16 == FIRST_FRESH + 4 {
                13
            } else {
                4
            };
        }
    }
    let kraft: f64 = wide_tables
        .main
        .iter()
        .filter(|&&width| width > 0)
        .map(|&width| 0.5f64.powi(i32::from(width)))
        .sum();
    assert!(kraft <= 1.0, "the wide main alphabet is prefix free");
    assert_eq!(
        wide_tables.main[usize::from(FIRST_FRESH + 4)],
        13,
        "the match symbol is wider than the direct table, which is the point"
    );

    for (which, tables) in [("direct", &flat_tables), ("wide", &wide_tables)] {
        for run in 0..=8usize {
            let mut out = BitWriter::default();
            let block = BlockWriter::start(&mut out, tables, &[0; TABLE_LENGTHS], false);
            let mut want: Vec<u8> = Vec::new();
            // A seed the match can name, then the run under test, then
            // the match itself. The seed is four bytes because the match
            // below names distance four.
            for &byte in &literals[..4] {
                block.main(&mut out, u16::from(byte));
                want.push(byte);
            }
            for i in 0..run {
                let byte = literals[i % literals.len()];
                block.main(&mut out, u16::from(byte));
                want.push(byte);
            }
            // THREE MATCHES BACK TO BACK, and the second and third are
            // the point. The first is met from INSIDE the burst, by the
            // `one_literal` that ends the run. The ones after it are met
            // at the TOP of the loop, with no literal before them, which
            // is the only place the new test is reached at all: a wide
            // code there must consume nothing and fall through to the
            // general step, and a direct one must be taken in hand.
            for _ in 0..3 {
                block.fresh(&mut out, 4, 0, 4);
                for _ in 0..7 {
                    want.push(want[want.len() - 4]);
                }
            }
            // A tail long enough that the burst has input room to reach
            // the symbol that ends each run, for the reason
            // `v_cache_the_burst_leaves_the_reader_in_step_at_every_exit`
            // gives at length: the burst takes at most `available() >> 4`
            // symbols in one turn.
            for i in 0..600usize {
                let byte = literals[(run + i) % literals.len()];
                block.main(&mut out, u16::from(byte));
                want.push(byte);
            }
            block.end(&mut out, BlockEnd::NewMemberNewTables);
            out.align();
            for forced in BOTH_LOOPS {
                let bytes = decode_one_forced(&out.bytes, 1 << 16, want.len() as u64, forced)
                    .unwrap_or_else(|error| {
                        panic!("{which}, a run of {run} then a match ({forced:?}): {error:?}")
                    });
                assert_eq!(
                    bytes, want,
                    "{which} main codes, a run of {run} literals then a match, \
                     pair forced {forced:?}"
                );
            }
        }
    }
}

#[test]
fn v_guess_the_speculative_pair_loop_decodes_the_same_bytes() {
    // SPEC-H1 3.4 and 3.10 as an INVARIANT of the burst's speculative arm:
    // which width the pair loop GUESSES for a pair's second code is a
    // performance decision and nothing else, so the bytes out must not
    // move with it, whether the guess is the table's own, declined, or a
    // width no literal of the alphabet has.
    //
    // The alphabet is cut so that the table DOES guess: twenty four
    // literals at five bits and two at six, with the end of block symbol
    // and one match symbol at six, so width five holds 0.75 of the code's
    // mass, above `SPECULATE_MASS_PERCENT`, and the guessed width is
    // right for twenty four literals in twenty six. Every run length of
    // the pair vector above is decoded five ways and all five must agree
    // with the bytes the vector was written from.
    //
    // It falsifies. Using the guessed entry where the first code's width
    // is NOT the guessed width (dropping the `width == guess` test) makes
    // the `Some(3)` and `Some(6)` decodes read the second code at the
    // wrong offset, and the run that first pairs a five bit literal with
    // a six bit one prints here.
    let literals: Vec<u8> = (b'a'..=b'z').collect();
    let main = main_alphabet(&literals, &[FIRST_FRESH + 4]);
    let mut tables = tables_for(&main, &slots_for(&[1, 4]), &[0]);
    let mut lengths = vec![0u8; MAIN_SYMBOLS];
    for (at, &byte) in literals.iter().enumerate() {
        lengths[usize::from(byte)] = if at < 24 { 5 } else { 6 };
    }
    lengths[usize::from(END_OF_BLOCK)] = 6;
    lengths[usize::from(FIRST_FRESH + 4)] = 6;
    assert_eq!(
        table_of(&lengths).literal_guess(),
        5,
        "width five holds 0.75 of the mass, so the table guesses it"
    );
    tables.main = lengths;

    // The run lengths of `v_pair_...`, which reach the warming symbols,
    // the first pairs, and a run cut by the window's own room. The
    // literals cycle a to z, so every run past twenty four pairs a five
    // bit code with a six bit one in both orders.
    for run in [
        0usize, 1, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 23, 24, 25, 26, 27, 100, 4095, 4096, 4097,
    ] {
        let mut out = BitWriter::default();
        let block = BlockWriter::start(&mut out, &tables, &[0; TABLE_LENGTHS], false);
        let mut want: Vec<u8> = Vec::new();
        for i in 0..run {
            let byte = literals[i % literals.len()];
            block.main(&mut out, u16::from(byte));
            want.push(byte);
        }
        if run >= 4 {
            block.fresh(&mut out, 4, 0, 4);
            for _ in 0..7 {
                want.push(want[want.len() - 4]);
            }
        }
        for i in 0..600usize {
            let byte = literals[(run + i) % literals.len()];
            block.main(&mut out, u16::from(byte));
            want.push(byte);
        }
        block.end(&mut out, BlockEnd::NewMemberNewTables);
        out.align();
        // As it ships (the table's guess, five), declined, forced to the
        // table's guess, and forced to two widths that are ALWAYS wrong:
        // three, which no literal has, and six, which two of them have
        // but which is not the modal width.
        for guess in [None, Some(0), Some(5), Some(3), Some(6)] {
            let bytes = decode_spans_guessed(
                &out.bytes,
                1 << 16,
                &[(0..out.bytes.len(), want.len() as u64)],
                None,
                guess,
            )
            .unwrap_or_else(|error| panic!("a run of {run}, guess {guess:?}: {error:?}"))
            .pop()
            .unwrap();
            assert_eq!(
                bytes, want,
                "a run of {run} literals, then a match, guess forced {guess:?}"
            );
        }
    }
}

#[test]
fn the_literal_guess_is_the_modal_width_only_when_it_holds_the_mass() {
    // `PrefixTable::literal_guess`, checked against the two REAL literal
    // alphabets the 21 Sep 2026 census read off the gate corpora and
    // against the edges of its own rule.
    fn lengths(literals: &[(u8, usize)], others: &[(u8, usize)]) -> Vec<u8> {
        let mut out = vec![0u8; MAIN_SYMBOLS];
        let mut at = 0usize;
        for &(width, count) in literals {
            for _ in 0..count {
                out[at] = width;
                at += 1;
            }
        }
        assert!(at <= 256);
        let mut at = 256usize;
        for &(width, count) in others {
            for _ in 0..count {
                out[at] = width;
                at += 1;
            }
        }
        out
    }
    let guess = |literals: &[(u8, usize)], others: &[(u8, usize)]| {
        table_of(&lengths(literals, others)).literal_guess()
    };

    // `rar3_incompressible_64m`'s table: 32 at 7, 191 at 8, 1 at 9, the
    // end of block at 9. Width 8 holds 0.746 of the mass: GUESSED.
    assert_eq!(guess(&[(7, 32), (8, 191), (9, 1)], &[(9, 1)]), 8);
    // `rar3_code_32m`'s table: 3 at 5, 11 at 6, 5 at 7, 23 at 8, 214 at
    // 9. Width 9 holds 0.418: DECLINED, and so is every other width.
    assert_eq!(
        guess(
            &[(5, 3), (6, 11), (7, 5), (8, 23), (9, 214)],
            &[(4, 2), (5, 1), (6, 1), (7, 1), (8, 1), (9, 2)]
        ),
        0
    );
    // A flat alphabet of 256 literals at 8, the whole mass: guessed. The
    // fuzz builder's flat alphabets are one bit wider than this because
    // they hold an end of block symbol too, and a power of two of
    // literals then holds exactly half the mass: declined.
    assert_eq!(guess(&[(8, 256)], &[]), 8);
    assert_eq!(guess(&[(9, 256)], &[(9, 1)]), 0);
    // The threshold itself, in units of 1/256 at width 8: 184 is
    // 0.71875, under 0.72, and 185 is 0.7227, over it.
    assert_eq!(guess(&[(8, 184)], &[]), 0);
    assert_eq!(guess(&[(8, 185)], &[]), 8);
    // Widths the direct table does not answer are never guessed, even
    // holding all the mass there is.
    assert_eq!(guess(&[(13, 256)], &[]), 0);
    // Mass in the non literal symbols does not count: a table whose
    // literals are all absent guesses nothing, and so does an empty one.
    assert_eq!(guess(&[], &[(6, 43)]), 0);
    assert_eq!(PrefixTable::new(MAIN_SYMBOLS).literal_guess(), 0);
    // The modal width wins on MASS and not on symbol count: three
    // literals at width 2 hold 0.75 and outweigh 200 at width 12, which
    // hold 0.05 between them; two at width 2 hold 0.5 and are declined,
    // and the 200 symbols do not make width 12 the guess instead.
    assert_eq!(guess(&[(2, 3), (12, 200)], &[]), 2);
    assert_eq!(guess(&[(2, 2), (12, 200)], &[]), 0);
}

// ---- a declared size the stream position cannot be added to ---------------

/// A solid continuation member whose header declares more bytes than a
/// `u64` has left past the stream position is a member whose data ends
/// before its declared size, exactly as the same size is answered on a
/// stream's first member, where nothing is added to it: it comes out
/// short with the bytes it holds when its data ends at an end of block
/// (SPEC-H1 3.7, E4), and is `Truncated` when its data runs out (4.3,
/// N2). The sum of the position and the declared size was unchecked: a
/// panic with overflow checks on, and a member answered whole with no
/// byte written with them off.
///
/// One thread, no pool; under 1 MiB of memory.
#[test]
fn a_declared_size_past_the_end_of_u64_ends_where_the_data_does() {
    let (packed, mut spans) = many_members(2, 500);
    let whole = decode_spans(&packed, 1 << 16, &spans).unwrap();
    // The first member of a stream: position 0, nothing to overflow.
    let first = decode_spans(&packed, 1 << 16, &[(spans[0].0.clone(), u64::MAX)]).unwrap();
    assert_eq!(first[0], whole[0]);
    // The second: position 500.
    for declared in [u64::MAX, u64::MAX - 499] {
        spans[1].1 = declared;
        let second = decode_spans(&packed, 1 << 16, &spans).unwrap();
        assert_eq!(second, whole, "declared {declared}");
        // With its end of block cut off, the data runs out instead.
        let mut cut = spans.clone();
        cut[1].0.end -= 1;
        let error = decode_spans(&packed, 1 << 16, &cut).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::Truncated), "{error:?}");
    }
}

// ---- the unknown end of a streamed member ----------------------------------

/// The extract driver hands a streamed member the span `0..usize::MAX`,
/// "the end is not known yet", and the reader must then have NO limit
/// until the pull stream ends, when the limit becomes the stream's real
/// end. The limit was computed as `usize::MAX * 8`, which is no limit only
/// where that saturates a `u64`.
///
/// TARGET: this fails before the fix on a 32-bit `usize` only
/// (armv7-unknown-linux-musleabihf: the limit there was 34,359,738,360
/// bits, so a compressed RAR 2.9 member with 4 GiB or more of packed data
/// met a false end of input at byte 4 GiB - 1, and nothing raises a limit
/// once set). On a 64-bit target it passes before and after.
///
/// One thread, no pool; under 1 MiB of memory.
#[test]
fn a_streamed_member_of_unknown_end_has_no_limit_until_the_stream_ends() {
    let data = vec![0xa5u8; 200_000];
    let mut source = crate::rar5_lz::SliceSource::new(&data);
    let mut input = Bits::streaming(&mut source);
    input.begin_member(0..usize::MAX);
    assert_eq!(
        input.available(),
        u64::MAX,
        "an unknown end is no limit, whatever the width of usize"
    );
    let mut read = 0u64;
    while let Ok(word) = input.read(32) {
        assert_eq!(word, 0xa5a5_a5a5);
        read += 32;
    }
    assert_eq!(read, 200_000 * 8, "every bit of the stream, and no more");
    assert_eq!(input.available(), 0);
}

// ---- the text model's literal runs ------------------------------------------

/// Packed bytes for one text model block that this test makes up: a START
/// header (order 6, a 1 MiB model, the escape byte set to 255), then bytes
/// that are zero but for one in `sparse` drawn from a seeded generator.
/// It is no archive a writer made. The model is driven only by what it
/// decodes, and a stream of mostly low counts decodes as long runs of
/// literals with copies, model restarts and a rare escape among them,
/// which is what the two readings below are compared over.
fn made_up_text_block(seed: u64, sparse: u64, len: usize) -> Vec<u8> {
    let mut state = seed;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut packed = vec![0x80 | 0x40 | 0x20 | 5, 0, 0xff];
    while packed.len() < len {
        let draw = next();
        packed.push(if draw % sparse == 0 {
            (draw >> 32) as u8
        } else {
            0
        });
    }
    packed
}

/// Whole bytes of a slice for the text model, `Truncated` past its end.
struct SliceBytes<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl crate::ppmd::StreamBytes for SliceBytes<'_> {
    fn next_byte(&mut self) -> Result<u8> {
        let byte = self.bytes.get(self.at).copied();
        self.at += 1;
        byte.ok_or_else(|| crate::Error::new(crate::ErrorKind::Truncated))
    }
}

/// The block's output read ONE TOKEN AT A TIME by `PpmDecoder::step`, up
/// to the first token that is not output or the first refusal: the reading
/// the member loop made before it decoded literals in runs.
fn token_by_token(packed: &[u8], dictionary: u32) -> Vec<u8> {
    use crate::ppmd::{MemoryBudget, PpmDecoder, PpmStep};
    let mut ppm = PpmDecoder::new();
    let mut bytes = SliceBytes {
        bytes: &packed[1..],
        at: 0,
    };
    let budget = MemoryBudget {
        working_limit: u64::MAX,
        held_elsewhere: 0,
    };
    ppm.begin_block(packed[0], &mut bytes, &budget).unwrap();
    let mut window = Window::new(dictionary);
    let mut out = Vec::new();
    while let Ok(PpmStep::Produced(_)) = ppm.step(&mut bytes, &mut window, u64::MAX) {
        let from = out.len() as u64;
        let (head, tail) = window.slices(from, window.produced()).unwrap();
        out.extend_from_slice(head);
        out.extend_from_slice(tail);
    }
    out
}

/// A member's text model output is the same bytes whether its literals
/// are decoded a token at a time or in the runs the member loop asks for
/// (`Rar3Stream::ppm_literals`): compared over made-up blocks long enough
/// to pass the gather point many times, in a window whose half is the
/// gather point (64 KiB) and in one where 256 KiB is.
///
/// One thread, no pool; about 30 MiB of memory.
#[test]
fn a_run_of_text_model_literals_is_the_tokens_one_at_a_time() {
    let mut passed_thrice = Vec::new();
    for (seed, sparse, dictionary) in [
        (0x2545_f491_4f6c_dd1du64, 5u64, 64u32 << 10),
        (0x0123_4567_89ab_cdef, 65, 64 << 10),
        (0x9e37_79b9_7f4a_7c15, 129, 64 << 10),
        (0x0123_4567_89ab_cdef, 65, 4 << 20),
        (0x0123_4567_89ab_cdef, 1025, 4 << 20),
        (0x9e37_79b9_7f4a_7c15, 4097, 4 << 20),
    ] {
        let packed = made_up_text_block(seed, sparse, 2_000_000);
        let want = token_by_token(&packed, dictionary);
        // Every size a run can end at: the whole reading, and sizes that
        // end inside a run and one byte either side of a gather point.
        let gather = (dictionary as usize / 2).min(256 << 10);
        for size in [
            want.len(),
            want.len() - 1,
            gather + 1,
            gather,
            gather - 1,
            1,
        ] {
            if size > want.len() {
                continue;
            }
            let mut stream = Rar3Stream::new(dictionary, &policy()).unwrap();
            let mut input = Bits::new(&packed);
            let mut kept = Kept::default();
            // What follows the declared size is the member's tail, and
            // whether that reads to an end is not this test's: the
            // member's own bytes are handed on before it is read.
            let _ = stream.member(
                &mut input,
                &MemberSpan {
                    packed: 0..packed.len(),
                    unpacked: size as u64,
                },
                &mut kept,
            );
            assert!(
                kept.0 == want[..size],
                "seed {seed:#x} sparse {sparse} dictionary {dictionary} size {size}"
            );
        }
        if want.len() >= 3 * gather {
            passed_thrice.push(dictionary);
        }
    }
    for dictionary in [64u32 << 10, 4 << 20] {
        assert!(
            passed_thrice.contains(&dictionary),
            "no block passed the gather point of a {dictionary} byte window three times"
        );
    }
}
