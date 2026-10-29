//! Long literal runs across TABLE BOUNDARIES: the stream builder behind
//! this package's fourth fuzz target (`fuzz_literal_burst`, SPEC-H1 6.3
//! and an item left open on 19 Sep 2026).
//!
//! The three targets SPEC-H1 6.3 names all feed the decoder bytes and
//! hope. That reaches a table read only when the fuzzer happens to write
//! one, and it reaches a SECOND table read in the same stream almost
//! never: `fuzz_tables` stops at the first header it cannot parse, and a
//! random body that decodes a thousand literals and then the end of block
//! symbol is not something libFuzzer finds by mutation. So the boundary
//! itself - the point where a block of literals ends, the stored code
//! lengths are carried or cleared, the 404 lengths are read as DELTAS on
//! what the last block left, and the next long run begins - is the least
//! reached machinery in the package.
//!
//! This builder writes that shape ON PURPOSE. The seed chooses every
//! alphabet, every run length, every end of block kind and every keep
//! bit; the SHAPE - several blocks, each a long literal run, each
//! followed by a boundary - is the construction's, the same rule the
//! window edge target had to learn (`internals_h::EDGE_TARGET`): a
//! property that depends on the seed LENGTH stops happening the moment
//! libFuzzer settles on short inputs.
//!
//! Every stream it writes is a stream this package must decode exactly,
//! so the target's assertion is a byte comparison and not merely "no
//! panic": the literals are known before the decoder runs.

use std::ops::Range;

use super::tables::{
    DISTANCE_SYMBOLS, LENGTH_SYMBOLS, LEVEL_SYMBOLS, LOW_SYMBOLS, MAIN_SYMBOLS, TABLE_LENGTHS,
};
use super::{BlockEnd, END_OF_BLOCK};

/// The dictionary every stream here declares: the smallest SPEC-H1 3.6
/// admits, `65,536 << 0`.
pub(crate) const BURST_WINDOW: u32 = 1 << 16;

/// The most output one execution may produce, which is what holds the
/// cost of a run flat whatever the seed says.
///
/// Two laps of [`BURST_WINDOW`], so a burst really does pass the write
/// point and the literal path is exercised where the ring wraps as well
/// as where it does not.
const MOST_OUTPUT: usize = 2 * BURST_WINDOW as usize;

/// The longest run one block may hold before the total cap applies.
const RUN_CAP: usize = 8192;

/// Table reads per stream, at the least: one reaches no boundary at all,
/// so the floor is two whatever the seed says.
const LEAST_BLOCKS: u8 = 2;

/// The most blocks one stream may hold, which bounds what a seed of tiny
/// runs can cost: every block is a 404 length table read of its own.
const MOST_BLOCKS: u32 = 64;

/// Bits out, most significant first (the writer of SPEC-H1 5.4, with a
/// word accumulator so a 128 KiB burst costs the builder less than the
/// decoder it is built for).
#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    word: u64,
    have: u32,
}

impl BitWriter {
    fn put(&mut self, value: u32, count: u32) {
        debug_assert!(count <= 32);
        let mask = if count == 0 {
            0
        } else {
            u64::MAX >> (64 - count)
        };
        self.word = (self.word << count) | (u64::from(value) & mask);
        self.have += count;
        while self.have >= 8 {
            self.have -= 8;
            self.bytes.push((self.word >> self.have) as u8);
        }
    }

    /// Up to the next byte boundary, discarding what is left of the part
    /// used byte, which is where a block header begins (SPEC-H1 3.2) and
    /// where a member's own span begins (SPEC-H1 3.8).
    fn align(&mut self) -> usize {
        if self.have > 0 {
            let pad = 8 - self.have;
            self.put(0, pad);
        }
        self.bytes.len()
    }
}

/// The canonical code a length list gives each symbol: codes of each
/// length assigned in symbol order, shorter lengths first, which is the
/// inverse of the decoding function of SPEC-H1 3.10.
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

/// A SKEWED main alphabet: the first `promoted` of `literals` one bit
/// narrower than the flat width the whole set needs, the rest and the end
/// of block symbol at that width.
///
/// This is the shape the literal burst's speculative arm exists for
/// (`PrefixTable::literal_guess`): a modal width holding most of the
/// code's mass, with a minority of literals one bit wider, so the guessed
/// width is right most of the time and wrong some of the time. A flat
/// alphabet cannot reach that arm at all: with the end of block symbol
/// beside a power of two of literals, the flat width holds exactly half
/// the mass and the table declines to guess, so every stream this
/// builder wrote before 22 Sep 2026 decoded through the dependent loop
/// only.
///
/// Kraft: `promoted / 2^(w-1) + (literals - promoted + 1) / 2^w` is
/// `(promoted + literals + 1) / 2^w`, at most one whenever `promoted <=
/// 2^w - literals - 1`, which the caller keeps. The modal width's mass
/// is then `promoted / 2^(w-1)`, and the SEED chooses `promoted`, so
/// across a campaign the guess is declined, taken at its threshold, and
/// taken with a hit rate from the threshold up to nearly one.
fn skewed(size: usize, literals: usize, promoted: usize) -> Vec<u8> {
    let mut width = 1u8;
    while (1usize << width) < literals + 1 {
        width += 1;
    }
    debug_assert!(width >= 2 && promoted + literals < 1 << width);
    let mut lengths = vec![0u8; size];
    for (symbol, length) in lengths.iter_mut().enumerate().take(literals) {
        *length = if symbol < promoted { width - 1 } else { width };
    }
    lengths[usize::from(END_OF_BLOCK)] = width;
    lengths
}

/// A stream of literal bursts, and everything needed to check it.
pub(crate) struct Burst {
    /// The stream's packed bytes.
    pub packed: Vec<u8>,
    /// Each member's packed span and declared size.
    pub members: Vec<(Range<usize>, u64)>,
    /// What each member must decode to, byte for byte.
    pub expected: Vec<Vec<u8>>,
    /// How many table reads the stream holds, which is the number this
    /// target exists for.
    pub blocks: u32,
    /// How many literals it decodes in all.
    pub literals: u64,
}

/// Build one stream of literal bursts from `data`.
///
/// The seed's first byte is a FLOOR on the table reads, two to
/// seventeen; the rest is CYCLED over the blocks, four bytes each, so a
/// seed of any length names every one of them. The stream ends when it
/// has produced [`MOST_OUTPUT`] bytes and read at least that floor of
/// tables, or at [`MOST_BLOCKS`], whichever comes first.
pub(crate) fn literal_burst(data: &[u8]) -> Option<Burst> {
    let (&first, rest) = data.split_first()?;
    if rest.len() < 4 {
        return None;
    }
    let floor = u32::from(first % 16) + u32::from(LEAST_BLOCKS);
    let mut noise =
        crate::bench_bytes::ByteRun::new(u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]));

    let mut out = BitWriter::default();
    let mut stored = vec![0u8; TABLE_LENGTHS];
    let mut members: Vec<(Range<usize>, u64)> = Vec::new();
    let mut expected: Vec<Vec<u8>> = Vec::new();
    let mut member_start = 0usize;
    let mut member_bytes: Vec<u8> = Vec::new();
    let mut produced = 0usize;
    let mut written = 0u32;

    // The blocks run until the OUTPUT is a burst, not until a count the
    // seed named is used up: a stream of short runs is exactly the shape
    // a fuzzer settles on, and the boundaries are only worth reaching
    // with real literal runs between them. The seed still chooses every
    // run, every alphabet, every keep bit and every end.
    let mut block = 0u32;
    // Set by `NewMemberKeepTables`: the next member resumes INSIDE this
    // block, under these tables, so no header is written for it
    // (SPEC-H1 3.7).
    let mut inside: Option<(usize, Vec<(u32, u8)>)> = None;
    let mut kept = false;
    while block < MOST_BLOCKS {
        let step = (block as usize * 4) % rest.len();
        let pick = |at: usize| rest[(step + at) % rest.len()];
        let (alphabet, codes) = match inside.take() {
            Some(held) => held,
            None => {
                // One to 256 literal values, so the main alphabet's code
                // width runs from 1 to 9 bits and a burst crosses the byte
                // boundary at a different rate in each block.
                let alphabet = 1usize << (pick(0) % 9);
                let mut main: Vec<u16> = (0..alphabet as u16).collect();
                main.push(END_OF_BLOCK);
                // Bit 6 of the same byte chooses a SKEWED alphabet over
                // a flat one, and the end kind byte's high bits choose
                // how skewed: how many literals sit one bit narrower
                // than the rest, from all but one of them down to none.
                // Two or more literals, because one literal and the end
                // of block symbol are the whole of a one bit code and
                // nothing in it can be promoted. See [`skewed`] for what
                // this reaches that [`flat`] cannot.
                let main_lengths = if pick(0) & 0x40 != 0 && alphabet >= 2 {
                    let promoted =
                        (alphabet - 1).saturating_sub(usize::from(pick(3) >> 2) % alphabet);
                    skewed(MAIN_SYMBOLS, alphabet, promoted)
                } else {
                    flat(MAIN_SYMBOLS, &main)
                };
                let mut wanted = main_lengths.clone();
                wanted.extend_from_slice(&flat(DISTANCE_SYMBOLS, &[0]));
                wanted.extend_from_slice(&flat(LOW_SYMBOLS, &[0]));
                wanted.extend_from_slice(&flat(LENGTH_SYMBOLS, &[0]));
                // The keep bit, which is the boundary this target is most
                // for: the 404 lengths are then read as deltas on what the
                // last block left behind (SPEC-H1 3.3), and only a stream
                // with more than one table read can tell a decoder that
                // carries them from one that does not.
                let keep = block > 0 && pick(0) & 0x80 != 0;
                write_block_header(&mut out, &wanted, &stored, keep);
                stored = wanted;
                written += 1;
                (alphabet, canonical(&main_lengths))
            }
        };

        // The seed chooses every run, and the CONSTRUCTION guarantees the
        // burst: the last block this stream may hold takes whatever is
        // left of [`MOST_OUTPUT`], so a seed whose every run is four
        // bytes long still ends in a run of tens of thousands. Without
        // this the burst is a function of the seed's BYTES, which is the
        // way the window edge target was blind for a whole campaign.
        let run = if block + 1 >= MOST_BLOCKS {
            MOST_OUTPUT - produced
        } else {
            ((usize::from(pick(1)) << 8 | usize::from(pick(2))) % RUN_CAP + 1)
                .min(MOST_OUTPUT - produced)
        };
        for _ in 0..run {
            let value = usize::from(noise.byte()) % alphabet;
            let (code, width) = codes[value];
            out.put(code, u32::from(width));
            member_bytes.push(value as u8);
        }
        produced += run;

        block += 1;
        let last = (produced >= MOST_OUTPUT && written >= floor) || block >= MOST_BLOCKS;
        let how = if last {
            // The stream ends with its last member ended, so no member of
            // it is left declaring bytes the input does not hold.
            BlockEnd::NewMemberNewTables
        } else {
            match pick(3) % 4 {
                0 => BlockEnd::NewMemberNewTables,
                // Never twice running: a stream that resumes inside its
                // block over and over is one long block, and the table
                // boundary this target exists for stops happening. One
                // resume, then a header again.
                1 if !kept => BlockEnd::NewMemberKeepTables,
                _ => BlockEnd::SameMemberNewTables,
            }
        };
        kept = how == BlockEnd::NewMemberKeepTables;
        let (code, width) = codes[usize::from(END_OF_BLOCK)];
        out.put(code, u32::from(width));
        match how {
            BlockEnd::SameMemberNewTables => out.put(1, 1),
            BlockEnd::NewMemberNewTables => {
                out.put(0, 1);
                out.put(1, 1);
            }
            BlockEnd::NewMemberKeepTables => {
                out.put(0, 1);
                out.put(0, 1);
                inside = Some((alphabet, codes));
            }
        }
        if how != BlockEnd::SameMemberNewTables {
            // A member begins at the first bit of its OWN span, so a
            // member boundary is a byte boundary and what is left of the
            // part used byte is never read (SPEC-H1 3.8, and
            // `Bits::begin_member`).
            let end = out.align();
            members.push((member_start..end, member_bytes.len() as u64));
            expected.push(std::mem::take(&mut member_bytes));
            member_start = end;
        }
        if last {
            break;
        }
    }

    Some(Burst {
        packed: out.bytes,
        members,
        expected,
        blocks: written,
        literals: produced as u64,
    })
}

/// A block header and its 404 code lengths (SPEC-H1 3.2 and 3.3).
///
/// The level alphabet is twenty five-bit codes, so a level symbol is its
/// own five-bit value and no run symbol fires; every length is written as
/// the DELTA on the stored one, modulo 16, which is the form the
/// specification states and the only form a keep bit can be checked
/// through.
fn write_block_header(out: &mut BitWriter, wanted: &[u8], stored: &[u8], keep: bool) {
    out.align();
    out.put(0, 1); // an LZ block, not a PPM one
    out.put(u32::from(keep), 1);
    for _ in 0..LEVEL_SYMBOLS {
        out.put(5, 4);
    }
    for (at, &length) in wanted.iter().enumerate() {
        let held = if keep { stored[at] } else { 0 };
        out.put(u32::from((16 + length - held) % 16), 5);
    }
}
