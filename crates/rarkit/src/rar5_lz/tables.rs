//! The code length alphabet, the four table read, and the STRICT canonical
//! prefix code RAR 5 decodes with (SPEC-H2 sections 3.3 and 3.4).
//!
//! **This is not RAR 3's tolerant decoder and must never share a component
//! with it** (section 3.4). RAR 5 refuses an oversubscribed length list at
//! BUILD time and refuses a lookahead that falls in an incomplete list's
//! unused space; RAR 3 answers both. Sharing one component across that line
//! would change the output of malformed RAR 3 archives that the reference
//! and the old engine both decode, so H1's tables live in their own module
//! and this one is reached from nowhere else.
//!
//! A RAR 5 code length also REPLACES where a RAR 3 code length is a DELTA
//! on the length already at that position (section 3.3). The two reads look
//! alike and mean different things; the loop body is not shared either.
//!
//! Implemented from `specs/SPEC-H2-rarkit-rar5-lz.md` alone.

use super::bits::BitReader;
use super::fault;
use super::ladders::{DISTANCE_SLOTS_V0, DISTANCE_SLOTS_V1};
use crate::carry::c_lz::codec::rar50::{
    distance_lut_metadata, HUFF_LUT_BITS, HUFF_LUT_LITERAL_BIT, HUFF_LUT_MISS,
};
use crate::Result;

/// The main alphabet: 256 literals, the filter record, the last length
/// repeat, four repeated distances and 44 fresh match length slots.
pub(crate) const MAIN_SYMBOLS: usize = 306;

/// The length-eight LITERAL codes a main table needs before the serial loop
/// decodes its block seven eight-bit literals a step (`serial_batch`).
///
/// **232, not the 192 it landed with** (the
/// multichannel delta measurement, 28 Sep 2026). A group of seven is taken whole only
/// when all seven codes are length-eight literals, and those hold
/// `literals / 256` of the code space, so at 192 a group is whole about
/// one time in eight and every refused group is work the scalar step then
/// does again. Delta-filtered 16-bit PCM of six and eight channels writes
/// tables of 193 to 228 such literals, and there the batch took 1.32 and
/// 1.36 times the plain loop's instructions over the whole member; blocks
/// of 224 to 231 lost on every layout counted, 232 to 239 were mixed and
/// net ahead, and 240 and up won everywhere (stereo and three- and
/// four-channel audio, 32-bit samples, near-random bytes). At 232 a group
/// is whole about half the time.
pub(crate) const SERIAL_BATCH_LITERALS: usize = 232;
/// The alignment alphabet (section 3.4).
pub(crate) const ALIGN_SYMBOLS: usize = 16;
/// The length alphabet (section 3.5).
pub(crate) const LENGTH_SYMBOLS: usize = 44;
/// The code length alphabet (section 3.3).
pub(crate) const LEVEL_SYMBOLS: usize = 20;
/// The longest code any table may hold: lengths come from a four bit field.
pub(crate) const MAX_CODE_LENGTH: usize = 15;
/// The primary lookup is nine bits wide, so 512 entries per table
/// (section 4.2). The width is carried.
pub(crate) const LUT_ENTRIES: usize = 1 << HUFF_LUT_BITS;

/// A lookup of misses alone: what a region reads an EMPTY table through
/// ([`DecodeTable::region_lookup`]).
#[cfg(feature = "parallel")]
static MISS_LOOKUP: [u32; LUT_ENTRIES] = [HUFF_LUT_MISS; LUT_ENTRIES];
/// The bits of the lookahead past the primary lookup's nine: what the
/// second level indexes by, in whole or in part.
const TAIL_BITS: u32 = LOOKAHEAD_BITS - HUFF_LUT_BITS as u32;
/// How many low bits of an `under` entry hold its block's index width,
/// which is 0 to [`TAIL_BITS`].
const UNDER_WIDTH_BITS: u32 = 3;
const _: () = assert!(TAIL_BITS < (1 << UNDER_WIDTH_BITS));
/// The lookahead the table walk of section 3.4 takes.
pub(crate) const LOOKAHEAD_BITS: u32 = MAX_CODE_LENGTH as u32;

/// How many code lengths one table set holds, by the member's algorithm
/// version (section 3.3): `306 + 64 + 16 + 44` at version 0 and
/// `306 + 80 + 16 + 44` at version 1.
pub(crate) fn total_lengths(algorithm: u8) -> usize {
    MAIN_SYMBOLS + distance_symbols(algorithm) + ALIGN_SYMBOLS + LENGTH_SYMBOLS
}

/// The distance alphabet's size for an algorithm version.
pub(crate) fn distance_symbols(algorithm: u8) -> usize {
    if algorithm == 0 {
        DISTANCE_SLOTS_V0
    } else {
        DISTANCE_SLOTS_V1
    }
}

/// How many runs of symbols [`DecodeTable::build`] tallies and places
/// side by side.
const WAYS: usize = 4;

/// The most entries the second level of a table of `symbols` symbols can
/// hold, the one miss at its front counted: what a table reserves when it
/// is made, so that no build grows it.
///
/// Codes count up with no gap, shorter first (section 3.4), so the long
/// codes fill the nine bit starts they reach one after another. A start
/// whose codes are all of one length holds as many entries as codes. Any
/// other start holds at most `2^6` entries, and there are at most six of
/// those: one where each long length gives way to the next, which is five
/// for the six lengths from ten to fifteen, and the last start, which the
/// codes may leave part empty.
const fn long_most(symbols: usize) -> usize {
    let long_lengths = MAX_CODE_LENGTH - HUFF_LUT_BITS;
    1 + symbols + (long_lengths << TAIL_BITS)
}

/// Write one shelf's short codes: `shelf` is the symbols of `bits` bits in
/// symbol order, `starts` the nine bit starts their codes cover, in order
/// and with no gap, `2^(9 - bits)` of them a code. The count of starts a
/// code covers is fixed by the length, so each length has a loop of its
/// own with that count written in.
#[inline(always)]
fn spread_shelf(starts: &mut [u32], shelf: &[u16], bits: usize, role: Role) {
    const _: () = assert!(HUFF_LUT_BITS == 9);
    match bits {
        9 => spread::<1>(starts, shelf, bits, role),
        8 => spread::<2>(starts, shelf, bits, role),
        7 => spread::<4>(starts, shelf, bits, role),
        6 => spread::<8>(starts, shelf, bits, role),
        5 => spread::<16>(starts, shelf, bits, role),
        4 => spread::<32>(starts, shelf, bits, role),
        3 => spread::<64>(starts, shelf, bits, role),
        2 => spread::<128>(starts, shelf, bits, role),
        _ => spread::<256>(starts, shelf, bits, role),
    }
}

/// [`spread_shelf`] for codes that each cover `SPAN` starts. The entry is
/// [`DecodeTable::entry`]'s, with the role asked once a shelf and not once
/// a symbol.
#[inline(always)]
fn spread<const SPAN: usize>(starts: &mut [u32], shelf: &[u16], bits: usize, role: Role) {
    debug_assert_eq!(SPAN, 1 << (HUFF_LUT_BITS - bits));
    debug_assert_eq!(starts.len(), shelf.len() * SPAN);
    let (groups, _) = starts.as_chunks_mut::<SPAN>();
    let plain = bits as u32;
    match role {
        Role::Main => {
            for (group, &symbol) in groups.iter_mut().zip(shelf) {
                let literal = u32::from(symbol < 256) * HUFF_LUT_LITERAL_BIT;
                *group = [(u32::from(symbol) << 8) | plain | literal; SPAN];
            }
        }
        Role::Distance => {
            for (group, &symbol) in groups.iter_mut().zip(shelf) {
                *group = [(u32::from(symbol) << 8) | plain | distance_lut_metadata(symbol); SPAN];
            }
        }
        Role::Plain => {
            for (group, &symbol) in groups.iter_mut().zip(shelf) {
                *group = [(u32::from(symbol) << 8) | plain; SPAN];
            }
        }
    }
}

/// One alphabet's canonical prefix code, decodable.
///
/// HOW THE TABLE IS HELD is this package's own choice (SPEC-H2 section 2
/// and 1.3.1): the format fixes which symbol a bit pattern is (3.4) and
/// nothing about the holding. It is held in TWO LEVELS, both read by
/// direct index, so no code of any length is found by a walk:
///
/// - the primary lookup answers every code of at most [`HUFF_LUT_BITS`]
///   bits in one load, indexed by the lookahead's first nine bits;
/// - a lookahead whose first nine bits begin a LONGER code (ten to fifteen
///   bits) is answered by a second load: `under` names, for those nine
///   bits, a block of `long` and how many of the bits after the ninth
///   index it, which is as many as the longest code under those nine bits
///   needs and no more.
///
/// A lookahead that begins no code finds the miss sentinel at either
/// level. The entry layout, its literal bit and its distance metadata are
/// carried (`HUFF_LUT_*`, `lut_entry_is_literal`, `distance_lut_metadata`),
/// and both levels hold entries of that one layout.
pub(crate) struct DecodeTable {
    /// Carried layout: symbol in bits 8..=23, code length in the low byte,
    /// literal in bit 31, distance extra bits in 24..=28 and the out of
    /// range flag in bit 30. Zero is the miss sentinel.
    pub(crate) lut: Box<[u32; LUT_ENTRIES]>,
    /// For each nine bit start that begins codes longer than the primary
    /// lookup holds: where its block of `long` starts, shifted up by
    /// [`UNDER_WIDTH_BITS`], over how many bits past the ninth index the
    /// block. Zero for every other start: block 0 of width 0, which is
    /// `long`'s first entry, always a miss. Written by `build` from the
    /// first start the short codes do not cover; the starts below that
    /// are answered by the primary lookup and never read here.
    under: Box<[u32; LUT_ENTRIES]>,
    /// The second level's entries: one miss, then a block for each nine
    /// bit start that `under` names. Its whole room ([`long_most`]) is
    /// taken when the table is made ([`DecodeTable::holding`]), so no
    /// build takes memory for it, the first included.
    long: Vec<u32>,
    /// The first code of each length, as a number of that many bits
    /// (section 3.4: codes are given out shorter first, each length's in
    /// symbol order, counting up).
    first_code: [u16; MAX_CODE_LENGTH + 1],
    /// Where each length's symbols start in `symbols`; the entry past the
    /// last length is the count of coded symbols.
    rank: [u16; MAX_CODE_LENGTH + 2],
    /// Symbols in canonical order: by length, then by symbol number. Room
    /// for the whole alphabet is taken when the table is made, as `long`'s
    /// is.
    symbols: Vec<u16>,
    /// A table with no symbols at all answers `EmptyTable` (section 3.4).
    empty: bool,
    /// What the entries of this table carry beyond symbol and length.
    role: Role,
    /// The longest code the table holds. A lookahead with at least this
    /// many bits left has seen every code there is, so failing to match is
    /// the incomplete table's unused space and not a short block.
    max_length: usize,
    /// The shortest code of a LITERAL (a symbol below 256), or 0 with no
    /// literal coded. A literal consumes at least this many bits, which
    /// is what bounds how many a block can hold (`tape::fast_region`).
    shortest_literal: u8,
    /// A main table's CONTROL MASS: the Kraft sum of its control symbols'
    /// codes (256 and up), `2^-length` each, in units of `2^-15`; 0 for
    /// every other role. The share of the code space the writer gave to
    /// matches, repeats and filters, so an estimate of how many symbols in
    /// a block are control symbols. The tape decode chooses its fast region
    /// by it (`tape::LEVER_MASS_FLOOR`).
    control_mass: u32,
}

impl DecodeTable {
    /// A table with no code yet, HOLDING ALL THE MEMORY a build of any
    /// list of at most `symbols` lengths writes: the two lookups, the
    /// alphabet's symbols and the second level at its most
    /// ([`long_most`]). Section 4.2 wants no allocation per block, and a
    /// build is per block: what a table needs it takes here, once, and
    /// [`DecodeTable::build`] takes nothing, whatever was built before.
    ///
    /// A list longer than `symbols` still builds; that build grows the
    /// table's lists, and no caller in the engine passes one.
    pub(crate) fn holding(symbols: usize) -> DecodeTable {
        DecodeTable {
            lut: Box::new([HUFF_LUT_MISS; LUT_ENTRIES]),
            under: Box::new([0; LUT_ENTRIES]),
            long: Vec::with_capacity(long_most(symbols)),
            first_code: [0; MAX_CODE_LENGTH + 1],
            rank: [0; MAX_CODE_LENGTH + 2],
            symbols: Vec::with_capacity(symbols),
            empty: true,
            role: Role::Plain,
            max_length: 0,
            shortest_literal: 0,
            control_mass: 0,
        }
    }
}

/// A table that holds the largest alphabet's memory, the main one's, so it
/// serves any of the five.
impl Default for DecodeTable {
    fn default() -> DecodeTable {
        DecodeTable::holding(MAIN_SYMBOLS)
    }
}

/// What extra metadata a table's lookup entries carry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// The main alphabet: literals are marked in bit 31, so a burst takes
    /// its literal class from the entry rather than from a comparison per
    /// symbol (section 7.3 item 5).
    Main,
    /// The distance alphabet: the slot's extra bit count and its out of
    /// range flag ride in the entry, so a match reads one table and not two
    /// (section 7.3 item 6).
    Distance,
    /// Nothing extra.
    Plain,
}

impl DecodeTable {
    /// The places in `symbols` of the codes of `length` bits.
    #[inline(always)]
    fn shelf_of(&self, length: usize) -> core::ops::Range<usize> {
        usize::from(self.rank[length])..usize::from(self.rank[length + 1])
    }

    /// Build from a list of code lengths, each 0 to 15 (section 3.4).
    ///
    /// Refuses an oversubscribed list at build time. An INCOMPLETE list is
    /// accepted: an archive whose tables have a hole its codes never reach
    /// decodes under the reference too, and refusing here would fail
    /// archives the reference extracts.
    // Canonical codes of one length are sorted by symbol. The Nth entry
    // is a literal iff at least N length-eight literals exist, which is
    // how `serial_literal_admitted` asks for `SERIAL_BATCH_LITERALS`.
    #[inline]
    pub(crate) fn serial_single_gap(&self) -> Option<u8> {
        let eights = self.shelf_of(8);
        let (start, count) = (eights.start, eights.len());
        if count < 255
            || self.symbols[start + 254] >= 256
            || (count > 255 && self.symbols[start + 255] < 256)
        {
            return None;
        }
        // 255 codes of eight bits leave room for none shorter.
        debug_assert_eq!(self.first_code[8], 0);
        // The 255 sorted literal symbols are 0..256 with one omission.
        // Find the first rank no longer equal to its symbol, or 255.
        let mut low = 0usize;
        let mut high = 255usize;
        while low < high {
            let middle = (low + high) / 2;
            if usize::from(self.symbols[start + middle]) == middle {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        Some(low as u8)
    }

    /// THE FULL-BYTE SHAPE: all 256 literals coded in exactly eight bits.
    /// They fill the code space, so no other symbol has a code and none is
    /// shorter; under section 3.4's canonical assignment code `c` is then
    /// literal `c`, and every eight bits of the block's symbols is one
    /// literal. The single-gap shape's escape does not exist here, which is
    /// why [`DecodeTable::serial_single_gap`] answers `None` for it.
    // Canonical codes of one length are sorted by symbol, so the shelf's
    // 256th entry is a literal only if all 256 are.
    #[inline]
    pub(crate) fn serial_full_byte(&self) -> bool {
        let eights = self.shelf_of(8);
        eights.len() == 256 && self.symbols[eights.start + 255] < 256
    }

    pub(crate) fn serial_literal_interval(&self) -> (u64, u64) {
        let literals = self.symbols[self.shelf_of(8)].partition_point(|&s| s < 256);
        let first = u64::from(self.first_code[8]);
        (first, first + literals as u64)
    }

    pub(crate) fn serial_literal_admitted(&self) -> bool {
        let eights = self.shelf_of(8);
        eights.len() >= SERIAL_BATCH_LITERALS
            && self
                .symbols
                .get(eights.start + SERIAL_BATCH_LITERALS - 1)
                .is_some_and(|&symbol| symbol < 256)
    }

    pub(crate) fn build(&mut self, lengths: &[u8], role: Role) -> Result<()> {
        // HOW MANY SYMBOLS HAVE EACH LENGTH, COUNTED IN FOUR TALLIES. A
        // tally bumped twice running for the same length waits for its own
        // last store, and a list of a big member's or of noise's literals is one
        // length 250 times over. So the list is cut into four runs of
        // symbols, each with a tally of its own, walked side by side: four
        // short chains for one long one. The runs are CONTIGUOUS, so that
        // the placing below can keep each length's symbols in symbol order.
        // (Counting a histogram in several tables is the common way to cut
        // that chain; it is no property of the format.)
        //
        // A length above 15 cannot come from a four bit field; it is
        // refused as a list no code fits. Every length is gathered into
        // `seen`, which is above 15 exactly when one of them is, and a
        // tally is indexed by a length's low four bits, so no symbol is
        // tested by itself.
        let run = lengths.len() / WAYS;
        let (first, rest) = lengths.split_at(run);
        let (second, rest) = rest.split_at(run);
        let (third, last) = rest.split_at(run);
        let (fourth, spare) = last.split_at(run);
        let mut tally = [[0u16; MAX_CODE_LENGTH + 1]; WAYS];
        let mut seen = 0u8;
        for at in 0..run {
            let lengths = [first[at], second[at], third[at], fourth[at]];
            for way in 0..WAYS {
                seen |= lengths[way];
                tally[way][usize::from(lengths[way]) & MAX_CODE_LENGTH] += 1;
            }
        }
        for &length in spare {
            seen |= length;
            tally[WAYS - 1][usize::from(length) & MAX_CODE_LENGTH] += 1;
        }
        if usize::from(seen) > MAX_CODE_LENGTH {
            return Err(fault::oversubscribed());
        }
        let mut count = [0u16; MAX_CODE_LENGTH + 1];
        for length in 1..=MAX_CODE_LENGTH {
            count[length] = tally.iter().map(|way| way[length]).sum();
        }
        // Section 3.4's count of the code space, and with it each length's
        // first code and its symbols' place in canonical order: one code
        // available, doubled at each step to a longer length and spent by
        // that length's symbols.
        let mut first_code = [0u16; MAX_CODE_LENGTH + 1];
        let mut rank = [0u16; MAX_CODE_LENGTH + 2];
        let mut unspent: u32 = 1;
        let mut code: u32 = 0;
        let mut coded: u16 = 0;
        let mut max_length = 0;
        for length in 1..=MAX_CODE_LENGTH {
            let here = count[length];
            unspent <<= 1;
            if u32::from(here) > unspent {
                return Err(fault::oversubscribed());
            }
            unspent -= u32::from(here);
            code <<= 1;
            first_code[length] = code as u16;
            rank[length] = coded;
            code += u32::from(here);
            coded += here;
            if here != 0 {
                max_length = length;
            }
        }
        rank[MAX_CODE_LENGTH + 1] = coded;
        self.first_code = first_code;
        self.rank = rank;
        self.role = role;
        self.max_length = max_length;
        self.shortest_literal = 0;
        self.control_mass = 0;
        self.symbols.clear();
        self.empty = coded == 0;
        if self.empty {
            // A list with no code: nothing reads its lookups (`lookup`'s
            // empty test, `region_lookup`), so they are not written.
            return Ok(());
        }
        // PLACED IN CANONICAL ORDER, the four runs side by side again. Each
        // run's symbols of a length go after the same length's symbols of
        // the runs before it, so a length's shelf is in symbol order. A
        // symbol with no code is placed too, past the last coded one, and
        // cut off after: the placing asks nothing of a symbol.
        self.symbols.resize(lengths.len(), 0);
        let mut next = [[0u16; MAX_CODE_LENGTH + 1]; WAYS];
        for length in 0..=MAX_CODE_LENGTH {
            let mut at = if length == 0 { coded } else { rank[length] };
            for way in 0..WAYS {
                next[way][length] = at;
                at += tally[way][length];
            }
        }
        {
            let placed = &mut self.symbols[..];
            for at in 0..run {
                let lengths = [first[at], second[at], third[at], fourth[at]];
                for way in 0..WAYS {
                    let slot = &mut next[way][usize::from(lengths[way]) & MAX_CODE_LENGTH];
                    placed[usize::from(*slot)] = (way * run + at) as u16;
                    *slot += 1;
                }
            }
            for (at, &length) in spare.iter().enumerate() {
                let slot = &mut next[WAYS - 1][usize::from(length) & MAX_CODE_LENGTH];
                placed[usize::from(*slot)] = (WAYS * run + at) as u16;
                *slot += 1;
            }
        }
        self.symbols.truncate(usize::from(coded));

        // The nine bit starts the short codes cover are the first `covered`
        // of them, with no gap: codes count up from zero, shorter first.
        // Every start past them begins a longer code or no code at all.
        let short_top = MAX_CODE_LENGTH.min(HUFF_LUT_BITS);
        let covered = (usize::from(first_code[short_top]) + usize::from(count[short_top]))
            << (HUFF_LUT_BITS - short_top);
        self.lut[covered..].fill(HUFF_LUT_MISS);
        self.under[covered..].fill(0);

        // THE SHORT CODES, A LENGTH AT A TIME. Codes count up through the
        // shelves in canonical order, so the starts they cover follow one
        // another with no gap: each shelf's entries are written straight
        // on from the shelf before, every code over as many starts as its
        // length leaves, a number fixed for the whole shelf.
        let mut shortest_literal = 0u8;
        let mut control_mass = 0u32;
        let mut start = 0usize;
        for bits in 1..=max_length {
            let shelf = &self.symbols[usize::from(rank[bits])..usize::from(rank[bits + 1])];
            if shelf.is_empty() {
                continue;
            }
            // A shelf is in symbol order, so its literals lead it.
            if shortest_literal == 0 && shelf[0] < 256 {
                shortest_literal = bits as u8;
            }
            if role == Role::Main {
                let controls = shelf.len() - shelf.partition_point(|&symbol| symbol < 256);
                control_mass += (controls as u32) << (MAX_CODE_LENGTH - bits);
            }
            if bits <= HUFF_LUT_BITS {
                let end = start + (shelf.len() << (HUFF_LUT_BITS - bits));
                spread_shelf(&mut self.lut[start..end], shelf, bits, role);
                start = end;
            }
        }
        debug_assert_eq!(start, covered);
        self.shortest_literal = shortest_literal;
        self.control_mass = control_mass;

        self.long.clear();
        self.long.push(HUFF_LUT_MISS);
        if max_length <= HUFF_LUT_BITS {
            return Ok(());
        }
        // THE SECOND LEVEL. First, how wide each start's block is: the
        // longest code under it, less the nine bits already spent. Codes
        // count up with their length, so the last code met under a start
        // is its longest.
        for bits in HUFF_LUT_BITS + 1..=max_length {
            let codes = usize::from(first_code[bits])
                ..usize::from(first_code[bits]) + usize::from(count[bits]);
            for code in codes {
                self.under[code >> (bits - HUFF_LUT_BITS)] = (bits - HUFF_LUT_BITS) as u32;
            }
        }
        // Then where each block starts, after the one miss at the front.
        let mut total = 1usize;
        for under in &mut self.under[covered..] {
            let width = *under;
            if width != 0 {
                *under = ((total as u32) << UNDER_WIDTH_BITS) | width;
                total += 1 << width;
            }
        }
        self.long.resize(total, HUFF_LUT_MISS);
        // Then each long code's entry, over every index of its start's
        // block that it is a prefix of.
        for bits in HUFF_LUT_BITS + 1..=max_length {
            let past = bits - HUFF_LUT_BITS;
            let first = usize::from(first_code[bits]);
            for (place, &symbol) in self.symbols
                [usize::from(rank[bits])..usize::from(rank[bits + 1])]
                .iter()
                .enumerate()
            {
                let code = first + place;
                let under = self.under[code >> past];
                let width = (under & ((1 << UNDER_WIDTH_BITS) - 1)) as usize;
                let block = (under >> UNDER_WIDTH_BITS) as usize;
                let tail = code & ((1 << past) - 1);
                let span = 1usize << (width - past);
                let start = block + (tail << (width - past));
                self.long[start..start + span].fill(Self::entry(usize::from(symbol), bits, role));
            }
        }
        Ok(())
    }

    /// One lookup entry, in the carried layout.
    fn entry(symbol: usize, length: usize, role: Role) -> u32 {
        let mut entry = ((symbol as u32) << 8) | length as u32;
        match role {
            // RAR control symbols begin at 256; everything below is a byte
            // to put (section 3.5).
            Role::Main if symbol < 256 => entry |= HUFF_LUT_LITERAL_BIT,
            Role::Distance => entry |= distance_lut_metadata(symbol as u16),
            _ => {}
        }
        entry
    }

    /// Decode one symbol (section 3.4).
    ///
    /// Takes the next 15 bits as a lookahead, most significant first, and
    /// answers the first length whose assigned range the lookahead's top
    /// bits fall in. `InvalidCode` when no length matches; `EmptyTable`
    /// when the table has no symbols, consuming nothing; `Truncated` when
    /// the code that matched needs more bits than the block has left.
    #[inline(always)]
    pub(crate) fn decode(&self, bits: &mut BitReader<'_>) -> Result<usize> {
        let entry = self.lookup(bits)?;
        Ok(super::lut_symbol(entry))
    }

    /// [`DecodeTable::decode`], answering the whole lookup entry so a
    /// caller can read its literal bit or its distance metadata without a
    /// second table.
    #[inline(always)]
    pub(crate) fn lookup(&self, bits: &mut BitReader<'_>) -> Result<u32> {
        if self.empty {
            return Err(fault::empty_table());
        }
        let look = bits.peek_code();
        let entry = self.lut[(look >> (LOOKAHEAD_BITS - HUFF_LUT_BITS as u32)) as usize];
        if entry != HUFF_LUT_MISS {
            let length = entry & 0xff;
            if bits.remaining() < length as usize {
                return Err(fault::truncated());
            }
            bits.advance_buffered(length);
            return Ok(entry);
        }
        let entry = self.lookup_long(look, bits.remaining())?;
        bits.advance_buffered(entry & 0xff);
        Ok(entry)
    }

    /// Whether the table has no symbols, so every lookup answers
    /// `EmptyTable` (section 3.4). Its one caller is the tape decode, which
    /// the `parallel` feature carries.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn is_empty(&self) -> bool {
        self.empty
    }

    /// How many LITERALS (symbols below 256) this table codes in exactly
    /// `length` bits. Canonical order sorts a length's symbols by number,
    /// so its literals lead and a binary search counts them. Its one caller
    /// is the tape decode's literal batch gate (`tape::batch::admits`).
    #[cfg(feature = "parallel")]
    pub(crate) fn literals_of_length(&self, length: usize) -> usize {
        self.symbols
            .get(self.shelf_of(length))
            .map_or(0, |codes| codes.partition_point(|&symbol| symbol < 256))
    }

    /// [`DecodeTable::lookup`] for a table the caller has ALREADY found
    /// non-empty ([`DecodeTable::is_empty`]): the same body without the
    /// empty test.
    ///
    /// **Why a loop asks once.** The tape decode's symbol loop asks every
    /// lookup of the same table, and whether that test stays out of the
    /// loop was the compiler's choice: the release build hoisted it, and a
    /// profile-guided build left it in, a load and a branch on every
    /// symbol, which a member of nothing but literals pays once per byte
    /// (24 Sep 2026, the `decode_one` literal path).
    /// Asked once before the loop, it is no longer the compiler's to move.
    ///
    /// **A copy of `lookup`'s body, not a call from it, on purpose.**
    /// `lookup` is inlined into every serial decode loop, and a profile
    /// sees the functions it is built from: written as the test plus a
    /// call to this, it read the same in a release build and cost the
    /// serial path of small non-solid members 6 to 8 percent of
    /// instructions under a profile (the screen of 24 Sep 2026, `V1`).
    /// `lookup` is left exactly as it was.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn lookup_filled(&self, bits: &mut BitReader<'_>) -> Result<u32> {
        debug_assert!(!self.empty);
        let look = bits.peek_code();
        let entry = self.lut[(look >> (LOOKAHEAD_BITS - HUFF_LUT_BITS as u32)) as usize];
        if entry != HUFF_LUT_MISS {
            let length = entry & 0xff;
            if bits.remaining() < length as usize {
                return Err(fault::truncated());
            }
            bits.advance_buffered(length);
            return Ok(entry);
        }
        let entry = self.lookup_long(look, bits.remaining())?;
        bits.advance_buffered(entry & 0xff);
        Ok(entry)
    }

    /// The main table's control mass ([`DecodeTable::control_mass`] the
    /// field), in units of `2^-15`.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn control_mass(&self) -> u32 {
        self.control_mass
    }

    /// The shortest literal code's length, 0 with no literal coded
    /// (`shortest_literal`). Its one caller is the tape decode's fast
    /// region, which the `parallel` feature carries.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn shortest_literal(&self) -> u32 {
        u32::from(self.shortest_literal)
    }

    /// [`DecodeTable::lookup`] for a caller inside the reader's fast region
    /// (`bits.rs`, "THE FAST REGION"): the same entry, with the truncation
    /// test gone, because no code can pass the block's end there, and the
    /// advance the region's. The empty test stays: the distance, alignment
    /// and length tables are asked through this with nothing asked before.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn lookup_in_region(&self, bits: &mut BitReader<'_>) -> Result<u32> {
        if self.empty {
            return Err(fault::empty_table());
        }
        self.lookup_filled_in_region(bits)
    }

    /// [`DecodeTable::lookup_in_region`] for a table already found
    /// non-empty: the main table, asked once before the loop.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn lookup_filled_in_region(&self, bits: &mut BitReader<'_>) -> Result<u32> {
        debug_assert!(!self.empty);
        let look = bits.peek_code_in_region();
        let entry = self.lut[(look >> (LOOKAHEAD_BITS - HUFF_LUT_BITS as u32)) as usize];
        if entry != HUFF_LUT_MISS {
            bits.advance_in_region(entry & 0xff);
            return Ok(entry);
        }
        // Inside the region the block has more than 15 bits left, so the
        // walk's own answer is the hole and never `Truncated`; `remaining`
        // is passed all the same, so the cold walk is the one function.
        let entry = self.lookup_long(look, bits.remaining())?;
        bits.advance_in_region(entry & 0xff);
        Ok(entry)
    }

    /// THE LOOKUP A REGION READS THIS TABLE THROUGH, asked once a block
    /// (lever 4 of the fresh match): the table's own, or for
    /// a table with NO symbols the shared [`MISS_LOOKUP`], every entry a
    /// miss. An empty table's own lookup is never written (see `build`),
    /// so it cannot stand in; the shared one sends every code to the cold
    /// walk, which answers `EmptyTable` for an empty table
    /// ([`DecodeTable::lookup_long`]) exactly where the `empty` test used to
    /// answer it, and a lookup through this carries no test of its own.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn region_lookup(&self) -> &[u32; LUT_ENTRIES] {
        if self.empty {
            &MISS_LOOKUP
        } else {
            &self.lut
        }
    }

    /// [`DecodeTable::lookup_in_region`] through `lut`, this table's
    /// [`DecodeTable::region_lookup`], with the code consumed by
    /// [`BitReader::advance_raw_in_region`]: no empty test and no refill
    /// test, for a caller that has ensured 15 bits and restores the
    /// watermark itself (the fresh match's one refill,
    /// `tape::fresh_match_in_region`).
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn lookup_raw_in_region(
        &self,
        lut: &[u32; LUT_ENTRIES],
        bits: &mut BitReader<'_>,
    ) -> Result<u32> {
        let look = bits.peek_code_in_region();
        let entry = lut[(look >> (LOOKAHEAD_BITS - HUFF_LUT_BITS as u32)) as usize];
        if entry != HUFF_LUT_MISS {
            bits.advance_raw_in_region(entry & 0xff);
            return Ok(entry);
        }
        let entry = self.lookup_long(look, bits.remaining())?;
        bits.advance_raw_in_region(entry & 0xff);
        Ok(entry)
    }

    /// The codes the primary lookup does not cover: lengths 10 to 15.
    ///
    /// Answers the ENTRY, whose low byte is the code's length, and leaves
    /// consuming it to the caller. **It takes no reader on purpose**: a
    /// cold call that receives the reader's address makes the address
    /// escape, and a reader whose address escapes lives in memory for the
    /// whole of the loop that holds it, which is the store and reload per
    /// symbol `decode_block`'s comment describes.
    ///
    /// An EMPTY table answers `EmptyTable` here, first: a region reaches an
    /// empty table's walk through [`MISS_LOOKUP`] (every other caller has
    /// asked `empty` before its lookup, and never gets here with one).
    #[cold]
    fn lookup_long(&self, look: u32, remaining: usize) -> Result<u32> {
        if self.empty {
            return Err(fault::empty_table());
        }
        // The second level, by direct index: the lookahead's first nine
        // bits name a block and its width, and that many of the bits after
        // them name the entry. A start that begins no long code names the
        // one miss at the front.
        let under = self.under[(look >> TAIL_BITS) as usize];
        let width = under & ((1 << UNDER_WIDTH_BITS) - 1);
        let tail = (look & ((1 << TAIL_BITS) - 1)) >> (TAIL_BITS - width);
        let entry = self
            .long
            .get((under >> UNDER_WIDTH_BITS) as usize + tail as usize)
            .copied()
            .unwrap_or(HUFF_LUT_MISS);
        if entry == HUFF_LUT_MISS {
            // No code begins these bits. With every code's worth of bits
            // still in the block that is the list's unused space (section
            // 3.4); with fewer, the block ended inside a symbol.
            return Err(if remaining >= self.max_length {
                fault::invalid_code()
            } else {
                fault::truncated()
            });
        }
        if remaining < (entry & 0xff) as usize {
            return Err(fault::truncated());
        }
        Ok(entry)
    }
}

/// The four alphabets of one block (section 2).
pub(crate) struct Tables {
    pub(crate) main: DecodeTable,
    pub(crate) distance: DecodeTable,
    pub(crate) align: DecodeTable,
    pub(crate) length: DecodeTable,
}

/// Each table holding its own alphabet's memory ([`DecodeTable::holding`]),
/// the distance table the larger of the two versions' (section 3.3).
impl Default for Tables {
    fn default() -> Tables {
        Tables {
            main: DecodeTable::holding(MAIN_SYMBOLS),
            distance: DecodeTable::holding(DISTANCE_SLOTS_V1),
            align: DecodeTable::holding(ALIGN_SYMBOLS),
            length: DecodeTable::holding(LENGTH_SYMBOLS),
        }
    }
}

/// Scratch the table read fills, reused across blocks so no block allocates
/// (section 4.2: no allocation per member, per block or per symbol).
pub(crate) struct TableScratch {
    levels: [u8; LEVEL_SYMBOLS],
    level_table: DecodeTable,
    lengths: Vec<u8>,
}

impl Default for TableScratch {
    fn default() -> TableScratch {
        // Room for the level code and for the longer of the two versions'
        // lists, so the first read takes nothing either.
        const _: () = assert!(DISTANCE_SLOTS_V1 >= DISTANCE_SLOTS_V0);
        TableScratch {
            levels: [0; LEVEL_SYMBOLS],
            level_table: DecodeTable::holding(LEVEL_SYMBOLS),
            lengths: Vec::with_capacity(
                MAIN_SYMBOLS + DISTANCE_SLOTS_V1 + ALIGN_SYMBOLS + LENGTH_SYMBOLS,
            ),
        }
    }
}

impl TableScratch {
    /// The code lengths the last [`Tables::read`] took, all four alphabets
    /// in their stream order (section 3.3). For the bench internals' block
    /// shape count and the table census (`internals_h2::table_census`).
    #[cfg(feature = "bench-internals")]
    pub(crate) fn lengths(&self) -> &[u8] {
        &self.lengths
    }
}

impl Tables {
    /// Read a block's tables from the front of its payload (section 3.3).
    pub(crate) fn read(
        &mut self,
        bits: &mut BitReader<'_>,
        algorithm: u8,
        scratch: &mut TableScratch,
    ) -> Result<()> {
        read_sending_code(bits, &mut scratch.levels)?;
        scratch.level_table.build(&scratch.levels, Role::Plain)?;

        let total = total_lengths(algorithm);
        scratch.lengths.clear();
        scratch.lengths.reserve(total);
        read_lengths(bits, &scratch.level_table, total, &mut scratch.lengths)?;

        let distance = distance_symbols(algorithm);
        let (main, rest) = scratch.lengths.split_at(MAIN_SYMBOLS);
        let (dist, rest) = rest.split_at(distance);
        let (align, length) = rest.split_at(ALIGN_SYMBOLS);
        self.main.build(main, Role::Main)?;
        self.distance.build(dist, Role::Distance)?;
        self.align.build(align, Role::Plain)?;
        self.length.build(length, Role::Plain)?;
        Ok(())
    }
}

/// Bits in one field of the twenty that open a block's tables (section
/// 3.3).
const FIELD_BITS: u32 = 4;

/// The field value that is not a length by itself: one more field, `z`,
/// follows it and says what it stands for.
const FIELD_ESCAPES: u8 = 15;

/// Read the twenty lengths a block's tables open with: those of the code
/// the other lengths are sent in (section 3.3).
///
/// Each step takes one 4 bit field and says what to write and how many
/// times. A field below 15 is one length, itself. A field of 15 takes a
/// second field `z`: a `z` of 0 is one length of 15, and any other `z` is
/// `z + 2` lengths of 0. A run of zeros that would pass the twentieth
/// length stops at the twentieth and is not an error. Every one of the
/// twenty places is written, so what `twenty` held before does not matter.
fn read_sending_code(bits: &mut BitReader<'_>, twenty: &mut [u8; LEVEL_SYMBOLS]) -> Result<()> {
    let mut written = 0;
    while written < LEVEL_SYMBOLS {
        let field = bits.take(FIELD_BITS)? as u8;
        let (length, times) = if field < FIELD_ESCAPES {
            (field, 1)
        } else {
            match bits.take(FIELD_BITS)? as usize {
                0 => (FIELD_ESCAPES, 1),
                z => (0, z + 2),
            }
        };
        // `take` is what stops a run at the twentieth place.
        for place in twenty.iter_mut().skip(written).take(times) {
            *place = length;
        }
        written += times;
    }
    Ok(())
}

/// What a run of the level code writes (section 3.3's table, its last
/// column).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fill {
    /// The length before the run, the list's last entry as the run starts.
    LengthBefore,
    /// Zero.
    Zero,
}

/// One run symbol of the level code, as section 3.3's table gives it.
struct Run {
    /// Bits read after the symbol, as `k`.
    extra_bits: u32,
    /// The run's length at `k` of 0; the run is this plus `k`.
    shortest: usize,
    fill: Fill,
}

/// The level code's first run symbol: the symbols below it are lengths.
const FIRST_RUN_SYMBOL: usize = 16;

/// The four run symbols as data, one row each for 16, 17, 18 and 19 in
/// that order, from section 3.3's table as it stands (section 1.3.1, rule
/// R2).
const RUNS: [Run; 4] = [
    Run {
        extra_bits: 3,
        shortest: 3,
        fill: Fill::LengthBefore,
    },
    Run {
        extra_bits: 7,
        shortest: 11,
        fill: Fill::LengthBefore,
    },
    Run {
        extra_bits: 3,
        shortest: 3,
        fill: Fill::Zero,
    },
    Run {
        extra_bits: 7,
        shortest: 11,
        fill: Fill::Zero,
    },
];

/// The `total` lengths of a block's four alphabets, read in the level code
/// into `list` as ONE list (section 3.3).
///
/// A symbol below [`FIRST_RUN_SYMBOL`] is the next length. Any other is a
/// run, and one piece of text serves all four of [`RUNS`]: read the row's
/// bits as `k`, cut the run of shortest plus `k` at the end of the list,
/// fill. A run that would pass the end stops there and is not an error.
/// The one test that is not data is `RepeatAtStart`: a row whose fill is
/// the length before, met while the list is still empty.
fn read_lengths(
    bits: &mut BitReader<'_>,
    levels: &DecodeTable,
    total: usize,
    list: &mut Vec<u8>,
) -> Result<()> {
    while list.len() < total {
        let symbol = levels.decode(bits)?;
        let Some(row) = symbol.checked_sub(FIRST_RUN_SYMBOL) else {
            list.push(symbol as u8);
            continue;
        };
        // The level code has twenty symbols, so no stream reaches this
        // refusal (section 3.3).
        let Some(run) = RUNS.get(row) else {
            return Err(fault::level_symbol());
        };
        let fill = match (run.fill, list.last()) {
            (Fill::Zero, _) => 0,
            (Fill::LengthBefore, Some(&before)) => before,
            (Fill::LengthBefore, None) => return Err(fault::repeat_at_start()),
        };
        let k = bits.take(run.extra_bits)? as usize;
        let left = total - list.len();
        list.resize(list.len() + (run.shortest + k).min(left), fill);
    }
    Ok(())
}

#[cfg(test)]
mod level_runs {
    use super::super::vectors::BlockBuilder;
    use super::*;

    /// A level code in which every one of the twenty symbols is five bits
    /// wide, so a symbol's code is its own number (section 3.4).
    fn levels() -> DecodeTable {
        let mut table = DecodeTable::default();
        table.build(&[5; LEVEL_SYMBOLS], Role::Plain).unwrap();
        table
    }

    /// Read `total` lengths from `(value, width)` fields written most
    /// significant bit first.
    fn read(fields: &[(u32, u32)], total: usize) -> Result<Vec<u8>> {
        let mut stream = BlockBuilder::default();
        for &(value, width) in fields {
            stream.raw(value, width);
        }
        let (bytes, nbits) = stream.body_bits();
        let mut bits = BitReader::new(bytes, nbits);
        let mut list = Vec::new();
        read_lengths(&mut bits, &levels(), total, &mut list)?;
        assert_eq!(bits.position(), nbits, "every field was read, and no more");
        Ok(list)
    }

    /// Section 1.3.1, rule R2: the four rows are section 3.3's table as it
    /// stands, for 16, 17, 18 and 19 in that order.
    #[test]
    fn the_four_rows_are_section_3_3_s_table() {
        let rows: Vec<(u32, usize, Fill)> = RUNS
            .iter()
            .map(|run| (run.extra_bits, run.shortest, run.fill))
            .collect();
        assert_eq!(
            rows,
            [
                (3, 3, Fill::LengthBefore),
                (7, 11, Fill::LengthBefore),
                (3, 3, Fill::Zero),
                (7, 11, Fill::Zero),
            ]
        );
        assert_eq!(FIRST_RUN_SYMBOL + RUNS.len(), LEVEL_SYMBOLS);
    }

    /// Section 3.3: each run symbol with `k` at 0 and at its largest
    /// writes shortest plus `k` entries of its fill, after a length of 9
    /// that the repeating rows repeat and the zero rows do not.
    #[test]
    fn each_run_symbol_writes_its_run_at_both_ends_of_k() {
        for (row, run) in RUNS.iter().enumerate() {
            let symbol = (FIRST_RUN_SYMBOL + row) as u32;
            let filled = if run.fill == Fill::Zero { 0 } else { 9 };
            for k in [0, (1u32 << run.extra_bits) - 1] {
                let length = run.shortest + k as usize;
                // 9, the run, then a 4 that shows where the run ended.
                let got = read(
                    &[(9, 5), (symbol, 5), (k, run.extra_bits), (4, 5)],
                    length + 2,
                );
                let mut want = vec![9u8];
                want.resize(1 + length, filled);
                want.push(4);
                assert_eq!(got.unwrap(), want, "symbol {symbol}, k {k}");
            }
        }
        // The longest run of all, by number: 11 + 127.
        assert_eq!(RUNS[3].shortest + 127, 138);
    }

    /// Section 3.3: a run that would pass the end of the list stops at
    /// the end and is not an error, whichever row it is; and a run that
    /// follows another repeats what that one wrote.
    #[test]
    fn a_run_is_cut_at_the_end_of_the_list() {
        for (row, run) in RUNS.iter().enumerate() {
            let symbol = (FIRST_RUN_SYMBOL + row) as u32;
            let filled = if run.fill == Fill::Zero { 0 } else { 7 };
            let k = (1u32 << run.extra_bits) - 1;
            let got = read(&[(7, 5), (symbol, 5), (k, run.extra_bits)], 3).unwrap();
            assert_eq!(got, [7, filled, filled], "symbol {symbol}");
        }
        // 18 at k = 0 writes three zeros; 16 at k = 0 then repeats a zero.
        let got = read(&[(6, 5), (18, 5), (0, 3), (16, 5), (0, 3)], 7).unwrap();
        assert_eq!(got, [6, 0, 0, 0, 0, 0, 0]);
    }

    /// Section 3.3: 16 or 17 with no length before it is `RepeatAtStart`,
    /// and the refusal comes before the row's bits are asked for; 18 and
    /// 19 as the first symbol are plain runs of zeros.
    #[test]
    fn a_repeat_with_no_length_before_it_is_refused_and_a_zero_run_is_not() {
        for symbol in [16u32, 17] {
            // No bits of `k` follow at all: the refusal is not `Truncated`.
            let error = read(&[(symbol, 5)], 40).unwrap_err();
            assert!(
                format!("{error:?}").contains("RepeatAtStart"),
                "symbol {symbol}: {error:?}"
            );
        }
        assert_eq!(read(&[(18, 5), (1, 3)], 4).unwrap(), [0; 4]);
        assert_eq!(read(&[(19, 5), (2, 7)], 13).unwrap(), [0; 13]);
    }
}

#[cfg(test)]
mod fused_kraft {
    use super::*;

    /// The separate pass `build` used before the check moved into the
    /// assignment loop: one code available at length 0, doubled at each
    /// step and spent by that length's codes.
    fn oversubscribed(lengths: &[u8]) -> bool {
        let mut counts = [0i64; MAX_CODE_LENGTH + 1];
        for &length in lengths {
            if length as usize > MAX_CODE_LENGTH {
                return true;
            }
            if length != 0 {
                counts[length as usize] += 1;
            }
        }
        // Section 3.4, taken whole: a symbol of length `n` takes one part in
        // `2^n` of the code space, and the list is oversubscribed when its
        // symbols take more than all of it. Counted in parts of `2^-15`,
        // the longest code's share, so every term is a whole number. A
        // share spent at one length is never given back at a longer one,
        // so this refuses exactly the lists the step by step count does.
        let whole = 1i64 << MAX_CODE_LENGTH;
        let taken: i64 = (1..=MAX_CODE_LENGTH)
            .map(|length| counts[length] << (MAX_CODE_LENGTH - length))
            .sum();
        if taken > whole {
            return true;
        }
        false
    }

    fn check(table: &mut DecodeTable, lengths: &[u8], role: Role) {
        let refused = table.build(lengths, role).is_err();
        assert_eq!(refused, oversubscribed(lengths), "{lengths:?}");
        // A table that refused one list still builds the next.
        table.build(&[1, 1], role).unwrap();
        assert!(!table.empty);
    }

    /// Every list of up to six lengths from 0 to 4, sparse long codes, and
    /// a length out of range: the fused check refuses exactly what the
    /// separate pass refused, in every role.
    #[test]
    fn fused_check_refuses_exactly_what_the_separate_pass_did() {
        let mut table = DecodeTable::default();
        let mut cases = 0u32;
        for role in [Role::Main, Role::Distance, Role::Plain] {
            for n in 0..=6u32 {
                for mut code in 0..5u32.pow(n) {
                    let mut lengths = Vec::with_capacity(n as usize);
                    for _ in 0..n {
                        lengths.push((code % 5) as u8);
                        code /= 5;
                    }
                    check(&mut table, &lengths, role);
                    cases += 1;
                }
            }
            for seed in 0..1024u32 {
                let mut x = seed.wrapping_mul(2_654_435_761) | 1;
                let lengths: Vec<u8> = (0..40)
                    .map(|_| {
                        x ^= x << 13;
                        x ^= x >> 17;
                        x ^= x << 5;
                        if x % 3 == 0 {
                            (x >> 8) as u8 % 16
                        } else {
                            0
                        }
                    })
                    .collect();
                check(&mut table, &lengths, role);
                cases += 1;
            }
            check(&mut table, &[16, 1], role);
            cases += 1;
        }
        assert_eq!(cases, 3 * (19_531 + 1_024 + 1));
    }
}

#[cfg(test)]
mod reused_build {
    use super::*;

    /// A lookup and the fields a decode reads, for comparing two builds.
    fn shape(table: &DecodeTable) -> (Vec<u32>, Vec<u16>, bool, usize) {
        let lut = if table.empty {
            Vec::new()
        } else {
            table.lut.to_vec()
        };
        (lut, table.symbols.clone(), table.empty, table.max_length)
    }

    /// Lengths from a small xorshift: sparse, often incomplete, sometimes
    /// oversubscribed, and now and then empty or a single code.
    fn lengths(seed: u32, n: usize) -> Vec<u8> {
        let mut x = seed.wrapping_mul(2_654_435_761) | 1;
        let dense = seed % 4;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                if x % 4 <= dense {
                    (x >> 8) as u8 % 16
                } else {
                    0
                }
            })
            .collect()
    }

    /// The canonical code of section 3.4 built the plain way, as a check
    /// on `build`: symbols sorted by length then by number, and a lookup
    /// filled with misses and then written one symbol's span at a time.
    /// `None` for a list `build` must refuse.
    fn reference(list: &[u8], role: Role) -> Option<(Vec<u32>, Vec<u16>)> {
        let bits_of = |symbol: u16| usize::from(list[usize::from(symbol)]);
        if list.iter().any(|&bits| usize::from(bits) > MAX_CODE_LENGTH) {
            return None;
        }
        // The symbols that have a code, shorter codes first and within one
        // length by number: a stable sort of the symbols in number order.
        let mut coded: Vec<u16> = (0..list.len() as u16)
            .filter(|&symbol| bits_of(symbol) != 0)
            .collect();
        coded.sort_by_key(|&symbol| bits_of(symbol));
        // Oversubscribed (section 3.4): the halves raised to each length sum
        // to more than 1. In parts of `2^-15` the sum is a whole number.
        let taken: u64 = coded
            .iter()
            .map(|&symbol| 1u64 << (MAX_CODE_LENGTH - bits_of(symbol)))
            .sum();
        if taken > 1 << MAX_CODE_LENGTH {
            return None;
        }
        if coded.is_empty() {
            return Some((Vec::new(), coded));
        }
        // The first code is all zero bits; each next is the one before plus
        // 1, doubled once for each bit its length adds.
        let mut lut = vec![HUFF_LUT_MISS; LUT_ENTRIES];
        let mut code = 0usize;
        let mut last_bits = bits_of(coded[0]);
        for (place, &symbol) in coded.iter().enumerate() {
            let bits = bits_of(symbol);
            if place != 0 {
                code = (code + 1) << (bits - last_bits);
            }
            last_bits = bits;
            if bits <= HUFF_LUT_BITS {
                // Every nine bit start this code is a prefix of.
                let span = 1usize << (HUFF_LUT_BITS - bits);
                let start = code << (HUFF_LUT_BITS - bits);
                lut[start..start + span].fill(DecodeTable::entry(usize::from(symbol), bits, role));
            }
        }
        Some((lut, coded))
    }

    /// `build` against the plain reference above, on fresh and on reused
    /// tables alike: the same refusals, the same canonical symbol order and
    /// the same lookup, entry for entry. An empty table's lookup is not
    /// compared, because nothing reads it.
    #[test]
    fn build_matches_the_plain_reference() {
        let mut reused = DecodeTable::default();
        let mut compared = 0u32;
        for role in [Role::Main, Role::Distance, Role::Plain] {
            for seed in 0..4096u32 {
                let n = [20, 16, 44, 64, 80, MAIN_SYMBOLS, 1, 3][seed as usize % 8];
                let list = lengths(seed ^ 0x5bd1_e995, n);
                let want = reference(&list, role);
                assert_eq!(
                    reused.build(&list, role).is_ok(),
                    want.is_some(),
                    "{list:?}"
                );
                if let Some((lut, symbols)) = want {
                    let (got_lut, got_symbols, _, _) = shape(&reused);
                    assert!(got_symbols == symbols, "symbols differ for {list:?}");
                    assert!(got_lut == lut, "lookup differs for {list:?}");
                    compared += 1;
                }
            }
        }
        assert!(compared > 3000, "only {compared} sets built");
    }

    /// A table built over one that held another set is the table built
    /// fresh, entry for entry: the build writes every lookup entry a
    /// decode can read, whatever the allocation held before, which is what
    /// lets the lanes reuse a released set's allocation.
    #[test]
    fn a_table_built_over_another_equals_one_built_fresh() {
        let mut reused = DecodeTable::default();
        let mut compared = 0u32;
        for role in [Role::Main, Role::Distance, Role::Plain] {
            for seed in 0..4096u32 {
                let n = [20, 16, 44, 64, 80, MAIN_SYMBOLS][seed as usize % 6];
                let list = lengths(seed, n);
                let mut fresh = DecodeTable::default();
                let fresh_ok = fresh.build(&list, role).is_ok();
                let reused_ok = reused.build(&list, role).is_ok();
                assert_eq!(fresh_ok, reused_ok, "{list:?}");
                if fresh_ok {
                    assert!(shape(&fresh) == shape(&reused), "seed {seed}");
                    compared += 1;
                }
            }
        }
        // Enough complete and incomplete sets were compared to mean it.
        assert!(compared > 3000, "only {compared} sets built");
    }
}

#[cfg(test)]
mod kept_storage {
    use super::*;
    use crate::rar3_filters::tests::counting;

    /// A list of `n` lengths that no build refuses: about one symbol in
    /// `sparse` has no code, and the others have codes of `shortest` to 15
    /// bits, which `n` of at most 306 symbols cannot oversubscribe from
    /// nine bits up.
    fn sound_list(seed: u32, n: usize, shortest: u32, sparse: u32) -> Vec<u8> {
        let mut x = seed.wrapping_mul(2_654_435_761) | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                if (x >> 4).is_multiple_of(sparse) {
                    0
                } else {
                    (shortest + (x >> 12) % (16 - shortest)) as u8
                }
            })
            .collect()
    }

    /// Every length from ten to fourteen once and the rest at fifteen, so
    /// the first nine bit start holds every long length and each start
    /// after it is full of the longest codes.
    fn ladder_list(n: usize) -> Vec<u8> {
        let mut list = vec![15u8; n];
        for (at, length) in (10u8..15).enumerate().take(n) {
            list[at] = length;
        }
        list
    }

    /// SPEC-H2 section 4.2, no allocation per block, at the table itself:
    /// a table takes its memory when it is made, and no build on it takes
    /// any, the FIRST build included, whatever list comes and in whatever
    /// order. Counted on this thread alone, which is the one that builds;
    /// no pool, and a few kilobytes held.
    #[test]
    fn a_build_takes_no_memory_from_the_allocator() {
        let mut lists: Vec<(Vec<u8>, Role)> = Vec::new();
        for (n, role) in [
            (MAIN_SYMBOLS, Role::Main),
            (DISTANCE_SLOTS_V1, Role::Distance),
            (DISTANCE_SLOTS_V0, Role::Distance),
            (LENGTH_SYMBOLS, Role::Plain),
            (LEVEL_SYMBOLS, Role::Plain),
            (ALIGN_SYMBOLS, Role::Plain),
        ] {
            lists.push((ladder_list(n), role));
            for seed in 0..64u32 {
                lists.push((sound_list(seed, n, 9, 5), role));
                lists.push((sound_list(seed ^ 0x9e37, n, 10, 2), role));
                lists.push((sound_list(seed ^ 0x79b9, n, 1, 3), role));
            }
            lists.push((vec![0u8; n], role));
            lists.push((vec![8u8; n.min(256)], role));
        }
        // Largest second level last and first as well, so no order of
        // lists is what keeps a build from growing its storage.
        lists.push((ladder_list(MAIN_SYMBOLS), Role::Main));

        let mut built = 0u32;
        let mut long_codes = 0u32;
        let mut table = DecodeTable::default();
        let before = counting::count();
        for (list, role) in &lists {
            if table.build(list, *role).is_ok() {
                built += 1;
                long_codes += u32::from(table.max_length > HUFF_LUT_BITS);
            }
        }
        let took = counting::count() - before;
        assert!(built > 600, "only {built} lists built");
        assert!(long_codes > 400, "only {long_codes} lists had a long code");
        assert_eq!(
            took,
            0,
            "{took} takes from the allocator over {} builds on one table",
            lists.len()
        );
    }

    /// [`long_most`] is a bound and not a guess: a table made for an
    /// alphabet's own size never grows a list, on the lists that fill the
    /// second level most and on some thousands of others, and the ladder
    /// comes within a start's worth of the bound.
    #[test]
    fn a_table_made_for_its_alphabet_never_grows() {
        for n in [
            MAIN_SYMBOLS,
            DISTANCE_SLOTS_V1,
            DISTANCE_SLOTS_V0,
            LENGTH_SYMBOLS,
            LEVEL_SYMBOLS,
            ALIGN_SYMBOLS,
        ] {
            let mut table = DecodeTable::holding(n);
            let room = (table.long.capacity(), table.symbols.capacity());
            assert!(room.0 >= long_most(n) && room.1 >= n);
            let mut most = 0usize;
            let mut check = |list: &[u8]| {
                if table.build(list, Role::Plain).is_ok() {
                    most = most.max(table.long.len());
                    assert!(table.long.len() <= long_most(n), "{list:?}");
                }
                assert_eq!(
                    (table.long.capacity(), table.symbols.capacity()),
                    room,
                    "{list:?}"
                );
            };
            check(&ladder_list(n));
            // Each long length in turn given way to by the next, at every
            // split of the alphabet between the two.
            for shorter in 10u8..15 {
                for split in 0..=n {
                    let mut list = vec![shorter; n];
                    list[split..].fill(shorter + 1);
                    check(&list);
                }
            }
            for seed in 0..1024u32 {
                check(&sound_list(seed, n, 9, 5));
                check(&sound_list(seed ^ 0x9e37, n, 10, 2));
                check(&sound_list(seed ^ 0x79b9, n, 7, 3));
                check(&sound_list(seed ^ 0x7f4a, n, 13, 9));
            }
            assert!(most + (1 << TAIL_BITS) > n, "{n}: the most was {most}");
        }
    }

    /// The full-byte shape is exactly "all 256 literals at eight bits": it
    /// is the identity code (code `c` is literal `c`), it is never also the
    /// single-gap shape, and every near miss answers no (one literal moved
    /// to nine bits with a control symbol beside it; 255 literals and a
    /// control symbol at eight, whose code 255 is that symbol; an
    /// incomplete table with 255 literals and nothing else: all three the
    /// single gap; and a table with no eight bit codes, neither).
    #[test]
    fn the_full_byte_shape_is_all_256_literals_at_eight_bits() {
        let mut table = DecodeTable::default();
        let mut full = vec![0u8; MAIN_SYMBOLS];
        full[..256].fill(8);
        table.build(&full, Role::Main).unwrap();
        assert!(table.serial_full_byte());
        assert_eq!(table.serial_single_gap(), None);
        assert_eq!(table.first_code[8], 0);
        for (rank, &symbol) in table.symbols[table.shelf_of(8)].iter().enumerate() {
            assert_eq!(usize::from(symbol), rank, "code {rank} is literal {rank}");
        }

        let mut near = Vec::new();
        for moved in [0usize, 1, 127, 128, 254, 255] {
            let mut gap = full.clone();
            gap[moved] = 9;
            gap[256] = 9;
            near.push((gap, Some(moved as u8)));
            let mut swapped = full.clone();
            swapped[moved] = 0;
            swapped[300] = 8;
            near.push((swapped, Some(moved as u8)));
            let mut short = full.clone();
            short[moved] = 0;
            near.push((short, Some(moved as u8)));
        }
        let mut wide = vec![0u8; MAIN_SYMBOLS];
        wide[..300].fill(9);
        near.push((wide, None));
        for (list, gap) in near {
            table.build(&list, Role::Main).unwrap();
            assert!(!table.serial_full_byte(), "{list:?}");
            assert_eq!(table.serial_single_gap(), gap, "{list:?}");
        }
    }
}
