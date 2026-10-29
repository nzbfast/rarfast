//! A block writer for the hand vectors of SPEC-H2 section 5.4.
//!
//! It writes the simplest legal tables: every symbol of an alphabet gets
//! the same code length unless a vector says otherwise, so a symbol's
//! canonical code is its own number. That is enough to say anything the
//! hand vectors need to say and it keeps each vector readable as a list of
//! symbols.

use super::block::{FLAG_LAST, FLAG_TABLES, HEADER_CHECK};
use super::tables::{ALIGN_SYMBOLS, LENGTH_SYMBOLS, LEVEL_SYMBOLS, MAIN_SYMBOLS};

/// Most significant bit first, like the payload it writes.
#[derive(Default, Clone)]
pub(crate) struct BitWriter {
    bytes: Vec<u8>,
    nbits: usize,
}

impl BitWriter {
    pub(crate) fn put(&mut self, value: u32, width: u32) {
        for step in (0..width).rev() {
            let bit = (value >> step) & 1;
            if self.nbits.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if bit != 0 {
                let at = self.nbits / 8;
                self.bytes[at] |= 1 << (7 - (self.nbits % 8));
            }
            self.nbits += 1;
        }
    }
}

/// The code length each alphabet's symbols get, so a symbol's code is its
/// own number at that width.
pub(crate) const MAIN_WIDTH: u8 = 9;
pub(crate) const DISTANCE_WIDTH: u8 = 6;
// Five, not four: an alignment alphabet whose codes are four bits wide
// would encode a distance's low nibble in exactly the bits six plain bits
// would, so the default keeps them apart; V5-ALIGN (b) asks for the four
// bit table by name.
pub(crate) const ALIGN_WIDTH: u8 = 5;
pub(crate) const LENGTH_WIDTH: u8 = 6;
/// Every code length alphabet symbol at five bits, which 20 symbols fit.
const LEVEL_WIDTH: u32 = 5;

/// One block under construction.
pub(crate) struct BlockBuilder {
    pub(crate) main: Vec<u8>,
    pub(crate) distance: Vec<u8>,
    pub(crate) align: Vec<u8>,
    pub(crate) length: Vec<u8>,
    body: BitWriter,
    /// The main alphabet's codes, worked out once: a vector that writes a
    /// quarter of a million literals should not recount the lengths for
    /// each one.
    main_codes: Vec<(u32, u32)>,
}

impl Default for BlockBuilder {
    fn default() -> BlockBuilder {
        BlockBuilder {
            main: vec![MAIN_WIDTH; MAIN_SYMBOLS],
            distance: vec![DISTANCE_WIDTH; 64],
            // There is no alignment mode to turn off (section 3.3): a far
            // distance always reads an alignment symbol, so the default
            // block carries a table. A vector asks for none with
            // `with_align_lengths`.
            align: vec![ALIGN_WIDTH; ALIGN_SYMBOLS],
            length: vec![LENGTH_WIDTH; LENGTH_SYMBOLS],
            body: BitWriter::default(),
            main_codes: Vec::new(),
        }
    }
}

impl BlockBuilder {
    /// These sixteen alignment code lengths (section 3.3). All zero is a
    /// table with no symbols: `fresh` then writes the distance's extra bits
    /// plain, which is what follows the slot for a decoder that must refuse.
    pub(crate) fn with_align_lengths(mut self, lengths: &[u8]) -> BlockBuilder {
        assert_eq!(lengths.len(), ALIGN_SYMBOLS);
        self.align = lengths.to_vec();
        self
    }

    /// The block's symbol bits so far, without its tables or framing.
    pub(crate) fn body_bits(&self) -> (&[u8], usize) {
        (&self.body.bytes, self.body.nbits)
    }

    /// A main alphabet of just these symbols, all at `width` bits, so a
    /// vector can put a code SHORTER than a byte in front of the decoder.
    pub(crate) fn with_main(mut self, symbols: &[usize], width: u8) -> BlockBuilder {
        self.main = vec![0; MAIN_SYMBOLS];
        for &symbol in symbols {
            self.main[symbol] = width;
        }
        self.main_codes.clear();
        self
    }

    /// A symbol's canonical code under a list of code lengths: shorter
    /// lengths first, and within a length by increasing symbol number.
    /// With every symbol at one width this is the symbol itself, which is
    /// what keeps the uniform vectors readable.
    fn code(lengths: &[u8], symbol: usize) -> (u32, u32) {
        let width = lengths[symbol];
        assert!(width != 0, "symbol {symbol} has no code");
        let mut counts = [0u32; 16];
        for &length in lengths {
            if length != 0 {
                counts[usize::from(length)] += 1;
            }
        }
        let mut first = [0u32; 16];
        let mut code = 0u32;
        for length in 1..16 {
            code = (code + counts[length - 1]) << 1;
            first[length] = code;
        }
        let rank = lengths[..symbol]
            .iter()
            .filter(|&&other| other == width)
            .count() as u32;
        (first[usize::from(width)] + rank, u32::from(width))
    }

    fn main_symbol(&mut self, symbol: usize) {
        if self.main_codes.is_empty() {
            self.main_codes = (0..self.main.len())
                .map(|s| {
                    if self.main[s] == 0 {
                        (0, 0)
                    } else {
                        Self::code(&self.main, s)
                    }
                })
                .collect();
        }
        let (code, width) = self.main_codes[symbol];
        assert!(width != 0, "symbol {symbol} has no code");
        self.body.put(code, width);
    }

    /// A literal byte (symbol 0 to 255).
    pub(crate) fn literal(&mut self, byte: u8) {
        self.main_symbol(usize::from(byte));
    }

    pub(crate) fn literals(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.literal(byte);
        }
    }

    /// A fresh match: main symbol `262 + length_slot`, the slot's extra
    /// bits, then a distance slot and its extra bits.
    pub(crate) fn fresh(
        &mut self,
        length_slot: usize,
        length_extra: u32,
        distance_slot: usize,
        distance_extra: u32,
    ) {
        use super::ladders::{DISTANCE_SLOT_BITS, LENGTH_SLOT_EXTRA_BITS};
        self.main_symbol(262 + length_slot);
        self.body
            .put(length_extra, u32::from(LENGTH_SLOT_EXTRA_BITS[length_slot]));
        let (code, width) = Self::code(&self.distance, distance_slot);
        self.body.put(code, width);
        let bits = u32::from(DISTANCE_SLOT_BITS[distance_slot]);
        if bits >= 4 && self.align.iter().any(|&l| l != 0) {
            // A slot past 65 has more plain bits than `distance_extra` can
            // state: the ones above its 28 are written as zeros.
            let plain = bits - 4;
            self.body.put(0, plain.saturating_sub(28));
            self.body.put(distance_extra >> 4, plain.min(28));
            let (code, width) = Self::code(&self.align, (distance_extra & 0xf) as usize);
            self.body.put(code, width);
        } else {
            self.body.put(distance_extra, bits);
        }
    }

    /// A repeated distance match: main symbol `258 + k`, then a length slot
    /// from the LENGTH alphabet and its extra bits.
    pub(crate) fn repeat(&mut self, k: usize, length_slot: usize, length_extra: u32) {
        use super::ladders::LENGTH_SLOT_EXTRA_BITS;
        self.main_symbol(258 + k);
        let (code, width) = Self::code(&self.length, length_slot);
        self.body.put(code, width);
        self.body
            .put(length_extra, u32::from(LENGTH_SLOT_EXTRA_BITS[length_slot]));
    }

    /// Symbol 257: repeat the last match.
    pub(crate) fn repeat_last(&mut self) {
        self.main_symbol(257);
    }

    /// Symbol 256 and its record (section 3.6).
    pub(crate) fn filter(&mut self, offset: u32, length: u32, kind: u32, channels: u32) {
        self.main_symbol(256);
        counted(&mut self.body, offset);
        counted(&mut self.body, length);
        self.body.put(kind, 3);
        if kind == 0 {
            self.body.put(channels - 1, 5);
        }
    }

    /// Raw bits, for a vector that needs a shape no helper writes.
    pub(crate) fn raw(&mut self, value: u32, width: u32) {
        self.body.put(value, width);
    }

    /// The whole block: its header and its payload.
    pub(crate) fn finish(&self, tables: bool, last: bool) -> Vec<u8> {
        let mut payload = BitWriter::default();
        if tables {
            self.write_tables(&mut payload);
        }
        for step in 0..self.body.nbits {
            let bit = (self.body.bytes[step / 8] >> (7 - (step % 8))) & 1;
            payload.put(u32::from(bit), 1);
        }
        frame(&payload, tables, last)
    }

    fn write_tables(&self, out: &mut BitWriter) {
        // The code length alphabet's own 20 lengths, all five bits.
        for _ in 0..LEVEL_SYMBOLS {
            out.put(LEVEL_WIDTH, 4);
        }
        // Then every code length, one level symbol each, with no runs.
        for list in [&self.main, &self.distance, &self.align, &self.length] {
            for &length in list {
                out.put(u32::from(length), LEVEL_WIDTH);
            }
        }
    }
}

/// A counted little endian 32 bit value (section 3.6).
fn counted(out: &mut BitWriter, value: u32) {
    let bytes = match value {
        0..=0xff => 1u32,
        0x100..=0xffff => 2,
        0x1_0000..=0xff_ffff => 3,
        _ => 4,
    };
    out.put(bytes - 1, 2);
    for index in 0..bytes {
        out.put((value >> (8 * index)) & 0xff, 8);
    }
}

/// Wrap a payload in the header section 3.2 states, with the check that
/// holds and the final byte's valid bit count.
pub(crate) fn frame(payload: &BitWriter, tables: bool, last: bool) -> Vec<u8> {
    let bytes = &payload.bytes;
    let final_bits = if payload.nbits == 0 {
        1
    } else {
        payload.nbits - (bytes.len() - 1) * 8
    };
    let mut flags = (final_bits as u8 - 1) & 7;
    if tables {
        flags |= FLAG_TABLES;
    }
    if last {
        flags |= FLAG_LAST;
    }
    let width = if bytes.len() < 0x100 {
        1
    } else if bytes.len() < 0x1_0000 {
        2
    } else {
        3
    };
    flags |= (width as u8 - 1) << 3;
    let mut out = vec![flags, 0];
    let mut acc = HEADER_CHECK ^ flags;
    for index in 0..width {
        let byte = (bytes.len() >> (8 * index)) as u8;
        out.push(byte);
        acc ^= byte;
    }
    out[1] = acc;
    out.extend_from_slice(bytes);
    out
}
