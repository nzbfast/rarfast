//! The STRICT canonical prefix table RAR 2.0 decodes through (spec H3
//! section 3.2, "Table classes").
//!
//! An oversubscribed length list is refused when the table is built
//! (rarkit's own rule). A list that is incomplete, has one symbol or is
//! all zero builds, and the 15 bit values no codeword owns are read by
//! section 3.2's T2: 15 bits, and symbol 0 or the first ranked symbol.
//! T2 is not established on the code length alphabet's own table, so that
//! table is read with [`Table::decode_owned`], which refuses such a value
//! as this decoder did before T2 was stated.
//!
//! The code itself is the ordinary canonical one spec D section 3.2.2
//! describes: symbols with a nonzero length sorted by length ascending then
//! symbol number ascending, codes of each length consecutive, shorter
//! lengths first, the first code all zeros.

use super::bits::BitSource;
use crate::error::Rar20Fault;
use crate::{Corruption, Error, ErrorKind, Result};

/// Widest code the four bit length fields can name.
pub(crate) const MAX_CODE_LEN: usize = 15;
/// Width of the primary lookup, carried from the predecessor's RAR 2.0
/// codec as ours from birth: it covers virtually every real code.
const LUT_BITS: usize = super::HUFF20_LUT_BITS;
const LUT_SIZE: usize = 1 << LUT_BITS;
/// Bits of a lookup entry that hold the symbol. The widest alphabet here
/// is the LZ main one at 298 symbols, so twelve bits hold every symbol of
/// every RAR 2.0 alphabet and the four above them hold a width of at most
/// [`LUT_BITS`] = 12. THE ENTRY IS SIXTEEN BITS WIDE, not thirty two: four
/// alphabets are live at once in a four channel multimedia block and the
/// narrower entry halves what they occupy, which is the point of it.
const LUT_SYMBOL_BITS: u32 = 12;
/// A lookup entry that the primary table cannot answer. Its width field is
/// 15, which no entry the builder writes can reach.
const LUT_MISS: u16 = u16::MAX;

/// One alphabet's decoding table.
pub(crate) struct Table {
    /// `LUT_BITS` of lookahead to `(width << LUT_SYMBOL_BITS) | symbol`,
    /// or [`LUT_MISS`]. A fixed length array, so the one index the hot
    /// path takes needs no bounds check: the lookahead is `LUT_BITS` wide
    /// and the array is `1 << LUT_BITS` long.
    lut: Box<[u16; LUT_SIZE]>,
    /// Symbols with a nonzero length, in canonical order.
    order: Vec<u16>,
    /// First canonical code of each length, indexed by length.
    first_code: [u32; MAX_CODE_LEN + 1],
    /// One past the last canonical code of each length.
    end_code: [u32; MAX_CODE_LEN + 1],
    /// Index into `order` of the first symbol of each length.
    first_index: [u32; MAX_CODE_LEN + 1],
    /// Whether any symbol has a nonzero length.
    used: bool,
    /// How many lengths the list has: the `n` of T2.
    listed: u32,
    /// How many of the 32,768 values of 15 bits a codeword owns: the `T`
    /// of T2.
    owned: u32,
}

impl Table {
    /// An empty table sized for an alphabet of `symbols`, allocated once
    /// and rebuilt in place for every block.
    pub(crate) fn new(symbols: usize) -> Table {
        Table {
            // An array VALUE, not `vec![LUT_MISS; LUT_SIZE]`: the vector
            // form is filled by the vector's own fill loop, which one
            // profile-use build after another was seen to leave as a call
            // to never-run code (1.5M instructions a run of a 9M row, a
            // decoder being made for every member). Every byte of
            // [`LUT_MISS`] is the same, so the array is one block fill.
            lut: Box::new([LUT_MISS; LUT_SIZE]),
            order: Vec::with_capacity(symbols),
            first_code: [0; MAX_CODE_LEN + 1],
            end_code: [0; MAX_CODE_LEN + 1],
            first_index: [0; MAX_CODE_LEN + 1],
            used: false,
            listed: symbols as u32,
            owned: 0,
        }
    }

    /// Whether the table has any symbol at all (spec D 2.2's "has no
    /// symbols").
    pub(crate) fn is_used(&self) -> bool {
        self.used
    }

    /// Whether [`Self::build`] would refuse `lengths` as oversubscribed,
    /// asked without building anything: a list that takes more than the
    /// whole code space (the same count `build` makes).
    pub(crate) fn oversubscribed(lengths: &[u8]) -> bool {
        let kraft: u64 = lengths
            .iter()
            .filter(|&&length| length != 0)
            .map(|&length| 1u64 << (16 - u32::from(length).min(16)))
            .sum();
        kraft > 1 << 16
    }

    /// Rebuild from `lengths`, one per symbol, each in 0..=15.
    ///
    /// An oversubscribed list is [`Rar20Fault::Oversubscribed`]. An
    /// incomplete one builds, and so does an all zero one.
    pub(crate) fn build(&mut self, lengths: &[u8]) -> Result<()> {
        let mut counts = [0u32; MAX_CODE_LEN + 1];
        for &length in lengths {
            debug_assert!(length as usize <= MAX_CODE_LEN);
            counts[length as usize] += 1;
        }
        counts[0] = 0;

        // Kraft, in sixteenths of the code space as spec D 3.2.1 counts it,
        // so that an exactly complete code sums to 1 << 16.
        let mut kraft: u64 = 0;
        for (length, &count) in counts.iter().enumerate().skip(1) {
            kraft += u64::from(count) << (16 - length);
        }
        if kraft > 1 << 16 {
            return Err(fault(Rar20Fault::Oversubscribed));
        }
        self.listed = lengths.len() as u32;
        self.owned = (kraft >> 1) as u32;

        self.order.clear();
        let mut code = 0u32;
        let mut index = 0u32;
        for (length, &count) in counts.iter().enumerate().skip(1) {
            self.first_code[length] = code;
            self.first_index[length] = index;
            self.end_code[length] = code + count;
            code = (code + count) << 1;
            index += count;
        }
        self.used = index != 0;

        // The canonical order in ONE pass over the lengths: each length's
        // symbols go to consecutive slots from that length's first index,
        // and the symbols are met in ascending order, which is the order
        // within a length. (Fifteen passes, one a length, wrote the same
        // order; a block's tables are built from several hundred lengths,
        // and on a small member that was a visible part of the decode.)
        self.order.resize(index as usize, 0);
        let mut next = self.first_index;
        for (symbol, &symbol_length) in lengths.iter().enumerate() {
            if symbol_length != 0 {
                let slot = &mut next[symbol_length as usize];
                self.order[*slot as usize] = symbol as u16;
                *slot += 1;
            }
        }

        // THE SHORT CODES TILE THE LOOKAHEAD SPACE FROM ZERO UPWARDS and
        // leave no hole. Canonical codes ascend with the length, so the
        // span this loop writes for one code begins exactly where the
        // previous one ended, starting at zero; what is left at the end
        // is the space belonging to codes wider than the lookup, and to
        // an incomplete table's unused codes. So the [`LUT_MISS`] fill
        // covers only THAT tail, instead of the whole array before the
        // spans overwrite most of it again. A near complete table, which
        // is what a real block has, writes the array once.
        let mut filled = 0usize;
        for (length, &count) in counts.iter().enumerate().take(LUT_BITS + 1).skip(1) {
            for rank in 0..count {
                let symbol = self.order[(self.first_index[length] + rank) as usize];
                let code = self.first_code[length] + rank;
                let entry = ((length as u16) << LUT_SYMBOL_BITS) | symbol;
                // Every lookahead whose top `length` bits are this code.
                let start = (code as usize) << (LUT_BITS - length);
                let span = 1usize << (LUT_BITS - length);
                debug_assert_eq!(start, filled);
                fill_entries(&mut self.lut[start..start + span], entry);
                filled = start + span;
            }
        }
        fill_entries(&mut self.lut[filled..], LUT_MISS);
        Ok(())
    }

    /// HOT PATH. Decode one symbol, consuming exactly its width.
    ///
    /// A value no codeword owns, which an incomplete or all zero table
    /// has, is read by T2. The bits past the end of the input read as
    /// zeros and a code that runs into them is read whole (spec H3 3.5: a
    /// symbol that begins inside the packed data is read whole, every
    /// field of it, and that is no fault). Whether a symbol may BEGIN is
    /// the caller's test of [`BitSource::available`], made before this.
    ///
    /// ALWAYS inlined, and the long arm never: with a plain `#[inline]` a
    /// profile-use build was seen to leave this lookup as a call in the
    /// decode loop, one call a byte of a multimedia block, where the plain
    /// build has it in line (seen 2 Oct 2026).
    /// The choice is made here so that no profile makes it.
    #[inline(always)]
    pub(crate) fn decode(&self, input: &mut impl BitSource) -> Result<u16> {
        let entry = self.lut[(input.peek(LUT_BITS as u8) as usize) & (LUT_SIZE - 1)];
        if entry != LUT_MISS {
            input.consume((entry >> LUT_SYMBOL_BITS) as u8);
            return Ok(entry & ((1 << LUT_SYMBOL_BITS) - 1));
        }
        self.decode_long(input)
    }

    /// The arm for codes wider than the primary lookup, and for the
    /// values no codeword owns.
    #[cold]
    #[inline(never)]
    fn decode_long(&self, input: &mut impl BitSource) -> Result<u16> {
        match self.long_code(input) {
            Some((symbol, length)) => {
                input.consume(length);
                Ok(symbol)
            }
            None => Ok(self.unowned(input)),
        }
    }

    /// Decode one symbol of a table on which T2 is not established: a
    /// value no codeword owns is [`Rar20Fault::InvalidCode`]. This is the
    /// read of a block header's own lengths, which is no symbol of the
    /// stream: a code wider than the input that is left is
    /// [`crate::ErrorKind::Truncated`], with nothing consumed.
    pub(crate) fn decode_owned(&self, input: &mut impl BitSource) -> Result<u16> {
        let entry = self.lut[(input.peek(LUT_BITS as u8) as usize) & (LUT_SIZE - 1)];
        let (symbol, length) = if entry != LUT_MISS {
            (
                entry & ((1 << LUT_SYMBOL_BITS) - 1),
                (entry >> LUT_SYMBOL_BITS) as u8,
            )
        } else {
            match self.long_code(input) {
                Some(found) => found,
                None => return Err(fault(Rar20Fault::InvalidCode)),
            }
        };
        if input.available() < u64::from(length) {
            return Err(Error::new(ErrorKind::Truncated));
        }
        input.consume(length);
        Ok(symbol)
    }

    /// A codeword wider than the primary lookup, if the next bits are
    /// one, and its width. Nothing is consumed.
    fn long_code(&self, input: &impl BitSource) -> Option<(u16, u8)> {
        let lookahead = input.peek(MAX_CODE_LEN as u8);
        for length in LUT_BITS + 1..=MAX_CODE_LEN {
            let code = lookahead >> (MAX_CODE_LEN - length);
            if code < self.end_code[length] {
                let rank = code - self.first_code[length];
                let symbol = self.order[(self.first_index[length] + rank) as usize];
                return Some((symbol, length as u8));
            }
        }
        None
    }

    /// Section 3.2's T2, for the next 15 bits when no codeword owns them.
    /// They are consumed, zeros standing for those past the end of the
    /// input. The unowned values run from the count of owned
    /// ones up to 32,767; as many of them as the list has symbols without
    /// a codeword give symbol 0, lowest values first, and every later one
    /// gives the first ranked symbol. A list with no ranked symbol gives
    /// symbol 0 throughout.
    fn unowned(&self, input: &mut impl BitSource) -> u16 {
        let fifteen = MAX_CODE_LEN as u8;
        let earlier_unowned = input.peek(fifteen).saturating_sub(self.owned);
        input.consume(fifteen);
        let without_codeword = self.listed - self.order.len() as u32;
        match self.order.first() {
            Some(&leader) if earlier_unowned >= without_codeword => leader,
            _ => 0,
        }
    }
}

/// Write `entry` to every slot of `span`.
///
/// Sixteen entries at a time as one array value, then the few that are
/// left: a store of a whole block, which the compiler emits as written
/// whether or not it chooses to vectorise the loop around it. One code's
/// span is a power of two long, so the blocks are all of it or none; the
/// tail after the last code is whatever is left.
#[inline(always)]
fn fill_entries(span: &mut [u16], entry: u16) {
    let (blocks, rest) = span.as_chunks_mut::<16>();
    for block in blocks {
        *block = [entry; 16];
    }
    for slot in rest {
        *slot = entry;
    }
}

fn fault(fault: Rar20Fault) -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::Rar20(fault)))
}

#[cfg(test)]
mod build_tests {
    use super::*;

    /// The table the long way: the canonical order by one pass a length,
    /// and the lookup slot by slot.
    fn reference(lengths: &[u8]) -> (Vec<u16>, Vec<u16>) {
        let mut order = Vec::new();
        for length in 1..=MAX_CODE_LEN {
            for (symbol, &symbol_length) in lengths.iter().enumerate() {
                if symbol_length as usize == length {
                    order.push(symbol as u16);
                }
            }
        }
        let mut lut = vec![LUT_MISS; LUT_SIZE];
        let mut code = 0usize;
        let mut rank = 0usize;
        for length in 1..=MAX_CODE_LEN {
            for &symbol_length in lengths {
                if symbol_length as usize == length {
                    if length <= LUT_BITS {
                        let entry = ((length as u16) << LUT_SYMBOL_BITS) | order[rank];
                        let start = code << (LUT_BITS - length);
                        for slot in &mut lut[start..start + (1 << (LUT_BITS - length))] {
                            *slot = entry;
                        }
                    }
                    rank += 1;
                    code += 1;
                }
            }
            code <<= 1;
        }
        (order, lut)
    }

    /// Length lists that are not oversubscribed, complete and incomplete,
    /// for an alphabet of `symbols`: lengths drawn by a fixed generator and
    /// then dropped to zero from the end until Kraft's sum fits.
    fn lists(symbols: usize, seed: u64) -> Vec<Vec<u8>> {
        let mut state = seed;
        let mut next = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };
        let mut out = Vec::new();
        for round in 0..200 {
            let spread = 1 + round % MAX_CODE_LEN as u32;
            let mut lengths: Vec<u8> = (0..symbols)
                .map(|_| match next() % 4 {
                    0 => 0,
                    _ => (1 + next() % spread).max(MAX_CODE_LEN as u32 - spread + 1) as u8,
                })
                .collect();
            let kraft = |lengths: &[u8]| -> u64 {
                lengths
                    .iter()
                    .filter(|&&l| l != 0)
                    .map(|&l| 1u64 << (16 - l))
                    .sum()
            };
            let mut at = symbols;
            while kraft(&lengths) > 1 << 16 {
                at -= 1;
                lengths[at] = 0;
            }
            out.push(lengths);
        }
        out
    }

    #[test]
    fn build_writes_the_canonical_order_and_lookup_for_every_list() {
        for (symbols, seed) in [(19, 1), (28, 2), (48, 3), (257, 4), (298, 5)] {
            let mut table = Table::new(symbols);
            for lengths in lists(symbols, seed) {
                table
                    .build(&lengths)
                    .expect("the list is not oversubscribed");
                let (order, lut) = reference(&lengths);
                assert_eq!(table.order, order, "{symbols} symbols: the canonical order");
                assert_eq!(&table.lut[..], &lut[..], "{symbols} symbols: the lookup");
                assert_eq!(table.used, !order.is_empty());
            }
        }
    }
}
