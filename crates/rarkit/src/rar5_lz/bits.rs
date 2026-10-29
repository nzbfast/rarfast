//! The block payload's bit stream: most significant bit first, with the
//! block's own bit length (SPEC-H2 section 3.2).
//!
//! Implemented from `specs/SPEC-H2-rarkit-rar5-lz.md` alone.

use super::fault;
use crate::Result;

/// A most significant bit first reader over one block's payload.
///
/// The payload's LAST byte may carry fewer than eight valid bits, so the
/// reader carries a bit LENGTH rather than a byte length: decoding stops at
/// that bit position even when whole bytes remain (section 3.2).
///
/// Bits at or past the limit read as ZERO. That is what makes the table
/// walk of section 3.4 answer the same symbol near the end of a block as it
/// would with the bits present: a code of `L` bits with `L` at most the
/// bits remaining never looks past the limit, and when no such code matches
/// the walk reports `Truncated` rather than a symbol. The final byte is
/// masked ONCE, here, rather than on every lookahead.
///
/// **The shape is a refill buffer, and section 7.5 is why.** The per symbol
/// cost is what this codec is made of - 5 to 9 ns against 0.05 ns per
/// output byte - and a reader that recomputed a byte offset, loaded eight
/// bytes and shifted them twice for every lookahead put 93% of the serial
/// arm inside one loop. `buf` holds the next bits left aligned, so a
/// lookahead is one shift and consuming one is another, and the load
/// happens once per eight bytes.
///
/// `Copy`, so the serial loop can hold the reader in a LOCAL rather than
/// behind its caller's pointer: see `decode_block` for why that matters.
#[derive(Clone, Copy)]
pub(crate) struct BitReader<'a> {
    data: &'a [u8],
    nbits: usize,
    /// The byte the next refill reads. Bytes below it are in `buf`, whole
    /// or in part.
    next: usize,
    /// The last byte the fast refill may touch; the payload's final byte
    /// is always taken through the slow one, where its invalid low bits
    /// are masked away.
    fast_limit: usize,
    /// The final byte with its invalid low bits cleared.
    tail: u8,
    /// The next bits, most significant first, left aligned. **Bits at or
    /// past `have` are zero or are the correct continuation of the
    /// stream**, which is what lets a refill `|` into them.
    buf: u64,
    /// How many of `buf`'s top bits the reader counts as loaded.
    have: u32,
}

impl<'a> BitReader<'a> {
    /// A reader over `data` whose first `nbits` bits are valid. `nbits` may
    /// not exceed `data.len() * 8`.
    #[inline]
    pub(crate) fn new(data: &'a [u8], nbits: usize) -> BitReader<'a> {
        debug_assert!(nbits <= data.len() * 8);
        let tail = match data.last() {
            // The valid bits of the final byte are the ones below the
            // limit; the rest are not the block's (section 3.2).
            Some(&byte) => {
                let used = nbits - (data.len() - 1) * 8;
                if used >= 8 {
                    byte
                } else {
                    byte & !(0xffu8 >> used)
                }
            }
            None => 0,
        };
        let mut reader = BitReader {
            data,
            nbits,
            next: 0,
            fast_limit: data.len().saturating_sub(1),
            tail,
            buf: 0,
            have: 0,
        };
        reader.refill();
        reader
    }

    /// The byte at `index`, with the payload's final byte masked.
    #[inline(always)]
    fn byte(&self, index: usize) -> u64 {
        let raw = if index + 1 == self.data.len() {
            self.tail
        } else {
            self.data[index]
        };
        u64::from(raw)
    }

    /// Top `buf` up to at least 56 loaded bits, or to the end of the data.
    #[inline(always)]
    fn refill(&mut self) {
        if self.next + 8 <= self.fast_limit {
            // Eight bytes at once. The bits this writes past `have + taken`
            // are the stream's own next bits, and the next refill writes
            // the same bits to the same places, so the `|` is exact.
            let word = u64::from_be_bytes(
                self.data[self.next..self.next + 8]
                    .try_into()
                    .expect("eight bytes"),
            );
            self.buf |= word >> self.have;
            self.next += ((63 - self.have) >> 3) as usize;
            self.have |= 56;
            return;
        }
        while self.have <= 56 && self.next < self.data.len() {
            self.buf |= self.byte(self.next) << (56 - self.have);
            self.next += 1;
            self.have += 8;
        }
    }

    // THE FAST REGION (the tape decode's, `tape::fast_region`): while the
    // refill's next byte is at least `FAST_MARGIN` bytes short of the
    // payload's end, every symbol a block can hold is inside the block and
    // every eight byte refill is inside the slice, so the symbol loop reads
    // with none of the tests below: no `remaining` per read, no position
    // per symbol, no bounds branch per refill. The proof, once: a refill
    // adds at most 7 to `next` and loads eight bytes at it, and one symbol
    // refills at most three times (each refill leaves at least 56 bits
    // and a symbol consumes at most 91: a main code of 15, or a filter
    // record's 2 + 32 + 2 + 32 + 3 + 5), so with `next + 32 <= len` the
    // last load of the symbol starts at or before `len - 11`. And the bit
    // position is at most `8 * next`, so `position + 91 <= 8 * len - 165`,
    // under `nbits >= 8 * len - 7` by 158 bits: no read passes the limit,
    // and no test of it is needed. The tail past the region is the checked
    // loop's, which the region hands its reader to after one ordinary
    // refill ([`BitReader::leave_fast_region`]).

    #[cfg(feature = "parallel")]
    /// The bytes the fast region keeps between the refill's next byte and
    /// the payload's end. See the proof above.
    pub(crate) const FAST_MARGIN: usize = 32;

    #[cfg(feature = "parallel")]
    /// The refill byte the fast region ends at: a symbol is read by the
    /// region's rules while [`BitReader::next_byte`] is below this. Asked
    /// once, so the loop's test is one compare against a register.
    #[inline(always)]
    pub(crate) fn fast_end(&self) -> usize {
        self.data.len().saturating_sub(Self::FAST_MARGIN)
    }

    #[cfg(feature = "parallel")]
    /// The byte the next refill reads.
    #[inline(always)]
    pub(crate) fn next_byte(&self) -> usize {
        self.next
    }

    #[cfg(feature = "parallel")]
    /// The fast refill alone, for a caller inside the region: eight bytes
    /// at `next`. The body of [`BitReader::refill`]'s first arm, a copy so
    /// that arm keeps its shape. The region's proof puts the eight bytes
    /// inside the slice; the index's own range test is what a safe load
    /// costs, and it is INDEXED rather than `get`, on purpose: a `get`
    /// whose `None` returned quietly gave the compiler a second way out of
    /// the refill, which it merged into the watermark test in front of it,
    /// two instructions on every symbol (counted 29 Sep 2026); a panic
    /// edge stays inside the refill.
    #[inline(always)]
    fn refill_in_region(&mut self) {
        debug_assert!(self.next + 8 <= self.data.len());
        let word = u64::from_be_bytes(
            self.data[self.next..self.next + 8]
                .try_into()
                .expect("eight bytes"),
        );
        self.buf |= word >> self.have;
        self.next += ((63 - self.have) >> 3) as usize;
        self.have |= 56;
    }

    #[cfg(feature = "parallel")]
    /// Consume `n` buffered bits inside the region, keeping the 16 bit
    /// watermark. `n` is at most 15 and at most `have`.
    #[inline(always)]
    pub(crate) fn advance_in_region(&mut self, n: u32) {
        debug_assert!(n <= 15 && n <= self.have);
        self.buf <<= n;
        self.have -= n;
        if self.have < 16 {
            self.refill_in_region();
        }
    }

    #[cfg(feature = "parallel")]
    /// The next 15 bits inside the region: the watermark holds them.
    #[inline(always)]
    pub(crate) fn peek_code_in_region(&self) -> u32 {
        debug_assert!(self.have >= 15);
        (self.buf >> 49) as u32
    }

    #[cfg(feature = "parallel")]
    /// Read a field of at most 15 bits inside the region: the watermark
    /// holds it. `n` may be zero.
    #[inline(always)]
    pub(crate) fn take_small_in_region(&mut self, n: u32) -> u32 {
        debug_assert!(n <= 15 && self.have >= n);
        // Two shifts, so `n == 0` is a shift of 63 and then of 1, never a
        // shift of 64.
        let value = ((self.buf >> (63 - n)) >> 1) as u32;
        self.buf <<= n;
        self.have -= n;
        if self.have < 16 {
            self.refill_in_region();
        }
        value
    }

    #[cfg(feature = "parallel")]
    /// Consume `n` bits inside the region, `n` at most 56 and at most
    /// `have`: the literal batch's advance past the codes it took.
    #[inline(always)]
    pub(crate) fn advance_wide_in_region(&mut self, n: u32) {
        debug_assert!(n <= 56 && n <= self.have);
        self.buf <<= n;
        self.have -= n;
        if self.have < 16 {
            self.refill_in_region();
        }
    }

    #[cfg(feature = "parallel")]
    /// The buffered bits inside the region, most significant first, for
    /// a caller that has [`BitReader::ensure_in_region`]d what it reads.
    #[inline(always)]
    pub(crate) fn window_in_region(&self) -> u64 {
        self.buf
    }

    #[cfg(feature = "parallel")]
    /// Top up inside the region so that at least `n` bits are buffered,
    /// `n` at most 56.
    #[inline(always)]
    pub(crate) fn ensure_in_region(&mut self, n: u32) {
        debug_assert!(n <= 56);
        if self.have < n {
            self.refill_in_region();
        }
    }

    // ONE TEST FOR SEVERAL READS (lever 2 of the fresh match). A reader that has been
    // `ensure_in_region(n)`d holds `n` bits, and the reads that fit in them
    // need no refill test of their own: the `_raw` forms below consume
    // with none, and the caller restores the 16 bit watermark the region's
    // next code needs with ONE `keep_watermark_in_region` after the last.
    // The region's proof above is untouched by it: it bounds the BITS a
    // symbol consumes (at most 91), and a refill still loads eight bytes at
    // a `next` no further on than the bits consumed put it, so fewer
    // refill tests change neither the bits read nor where any load lands.

    #[cfg(feature = "parallel")]
    /// Read a field of at most 32 bits inside the region with no refill
    /// test: the caller has [`BitReader::ensure_in_region`]d it, and owes
    /// a [`BitReader::keep_watermark_in_region`] before the next code.
    /// `n` may be zero.
    #[inline(always)]
    pub(crate) fn take_raw_in_region(&mut self, n: u32) -> u32 {
        debug_assert!(n <= 32 && self.have >= n);
        let value = ((self.buf >> (63 - n)) >> 1) as u32;
        self.buf <<= n;
        self.have -= n;
        value
    }

    #[cfg(feature = "parallel")]
    /// Consume `n` buffered bits inside the region with no refill test, as
    /// [`BitReader::take_raw_in_region`].
    #[inline(always)]
    pub(crate) fn advance_raw_in_region(&mut self, n: u32) {
        debug_assert!(n <= 15 && n <= self.have);
        self.buf <<= n;
        self.have -= n;
    }

    #[cfg(feature = "parallel")]
    /// The region's 16 bit watermark, after `_raw` reads.
    #[inline(always)]
    pub(crate) fn keep_watermark_in_region(&mut self) {
        if self.have < 16 {
            self.refill_in_region();
        }
    }

    #[cfg(feature = "parallel")]
    /// Read a field of at most 27 bits inside the region, the caller having
    /// [`BitReader::ensure_in_region`]d it. `n` may be zero.
    #[inline(always)]
    pub(crate) fn take_wide_in_region(&mut self, n: u32) -> u32 {
        debug_assert!(n <= 32 && self.have >= n);
        let value = ((self.buf >> (63 - n)) >> 1) as u32;
        self.buf <<= n;
        self.have -= n;
        if self.have < 16 {
            self.refill_in_region();
        }
        value
    }

    #[cfg(feature = "parallel")]
    /// The payload the reader walks, whole: for the bulk literal step of
    /// the literal batch's region (`tape::batch`), which reads whole codes
    /// as bytes straight from it at the reader's bit position and then
    /// repositions the reader with [`BitReader::seek_in_region`].
    #[inline(always)]
    pub(crate) fn payload(&self) -> &'a [u8] {
        self.data
    }

    #[cfg(feature = "parallel")]
    /// Put the reader at bit `pos` inside the region: `pos / 8 + 8` must
    /// be inside the slice (the bulk step's bound keeps it 33 bytes short
    /// of it), so the refill is the region's and the invariants hold
    /// again (at least 56 bits buffered, less the bits below the byte).
    #[inline(always)]
    pub(crate) fn seek_in_region(&mut self, pos: usize) {
        debug_assert!(pos / 8 + 8 <= self.data.len());
        self.next = pos / 8;
        self.buf = 0;
        self.have = 0;
        self.refill_in_region();
        let within = (pos % 8) as u32;
        self.buf <<= within;
        self.have -= within;
    }

    #[cfg(feature = "parallel")]
    /// Hand the reader back to the checked loops: one ordinary refill, so
    /// every invariant they hold (at least 56 bits buffered wherever the
    /// block has them, on either architecture's read surface) holds again.
    #[inline(always)]
    pub(crate) fn leave_fast_region(&mut self) {
        self.refill();
    }

    // The literal batch's window: at least 56 bits buffered, for a caller
    // that has checked 56 valid bits remain. No other method changes.
    #[inline(always)]
    pub(crate) fn serial_window(&mut self) -> u64 {
        if self.have < 56 {
            self.refill();
        }
        self.buf
    }

    /// The bit position reached so far.
    #[inline(always)]
    pub(crate) fn position(&self) -> usize {
        self.next * 8 - self.have as usize
    }

    /// Resume at `pos`, which a parked tape worker left behind.
    #[inline]
    // Live with the `parallel` feature only, which the default build has.
    #[allow(dead_code)]
    pub(crate) fn seek(&mut self, pos: usize) {
        debug_assert!(pos <= self.nbits);
        self.next = pos / 8;
        self.buf = 0;
        self.have = 0;
        self.refill();
        self.advance((pos % 8) as u32);
    }

    /// [`BitReader::seek`] for the tape decode's literal batch, and only for
    /// it: a COPY of the body, not a call, on purpose. With the batched loop
    /// as a second caller of `seek` the compiler stopped inlining it into
    /// `decode_one`, the reader's address escaped, and the plain loop kept
    /// the reader in memory (stores 167 to 514 on aarch64; the literal batch
    /// work, 26 Sep 2026). Forcing `seek` inline instead reshaped the serial
    /// `apply_one`. A second function leaves `seek` with its one caller.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn seek_batched(&mut self, pos: usize) {
        debug_assert!(pos <= self.nbits);
        self.next = pos / 8;
        self.buf = 0;
        self.have = 0;
        self.refill();
        self.advance((pos % 8) as u32);
    }

    /// [`BitReader::seek`] for the tape decode's own loop
    /// (`tape::decode::symbols_from`), and only for it: a COPY of the body,
    /// always inlined, as [`BitReader::seek_batched`] is for the batch.
    ///
    /// `seek` stayed inlined at that one call only while the build's
    /// partition happened to allow it. Where it did not, the tape decoder
    /// CALLED `seek`, the reader's address escaped and the symbol loop kept
    /// the reader in memory: 1.39 percent more instructions on a test or
    /// an extract of compiled code at the default width (x86-64, plain
    /// build, counted 4 and 6 Oct 2026), brought in by edits to other
    /// files that touched no decode loop. A copy that is always inlined
    /// takes that call site off the partition. `seek` itself is left as
    /// it is, for the reason the note above gives: forcing IT inline
    /// reshaped the serial `apply_one`.
    ///
    /// x86-64 ONLY. On aarch64 `seek` is inlined at that call already,
    /// and this forced copy there cost 1.1 percent of instructions at the
    /// default width (plain build, counted 6 Oct 2026), so the tape decode
    /// keeps `seek` on every other system.
    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[inline(always)]
    pub(crate) fn seek_tape(&mut self, pos: usize) {
        debug_assert!(pos <= self.nbits);
        self.next = pos / 8;
        self.buf = 0;
        self.have = 0;
        self.refill();
        self.advance((pos % 8) as u32);
    }

    /// Valid bits not yet consumed.
    #[inline(always)]
    pub(crate) fn remaining(&self) -> usize {
        self.nbits.saturating_sub(self.position())
    }

    /// Whether any valid bit is left.
    #[inline(always)]
    pub(crate) fn at_end(&self) -> bool {
        self.position() >= self.nbits
    }

    // THE READ SURFACE COMES IN TWO FORMS, chosen by `target_arch`
    // (the standing rule: an optimisation is compiled only
    // where it helps). On aarch64 the buffer's watermark is 16 bits and the
    // symbol loops read through `peek_code`, `take_small` and
    // `advance_buffered`. On every other architecture the reader is the one
    // main had before the watermark, exactly: the three names below are thin
    // forwards to the old `peek`, `take` and `advance`, so they compile to the
    // calls they replaced (proved census-SAME against main on x86-64). The
    // reader differential in the tests runs on both.

    /// The next `n` bits without consuming them, `1 <= n <= 32`, with bits
    /// at or past the block's limit read as zero.
    #[cfg(not(target_arch = "aarch64"))]
    #[inline(always)]
    pub(crate) fn peek(&self, n: u32) -> u32 {
        debug_assert!((1..=32).contains(&n));
        (self.buf >> (64 - n)) as u32
    }

    /// The next `n` bits without consuming them, `1 <= n <= 32`, with bits
    /// at or past the block's limit read as zero.
    ///
    /// The buffer is only guaranteed 16 bits deep between symbols, so a
    /// wider look refills a COPY of the reader and leaves this one as it
    /// was; the code lookup and the small field read never come here.
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    #[allow(dead_code)]
    pub(crate) fn peek(&self, n: u32) -> u32 {
        debug_assert!((1..=32).contains(&n));
        if self.have < n {
            let mut ready = *self;
            ready.refill();
            return (ready.buf >> (64 - n)) as u32;
        }
        (self.buf >> (64 - n)) as u32
    }

    /// The next 15 bits, the longest code: the old 15 bit lookahead.
    #[cfg(not(target_arch = "aarch64"))]
    #[inline(always)]
    pub(crate) fn peek_code(&self) -> u32 {
        self.peek(15)
    }

    /// The next 15 bits, the longest code. The refill below keeps at least
    /// `min(16, valid bits left)` buffered at every symbol boundary, and bits
    /// past the data or the limit are zero, so this never needs its own
    /// refill.
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    pub(crate) fn peek_code(&self) -> u32 {
        debug_assert!(self.have >= 15 || self.remaining() < 15);
        (self.buf >> 49) as u32
    }

    /// The loaded bits, most significant first, topped up first so that at
    /// least 56 are loaded wherever the block has that many left. Bits at
    /// or past the block's limit read as zero, as `peek` reads them. Its
    /// one caller is the tape decode's literal batch.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    pub(crate) fn window(&mut self) -> u64 {
        self.refill();
        self.buf
    }

    /// Consume `n` bits already known to be inside the block.
    #[cfg(not(target_arch = "aarch64"))]
    #[inline(always)]
    pub(crate) fn advance(&mut self, n: u32) {
        debug_assert!(n <= self.have || self.position() + n as usize > self.nbits);
        self.buf <<= n;
        self.have = self.have.saturating_sub(n);
        if self.have < 32 {
            self.refill();
        }
    }

    /// Consume `n` bits already known to be inside the block, for ANY `n`
    /// up to 32: refills first when fewer are buffered. The seek and the
    /// tests come here; the symbol loops use [`BitReader::advance_buffered`],
    /// which is this without the availability branch (written apart because
    /// that branch inlined a second refill into every decode loop:
    /// `decode_block` 3242 to 5895 instructions on aarch64, 25 Sep 2026).
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    pub(crate) fn advance(&mut self, n: u32) {
        if self.have < n {
            self.refill();
        }
        debug_assert!(n <= self.have || self.position() + n as usize > self.nbits);
        self.buf <<= n;
        self.have = self.have.saturating_sub(n);
        if self.have < 16 {
            self.refill();
        }
    }

    /// Consume `n` bits the caller knows are inside the block: the old
    /// `advance`.
    #[cfg(not(target_arch = "aarch64"))]
    #[inline(always)]
    pub(crate) fn advance_buffered(&mut self, n: u32) {
        self.advance(n);
    }

    /// Consume `n` bits the caller knows are BUFFERED, not just inside the
    /// block: a code length after a lookup, or a field a checked read has
    /// already made room for.
    ///
    /// **The watermark is 16, not 32.** A Huffman code is at most 15 bits,
    /// so a symbol boundary needs 16 buffered, not 32; refilling below 16
    /// takes the refill off most symbols. A caller that consumes more than
    /// is buffered (a wide read) refills first, in `take`, before it gets here.
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    pub(crate) fn advance_buffered(&mut self, n: u32) {
        debug_assert!(n <= self.have);
        self.buf <<= n;
        self.have = self.have.saturating_sub(n);
        if self.have < 16 {
            self.refill();
        }
    }

    /// Read `n` bits, `n <= 32`. `Truncated` when the block has fewer left.
    #[cfg(not(target_arch = "aarch64"))]
    #[inline(always)]
    pub(crate) fn take(&mut self, n: u32) -> Result<u32> {
        if n == 0 {
            return Ok(0);
        }
        if self.remaining() < n as usize {
            return Err(fault::truncated());
        }
        let value = self.peek(n);
        self.advance(n);
        Ok(value)
    }

    /// Read `n` bits, `n <= 32`. `Truncated` when the block has fewer left.
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    pub(crate) fn take(&mut self, n: u32) -> Result<u32> {
        if n == 0 {
            return Ok(0);
        }
        if self.remaining() < n as usize {
            return Err(fault::truncated());
        }
        if self.have < n {
            self.refill();
        }
        let value = (self.buf >> (64 - n)) as u32;
        self.advance_buffered(n);
        Ok(value)
    }

    /// A field of at most 15 bits: the old `take`.
    #[cfg(not(target_arch = "aarch64"))]
    #[inline(always)]
    pub(crate) fn take_small(&mut self, n: u32) -> Result<u32> {
        self.take(n)
    }

    /// [`BitReader::take`] for a field of at most 15 bits: the length
    /// extras (at most 9) and the distance extras below four bits. After the
    /// remaining check the 16 bit watermark has them buffered, so the
    /// wide read's own availability branch is skipped.
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    pub(crate) fn take_small(&mut self, n: u32) -> Result<u32> {
        debug_assert!(n <= 15);
        if n == 0 {
            return Ok(0);
        }
        if self.remaining() < n as usize {
            return Err(fault::truncated());
        }
        debug_assert!(self.have >= n);
        let value = (self.buf >> (64 - n)) as u32;
        self.advance_buffered(n);
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reader's whole contract, said the slowest way there is: bit `i`
    /// of the stream is bit `7 - i % 8` of byte `i / 8`, and bits at or
    /// past the limit are zero.
    fn reference(data: &[u8], nbits: usize, at: usize, n: u32) -> u32 {
        let mut value = 0u32;
        for step in 0..n as usize {
            let index = at + step;
            let bit = if index < nbits {
                (data[index >> 3] >> (7 - (index & 7))) & 1
            } else {
                0
            };
            value = (value << 1) | u32::from(bit);
        }
        value
    }

    fn payload(len: usize) -> Vec<u8> {
        (0..len as u32)
            .map(|i| (i * 37 + i / 5 + 11) as u8)
            .collect()
    }

    /// Every width at every position, over payloads of every length up to
    /// three refills, with every final byte bit count.
    #[test]
    fn the_reader_answers_what_the_bits_say() {
        for len in [0usize, 1, 2, 3, 7, 8, 9, 15, 16, 17, 23, 24, 25, 31, 33] {
            let data = payload(len);
            for used in 1..=8usize {
                if len == 0 && used != 8 {
                    continue;
                }
                let nbits = if len == 0 { 0 } else { (len - 1) * 8 + used };
                for width in [1u32, 2, 3, 7, 8, 9, 15, 16, 24, 32] {
                    let mut bits = BitReader::new(&data, nbits);
                    let mut at = 0usize;
                    while at < nbits {
                        assert_eq!(bits.position(), at, "len {len} used {used}");
                        assert_eq!(bits.remaining(), nbits - at);
                        assert!(!bits.at_end());
                        assert_eq!(
                            bits.peek(width),
                            reference(&data, nbits, at, width),
                            "len {len} used {used} width {width} at {at}"
                        );
                        let step = width.min((nbits - at) as u32);
                        if step == 0 {
                            break;
                        }
                        bits.advance(step);
                        at += step as usize;
                    }
                    assert!(bits.at_end());
                    assert_eq!(bits.remaining(), 0);
                }
            }
        }
    }

    /// `seek` puts the reader exactly where a parked worker left it.
    #[test]
    fn a_seek_lands_on_the_bit_it_names() {
        let data = payload(40);
        let nbits = 39 * 8 + 5;
        for at in (0..=nbits).step_by(1) {
            let mut bits = BitReader::new(&data, nbits);
            bits.seek(at);
            assert_eq!(bits.position(), at);
            assert_eq!(bits.remaining(), nbits - at);
            assert_eq!(bits.peek(15), reference(&data, nbits, at, 15), "at {at}");
        }
    }

    /// `take` refuses what the block does not hold, and consumes nothing
    /// when it refuses.
    #[test]
    fn take_refuses_past_the_limit() {
        let data = payload(4);
        let nbits = 3 * 8 + 2;
        let mut bits = BitReader::new(&data, nbits);
        bits.advance(24);
        assert_eq!(bits.take(2).unwrap(), reference(&data, nbits, 24, 2));
        assert!(bits.take(1).is_err());
        assert_eq!(bits.position(), nbits);
        assert_eq!(bits.take(0).unwrap(), 0);
    }

    /// The final byte's bits past the limit are not the block's, whatever
    /// the byte holds.
    #[test]
    fn the_final_bytes_spare_bits_read_as_zero() {
        let data = [0xffu8, 0xff];
        for used in 1..=8usize {
            let nbits = 8 + used;
            let bits = BitReader::new(&data, nbits);
            let want = reference(&data, nbits, 0, 16);
            assert_eq!(bits.peek(16), want, "used {used}");
            assert_eq!(want.count_ones() as usize, nbits);
        }
    }
}

#[cfg(test)]
mod reader_differential {
    use super::*;

    /// The reader's contract as a plain bit vector: the first `nbits` bits
    /// of `data`, zero beyond them.
    struct Model {
        bits: Vec<bool>,
        nbits: usize,
        pos: usize,
    }

    impl Model {
        fn new(data: &[u8], nbits: usize) -> Model {
            let bits = (0..data.len() * 8)
                .map(|i| i < nbits && data[i / 8] >> (7 - i % 8) & 1 == 1)
                .collect();
            Model {
                bits,
                nbits,
                pos: 0,
            }
        }
        fn peek(&self, n: u32) -> u32 {
            (0..n as usize).fold(0u32, |acc, i| {
                (acc << 1) | u32::from(self.bits.get(self.pos + i).copied().unwrap_or(false))
            })
        }
    }

    fn lcg(seed: &mut u32) -> u32 {
        *seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *seed >> 8
    }

    /// Every operation the decoders use, in random order, against the model:
    /// peek at every width, take at every width, validated advance, seek,
    /// exhaustion and the zero padding past the block's limit.
    #[test]
    fn the_reader_agrees_with_a_bit_vector_model() {
        let mut seed = 0x5eed_1234_u32;
        for len in 0..=40usize {
            let data: Vec<u8> = (0..len).map(|_| lcg(&mut seed) as u8).collect();
            let low = len.saturating_sub(1) * 8;
            for nbits in low..=len * 8 {
                let mut r = BitReader::new(&data, nbits);
                let mut m = Model::new(&data, nbits);
                for _ in 0..400 {
                    let n = 1 + lcg(&mut seed) % 32;
                    assert_eq!(r.peek(n), m.peek(n), "peek {n} at {}", m.pos);
                    match lcg(&mut seed) % 6 {
                        0 => {
                            let want = if m.nbits - m.pos.min(m.nbits) >= n as usize {
                                Some(m.peek(n))
                            } else {
                                None
                            };
                            let got = r.take(n).ok();
                            assert_eq!(got, want, "take {n} at {}", m.pos);
                            if want.is_some() {
                                m.pos += n as usize;
                            }
                        }
                        1 => {
                            let room = (m.nbits - m.pos.min(m.nbits)).min(32) as u32;
                            if room > 0 {
                                let k = 1 + lcg(&mut seed) % room;
                                // Up to 15 bits are always buffered
                                // (the watermark's promise), so the
                                // unchecked form may take them.
                                if k <= 15 && lcg(&mut seed).is_multiple_of(2) {
                                    r.advance_buffered(k);
                                } else {
                                    r.advance(k);
                                }
                                m.pos += k as usize;
                            }
                        }
                        2 => {
                            let pos = (lcg(&mut seed) as usize) % (m.nbits + 1);
                            r.seek(pos);
                            m.pos = pos;
                        }
                        3 => {
                            assert_eq!(r.take(0).ok(), Some(0));
                            assert_eq!(r.peek_code(), m.peek(15), "peek_code at {}", m.pos);
                        }
                        4 if m.nbits - m.pos.min(m.nbits) > 0 => {
                            let n = 1 + lcg(&mut seed) % 15;
                            let want = if m.nbits - m.pos.min(m.nbits) >= n as usize {
                                Some(m.peek(n))
                            } else {
                                None
                            };
                            let got = r.take_small(n).ok();
                            assert_eq!(got, want, "take_small {n} at {}", m.pos);
                            if want.is_some() {
                                m.pos += n as usize;
                            }
                        }
                        _ => {}
                    }
                    assert_eq!(r.position(), m.pos, "position");
                    assert_eq!(r.remaining(), m.nbits - m.pos.min(m.nbits), "remaining");
                    assert_eq!(r.at_end(), m.pos >= m.nbits, "at_end");
                }
            }
        }
    }
}
