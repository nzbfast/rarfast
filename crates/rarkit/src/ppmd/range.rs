//! Spec I section 3.6: the carryless range decoder, 32-bit throughout.
//!
//! The section states three operations by what they leave in `low`,
//! `range` and `code`. Here a decision is made in two halves the caller
//! sees, [`RangeDecoder::count`] and [`RangeDecoder::take`], and a binary
//! decision in one, [`RangeDecoder::bit`]; both end in the one private
//! narrowing, which is where bytes are read.
//!
//! WHAT A FAILURE LEAVES BEHIND IS PART OF THIS FILE'S CONTRACT. A refusal
//! leaves the three quantities exactly as they were found, and an input
//! that runs out leaves them as the last whole byte left them. A caller
//! may carry on after either: a solid stream moves to its next member
//! with this decoder. A decoder left holding a range shifted down for a
//! binary decision that was then refused would divide by zero at the
//! next one; one byte of `fixtures/legacy/archives/r393_md.rar` flipped
//! does exactly that, and `ppmd::tests` pins it.

use super::{fault, PpmFault, StreamBytes};
use crate::Result;

/// `TOP` is `2^24` and `BOT` is `2^15` (spec I 3.6), held as the shifts
/// that test against them.
const TOP_SHIFT: u32 = 24;
const BOT_SHIFT: u32 = 15;

/// What a binary context's probability is out of: 16,384 (spec I 3.6).
const WHOLE: u32 = 16_384;

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct RangeDecoder {
    low: u32,
    range: u32,
    code: u32,
}

#[inline(always)]
fn refused<T>() -> Result<T> {
    Err(fault(PpmFault::RangeOutOfBounds))
}

impl RangeDecoder {
    /// Set the decoder up from the four bytes after a block header, the
    /// first of them the most significant.
    pub(super) fn init(&mut self, input: &mut impl StreamBytes) -> Result<()> {
        *self = RangeDecoder {
            low: 0,
            range: u32::MAX,
            code: 0,
        };
        // `code` alone takes these four: `low` and `range` are already
        // 3.6's start values.
        for _ in 0..4 {
            self.code = (self.code << 8) | u32::from(input.next_byte()?);
        }
        Ok(())
    }

    /// How far `code` stands above `low`, mod 2^32.
    #[inline(always)]
    fn offset(&self) -> u32 {
        self.code.wrapping_sub(self.low)
    }

    /// The count this symbol falls in, out of `total`. The caller checks it
    /// against its own total and raises `RangeOutOfBounds` when it is not
    /// below it (spec I 3.7 says where).
    ///
    /// Refused, with nothing changed, when `total` is 0 or the range holds
    /// fewer than `total` values: either way there is nothing to divide by.
    /// On success `range` is as low as 1 until the matching `take` widens
    /// it, and a caller that refuses the count in between leaves it so,
    /// which is why `bit` trusts nothing about the range it finds.
    #[inline(always)]
    pub(super) fn count(&mut self, total: u32) -> Result<u32> {
        match self.range.checked_div(total) {
            Some(each) if each != 0 => {
                self.range = each;
                Ok(self.offset() / each)
            }
            _ => refused(),
        }
    }

    /// Narrow to the sub-range `[lo, lo + size)` of the total the matching
    /// [`RangeDecoder::count`] divided by.
    ///
    /// `size` is at least 1 and `lo + size` is at most that total, at all
    /// five call sites in `model.rs`: each picks its sub-range from a count
    /// it has just checked against a running sum, which makes the picked
    /// size positive and the sum no larger than the total. So the products
    /// in `narrow` cannot wrap and cannot be zero. Were `size` ever 0 the
    /// range would be 0 and `narrow` would read bytes until the member ran
    /// out and raise `Truncated`: slow, but never a panic and never a
    /// decoded byte.
    #[inline(always)]
    pub(super) fn take(&mut self, lo: u32, size: u32, input: &mut impl StreamBytes) -> Result<()> {
        self.narrow(self.range, lo, size, input)
    }

    /// One binary decision at probability `p` out of 16,384. Returns false
    /// for the symbol and true for the escape.
    ///
    /// Spec I 3.6 states it as a shift of the range by 14 and then a `take`
    /// of `[0, p)` or of `[p, 16,384)`, and that is how it is made: the
    /// shifted range stays in a local until the decision is known to be
    /// sound, so both refusals leave the decoder untouched.
    ///
    /// The first refusal is not idle. On a decoder that has not faulted
    /// `narrow` only ever returns with `range` at least `2^15`, which the
    /// shift leaves at least 2; but a count the caller refused leaves a
    /// range as low as 1 behind it (see `count`), and this decoder may be
    /// entered again after that.
    ///
    /// The products cannot wrap: the shift leaves less than `2^18` and both
    /// multipliers are at most 16,384. Nor can the new range be 0: `p` is 1
    /// to 16,383 out of the caller's table (`model.rs` proves the row and
    /// column, and the update step keeps the entry in range).
    #[inline(always)]
    pub(super) fn bit(&mut self, p: u32, input: &mut impl StreamBytes) -> Result<bool> {
        let each = self.range / WHOLE;
        if each == 0 {
            return refused();
        }
        let v = self.offset() / each;
        if v >= WHOLE {
            return refused();
        }
        let escape = v >= p;
        let (lo, size) = if escape { (p, WHOLE - p) } else { (0, p) };
        self.narrow(each, lo, size, input)?;
        Ok(escape)
    }

    /// The end of every decision: `size` parts of `each` from part `lo`
    /// up, and then spec I 3.6's normalise.
    #[inline(always)]
    fn narrow(
        &mut self,
        each: u32,
        lo: u32,
        size: u32,
        input: &mut impl StreamBytes,
    ) -> Result<()> {
        self.range = each.wrapping_mul(size);
        self.low = self.low.wrapping_add(each.wrapping_mul(lo));
        while self.is_short()? {
            self.shift_in(input.next_byte()?);
        }
        Ok(())
    }

    /// Whether normalise owes another byte. The range is too narrow to
    /// decide from while its two ends still agree in their top byte; and
    /// once they differ, while it is below `2^15`, in which case it first
    /// becomes the low 15 bits of `-low`, which is refused if that is 0
    /// (the loop would then run until the input ended).
    #[inline(always)]
    fn is_short(&mut self) -> Result<bool> {
        let ends_differ = (self.low ^ self.low.wrapping_add(self.range)) >> TOP_SHIFT != 0;
        if ends_differ {
            if self.range >> BOT_SHIFT != 0 {
                return Ok(false);
            }
            self.range = self.low.wrapping_neg() & ((1 << BOT_SHIFT) - 1);
            if self.range == 0 {
                return refused();
            }
        }
        Ok(true)
    }

    /// One more byte of the stream under all three quantities.
    #[inline(always)]
    fn shift_in(&mut self, byte: u8) {
        self.low <<= 8;
        self.range <<= 8;
        self.code = (self.code << 8) | u32::from(byte);
    }
}
