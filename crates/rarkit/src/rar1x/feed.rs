//! The bit stream of spec A section 2, pulled from a member's packed
//! bytes: most significant bit first, zero bits past the end (4.11).
//!
//! [`Feed`] is meant to live in its user's registers: every method that
//! runs per field is inlined, and the one path that is not, the refill
//! at a buffer's edge, takes and returns its words by value. Packed bytes
//! are staged 4 KiB at a time, so the refill is one load from a fixed
//! array.
//!
//! The refill runs once per decode step, not once per field: it leaves
//! at least [`STEP_BITS`] bits in hand, more than any one step of 4.4 to
//! 4.7 reads, and the field reads trust that and test nothing.

use crate::error::Error;
use crate::rar5_lz::PackedSource;

use super::codes::{Narrow, Wide};

/// How many packed bytes are asked of the source at a time.
const ASK: usize = 32 * 1024;

/// How many packed bytes are staged at a time.
const STAGE: usize = 4096;

/// How many bits [`Feed::top_up`] leaves in hand while the packed bytes
/// last. The most one step reads is 46: a flag byte's code (10) and, in
/// the short family, a repeat bit (1), an index (8), a `LENB` length (12)
/// and a 15 bit distance; a far match reads 45, at most 10 then 16, 12
/// and 7. The tail of a run of literals reads 17 more after its last
/// literal code (12), from the same refill. 56 covers each, and is what
/// one 8 byte load can always bring a window of 64 bits up to.
const STEP_BITS: i32 = 56;

/// What a [`Feed`] keeps outside its registers: the packed bytes staged
/// for it, and what is known of the source's end.
pub(super) struct Hold {
    staged: [u8; STAGE],
    /// The source has given its last byte.
    dry: bool,
    /// The source's own failure, kept for the member's caller.
    pub(super) fault: Option<Error>,
}

impl Hold {
    pub(super) fn new() -> Hold {
        Hold {
            staged: [0; STAGE],
            dry: false,
            fault: None,
        }
    }
}

pub(super) struct Feed<'s, S: PackedSource> {
    source: &'s mut S,
    hold: &'s mut Hold,
    /// `hold.staged[at..upto]` is packed bytes not yet in the window.
    at: usize,
    upto: usize,
    /// The next bits of the stream, the very next one at the top. Below
    /// the held bits it is zero.
    window: u64,
    /// How many bits of `window` are packed bits. Under 1 once a read has
    /// gone past the end of the packed bytes.
    held: i32,
}

/// Take staged bytes one at a time, staging more from the source as they
/// run out, until [`STEP_BITS`] bits are held or the source has no more.
/// Answers the feed's four words.
#[cold]
#[inline(never)]
fn scrape<S: PackedSource>(
    source: &mut S,
    hold: &mut Hold,
    mut at: usize,
    mut upto: usize,
    mut window: u64,
    mut held: i32,
) -> (usize, usize, u64, i32) {
    while held < STEP_BITS && !hold.dry {
        if at == upto {
            if source.available().is_empty() {
                if let Err(fault) = source.fill(ASK) {
                    hold.fault = Some(fault);
                    hold.dry = true;
                    break;
                }
            }
            let ready = source.available();
            let take = ready.len().min(STAGE);
            hold.staged[..take].copy_from_slice(&ready[..take]);
            source.advance(take);
            (at, upto) = (0, take);
            if take == 0 {
                hold.dry = true;
                break;
            }
        }
        if (0..=32).contains(&held) {
            if let Some(four) = hold.staged[..upto].get(at..at + 4) {
                let four: [u8; 4] = four.try_into().expect("four bytes");
                window |= u64::from(u32::from_be_bytes(four)) << (32 - held);
                held += 32;
                at += 4;
                continue;
            }
        }
        window |= u64::from(hold.staged[at]) << (56 - held);
        held += 8;
        at += 1;
    }
    (at, upto, window, held)
}

impl<'s, S: PackedSource> Feed<'s, S> {
    pub(super) fn new(source: &'s mut S, hold: &'s mut Hold) -> Feed<'s, S> {
        Feed {
            source,
            hold,
            at: 0,
            upto: 0,
            window: 0,
            held: 0,
        }
    }

    /// Hold at least [`STEP_BITS`] packed bits, or every one that is
    /// left: once per step, before the step's first field.
    ///
    /// With eight bytes staged this is one load and no test of how many
    /// bits are held. The window's bits below the held ones are zero or
    /// are the very stream bits that follow, left there by the load
    /// before, so the eight bytes from `at` may be laid over them whole;
    /// only the whole bytes that fit count as taken, and the held count
    /// becomes `held | 56`, which for `0 <= held < 64` is `held` plus
    /// those bytes' bits. A feed that has gone past the end is dry with
    /// nothing staged, and never comes here.
    #[inline(always)]
    pub(super) fn top_up(&mut self) {
        if let Some(eight) = self.hold.staged[..self.upto].get(self.at..self.at + 8) {
            debug_assert!((0..64).contains(&self.held));
            let eight: [u8; 8] = eight.try_into().expect("eight bytes");
            self.window |= u64::from_be_bytes(eight) >> self.held;
            self.at += (63 - self.held) as usize >> 3;
            self.held |= STEP_BITS;
            return;
        }
        (self.at, self.upto, self.window, self.held) = scrape(
            self.source,
            self.hold,
            self.at,
            self.upto,
            self.window,
            self.held,
        );
    }

    /// No packed bit is left. Asked right after [`Feed::top_up`].
    #[inline(always)]
    pub(super) fn spent(&self) -> bool {
        self.held <= 0
    }

    /// Take `count` bits. A step that reads more than [`Feed::top_up`]
    /// left would go below zero while packed bytes remain: debug builds
    /// stop there.
    #[inline(always)]
    fn drop_bits(&mut self, count: u32) {
        self.window <<= count;
        self.held -= count as i32;
        debug_assert!(
            self.held >= 0 || self.hold.dry,
            "rar1x: a step read past the bits its refill left"
        );
    }

    /// A field of 1 to 16 bits.
    #[inline(always)]
    pub(super) fn field(&mut self, bits: u32) -> u32 {
        let value = (self.window >> (64 - bits)) as u32;
        self.drop_bits(bits);
        value
    }

    #[inline(always)]
    pub(super) fn bit(&mut self) -> bool {
        self.field(1) == 1
    }

    /// A value of one of 4.2's codes.
    #[inline(always)]
    pub(super) fn coded(&mut self, code: &Wide) -> u32 {
        let entry = code[(self.window >> 52) as usize];
        self.drop_bits(u32::from(entry & 15));
        u32::from(entry >> 4)
    }

    /// A short-match index of 4.3.
    #[inline(always)]
    pub(super) fn index(&mut self, column: &Narrow) -> u32 {
        let entry = column[(self.window >> 56) as usize];
        self.drop_bits(u32::from(entry & 15));
        u32::from(entry >> 4)
    }

    /// The length code of a long match in its counted form (4.7, the
    /// case of a low average): 16 bits when the first eight are zero,
    /// otherwise the count of zero bits before the first one bit.
    #[inline(always)]
    pub(super) fn counted(&mut self) -> u32 {
        let next = (self.window >> 48) as u16;
        if next < 256 {
            self.drop_bits(16);
            u32::from(next)
        } else {
            let zeros = next.leading_zeros();
            self.drop_bits(zeros + 1);
            zeros
        }
    }
}
