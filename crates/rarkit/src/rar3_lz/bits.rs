//! The bit input a RAR 3 stream is read through (SPEC-H1 section 2).
//!
//! Bits are taken most significant first. The reader sits over the packed
//! bytes of one stream: spec F concatenates a solid chain's member spans,
//! and [`Bits::begin_member`] moves the limit on to the member being
//! decoded. A symbol may straddle the boundary between two spans, because a
//! member that ends inside a block leaves the next one mid byte
//! (SPEC-H1 3.8), so the limit moves forward without moving the position.
//!
//! # Where the bytes come from
//!
//! Either [`Store::Whole`] - a slice a caller already holds, which is what
//! the vectors, the benches and `internals_h` use - or [`Store::Stream`],
//! spec F's pull stream (spec F 2.3), read through a bounded buffer.
//!
//! The streaming form is what `extract` uses, and it is why this package's
//! working memory no longer grows with a member's PACKED size. It used to:
//! `read/extract.rs` read a member's packed bytes whole into one buffer
//! (`slurp`) because this reader took a slice, so a 46 MB member was 46 MB
//! held, bounded only by the operation's working limit rather than by
//! anything in SPEC-H1 4.2, whose figure is "the window plus under
//! 128 KiB, whatever the archive says".
//!
//! The reader only ever moves FORWARD - `begin_member` jumps to the next
//! member's span, which spec F lays after this one - so the stream needs no
//! history: bytes the position has passed are handed back to the source and
//! the buffer slides. What it costs on the hot path is one subtraction per
//! refill, because a byte offset is now relative to the buffer's base.

use crate::rar5_lz::PackedSource;
use crate::{Error, ErrorKind, Result};

/// Packed bytes asked of the pull stream at a time, and the size of the
/// buffer it therefore holds. Within SPEC-H1 4.2's 128 KiB.
const FILL: usize = 64 * 1024;

/// Bytes that must be held ahead of the position for a refill and for the
/// shared-reference [`BitSource::peek`] that may follow it: one eight byte
/// word, plus the eight bytes 64 bits of consumption can cross, with room
/// to spare.
const AHEAD: usize = 64;

/// Bit input, shared with spec I (which reads whole bytes through it) and
/// with spec J's record reader.
pub(crate) trait BitSource {
    /// The next `count` bits, most significant first, zero filled past the
    /// end of the member's packed data. `count` is 1 to 32.
    fn peek(&self, count: u8) -> u32;
    /// [`BitSource::peek`], allowed to refill a cache of its own. This is
    /// the form the hot path uses.
    #[inline(always)]
    fn peek_ready(&mut self, count: u8) -> u32 {
        self.peek(count)
    }
    /// Bits of the member's packed data not yet consumed.
    fn available(&self) -> u64;
    /// Drop `count` bits.
    fn consume(&mut self, count: u8);
    /// [`BitSource::consume`] for a caller that has just had an answer of
    /// `at least` `count` bits out of [`BitSource::peek_ready`], so the
    /// cache is known to hold them. This is the form the literal burst
    /// uses: the direct table answers at most twelve bits and the burst
    /// peeks sixteen before each symbol, so the short-cache arm of
    /// `consume` is unreachable there and testing for it costs a branch a
    /// symbol.
    #[inline(always)]
    fn consume_ready(&mut self, count: u8) {
        self.consume(count);
    }
    /// The cached word, how many of its bits are live, and the bit
    /// position, for a caller that holds all three in LOCALS across a run
    /// of symbols and hands them back with [`BitSource::put_cache`] before
    /// it calls anything else on this reader. The literal burst's pair
    /// loop is that caller: held in the reader, the word went to memory
    /// and came back on every pair, a store to load round trip on the
    /// loop's own carried chain.
    fn take_cache(&self) -> (u64, u8, u64);
    /// Hand back what [`BitSource::take_cache`] lent, advanced by exactly
    /// the bits consumed from it and no others.
    fn put_cache(&mut self, window: u64, have: u8, at: u64);
    /// The refilled word and its live bit count at bit position `at`,
    /// WITHOUT touching the reader, when the bytes it needs are already
    /// held and the whole word is inside the member; `None` otherwise, and
    /// the caller then refills through the reader. Where it answers, it
    /// answers exactly what a refill at `at` would leave in the cache,
    /// which is what lets the pair loop refill in its locals rather than
    /// sending its word through memory and back at every refill.
    fn refill_word(&self, at: u64) -> Option<(u64, u8)>;
    /// Move to the next byte boundary, discarding the bits between.
    fn align_to_byte(&mut self);
    /// `count` bits, or [`ErrorKind::Truncated`] with nothing consumed.
    fn read(&mut self, count: u8) -> Result<u32>;
}

/// Where a reader's packed bytes come from.
enum Store<'a> {
    /// Every byte of the stream, already in memory.
    Whole(&'a [u8]),
    /// Spec F's pull stream, and the bounded buffer it holds.
    Stream {
        source: &'a mut dyn PackedSource,
        /// Absolute byte offset, in the stream, of the source's first
        /// available byte.
        base: u64,
        /// Whether the source has handed over its last byte.
        ended: bool,
    },
}

/// A reader over one stream's packed bytes.
///
/// `window` caches the next `have` bits at `at`, most significant first,
/// so a peek is a shift of a register rather than a load and a shift; it
/// is rebuilt from `at` whenever it runs short, which makes it a cache
/// and not state a caller can desynchronise.
pub(crate) struct Bits<'a> {
    store: Store<'a>,
    /// Bit position from the start of the STREAM, not of the buffer.
    at: u64,
    /// Bit position one past the end of the member being decoded.
    limit: u64,
    window: u64,
    have: u8,
    /// The pull stream's own error, which no shared-reference reader can
    /// return. [`Bits::fault`] hands it to the caller, which prefers it to
    /// whatever the decode made of the zero bits that followed.
    fault: Option<Error>,
    /// Stream byte offset one past the last byte held now, or `u64::MAX`
    /// once the stream has ended and there is nothing left to pull.
    ///
    /// Cached so the per-refill check is one compare rather than two
    /// calls into the store. The `u64::MAX` for an ended stream is what
    /// makes that check WORK on a short member: a member whose packed
    /// data is under [`AHEAD`] bytes - and the 20,000 member RAR 2.9 leg
    /// is 20,000 of those - would otherwise fail the compare on every
    /// refill and take the slow path for the whole archive.
    held_end: u64,
}

impl<'a> Bits<'a> {
    /// A reader over `data`, with the whole of it available.
    pub(crate) fn new(data: &'a [u8]) -> Bits<'a> {
        Bits {
            limit: (data.len() as u64) * 8,
            held_end: data.len() as u64,
            store: Store::Whole(data),
            at: 0,
            window: 0,
            have: 0,
            fault: None,
        }
    }

    /// A reader over spec F's pull stream, holding at most [`FILL`] bytes
    /// of it.
    ///
    /// The limit starts UNKNOWN, which reads as "there are more bits", and
    /// is tightened to the stream's real end the moment [`Bits::ensure`]
    /// finds it. That is not a guess about the tail: `ensure` asks for
    /// [`FILL`] bytes and learns the end as soon as fewer are left, so the
    /// limit is exact for the whole of the last 64 KiB - which is the only
    /// region where anything asks. A member shorter than that has its
    /// exact limit before the first symbol is read.
    pub(crate) fn streaming(source: &'a mut dyn PackedSource) -> Bits<'a> {
        Bits {
            store: Store::Stream {
                source,
                base: 0,
                ended: false,
            },
            at: 0,
            limit: u64::MAX,
            window: 0,
            have: 0,
            fault: None,
            held_end: 0,
        }
    }

    /// The pull stream's own error, if it had one. A caller that gets an
    /// error out of the decode should prefer this one.
    pub(crate) fn fault(&mut self) -> Option<Error> {
        self.fault.take()
    }

    /// Start the member whose packed span is `span` (byte offsets into
    /// the stream).
    ///
    /// A member's data begins at the first bit of its own span: bits left
    /// over in the member before it are not read, because the next
    /// member's packed data is a separate span (SPEC-H1 3.8). A member
    /// that resumes inside a block resumes at its own first bit, under the
    /// tables and the state the stream carries.
    pub(crate) fn begin_member(&mut self, span: std::ops::Range<usize>) {
        self.at = (span.start as u64).saturating_mul(8);
        // A streaming reader is given `usize::MAX` for the end it cannot
        // know, and that is NO limit, by name: `ensure` replaces it with
        // the real one when the stream ends. Multiplying it out is no
        // limit only where it saturates a `u64`; on a 32-bit `usize` it
        // was a limit at byte 4 GiB - 1, which nothing ever raises, so a
        // member with more packed data than that met a false end.
        self.limit = if span.end == usize::MAX {
            u64::MAX
        } else {
            (span.end as u64).saturating_mul(8)
        };
        self.have = 0;
        self.ensure();
        // A member that begins with the stream already ended keeps the
        // limit `ensure` found; one that does not will find it later.
    }

    /// The bit position, for a test or a caller that resumes a stream.
    // Live in the `cfg(test)` build only: this package's own tests are its
    // one caller.
    #[allow(dead_code)]
    pub(crate) fn position(&self) -> u64 {
        self.at
    }

    /// The bytes held now, and the stream offset of the first of them.
    #[inline(always)]
    fn held(&self) -> (&[u8], u64) {
        match &self.store {
            Store::Whole(data) => (data, 0),
            Store::Stream { source, base, .. } => (source.available(), *base),
        }
    }

    /// Hand back the bytes the position has passed and pull more, so that
    /// [`AHEAD`] bytes sit at or after the position while the stream has
    /// them.
    ///
    /// Only the mutable path calls this, which is what makes the shared
    /// [`BitSource::peek`] safe: every `&mut self` operation leaves enough
    /// buffered for the eight byte word a refill reads.
    #[inline(always)]
    fn ensure(&mut self) {
        // The whole-slice store never needs anything, and a streaming one
        // needs nothing while it still holds `AHEAD` bytes: one compare
        // against a cached end, not two calls into the store.
        if self.at / 8 + AHEAD as u64 <= self.held_end {
            return;
        }
        self.ensure_slow();
    }

    #[cold]
    fn ensure_slow(&mut self) {
        let want = self.at / 8;
        let Store::Stream {
            source,
            base,
            ended,
        } = &mut self.store
        else {
            return;
        };
        if want >= *base {
            // The reader never goes backwards, so everything before the
            // position is finished with.
            // Clamped in `u64` and THEN narrowed: `want - base` is a
            // stream offset and may be past 4 GiB, and narrowing first
            // would truncate on a 32-bit target and leave the reader
            // advancing by the wrong step or not at all.
            let step = (want - *base).min(source.available().len() as u64) as usize;
            if step > 0 {
                source.advance(step);
                *base += step as u64;
            }
        }
        if *ended || source.available().len() >= AHEAD {
            let end = *base + source.available().len() as u64;
            if *ended {
                self.limit = self.limit.min(end.saturating_mul(8));
                // Nothing more will ever arrive, so nothing more need be
                // checked. The buffer keeps every byte from `base` on,
                // because `ensure` stops handing them back too.
                self.held_end = u64::MAX;
            } else {
                self.held_end = end;
            }
            return;
        }
        if let Err(error) = source.fill(FILL) {
            // A source that failed has no more bytes to give, and the
            // decode runs on to its end against the zero fill of section
            // 3.8. The caller is handed this error instead of whatever it
            // made of those zeros.
            *ended = true;
            self.fault.get_or_insert(error);
        } else if source.available().len() < FILL {
            // `fill` reads until it has what was asked for or the stream
            // stops, so a short answer is the end of the packed bytes.
            *ended = true;
        }
        if let Store::Stream {
            source,
            base,
            ended,
        } = &self.store
        {
            let end = *base + source.available().len() as u64;
            if *ended {
                // The member ends where the stream does, however much its
                // header declared.
                self.limit = self.limit.min(end.saturating_mul(8));
                self.held_end = u64::MAX;
            } else {
                self.held_end = end;
            }
        }
    }

    /// Rebuild the cache from `at`: the next bits of the member's packed
    /// data, most significant first, zero filled past its end.
    #[inline]
    fn refill(&mut self) {
        self.ensure();
        self.refill_from_buffer();
    }

    /// [`Bits::refill`] without the pull, for a reader that already holds
    /// what it needs.
    #[inline]
    fn refill_from_buffer(&mut self) {
        let shift = (self.at % 8) as u32;
        let (data, base) = self.held();
        let byte = (self.at / 8).saturating_sub(base) as usize;
        let head = match data.get(byte..byte + 8) {
            Some(eight) => u64::from_be_bytes(eight.try_into().unwrap_or([0; 8])),
            None => self.tail_word(byte),
        };
        // The bits below `shift` come from the ninth byte, which nothing
        // here reads: every read is at most 32 bits wide.
        self.window = head << shift;
        let left = self.limit.saturating_sub(self.at);
        let room = 64 - u64::from(shift as u8);
        if left >= room {
            // The whole word is the member's. Nothing to zero fill: the
            // `<< shift` above already shifted zeros into the low
            // `shift` bits, which is exactly the region below `have`, so
            // the mask the short arm applies would be a no-op. Leaving
            // it out takes two shifts and a branch off the refill, which
            // is one refill in six or seven literals on a stream of
            // eight bit codes.
            self.have = room as u8;
            return;
        }
        // Past the member's packed data the answer is zero filled.
        self.have = left as u8;
        if self.have == 0 {
            self.window = 0;
            return;
        }
        let drop = 64 - u32::from(self.have);
        self.window = (self.window >> drop) << drop;
    }

    #[cold]
    fn tail_word(&self, byte: usize) -> u64 {
        let (data, base) = self.held();
        // Clamped in `u64` and THEN narrowed. `limit` is a stream-wide
        // BIT count, so the byte count it yields may be past 4 GiB;
        // narrowing first truncates on a 32-bit target and the `min` then
        // picks the wrong end, which here means reading zeros in place of
        // live bytes at the tail of a large member.
        let stop = self.limit.div_ceil(8).saturating_sub(base);
        let end = stop.min(data.len() as u64) as usize;
        let mut word = 0u64;
        for i in 0..8 {
            let got = match byte.checked_add(i) {
                #[allow(clippy::indexing_slicing)] // `at < end <= data.len()`
                Some(at) if at < end => data[at],
                _ => 0,
            };
            word = (word << 8) | u64::from(got);
        }
        word
    }
}

impl Bits<'_> {
    /// The cached bits, refilled when fewer than `count` are held.
    #[inline(always)]
    fn ready(&mut self, count: u8) -> u64 {
        if self.have < count {
            self.refill();
        }
        self.window
    }
}

impl BitSource for Bits<'_> {
    #[inline(always)]
    fn peek_ready(&mut self, count: u8) -> u32 {
        (self.ready(count) >> (64 - u32::from(count))) as u32
    }

    #[inline]
    fn peek(&self, count: u8) -> u32 {
        debug_assert!((1..=32).contains(&count));
        if self.have >= count {
            return (self.window >> (64 - u32::from(count))) as u32;
        }
        // The buffer already holds what this reads: every `&mut self`
        // operation leaves `AHEAD` bytes at or after the position, and
        // nothing consumes more than 64 bits between two of them.
        let (data, base) = self.held();
        let mut copy = Bits {
            held_end: data.len() as u64,
            store: Store::Whole(data),
            at: self.at.saturating_sub(base * 8),
            limit: self.limit.saturating_sub(base * 8),
            window: 0,
            have: 0,
            fault: None,
        };
        copy.refill_from_buffer();
        (copy.window >> (64 - u32::from(count))) as u32
    }

    #[inline]
    fn available(&self) -> u64 {
        self.limit.saturating_sub(self.at)
    }

    #[inline]
    fn consume(&mut self, count: u8) {
        self.at += u64::from(count);
        if self.have >= count {
            self.window <<= count;
            self.have -= count;
        } else {
            self.have = 0;
        }
    }

    #[inline(always)]
    fn consume_ready(&mut self, count: u8) {
        debug_assert!(self.have >= count);
        self.at += u64::from(count);
        self.window <<= count;
        self.have -= count;
    }

    #[inline(always)]
    fn take_cache(&self) -> (u64, u8, u64) {
        (self.window, self.have, self.at)
    }

    #[inline(always)]
    fn put_cache(&mut self, window: u64, have: u8, at: u64) {
        self.window = window;
        self.have = have;
        self.at = at;
    }

    #[inline(always)]
    fn refill_word(&self, at: u64) -> Option<(u64, u8)> {
        // The two conditions under which `refill` takes its fast arms:
        // `ensure` pulls nothing (the same compare it makes), and the
        // whole word is the member's, so nothing is zero filled.
        if at / 8 + AHEAD as u64 > self.held_end {
            return None;
        }
        let shift = (at % 8) as u32;
        let room = 64 - u64::from(shift as u8);
        if self.limit.saturating_sub(at) < room {
            return None;
        }
        let (data, base) = self.held();
        let byte = (at / 8).saturating_sub(base) as usize;
        let eight = data.get(byte..byte + 8)?;
        let head = u64::from_be_bytes(eight.try_into().unwrap_or([0; 8]));
        Some((head << shift, room as u8))
    }

    #[inline]
    fn align_to_byte(&mut self) {
        let to = self.at.div_ceil(8) * 8;
        self.consume((to - self.at) as u8);
    }

    /// `#[inline(always)]` since 22 Sep 2026: at plain `#[inline]` the
    /// release build kept this as a call of 123 instructions, and a fresh
    /// match reaches it up to twice in its serial chain (the length's
    /// extra bits and the distance's), each call spilling the reader's
    /// cached word around it. Its body is the same refill that
    /// [`BitSource::peek_ready`] already inlines into every decode.
    #[inline(always)]
    fn read(&mut self, count: u8) -> Result<u32> {
        if self.available() < u64::from(count) {
            return Err(Error::new(ErrorKind::Truncated));
        }
        let value = (self.ready(count) >> (64 - u32::from(count))) as u32;
        self.consume(count);
        Ok(value)
    }
}
