//! The bit input the RAR 2.0 codec reads through (spec H1 section 2's
//! `BitSource`, which spec H3 section 2 adopts unchanged).
//!
//! RAR reads its bit stream most significant bit first out of bytes taken
//! in order. The reader keeps a 64 bit accumulator holding the next bits
//! left aligned, so a peek is a shift and a consume is a shift and a
//! refill: no per bit work on the hot path.

/// Bit input over one member's packed bytes.
///
/// Past the end the stream reads as zero bits, which is what
/// [`BitSource::peek`] promises and what a SYMBOL'S fields are read
/// through ([`BitSource::read_field`]); [`BitSource::read`], which a
/// block header and its tables are read through, refuses instead.
pub(crate) trait BitSource {
    /// The next `count` bits, most significant first, zero filled past the
    /// end of the input. `count` is at most 32.
    fn peek(&self, count: u8) -> u32;
    /// Bits not yet consumed.
    fn available(&self) -> u64;
    /// Drop `count` bits.
    fn consume(&mut self, count: u8);
    /// Consume `count` bits, refusing past the end of the input.
    fn read(&mut self, count: u8) -> crate::Result<u32>;
    /// Consume `count` bits of a symbol that began inside the input, the
    /// bits past its end read as zeros. Spec H3 3.5: such a symbol is read
    /// whole, every field of it, and reading them is no fault; whether a
    /// symbol may BEGIN is the caller's test of [`BitSource::available`].
    #[inline(always)]
    fn read_field(&mut self, count: u8) -> u32 {
        let value = self.peek(count);
        self.consume(count);
        value
    }
    /// Bytes from the one holding the next unread bit to the end of the
    /// input, counting a partly consumed byte in full (spec D 2.2's `R`).
    fn whole_bytes_left(&self) -> usize;
    /// How many bits have been consumed from the zero fill past the end
    /// of the input; 0 while every bit read was one the packed data holds.
    fn bits_past_end(&self) -> u64;
    /// Whether what was last read was completed by bits the packed data
    /// does not hold.
    #[inline(always)]
    fn past_end(&self) -> bool {
        self.bits_past_end() > 0
    }
}

/// A member's bit input for a block header met inside its packed data:
/// every bit the header asks for is granted, those past the end as zeros,
/// and nothing is refused (spec H3 3.5, "A block header that the end of
/// the packed data cuts", rule 1). `available` answers that there is
/// always more; how far the read ran past the end is asked of the input
/// itself afterwards ([`BitSource::bits_past_end`]).
pub(crate) struct PastEndAsZeros<'a, B: BitSource>(pub(crate) &'a mut B);

impl<B: BitSource> BitSource for PastEndAsZeros<'_, B> {
    #[inline(always)]
    fn peek(&self, count: u8) -> u32 {
        self.0.peek(count)
    }

    #[inline(always)]
    fn available(&self) -> u64 {
        u64::MAX
    }

    #[inline(always)]
    fn consume(&mut self, count: u8) {
        self.0.consume(count);
    }

    #[inline(always)]
    fn read(&mut self, count: u8) -> crate::Result<u32> {
        Ok(self.0.read_field(count))
    }

    #[inline]
    fn whole_bytes_left(&self) -> usize {
        self.0.whole_bytes_left()
    }

    #[inline(always)]
    fn bits_past_end(&self) -> u64 {
        self.0.bits_past_end()
    }
}

/// Packed bytes asked of the pull stream at a time, and so the size of
/// the buffer it holds. Spec H3 part A's member is read through this.
const FILL: usize = 64 * 1024;

/// How few bits the accumulator may hold before a refill tops it up.
///
/// It is the widest single read the trait allows, which is what makes the
/// invariant hold: a refill leaves more than 56 bits while any byte
/// remains, and no read takes more than 32, so topping up only BELOW this
/// floor still leaves every `peek` its bits. It is a floor and not 56
/// because a refill per symbol is a refill per twelve bits or so, where
/// this way one refill serves two or three symbols.
const REFILL_FLOOR: u32 = 32;

/// Where a reader's packed bytes come from.
enum Store<'a> {
    /// Every byte of the member, already in memory.
    Whole(&'a [u8]),
    /// Spec F's pull stream (spec F 2.3), and the bounded buffer it holds.
    ///
    /// This is what `extract` uses, and it is why a RAR 2.0 member's
    /// PACKED size is no longer held whole. It used to be: the reader
    /// took a slice, so `read/extract.rs` read the member in first
    /// (`slurp`) and a large member was bounded only by the operation's
    /// working limit.
    Stream {
        source: &'a mut dyn crate::rar5_lz::PackedSource,
        /// Whether the source has handed over its last byte.
        ended: bool,
    },
}

/// A [`BitSource`] over a member's packed bytes.
pub(crate) struct SliceBits<'a> {
    store: Store<'a>,
    /// Index, in the bytes held NOW, of the next byte to pull into `acc`.
    at: usize,
    /// The next bits, left aligned: bit 63 is the next bit out.
    acc: u64,
    /// Valid bits in `acc`, at most 64.
    have: u32,
    /// Bits consumed since the start, counting bits taken from the zero
    /// fill past the end of the input.
    consumed: u64,
    /// Bytes handed back to the pull stream, which the buffer no longer
    /// holds. Zero for a whole slice.
    base: u64,
    /// The member's byte length, once the stream's end has been found.
    total: Option<u64>,
    /// The same figure in BITS, or `u64::MAX` while the end has not been
    /// found. Held beside `total` rather than derived from it because
    /// [`BitSource::available`] is on the hot path - a prefix decode asks
    /// it once per symbol - and the `Option` costs a test and a select
    /// there that this costs nowhere.
    total_bits: u64,
    /// The pull stream's own error, which no shared-reference reader can
    /// return. [`SliceBits::fault`] hands it to the caller, which prefers
    /// it to whatever the decode made of the zero bits that followed.
    fault: Option<crate::Error>,
}

impl<'a> SliceBits<'a> {
    /// A reader positioned at the first bit of `bytes`.
    pub(crate) fn new(bytes: &'a [u8]) -> SliceBits<'a> {
        let total = bytes.len() as u64;
        let mut bits = SliceBits {
            store: Store::Whole(bytes),
            at: 0,
            acc: 0,
            have: 0,
            consumed: 0,
            base: 0,
            total: Some(total),
            total_bits: total.saturating_mul(8),
            fault: None,
        };
        bits.refill();
        bits
    }

    /// A reader over spec F's pull stream, holding at most [`FILL`] bytes
    /// of the member at a time.
    pub(crate) fn streaming(source: &'a mut dyn crate::rar5_lz::PackedSource) -> SliceBits<'a> {
        let mut bits = SliceBits {
            store: Store::Stream {
                source,
                ended: false,
            },
            at: 0,
            acc: 0,
            have: 0,
            consumed: 0,
            base: 0,
            total: None,
            total_bits: u64::MAX,
            fault: None,
        };
        bits.refill();
        bits
    }

    /// The pull stream's own error, if it had one.
    pub(crate) fn fault(&mut self) -> Option<crate::Error> {
        self.fault.take()
    }

    /// The bytes held now.
    #[inline(always)]
    fn held(&self) -> &[u8] {
        match &self.store {
            Store::Whole(bytes) => bytes,
            Store::Stream { source, .. } => source.available(),
        }
    }

    /// Up to eight bytes from the position, answered by VALUE so the
    /// refill below can read them while it writes the accumulator. One
    /// look at the store per refill, not one per byte.
    #[inline(always)]
    fn ahead(&self, out: &mut [u8; 8]) -> usize {
        let data = self.held();
        let take = data.len().saturating_sub(self.at).min(8);
        #[allow(clippy::indexing_slicing)] // `take` is bounded by the length
        out[..take].copy_from_slice(&data[self.at..self.at + take]);
        take
    }

    /// Pull bytes in until the accumulator holds more than 56 bits or the
    /// input runs out.
    ///
    /// ONE BIG ENDIAN LOAD is the fast arm, and it is exact rather than
    /// approximate. The accumulator holds the next bits LEFT ALIGNED, so
    /// the eight bytes at the position, read big endian and shifted down
    /// by `have`, land in exactly the slots they belong in: the first
    /// `(64 - have) / 8` of them whole, and the leading bits of the byte
    /// after them in the slots below. Those leading bits are correct
    /// stream bits, they are simply not COUNTED in `have`, and `at` is not
    /// advanced past their byte. The next refill reads that byte again and
    /// ORs the same bits into the same slots, so the OR is idempotent and
    /// the arm needs no masking and no per byte loop.
    ///
    /// The invariant the arm keeps, and which [`SliceBits::consume`]
    /// preserves because a left shift moves the whole accumulator
    /// together: above bit `64 - have` the accumulator is valid and
    /// counted, below it the bits are either correct and uncounted or
    /// zero, and never stale.
    ///
    /// ALWAYS inlined, with the tail arm never: this and the three reader
    /// methods a prefix decode goes through ([`BitSource::peek`],
    /// [`BitSource::available`], [`BitSource::consume`]) are the whole of a
    /// symbol's bit work, and a profile-use build may not choose to leave
    /// one of them as a call a symbol (see `Table::decode` in `lz20::table`).
    #[inline(always)]
    fn refill(&mut self) {
        if self.have >= REFILL_FLOOR {
            return;
        }
        let at = self.at;
        let mut eight = [0u8; 8];
        let whole = {
            let data = self.held();
            // The eight bytes as an array VALUE, not `copy_from_slice`: a
            // load with nothing left to call, whatever a profile chooses
            // (see `fixed_pair` in `rar3_lz::window`).
            match data.get(at..at + 8) {
                Some(chunk) => match chunk.first_chunk::<8>() {
                    Some(block) => {
                        eight = *block;
                        true
                    }
                    None => false,
                },
                None => false,
            }
        };
        if whole {
            let taken = (64 - self.have) / 8;
            self.acc |= u64::from_be_bytes(eight) >> self.have;
            self.at = at + taken as usize;
            self.have += taken * 8;
            return;
        }
        self.refill_tail();
    }

    /// The arm for the last bytes of the buffer, where eight cannot be
    /// read at once, and for the pull stream behind it.
    #[cold]
    #[inline(never)]
    fn refill_tail(&mut self) {
        loop {
            let mut eight = [0u8; 8];
            let got = self.ahead(&mut eight);
            let mut used = 0usize;
            while self.have <= 56 && used < got {
                #[allow(clippy::indexing_slicing)] // `used < got <= 8`
                let byte = eight[used];
                self.acc |= u64::from(byte) << (56 - self.have);
                used += 1;
                self.have += 8;
            }
            self.at += used;
            if self.have > 56 {
                return;
            }
            if !self.pull() {
                // The member's packed bytes are exhausted; past them the
                // stream reads as zero bits.
                return;
            }
        }
    }

    /// Ask the stream for more bytes. Answers whether any arrived.
    fn pull(&mut self) -> bool {
        let at = self.at;
        let Store::Stream { source, ended } = &mut self.store else {
            return false;
        };
        if *ended {
            return false;
        }
        if at > 0 {
            source.advance(at);
            self.base += at as u64;
            self.at = 0;
        }
        // Every byte the buffer held has been taken into the accumulator
        // by now, which is the only way the caller reaches here, so what
        // the stream gives is all there is to take.
        if let Err(error) = source.fill(FILL) {
            *ended = true;
            self.fault.get_or_insert(error);
        } else if source.available().len() < FILL {
            *ended = true;
        }
        let now = source.available().len();
        if let Store::Stream {
            source,
            ended: true,
        } = &self.store
        {
            // The member ends where the stream does.
            let total = self.base + source.available().len() as u64;
            self.total = Some(total);
            self.total_bits = total.saturating_mul(8);
        }
        now > 0
    }
}

impl BitSource for SliceBits<'_> {
    #[inline(always)]
    fn peek(&self, count: u8) -> u32 {
        debug_assert!(count <= 32);
        if count == 0 {
            return 0;
        }
        (self.acc >> (64 - u32::from(count))) as u32
    }

    /// While the stream's end has not been found there are more bits by
    /// definition: [`SliceBits::refill`] keeps the accumulator above 56
    /// bits for as long as bytes remain, and the only way it falls short
    /// is the stream stopping, which sets `total`. So an unknown answer is
    /// "more than any reader asks for", and it is exact from the moment it
    /// could matter.
    #[inline(always)]
    fn available(&self) -> u64 {
        self.total_bits.saturating_sub(self.consumed)
    }

    #[inline(always)]
    fn consume(&mut self, count: u8) {
        let count = u32::from(count);
        debug_assert!(count <= 64);
        // A consume past what the accumulator holds takes bits from the
        // zero fill past the end. The position still advances by the full
        // count, so `whole_bytes_left` stays truthful.
        self.acc = if count >= 64 { 0 } else { self.acc << count };
        self.have -= count.min(self.have);
        self.consumed += u64::from(count);
        self.refill();
    }

    #[inline(always)]
    fn read(&mut self, count: u8) -> crate::Result<u32> {
        if self.available() < u64::from(count) {
            return Err(crate::Error::new(crate::ErrorKind::Truncated));
        }
        let value = self.peek(count);
        self.consume(count);
        Ok(value)
    }

    #[inline(always)]
    fn bits_past_end(&self) -> u64 {
        self.consumed.saturating_sub(self.total_bits)
    }

    #[inline]
    fn whole_bytes_left(&self) -> usize {
        match self.total {
            // Subtracted in `u64` and THEN narrowed. `total` is a
            // stream-wide byte count (it grows with `base`), so on a
            // 32-bit target narrowing either side first wraps and the
            // answer is not even monotone in the bytes consumed.
            Some(total) => total
                .saturating_sub(self.consumed / 8)
                .min(usize::MAX as u64) as usize,
            // Unknown, and therefore plenty: see `available`.
            None => usize::MAX,
        }
    }
}
