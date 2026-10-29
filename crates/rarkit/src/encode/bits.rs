//! The bit output both encoders write through.
//!
//! RAR lays its bit fields down most significant bit first, out of bytes
//! taken in order, so this is the mirror of the decoder's reader. The
//! writer keeps a 64 bit accumulator and flushes whole bytes, which keeps
//! per field work off the token path.

/// A most significant bit first writer over a growable byte buffer.
#[derive(Default)]
pub(crate) struct BitWriter {
    bytes: Vec<u8>,
    /// The bits not yet flushed, left aligned in the high bits.
    acc: u64,
    /// How many bits of `acc` are valid: under 32 between calls.
    have: u32,
}

impl BitWriter {
    /// An empty writer.
    pub(crate) fn new() -> BitWriter {
        BitWriter::default()
    }

    /// Start again, keeping the buffer so no block allocates.
    pub(crate) fn clear(&mut self) {
        self.bytes.clear();
        self.acc = 0;
        self.have = 0;
    }

    /// Write the low `count` bits of `value`, most significant first.
    #[inline]
    pub(crate) fn push(&mut self, value: u32, count: u8) {
        debug_assert!(count <= 32);
        debug_assert!(count == 32 || value < (1u32 << count) || count == 0);
        if count == 0 {
            return;
        }
        // Fewer than 32 bits are ever held between calls, so a field of up
        // to 32 fits the accumulator; whole 32 bit words go out at once,
        // which is one store for several fields where a byte at a time was
        // one store and one capacity check per byte.
        self.acc |= u64::from(value) << (64 - self.have - u32::from(count));
        self.have += u32::from(count);
        if self.have >= 32 {
            self.bytes
                .extend_from_slice(&((self.acc >> 32) as u32).to_be_bytes());
            self.acc <<= 32;
            self.have -= 32;
        }
    }

    /// Pad with zero bits up to the next byte boundary, which is where a
    /// RAR 2.9 block header begins.
    #[inline]
    pub(crate) fn align(&mut self) {
        if !self.have.is_multiple_of(8) {
            self.push(0, (8 - self.have % 8) as u8);
        }
    }

    /// Write a canonical code.
    #[inline]
    pub(crate) fn push_code(&mut self, code: Code) {
        self.push(code.bits, code.len);
    }

    /// The writer for the length of one loop, its accumulator held by
    /// value: [`Held::push`] is [`BitWriter::push`] with the accumulator
    /// and its bit count in registers, where a loop that pushes through
    /// `&mut BitWriter` loads and stores both around every field. They go
    /// back to the writer when the [`Held`] is dropped. The same bits in
    /// the same order.
    #[inline]
    pub(crate) fn hold(&mut self) -> Held<'_> {
        Held {
            acc: self.acc,
            have: self.have,
            writer: self,
        }
    }

    /// The writer for the length of one loop, as [`BitWriter::hold`] is,
    /// with NO branch on how many bits are held. [`Held::push`] flushes a
    /// word when 32 bits have gathered, which in a token loop turns on
    /// the widths of the codes just written; where nearly every token is
    /// a literal of a few bits that is a guess the processor gets wrong
    /// every few tokens. This one stores the accumulator's eight bytes at
    /// the output's end after every field and moves the end past the
    /// whole bytes among them: more work a field, and steadier. Timed 1
    /// Oct 2026 on the fast level 1 (one 4 GiB member, one thread, an M3
    /// Ultra): 1.9 percent faster than [`Held`]; counted at levels 2 and
    /// 3, where matches carry the bits, about 3 percent slower, so those
    /// keep [`Held`]. The same bits in the same order either way; the
    /// writer has its bytes, and under eight bits waiting, when the
    /// [`Steady`] is dropped.
    #[inline]
    pub(crate) fn steady(&mut self) -> Steady<'_> {
        Steady {
            acc: self.acc,
            have: self.have,
            end: self.bytes.len(),
            writer: self,
        }
    }

    /// Pad the last byte with zero bits and return the bytes, with the
    /// number of valid bits in the last one.
    pub(crate) fn finish(&mut self) -> (&[u8], u8) {
        while self.have >= 8 {
            self.bytes.push((self.acc >> 56) as u8);
            self.acc <<= 8;
            self.have -= 8;
        }
        let valid = if self.have == 0 { 8 } else { self.have as u8 };
        if self.have > 0 {
            self.bytes.push((self.acc >> 56) as u8);
            self.acc = 0;
            self.have = 0;
        }
        (&self.bytes, valid)
    }
}

/// A [`BitWriter`] held for one loop: see [`BitWriter::hold`].
pub(crate) struct Held<'a> {
    writer: &'a mut BitWriter,
    acc: u64,
    have: u32,
}

impl Held<'_> {
    /// [`BitWriter::push`].
    #[inline(always)]
    pub(crate) fn push(&mut self, value: u32, count: u8) {
        debug_assert!(count <= 32);
        debug_assert!(count == 32 || value < (1u32 << count) || count == 0);
        if count == 0 {
            return;
        }
        self.acc |= u64::from(value) << (64 - self.have - u32::from(count));
        self.have += u32::from(count);
        if self.have >= 32 {
            self.writer
                .bytes
                .extend_from_slice(&((self.acc >> 32) as u32).to_be_bytes());
            self.acc <<= 32;
            self.have -= 32;
        }
    }
}

impl Drop for Held<'_> {
    #[inline]
    fn drop(&mut self) {
        self.writer.acc = self.acc;
        self.writer.have = self.have;
    }
}

/// What a token loop writes through: [`Held`] or [`Steady`].
pub(crate) trait Push {
    /// [`BitWriter::push`].
    fn push(&mut self, value: u32, count: u8);

    /// [`BitWriter::push_code`].
    #[inline(always)]
    fn push_code(&mut self, code: Code) {
        self.push(code.bits, code.len);
    }
}

impl Push for Held<'_> {
    #[inline(always)]
    fn push(&mut self, value: u32, count: u8) {
        Held::push(self, value, count);
    }
}

/// A [`BitWriter`] held for one loop, flushing whole bytes after every
/// field: see [`BitWriter::steady`].
pub(crate) struct Steady<'a> {
    writer: &'a mut BitWriter,
    acc: u64,
    /// Under eight between pushes.
    have: u32,
    /// Where the next byte goes: the writer's buffer is kept at least
    /// eight bytes longer while the writer is held.
    end: usize,
}

/// How far a steady writer's buffer grows at a time.
const STEADY_ROOM: usize = 16 << 10;

impl Steady<'_> {
    #[cold]
    #[inline(never)]
    fn room(&mut self) {
        self.writer.bytes.resize(self.end + STEADY_ROOM, 0);
    }
}

impl Push for Steady<'_> {
    #[inline(always)]
    fn push(&mut self, value: u32, count: u8) {
        debug_assert!(count <= 32);
        debug_assert!(count == 32 || value < (1u32 << count) || count == 0);
        if count == 0 {
            return;
        }
        // At most 31 bits are held when the writer is taken and under
        // eight after any push, so a field of up to 32 fits.
        self.acc |= u64::from(value) << (64 - self.have - u32::from(count));
        self.have += u32::from(count);
        if self.writer.bytes.len() < self.end + 8 {
            self.room();
        }
        self.writer.bytes[self.end..self.end + 8].copy_from_slice(&self.acc.to_be_bytes());
        let whole = self.have / 8;
        self.end += whole as usize;
        self.acc <<= 8 * whole;
        self.have -= 8 * whole;
    }
}

impl Drop for Steady<'_> {
    #[inline]
    fn drop(&mut self) {
        self.writer.bytes.truncate(self.end);
        self.writer.acc = self.acc;
        self.writer.have = self.have;
    }
}

/// One symbol's canonical code.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Code {
    /// The code itself, in the low `len` bits.
    pub(crate) bits: u32,
    /// Its width; zero means the symbol has no code.
    pub(crate) len: u8,
}
