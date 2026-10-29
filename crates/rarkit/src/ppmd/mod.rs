//! Spec I: the PPMd variant H text model, as the RAR 3 format uses it.
//!
//! Decoding only (spec I question 6: nothing in the API asks for a PPMd
//! encoder). One [`PpmDecoder`] serves a whole solid stream: the model, its
//! arena and the escape byte survive from block to block and from member to
//! member, and only the range decoder restarts at each block header.
//!
//! The LZ side (spec H) owns the bit reader, the block headers of LZ blocks
//! and the output window; it enters this package through
//! [`PpmDecoder::begin_block`] when a block header's first bit is 1, and
//! takes the stream back at [`PpmStep::EndOfBlock`]. This package never
//! reads a partial byte and never gives a byte back.

mod arena;
mod model;
mod range;
mod tables;
#[cfg(test)]
mod tests;

use crate::{Corruption, Error, ErrorKind, Resource, Result};

pub use crate::error::PpmFault;

use model::Model;
use range::RangeDecoder;

/// Everything this package holds beside the arena: the two tables, the
/// per-symbol scratch and the filter-record buffer (spec I 4.2).
pub(crate) const OVERHEAD: u64 = 84 * 1024;

/// The largest filter-record body a code 3 can frame.
const MAX_RECORD_BODY: usize = 65_535;

/// How many symbols a filter record's first byte asks for before its body
/// (spec I 3.3): none, one for a length of 7 to 262, or two for a 16-bit
/// length.
#[inline]
fn record_extra(flags: u8) -> usize {
    match (flags & 7) + 1 {
        7 => 1,
        8 => 2,
        _ => 0,
    }
}

/// The body length a filter record's first byte and its extra symbols
/// frame: 1 to 6, 7 to 262, or 0 to 65,535 (spec I 3.3).
#[inline]
fn record_length(flags: u8, extra: [u8; 2]) -> u32 {
    match u32::from(flags & 7) + 1 {
        7 => u32::from(extra[0]) + 7,
        8 => u32::from(extra[0]) * 256 + u32::from(extra[1]),
        short => short,
    }
}

/// One fault of this package, as an [`Error`].
#[inline]
pub(crate) fn fault(which: PpmFault) -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::Ppmd(which)))
}

/// Byte-granular input, shared with the LZ side. The PPM decoder reads
/// whole bytes; the LZ side hands over on a byte boundary (spec I 3.1).
pub(crate) trait StreamBytes {
    /// The next byte of the stream. Past the end of the member's packed
    /// data this is [`ErrorKind::Truncated`]: never a zero byte, never a
    /// panic.
    fn next_byte(&mut self) -> Result<u8>;
}

/// The output side, owned by spec H: one window per solid stream.
pub(crate) trait StreamWindow {
    /// Append one byte.
    fn put(&mut self, byte: u8) -> Result<()>;
    /// Copy `length` bytes from `distance` back, under spec H's distance
    /// rule. A distance beyond what the stream has produced is spec H's
    /// error, which this package passes through unchanged.
    fn copy(&mut self, distance: u32, length: u32) -> Result<()>;
}

/// What one [`PpmDecoder::step`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PpmStep {
    /// Bytes written to the window.
    Produced(u32),
    /// A filter record (escape code 3) for spec J, whose bytes are in
    /// [`PpmDecoder::record_body`]. `first` is the record's first byte.
    FilterRecord {
        /// The record's first byte, which spec J's parser reads as flags.
        first: u8,
        /// How many body bytes follow it, 0 to 65,535.
        len: u32,
    },
    /// Escape code 0: the LZ side reads a block header next.
    EndOfBlock,
    /// Escape code 2 at or after the member's declared size: nothing more
    /// of the member's packed data is read.
    EndOfMemberData,
}

/// What this package may hold, checked before the arena is sized.
///
/// Spec F owns the process-wide accounting; this is the slice of it the
/// text model needs: the caller's limit, and what the rest of the stream
/// (spec H's window above all) already holds.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MemoryBudget {
    /// [`MemoryPolicy::working_limit`].
    pub(crate) working_limit: u64,
    /// Bytes this stream already holds outside the text model.
    pub(crate) held_elsewhere: u64,
}

impl MemoryBudget {
    /// Judge a model of `size` bytes (spec I 4.2).
    fn judge(&self, size: u32) -> Result<()> {
        let needed = self
            .held_elsewhere
            .saturating_add(u64::from(size))
            .saturating_add(OVERHEAD);
        if needed > self.working_limit {
            return Err(Error::new(ErrorKind::LimitExceeded {
                resource: Resource::TextModel,
                needed,
                limit: self.working_limit,
            }));
        }
        Ok(())
    }
}

/// The RAR 3 text-model decoder: one per solid stream, or one per non-solid
/// member.
pub(crate) struct PpmDecoder {
    model: Model,
    rc: RangeDecoder,
    escape: u8,
    started: bool,
    /// The size the last START header signalled.
    size: u32,
    /// The packed data ran out where nothing was owed but an end pair or
    /// a whole block header (spec I 3.10.1): kept, and raised again at
    /// every block that would continue this model, until a model start.
    ran_out_past_end: bool,
    body: Vec<u8>,
}

impl Default for PpmDecoder {
    fn default() -> PpmDecoder {
        PpmDecoder::new()
    }
}

impl PpmDecoder {
    /// A decoder with no arena and no model. The escape byte is 2 at the
    /// start of every stream (spec I 3.2).
    pub(crate) fn new() -> PpmDecoder {
        PpmDecoder {
            model: Model::new(),
            rc: RangeDecoder::default(),
            escape: 2,
            started: false,
            size: 0,
            ran_out_past_end: false,
            body: Vec::new(),
        }
    }

    /// Start a new stream on this decoder, keeping the arena buffer for
    /// re-use (API 5.2). The model is empty: the next member's first block
    /// header must be a START, and the escape byte is 2 again.
    pub(crate) fn reset_stream(&mut self) {
        self.started = false;
        self.escape = 2;
        self.ran_out_past_end = false;
    }

    /// Working memory held, for `memory::current` (API section 8).
    pub(crate) fn held_bytes(&self) -> u64 {
        self.model.held_bytes() + self.body.capacity() as u64
    }

    /// How many times this stream's model has been started, which the
    /// vectors' `model_starts` column records.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub(crate) fn model_starts(&self) -> u64 {
        self.model.starts
    }

    /// The body of the filter record the last [`PpmStep::FilterRecord`]
    /// framed.
    pub(crate) fn record_body(&self) -> &[u8] {
        &self.body
    }

    /// Read the rest of a PPM block header and prime the range decoder
    /// (spec I 3.2). The LZ side calls this when a block header's first bit
    /// is 1, passing the header's whole first byte.
    ///
    /// A header is its one to three bytes and the four range bytes after
    /// them, and it takes effect only when the packed data holds all of
    /// it: until then the escape byte, the model and the range decoder
    /// are as they were.
    pub(crate) fn begin_block(
        &mut self,
        first: u8,
        input: &mut impl StreamBytes,
        budget: &MemoryBudget,
    ) -> Result<()> {
        let starting = first & 0x20 != 0;
        let size = match starting {
            true => (u32::from(input.next_byte()?) + 1) << 20,
            false => self.size,
        };
        let escape = match first & 0x40 != 0 {
            true => input.next_byte()?,
            false => self.escape,
        };
        let mut order = 0;
        if starting {
            let code = u32::from(first & 0x1f) + 1;
            order = match code {
                1 => return Err(fault(PpmFault::BadOrder)),
                2..=16 => code,
                _ => 16 + 3 * (code - 16),
            };
            budget.judge(size)?;
        } else if self.ran_out_past_end {
            // This block would continue from a point the reference had
            // passed on bytes the member did not hold (3.10.1), whether
            // or not a model had been started by then.
            return Err(Error::new(ErrorKind::Truncated));
        } else if !self.started {
            return Err(fault(PpmFault::NoModel));
        }
        let mut rc = RangeDecoder::default();
        rc.init(input)?;

        self.rc = rc;
        self.escape = escape;
        if starting {
            self.model.reserve(size);
            self.size = size;
            self.model.start(order);
            self.started = true;
            self.ran_out_past_end = false;
        }
        Ok(())
    }

    /// [`PpmDecoder::begin_block`] for a header met where the member owes
    /// no byte: after its declared size, or in a member of zero bytes
    /// (spec I 3.1). The packed data running out inside such a header is
    /// kept (spec I 3.2, 3.10.1).
    pub(crate) fn begin_block_past_end(
        &mut self,
        first: u8,
        input: &mut impl StreamBytes,
        budget: &MemoryBudget,
    ) -> Result<()> {
        let read = self.begin_block(first, input, budget);
        self.keep_running_out(read)
    }

    /// Keep the packed data running out, where `outcome` is that.
    fn keep_running_out<T>(&mut self, outcome: Result<T>) -> Result<T> {
        if let Err(error) = &outcome {
            self.ran_out_past_end |= matches!(error.kind(), ErrorKind::Truncated);
        }
        outcome
    }

    /// Decode one token and write its bytes (spec I 3.3). `room` is how
    /// many bytes the member still needs, and it decides one thing only:
    /// escape code 2 while the member still needs bytes is
    /// [`PpmFault::EndedShort`], and with `room` 0 it is
    /// [`PpmStep::EndOfMemberData`]. A token's bytes enter the window
    /// WHOLE whatever `room` is: a copy that passes the declared size is
    /// not cut, and the caller takes the member's output from the part
    /// before it (spec I 3.3, "A copy past the declared size").
    pub(crate) fn step(
        &mut self,
        input: &mut impl StreamBytes,
        out: &mut impl StreamWindow,
        room: u64,
    ) -> Result<PpmStep> {
        let byte = self.model.decode(&mut self.rc, input)?;
        if byte != self.escape {
            return self.emit(out, byte);
        }
        self.escaped(input, out, room)
    }

    /// [`PpmDecoder::step`], token after token, for as long as the tokens
    /// are literals and fewer than `literals` of them have been written.
    /// It returns what `step` returns for the last token it decoded, and
    /// so `Produced` when it stops at the count: a caller that hands
    /// bytes on at a known count ahead comes back here once a run and not
    /// once a byte. `literals` is 1 to `room`, so every token of the run
    /// is decoded while the member still needs bytes, as `step` decodes
    /// it with a `room` above 0.
    pub(crate) fn run(
        &mut self,
        input: &mut impl StreamBytes,
        out: &mut impl StreamWindow,
        literals: u64,
    ) -> Result<PpmStep> {
        let mut left = literals;
        loop {
            let byte = self.model.decode(&mut self.rc, input)?;
            if byte == self.escape {
                return self.escaped(input, out, left);
            }
            out.put(byte)?;
            left -= 1;
            if left == 0 {
                return Ok(PpmStep::Produced(1));
            }
        }
    }

    /// The token after the escape byte (spec I 3.3).
    fn escaped(
        &mut self,
        input: &mut impl StreamBytes,
        out: &mut impl StreamWindow,
        room: u64,
    ) -> Result<PpmStep> {
        let code = self.model.decode(&mut self.rc, input)?;
        match code {
            // End of block: the next block header follows.
            0 => Ok(PpmStep::EndOfBlock),
            // The member's data ends here, short of its declared size
            // (spec I 3.3, E6): no block header is read after it.
            2 if room > 0 => Err(fault(PpmFault::EndedShort)),
            2 => Ok(PpmStep::EndOfMemberData),
            3 => self.filter_record(input),
            4 => {
                let d2 = u32::from(self.model.decode(&mut self.rc, input)?);
                let d1 = u32::from(self.model.decode(&mut self.rc, input)?);
                let d0 = u32::from(self.model.decode(&mut self.rc, input)?);
                let len = u32::from(self.model.decode(&mut self.rc, input)?) + 32;
                self.copy(out, (d2 << 16 | d1 << 8 | d0) + 2, len)
            }
            5 => {
                let len = u32::from(self.model.decode(&mut self.rc, input)?) + 4;
                self.copy(out, 1, len)
            }
            // 1, and 6 to 255: a literal escape byte.
            _ => {
                let escape = self.escape;
                self.emit(out, escape)
            }
        }
    }

    /// [`PpmDecoder::step`] where the member's declared size has been
    /// produced, or after a block header read with nothing owed (spec I
    /// 3.3, "Member end"): the decode goes on, every symbol applied as one
    /// before the declared size is, until escape code 2 or 0. The packed
    /// data running out before either is [`ErrorKind::Truncated`], and is
    /// kept until a model start (spec I 3.10.1).
    pub(crate) fn step_past_end(
        &mut self,
        input: &mut impl StreamBytes,
        out: &mut impl StreamWindow,
    ) -> Result<PpmStep> {
        let step = self.step(input, out, 0);
        self.keep_running_out(step)
    }

    #[inline(always)]
    fn emit(&self, out: &mut impl StreamWindow, byte: u8) -> Result<PpmStep> {
        out.put(byte)?;
        Ok(PpmStep::Produced(1))
    }

    #[inline(always)]
    fn copy(&self, out: &mut impl StreamWindow, distance: u32, length: u32) -> Result<PpmStep> {
        out.copy(distance, length)?;
        Ok(PpmStep::Produced(length))
    }

    /// Escape code 3: frame a filter record and hand its bytes to spec J
    /// (spec I 3.3). Every byte of it is an ordinary model symbol.
    fn filter_record(&mut self, input: &mut impl StreamBytes) -> Result<PpmStep> {
        let flags = self.model.decode(&mut self.rc, input)?;
        let mut extra = [0u8; 2];
        for slot in extra.iter_mut().take(record_extra(flags)) {
            *slot = self.model.decode(&mut self.rc, input)?;
        }
        let len = record_length(flags, extra);
        if self.body.capacity() < MAX_RECORD_BODY {
            self.body
                .reserve_exact(MAX_RECORD_BODY - self.body.capacity());
        }
        self.body.clear();
        for _ in 0..len {
            let byte = self.model.decode(&mut self.rc, input)?;
            self.body.push(byte);
        }
        Ok(PpmStep::FilterRecord { first: flags, len })
    }
}
