//! One RAR 3 stream end to end: the window, this package's LZ decoder,
//! spec I's text model on the other side of the mode bit, and spec J's
//! filters, whose output replaces spans on the way to the caller while the
//! window keeps the unfiltered bytes (SPEC-H1 3.1, 3.9 and spec J 3.6).
//!
//! A stream is one solid chain, or one non solid member on its own; spec F
//! decides which by the member's solid flag and hands each member's packed
//! span and declared size here.

use std::ops::Range;

use crate::memory::MemoryPolicy;
use crate::ppmd::{MemoryBudget, PpmDecoder, PpmStep, StreamBytes};
use crate::rar3_filters::{FilterState, MemberBounds, RecordBytes, SpanBytes};
use crate::rar3_lz::bits::{BitSource, Bits};
use crate::rar3_lz::{BlockEnd, LzStep, Rar3Lz, Window, MAX_MATCH};
use crate::{Error, ErrorKind, Result};

/// The most bytes ONE decoded token writes, on either side of the mode
/// bit, and so the most the position can run past a filter span's end
/// before the span is looked at: the text model's escape code 4 copies
/// `l + 32` bytes for a one byte `l`, 287 (spec I 3.3), which is more than
/// the LZ side's [`MAX_MATCH`]. A span is lent by the window only when it
/// and this overshoot fit the dictionary together.
const MAX_OVERSHOOT: u32 = 287;
const _: () = assert!(MAX_OVERSHOOT >= MAX_MATCH);

/// How many bytes one call decodes while a member's packed data is read
/// past its output ([`Rar3Stream::after_the_output`]).
const TAIL_STEP: u64 = 1 << 16;

/// Where one member's packed data sits, and how many bytes it declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemberSpan {
    /// The member's packed bytes, as offsets into the stream's input.
    pub packed: Range<usize>,
    /// The size the member's header declares (spec F's, never inferred).
    pub unpacked: u64,
}

/// Where a member's bytes go, in stream order.
pub(crate) trait StreamOut {
    /// Deliver the next bytes of the member being decoded.
    fn write(&mut self, bytes: &[u8]) -> Result<()>;
}

/// Which state the stream is in whenever a member begins (SPEC-H1 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// The next thing in the input is a block header.
    HeaderExpected,
    /// The next thing is a coded symbol under the tables already built.
    InLzBlock,
    /// The text model holds the stream.
    InPpmBlock,
}

/// One RAR 3 stream.
pub(crate) struct Rar3Stream {
    window: Window,
    lz: Rar3Lz,
    ppm: PpmDecoder,
    filters: FilterState,
    limit: u64,
    state: State,
    /// Stream position of the last byte handed to the caller.
    delivered: u64,
    /// Stream position up to which the held span has been staged.
    staged: u64,
    /// Filter records framed for spec J, for the corpus tests.
    records: u64,
    /// Whether the member last decoded began a filter span it did not
    /// complete inside its declared output (spec J 3.8).
    span_left_member: bool,
}

impl Rar3Stream {
    /// This stream's filter slots, for the `bench-internals` census.
    #[cfg(feature = "bench-internals")]
    pub(crate) fn filter_census(&self) -> Vec<(crate::rar3_filters::StandardProgram, u32)> {
        self.filters.slot_census()
    }

    /// A stream whose window is `dictionary` bytes, which spec F has
    /// already checked against the policy.
    pub(crate) fn new(dictionary: u32, policy: &MemoryPolicy) -> Result<Rar3Stream> {
        Ok(Rar3Stream {
            window: Window::new(dictionary),
            lz: Rar3Lz::new(),
            ppm: PpmDecoder::new(),
            filters: FilterState::new(policy)?,
            limit: policy.working_limit,
            state: State::HeaderExpected,
            delivered: 0,
            staged: 0,
            records: 0,
            span_left_member: false,
        })
    }

    /// Working memory this stream holds (API section 8), the text model's
    /// arena included.
    pub(crate) fn held_bytes(&self) -> u64 {
        self.held_outside_the_model() + self.ppm.held_bytes()
    }

    /// What the stream holds beside the text model, which is the figure
    /// spec I judges its arena against (spec I 4.2).
    fn held_outside_the_model(&self) -> u64 {
        self.codec_bytes() + FilterState::STAGING_BYTES
    }

    /// What THIS package holds: the window, the five tables and the
    /// stored code lengths (SPEC-H1 4.2).
    pub(crate) fn codec_bytes(&self) -> u64 {
        self.window.held_bytes() + self.lz.held_bytes()
    }

    /// Start a new stream in the same allocations: a non solid member, or
    /// the first member of a solid chain. The window is re-allocated only
    /// when the dictionary size differs (API 5.2: a decoder is re-used
    /// across members and a dictionary never shrinks and regrows within
    /// one operation).
    pub(crate) fn begin_stream(&mut self, dictionary: u32) {
        if self.window.capacity() != dictionary {
            self.window = Window::new(dictionary);
        } else {
            self.window.reset();
        }
        self.lz.reset_stream();
        self.ppm.reset_stream();
        self.filters.reset_stream();
        self.state = State::HeaderExpected;
        self.delivered = 0;
        self.staged = 0;
        self.records = 0;
        self.span_left_member = false;
    }

    /// Filter records this stream has framed and handed to spec J.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub(crate) fn records(&self) -> u64 {
        self.records
    }

    /// Unit tests only: see [`Rar3Lz::force_pair`].
    #[cfg(test)]
    pub(crate) fn force_pair(&mut self, forced: Option<bool>) {
        self.lz.force_pair(forced);
    }

    /// Unit tests only: see [`Rar3Lz::force_guess`].
    #[cfg(test)]
    pub(crate) fn force_guess(&mut self, forced: Option<u8>) {
        self.lz.force_guess(forced);
    }

    /// Main symbols this stream has decoded (SPEC-H1 7.5).
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub(crate) fn symbols(&self) -> u64 {
        self.lz.symbols()
    }

    /// Of those, the literals (SPEC-H1 7.5).
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub(crate) fn literals(&self) -> u64 {
        self.lz.literals()
    }

    /// Decode one member into `out`.
    ///
    /// The member's OUTPUT is the first bytes its packed data produces, as
    /// many as it declares (SPEC-H1 3.8, B2). Its packed data is then read
    /// on to the end of block that ends the member, or to the data's end
    /// ([`Rar3Stream::after_the_output`]): what that produces stays in the
    /// window and is no member's output.
    ///
    /// A member whose data ends at an end of block BEFORE its declared
    /// size has come out short, and that is not a failure of this package
    /// (SPEC-H1 3.7 E4 and 4.3 N4): `out` has been given what was produced
    /// and the verdict is the caller's, by the member's checksum.
    ///
    /// However the member ends, no filter waits after it (spec J 3.8): a
    /// span it began and did not complete inside its declared output fails
    /// it, `Corrupt`, record, after its packed data has been decoded to
    /// its end, and [`Rar3Stream::span_left_member`] then says so.
    pub(crate) fn member(
        &mut self,
        input: &mut Bits<'_>,
        member: &MemberSpan,
        out: &mut impl StreamOut,
    ) -> Result<()> {
        self.span_left_member = false;
        let decoded = self.decode_member(input, member, out);
        // The member's END is where the bytes its packed data produced
        // end, which may lie past its declared size.
        let spans = self.filters.end_member(self.window.produced());
        self.span_left_member |= spans.is_err();
        // A failure of the decode itself is named first; the span's is the
        // member's verdict either way.
        decoded?;
        match self.span_left_member {
            true => Err(Error::new(ErrorKind::Corrupt(
                crate::Corruption::FilterRecord,
            ))),
            false => Ok(()),
        }
    }

    /// Whether the member last decoded failed by a filter span of its own:
    /// one the stream completed past its declared size, or one it began
    /// and its packed data did not complete (spec J 3.8). That failure is
    /// the member's own verdict even when it declares no bytes (spec F
    /// 3.6.3 item 4), which no other failure met in such a member's packed
    /// data is.
    pub(crate) fn span_left_member(&self) -> bool {
        self.span_left_member
    }

    fn decode_member(
        &mut self,
        input: &mut Bits<'_>,
        member: &MemberSpan,
        out: &mut impl StreamOut,
    ) -> Result<()> {
        input.begin_member(member.packed.clone());
        let start = self.window.produced();
        // Bytes the member before this one left in the window past its own
        // end are nobody's output (B2).
        self.delivered = start;
        self.staged = start;
        // The declared size is the header's and may be any 64 bit value: a
        // sum past the end of `u64` is a member no stream can complete,
        // and it ends `Truncated` where its data does, as the same size
        // does on a stream's first member.
        let end = start.saturating_add(member.unpacked);
        let bounds = MemberBounds { start, end };
        let mut ended = false;
        while !ended && self.window.produced() < end {
            match self.state {
                State::HeaderExpected => match self.lz.begin_block(input)? {
                    None => self.state = State::InLzBlock,
                    Some(first) => {
                        // The whole header byte is spec I's, and the
                        // reader is on a byte boundary (spec I 3.1).
                        let budget = MemoryBudget {
                            working_limit: self.limit,
                            held_elsewhere: self.held_outside_the_model(),
                        };
                        let mut bytes = ByteSource { input };
                        self.ppm.begin_block(first, &mut bytes, &budget)?;
                        self.state = State::InPpmBlock;
                    }
                },
                State::InPpmBlock => {
                    let literals = self.ppm_literals(end - self.window.produced());
                    let Rar3Stream { ppm, window, .. } = self;
                    let mut bytes = ByteSource { input };
                    let step = match ppm.run(&mut bytes, window, literals) {
                        Ok(step) => step,
                        Err(error) => {
                            if ended_short(&error) {
                                // The member's data is over, and the
                                // member after it begins with a block
                                // header (spec I 3.3, E4).
                                self.state = State::HeaderExpected;
                            }
                            return Err(error);
                        }
                    };
                    match step {
                        // One token is one byte or one short copy, so
                        // handing each to the caller costs a write per
                        // byte. The bytes wait in the window until a
                        // filter falls due or enough of them gather. A
                        // run of literals stops where the first of those
                        // can turn true (`ppm_literals`), so asking after
                        // a run is asking after each of its bytes.
                        PpmStep::Produced(_) if !self.ppm_must_deliver() => continue,
                        PpmStep::Produced(_) => {}
                        PpmStep::FilterRecord { first, len } => {
                            let position = self.window.produced();
                            let mut source = ModelRecord::new(first, len, self.ppm.record_body());
                            self.filters.read_record(&mut source, position, bounds)?;
                            self.records += 1;
                        }
                        // Escape code 0: a block header follows (spec I
                        // 3.3). Code 2 is not answered here: the member
                        // still needs bytes, and the step refused it.
                        PpmStep::EndOfBlock | PpmStep::EndOfMemberData => {
                            self.state = State::HeaderExpected;
                        }
                    }
                    // A copy may have carried the window past the member's
                    // declared size; the member's bytes stop at it.
                    self.deliver(self.window.produced().min(end), out)?;
                }
                State::InLzBlock => {
                    let room = end - self.window.produced();
                    let budget = self.budget(room);
                    match self.lz.run(input, &mut self.window, room, budget)? {
                        LzStep::Produced(_) => {}
                        LzStep::FilterRecord => {
                            let position = self.window.produced();
                            let mut source = RecordSource { input };
                            self.filters.read_record(&mut source, position, bounds)?;
                            self.records += 1;
                        }
                        LzStep::BlockEnded(how) => ended = self.block_ended(how),
                    }
                    // A match may have carried the window past the
                    // member's end; the member's bytes stop at it.
                    self.deliver(self.window.produced().min(end), out)?;
                }
            }
        }
        let reached = self.window.produced().min(end);
        self.deliver(reached, out)?;
        if !ended {
            self.after_the_output(input, bounds)?;
        }
        Ok(())
    }

    /// What an end of block leaves the stream at (SPEC-H1 3.7), and
    /// whether it ended the member's data.
    fn block_ended(&mut self, how: BlockEnd) -> bool {
        match how {
            BlockEnd::SameMemberNewTables => {
                self.state = State::HeaderExpected;
                false
            }
            BlockEnd::NewMemberNewTables => {
                self.state = State::HeaderExpected;
                true
            }
            BlockEnd::NewMemberKeepTables => true,
        }
    }

    /// Read a member's packed data from the point where its declared size
    /// has been produced (SPEC-H1 3.8, B1 to B8; spec I 3.3, "Member end").
    ///
    /// On the LZ side: symbol after symbol, each with its whole effect on
    /// the stream, to the end of block that ends the member or to the end
    /// of the data. Nothing produced here is delivered. The data running
    /// out there is no failure: the member's output is complete, the
    /// stream stays as the last whole symbol left it (B7), and a table
    /// read that does not complete leaves it at a header expected point
    /// (B6). A member of zero bytes arrives here with its first bit (B5).
    ///
    /// On the text model's side the same (spec I 3.3, "Member end"): token
    /// after token, each applied whole, to escape code 2, which ends the
    /// member, or escape code 0, after which the stream is at a block
    /// header inside this member (E7) and what is left of its packed data
    /// is read on from there, as either kind of block. The data running
    /// out before either is `Truncated`, there and inside a PPM block
    /// header met here (B4, B5), and the text model keeps it.
    ///
    /// A filter record read here is spec J's like any other. A span the
    /// stream completes here reaches past the declared size: it is never
    /// run, and it fails the member when the member ends (spec J 3.8).
    ///
    /// A symbol this package refuses anywhere is refused here too, by the
    /// same name: the strictness is the project's and has no exception
    /// for bytes that are nobody's output.
    fn after_the_output(&mut self, input: &mut Bits<'_>, bounds: MemberBounds) -> Result<()> {
        loop {
            match self.state {
                State::InPpmBlock => {
                    let Rar3Stream { ppm, window, .. } = self;
                    let mut bytes = ByteSource { input };
                    let step = match ppm.step_past_end(&mut bytes, window) {
                        Ok(step) => step,
                        Err(error) => {
                            // However the block ended, the member after
                            // this one begins with a block header.
                            self.state = State::HeaderExpected;
                            return Err(error);
                        }
                    };
                    match step {
                        PpmStep::Produced(_) => self.pass_completed(),
                        PpmStep::FilterRecord { first, len } => {
                            let position = self.window.produced();
                            let mut source = ModelRecord::new(first, len, self.ppm.record_body());
                            self.filters.read_record(&mut source, position, bounds)?;
                            self.records += 1;
                        }
                        PpmStep::EndOfBlock => self.state = State::HeaderExpected,
                        PpmStep::EndOfMemberData => {
                            self.state = State::HeaderExpected;
                            return Ok(());
                        }
                    }
                }
                State::HeaderExpected => {
                    input.align_to_byte();
                    // No header left in this member's data: the next
                    // member begins with one.
                    if input.available() == 0 {
                        return Ok(());
                    }
                    match self.lz.begin_block(input) {
                        Ok(None) => self.state = State::InLzBlock,
                        Ok(Some(first)) => {
                            self.ppm_block_in_the_tail(first, input)?;
                            self.state = State::InPpmBlock;
                        }
                        Err(error) if ran_out(&error) => return Ok(()),
                        Err(error) => return Err(error),
                    }
                }
                State::InLzBlock => {
                    // Nothing is held for a caller here, so the budget is
                    // only how often this loop comes round.
                    let step = self.lz.run(input, &mut self.window, u64::MAX, TAIL_STEP);
                    match step {
                        Ok(LzStep::Produced(_)) => self.pass_completed(),
                        Ok(LzStep::FilterRecord) => {
                            self.pass_completed();
                            let position = self.window.produced();
                            let mut source = RecordSource { input };
                            match self.filters.read_record(&mut source, position, bounds) {
                                Ok(()) => self.records += 1,
                                Err(error) if ran_out(&error) => return Ok(()),
                                Err(error) => return Err(error),
                            }
                        }
                        Ok(LzStep::BlockEnded(how)) => {
                            self.pass_completed();
                            if self.block_ended(how) {
                                return Ok(());
                            }
                        }
                        Err(error) if ran_out(&error) => return Ok(()),
                        Err(error) => return Err(error),
                    }
                }
            }
        }
    }

    /// Past the member's declared size: forget each waiting filter whose
    /// span the stream has now completed, and note that the member began
    /// one it could not deliver (spec J 3.8).
    fn pass_completed(&mut self) {
        let produced = self.window.produced();
        self.span_left_member |= self.filters.pass_completed(produced);
    }

    /// Read the rest of a PPM block header whose first byte, `first`, was
    /// met with nothing owed (SPEC-H1 3.8, B4 and B5). It is read like any
    /// other: a START header starts the model, within the caller's memory
    /// limit, and may set the escape byte. The packed data running out
    /// inside it is `Truncated`, and the text model keeps that (spec I
    /// 3.2).
    fn ppm_block_in_the_tail(&mut self, first: u8, input: &mut Bits<'_>) -> Result<()> {
        let budget = MemoryBudget {
            working_limit: self.limit,
            held_elsewhere: self.held_outside_the_model(),
        };
        let mut bytes = ByteSource { input };
        self.ppm.begin_block_past_end(first, &mut bytes, &budget)
    }

    /// The oldest byte the window must still hold: the start of the
    /// earliest queued span, or, when that span is too long for the
    /// window, the point up to which it has been staged. With nothing
    /// queued it is what the caller has already been handed.
    fn floor(&self) -> u64 {
        match self.filters.hold_from() {
            Some(hold) if self.staging() => self.staged.max(hold),
            Some(hold) => hold,
            None => self.delivered,
        }
    }

    /// Whether the earliest queued span is longer than the window can lend
    /// at the moment it falls due, the overshoot of the token that crosses
    /// its end included. That token may be the text model's, whatever the
    /// mode was when the record was read, so the room left is
    /// [`MAX_OVERSHOOT`] and not the LZ side's [`MAX_MATCH`]: with the
    /// smaller figure a span of `capacity - 287` to `capacity - 261` bytes
    /// overshot by a text model copy was neither staged nor still held.
    fn staging(&self) -> bool {
        match (self.filters.hold_from(), self.filters.due_at()) {
            (Some(hold), Some(due)) => {
                due - hold + u64::from(MAX_OVERSHOOT) > u64::from(self.window.capacity())
            }
            _ => false,
        }
    }

    /// How many bytes the decoder may produce before the caller must
    /// drain: everything the window can hold past [`Rar3Stream::floor`],
    /// less a match's worth of overshoot, and never past the point where
    /// the earliest queued filter falls due.
    fn budget(&self, room: u64) -> u64 {
        // A record may be read long before its span starts (spec J 3.6),
        // so the floor can sit ahead of the position.
        let held = self.window.produced().saturating_sub(self.floor());
        let free = u64::from(self.window.capacity()).saturating_sub(held);
        let mut budget = free.saturating_sub(u64::from(MAX_MATCH)).max(1);
        if let Some(due) = self.filters.due_at() {
            // The filter runs when the position reaches its span's end, so
            // there is no gain in producing past it.
            budget = budget.min((due - self.window.produced().min(due)).max(1));
        }
        room.min(budget)
    }

    /// Whether the text model's output must be handed on now rather than
    /// after a later token: a queued filter has fallen due, its span is
    /// being staged (which copies as bytes are produced), or the bytes not
    /// yet handed on have reached [`Rar3Stream::ppm_gather`]. Everything
    /// the window must still hold starts at or after `delivered`, and a
    /// token adds at most 287 bytes, so the window never wraps over it.
    fn ppm_must_deliver(&self) -> bool {
        let produced = self.window.produced();
        produced - self.delivered >= self.ppm_gather()
            || self.filters.due_at().is_some_and(|due| due <= produced)
            || self.staging()
    }

    /// How many literals the text model may write before
    /// [`Rar3Stream::ppm_must_deliver`] can turn true, at least 1 and at
    /// most `room`, the bytes the member still needs (1 or more). The
    /// gathered count and a filter falling due both turn on the position
    /// alone, which a literal moves by one; whether a span is being staged
    /// does not change while tokens are decoded, and while it is, every
    /// token is asked after, as before.
    fn ppm_literals(&self, room: u64) -> u64 {
        if self.staging() {
            return 1;
        }
        let produced = self.window.produced();
        let mut ahead = self.ppm_gather().saturating_sub(produced - self.delivered);
        if let Some(due) = self.filters.due_at() {
            ahead = ahead.min(due.saturating_sub(produced));
        }
        ahead.max(1).min(room)
    }

    /// How many bytes of the text model's output gather before they are
    /// handed on: 256 KiB, or half the window when that is less.
    fn ppm_gather(&self) -> u64 {
        u64::from(self.window.capacity() / 2).min(256 << 10)
    }

    /// Hand the caller every byte up to `upto` that no queued filter holds
    /// back, running the filters that have fallen due (spec J 3.6).
    fn deliver(&mut self, upto: u64, out: &mut impl StreamOut) -> Result<()> {
        loop {
            let limit = self.filters.hold_from().map_or(upto, |hold| hold.min(upto));
            if limit > self.delivered {
                let (head, tail) = self
                    .window
                    .slices(self.delivered, limit)
                    .ok_or_else(lost_history)?;
                out.write(head)?;
                if !tail.is_empty() {
                    out.write(tail)?;
                }
                self.delivered = limit;
            }
            self.stage(upto)?;
            match self.filters.due_at() {
                Some(due) if due <= upto => {
                    let held = self.filters.hold_from().unwrap_or(due);
                    let Rar3Stream {
                        filters, window, ..
                    } = self;
                    let span = match window.slices(held, due) {
                        Some((head, tail)) => SpanBytes::Window(head, tail),
                        None => SpanBytes::Staged,
                    };
                    let filtered = filters
                        .run_due(due, span)?
                        .ok_or_else(|| Error::new(ErrorKind::Corrupt(crate::Corruption::Stream)))?;
                    out.write(filtered.bytes)?;
                    self.delivered = due;
                    self.staged = self.delivered;
                }
                _ => return Ok(()),
            }
        }
    }

    /// Copy the held span's bytes into spec J's staging area as they are
    /// produced, for the one case the window cannot lend them: a span
    /// longer than the dictionary. No genuine archive reaches it (spec J
    /// 3.6: the longest genuine span is 65,536 bytes and the smallest
    /// dictionary is 65,536), and the bound is spec J's 245,760.
    fn stage(&mut self, upto: u64) -> Result<()> {
        if !self.staging() {
            self.staged = upto.max(self.staged);
            return Ok(());
        }
        let (Some(held), Some(due)) = (self.filters.hold_from(), self.filters.due_at()) else {
            return Ok(());
        };
        let from = self.staged.max(held);
        let to = upto.min(due);
        if to <= from {
            return Ok(());
        }
        let at = (from - held) as usize;
        let length = (to - from) as usize;
        let staging = self.filters.staging_in().ok_or_else(lost_history)?;
        self.window.copy_out(from, &mut staging[at..at + length])?;
        self.staged = to;
        Ok(())
    }
}

/// The record's bytes as the next 8 bits each, at whatever bit position
/// the stream is at (SPEC-H1 3.9, spec J 3.1). One parser reads a record
/// from here and from spec I's model symbols.
struct RecordSource<'a, 'b> {
    input: &'a mut Bits<'b>,
}

impl RecordBytes for RecordSource<'_, '_> {
    fn next_byte(&mut self) -> Result<u8> {
        self.input.read(8).map(|byte| byte as u8)
    }
}

/// Whole bytes for spec I, which the LZ side hands over on a byte
/// boundary (spec I 3.1).
struct ByteSource<'a, 'b> {
    input: &'a mut Bits<'b>,
}

impl StreamBytes for ByteSource<'_, '_> {
    fn next_byte(&mut self) -> Result<u8> {
        self.input.read(8).map(|byte| byte as u8)
    }
}

/// A record spec I's model already decoded, as bytes for the one parser.
///
/// The parser reads the whole framing itself (SPEC-H1 3.9), so this hands
/// it the first byte, then the length bytes that byte asks for, then the
/// body. Spec I decoded those length symbols already and gives back the
/// length they framed, which names them uniquely: `n - 7` for the one
/// byte form and the two halves of `n` for the two byte form (spec I
/// 3.3).
struct ModelRecord<'a> {
    head: [u8; 3],
    head_len: usize,
    taken: usize,
    body: &'a [u8],
}

impl<'a> ModelRecord<'a> {
    fn new(first: u8, len: u32, body: &'a [u8]) -> ModelRecord<'a> {
        let mut head = [first, 0, 0];
        let head_len = match (first & 7) + 1 {
            7 => {
                head[1] = (len - 7) as u8;
                2
            }
            8 => {
                head[1] = (len >> 8) as u8;
                head[2] = len as u8;
                3
            }
            _ => 1,
        };
        ModelRecord {
            head,
            head_len,
            taken: 0,
            body,
        }
    }
}

impl RecordBytes for ModelRecord<'_> {
    fn next_byte(&mut self) -> Result<u8> {
        let at = self.taken;
        self.taken += 1;
        if at < self.head_len {
            return Ok(self.head[at]);
        }
        self.body
            .get(at - self.head_len)
            .copied()
            .ok_or_else(|| Error::new(ErrorKind::Truncated))
    }
}

/// Whether `error` is the text model's refusal of a member whose data
/// ended before its declared size.
fn ended_short(error: &Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Corrupt(crate::Corruption::Ppmd(crate::PpmFault::EndedShort))
    )
}

/// Whether `error` says the member's packed data ended.
fn ran_out(error: &Error) -> bool {
    matches!(error.kind(), ErrorKind::Truncated)
}

fn lost_history() -> Error {
    Error::new(ErrorKind::Corrupt(crate::Corruption::Stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rar3_filters::{Params, RecordBuilder, StandardProgram};

    #[derive(Default)]
    struct Kept(Vec<u8>);

    impl StreamOut for Kept {
        fn write(&mut self, bytes: &[u8]) -> Result<()> {
            self.0.extend_from_slice(bytes);
            Ok(())
        }
    }

    struct Record<'a>(std::slice::Iter<'a, u8>);

    impl RecordBytes for Record<'_> {
        fn next_byte(&mut self) -> Result<u8> {
            self.0
                .next()
                .copied()
                .ok_or_else(|| Error::new(ErrorKind::Truncated))
        }
    }

    /// The text model's side of [`Rar3Stream::member`] with the tokens
    /// given rather than decoded (this crate has no PPMd encoder to write
    /// them with): a delta record at position 0 over `span` bytes, then
    /// `span - 1` literals, then ONE copy of `last` bytes at distance 2,
    /// which is what carries the position past the span's end. Each token
    /// is followed by exactly what the `InPpmBlock` arm does after it.
    /// Answers what reached the sink and what should have.
    fn span_overshot_by_one_copy(capacity: u32, span: u32, last: u32) -> (Vec<u8>, Vec<u8>) {
        let policy = MemoryPolicy {
            max_window: 1 << 22,
            max_dictionary: 1 << 22,
            max_workers: 1,
            ..MemoryPolicy::from_limit(1 << 30)
        };
        let mut stream = Rar3Stream::new(capacity, &policy).unwrap();
        let total = u64::from(span) - 1 + u64::from(last);
        let bounds = MemberBounds {
            start: 0,
            end: total,
        };
        let mut record = Vec::new();
        RecordBuilder::new()
            .record(
                StandardProgram::Delta,
                0,
                span,
                0,
                Params::Channels(1),
                &mut record,
            )
            .expect("a record");
        let mut out = Kept::default();
        stream
            .filters
            .read_record(&mut Record(record.iter()), 0, bounds)
            .unwrap();
        stream.deliver(0, &mut out).unwrap();
        let mut plain = Vec::with_capacity(total as usize);
        for index in 0..span - 1 {
            let byte = (index.wrapping_mul(7) ^ (index >> 9)) as u8;
            stream.window.put(byte).unwrap();
            plain.push(byte);
            if stream.ppm_must_deliver() {
                let produced = stream.window.produced();
                stream.deliver(produced, &mut out).unwrap();
            }
        }
        stream.window.copy(2, last).unwrap();
        for _ in 0..last {
            plain.push(plain[plain.len() - 2]);
        }
        assert!(stream.ppm_must_deliver(), "the filter has fallen due");
        stream.deliver(total, &mut out).unwrap();
        stream.filters.end_member(total).unwrap();
        let mut want = plain.clone();
        let span = span as usize;
        crate::rar3_filters::delta_decode(&plain[..span], &mut want[..span], 1);
        (out.0, want)
    }

    /// A filter span that the text model's longest copy (escape code 4,
    /// 287 bytes, spec I 3.3) carries the position past must still reach
    /// the transform whole. The decision to stage a span left the LZ
    /// maximum of 260 bytes for that overshoot, so a span of `cap - 287`
    /// to `cap - 261` bytes was neither staged nor still in the window
    /// when it fell due, and the transform ran over a staging area that
    /// was never filled: wrong bytes to the sink, and no error.
    ///
    /// One thread, no pool; under 2 MiB of memory.
    #[test]
    fn a_span_the_text_models_longest_copy_overshoots_is_filtered_whole() {
        let capacity = 1u32 << 16;
        // The item's own figures: 65,266 is `cap - 270`.
        for (span, last) in [
            (capacity - 270, 287),
            (capacity - 286, 287),
            (capacity - 261, 262),
            // The edges that were right before: lent by the window, and
            // staged.
            (capacity - 287, 287),
            (capacity - 270, 260),
            (capacity - 260, 287),
        ] {
            let (got, want) = span_overshot_by_one_copy(capacity, span, last);
            assert_eq!(got.len(), want.len(), "span {span}, copy {last}");
            assert!(got == want, "span {span}, copy {last}: different bytes");
        }
    }
}
