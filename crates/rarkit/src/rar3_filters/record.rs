//! The filter record reader, the program slots and the queue of pending
//! spans of one decoding stream (SPEC-J sections 3.2 to 3.8 and 4).

use std::collections::VecDeque;

use super::{identify, transforms, StandardProgram};
use crate::carry::h_ours::codec::address_filters::{self, Direction};
use crate::error::{Corruption, Error, ErrorKind, Resource, Result, Unsupported};
use crate::memory::MemoryPolicy;

/// The longest span a record may name, by its program (SPEC-J 3.5 and
/// section 4, "Span length"): where the reference stops running each. It
/// runs the three address programs over a span of 262,143 bytes and not
/// over one of 262,144, and delta, RGB and audio over 131,072 bytes and
/// not over 131,073. A longer span is refused here as a damaged record:
/// no transform is run that the reference would not run.
pub(crate) const fn longest_span(program: StandardProgram) -> u32 {
    match program {
        StandardProgram::X86Call | StandardProgram::X86CallJump | StandardProgram::Itanium => {
            STAGE_SPAN
        }
        StandardProgram::Delta | StandardProgram::Rgb | StandardProgram::Audio => 131_072,
    }
}
/// The most channels the reference runs the delta program for, and the
/// audio program (SPEC-J 3.5).
const DELTA_CHANNELS_AT_MOST: u32 = 1_024;
/// See [`DELTA_CHANNELS_AT_MOST`].
const AUDIO_CHANNELS_AT_MOST: u32 = 128;
/// The widest RGB row a record may name: 3,145,728 bytes, the widest that
/// was put to a genuine reader and run (SPEC-J 3.5, the constructed spans
/// of its short span probe).
///
/// The section's table gives a row no upper bound, and its vectors (5.4)
/// refuse a first register of 2^32 - 1, whose row of 2^32 - 4 bytes is a
/// multiple of three: the two meet only if a bound lies between, and the
/// text names none. This is the one the evidence reaches.
const RGB_ROW_AT_MOST: u32 = 3_145_728;
/// The flags byte's field bits (SPEC-J 3.2). Bit 3 means nothing.
const HAS_SELECTOR: u8 = 0x80;
const START_PLUS_258: u8 = 0x40;
const HAS_LENGTH: u8 = 0x20;
const HAS_REGISTERS: u8 = 0x10;
/// The register a record sends the span's length in, when it sends it
/// (SPEC-J 3.5).
const LENGTH_REGISTER: usize = 4;
/// The longest span of any program, which is what each staging area
/// holds.
pub(crate) const STAGE_SPAN: u32 = 262_143;
/// The most program slots one stream may define, and the most filters
/// that may wait at once (section 4). One figure for both, and the one
/// the reference shows for both: it runs every filter of a stream that
/// defines 8,193 slots, and all of 8,193 that wait together, and neither
/// at 8,194. Genuine output was seen to define at most 4 and to have at
/// most 8 waiting. The slots are 8 bytes each and a waiting filter 24, so
/// both at their limits are 262,176 bytes beside the staging.
pub(crate) const SLOTS_AT_MOST: usize = 8_193;
/// See [`SLOTS_AT_MOST`].
pub(crate) const WAITING_AT_MOST: usize = 8_193;

/// Where the record reader gets the record's bytes: the next 8 bits of an
/// LZ block, or the next symbol of a PPMd block.
pub(crate) trait RecordBytes {
    /// The next byte. When the member's packed data has ended this returns
    /// `Truncated`; any error is passed through unchanged.
    fn next_byte(&mut self) -> Result<u8>;
}

/// The stream positions where the current member starts and ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemberBounds {
    /// Position of the member's first byte (`M`).
    pub start: u64,
    /// Position one past the member's last byte (`M_end`).
    pub end: u64,
}

/// The unfiltered bytes of the span that is due.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SpanBytes<'w> {
    /// The span's bytes in stream order, as one or two slices of the
    /// decoder's history (two when the span crosses the window's wrap).
    Window(&'w [u8], &'w [u8]),
    /// The decoder has already copied the span's bytes, as it produced
    /// them, into [`FilterState::staging_in`] (for a window that cannot
    /// hold the whole span).
    Staged,
}

/// A filter's output, which replaces the span's bytes in the member's
/// output (never in the history).
#[derive(Debug)]
pub(crate) struct FilteredSpan<'a> {
    /// Stream position of the span's first byte.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub start: u64,
    /// The filtered bytes, as long as the span.
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    program: StandardProgram,
    len: u32,
}

/// One queued filter.
#[derive(Debug, Clone, Copy)]
struct Filter {
    program: StandardProgram,
    start: u64,
    len: u32,
    /// Channels (delta, audio), row width `R0 - 3` (RGB), or the
    /// member-relative offset `F_off` (x86, Itanium).
    param: u32,
    /// RGB's red position.
    red_at: u32,
}

/// What one record said, for the trace of section 6.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Parsed {
    pub flags: u8,
    pub slot: u32,
    pub defined: bool,
    pub start: u64,
    pub len: u32,
    pub regs: [u32; 7],
    pub body_len: u32,
}

fn corrupt_record() -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::FilterRecord))
}

fn corrupt_parameters() -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::FilterParameters))
}

/// The record body as a bit string, most significant bit first, pulling
/// bytes from the source only as fields need them.
struct Body<'s, S: RecordBytes> {
    src: &'s mut S,
    /// Body bytes not yet pulled from `src`.
    left: u32,
    acc: u64,
    bits: u32,
}

impl<S: RecordBytes> Body<'_, S> {
    fn bits_left(&self) -> u64 {
        self.bits as u64 + 8 * self.left as u64
    }

    /// `count` bits, at most 32.
    fn take(&mut self, count: u32) -> Result<u32> {
        while self.bits < count {
            if self.left == 0 {
                return Err(corrupt_record());
            }
            let byte = self.src.next_byte()?;
            self.left -= 1;
            self.acc = (self.acc << 8) | byte as u64;
            self.bits += 8;
        }
        self.bits -= count;
        let value = (self.acc >> self.bits) & ((1u64 << count) - 1);
        self.acc &= (1u64 << self.bits) - 1;
        Ok(value as u32)
    }

    /// The variable-length integer of section 3.3.
    fn vint(&mut self) -> Result<u32> {
        Ok(match self.take(2)? {
            0 => self.take(4)?,
            1 => {
                let h = self.take(8)?;
                if h >= 16 {
                    h
                } else {
                    0xFFFF_FF00 | (h << 4) | self.take(4)?
                }
            }
            2 => self.take(16)?,
            _ => self.take(32)?,
        })
    }

    /// Consume the rest of the body: padding, or bytes no field needed.
    fn drain(&mut self) -> Result<()> {
        while self.left > 0 {
            self.src.next_byte()?;
            self.left -= 1;
        }
        Ok(())
    }
}

/// The program a definition carries (SPEC-J 3.3 item 5 and 3.4): `k`
/// bytes, known by `k`, their CRC32 and a zero XOR of them all, and by
/// nothing else about them. Any other is refused by its length and CRC32.
fn program_defined<S: RecordBytes>(body: &mut Body<'_, S>) -> Result<StandardProgram> {
    let k = body.vint()?;
    if k == 0 || u64::from(k) * 8 > body.bits_left() {
        return Err(corrupt_record());
    }
    let mut crc = crc32fast::Hasher::new();
    let mut xor = 0u8;
    for _ in 0..k {
        let byte = body.take(8)? as u8;
        crc.update(&[byte]);
        xor ^= byte;
    }
    let crc32 = crc.finalize();
    identify(k, crc32).filter(|_| xor == 0).ok_or_else(|| {
        Error::new(ErrorKind::Unsupported(Unsupported::FilterProgram {
            len: k,
            crc32,
        }))
    })
}

/// A delta or audio record's channel count, where the reference runs the
/// program for it: 1 to `most`.
fn channels(count: u32, most: u32) -> Result<u32> {
    if (1..=most).contains(&count) {
        Ok(count)
    } else {
        Err(corrupt_parameters())
    }
}

/// Filter state of one decoding stream: one per non-solid member, one per
/// solid group.
#[derive(Debug)]
pub(crate) struct FilterState {
    slots: Vec<Slot>,
    /// The slot index of the previous record (0 before the first).
    last: u32,
    queue: VecDeque<Filter>,
    /// Where the transform reads the span when the window cannot lend it.
    stage_in: Box<[u8]>,
    /// Where the transform writes the span's filtered bytes.
    stage_out: Box<[u8]>,
}

impl FilterState {
    /// A fresh stream: no slots, empty queue. Allocates both staging areas
    /// here, once; nothing is sized from archive bytes.
    pub fn new(policy: &MemoryPolicy) -> Result<FilterState> {
        let needed = FilterState::STAGING_BYTES;
        if policy.working_limit < needed {
            return Err(Error::new(ErrorKind::LimitExceeded {
                resource: Resource::Window,
                needed,
                limit: policy.working_limit,
            }));
        }
        Ok(FilterState {
            slots: Vec::new(),
            last: 0,
            queue: VecDeque::with_capacity(16),
            stage_in: vec![0; STAGE_SPAN as usize].into_boxed_slice(),
            stage_out: vec![0; STAGE_SPAN as usize].into_boxed_slice(),
        })
    }

    /// Each defined slot's program and declared length, for the
    /// `bench-internals` census.
    ///
    /// A RAR 3 stream defines a slot's bytecode once and then names it by
    /// index, so this is the whole of WHICH programs a member used. It
    /// says nothing about how MANY records named each, which
    /// `internals::rar3_lz::Runner::run`'s own record count gives.
    ///
    /// Nothing is counted at decode time: the program is stored when the
    /// slot is defined, on the cold path, and this reads it afterwards. A
    /// census that counted records where they are DISPATCHED would run
    /// inside every timed RAR 3 leg, because the crate is its own dev
    /// dependency with `bench-internals` on.
    #[cfg(feature = "bench-internals")]
    pub(crate) fn slot_census(&self) -> Vec<(StandardProgram, u32)> {
        self.slots
            .iter()
            .map(|slot| (slot.program, slot.len))
            .collect()
    }

    /// Bytes of working memory one `FilterState` holds beyond its tables.
    pub const STAGING_BYTES: u64 = 2 * STAGE_SPAN as u64;
    /// Bytes one defined slot holds, and one waiting filter.
    #[cfg(test)]
    pub(crate) const SLOT_BYTES: usize = std::mem::size_of::<Slot>();
    /// See [`FilterState::SLOT_BYTES`].
    #[cfg(test)]
    pub(crate) const WAITING_BYTES: usize = std::mem::size_of::<Filter>();

    /// Start a new stream on this state, keeping both staging areas: no
    /// slots, an empty queue, and the previous slot index 0, which is
    /// what [`FilterState::new`] gives (spec J 3.8). A decoder re-uses one
    /// state across streams so that nothing is allocated per member.
    pub(crate) fn reset_stream(&mut self) {
        self.slots.clear();
        self.last = 0;
        self.queue.clear();
    }

    /// Read one record from `src`: called by the LZ decoder after symbol
    /// 257 and by the PPMd decoder after escape, 3. `pos` is the number of
    /// bytes of the stream decoded before the record (`P`).
    pub fn read_record(
        &mut self,
        src: &mut impl RecordBytes,
        pos: u64,
        member: MemberBounds,
    ) -> Result<()> {
        self.parse(src, pos, member).map(|_| ())
    }

    /// [`read_record`](Self::read_record), returning the record's fields.
    pub(crate) fn parse(
        &mut self,
        src: &mut impl RecordBytes,
        pos: u64,
        member: MemberBounds,
    ) -> Result<Parsed> {
        let flags = src.next_byte()?;
        let body_len = match flags & 7 {
            short @ 0..=5 => u32::from(short) + 1,
            6 => 7 + u32::from(src.next_byte()?),
            _ => {
                let high = u32::from(src.next_byte()?);
                high << 8 | u32::from(src.next_byte()?)
            }
        };
        let mut body = Body {
            src,
            left: body_len,
            acc: 0,
            bits: 0,
        };

        // The fields, in the body's order (3.3 items 1 to 5).
        let slot = if flags & HAS_SELECTOR == 0 {
            self.last
        } else {
            match body.vint()? {
                0 => {
                    // A reset drops nothing that waits: with a filter
                    // waiting it is refused.
                    if !self.queue.is_empty() {
                        return Err(corrupt_record());
                    }
                    self.slots.clear();
                    0
                }
                selector => selector - 1,
            }
        };
        let held = self.slots.get(slot as usize).copied();
        if held.is_none() && slot as usize != self.slots.len() {
            return Err(corrupt_record());
        }
        // The sum is taken in 32 bits, which is what lets the negative
        // form of the start reach forward with bit 6 (3.3 item 2). A start
        // that sum lands BEFORE the record's own position is refused
        // (section 4): only the negative form reaches it, an advance of
        // 2 GiB or more whose sum with the position's low 32 bits wraps.
        // Any other start is the position plus the advance, with the
        // stream's own position not cut to 32 bits.
        let advance = match (body.vint()?, flags & START_PLUS_258) {
            (v, 0) => v,
            (v, _) => v.wrapping_add(258),
        };
        if advance >= 1 << 31 && (pos as u32).checked_add(advance).is_none() {
            return Err(corrupt_record());
        }
        let start = pos + u64::from(advance);
        let len = match (flags & HAS_LENGTH, held) {
            (0, Some(slot)) => slot.len,
            (0, None) => 0,
            _ => body.vint()?,
        };
        let mut regs = [0u32; 7];
        let mut sent = 0;
        if flags & HAS_REGISTERS != 0 {
            sent = body.take(7)?;
            for (number, register) in regs.iter_mut().enumerate() {
                if sent >> number & 1 == 1 {
                    *register = body.vint()?;
                }
            }
        }
        let program = match held {
            Some(slot) => slot.program,
            None if self.slots.len() == SLOTS_AT_MOST => return Err(corrupt_record()),
            None => program_defined(&mut body)?,
        };
        // Whatever the body still holds is nothing (3.3 item 6), bit 3 of
        // the flags or not.
        body.drain()?;

        // The span against its program and the spans recorded before it
        // (3.5, 3.6 and section 4). Against its MEMBER it is judged when
        // the member ends and not here (3.8): where the bytes a member's
        // packed data produces end is not known while a record is read,
        // and the size its header declares may lie before that.
        if len > longest_span(program) {
            return Err(corrupt_record());
        }
        if let Some(before) = self.queue.back() {
            if start < before.start + u64::from(before.len) {
                return Err(corrupt_record());
            }
        }
        if self.queue.len() == WAITING_AT_MOST {
            return Err(corrupt_record());
        }
        // The registers (3.5). One the record did not send reads as zero.
        if sent >> LENGTH_REGISTER & 1 == 1 && regs[LENGTH_REGISTER] != len {
            return Err(corrupt_parameters());
        }
        let (param, red_at) = match program {
            StandardProgram::X86Call | StandardProgram::X86CallJump | StandardProgram::Itanium => {
                (start.wrapping_sub(member.start) as u32, 0)
            }
            StandardProgram::Delta => (channels(regs[0], DELTA_CHANNELS_AT_MOST)?, 0),
            StandardProgram::Audio => (channels(regs[0], AUDIO_CHANNELS_AT_MOST)?, 0),
            StandardProgram::Rgb => {
                // The row is `R0 - 3` bytes: a positive multiple of three,
                // with a red position of 0 to 2 (SPEC-J 3.5).
                //
                // A row WIDER than its span is run, where reference unrar
                // 7.23 leaves the span as it is: genuine rar 4.20 and
                // 5.50 end a true colour member that is 1 or 2 bytes past
                // a multiple of 65,536 with a row of three over those
                // bytes, the member's checksum is of what this transform
                // gives, and unrar 4.20 reads it so. The genuine writer
                // wins over the later reader.
                //
                // A first register under 3, or one whose row is past
                // [`RGB_ROW_AT_MOST`], is refused with the widths that
                // are not a multiple of three.
                match regs[0].checked_sub(3) {
                    Some(width)
                        if width != 0
                            && width % 3 == 0
                            && width <= RGB_ROW_AT_MOST
                            && regs[1] <= 2 =>
                    {
                        (width, regs[1])
                    }
                    _ => return Err(corrupt_parameters()),
                }
            }
        };

        match held {
            Some(_) => self.slots[slot as usize].len = len,
            None => self.slots.push(Slot { program, len }),
        }
        self.last = slot;
        self.queue.push_back(Filter {
            program,
            start,
            len,
            param,
            red_at,
        });
        Ok(Parsed {
            flags,
            slot,
            defined: held.is_none(),
            start,
            len,
            regs,
            body_len,
        })
    }

    /// The lowest stream position that may not yet be delivered: the start
    /// of the earliest queued span.
    #[inline]
    pub fn hold_from(&self) -> Option<u64> {
        self.queue.front().map(|f| f.start)
    }

    /// The position at which the earliest queued span becomes due (its
    /// end). A decoder may stop producing there to run it.
    #[inline]
    pub fn due_at(&self) -> Option<u64> {
        self.queue.front().map(|f| f.start + f.len as u64)
    }

    /// The input staging area for the earliest queued span, as long as the
    /// span, for a decoder that passes [`SpanBytes::Staged`].
    pub fn staging_in(&mut self) -> Option<&mut [u8]> {
        let len = self.queue.front()?.len as usize;
        Some(&mut self.stage_in[..len])
    }

    /// If the decoder's position `pos` has reached the end of the earliest
    /// queued span, run its filter over `window` (that span's unfiltered
    /// bytes) and return the filtered bytes; the filter leaves the queue.
    /// Call again until it returns `None`: adjacent spans fall due together.
    pub fn run_due<'a>(
        &'a mut self,
        pos: u64,
        window: SpanBytes<'_>,
    ) -> Result<Option<FilteredSpan<'a>>> {
        let Some(&f) = self.queue.front() else {
            return Ok(None);
        };
        if pos < f.start + f.len as u64 {
            return Ok(None);
        }
        let n = f.len as usize;
        if let SpanBytes::Window(a, b) = window {
            if a.len() + b.len() != n {
                return Err(Error::new(ErrorKind::Corrupt(Corruption::Stream)));
            }
        }
        self.queue.pop_front();
        let FilterState {
            stage_in,
            stage_out,
            ..
        } = self;
        let bytes: &[u8] = match f.program {
            StandardProgram::X86Call | StandardProgram::X86CallJump | StandardProgram::Itanium => {
                // In place, on one copy of the span.
                let buf: &mut [u8] = match window {
                    SpanBytes::Window(a, b) => {
                        let buf = &mut stage_out[..n];
                        buf[..a.len()].copy_from_slice(a);
                        buf[a.len()..].copy_from_slice(b);
                        buf
                    }
                    SpanBytes::Staged => &mut stage_in[..n],
                };
                match f.program {
                    // Walking, for the reason `rar5_lz::filters::apply`
                    // gives. A RAR 3 stream carries type 1 more often
                    // than a RAR 5 one does, and type 1 is the record the
                    // split was measured WORST on: 2.7 percent behind
                    // walking on the generated corpus, 18 percent behind
                    // over real filter blocks.
                    StandardProgram::X86Call => x86_apply::<false>(buf, f.param),
                    StandardProgram::X86CallJump => x86_apply::<true>(buf, f.param),
                    _ => address_filters::ia64(buf, f.param, Direction::Decode),
                }
                buf
            }
            _ => {
                let src: &[u8] = match window {
                    SpanBytes::Window(a, []) => a,
                    SpanBytes::Window(a, b) => {
                        stage_in[..a.len()].copy_from_slice(a);
                        stage_in[a.len()..n].copy_from_slice(b);
                        &stage_in[..n]
                    }
                    SpanBytes::Staged => &stage_in[..n],
                };
                let out = &mut stage_out[..n];
                match f.program {
                    StandardProgram::Delta => transforms::delta_decode(src, out, f.param),
                    StandardProgram::Rgb => transforms::rgb_decode(src, out, f.param, f.red_at),
                    _ => transforms::audio_decode(src, out, f.param),
                }
                out
            }
        };
        Ok(Some(FilteredSpan {
            start: f.start,
            bytes,
        }))
    }

    /// Forget every filter whose span the stream has completed by
    /// position `pos`, without running it, and say whether there was one.
    ///
    /// For a member's packed data read after its declared size (3.8): a
    /// span completed there reaches past the declared size, so it is never
    /// run and no byte of it is delivered, and it is the member's failure.
    pub fn pass_completed(&mut self, pos: u64) -> bool {
        let mut passed = false;
        while self.due_at().is_some_and(|due| due <= pos) {
            self.queue.pop_front();
            passed = true;
        }
        passed
    }

    /// The member's end at stream position `end`, however it ended: by its
    /// end mark, by its packed data running out or by a failure (3.8).
    ///
    /// EVERY filter still waiting is dropped: none is run, none holds back
    /// a byte of a later member, and no later record is tested against
    /// one. The slots and the previous slot index are the stream's and
    /// stay. A waiting span that starts before `end` is one this member
    /// began and did not complete inside its output, which fails the
    /// member; one that starts at or past `end` fails nothing.
    pub fn end_member(&mut self, end: u64) -> Result<()> {
        let began = self.queue.iter().any(|filter| filter.start < end);
        self.queue.clear();
        if began {
            Err(corrupt_record())
        } else {
            Ok(())
        }
    }

    /// Filters now queued.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub(crate) fn queued(&self) -> usize {
        self.queue.len()
    }
}

/// The x86 pass this build runs, RAR 3 direction and decode.
///
/// The RAR 5 side has the same helper for the same reason; see
/// `rar5_lz::filters`'s `x86_apply`. RAR 3 carries TYPE 1 more often than
/// RAR 5 does, and type 1 is the record the split was measured worst on,
/// so a timed run wants to price both passes here too.
#[inline(always)]
fn x86_apply<const JUMP: bool>(data: &mut [u8], f: u32) {
    #[cfg(feature = "x86-arm-knob")]
    match crate::probe::x86_arm() {
        crate::probe::X86_ARM_WALKING => {
            return address_filters::x86_pass_walking::<false, JUMP, false>(data, f)
        }
        crate::probe::X86_ARM_SPLIT => {
            return address_filters::x86_pass::<false, JUMP, false>(data, f)
        }
        _ => {}
    }
    address_filters::x86_pass_adaptive::<false, JUMP, false>(data, f)
}
