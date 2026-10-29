//! Framing a RAR 5 filter record and handing it to the transforms
//! (SPEC-H2 section 3.6).
//!
//! This package frames the record and names the span. The TRANSFORMS are
//! spec C's: the x86 call, the x86 call and jump and the ARM branch passes
//! are carried in `carry::h_ours::codec::address_filters`, and the delta
//! reconstruction is carried in `carry::c_lz::codec::filters`.
//!
//! The span is MEMBER relative: in a solid chain the base resets at
//! every member boundary, so a filter in the second member of a solid
//! archive is measured from that member's own start, and its `F` is that
//! member relative start.
//!
//! Implemented from `specs/SPEC-H2-rarkit-rar5-lz.md` alone.

use std::collections::VecDeque;

use super::bits::BitReader;
use super::fault;
#[cfg(feature = "parallel")]
use super::output::LzSink;
use super::output::{FilterQueue, Span};
use crate::carry::c_lz::codec::filters::delta_rows;
use crate::carry::c_lz::codec::rar50::STREAM_FILTER_HOLD_LIMIT;
use crate::carry::h_ours::codec::address_filters::{arm, Direction};

/// The x86 pass this build runs, RAR 5 direction and decode.
///
/// One call in the shipped build: `test-support` is off, so this is
/// `x86_pass_walking` with nothing in front of it. With `test-support` on
/// a harness may select the split instead, which is how a timed run prices
/// the two against each other inside ONE binary rather than against a
/// second build that differs in layout as well as in the pass.
#[inline(always)]
fn x86_apply<const JUMP: bool>(data: &mut [u8], f: u32) {
    use crate::carry::h_ours::codec::address_filters as af;
    #[cfg(feature = "x86-arm-knob")]
    match crate::probe::x86_arm() {
        crate::probe::X86_ARM_WALKING => return af::x86_pass_walking::<false, JUMP, true>(data, f),
        crate::probe::X86_ARM_SPLIT => return af::x86_pass::<false, JUMP, true>(data, f),
        _ => {}
    }
    af::x86_pass_adaptive::<false, JUMP, true>(data, f)
}
use crate::Result;

/// THE FILTER PASS'S SUBTRACTION ARMS, for the untimed profile of the
/// parallel density rows (`examples/h2_filter_profile.rs`). A feature of
/// its own, for the reason `h2-apply-arms` gives in `Cargo.toml`: no gate
/// binary compiles this, so the measured walk and drain keep their shape.
///
/// Neither arm is byte exact and neither is meant to be. Each removes one
/// piece of the filter pass from the one apply thread, so the wall it
/// saves is that piece's price on the critical path, read by subtraction
/// inside one process rather than off a sampled profile.
#[cfg(feature = "h2-filter-arms")]
pub(crate) mod arms {
    use std::sync::atomic::{AtomicU8, Ordering};

    /// What ships.
    pub(crate) const SHIPPED: u8 = 0;
    /// Every record is queued and its span copied out of the ring as
    /// shipped, but the transform itself is not run.
    pub(crate) const NO_TRANSFORM: u8 = 1;
    /// Every record is counted and then dropped, so no span is ever held
    /// back: the drain sends the member straight out of the ring, as it
    /// does for a member that carries no filter at all.
    pub(crate) const NO_FILTERS: u8 = 2;

    static ARM: AtomicU8 = AtomicU8::new(SHIPPED);

    pub(crate) fn set(arm: u8) {
        ARM.store(arm, Ordering::Relaxed);
    }

    #[inline(always)]
    pub(crate) fn get() -> u8 {
        ARM.load(Ordering::Relaxed)
    }
}

/// The most bytes a pending filter may hold back from the sink; carried.
pub(crate) const FILTER_HOLD_LIMIT: usize = STREAM_FILTER_HOLD_LIMIT;
/// The most records that may wait at once (section 4.2, "Filter records
/// waiting at once"). The section leaves the number open above a floor
/// of 8,192, the most the reference was seen to run together; this is
/// the floor itself, because one record more is where
/// the reference stops running them all, and a reader that honoured more
/// would give bytes on such a stream that the reference does not. Past
/// it the stream is refused by name. No archive the reference was seen
/// to write has more than 20 waiting.
pub(crate) const WAITING_AT_ONCE: usize = 8_192;
/// The longest span that runs at EVERY dictionary: `W - 1` at the
/// smallest `W`, 256 KiB (section 3.6, "Long records"). A dictionary of
/// more than 256 KiB runs longer ones, up to [`IGNORED_ABOVE`]; this is
/// the bound a generator uses when it must not depend on the dictionary,
/// and only a generator uses it: the decoder bounds a span by `W`.
#[cfg(any(test, feature = "bench-internals"))]
pub(crate) const MAX_FILTER_BLOCK_LENGTH: usize = MIN_SPAN_BOUND as usize - 1;
/// A record LONGER than this is ignored as though it had never been read,
/// whatever the dictionary (section 3.6, "Long records", rule 1): not
/// queued, not run, not checked, and the order rule's floor does not move.
pub(crate) const IGNORED_ABOVE: usize = 0x40_0000;
/// The smallest `W`: a kept span is `FilterRange` when it is at least
/// `W = max(D, 256 KiB)` long (section 3.6, "Long records", rule 3).
pub(crate) const MIN_SPAN_BOUND: u64 = 256 << 10;

/// What a record's three bit type field names (section 3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterKind {
    /// Type 0, with a channel count of 1 to 32.
    Delta(u8),
    /// Type 1: x86 near calls.
    X86Call,
    /// Type 2: x86 near calls and jumps.
    X86CallJump,
    /// Type 3: ARM branch with link.
    Arm,
}

/// A record whose type field is 4 or above, as [`read_record`] hands it
/// on: a delta of NO channels, which no stream can name (the channel
/// field is the count less one, so a real delta has 1 to 32). It never
/// reaches the queue or a transform: [`Filters::push`] judges it first.
/// A value of the kind the writer shares rather than a kind of its own,
/// so that nothing outside this decoder learns of it.
pub(crate) const UNKNOWN_TYPE: FilterKind = FilterKind::Delta(0);

/// One queued record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) span: Span,
    pub(crate) kind: FilterKind,
}

/// A counted little endian 32 bit value: 2 bits give `k` and the value is
/// `k + 1` bytes of 8 bits each, least significant byte first (section 3.6).
#[inline]
pub(crate) fn read_counted(bits: &mut BitReader<'_>) -> Result<u32> {
    let bytes = bits.take(2)? + 1;
    let mut value = 0u32;
    for index in 0..bytes {
        value |= bits.take(8)? << (8 * index);
    }
    Ok(value)
}

/// One record as the bit stream holds it, before the member's own
/// position turns its offset into a span.
///
/// The split matters for the parallel block decode: everything a symbol
/// reads is a table lookup or a fixed width bit field (section 3.8), so
/// the fields below are decoded ahead of the decode point, and only the
/// SPAN - which is measured from the bytes produced so far - resolves when
/// the record is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RawRecord {
    pub(crate) offset: u32,
    pub(crate) length: u32,
    pub(crate) kind: FilterKind,
}

/// Read one filter record's fields (section 3.6).
pub(crate) fn read_record(bits: &mut BitReader<'_>) -> Result<RawRecord> {
    let offset = read_counted(bits)?;
    let length = read_counted(bits)?;
    let kind = match bits.take(3)? {
        0 => FilterKind::Delta(bits.take(5)? as u8 + 1),
        1 => FilterKind::X86Call,
        2 => FilterKind::X86CallJump,
        3 => FilterKind::Arm,
        // A type of 4 or above is READ like any other, with no channel
        // field, and judged only if the record is kept (section 3.6, "A
        // type of 4 or above", restated 9 Oct 2026): [`Filters::push`].
        _ => UNKNOWN_TYPE,
    };
    // No length test here: a long record is not refused when it is READ
    // (section 3.6, "Long records"). [`Filters::push`] ignores one past
    // [`IGNORED_ABOVE`] before the order rule and fails a kept one of `W`
    // or more after it, so that each is decided in the reference's order.
    Ok(RawRecord {
        offset,
        length,
        kind,
    })
}

impl RawRecord {
    /// The span this record names, measured from what the MEMBER has
    /// produced. Arithmetic only: whether the span is inside the
    /// member is [`Filters::push`]'s question, asked AFTER the order rule,
    /// because section 3.6 drops a record behind the last kept span without
    /// checking it against the member's end.
    ///
    /// **Why the check moved out of here** (27 Sep 2026, counted untimed on
    /// an Apple M3 Mac against the revision before it). The first form of the order rule
    /// passed the record, `produced` and the declared size into the serial
    /// loop's inlined record arm and checked the order before this range
    /// test: the loop spilled (`decode_block` 52 more loads, `run_fallback`
    /// 31) and retired 0.45 to 1.07 percent more instructions a round on
    /// every `_serial` row, the no filter row included. With the declared
    /// size held by [`Filters`] and the arm back to one resolved record, the
    /// same rows read 0.47 to 1.33 percent FEWER than main.
    #[inline(always)]
    pub(crate) fn resolve(&self, produced: u64) -> Record {
        let start = produced + u64::from(self.offset);
        Record {
            span: Span {
                start,
                length: self.length as usize,
            },
            kind: self.kind,
        }
    }
}

/// A member's declared size, unbounded until [`Filters::begin`] sets it.
#[derive(Clone, Copy)]
struct End(u64);

impl Default for End {
    fn default() -> End {
        End(u64::MAX)
    }
}

/// `W`, the length a KEPT span must stay below (section 3.6, "Long
/// records"): `max(D, 256 KiB)` for the decoder's declared dictionary `D`,
/// the smallest `W` until [`Filters::for_dictionary`] sets it.
#[derive(Clone, Copy)]
struct SpanBound(u64);

impl Default for SpanBound {
    fn default() -> SpanBound {
        SpanBound(MIN_SPAN_BOUND)
    }
}

/// The pending records of one member, in the order they were read (which
/// [`Filters::push`] makes start order too), and the scratch the delta
/// reconstruction writes through.
#[derive(Default)]
pub(crate) struct Filters {
    queue: VecDeque<Record>,
    /// Where the last record KEPT for this member ends, member relative: a
    /// record whose span starts before it is ignored ([`Filters::push`]).
    floor: u64,
    /// The member's declared size: a KEPT span past it is `FilterRange`.
    end: End,
    /// A kept span that left the member's declared output, or that is `W`
    /// or longer: the member's `FilterRange`, DEFERRED to the member's end
    /// (SPEC-H2 3.1 and 3.6, 28 Sep 2026). The member keeps decoding every
    /// symbol it owns, so the next member of a solid stream starts where
    /// the reference starts it; only this member fails.
    failed: bool,
    /// The earliest END of a kept span that starts at or past the declared
    /// size, when the member has read one (SPEC-H2 3.1, restated 8 Oct
    /// 2026). Such a span touches no declared byte; what it means for the
    /// member is known only at the member's end, by whether the stream
    /// went on to complete it ([`Filters::take_failed`]).
    beyond: Option<u64>,
    /// Whether the member carries NO checksum, which its reader says
    /// through [`Filters::carries_no_checksum`] before the member begins;
    /// it holds for that member and [`Filters::take_failed`] forgets it.
    unchecked: bool,
    /// Where a kept span that STRADDLES the declared size ends, in a
    /// member that carries no checksum, and zero when the member has
    /// none. The span is queued like any other and the window drains
    /// through to this point, so the transform sees its whole span; what
    /// lies past the declared size is not delivered ([`Window::drain`],
    /// SPEC-H2 3.1, rule 2 of "a kept filter record whose span is not
    /// wholly inside the member's declared output"). At most one a
    /// member: a later record starts at or past the declared size.
    reach: u64,
    /// `W`: a KEPT span this long or longer is `FilterRange`. A property of
    /// the decoder's window, so a member boundary does not touch it.
    bound: SpanBound,
    scratch: Vec<u8>,
    /// Records read for this member, for the tests and the vector reports.
    pub(crate) seen: usize,
    /// Records ignored for being longer than [`IGNORED_ABOVE`], and kept
    /// spans refused for being `W` or longer, across the decoder's life:
    /// the one place the old engine parts from section 3.6's long records,
    /// counted so the oracle fuzz targets can name that class. Both are
    /// bumped on a cold branch only.
    pub(crate) long_records: [u64; 2],
    /// How many of each kind, and their bytes, for the untimed census.
    pub(crate) kinds: [u64; 4],
    pub(crate) kind_bytes: [u64; 4],
    /// Off unless an untimed lab turns it on. The density lab needs the
    /// SPANS a real archive frames, and it has no other way to see them:
    /// a record is read, queued and applied inside one member decode.
    ///
    /// It is a flag rather than a `cfg` so that the branch a measured
    /// leg pays is one predictable test per RECORD, not per byte and not
    /// per block, and so the capture cannot be reached by a leg that did
    /// not ask for it. `bench-internals` is the only way to set it and no
    /// shipped build enables that feature.
    #[cfg_attr(not(feature = "bench-internals"), allow(dead_code))]
    pub(crate) capture: bool,
    /// `(start, length, kind slot)` per record, in the order the stream
    /// framed them, while `capture` is set.
    #[cfg_attr(not(feature = "bench-internals"), allow(dead_code))]
    pub(crate) captured: Vec<(u64, u32, u8)>,
    /// Whether the drain may hand this member's transforms to a pool task
    /// ([`Offload`]). Set by the tape path's apply stage, which is the only
    /// place it is ever set, and cleared with the queue at every member, so
    /// the serial decode never takes it.
    pub(crate) offload: bool,
    /// The spans handed away and not yet put, when `offload` is set.
    #[cfg(feature = "parallel")]
    handed: Offload,
}

impl Filters {
    /// A queue for a decoder whose declared dictionary is `dictionary`
    /// bytes: `W = max(D, 256 KiB)` (section 3.6, "Long records").
    pub(crate) fn for_dictionary(dictionary: u64) -> Filters {
        Filters {
            bound: SpanBound(dictionary.max(MIN_SPAN_BOUND)),
            ..Filters::default()
        }
    }

    /// Start a member that declares `unpacked` bytes: forget the queue and
    /// hold the size a kept span is checked against.
    pub(crate) fn begin(&mut self, unpacked: u64) {
        self.clear();
        self.end = End(unpacked);
    }

    /// How many batches of transforms this queue has handed to the pool,
    /// over every member it served, for the `internals` seam.
    #[cfg(all(feature = "parallel", feature = "bench-internals"))]
    pub(crate) fn batches_sealed(&self) -> u64 {
        self.handed.sealed_count
    }

    /// The member's deferred `FilterRange`, if it has one
    /// ([`Filters::push`]); asked once, at the member's end.
    ///
    /// `produced` is how far the member's blocks ran, surplus past the
    /// declared size included, and `checked` whether the member carries a
    /// checksum of either kind. A span at or past the declared size that
    /// the stream COMPLETED fails a member that carries a checksum and
    /// passes one that carries none; one the stream did not complete is
    /// dropped here and fails nothing (SPEC-H2 3.1, rules 2 to 4 of "a
    /// kept filter record whose span is not wholly inside the member's
    /// declared output"). The earliest end is enough: if any such span
    /// was completed, that one was.
    ///
    /// A span that STRADDLES the declared size, kept for a member with no
    /// checksum, fails the member here when the stream did not complete
    /// it: its bytes inside the declared output were held back for a
    /// transform that never ran, and a member never ends short at a
    /// filter boundary (3.1, 3.6).
    pub(crate) fn take_failed(&mut self, produced: u64, checked: bool) -> Option<crate::Error> {
        let completed = self.beyond.take().is_some_and(|end| produced >= end);
        let failed = std::mem::take(&mut self.failed);
        let cut = std::mem::take(&mut self.reach) > produced;
        self.unchecked = false;
        (failed || cut || (completed && checked)).then(fault::filter_range)
    }

    /// A KEPT record whose type field is 4 or above (section 3.6, "A type
    /// of 4 or above", restated 9 Oct 2026). It moves the order rule's
    /// floor as any kept record does. Where its span is empty, or starts
    /// at or past the member's declared size, it fails nothing: it
    /// transforms nothing and holds nothing back, and the decode goes on
    /// with the next symbol. Where its span is not empty and starts
    /// inside the declared output the member fails, `FilterType`, with a
    /// checksum or without: the genuine programs write such a member
    /// with the span cut out of its middle and call it good when nothing
    /// checks it, which is the one thing not followed here.
    ///
    /// Out of line and cold: no genuine writer sends such a record.
    #[cold]
    #[inline(never)]
    fn unknown_type(&mut self, span: Span) -> Result<()> {
        self.floor = span.start + span.length as u64;
        if span.length == 0 || span.start >= self.end.0 {
            return Ok(());
        }
        Err(fault::filter_type())
    }

    /// Whether a kept span is still waiting, which at a member's end
    /// means the stream never completed it.
    pub(crate) fn span_open(&self) -> bool {
        !self.queue.is_empty()
    }

    /// The member about to begin carries no checksum, neither a CRC32
    /// field nor a hash record. Said before [`Filters::begin`], which
    /// keeps it; a queue told nothing gives the strict answer.
    pub(crate) fn carries_no_checksum(&mut self) {
        self.unchecked = true;
    }

    /// Forget the queue; a new member starts with none pending.
    pub(crate) fn clear(&mut self) {
        self.queue.clear();
        self.floor = 0;
        self.end = End::default();
        self.failed = false;
        self.beyond = None;
        self.reach = 0;
        self.seen = 0;
        self.offload = false;
        #[cfg(feature = "parallel")]
        self.handed.clear();
    }

    /// [`Filters::push`], kept OUT OF LINE, for the tape path's apply stage
    /// ONLY (`tape::apply`).
    ///
    /// **Why a second entry point and not an attribute on `push`, and both
    /// halves are measured** (23 Sep 2026). A filter
    /// record is rare against the symbols around it, and `tape::apply` is the
    /// critical loop of a solid chain decoded ahead. From 22 Sep the compiler
    /// chose to inline `push` into it (a neighbouring change tipped its
    /// inlining budget): the apply stage grew from 1,233 to 1,341
    /// instructions and from 317 to 362 loads and stores, and
    /// `rar5_small_solid_20k_vsnull` lost about 10 percent of rarkit's own
    /// wall on an Apple M3 Mac. Marking `push` itself out of line recovered that
    /// row and cost the SERIAL loop, which calls `push` too, about 5 percent
    /// on all four `_serial` rows on the same machine. So the serial loop keeps
    /// `push` as the compiler likes it, and only the apply stage goes through
    /// this call, which it can never inline.
    #[cfg(feature = "parallel")]
    #[inline(never)]
    pub(crate) fn push_outlined(&mut self, record: Record) -> Result<()> {
        self.push(record)
    }

    /// Queue a record PAST the order rule, which no stream can: the one way
    /// a test still reaches a queue whose span starts behind what has left
    /// (`tests::a_member_a_filter_kept_short_is_incomplete`).
    #[cfg(test)]
    pub(crate) fn push_unordered_for_test(&mut self, record: Record) {
        self.queue.push_back(record);
    }

    /// Queue one record. A record whose length is zero names an empty span
    /// and is a no operation, not an error (section 3.6).
    ///
    /// **INLINED INTO THE SERIAL LOOP ON PURPOSE** (the code
    /// serial M1 measurement, 23 Sep 2026). The serial decode loop
    /// (`decode_block`) is the one caller that reaches this body directly;
    /// the tape path's apply stage comes through [`Filters::push_outlined`],
    /// which never inlines, so pinning this changes nothing there
    /// (`tape::apply` is 1,757 instructions, 272 loads and 137 stores with
    /// the pin and without it). Left to the compiler, whether this body
    /// joins the serial loop flipped with unrelated landings: an
    /// earlier revision called it out of line, `decode_block` 3,127 instructions,
    /// and one more function in this file was enough to inline it again.
    /// Inlined, the loop is 3,490 instructions and retires about 1 to 2.6
    /// percent MORE of them a round on the `_serial` rows, yet takes FEWER
    /// cycles on every one: counted against the control's own binary in one
    /// run, 3.0 percent fewer on the code row on an Apple M1 Mac and 5.4 on
    /// an Apple M3 Mac, 0.7 to 5.7 percent on the rest. The 20k work priced the
    /// same boundary the other way (`inline(never)` here cost the four
    /// `_serial` rows about 5 percent on another M3 Mac),
    /// so the boundary is pinned rather than left to a budget any
    /// neighbouring change can tip.
    #[inline(always)]
    pub(crate) fn push(&mut self, record: Record) -> Result<()> {
        // A RECORD LONGER THAN 4 MiB WAS NEVER READ (section 3.6, "Long
        // records", rule 1, measured on reference unrar 7.23 at every
        // dictionary from 128 KiB to 4 GiB): it is not counted, not
        // queued and not checked, and the floor below does not move, so a
        // record after it on an earlier span still runs.
        if record.span.length > IGNORED_ABOVE {
            self.long_records[0] += 1;
            return Ok(());
        }
        self.seen += 1;
        let slot = match record.kind {
            FilterKind::Delta(_) => 0,
            FilterKind::X86Call => 1,
            FilterKind::X86CallJump => 2,
            FilterKind::Arm => 3,
        };
        self.kinds[slot] += 1;
        self.kind_bytes[slot] += record.span.length as u64;
        if self.capture {
            self.captured
                .push((record.span.start, record.span.length as u32, slot as u8));
        }
        // A RECORD THAT STARTS BEFORE THE END OF THE LAST ONE KEPT IS
        // IGNORED, and an empty record is kept like any other, its end
        // being its start. Section 3.6 is silent on a second record over
        // bytes a first already names; this is reference unrar 7.23's
        // answer, measured black box on 27 Sep 2026 for all four types: the same
        // span, nested either way, partly overlapping either way, a record
        // read mid-span, and a DISJOINT record that starts before one read
        // earlier all keep the earlier record alone; adjacent spans and an
        // empty record ahead of a later one hold their places in the order
        // read. So the queue stays in read order, which this makes start
        // order too, and a span can never start behind what the drain has
        // already sent (`Window::drain`). Before this, a second record on
        // the same span went down the drain's hold path, waited for bytes
        // the member never produced, and the member ended short.
        if record.span.start < self.floor {
            return Ok(());
        }
        // THE TYPE IS JUDGED HERE, for a record the two rules above have
        // KEPT, and not where the record is read (section 3.6, "A type of
        // 4 or above", restated 9 Oct 2026).
        if record.kind == UNKNOWN_TYPE {
            return self.unknown_type(record.span);
        }
        // A KEPT span is shorter than `W`, or it is `FilterRange` for the
        // member (3.6, "Long records" rule 3, where the reference stops
        // silently and rarkit fails loudly); a dropped one, above, never
        // reaches this test. One that STRADDLES the member's declared
        // size is `FilterRange` too where the member carries a checksum;
        // where it carries none the span is kept and queued below, and
        // only its end is noted, for the drain to run through to. One
        // that starts AT OR PAST the declared size is only noted: the
        // member's end says what it means ([`Filters::take_failed`]).
        // Each failure waits for the
        // member's end and the decode goes on: the member still owns
        // every symbol after the record, which the next member of a solid
        // stream counts from (3.1). The record keeps its place in the
        // order rule, as the reference's does for a span past the end.
        let end = record.span.start + record.span.length as u64;
        if record.span.length as u64 >= self.bound.0 {
            self.long_records[1] += 1;
            self.failed = true;
            self.floor = end;
            return Ok(());
        }
        if end > self.end.0 {
            if record.span.start >= self.end.0 {
                self.beyond = Some(self.beyond.map_or(end, |earliest| earliest.min(end)));
                self.floor = end;
                return Ok(());
            }
            if !self.unchecked {
                self.failed = true;
                self.floor = end;
                return Ok(());
            }
            self.reach = end;
        }
        self.floor = end;
        if record.span.length == 0 {
            return Ok(());
        }
        #[cfg(feature = "h2-filter-arms")]
        if arms::get() == arms::NO_FILTERS {
            return Ok(());
        }
        let waiting = self.queue.len() + 1;
        if waiting > WAITING_AT_ONCE {
            return Err(fault::pending_exceeded(waiting as u64));
        }
        self.queue.push_back(record);
        Ok(())
    }
}

impl FilterQueue for Filters {
    fn front(&self) -> Option<Span> {
        self.queue.front().map(|record| record.span)
    }

    fn apply(&mut self, _span: &Span, data: &mut [u8]) {
        let Some(record) = self.queue.front().copied() else {
            return;
        };
        transform(record, data, &mut self.scratch);
    }

    #[cfg(feature = "parallel")]
    fn offload(&self) -> bool {
        self.offload
    }

    #[cfg(feature = "parallel")]
    fn hand_away(&mut self, first: &[u8], second: &[u8]) {
        if let Some(record) = self.queue.front().copied() {
            self.handed.add(Some(record), first, second);
        }
    }

    #[cfg(feature = "parallel")]
    fn hand_plain(&mut self, first: &[u8], second: &[u8]) {
        self.handed.add(None, first, second);
    }

    #[cfg(feature = "parallel")]
    fn hand_open(&mut self, first: &[u8], second: &[u8]) {
        self.handed.open_span(first, second);
    }

    #[cfg(feature = "parallel")]
    fn open_len(&self) -> usize {
        self.handed.partial.as_ref().map_or(0, Vec::len)
    }

    #[cfg(feature = "parallel")]
    fn take_open(&mut self) -> Option<Vec<u8>> {
        self.handed.partial.take()
    }

    #[cfg(feature = "parallel")]
    fn seal(&mut self) {
        self.handed.seal();
    }

    #[cfg(feature = "parallel")]
    fn put_handed<S: LzSink>(&mut self, sink: &mut S) -> Result<usize> {
        self.handed.put_next(sink)
    }

    fn pop(&mut self) {
        self.queue.pop_front();
    }

    fn reach(&self) -> u64 {
        self.reach
    }
}

/// Run one record's transform over its span's bytes, in place. `scratch`
/// is what the delta reconstruction copies through.
///
/// One function for both places a transform runs, the drain's own thread
/// and a pool task ([`Offload`]), so the two cannot differ in a byte.
#[inline(always)]
fn transform(record: Record, data: &mut [u8], scratch: &mut Vec<u8>) {
    #[cfg(feature = "h2-filter-arms")]
    if arms::get() == arms::NO_TRANSFORM {
        return;
    }
    // `F` is the span's MEMBER relative start (section 3.6), and it
    // is a 32 bit value: a start past 4 GiB is taken modulo 2^32, as
    // it was on a 64-bit `usize` before this was widened.
    let f = record.span.start as u32;
    match record.kind {
        FilterKind::Delta(channels) => {
            scratch.clear();
            scratch.extend_from_slice(data);
            delta_decode(usize::from(channels), scratch, data);
        }
        // The WALKING body, on the real-corpus measurement
        // of 22 Sep 2026: over 3,039 filter
        // blocks that reference `rar` framed itself over real x86-64
        // binaries, walking is 17 percent faster than the
        // scan-then-convert split, in every trigger-gap band and on
        // both record types. The split leads only near 13 bytes a
        // trigger, which is below the tenth percentile of the real
        // population and is where this suite's own generated legs
        // sit.
        FilterKind::X86Call => x86_apply::<false>(data, f),
        FilterKind::X86CallJump => x86_apply::<true>(data, f),
        FilterKind::Arm => arm(data, f, Direction::Decode),
    }
}

/// [`transform`] for one record of type `kind` (0 to 3, section 3.6) and,
/// for delta, `channels`, over `data` as the span starting at member offset
/// `start`: the `internals` seam's way to say what a span's bytes become.
#[cfg(feature = "bench-internals")]
pub(crate) fn transform_for_seam(kind: u8, channels: u8, start: u64, data: &mut [u8]) {
    let kind = match kind {
        0 => FilterKind::Delta(channels),
        1 => FilterKind::X86Call,
        2 => FilterKind::X86CallJump,
        _ => FilterKind::Arm,
    };
    let span = Span {
        start,
        length: data.len(),
    };
    transform(Record { span, kind }, data, &mut Vec::new());
}

/// Whether the tape path hands its transforms to a pool task.
///
/// On, unless a harness under `h2-filter-arms` sets `RARKIT_FILTER_OFFLOAD`
/// to `0`, which is how a timed run prices the two arms inside ONE binary.
/// Read once per process: the variable is not consulted per block.
#[cfg(feature = "parallel")]
pub(crate) fn offload_wanted() -> bool {
    #[cfg(feature = "h2-filter-arms")]
    {
        static WANTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *WANTED.get_or_init(|| match std::env::var("RARKIT_FILTER_OFFLOAD") {
            // Said once, and only when the variable is set, so a timed run
            // can SHOW the knob reached the binary rather than assume it.
            Ok(v) => {
                let on = v.trim() != "0";
                eprintln!("rarkit filter offload: {}", if on { "ON" } else { "OFF" });
                on
            }
            Err(_) => true,
        })
    }
    #[cfg(not(feature = "h2-filter-arms"))]
    true
}

/// Where a handed span's bytes are: in its batch's one buffer, or, for a
/// span that was copied out while still open, in the buffer that copy
/// filled ([`Offload::open_span`]), which the span keeps so its bytes
/// are not moved a second time.
#[cfg(feature = "parallel")]
enum Place {
    Sheet(usize, usize),
    Own(Vec<u8>),
}

/// One span handed away: where its unfiltered bytes are, transformed in
/// place by whoever runs the batch, and the record that says how. No
/// record is a range with no filter over it, which a ring too short to
/// keep it until the next drain hands away too, to be put as it is
/// (`Window::drain`'s short ring form).
#[cfg(feature = "parallel")]
struct Handed {
    record: Option<Record>,
    at: Place,
}

/// THE SPANS ONE DRAIN HANDED AWAY, AND THEIR BYTES END TO END IN ONE
/// BUFFER.
///
/// One buffer a batch, not one a span, is what keeps a read's memory flat
/// in the member's size (measured 1 Oct 2026).
/// With a buffer a span, kept for reuse, the kept list grew to the most
/// spans ever in flight (428 on a 1 GiB tar of binaries as reference `rar`
/// packs it at `-m3`), and each buffer's capacity to the largest range it
/// ever carried, a whole 1 MiB drain batch on a ring under four batches:
/// 300 MB held at the end of a 4.1 GiB member, counted, where the bytes in
/// flight were under 2 MB. A sheet holds what one drain handed, so what
/// the offload keeps is a few sheets of about a batch each, whatever the
/// member's size and however many records it carries.
#[cfg(feature = "parallel")]
#[derive(Default)]
struct Sheet {
    bytes: Vec<u8>,
    spans: Vec<Handed>,
}

#[cfg(feature = "parallel")]
impl Sheet {
    /// The bytes of the span at `index`, as they stand.
    fn data(&self, index: usize) -> Option<&[u8]> {
        Some(match &self.spans.get(index)?.at {
            Place::Sheet(from, to) => &self.bytes[*from..*to],
            Place::Own(data) => data,
        })
    }

    /// Run every span of the sheet, in place.
    fn run(&mut self) {
        let mut scratch = Vec::new();
        for span in self.spans.iter_mut() {
            let Some(record) = span.record else {
                continue;
            };
            let data = match &mut span.at {
                Place::Sheet(from, to) => &mut self.bytes[*from..*to],
                Place::Own(data) => &mut data[..],
            };
            transform(record, data, &mut scratch);
        }
    }

    /// Empty the sheet, keeping its buffers, and answer the spans' own
    /// buffers it carried.
    fn reset(&mut self, own: &mut Vec<Vec<u8>>) {
        self.bytes.clear();
        for span in self.spans.drain(..) {
            if let Place::Own(data) = span.at {
                if own.len() < SPARE_OWN {
                    own.push(data);
                }
            }
        }
    }
}

/// How many emptied sheets the offload keeps for reuse. Three are in use
/// at a steady member (the one being filled, the one a task is running,
/// the one being put), so at most one is ever idle; two covers the drain
/// that seals twice.
#[cfg(feature = "parallel")]
const SPARE_SHEETS: usize = 2;
/// How many open-span buffers the offload keeps for reuse: one drain
/// leaves at most one span open.
#[cfg(feature = "parallel")]
const SPARE_OWN: usize = 2;

/// Where a batch is. A batch is run exactly once, by the pool task or by
/// the drain's own thread, whichever takes it out of `Queued` first.
#[cfg(feature = "parallel")]
enum Stage {
    Queued(Sheet),
    Running,
    Done(Sheet),
    Taken,
}

#[cfg(feature = "parallel")]
struct Batch {
    stage: std::sync::Mutex<Stage>,
    finished: std::sync::Condvar,
}

#[cfg(feature = "parallel")]
impl Batch {
    fn stage(&self) -> std::sync::MutexGuard<'_, Stage> {
        // Nothing that holds this lock can panic between taking and
        // releasing it, so a poisoned lock still guards a sound value.
        self.stage.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The batch's sheet, transformed: waited for if a task is running
    /// it, and run here if nobody has started it yet. This is what makes
    /// the pool's width irrelevant to progress: a batch no pool thread has
    /// reached costs this thread the transform it would have paid anyway,
    /// and never a wait on a queue.
    fn collect(&self) -> (Sheet, bool) {
        let mut stage = self.stage();
        loop {
            match std::mem::replace(&mut *stage, Stage::Taken) {
                Stage::Queued(mut sheet) => {
                    drop(stage);
                    sheet.run();
                    return (sheet, true);
                }
                Stage::Done(sheet) => return (sheet, false),
                Stage::Running => {
                    *stage = Stage::Running;
                    stage = self.finished.wait(stage).unwrap_or_else(|p| p.into_inner());
                }
                // Collected once only, by construction of `Offload`.
                Stage::Taken => return (Sheet::default(), false),
            }
        }
    }
}

/// THE TRANSFORM OFFLOAD: the spans one drain completed, handed to a pool
/// task as one batch, and put to the sink by a LATER drain in member
/// order (`Window::drain`, the x86 density rows'
/// measurement of 22 Sep 2026).
///
/// The drain still copies each span out of the ring and still puts it;
/// what leaves its thread is the transform, which was 2.5 to 4.8 ms of a
/// 20 ms member on the density rows and all of it on the tape path's one
/// apply thread. A task never blocks, so a pool task is the right home
/// for it, and [`Batch::collect`] runs a batch the pool has not reached,
/// so a pool of any width, the caller's included, cannot stall a member.
#[cfg(feature = "parallel")]
#[derive(Default)]
struct Offload {
    /// The batch this drain is filling.
    open: Sheet,
    /// Sealed batches in member order, oldest first.
    sealed: VecDeque<std::sync::Arc<Batch>>,
    /// The oldest batch's sheet once collected, and how many of its spans
    /// are put.
    current: Sheet,
    next: usize,
    /// Emptied sheets kept for reuse, so a steady member allocates
    /// nothing: never more than [`SPARE_SHEETS`], each as large as the
    /// most one drain handed away.
    spare: Vec<Sheet>,
    /// Open-span buffers kept for reuse, never more than [`SPARE_OWN`].
    own: Vec<Vec<u8>>,
    /// The front span's bytes copied out so far while it is still open,
    /// on a ring too short to keep them until it completes (the short
    /// ring form of `Window::drain`); the span's handed buffer once it
    /// does.
    partial: Option<Vec<u8>>,
    /// Batches sealed, and batches the drain ran itself because no pool
    /// thread had started them, for the tests.
    sealed_count: u64,
    stolen_count: u64,
}

#[cfg(feature = "parallel")]
impl Offload {
    /// Forget everything: a batch still running finishes on its own and
    /// drops its buffers there.
    fn clear(&mut self) {
        self.open.reset(&mut self.own);
        self.sealed.clear();
        self.current.reset(&mut self.own);
        self.next = 0;
        self.partial = None;
    }

    /// Hand `first` then `second` away under `record`, after whatever of
    /// the span [`Offload::open_span`] already copied.
    fn add(&mut self, record: Option<Record>, first: &[u8], second: &[u8]) {
        let at = match self.partial.take() {
            Some(mut partial) if record.is_some() => {
                partial.extend_from_slice(first);
                partial.extend_from_slice(second);
                Place::Own(partial)
            }
            other => {
                self.partial = other;
                let from = self.open.bytes.len();
                self.open.bytes.extend_from_slice(first);
                self.open.bytes.extend_from_slice(second);
                Place::Sheet(from, self.open.bytes.len())
            }
        };
        self.open.spans.push(Handed { record, at });
    }

    /// Copy the front span's bytes produced so far, while it is open.
    fn open_span(&mut self, first: &[u8], second: &[u8]) {
        let mut data = match self.partial.take() {
            Some(partial) => partial,
            None => {
                let mut data = self.own.pop().unwrap_or_default();
                data.clear();
                data
            }
        };
        data.extend_from_slice(first);
        data.extend_from_slice(second);
        self.partial = Some(data);
    }

    fn seal(&mut self) {
        if self.open.spans.is_empty() {
            return;
        }
        let fresh = self.spare.pop().unwrap_or_default();
        let batch = std::sync::Arc::new(Batch {
            stage: std::sync::Mutex::new(Stage::Queued(std::mem::replace(&mut self.open, fresh))),
            finished: std::sync::Condvar::new(),
        });
        let task = std::sync::Arc::clone(&batch);
        rayon::spawn(move || {
            let mut sheet = {
                let mut stage = task.stage();
                match std::mem::replace(&mut *stage, Stage::Running) {
                    Stage::Queued(sheet) => sheet,
                    other => {
                        // The drain took it back first.
                        *stage = other;
                        return;
                    }
                }
            };
            sheet.run();
            *task.stage() = Stage::Done(sheet);
            task.finished.notify_all();
        });
        self.sealed.push_back(batch);
        self.sealed_count += 1;
    }

    /// Put the next handed span, in member order, and answer its length.
    fn put_next<S: LzSink>(&mut self, sink: &mut S) -> Result<usize> {
        if self.next == self.current.spans.len() {
            // The sheet just put goes back first, so the next one sealed
            // or filled is the one whose bytes this thread touched last.
            let mut put = std::mem::take(&mut self.current);
            put.reset(&mut self.own);
            if self.spare.len() < SPARE_SHEETS {
                self.spare.push(put);
            }
            self.next = 0;
            self.seal();
            if let Some(batch) = self.sealed.pop_front() {
                let (sheet, stolen) = batch.collect();
                self.current = sheet;
                self.stolen_count += u64::from(stolen);
            }
        }
        let Some(data) = self.current.data(self.next) else {
            return Ok(0);
        };
        self.next += 1;
        sink.put(data)?;
        Ok(data.len())
    }

    /// What the offload holds allocated, in bytes, for the tests.
    #[cfg(test)]
    fn kept(&self) -> usize {
        let sheet = |s: &Sheet| {
            s.bytes.capacity()
                + s.spans
                    .iter()
                    .map(|h| match &h.at {
                        Place::Own(data) => data.capacity(),
                        Place::Sheet(..) => 0,
                    })
                    .sum::<usize>()
        };
        sheet(&self.open)
            + sheet(&self.current)
            + self.spare.iter().map(sheet).sum::<usize>()
            + self.own.iter().map(Vec::capacity).sum::<usize>()
            + self.partial.as_ref().map_or(0, Vec::capacity)
    }
}

/// One member driven straight through a [`Window`], the way the apply
/// stage drives it: seeded literal runs and matches, filter records of
/// every kind pushed at seeded points, some overlapping the span before
/// them, some far ahead of the decode point and some empty, and a
/// drain whenever one is due. Answers the sink's bytes and the offload's
/// sealed and stolen batch counts.
/// `script` steers every choice: its bytes are folded into a seeded
/// generator, cycling, so a fuzzer's input and a test's seed reach the
/// same shapes. The member is 6 MiB, which LAPS a 4 MiB ring by
/// construction whatever the script's length (the fuzz target inventory).
#[cfg(all(feature = "parallel", any(test, feature = "bench-internals")))]
pub(crate) fn offload_case(
    ring: u64,
    offload: bool,
    script: &[u8],
    overlap: bool,
) -> (Vec<u8>, u64, u64) {
    use super::output::Window;

    let total: u64 = 6 << 20;
    let mut rng = script.iter().fold(0x2209_2026u32, |h, &b| {
        h.rotate_left(5) ^ u32::from(b).wrapping_mul(0x9E37_79B1)
    }) | 1;
    let mut at = 0usize;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 17;
        rng ^= rng << 5;
        let steer = if script.is_empty() {
            0
        } else {
            at = (at + 1) % script.len();
            u32::from(script[at])
        };
        rng ^ steer
    };
    let mut win = Window::new(ring, u64::MAX).unwrap();
    win.reset();
    let mut filters = Filters {
        offload,
        ..Filters::default()
    };
    let mut sink: Vec<u8> = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    // Where the last pushed span ends: seeded records never overlap,
    // and the one overlapping pair below is placed by hand.
    let mut clear_from = 0u64;
    let mut overlapped = false;
    while win.produced() < total {
        let produced = win.produced();
        if overlap && !overlapped && produced >= 1 << 20 && produced >= clear_from {
            // A span that completes first, then one starting inside
            // it, the shape `an_overlapping_filter_span_keeps_going_
            // through_the_hold` pins: the second reaches the front
            // behind the emission cursor.
            overlapped = true;
            for (offset, length) in [(0u64, 4_096usize), (64, 100)] {
                filters
                    .push(Record {
                        span: Span {
                            start: produced + offset,
                            length,
                        },
                        kind: FilterKind::X86Call,
                    })
                    .unwrap();
            }
            clear_from = produced + 4_096;
        } else if next() % 24 == 0 {
            let start = produced.max(clear_from) + u64::from(next() % 150_000);
            let length = if next() % 16 == 0 {
                0
            } else {
                u64::from(next() % MAX_FILTER_BLOCK_LENGTH as u32)
            };
            if start + length <= total {
                let kind = match next() % 6 {
                    0 => FilterKind::Delta((next() % 5 + 1) as u8),
                    1 => FilterKind::Arm,
                    2 | 3 => FilterKind::X86Call,
                    _ => FilterKind::X86CallJump,
                };
                let record = Record {
                    span: Span {
                        start,
                        length: length as usize,
                    },
                    kind,
                };
                filters.push(record).unwrap();
                clear_from = start + length;
            }
        }
        let room = (total - produced) as usize;
        if produced > 300 && next() % 3 == 0 {
            let distance = 1 + (next() as u64 % produced.min(ring)) as usize;
            let length = (2 + next() as usize % 300).min(room);
            win.copy_match(distance, length).unwrap();
        } else {
            let length = (1 + next() as usize % 4_000).min(room);
            run.clear();
            for _ in 0..length {
                let r = next();
                run.push(match r % 11 {
                    0 => 0xE8,
                    1 => 0xE9,
                    2 => 0xEB,
                    _ => (r >> 9) as u8,
                });
            }
            win.literals(&run);
        }
        if win.drain_due() {
            win.drain(&mut sink, &mut filters, false).unwrap();
        }
    }
    win.drain(&mut sink, &mut filters, true).unwrap();
    // With an overlapping pair the hold path may leave the tail short
    // (the shipped behaviour, an open specification question); both
    // arms must still agree, which is what the callers check.
    if !overlap {
        assert_eq!(sink.len() as u64, total, "the member is its declared size");
    }
    (
        sink,
        filters.handed.sealed_count,
        filters.handed.stolen_count,
    )
}

/// Reconstruct `channels` interleaved channels from their stored planes.
///
/// The carried row at a time reconstruction serves the counts the reference
/// writer picks; every other count goes down the plane at a time path,
/// which is the same arithmetic written once.
fn delta_decode(channels: usize, encoded: &[u8], out: &mut [u8]) {
    debug_assert_eq!(encoded.len(), out.len());
    match channels {
        1 => delta_rows::<1>(encoded, out),
        2 => delta_rows::<2>(encoded, out),
        3 => delta_rows::<3>(encoded, out),
        4 => delta_rows::<4>(encoded, out),
        _ => {
            let mut at = 0;
            for channel in 0..channels {
                let mut previous = 0u8;
                let mut index = channel;
                while index < out.len() {
                    previous = previous.wrapping_sub(encoded[at]);
                    out[index] = previous;
                    at += 1;
                    index += channels;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE TRANSFORM OFFLOAD MOVES NO BYTE. The same member, drain for
    /// drain, with the transforms handed to a pool task and without, on
    /// rings under four batches (the short ring form, which copies out
    /// everything it accounts for: dictionaries of 64 KiB, 1 MiB and
    /// rarkit's default 2 MiB) and on rings long enough to keep a range
    /// until the next drain. Every one must seal batches: until 28 Sep
    /// 2026 a short ring kept the synchronous path and sealed nothing.
    #[cfg(feature = "parallel")]
    #[test]
    fn the_handed_drain_is_the_drain_byte_for_byte() {
        for seed in [0x2209_2026u32, 0x5150_cafe, 0x1957_0001, 0x0bad_f00d] {
            for ring in [1u64 << 16, 1 << 20, 2 << 20, 4 << 20, 8 << 20] {
                for overlap in [false, true] {
                    let (want, sealed_off, _) =
                        offload_case(ring, false, &seed.to_le_bytes(), overlap);
                    assert_eq!(sealed_off, 0, "the synchronous arm hands nothing away");
                    let (got, sealed, _) = offload_case(ring, true, &seed.to_le_bytes(), overlap);
                    assert!(
                        got == want,
                        "seed {seed:#x}, ring {ring}, overlap {overlap}: the bytes differ"
                    );
                    assert!(
                        sealed > 4,
                        "ring {ring}: the offload was not taken ({sealed})"
                    );
                }
            }
        }
    }

    /// One member through a ring of `dictionary`, with `spans` queued as
    /// 12 channel delta records before a byte is produced, literals in runs
    /// of `step`, a drain whenever one is due, and the member's declared
    /// size set, so the last drain is the COMPLETE one. Answers the sink's
    /// bytes, the batches handed away and the drain's counts.
    #[cfg(feature = "parallel")]
    fn short_ring_case(
        dictionary: u64,
        offload: bool,
        spans: &[(u64, usize)],
        total: usize,
        step: usize,
    ) -> (Vec<u8>, u64, crate::rar5_lz::output::DrainCounts) {
        use super::super::output::Window;
        let mut win = Window::new(dictionary, u64::MAX).unwrap();
        win.reset();
        win.begin_member();
        win.set_output(total as u64);
        let mut filters = Filters::for_dictionary(dictionary);
        filters.offload = offload;
        for &(start, length) in spans {
            filters
                .push(Record {
                    span: Span { start, length },
                    kind: FilterKind::Delta(12),
                })
                .unwrap();
        }
        let mut rng = 0x2809_2026u32;
        let bytes: Vec<u8> = (0..total)
            .map(|_| {
                rng ^= rng << 13;
                rng ^= rng >> 17;
                rng ^= rng << 5;
                (rng >> 11) as u8
            })
            .collect();
        let mut sink: Vec<u8> = Vec::new();
        for run in bytes.chunks(step) {
            if win.drain_due() {
                win.drain(&mut sink, &mut filters, false).unwrap();
            }
            win.literals(run);
        }
        win.drain(&mut sink, &mut filters, true).unwrap();
        assert_eq!(sink.len(), total, "the member is its declared size");
        (sink, filters.handed.sealed_count, win.drain_counts())
    }

    /// THE SHORT RING FORM HANDS A SPAN AWAY (the filter layout work, 28
    /// Sep 2026). A 2 MiB dictionary, rarkit's default, has a ring under
    /// four drain batches. Before that work such a ring ran every
    /// transform on the drain's own thread and sealed nothing, so this
    /// fails on the drain it replaced; the bytes must be the synchronous
    /// drain's, on spans laid as rarkit's writer lays them (one per 256 KiB
    /// parse block, 0x3ffff long), as reference `rar` does (64 KiB), and as
    /// long as section 3.6's long records let a span be under the
    /// dictionary: longer than the four batch form keeps open beside two
    /// batches, which this form copies out whatever its length.
    #[cfg(feature = "parallel")]
    #[test]
    fn a_short_ring_hands_its_spans_away_and_moves_no_byte() {
        let total = 6 << 20;
        for (layout, every, length, dictionaries) in [
            (
                "rarkit",
                0x40000u64,
                0x3ffffusize,
                &[1u64 << 20, 2 << 20][..],
            ),
            ("rar", 0x10000, 0x10000, &[1 << 20, 2 << 20][..]),
            ("long 1 MiB", 0xf_0000, 0xe_0000, &[1 << 20][..]),
            ("long 2 MiB", 0x1f_0000, 0x1e_0000, &[2 << 20][..]),
        ] {
            let spans: Vec<(u64, usize)> = (0..total as u64 / every)
                .map(|i| (i * every, length))
                .collect();
            for &dictionary in dictionaries {
                for step in [4_000usize, 65_536, 300_001] {
                    let (want, sealed_off, _) =
                        short_ring_case(dictionary, false, &spans, total, step);
                    assert_eq!(sealed_off, 0);
                    let (got, sealed, _) = short_ring_case(dictionary, true, &spans, total, step);
                    assert!(
                        got == want,
                        "{layout}, dictionary {dictionary}, step {step}: the bytes differ"
                    );
                    // Three long spans fill the member, so fewer batches.
                    let least = if spans.len() > 8 { 5 } else { 1 };
                    assert!(
                        sealed >= least,
                        "{layout}, dictionary {dictionary}, step {step}: sealed {sealed}"
                    );
                }
            }
        }
    }

    /// THE SYNCHRONOUS PATH TAKES OVER AN OPEN SPAN. The member's last span
    /// is still open at the drain before the member completes, so the short
    /// ring form has copied its produced bytes into the queue's open
    /// buffer; the complete drain may not hand away, and must serve the
    /// span from the hold that buffer becomes, with the rest of its bytes
    /// taken from the ring. A span handed earlier makes the offload's
    /// presence visible, which the drain this replaced never reached.
    #[cfg(feature = "parallel")]
    #[test]
    fn the_synchronous_path_takes_over_an_open_span_at_the_member_end() {
        // The first drain is due at 1 MiB; every tail below starts before
        // it and ends at the member's end, so it is open there whatever the
        // run length, and the drain after it is the complete one.
        let total: usize = (1 << 20) + 200_000;
        for step in [4_000usize, 65_536, 300_001] {
            for tail in [0x3ffffusize, 0x3f000, 0x3_8000] {
                let spans = [(0u64, 0x3ffffusize), ((total - tail) as u64, tail)];
                let (want, _, _) = short_ring_case(2 << 20, false, &spans, total, step);
                let (got, sealed, counts) = short_ring_case(2 << 20, true, &spans, total, step);
                assert!(got == want, "step {step}, tail {tail}: the bytes differ");
                assert!(
                    sealed > 0,
                    "step {step}, tail {tail}: nothing was handed away"
                );
                assert!(
                    counts.spans_held >= 1,
                    "step {step}, tail {tail}: the last span was not served from the hold"
                );
            }
        }
    }

    /// A pool that never reaches a batch cannot stall the member: with the
    /// decode running on the ONLY thread of its pool, every batch it hands
    /// away is queued to a pool with no thread free, and the drain must run
    /// each one itself when it comes to put it.
    #[cfg(feature = "parallel")]
    #[test]
    fn a_batch_no_pool_thread_reaches_is_run_by_the_drain() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let seed = 0x0bad_f00du32;
        let (want, _, _) = offload_case(8 << 20, false, &seed.to_le_bytes(), false);
        let (got, sealed, stolen) =
            pool.install(|| offload_case(8 << 20, true, &seed.to_le_bytes(), false));
        assert!(got == want, "the bytes differ");
        assert!(sealed > 4, "the offload was not taken ({sealed})");
        assert_eq!(stolen, sealed, "every batch was the drain's own to run");
    }

    /// WHAT THE OFFLOAD KEEPS DOES NOT GROW WITH THE MEMBER (the
    /// read-filter-peak work, 1 Oct 2026). A 96 MiB member on a 2 MiB
    /// ring, laid the way that made the buffer-a-span offload grow: a MiB
    /// of small dense spans, so many are in flight at once, then a MiB
    /// that is one span and a long range no filter covers, which the short
    /// ring form copies out whole, and so on in turn. One buffer a span,
    /// each kept for reuse, held about a MiB more for every such pair; a
    /// sheet a drain holds a few batches whatever the member's length. The
    /// bytes are the synchronous drain's.
    #[cfg(feature = "parallel")]
    #[test]
    fn the_offload_keeps_a_few_batches_whatever_the_member_carries() {
        use super::super::output::Window;
        let dictionary = 2u64 << 20;
        let total: u64 = 96 << 20;
        let pair: u64 = 2 << 20;
        let run = |offload: bool| {
            let mut win = Window::new(dictionary, u64::MAX).unwrap();
            win.reset();
            win.begin_member();
            win.set_output(total);
            let mut filters = Filters::for_dictionary(dictionary);
            filters.offload = offload;
            let mut sink: Vec<u8> = Vec::new();
            let mut laid = 0u64;
            let mut rng = 0x0110_2026u32;
            let mut literals = vec![0u8; 4_000];
            let mut most = 0usize;
            while win.produced() < total {
                let produced = win.produced();
                // The records of a pair are read before its first byte.
                while laid < total && laid <= produced {
                    let mut lay = |start: u64, length: usize| {
                        filters
                            .push(Record {
                                span: Span { start, length },
                                kind: FilterKind::X86Call,
                            })
                            .unwrap();
                    };
                    for index in 0..256u64 {
                        lay(laid + index * 4_096, 2_048);
                    }
                    lay(laid + (1 << 20), 65_536);
                    laid += pair;
                }
                if win.drain_due() {
                    win.drain(&mut sink, &mut filters, false).unwrap();
                    most = most.max(filters.handed.kept());
                }
                for byte in literals.iter_mut() {
                    rng ^= rng << 13;
                    rng ^= rng >> 17;
                    rng ^= rng << 5;
                    *byte = if rng.is_multiple_of(61) {
                        0xE8
                    } else {
                        (rng >> 9) as u8
                    };
                }
                let room = ((total - produced) as usize).min(literals.len());
                win.literals(&literals[..room]);
            }
            win.drain(&mut sink, &mut filters, true).unwrap();
            assert_eq!(sink.len() as u64, total, "the member is its declared size");
            (sink, most, filters.handed.sealed_count)
        };
        let (want, _, sealed_off) = run(false);
        assert_eq!(sealed_off, 0, "the synchronous arm hands nothing away");
        let (got, most, sealed) = run(true);
        assert!(got == want, "the bytes differ");
        assert!(sealed > 80, "the offload was not taken ({sealed})");
        // Counted on this member: 4.3 MiB kept, which is four sheets (the
        // one being filled, the one being put and two spares) of about one
        // drain's batch each. A buffer a span kept 12 MB by 48 MiB of it
        // and went on growing.
        assert!(
            most <= 6 << 20,
            "the offload kept {most} bytes over a 96 MiB member"
        );
    }

    /// The generic plane walk and the carried row walk are one transform.
    #[test]
    fn the_two_delta_paths_agree() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 37 + i / 3) as u8).collect();
        for channels in 1..=4usize {
            let mut rows = vec![0u8; data.len()];
            delta_decode(channels, &data, &mut rows);
            let mut planes = vec![0u8; data.len()];
            let mut at = 0;
            for channel in 0..channels {
                let mut previous = 0u8;
                let mut index = channel;
                while index < planes.len() {
                    previous = previous.wrapping_sub(data[at]);
                    planes[index] = previous;
                    at += 1;
                    index += channels;
                }
            }
            assert_eq!(rows, planes, "{channels} channels");
        }
    }
}
