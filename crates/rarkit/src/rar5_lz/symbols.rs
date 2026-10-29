//! THE 32-BIT SYMBOL PASS: the tape path's operation walk moved onto the
//! decode lanes, for SMALL dictionaries (named and priced in the
//! parallel rows' measurement).
//!
//! **Why.** On `rar5_text_64m_m5_md128k` the member's wall is ONE thread,
//! the apply stage, walking 12.3 million operations of about five bytes
//! each out of a 128 KiB dictionary that lives in cache: nothing misses,
//! and the cost is the walk itself plus a store per operation (measured in
//! step 2 of that work: the walk alone 42 percent of the stage, the two
//! stores the rest). The lanes that decode the blocks sit idle beside it.
//!
//! **What.** A lane that has decoded a block walks the block's operations
//! ITSELF into one 32-bit symbol per output byte: a literal byte, tagged
//! with [`Window::SYMBOL_LITERAL`], or the NAME of a byte from before the
//! gathered part, as how far back of the part's first byte it sits. SPEC-H2
//! 3.7's byte at a time rule makes every output byte a literal or a copy of
//! one earlier byte, so a copy inside the block copies SYMBOLS (a copy of a
//! literal is a literal, a copy of a name is the same name) and a copy
//! reaching before the part writes fresh names. The apply thread then turns
//! the part into bytes by a gather ([`Window::put_symbols`]): one symbol and
//! at most one ring byte per output byte, no operation walk and no
//! dependency between bytes.
//!
//! **The part a lane cannot do, and who does it.** At a block's start the
//! four repeated distances and the last length are the apply stage's, not
//! the lane's. So a block splits at the first operation after which every
//! repeat names a slot the block itself set: the PREFIX before it is a
//! small tape of its own, walked by the shipped [`super::tape::apply`], and
//! only the SUFFIX is gathered. A filter record anywhere puts everything up
//! to it in the prefix too, so the gathered part never carries one.
//!
//! **What it refuses, so no byte and no error can move.** A zero distance or one past the declared window (the lane checks);
//! a suffix whose farthest reach before its start is more than the stream
//! has produced, or which would carry the member past its declared size, or
//! whose length plus that reach could let the ring lap a source before the
//! gather reads it, or which holds a literal run longer than the drain batch
//! (the apply stage checks, before it has done anything). Each of those is
//! the WHOLE block walked by the shipped path, which raises exactly where it
//! always raised. The gathered part is cut at exactly the operation ends the
//! walk drains after, so the sink sees the same bytes in the same pieces.
//!
//! **ON, on its measured wall.** [`SHIPPED`] is true since the timed measurement of
//! 23 Sep 2026 on an Apple M3 Mac (the md128k symbol
//! pass measurement): `rar5_text_64m_m5_md128k` 0.86x FAIL on the control's own binary
//! at both ends to 1.414x WON with the pass, rarkit's own wall 51.5 ms to
//! 31.1 ms, nothing else fallen. With `test-support` the knob
//! `RARKIT_SYMBOL_PASS` (read once a process, `0` off) or a test's own dial
//! ([`set_dial`]) overrides it. Implemented from
//! `specs/SPEC-H2-rarkit-rar5-lz.md` and this repository's own measurements
//! alone.

use super::filters::Filters;
use super::output::{LzSink, Window, STRIDE, STRIDE_MAX};
use super::tape::{self, tape_kind, BlockTape};
use super::MatchState;
use crate::carry::c_lz::codec::rar50::TapeApplied;
use crate::Result;

// THE LEAN LANE BUILD lives in a module of its own: its code in this file moved
// how the shipped walk and the serial loop compiled with its knob off.
mod lean;
pub(crate) use lean::lean_form;
#[cfg(feature = "test-support")]
#[allow(unused_imports)]
pub(crate) use lean::set_form_dial;

/// Whether the pass runs when no harness has said otherwise.
pub(crate) const SHIPPED: bool = true;

/// A gathered part shorter than this is left to the walk: the split and the
/// hand-over cost something per block, and a short part saves little.
const MIN_GATHER: usize = 1024;

/// The longest block the lane symbolises, in output bytes: four bytes of
/// symbol a byte, so a lane holds at most 16 MiB of symbols per block in
/// flight (two blocks a lane). Past it the block is walked.
const MAX_GATHER: usize = 4 << 20;

#[cfg(feature = "test-support")]
thread_local! {
    /// A test's own dial, on the thread that calls the decoder.
    static DIAL: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Force the pass on or off for this thread's next decodes, or defer to the
/// environment and then [`SHIPPED`] with `None`. The lanes do not read it:
/// the decoder reads it once per chunk on the calling thread and hands the
/// answer down.
#[cfg(feature = "test-support")]
#[allow(dead_code)]
pub(crate) fn set_dial(on: Option<bool>) {
    let _ = DIAL.try_with(|c| c.set(on));
}

#[cfg(test)]
thread_local! {
    /// Blocks this thread gathered, so a test can show the pass RAN.
    pub(crate) static GATHERED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Whether the pass is on for this thread's decode.
pub(crate) fn enabled() -> bool {
    #[cfg(feature = "test-support")]
    {
        if let Some(on) = DIAL.try_with(std::cell::Cell::get).unwrap_or(None) {
            return on;
        }
        static FROM_ENV: std::sync::OnceLock<Option<bool>> = std::sync::OnceLock::new();
        FROM_ENV
            .get_or_init(|| {
                let v = std::env::var("RARKIT_SYMBOL_PASS").ok()?;
                let on = v.trim() != "0" && !v.trim().is_empty();
                eprintln!("rarkit symbol pass: {}", if on { "on" } else { "off" });
                Some(on)
            })
            .unwrap_or(SHIPPED)
    }
    #[cfg(not(feature = "test-support"))]
    SHIPPED
}

/// Whether a stream with this declared dictionary and ring may use the
/// pass at all: only where the ring is at least twice the dictionary, which
/// with the 1 MiB ring floor is every dictionary up to 512 KiB. On a larger
/// dictionary the names reach megabytes back and each is a miss, which the
/// walk (and the far-copy prefetch) already handles better.
pub(crate) fn fits(declared: usize, ring_len: usize) -> bool {
    declared.saturating_mul(2) <= ring_len
}

/// A repeat slot, or the last length, after the split: a value the lane
/// knows, or slot `j` of the live state at the split (`AT_SPLIT | j`).
type Slot = usize;
const AT_SPLIT: usize = 1 << (usize::BITS - 1);

/// What a lane made of one block.
#[derive(Default)]
pub(crate) struct Symbols {
    /// Whether the rest of this is a gatherable block at all.
    ready: bool,
    /// The operations before the split, as a tape the shipped walk takes.
    prefix: BlockTape,
    /// Bytes the prefix produces that the lane knows, and how many of its
    /// operations take the last length from before the block (their
    /// length is the live state's `last_length`).
    prefix_known: usize,
    prefix_carried: usize,
    /// One per output byte of the suffix, in `symbols[..len]`.
    symbols: Vec<u32>,
    len: usize,
    /// The suffix offset at each suffix operation's end.
    ends: Vec<u32>,
    /// The farthest a suffix copy reaches before the suffix's first byte.
    reach: usize,
    /// The suffix's longest literal run.
    longest_literal: usize,
    /// The state after the block, in terms of the state at the split.
    slots: [Slot; 4],
    last: Slot,
}

impl Symbols {
    /// Build the symbols of `tape`, a block a lane just decoded, for a
    /// window of `declared` bytes (the lane's own checks); `ready` says
    /// whether it came to anything.
    ///
    /// ONE PASS, RESTARTED. The walk starts with the split at the block's
    /// start and every repeat slot and the last length unknown (the live
    /// state's at the split). An operation that reads an unknown, or a
    /// filter record, moves the split past itself and starts the symbols
    /// again from there, with what the block has set so far now KNOWN and
    /// what it has not set the live state's at the new split. Those
    /// operations sit at a block's front, so the restart costs a few
    /// operations and saves a second walk over every block.
    pub(crate) fn build(&mut self, tape: &BlockTape, declared: usize) {
        self.ready = false;
        self.len = 0;
        self.ends.clear();
        let ops = &tape.steps[..];
        if ops.is_empty() {
            return;
        }
        let mut buf = std::mem::take(&mut self.symbols);
        let mut split = 0usize;
        let mut slots: [Slot; 4] = [AT_SPLIT, AT_SPLIT | 1, AT_SPLIT | 2, AT_SPLIT | 3];
        let mut last_slot: Slot = AT_SPLIT;
        let mut literals = 0usize;
        let mut reach = 0usize;
        let mut longest = 0usize;
        let mut p = 0usize;
        let mut refused = false;
        for (i, op) in ops.iter().enumerate() {
            let length = op.length();
            let prefix = op.prefix();
            if buf.len() < p + prefix + length + STRIDE {
                if p + prefix + length > MAX_GATHER {
                    refused = true;
                    break;
                }
                buf.resize((p + prefix + length + STRIDE).max(2 * buf.len()), 0);
            }
            // THE PREFIX (the literal run before the operation, the whole
            // of a `LITS`), in whole strides of 16 as the copies below: the
            // tape's literal buffer is padded past its last run
            // (`decode_block_tape`), so a stride reads only the tape's own
            // bytes, and what it writes past the run the operation after
            // it overwrites.
            let from = literals;
            literals += prefix;
            longest = longest.max(prefix);
            let mut k = 0usize;
            while k < prefix {
                let lits: &[u8; STRIDE] = tape.verbatim[from + k..from + k + STRIDE]
                    .try_into()
                    .expect("a stride of literals");
                let out: &mut [u32; STRIDE] = (&mut buf[p + k..p + k + STRIDE])
                    .try_into()
                    .expect("a stride of symbols");
                for (slot, &byte) in out.iter_mut().zip(lits) {
                    *slot = Window::SYMBOL_LITERAL | u32::from(byte);
                }
                k += STRIDE;
            }
            p += prefix;
            let (distance, length) = match op.kind() {
                tape_kind::LITS => {
                    self.ends.push(p as u32);
                    continue;
                }
                tape_kind::MATCH => {
                    let distance = op.distance as usize;
                    slots = [distance, slots[0], slots[1], slots[2]];
                    last_slot = length;
                    (distance, length)
                }
                tape_kind::REP => {
                    let k = op.distance as usize & 3;
                    let chosen = slots[k];
                    let mut moved = slots;
                    moved[0] = chosen;
                    moved[1..=k].copy_from_slice(&slots[..k]);
                    slots = moved;
                    last_slot = length;
                    if chosen & AT_SPLIT != 0 {
                        restart(&mut split, i, &mut slots, &mut last_slot, &mut p);
                        self.ends.clear();
                        reach = 0;
                        longest = 0;
                        continue;
                    }
                    (chosen, length)
                }
                tape_kind::REP_LAST => {
                    if last_slot & AT_SPLIT != 0 || slots[0] & AT_SPLIT != 0 {
                        restart(&mut split, i, &mut slots, &mut last_slot, &mut p);
                        self.ends.clear();
                        reach = 0;
                        longest = 0;
                        continue;
                    }
                    let length = last_slot;
                    if length == 0 {
                        self.ends.push(p as u32);
                        continue;
                    }
                    if buf.len() < p + length + STRIDE {
                        buf.resize((p + length + STRIDE).max(2 * buf.len()), 0);
                    }
                    (slots[0], length)
                }
                _ => {
                    restart(&mut split, i, &mut slots, &mut last_slot, &mut p);
                    self.ends.clear();
                    reach = 0;
                    longest = 0;
                    continue;
                }
            };
            // The walk raises on these; so the whole block goes to it.
            if distance == 0 || distance > declared || distance >= AT_SPLIT {
                refused = true;
                break;
            }
            p = copy(&mut buf, p, distance, length, &mut reach);
            self.ends.push(p as u32);
        }
        self.symbols = buf;
        if refused || split >= ops.len() || p < MIN_GATHER {
            return;
        }

        // THE PREFIX, as a tape of its own for the shipped walk: its
        // operations, its literals (padded as `decode_block_tape` pads, for
        // `Window::literals_padded`), every filter record of the block
        // (they all sit in it), and what it produces that the lane knows.
        let mut prefix_literals = 0usize;
        let mut prefix_known = 0usize;
        let mut prefix_carried = 0usize;
        let mut last_p: Option<usize> = None;
        for op in &ops[..split] {
            let length = op.length();
            prefix_literals += op.prefix();
            prefix_known += op.prefix();
            match op.kind() {
                tape_kind::LITS => {}
                tape_kind::MATCH | tape_kind::REP => {
                    prefix_known += length;
                    last_p = Some(length);
                }
                tape_kind::REP_LAST => match last_p {
                    Some(l) => prefix_known += l,
                    None => prefix_carried += 1,
                },
                _ => {}
            }
        }
        let prefix = &mut self.prefix;
        prefix.steps.clear();
        prefix.steps.extend_from_slice(&ops[..split]);
        prefix.verbatim.clear();
        prefix
            .verbatim
            .extend_from_slice(&tape.verbatim[..prefix_literals]);
        prefix.verbatim.resize(prefix_literals + STRIDE_MAX, 0);
        prefix.records.clear();
        prefix.records.extend_from_slice(&tape.records);
        prefix.parked_at = None;
        prefix.failure = None;
        self.prefix_known = prefix_known;
        self.prefix_carried = prefix_carried;
        self.len = p;
        self.reach = reach;
        self.longest_literal = longest;
        self.slots = slots;
        self.last = last_slot;
        self.ready = true;
    }
}

/// For the lane form differential: every field a later apply reads, so
/// the two forms can be compared field for field.
#[cfg(test)]
impl Symbols {
    #[allow(clippy::type_complexity)]
    pub(crate) fn fields(
        &self,
    ) -> Option<(
        Vec<u32>,
        Vec<u32>,
        usize,
        usize,
        [Slot; 4],
        Slot,
        usize,
        usize,
        usize,
        Vec<u64>,
        Vec<u8>,
        usize,
    )> {
        if !self.ready {
            return None;
        }
        Some((
            self.symbols[..self.len].to_vec(),
            self.ends.clone(),
            self.reach,
            self.longest_literal,
            self.slots,
            self.last,
            self.prefix_known,
            self.prefix_carried,
            self.prefix.steps.len(),
            self.prefix
                .steps
                .iter()
                .map(|o| {
                    (u64::from(o.kind()) << 40)
                        | ((o.length() as u64) << 32)
                        | u64::from(o.distance)
                })
                .collect(),
            self.prefix.verbatim.clone(),
            self.prefix.records.len(),
        ))
    }
}

#[cfg(feature = "h2-stage-probe")]
impl Symbols {
    /// For the lane split probe only: whether the block came to anything,
    /// its gathered length, its prefix's operations and the symbol buffer's
    /// capacity in symbols.
    pub(crate) fn probe_shape(&self) -> (bool, usize, usize, usize) {
        (
            self.ready,
            self.len,
            self.prefix.steps.len(),
            self.symbols.capacity(),
        )
    }
}

/// For the lane split probe only: the SHAPE of a block's operations as the
/// build walks them, from the block's start (the prefix is a few
/// operations a member): literal runs and their bytes; copies whose every
/// byte is a name, none is, or some are; copies taking the common two
/// stride form, and of those how many are at most 4 and at most 8 long;
/// the rest. Counts only; the build is not run.
#[cfg(feature = "h2-stage-probe")]
pub(crate) fn probe_census(tape: &BlockTape, out: &mut [u64; 10]) {
    let mut p = 0usize;
    let mut last = 0usize;
    let mut rep = [0usize; 4];
    for op in &tape.steps {
        if op.prefix() != 0 {
            out[0] += 1;
            out[1] += op.prefix() as u64;
            p += op.prefix();
        }
        let (distance, length) = match op.kind() {
            tape_kind::LITS => continue,
            tape_kind::MATCH => {
                let d = op.distance as usize;
                rep = [d, rep[0], rep[1], rep[2]];
                last = op.length();
                (d, op.length())
            }
            tape_kind::REP => {
                let k = op.distance as usize & 3;
                let d = rep[k];
                let mut moved = rep;
                moved[0] = d;
                moved[1..=k].copy_from_slice(&rep[..k]);
                rep = moved;
                last = op.length();
                (d, op.length())
            }
            tape_kind::REP_LAST => (rep[0], last),
            _ => continue,
        };
        let back = distance.saturating_sub(p);
        let holes = length.min(back);
        out[2 + usize::from(holes > 0) + usize::from(holes > 0 && holes < length)] += 1;
        if length <= 16 && distance >= 16 {
            out[5] += 1;
            out[6] += u64::from(length <= 4);
            out[7] += u64::from(length <= 8);
        } else {
            out[8] += 1;
        }
        out[9] += length as u64;
        p += length;
    }
}

/// Move the split past operation `i`: what the block has set so far is now
/// KNOWN, and a slot (or the last length) it has not set is the live
/// state's at the new split, in its own position. The symbols start again.
#[inline(never)]
fn restart(split: &mut usize, i: usize, slots: &mut [Slot; 4], last: &mut Slot, p: &mut usize) {
    *split = i + 1;
    for (position, slot) in slots.iter_mut().enumerate() {
        if *slot & AT_SPLIT != 0 {
            *slot = AT_SPLIT | position;
        }
    }
    if *last & AT_SPLIT != 0 {
        *last = AT_SPLIT;
    }
    *p = 0;
}

/// Write `length` symbols at `p`, copied from `distance` back, one byte at
/// a time as SPEC-H2 3.7 defines it: a source before the suffix is a name,
/// a source inside it is the source's own symbol. Answers the new end.
///
/// THE SHAPE OF THE RING'S OWN STRIDE COPY (`output::stride_copy`), and for
/// the same reason: most copies are a few symbols long, and a copy of a
/// variable length lowers to a `memmove` call that costs more than the
/// copy. The COMMON copy, at most a stride long and at least a stride back,
/// is two fixed-width moves and no data-dependent branch: a stride of names
/// counting down from its first byte, then a stride copied from `distance`
/// back to where the names stop being names. Each stride writes past what
/// it owns onto symbols not yet written, which later writes overwrite, and
/// the buffer carries a stride of slack for the last one.
#[inline]
fn copy(buf: &mut [u32], p: usize, distance: usize, length: usize, reach: &mut usize) -> usize {
    const STRIDE_SYMBOLS: usize = 16;
    let end = p + length;
    // The bytes whose source lies before the suffix: names, counting down.
    let back = distance.saturating_sub(p);
    let holes = length.min(back);
    *reach = (*reach).max(back);
    if length <= STRIDE_SYMBOLS && distance >= STRIDE_SYMBOLS {
        let first = back as u32;
        let names: &mut [u32; STRIDE_SYMBOLS] = (&mut buf[p..p + STRIDE_SYMBOLS])
            .try_into()
            .expect("a stride of symbols");
        for (j, slot) in names.iter_mut().enumerate() {
            *slot = first.wrapping_sub(j as u32);
        }
        // Where the names stop, the rest reads the suffix; when every byte
        // was a name this reads a stride at the part's front and writes it
        // past the copy's end, which the next operation overwrites.
        let q = p + holes;
        let src = q.saturating_sub(distance);
        buf.copy_within(src..src + STRIDE_SYMBOLS, q);
        return end;
    }
    if holes > 0 {
        // Whole strides of names counting down, spilling as the copies do.
        let first = back as u32;
        let mut k = 0usize;
        while k < holes {
            let out: &mut [u32; STRIDE_SYMBOLS] = (&mut buf[p + k..p + k + STRIDE_SYMBOLS])
                .try_into()
                .expect("a stride of symbols");
            for (j, slot) in out.iter_mut().enumerate() {
                *slot = first.wrapping_sub((k + j) as u32);
            }
            k += STRIDE_SYMBOLS;
        }
    }
    let mut q = p + holes;
    if q >= end {
        return end;
    }
    if distance >= STRIDE_SYMBOLS && end - q <= 4 * STRIDE_SYMBOLS {
        let mut src = q - distance;
        while q < end {
            buf.copy_within(src..src + STRIDE_SYMBOLS, q);
            q += STRIDE_SYMBOLS;
            src += STRIDE_SYMBOLS;
        }
        return end;
    }
    // A long copy, or a near one: whole periods of `distance` at a time,
    // each reading only symbols already written.
    while q < end {
        let take = (end - q).min(distance);
        buf.copy_within(q - distance..q - distance + take, q);
        q += take;
    }
    end
}

/// Apply a block its lane symbolised: the prefix by the shipped walk, the
/// suffix by the gather. `None` means the live window refused it and the
/// caller must walk the whole tape, which is always correct: nothing has
/// been applied when this answers `None`.
#[inline(never)]
pub(crate) fn apply<S: LzSink>(
    symbols: &Symbols,
    state: &mut MatchState,
    window: &mut Window,
    filters: &mut Filters,
    unpacked: u64,
    sink: &mut S,
) -> Result<Option<TapeApplied>> {
    if !symbols.ready {
        return Ok(None);
    }
    let part = &symbols.symbols[..symbols.len];
    let len = part.len();
    // Every refusal is decided here, before a byte moves.
    let prefix_bytes =
        symbols.prefix_known as u64 + symbols.prefix_carried as u64 * state.last_length as u64;
    if symbols.reach as u64 > window.stream_produced()
        || window.produced() + prefix_bytes + len as u64 > unpacked
        || len + symbols.reach > window.ring_bytes()
        || symbols.longest_literal > window.drain_batch()
    {
        return Ok(None);
    }
    // A block that would cross the member's declared size was refused
    // above, and the walk, which applies the surplus past it (SPEC-H2
    // 3.1), takes it whole.
    if !symbols.prefix.steps.is_empty() {
        tape::apply(&symbols.prefix, state, window, filters, unpacked, sink)?;
    }
    let at_split = *state;
    #[cfg(test)]
    GATHERED.with(|g| g.set(g.get() + 1));
    // The gather, cut where the walk drains: after the first operation that
    // ends at or past the drain point, before the next one.
    let ends = &symbols.ends[..];
    let mut p = 0usize;
    while p < len {
        if window.drain_due() {
            window.drain(sink, filters, false)?;
        }
        let target = p + window.apply_budget();
        let end = if target >= len {
            len
        } else {
            // The first operation end at or past the drain point; the last
            // end is `len`, past `target`, so there is always one.
            ends[ends.partition_point(|&end| (end as usize) < target)] as usize
        };
        window.put_symbols(&part[p..end], p, symbols.reach);
        p = end;
    }
    let resolve = |slot: Slot, live: &[usize; 4]| {
        if slot & AT_SPLIT != 0 {
            live[slot & !AT_SPLIT]
        } else {
            slot
        }
    };
    state.repeats = [
        resolve(symbols.slots[0], &at_split.repeats),
        resolve(symbols.slots[1], &at_split.repeats),
        resolve(symbols.slots[2], &at_split.repeats),
        resolve(symbols.slots[3], &at_split.repeats),
    ];
    state.last_length = if symbols.last & AT_SPLIT != 0 {
        at_split.last_length
    } else {
        symbols.last
    };
    Ok(Some(TapeApplied::BlockDone))
}
