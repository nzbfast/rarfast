//! THE ONE-PASS REGION of the serial decode:
//! for a member decoded
//! on ONE thread, each symbol is decoded and applied to the ring at once,
//! with no tape, no far list and no second walk.
//!
//! Implemented from `specs/SPEC-H2-rarkit-rar5-lz.md` alone (sections 3.1,
//! 3.5, 3.7 and 3.8), after the research work's counted kernel
//! (the per-core text decode research of 30 Sep 2026): the tape's fast region reads a block's symbols with no bounds test
//! per read, and the tape's walk copies a match with the stride ladder; this
//! region does both in one loop, so the operation list the walk reads back
//! is never written.
//!
//! **What it takes and what it gives back.** [`region`] runs inside the
//! checked serial loop (`decode_block_body`) and decodes symbols while three
//! things hold: the reader is inside its fast region (`bits.rs`, "THE FAST
//! REGION"), so no symbol can pass the block's end; the write point is a
//! whole operation short of the ring's end ([`ROOM`]), so no operation laps
//! the ring; and the drain budget the checked loop handed it is not spent,
//! so the drain cadence is the checked loop's exactly. Anything else is
//! answered by the checked loop, one symbol at a time.
//!
//! **A SYMBOL IS APPLIED WHOLE OR NOT AT ALL.** The region reads a symbol's
//! every field before it touches the repeat state or the ring. A symbol it
//! does not take whole - a filter record, a code the lookup does not hold
//! and the walk answers as a hole, an empty table, an uninitialised repeat,
//! a distance slot of 30 extra bits or more, a distance past what section
//! 3.7 admits - puts the reader back at the symbol's FIRST bit and leaves
//! the region, and the checked loop decodes that symbol from there. So every
//! error is raised by the checked loop's own code at the exact symbol the
//! serial decoder raises it at, with the window and the repeat state as
//! that decoder leaves them (SPEC-H2 3.1 and 3.8, consequence 2), and a
//! distance past the declared end writes its zeros through
//! `Window::copy_match` as before.

use super::bits::BitReader;
use super::ladders::{
    fresh_match_length, DISTANCE_SLOT_BASE, LENGTH_SLOT_BASE, LENGTH_SLOT_EXTRA_BITS,
};
use super::output::{stride_copy, Window, MAX_APPEND, STRIDE, STRIDE_MAX};
use super::tables::Tables;
use super::tape::SideLookups;
use super::{
    lut_symbol, RepeatState, SYMBOL_FILTER, SYMBOL_MATCH_BASE, SYMBOL_REPEAT_BASE,
    SYMBOL_REPEAT_LAST,
};
use crate::carry::c_lz::codec::rar50::{
    lut_entry_is_literal, HUFF_LUT_DISTANCE_BITS_MASK, HUFF_LUT_DISTANCE_BITS_SHIFT,
    HUFF_LUT_DISTANCE_INVALID_BIT,
};

/// How far short of the ring's end the write point must be for the region
/// to take a symbol: the longest operation (a match of 4,100 bytes, section
/// 4.1) plus the stride ladder's widest write. Inside it no operation
/// reaches the ring's end, so the region never laps, and a stride copy's
/// spill stays inside the ring as `Window::copy_match` has it.
const ROOM: usize = MAX_APPEND + STRIDE_MAX;

/// The fewest extra bits a distance slot has for its distance to reach past
/// what the region reads in a `u32` (the tape region's `FAR_SLOT_BITS`):
/// such a slot, and an invalid one, is the checked loop's.
const FAR_SLOT_BITS: u32 = 30;

/// The most extra bits a distance slot may have for the one top up at the
/// head of [`fresh_match`] to hold its whole distance: 32 bits are left
/// after the length's extra bits and the distance code, the alignment code
/// may look at 15 of them, and the plain part is the count less four.
const ONE_FILL_BITS: u32 = 32 - 15 + 4;

/// The region's refill tests budget 9 bits for a length slot's extra bits
/// (`fresh_match`, `repeat_length`), which is section 3.5's largest: slot
/// 43 has 9. Held here at compile time, for all 44 slots, so the region
/// reads a slot's bits with no test at any symbol (section 1.3.1, R1).
const _: () = {
    let mut slot = 0;
    while slot < LENGTH_SLOT_EXTRA_BITS.len() {
        assert!(LENGTH_SLOT_EXTRA_BITS[slot] <= 9);
        slot += 1;
    }
};

/// Whether the one-pass decode is on: always, except with the
/// `h2-one-pass-knob` feature and `RARKIT_ONE_PASS=0`, read once a process
/// and said once on stderr so a timed run can show the knob reached the
/// binary.
#[inline(always)]
pub(super) fn on() -> bool {
    #[cfg(feature = "h2-one-pass-knob")]
    {
        static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ON.get_or_init(|| {
            let off = std::env::var_os("RARKIT_ONE_PASS").is_some_and(|v| v == "0");
            eprintln!("rarkit one pass: {}", if off { "off" } else { "on" });
            !off
        })
    }
    #[cfg(not(feature = "h2-one-pass-knob"))]
    {
        true
    }
}

/// Decode and apply symbols of the block `bits` reads, straight into the
/// window's ring, until the reader leaves its fast region, the write point
/// comes within [`ROOM`] of the ring's end, `fuel` bytes are written, or a
/// symbol needs the checked loop. Answers the bytes written; the window's
/// write point, the repeat state and the reader are left where the last
/// symbol applied put them (or, for a symbol handed back, at its first bit).
#[inline(always)]
pub(super) fn region<R: RepeatState>(
    tables: &Tables,
    bits: &mut BitReader<'_>,
    state: &mut R,
    window: &mut Window,
    fuel: usize,
) -> usize {
    let fast_end = bits.fast_end();
    let ring_len = window.ring.len();
    let start = window.at;
    if !on()
        || tables.main.is_empty()
        || bits.next_byte() >= fast_end
        || ring_len < ROOM
        || start >= ring_len - ROOM
    {
        return 0;
    }
    // THE BYTE BOUND, one compare a symbol: the drain budget and the ring's
    // end together. An operation that passes it is applied whole, as the
    // checked loop applies one past its budget.
    let stop = start.saturating_add(fuel).min(ring_len - ROOM);
    // Section 3.7 admits a distance from 1 to the least of the declared
    // window and the bytes the stream has produced. Past the ring's first
    // lap the stream has produced more than the ring holds, so only the
    // window bounds it; on the first lap the write point is the stream's
    // count. `reach` is all ones past the first lap and zero on it, so
    // `at | reach` is that bound in one instruction and one compare.
    let limit = window.limit;
    let reach = if window.lap_base != 0 { usize::MAX } else { 0 };
    let side = SideLookups::of(tables);
    let ring = &mut window.ring[..];
    // `at` is where the NEXT symbol writes. The last match decoded is held
    // back as `pending` (its source, its distance and its length, written
    // at `at - length`) until the next symbol is read, and its source was
    // hinted the moment its distance was known: see "THE COPY ONE SYMBOL
    // LATE" below.
    let mut at = start;
    let mut pending = Pending::NONE;
    let handed_back = loop {
        if bits.next_byte() >= fast_end || at >= stop {
            break None;
        }
        let entry = match tables.main.lookup_filled_in_region(bits) {
            Ok(entry) => entry,
            // Nothing of the symbol is consumed when its lookup fails.
            Err(_) => break Some(bits.position()),
        };
        if lut_entry_is_literal(entry) {
            pending.land(ring, at);
            ring[at] = lut_symbol(entry) as u8;
            at += 1;
            continue;
        }
        let first_bit = bits.position() - (entry & 0xff) as usize;
        let symbol = lut_symbol(entry);
        let (distance, length) = if symbol >= SYMBOL_MATCH_BASE {
            match fresh_match(tables, side, bits, symbol) {
                Some(read) => read,
                None => break Some(first_bit),
            }
        } else if symbol == SYMBOL_REPEAT_LAST {
            // With no match yet in the stream, nothing (section 3.5).
            let length = state.last_length();
            if length == 0 {
                continue;
            }
            (state.nearest(), length)
        } else if symbol == SYMBOL_FILTER {
            break Some(first_bit);
        } else {
            match repeat_length(tables, side, bits) {
                Some(length) => (state.repeat(symbol - SYMBOL_REPEAT_BASE), length),
                None => break Some(first_bit),
            }
        };
        // A zero distance is an uninitialised repeat; the rest is 3.7.
        if distance == 0 || distance > limit || distance > at | reach {
            break Some(first_bit);
        }
        // THE SYMBOL IS GOOD: its state first, then its bytes.
        if symbol >= SYMBOL_MATCH_BASE {
            state.fresh(distance, length);
        } else if symbol != SYMBOL_REPEAT_LAST {
            state.promote(symbol - SYMBOL_REPEAT_BASE, length);
        }
        // The source may be behind the ring's start, at `at + ring_len -
        // distance`; `distance <= limit <= ring_len - SPILL` puts such a
        // source at least a spill past the write point.
        let src = if distance <= at {
            at - distance
        } else {
            at + ring_len - distance
        };
        // THE COPY ONE SYMBOL LATE. The source's line is hinted now and the
        // copy made when the next symbol has been read, so the line's trip
        // from the cache below overlaps a symbol's decode rather than
        // stalling the copy that needs it: the research work's kernel was
        // 53 percent back-end stalled on exactly that, with no hint
        // (30 Sep 2026). The
        // match before this one lands first, so the copies still run in
        // stream order and each reads what the ones before it wrote.
        Window::prefetch_line(&ring[src]);
        pending.land(ring, at);
        pending = Pending {
            src,
            distance,
            length,
        };
        at += length;
    };
    pending.land(ring, at);
    window.at = at;
    if let Some(bit) = handed_back {
        // Back to the symbol's first bit.
        bits.seek_in_region(bit);
    }
    // THE CHECKED LOOP'S READER on every way out, as the tape region hands
    // it over: one ordinary refill, so the checked reads' own invariant
    // (on x86-64, 32 bits buffered wherever the block has them, where the
    // region keeps 16) holds again.
    bits.leave_fast_region();
    at - start
}

/// The match [`region`] holds back one symbol: its source's ring index,
/// its distance and its length, to be written at the write point less its
/// length. A length of zero holds nothing.
#[derive(Clone, Copy)]
struct Pending {
    src: usize,
    distance: usize,
    length: usize,
}

impl Pending {
    const NONE: Pending = Pending {
        src: 0,
        distance: 0,
        length: 0,
    };

    /// Write the held match, `at` being the write point just past it, and
    /// hold nothing. The stride ladder where it reaches (a match of at most
    /// [`STRIDE_MAX`] from at least a [`STRIDE`] back, its reach inside the
    /// ring), else [`copy_slow`], as `Window::copy_match` chooses.
    #[inline(always)]
    fn land(&mut self, ring: &mut [u8], at: usize) {
        let Pending {
            src,
            distance,
            length,
        } = *self;
        if length == 0 {
            return;
        }
        *self = Pending::NONE;
        let dst = at - length;
        if length <= STRIDE_MAX && distance >= STRIDE && src + STRIDE_MAX <= ring.len() {
            stride_copy(ring, dst, src, length);
        } else {
            copy_slow(ring, dst, distance, length);
        }
    }
}

/// A fresh match's fields after its main code, read by the tape region's
/// rules (`tape::fresh_match_in_region`): the length's extra bits, the
/// distance code, its extra bits and the alignment code, then the bonus.
/// `None` for a symbol the checked loop must decode: a failed lookup, an
/// invalid distance slot or one of [`FAR_SLOT_BITS`] or more.
#[inline(always)]
fn fresh_match(
    tables: &Tables,
    side: SideLookups<'_>,
    bits: &mut BitReader<'_>,
    symbol: usize,
) -> Option<(usize, usize)> {
    // ONE TOP UP FOR THE HEAD OF THE MATCH. A refill leaves at least 56
    // bits buffered. The length's extra bits (at most 9) and the distance
    // code (at most 15) spend 24 of them, which leaves 32: a distance of
    // up to [`ONE_FILL_BITS`] extra bits, 15 of them the alignment code's
    // reach, is read with no test between its fields.
    let slot = symbol - SYMBOL_MATCH_BASE;
    bits.ensure_in_region(56);
    let laddered =
        LENGTH_SLOT_BASE[slot] + bits.take_raw_in_region(u32::from(LENGTH_SLOT_EXTRA_BITS[slot]));
    let entry = tables
        .distance
        .lookup_raw_in_region(side.distance, bits)
        .ok()?;
    // The checked loop's: a slot section 3.5 does not read, and a slot
    // whose distance a `u32` may not hold. The mark of the first sits two
    // bits above the count, so one compare asks both.
    let count_or_mark = (entry >> HUFF_LUT_DISTANCE_BITS_SHIFT)
        & (HUFF_LUT_DISTANCE_BITS_MASK
            | (HUFF_LUT_DISTANCE_INVALID_BIT >> HUFF_LUT_DISTANCE_BITS_SHIFT));
    if count_or_mark >= FAR_SLOT_BITS {
        return None;
    }
    let count = count_or_mark;
    if count > ONE_FILL_BITS {
        // Up to 25 plain bits and the alignment code's 15.
        bits.ensure_in_region(40);
    }
    // Section 3.5: under four extra bits they are all read plain. With four
    // or more, the plain bits come first, four fewer than the count, and
    // the value's low four are one symbol of the alignment code after them.
    let extra = if count < 4 {
        bits.take_raw_in_region(count)
    } else {
        let above = bits.take_raw_in_region(count - 4);
        let low = tables.align.lookup_raw_in_region(side.align, bits).ok()?;
        super::ladders::extra_bits_value(above, lut_symbol(low))
    };
    bits.keep_watermark_in_region();
    // The table's entry is the slot's first distance less one.
    let distance = (DISTANCE_SLOT_BASE[lut_symbol(entry)] + extra) as usize + 1;
    Some((distance, fresh_match_length(laddered as usize, distance)))
}

/// A repeated distance's length (symbols 258 to 261), read by the tape
/// region's rules; `None` where the checked loop must decode it.
#[inline(always)]
fn repeat_length(
    tables: &Tables,
    side: SideLookups<'_>,
    bits: &mut BitReader<'_>,
) -> Option<usize> {
    // The length code (15 bits) and its extra bits (at most 9) on one test.
    bits.ensure_in_region(24);
    let entry = tables.length.lookup_raw_in_region(side.length, bits).ok()?;
    let slot = lut_symbol(entry);
    let extra = bits.take_raw_in_region(u32::from(LENGTH_SLOT_EXTRA_BITS[slot]));
    bits.keep_watermark_in_region();
    Some((LENGTH_SLOT_BASE[slot] + extra) as usize)
}

/// A match the stride ladder does not take: longer than [`STRIDE_MAX`],
/// nearer than [`STRIDE`], or with a source within a ladder of the ring's
/// end. `Window::copy_match_slow`'s runs, on a write that cannot reach the
/// ring's end ([`ROOM`]), so with no lap. Each run stops at the ring's end
/// and short of the write point, so an overlapping match reads what this
/// copy has already written: the byte at a time result (section 3.7).
#[cold]
#[inline(never)]
fn copy_slow(ring: &mut [u8], at: usize, distance: usize, length: usize) {
    let ring_len = ring.len();
    debug_assert!(at + length < ring_len);
    // DISTANCE ONE IS A FILL of the byte before the write point, which at
    // slot 0 is the ring's last (the region has refused it on a first lap).
    if distance == 1 {
        let byte = ring[if at == 0 { ring_len } else { at } - 1];
        ring[at..at + length].fill(byte);
        return;
    }
    let mut done = 0;
    while done < length {
        let pos = at + done;
        let src = if distance <= pos {
            pos - distance
        } else {
            pos + ring_len - distance
        };
        let run = (length - done).min(ring_len - src).min(pos.abs_diff(src));
        if src < pos {
            ring.copy_within(src..src + run, pos);
        } else {
            let (front, back) = ring.split_at_mut(src);
            front[pos..pos + run].copy_from_slice(&back[..run]);
        }
        done += run;
    }
}
