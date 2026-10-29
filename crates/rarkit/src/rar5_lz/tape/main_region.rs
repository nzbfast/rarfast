//! MAIN'S REGION CODE beside the fresh-match levers,
//! as it stood on main with the
//! park at the symbol's first bit (an earlier revision), renamed.
//!
//! - ALWAYS: the plain control decode ([`decode_control_in_region_main`] and
//!   its readers), which the literal batch's region (`batch::batched_region`,
//!   the control's own) reads. The levers are the SCALAR region's alone: inside the
//!   batch region, a loop almost wholly of literals on the media rows, the
//!   levers' cursor and lookups cost S8 1.5 to 2 percent of wall on x86-64
//!   inside one binary (the fresh match's cost measurement).
//! - ALWAYS: the control's scalar region ([`fast_region_main`]), which a block of
//!   few control symbols takes (`tape::LEVER_MASS_FLOOR`).
//! - With the `h2-fresh-match-knob` feature only (no shipped build, gate
//!   binary or `make ci` target): `RARKIT_FRESH_MATCH=0` sends EVERY block
//!   to the control's regions ([`use_main`]), for a timed run inside ONE
//!   binary.
#![cfg_attr(not(feature = "h2-fresh-match-knob"), allow(unused_imports))]

use super::super::bits::BitReader;
use super::super::filters::{self, RawRecord};
use super::super::ladders::fresh_match_length;
use super::super::tables::Tables;
use super::super::{
    lut_symbol, SYMBOL_FILTER, SYMBOL_MATCH_BASE, SYMBOL_REPEAT_BASE, SYMBOL_REPEAT_LAST,
};
use super::{cold_path, flush_run, push_after, tape_kind, BlockTape, Region, TapeOp};
use crate::carry::c_lz::codec::rar50::lut_entry_is_literal;
use crate::Result;

/// Whether this process walks the control's region: `RARKIT_FRESH_MATCH=0`, read
/// once a process and said once on stderr, so a timed run can show the knob
/// reached the binary.
#[cfg(feature = "h2-fresh-match-knob")]
pub(crate) fn use_main() -> bool {
    static MAIN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *MAIN.get_or_init(|| {
        let main = std::env::var_os("RARKIT_FRESH_MATCH").is_some_and(|v| v == "0");
        eprintln!(
            "rarkit fresh match: {}",
            if main { "main" } else { "levers" }
        );
        main
    })
}

#[inline(always)]
pub(super) fn fast_region_main(
    tables: &Tables,
    bits: &mut BitReader<'_>,
    tape: &mut BlockTape,
    literal_run: &mut usize,
) -> Region {
    let shortest = tables.main.shortest_literal() as usize;
    let fast_end = bits.fast_end();
    if shortest == 0 || bits.next_byte() >= fast_end {
        return Region::Tail;
    }
    // THE TAPE'S FIELDS APART, so the literal buffer's pointer and length
    // are locals of the loop and not re-read from the tape at every
    // literal; the operation list is pushed to as before.
    let BlockTape {
        steps: ops,
        verbatim: literals,
        records,
        parked_at,
        failure,
        ..
    } = tape;
    let base = literals.len();
    let room = bits.remaining() / shortest + 1;
    literals.resize(base + room, 0);
    // THE BUFFER AS A SLICE CURSOR: a fat pointer held in registers for
    // the loop, where a `&mut Vec` is memory the compiler re-read at every
    // literal (counted 29 Sep 2026: two loads a literal); and a literal
    // takes its head, so the loop carries the cursor's pointer and length
    // and nothing else per literal. Where it stands is `end - lits.len()`,
    // asked only at a control symbol.
    let end = base + room;
    let mut lits: &mut [u8] = &mut literals[base..end];
    let mut run_start = base - *literal_run;
    let fold = super::fold();
    let region = loop {
        if bits.next_byte() >= fast_end {
            break Region::Tail;
        }
        let entry = match tables.main.lookup_filled_in_region(bits) {
            Ok(entry) => entry,
            Err(err) => {
                let at = end - lits.len();
                literals.truncate(at);
                flush_run(ops, at - run_start);
                *literal_run = 0;
                *failure = Some(err);
                return Region::Stopped;
            }
        };
        if lut_entry_is_literal(entry) {
            let byte = lut_symbol(entry) as u8;
            match std::mem::take(&mut lits).split_first_mut() {
                Some((slot, rest)) => {
                    *slot = byte;
                    lits = rest;
                }
                None => {
                    // Unreachable by the bound. Right if reached: the
                    // region ends here with the literal pushed the slow
                    // way, and the checked loop takes the rest.
                    debug_assert!(false, "a literal past the region's bound");
                    literals.push(byte);
                    *literal_run = end + 1 - run_start;
                    bits.leave_fast_region();
                    return Region::Tail;
                }
            }
            continue;
        }
        let at = end - lits.len();
        let symbol = lut_symbol(entry);
        match decode_control_in_region_main(tables, bits, symbol, records) {
            Ok(Ok(op)) => {
                // The push reads the run's count alone, never the
                // buffer, so the bound stays in place.
                push_after(ops, fold, at - run_start, op);
                run_start = at;
            }
            Ok(Err(after_main)) => {
                // A distance the op's `u32` cannot hold: park at the
                // symbol's first bit, which is the bit after its main
                // code (`decode_control_in_region` names it) less that
                // code's length.
                literals.truncate(at);
                flush_run(ops, at - run_start);
                *literal_run = 0;
                *parked_at = Some(after_main - (entry & 0xff) as usize);
                return Region::Stopped;
            }
            Err(err) => {
                literals.truncate(at);
                flush_run(ops, at - run_start);
                *literal_run = 0;
                *failure = Some(err);
                return Region::Stopped;
            }
        }
    };
    let at = end - lits.len();
    literals.truncate(at);
    *literal_run = at - run_start;
    bits.leave_fast_region();
    region
}

#[inline(always)]
pub(super) fn decode_control_in_region_main(
    tables: &Tables,
    bits: &mut BitReader<'_>,
    symbol: usize,
    records: &mut Vec<RawRecord>,
) -> Result<std::result::Result<TapeOp, usize>> {
    match symbol {
        SYMBOL_FILTER => {
            bits.ensure_in_region(56);
            let mut spill = *bits;
            let record = filters::read_record(&mut spill);
            *bits = spill;
            let record = record?;
            records.push(record);
            Ok(Ok(TapeOp::new(tape_kind::FILTER, 0, 0)))
        }
        SYMBOL_REPEAT_LAST => Ok(Ok(TapeOp::new(tape_kind::REP_LAST, 0, 0))),
        258..=261 => {
            let slot = lut_symbol(tables.length.lookup_in_region(bits)?);
            let length = length_slot_in_region(bits, slot)?;
            let index = (symbol - SYMBOL_REPEAT_BASE) as u32;
            Ok(Ok(TapeOp::new(tape_kind::REP, length, index)))
        }
        _ => {
            let slot = symbol - SYMBOL_MATCH_BASE;
            let length = length_slot_in_region(bits, slot)?;
            match distance_in_region(tables, bits)? {
                Ok(distance) => {
                    let length = fresh_match_length(length, distance as usize);
                    Ok(Ok(TapeOp::new(tape_kind::MATCH, length, distance)))
                }
                // The distance code began this many bits after the main
                // code: the length slot's extra bits.
                Err(code_at) => {
                    Ok(Err(code_at
                        - usize::from(
                            super::super::ladders::LENGTH_SLOT_EXTRA_BITS[slot],
                        )))
                }
            }
        }
    }
}

#[inline(always)]
fn length_slot_in_region(bits: &mut BitReader<'_>, slot: usize) -> Result<usize> {
    let Some(extra_bits) = super::super::ladders::bits_after_slot(slot) else {
        return super::super::ladders::refuse_length_slot();
    };
    let extra = bits.take_small_in_region(u32::from(extra_bits));
    Ok(super::super::ladders::length_from_slot(slot, extra))
}

#[inline(always)]
fn distance_in_region(
    tables: &Tables,
    bits: &mut BitReader<'_>,
) -> Result<std::result::Result<u32, usize>> {
    use crate::carry::c_lz::codec::rar50::{
        HUFF_LUT_DISTANCE_BITS_MASK, HUFF_LUT_DISTANCE_BITS_SHIFT, HUFF_LUT_DISTANCE_INVALID_BIT,
    };
    // Where the distance code begins: what a park is counted back from.
    let code_at = bits.position();
    let entry = tables.distance.lookup_in_region(bits)?;
    if entry & HUFF_LUT_DISTANCE_INVALID_BIT != 0 {
        // A slot of 66 to 79: not refused (section 3.5). The block parks
        // at this match, and the serial reader, which reads such a slot,
        // takes it up from there.
        return Ok(Err(code_at));
    }
    let count = (entry >> HUFF_LUT_DISTANCE_BITS_SHIFT) & HUFF_LUT_DISTANCE_BITS_MASK;
    // Section 3.5: under four extra bits they are all read plain. With four
    // or more, the plain bits come first, four fewer than the count (at
    // most 27, topped up to hold them and the alignment code's 15), and
    // the value's low four are one symbol of the alignment code after them.
    let extra = if count < 4 {
        bits.take_small_in_region(count)
    } else {
        bits.ensure_in_region(42);
        let above = bits.take_wide_in_region(count - 4);
        let alignment = lut_symbol(tables.align.lookup_in_region(bits)?);
        super::super::ladders::extra_bits_value(above, alignment)
    };
    // A slot under `FAR_SLOT_BITS` names no distance past a `u32`, so its
    // distance is handed back with nothing asked of it: the count of
    // distances before the slot's run, from the table, the extra bits'
    // value and one more.
    if count < u32::from(FAR_SLOT_BITS) {
        let before = super::super::ladders::DISTANCE_SLOT_BASE[lut_symbol(entry)];
        return Ok(Ok(before + extra + 1));
    }
    let distance = super::super::ladders::distance_named(lut_symbol(entry), extra);
    // A distance the operation's `u32` cannot hold parks the block.
    Ok(u32::try_from(distance).map_err(|_| code_at))
}

/// The control's `FAR_SLOT_BITS`: the fewest extra bits a distance slot has for its
/// distance to reach past `u32::MAX`.
const FAR_SLOT_BITS: u8 = 30;
