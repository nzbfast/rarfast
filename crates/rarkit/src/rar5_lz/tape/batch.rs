//! THE LITERAL BATCH, out of the scalar decode's way (v7 of the literal
//! batch work, 26 Sep 2026).
//!
//! A member of compressed media is almost all length-8 literals, and the
//! tape decoder takes them one lookup at a time. This module takes them
//! [`BATCH_WIDTH`] at a time from one 64-bit window, for a table set whose
//! main table codes at least [`BATCH_GATE`] literals in 8 bits, and gives
//! exactly the tape the scalar loop gives (`decode_block_tape_batched`).
//!
//! **Why it is a module of its own, and why it calls nothing the scalar
//! path inlines.** Every earlier form put the choice inside
//! [`super::decode_one`]'s inlined tree (a field on the table set and a
//! branch in `decode_block_tape`, V5), and `decode_one` was re-allocated by
//! the compiler around it: 3378 to 3447 instructions on aarch64 at equal
//! counts, which one timed machine (an Apple M3 Mac) paid 1.5 to 2 percent of wall
//! on the parallel text rows and the other (an Apple M1 Mac) did not
//! (the literal batch reshaped, a priced decline). So
//! here the scalar path is the control's, byte for byte: `decode_one`,
//! `decode_block_tape`, `LazyDecodeTables::get`, `decode_control` and
//! `flush_literals` are not called from this module at all, because a
//! second caller of a private function the compiler had inlined for its
//! ONE caller is what un-inlines it (the `seek` finding of the same work,
//! `bits.rs`). What this module needs of them it carries as a COPY, on
//! purpose, each marked as one. The dispatch is [`decode_one`] here, out
//! of line, chosen by [`super::decode_one_dispatch`] at compile time on
//! aarch64 and x86-64 (x86-64 since 27 Sep 2026, where it was
//! held on a function-aligned build); it
//! asks the gate itself, with the set in hand, and hands a
//! set the gate refuses to the control's `decode_one` untouched.
//!
//! On any other target the shim never calls in here, so every item is dead
//! there by design and compiled and tested all the same; the
//! allow below says so once, for the module, on those targets alone.
#![cfg_attr(
    not(any(target_arch = "aarch64", target_arch = "x86_64")),
    allow(dead_code)
)]

use std::sync::Arc;

use super::super::bits::BitReader;
use super::super::block::Located;
use super::super::fault;
use super::super::filters;
use super::super::ladders::fresh_match_length;
use super::super::tables::Tables;
use super::super::{
    lut_symbol, read_distance, read_length, read_length_slot, SYMBOL_FILTER, SYMBOL_MATCH_BASE,
    SYMBOL_REPEAT_BASE, SYMBOL_REPEAT_LAST,
};
use super::{
    flush_run, push_after, tape_kind, BlockTape, LazyDecodeTables, Plan, Region, TapeOp, FAR_LIST,
    LIST_KNOB, OWN_SETS_MOST, OWN_TABLES,
};
use crate::carry::c_lz::codec::rar50::{
    lut_entry_is_literal, HUFF_LUT_LITERAL_BIT, TAPE_LITS_CAP, TAPE_OPS_CAP,
};
use crate::Result;

/// THE LANE CENSUS (feature `lane-census`): what the batched region's
/// loop did, turn by turn, summed over a process. A lab instrument, a
/// feature of its own under the measured-arm rule: no shipped build and no
/// gate binary turns it on, and a figure of time from a build with it
/// means nothing. A region counts into its own [`census::Tally`] and adds
/// it to the shared counters once, as it ends.
#[cfg(feature = "lane-census")]
pub(crate) mod census {
    use std::sync::atomic::{AtomicU64, Ordering};

    pub(crate) const NAMES: [&str; 17] = [
        "regions-gap",
        "regions-other",
        "bulk-whole",
        "bulk-cut",
        "bulk-none",
        "bulk-codes",
        "lanes-gap-none",
        "lanes-gap-some",
        "lanes-gap-codes",
        "lanes-other-none",
        "lanes-other-some",
        "lanes-other-codes",
        "scalar-literals",
        "scalar-controls",
        "lanes-gap-full",
        "lanes-other-full",
        "lanes-none-after-part",
    ];
    static TOTAL: [AtomicU64; 17] = [const { AtomicU64::new(0) }; 17];

    /// One region's counts, in [`NAMES`]' order.
    #[derive(Default)]
    pub(crate) struct Tally(pub(crate) [u64; 17]);

    impl Drop for Tally {
        fn drop(&mut self) {
            for (total, count) in TOTAL.iter().zip(self.0) {
                total.fetch_add(count, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn read() -> Vec<(&'static str, u64)> {
        NAMES
            .iter()
            .zip(&TOTAL)
            .map(|(name, total)| (*name, total.load(Ordering::Relaxed)))
            .collect()
    }
}

/// THE LITERAL BATCH'S WIDTH: how many length-8 literals one batch takes
/// from one 64-bit window. Seven, because a refilled reader holds at least
/// 56 bits and the seventh code's ninth index bit is a don't-care (a
/// length-8 code's entry spans both halves).
pub(crate) const BATCH_WIDTH: usize = 7;

/// THE LITERAL BATCH'S GATE: the length-8 literals a main table must code
/// before its blocks are decoded batched. Below it most literals are other
/// lengths and a batch mostly refuses.
///
/// **240 on x86-64, 192 elsewhere.** At 192 the x86 batch lost 3 to 5
/// percent of wall on REAL rar-made `-m3` media sets (A12, A8, S8 on
/// a Zen 4 rental, 29 Sep 2026), whose tables it admitted with fewer instructions
/// and more cycles, while it won on rarkit-made media sets and flat synthetic
/// media. From 224 to 248 every media set read level or faster than main and
/// the wins held (rarkit-made A12 -17 percent, S4 -28, synthetic -16); 256
/// admits almost nothing. 240 sits in the middle of that plateau. aarch64
/// was held at 192 and keeps it.
#[cfg(target_arch = "x86_64")]
pub(crate) const BATCH_GATE: usize = 240;
/// See the x86-64 form above.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) const BATCH_GATE: usize = 192;

/// Whether a table set's blocks take the literal batch. Asked once per
/// BLOCK by [`decode_one`], with the set in hand: a binary search over the
/// main table's length-8 codes, a few dozen instructions against a block
/// of thousands of symbols, and nothing carried on the set or the plan
/// (a field on either re-allocated `decode_one`; see the module note).
#[inline]
pub(crate) fn admits(tables: &Tables) -> bool {
    tables.main.literals_of_length(8) >= BATCH_GATE
}

/// [`super::decode_one`] with the literal batch: the same answer, the
/// same tape, for block `index`. A set the gate admits is decoded here by
/// [`decode_block_tape_batched`]; any other set, and any failed build, is
/// handed to the control's `decode_one` exactly as its callers would have called
/// it (that one re-asks the group's cell, a lock and a clone, per block).
/// **Out of line on purpose**, so no caller's text carries the batch.
#[inline(never)]
pub(crate) fn decode_one(
    plan: &Plan,
    packed: &[u8],
    algorithm: u8,
    carried: Option<&Arc<Tables>>,
    index: usize,
    tape: &mut BlockTape,
) -> Option<Arc<Tables>> {
    let group = &plan.groups[plan.group_of[index]];
    if let Ok((tables, start)) = tables_of_group(group, &plan.blocks, packed, algorithm, carried) {
        if admits(&tables) {
            // Counts how wide the decode ran, as `super::decode_one` does
            // for the sets it takes: a batched block is a decoding unit
            // too, and without this a member whose tables all pass the
            // gate read as no parallel decode at all (found 30 Sep 2026
            // when level 3's lazy parse left `breadth_width`'s
            // fixture literal-heavy enough to batch every block). Compiled
            // out entirely without `h2-probes`; see `crate::probe`.
            #[cfg(feature = "h2-probes")]
            let _worker = crate::probe::WorkerGuard::enter();
            let from = if group.first == Some(index) { start } else { 0 };
            tape.far_off = plan.far_off;
            decode_block_tape_batched(&tables, packed, &plan.blocks[index], from, tape);
            return Some(tables);
        }
    }
    super::decode_one(plan, packed, algorithm, carried, index, tape)
}

/// `build_own` of the module above, a COPY of its body and not a call, on
/// purpose (the module note): the control's `get` is its caller. The set
/// is built into one THIS THREAD holds and nothing else uses any more, and
/// its lengths are read into the thread's scratch, so a group's build
/// takes nothing from the allocator once the thread has made the sets it
/// has out at once. Before this a fresh set and a fresh scratch were made
/// here for EVERY group, and a big member has a group a block.
fn build_held(bits: &mut BitReader<'_>, algorithm: u8) -> Result<Arc<Tables>> {
    OWN_TABLES.with(|own| {
        let mut own = own.borrow_mut();
        let own = &mut *own;
        let free = own
            .held
            .iter_mut()
            .position(|held| Arc::get_mut(held).is_some());
        let mut tables = match free {
            Some(at) => own.held.swap_remove(at),
            None => Arc::new(Tables::default()),
        };
        let read = Arc::get_mut(&mut tables)
            .expect("a fresh set, or a held set nothing else holds")
            .read(bits, algorithm, &mut own.scratch);
        if own.held.len() < OWN_SETS_MOST {
            own.held.push(Arc::clone(&tables));
        }
        read.map(|()| tables)
    })
}

/// [`LazyDecodeTables::get`], a COPY of its body and not a call, on
/// purpose (the module note): `get` is inlined into `decode_one` for its
/// one caller, and this must not be a second. Kept line for line with it.
fn tables_of_group(
    group: &LazyDecodeTables,
    blocks: &[Located],
    packed: &[u8],
    algorithm: u8,
    carried: Option<&Arc<Tables>>,
) -> Result<(Arc<Tables>, usize)> {
    let Some(first) = group.first else {
        return carried
            .cloned()
            .map(|tables| (tables, 0))
            .ok_or_else(fault::empty_table);
    };
    let build = || {
        let block = &blocks[first];
        let mut bits = BitReader::new(block.payload(packed), block.bits());
        build_held(&mut bits, algorithm).map(|tables| (tables, bits.position()))
    };
    let mut held = group.cell.lock().unwrap_or_else(|e| e.into_inner());
    if held.is_none() {
        *held = Some(build().map_err(|err| format!("{:?}", err.kind())));
    }
    match held.as_ref().expect("just filled") {
        Ok((tables, start)) => Ok((Arc::clone(tables), *start)),
        Err(_) => match build() {
            Err(err) => Err(err),
            Ok(_) => Err(fault::empty_table()),
        },
    }
}

/// [`super::decode_block_tape`] for a table set [`admits`]: the same tape,
/// byte for byte, operation for operation, parked at the same bit and
/// failing with the same error, with runs of length-8 literals taken
/// [`BATCH_WIDTH`] at a time. Its tail (the pad, the far list) is a COPY
/// of `decode_block_tape`'s, not a call (the module note).
#[inline(never)]
pub(crate) fn decode_block_tape_batched(
    tables: &Tables,
    packed: &[u8],
    block: &Located,
    from_bit: usize,
    tape: &mut BlockTape,
) {
    decode_block_tape_batched_body(tables, packed, block, from_bit, tape);
    // THE PAD, as `decode_block_tape` adds it: `Window::literals_padded`
    // reads `STRIDE_MAX` bytes from a run's start whatever its length.
    tape.verbatim
        .resize(tape.verbatim.len() + super::super::output::STRIDE_MAX, 0);
    // THE FAR LIST, as `decode_block_tape` writes it, outside the loop.
    if FAR_LIST || LIST_KNOB {
        super::build_far_list(tape);
    }
    super::note_reach(tape);
}

/// `decode_block_tape_body` with the literal batch in front of each
/// lookup.
///
/// **Why it is exact.** A batch reads the SAME primary entries the scalar
/// loop would, at the bit offsets the scalar loop would reach them (each
/// taken lane is a length-8 code, so the next starts 8 bits on), and takes
/// only the leading lanes that are length-8 literals, which the scalar loop
/// would push one by one with no other effect. It runs only with at least
/// `8 * BATCH_WIDTH` valid bits left, so no taken code is truncated, and
/// only while the literal buffer has `BATCH_WIDTH` of room below its cap,
/// so the scalar loop could not have parked inside the batch. Anything else
/// is one ordinary step, the scalar loop's own.
///
/// **The cap-free admission** is the scalar loop's ([`super::cap_free`],
/// whose note is the proof), asked once per block. The batch changes
/// nothing in it: a batched literal consumes eight bits, so literals and
/// operations stay at most the bits consumed. Admitted, the batch's own
/// room test goes too, since with `8 * BATCH_WIDTH` bits left the literal
/// buffer holds at most `CAP_FREE_BITS - 8 * BATCH_WIDTH` bytes, which
/// leaves `BATCH_WIDTH` of room below either cap.
fn decode_block_tape_batched_body(
    tables: &Tables,
    packed: &[u8],
    block: &Located,
    from_bit: usize,
    tape: &mut BlockTape,
) {
    let Some(bits) = batched_from(tables, packed, block, from_bit, tape) else {
        return;
    };
    if super::cap_free(block, from_bit) {
        batched_symbols::<false>(tables, bits, tape);
    } else {
        super::cold_path();
        batched_symbols::<true>(tables, bits, tape);
    }
}

/// The tape cleared and a reader at the first symbol bit, or `None` with
/// the tape answered: `tape::symbols_from`'s prelude, a COPY (the module
/// note), and before the choice of loop for its reason: `seek_batched`
/// keeps one caller. Both loops are inlined into the caller, the checked
/// one marked cold, as `tape::decode_block_tape_body` has them and for its
/// counted reason.
#[inline(always)]
fn batched_from<'a>(
    tables: &Tables,
    packed: &'a [u8],
    block: &Located,
    from_bit: usize,
    tape: &mut BlockTape,
) -> Option<BitReader<'a>> {
    tape.clear();
    let mut bits = BitReader::new(block.payload(packed), block.bits());
    bits.seek_batched(from_bit);
    // An admitted table codes at least `BATCH_GATE` symbols, so it is never
    // empty; asked anyway, because the scalar step below relies on it.
    if tables.main.is_empty() {
        if !bits.at_end() {
            tape.failure = Some(fault::empty_table());
        }
        return None;
    }
    Some(bits)
}

/// [`decode_block_tape_batched`] with the checked loop whatever the
/// block's size, for the tests that prove the two agree.
#[cfg(test)]
pub(crate) fn decode_block_tape_batched_checked(
    tables: &Tables,
    packed: &[u8],
    block: &Located,
    from_bit: usize,
    tape: &mut BlockTape,
) {
    if let Some(bits) = batched_from(tables, packed, block, from_bit, tape) {
        batched_symbols::<true>(tables, bits, tape);
    }
    tape.verbatim
        .resize(tape.verbatim.len() + super::super::output::STRIDE_MAX, 0);
    if FAR_LIST || LIST_KNOB {
        super::build_far_list(tape);
    }
    super::note_reach(tape);
}

/// The batched symbol loop over a non-empty main table; `CAPPED` as
/// `tape::decode_symbols` has it.
#[inline(always)]
fn batched_symbols<const CAPPED: bool>(
    tables: &Tables,
    mut bits: BitReader<'_>,
    tape: &mut BlockTape,
) {
    let lut = &*tables.main.lut;
    const TAKEN: u32 = HUFF_LUT_LITERAL_BIT | 8;
    let mut literal_run = 0usize;
    let fold = super::fold();
    if !CAPPED && batched_region(tables, &mut bits, tape, &mut literal_run) == Region::Stopped {
        return;
    }
    while !bits.at_end() {
        let op_start = bits.position();
        if CAPPED && (tape.steps.len() >= TAPE_OPS_CAP || tape.verbatim.len() >= TAPE_LITS_CAP) {
            flush_literals(tape, &mut literal_run);
            tape.parked_at = Some(op_start);
            return;
        }
        if (!CAPPED || tape.verbatim.len() + BATCH_WIDTH <= TAPE_LITS_CAP)
            && bits.remaining() >= 8 * BATCH_WIDTH
        {
            let window = bits.window();
            let mut taken = 0u32;
            let mut bytes = 0u64;
            for lane in 0..BATCH_WIDTH {
                // The nine index bits at offset `8 * lane`, as `lookup`
                // would take them once the lanes before were consumed.
                let index = (window >> (55 - 8 * lane)) as usize & (lut.len() - 1);
                let entry = lut[index];
                taken |= u32::from(entry & (HUFF_LUT_LITERAL_BIT | 0xff) == TAKEN) << lane;
                bytes |= u64::from((entry >> 8) & 0xff) << (8 * lane);
            }
            // The leading taken lanes; bit `BATCH_WIDTH` of `taken` is clear.
            let run = (!taken).trailing_zeros() as usize;
            if run > 0 {
                let at = tape.verbatim.len();
                tape.verbatim
                    .extend_from_slice(&bytes.to_le_bytes()[..BATCH_WIDTH]);
                tape.verbatim.truncate(at + run);
                literal_run += run;
                bits.advance(8 * run as u32);
                continue;
            }
        }
        let entry = match tables.main.lookup_filled(&mut bits) {
            Ok(entry) => entry,
            Err(err) => {
                flush_literals(tape, &mut literal_run);
                tape.failure = Some(err);
                return;
            }
        };
        if lut_entry_is_literal(entry) {
            tape.verbatim.push(lut_symbol(entry) as u8);
            literal_run += 1;
            continue;
        }
        let symbol = lut_symbol(entry);
        match decode_control(tables, &mut bits, symbol, tape) {
            Ok(Some(op)) => {
                push_after(&mut tape.steps, fold, literal_run, op);
                literal_run = 0;
            }
            Ok(None) => {
                flush_literals(tape, &mut literal_run);
                tape.parked_at = Some(op_start);
                return;
            }
            Err(err) => {
                flush_literals(tape, &mut literal_run);
                tape.failure = Some(err);
                return;
            }
        }
    }
    flush_literals(tape, &mut literal_run);
}

/// THE FAST REGION OF THE BATCHED LOOP (as at an earlier revision; the fresh-match
/// levers are the scalar region's alone, `tape::main_region`): `tape::fast_region`'s rules
/// (its note and `bits.rs`'s "THE FAST REGION" carry the proof) with the
/// literal batch in front of each scalar step, as [`batched_symbols`] has
/// it. A batch reads the same 56 bit window (`ensure_in_region` tops the
/// reader up as `window` did; the region's margin holds the 56 valid bits
/// the batched loop tested for), takes the same leading lanes, and writes
/// them through the region's slice cursor as one eight byte store, where
/// the cursor has eight bytes of room; otherwise the scalar step takes
/// the symbol, exactly as the batched loop falls to it. The tape is the
/// batched loop's, operation for operation.
///
/// The region's pieces are the scalar path's, called and not copied: each
/// is `#[inline(always)]`, so a second caller cannot outline it (the
/// module note's reason for its copies).
#[inline(always)]
fn batched_region(
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
    let end = base + room;
    let mut lits: &mut [u8] = &mut literals[base..end];
    let mut run_start = base - *literal_run;
    let fold = super::fold();
    let lut = &*tables.main.lut;
    const TAKEN: u32 = HUFF_LUT_LITERAL_BIT | 8;
    // THE SINGLE-GAP SHAPE, asked once per block: with it, a run of
    // literal codes is read as bytes ([`bulk_literals`]).
    let gap = tables.main.serial_single_gap();
    // THE FULL-BYTE SHAPE, asked once per block too: every code is an
    // eight bit literal, so the same step reads the codes as the literals
    // themselves, with no escape to find (`DecodeTable::serial_full_byte`).
    let full = gap.is_none() && tables.main.serial_full_byte();
    #[cfg(feature = "lane-census")]
    let mut tally = census::Tally::default();
    // Whether the turn before was a lane pass that took one to six codes.
    #[cfg(feature = "lane-census")]
    let mut part = false;
    #[cfg(feature = "lane-census")]
    {
        tally.0[usize::from(gap.is_none())] += 1;
    }
    let region = 'turn: loop {
        if bits.next_byte() >= fast_end {
            break Region::Tail;
        }
        'lanes: {
            if let Some(hole) = gap {
                #[cfg(feature = "lane-census")]
                let before = bits.position();
                let bulk = bulk_literals::<false>(bits, hole, &mut lits);
                #[cfg(feature = "lane-census")]
                {
                    let codes = (bits.position() - before) / 8;
                    tally.0[if bulk == Bulk::Whole {
                        2
                    } else if codes > 0 {
                        3
                    } else {
                        4
                    }] += 1;
                    tally.0[5] += codes as u64;
                }
                match bulk {
                    Bulk::Whole => continue 'turn,
                    // The reader stands on an escape, which no lane takes:
                    // a pass from there looks up seven lanes to take none
                    // (2.47 million of them on a media-like 1 GiB member,
                    // counted 12 Oct 2026 on an Apple M5), so the scalar
                    // step reads the long code now.
                    Bulk::Escape => break 'lanes,
                    Bulk::Short => {}
                }
            } else if full && bulk_literals::<true>(bits, 0, &mut lits) == Bulk::Whole {
                // A short step (too little room for a group) leaves the
                // codes to the passes below, which take a full-byte
                // table's codes seven at a time as they always did.
                continue 'turn;
            }
            // THE FULL PASSES ARE A LOOP OF THEIR OWN: a pass that takes all
            // seven lanes is followed by another without a look at anything
            // else the region carries (29.4 million of the 32.0 million
            // taking passes on a media-like 1 GiB member on x86-64, counted
            // 12 Oct 2026), so what that loop does not read need not be
            // held for it.
            let run = loop {
                bits.ensure_in_region(56);
                let window = bits.window_in_region();
                let mut taken = 0u32;
                let mut bytes = 0u64;
                for lane in 0..BATCH_WIDTH {
                    let index = (window >> (55 - 8 * lane)) as usize & (lut.len() - 1);
                    let entry = lut[index];
                    taken |= u32::from(entry & (HUFF_LUT_LITERAL_BIT | 0xff) == TAKEN) << lane;
                    bytes |= u64::from((entry >> 8) & 0xff) << (8 * lane);
                }
                let run = (!taken).trailing_zeros() as usize;
                #[cfg(feature = "lane-census")]
                {
                    let at = if gap.is_some() { 6 } else { 9 };
                    tally.0[at + usize::from(run > 0)] += 1;
                    tally.0[at + 2] += run as u64;
                    tally.0[14 + usize::from(gap.is_none())] += u64::from(run == BATCH_WIDTH);
                    tally.0[16] += u64::from(part && run == 0);
                    part = run > 0 && run < BATCH_WIDTH;
                }
                if run == 0 || lits.len() < 8 {
                    break 0;
                }
                let cursor = std::mem::take(&mut lits);
                cursor[..8].copy_from_slice(&bytes.to_le_bytes());
                lits = &mut cursor[run..];
                bits.advance_wide_in_region(8 * run as u32);
                if run < BATCH_WIDTH {
                    break run;
                }
                if bits.next_byte() >= fast_end {
                    continue 'turn;
                }
            };
            // A PASS CUT SHORT stands on the code that cut it: lane `run`
            // was looked up and is not an eight bit literal. Another pass
            // from there looks up seven lanes to take none (counted 12 Oct
            // 2026 on an Apple M5: every one of the 3.63 million passes cut
            // short on a media-like 1 GiB member was followed by an empty
            // one, 1.44 million on a 4 GiB binary member), so the scalar
            // step takes that code now, once the region's end is asked as
            // the loop's head asks it.
            if run > 0 && bits.next_byte() >= fast_end {
                continue 'turn;
            }
        }
        #[cfg(feature = "lane-census")]
        {
            part = false;
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
            #[cfg(feature = "lane-census")]
            {
                tally.0[12] += 1;
            }
            let byte = lut_symbol(entry) as u8;
            match std::mem::take(&mut lits).split_first_mut() {
                Some((slot, rest)) => {
                    *slot = byte;
                    lits = rest;
                }
                None => {
                    debug_assert!(false, "a literal past the region's bound");
                    literals.push(byte);
                    *literal_run = end + 1 - run_start;
                    bits.leave_fast_region();
                    return Region::Tail;
                }
            }
            continue;
        }
        #[cfg(feature = "lane-census")]
        {
            tally.0[13] += 1;
        }
        let at = end - lits.len();
        let symbol = lut_symbol(entry);
        match super::main_region::decode_control_in_region_main(tables, bits, symbol, records) {
            Ok(Ok(op)) => {
                push_after(ops, fold, at - run_start, op);
                run_start = at;
            }
            Ok(Err(after_main)) => {
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

/// What one bulk step left.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Bulk {
    /// A whole group taken: the next step is another.
    Whole,
    /// The reader stands on an escape, the codes before it taken.
    Escape,
    /// No room for a group; nothing read.
    Short,
}

/// The most codes one bulk step reads.
const BULK: usize = 256;

/// The codes one pass of the bulk step's reading loop makes (see the
/// loop). [`BULK`] is a whole number of them.
const CODE_PASS: usize = 16;
const _: () = assert!(BULK.is_multiple_of(CODE_PASS));

/// THE BULK LITERAL STEP,
/// for a main table
/// of the SINGLE-GAP shape: 255 of the 256 byte literals coded in exactly
/// eight bits, one byte value `hole` omitted (or coded longer), and no
/// code shorter than eight. Under SPEC-H2 3.4's canonical assignment the
/// eight bit codes are then the values 0 to 254 in symbol order, so code
/// `c` is the literal `c + (c >= hole)`, and code 255 is the prefix of
/// every longer code: the ESCAPE, behind which every control symbol and
/// the omitted literal live. So a run of literal codes is read as BYTES
/// straight from the payload at the reader's bit position, the first
/// escape found, the codes before it translated in one pass into the
/// region's cursor, and the reader put back down at the escape once.
///
/// **What keeps it exact.** The step runs inside the region, so its `K`
/// codes are inside the block: it takes codes from bytes `byte0 .. byte0 +
/// K + 1` of the payload (and reads up to 15 bytes more, which it never
/// takes: the reading loop's whole passes), with `K` bounded so that
/// `byte0 + K + 41 <= len`,
/// which puts every code's bits under the block's limit (`nbits >= 8 *
/// len - 7`) and leaves the reader's refill after the seek 33 bytes short
/// of the slice, inside the region's own margin; no padding bit is ever
/// decoded. `K` is also bounded by the cursor's room, so a literal never
/// passes the block's bound. The codes taken are exactly the ones the
/// scalar step would take one by one (each an eight bit literal entry,
/// none an escape), pushed in the same order to the same run, and the
/// reader lands on the escape's first bit, where the scalar step reads
/// the long code as it always did; a park, a record and every error kind
/// are the scalar step's, because the scalar step is what reads them.
///
/// Answers what it left ([`Bulk`]): a WHOLE group taken, a group cut by an
/// escape (the reader stands on it, for the caller's scalar step), or no
/// group at all (fewer than eight codes of room), which leaves the caller
/// to its batch and scalar steps from where the reader stands.
///
/// **`FULL`: the full-byte shape** (`DecodeTable::serial_full_byte`): all
/// 256 literals in eight bits, so code `c` is literal `c` and there is no
/// escape. The codes are read exactly as above and taken whole, all `K` of
/// them, untranslated: no escape search and no hole (`hole` is unused).
/// The same bounds hold, so the same `K` codes are the scalar step's, in
/// the same order, and the step is never cut short by an escape.
#[inline(always)]
fn bulk_literals<const FULL: bool>(
    bits: &mut BitReader<'_>,
    hole: u8,
    lits: &mut &mut [u8],
) -> Bulk {
    let data = bits.payload();
    let pos = bits.position();
    let byte0 = pos >> 3;
    let shift = (pos & 7) as u32;
    let k_max = data
        .len()
        .saturating_sub(byte0 + 41)
        .min(BULK)
        .min(lits.len());
    if k_max < 8 {
        return Bulk::Short;
    }
    // The codes, each straddling two payload bytes below the bit `shift`
    // (`shift == 0` reads the byte whole): the payload from the reader's
    // bit, read as bytes.
    //
    // SIXTEEN A PASS, EACH PASS ONE VALUE, the last pass read past `k_max`:
    // its spare codes are payload bytes this step never takes (the escape
    // search and the translation below stop at `k_max`), and they are
    // inside the slice, because `byte0 + k_max + 41 <= len` leaves 40 bytes
    // after the last code's second byte and the passes read at most 15
    // more. The loop this was made one code a turn, `k_max` turns, and left
    // its width to the compiler, which kept a byte-at-a-time remainder of
    // up to 16 codes a step (the second byte of the last code could not be
    // read wide) and, under a profile, chose the width and the remainder's
    // shape by the trip counts the profile had seen. Three things make this
    // form one 16 byte pass with nothing left over, on aarch64 and x86-64,
    // profile or none (each was needed; counted 11 Oct 2026 on an Apple M5,
    // see this change's commit message):
    // - a pass's count is the constant [`CODE_PASS`];
    // - a pass is BUILT whole and stored once, so every load is before the
    //   one store (stored code by code, the stores might overlap the
    //   payload for all the compiler can prove, and it keeps 16 scalar
    //   copies);
    // - a code is two BYTE shifts, never a 16 bit value of two bytes (that
    //   is recognised as a two byte load, and 16 of those are not one wide
    //   load). `(low >> 1) >> (7 - shift)` is `low >> (8 - shift)` without
    //   the shift by eight that `shift == 0` would ask of a byte.
    let passes = k_max.div_ceil(CODE_PASS);
    let src = &data[byte0..byte0 + CODE_PASS * passes + 1];
    let mut codes = [0u8; BULK];
    let (high, _) = src[..CODE_PASS * passes].as_chunks::<CODE_PASS>();
    let (low, _) = src[1..].as_chunks::<CODE_PASS>();
    let (passed, _) = codes.as_chunks_mut::<CODE_PASS>();
    for ((out, high), low) in passed.iter_mut().zip(high).zip(low) {
        *out = std::array::from_fn(|i| (high[i] << shift) | ((low[i] >> 1) >> (7 - shift)));
    }
    // THE ESCAPE SEARCH, a wide compare and not a byte at a time. On a big
    // member a step takes about 170 codes (17.7 million steps for 3.09 billion
    // literals of a media-like 4 GiB member), and the byte loop this was (a
    // compare and a branch a code) was a quarter of this body's cycles there.
    // Plain builds of one main on a 48 core Xeon, the big member: 0.824 of the
    // cycles at one thread (1.18 by wall) and 0.887 at the default width,
    // where the wall is level because the apply binds it
    // (measured 2 Oct 2026). The answer is the
    // first 0xff's place, exactly as the loop gave it.
    let k = if FULL {
        k_max
    } else {
        memchr::memchr(0xff, &codes[..k_max]).unwrap_or(k_max)
    };
    if k == 0 {
        return Bulk::Escape;
    }
    let cursor = std::mem::take(lits);
    let (head, rest) = cursor.split_at_mut(k);
    if FULL {
        head.copy_from_slice(&codes[..k]);
    } else {
        for (slot, &code) in head.iter_mut().zip(&codes[..k]) {
            // `code <= 254`, so the sum cannot wrap.
            *slot = code + u8::from(code >= hole);
        }
    }
    *lits = rest;
    bits.seek_in_region(pos + 8 * k);
    if k == k_max {
        Bulk::Whole
    } else {
        Bulk::Escape
    }
}

/// A COPY of `tape::flush_literals`, not a call (the module note).
#[inline(always)]
fn flush_literals(tape: &mut BlockTape, run: &mut usize) {
    flush_run(&mut tape.steps, *run);
    *run = 0;
}

/// A COPY of `tape::decode_control`, not a call (the module note): that
/// one is inlined into the scalar loop for its one caller. Kept line for
/// line with it, and always inlined for `tape::decode_control`'s reason.
#[inline(always)]
fn decode_control(
    tables: &Tables,
    bits: &mut BitReader<'_>,
    symbol: usize,
    tape: &mut BlockTape,
) -> Result<Option<TapeOp>> {
    match symbol {
        SYMBOL_FILTER => {
            let mut spill = *bits;
            let record = filters::read_record(&mut spill);
            *bits = spill;
            let record = record?;
            tape.records.push(record);
            Ok(Some(TapeOp::new(tape_kind::FILTER, 0, 0)))
        }
        SYMBOL_REPEAT_LAST => Ok(Some(TapeOp::new(tape_kind::REP_LAST, 0, 0))),
        258..=261 => {
            let length = read_length(tables, bits)?;
            let index = (symbol - SYMBOL_REPEAT_BASE) as u32;
            Ok(Some(TapeOp::new(tape_kind::REP, length, index)))
        }
        _ => {
            let slot = symbol - SYMBOL_MATCH_BASE;
            let length = read_length_slot(bits, slot)?;
            let distance = read_distance(tables, bits)?;
            let length = fresh_match_length(length, distance);
            match u32::try_from(distance) {
                Ok(distance) => Ok(Some(TapeOp::new(tape_kind::MATCH, length, distance))),
                Err(_) => Ok(None),
            }
        }
    }
}

/// The table set block `index` decodes with, the bit its symbols start at
/// and whether the gate admits the set; unit tests only.
#[cfg(test)]
pub(crate) fn tables_of(
    plan: &Plan,
    packed: &[u8],
    algorithm: u8,
    index: usize,
) -> Result<(Arc<Tables>, usize, bool)> {
    let group = &plan.groups[plan.group_of[index]];
    let (tables, start) = tables_of_group(group, &plan.blocks, packed, algorithm, None)?;
    let from = if group.first == Some(index) { start } else { 0 };
    let batch = admits(&tables);
    Ok((tables, from, batch))
}

/// THE BULK STEP IS THE SCALAR DECODE, on every single-gap table there is.
#[cfg(test)]
mod bulk_tests {
    use super::super::super::tables::MAIN_SYMBOLS;
    use super::super::super::vectors::BlockBuilder;
    use super::super::{self as tape, Plan};
    use super::*;

    /// A main table of the single-gap shape: every literal eight bits but
    /// `hole`, omitted or coded at twelve; the filter symbol at twelve,
    /// the last-length repeat at nine, repeat 0 at eleven and the first
    /// fresh match slot at ten, which spends exactly the one eight bit
    /// slot the 255 literals leave (a complete table with the hole coded,
    /// an incomplete one without).
    fn gap_lengths(hole: u8, coded_hole: bool) -> Vec<u8> {
        let mut main = vec![0u8; MAIN_SYMBOLS];
        for length in main.iter_mut().take(256) {
            *length = 8;
        }
        main[usize::from(hole)] = if coded_hole { 12 } else { 0 };
        main[256] = 12;
        main[257] = 9;
        main[258] = 11;
        main[262] = 10;
        main
    }

    /// The tape of one block by the region path (the batch's region, the
    /// bulk step inside it, and the checked tail), and by the plain
    /// checked loop and the scalar region, all from `from`.
    fn three_tapes(
        tables: &Tables,
        packed: &[u8],
        block: &Located,
        from: usize,
    ) -> (BlockTape, BlockTape, BlockTape) {
        let mut region = BlockTape::default();
        if let Some(bits) = batched_from(tables, packed, block, from, &mut region) {
            batched_symbols::<false>(tables, bits, &mut region);
        }
        let mut checked = BlockTape::default();
        if let Some(bits) = tape::symbols_from(tables, packed, block, from, &mut checked) {
            tape::decode_symbols::<true>(tables, bits, &mut checked);
        }
        let mut scalar = BlockTape::default();
        if let Some(bits) = tape::symbols_from(tables, packed, block, from, &mut scalar) {
            tape::decode_symbols::<false>(tables, bits, &mut scalar);
        }
        (region, checked, scalar)
    }

    fn same(a: &BlockTape, b: &BlockTape, what: &str) {
        let ops = |t: &BlockTape| -> Vec<(u32, usize, usize, u32)> {
            t.steps
                .iter()
                .map(|op| (op.kind(), op.prefix(), op.length(), op.distance))
                .collect()
        };
        assert_eq!(ops(a), ops(b), "{what}: operations");
        assert_eq!(a.verbatim, b.verbatim, "{what}: literals");
        assert_eq!(a.records, b.records, "{what}: records");
        assert_eq!(a.parked_at, b.parked_at, "{what}: parked");
        assert_eq!(
            a.failure.as_ref().map(|e| format!("{:?}", e.kind())),
            b.failure.as_ref().map(|e| format!("{:?}", e.kind())),
            "{what}: failure"
        );
    }

    /// Every omitted value (0 to 255, coded longer or left out), every
    /// starting bit offset of the first run (0 to 7, by leading nine bit
    /// codes), runs across and exactly at the group boundary (256, 512),
    /// escapes of every kind between them (the last-length repeat, a fresh
    /// match, a repeat, a filter record, the hole's own long code), short
    /// tails, a run ending at the block's end, and blocks from a few
    /// hundred bytes to a few thousand: the region with the bulk step
    /// gives the plain checked loop's tape and the scalar region's.
    #[test]
    fn the_bulk_step_is_the_scalar_decode_on_every_single_gap_table() {
        let mut rng = rarkit_testdata::Seeded::new(0x62756c6b_6c697473);
        let mut groups_whole = 0usize;
        let mut cases = 0usize;
        for hole in 0..=255u8 {
            for offset in 0..8usize {
                let coded_hole = (usize::from(hole) + offset) % 2 == 0;
                let mut builder = BlockBuilder::default();
                builder.main = gap_lengths(hole, coded_hole);
                for _ in 0..offset {
                    builder.repeat_last();
                }
                let shape = (usize::from(hole) + offset) % 5;
                let runs = match shape {
                    0 => vec![256, 1, 512, 300],
                    1 => vec![7, 8, 9, 255, 257],
                    2 => vec![1000, 3],
                    3 => vec![40, 40, 40, 2000],
                    _ => vec![256 - 40, 12],
                };
                let mut literals = 0usize;
                for (i, &run) in runs.iter().enumerate() {
                    for _ in 0..run {
                        // Mostly the ordinary literals, now and then the
                        // hole's own long code where it has one.
                        let mut byte = rng.below(256) as u8;
                        if byte == hole && !(coded_hole && rng.below(16) == 0) {
                            byte = byte.wrapping_add(1);
                            if byte == hole {
                                byte = byte.wrapping_add(1);
                            }
                        }
                        builder.literal(byte);
                        literals += 1;
                    }
                    match (i + shape) % 5 {
                        0 => builder.repeat_last(),
                        1 => builder.fresh(0, 0, rng.below(4) as usize, 0),
                        2 => builder.repeat(0, 3, 0),
                        3 => builder.filter(rng.below(200) as u32, 16, 1, 0),
                        _ => {}
                    }
                }
                // Tails of every length under a group, ending at the block's
                // end: the last run is what is left after the last escape.
                let tail = (usize::from(hole) * 7 + offset * 3) % 300;
                for _ in 0..tail {
                    let mut byte = rng.below(256) as u8;
                    if byte == hole {
                        byte = byte.wrapping_add(1);
                    }
                    builder.literal(byte);
                    literals += 1;
                }
                assert!(literals < 15_000, "the test caps park the checked loop");
                let packed = builder.finish(true, true);
                let mut plan = Plan::default();
                tape::plan(&packed, false, &mut plan).expect("a sound block chain");
                let (tables, from, admitted) = tables_of(&plan, &packed, 0, 0).expect("tables");
                assert!(admitted, "hole {hole}: the batch gate admits the shape");
                assert_eq!(
                    tables.main.serial_single_gap(),
                    Some(hole),
                    "hole {hole} coded {coded_hole}"
                );
                let what = format!("hole {hole} offset {offset} coded {coded_hole}");
                let (region, checked, scalar) =
                    three_tapes(&tables, &packed, &plan.blocks[0], from);
                same(&region, &checked, &what);
                same(&scalar, &checked, &what);
                assert!(
                    region.failure.is_none() && region.parked_at.is_none(),
                    "{what}"
                );
                groups_whole += literals / BULK;
                cases += 1;
            }
        }
        assert_eq!(cases, 2048);
        assert!(groups_whole > 4000, "only {groups_whole} whole groups");
    }

    /// THE FULL-BYTE BULK STEP IS THE SCALAR DECODE. A main table of all
    /// 256 literals at eight bits, blocks of every literal count from none
    /// to past three groups and a few long ones, decoded from EVERY bit
    /// shift of the symbols' start (under this table any eight bits are a
    /// literal, so a block read from one to seven bits late is still a
    /// sound stream of literals, with a short last code where the block
    /// ends): the region with the bulk step gives the plain checked loop's
    /// tape and the scalar region's, the end's failure included.
    #[test]
    fn the_full_byte_bulk_step_is_the_scalar_decode_at_every_shift() {
        let mut rng = rarkit_testdata::Seeded::new(0x6675_6c6c_6279_7465);
        let mut full = vec![0u8; MAIN_SYMBOLS];
        full[..256].fill(8);
        let mut counts: Vec<usize> = (0..=3 * BULK + 40).step_by(7).collect();
        counts.extend([BULK - 1, BULK, BULK + 1, 2 * BULK, 4000, 9001, 14_000]);
        let mut literals_seen = 0usize;
        for &count in &counts {
            let mut builder = BlockBuilder::default();
            builder.main = full.clone();
            for _ in 0..count {
                builder.literal(rng.below(256) as u8);
            }
            let packed = builder.finish(true, true);
            let mut plan = Plan::default();
            tape::plan(&packed, false, &mut plan).expect("a sound block chain");
            let (tables, from, admitted) = tables_of(&plan, &packed, 0, 0).expect("tables");
            assert!(admitted, "{count}: the batch gate admits the shape");
            assert!(tables.main.serial_full_byte(), "{count}");
            assert_eq!(tables.main.serial_single_gap(), None, "{count}");
            // A block of no literals ends where its symbols start: no later
            // start is inside it.
            let shifts = if count == 0 { 0..1 } else { 0..8 };
            for shift in shifts {
                let what = format!("{count} literals, shift {shift}");
                let (region, checked, scalar) =
                    three_tapes(&tables, &packed, &plan.blocks[0], from + shift);
                same(&region, &checked, &what);
                same(&scalar, &checked, &what);
                if shift == 0 {
                    assert!(
                        region.failure.is_none() && region.parked_at.is_none(),
                        "{what}"
                    );
                    assert_eq!(region.verbatim.len(), count, "{what}");
                }
                literals_seen += region.verbatim.len();
            }
        }
        assert!(literals_seen > 8 * 30_000, "only {literals_seen} literals");
    }

    /// THE ESCAPE SEARCH's answer at every place: a run of every length
    /// from none to past two whole groups, then one escape (a fresh match),
    /// then a run long enough to keep the escape inside the fast region, at
    /// two bit offsets. The first escape code therefore stands at every
    /// index of a group, the ends of the search's wide blocks included, and
    /// the region's tape is the checked loop's.
    #[test]
    fn the_escape_search_finds_the_escape_at_every_place_of_a_group() {
        let mut rng = rarkit_testdata::Seeded::new(0x6573_6361_7065_2121);
        let hole = 0x41u8;
        for offset in [0usize, 3] {
            for run in 0..=(2 * BULK + 88) {
                let mut builder = BlockBuilder::default();
                builder.main = gap_lengths(hole, false);
                for _ in 0..offset {
                    builder.repeat_last();
                }
                for i in 0..(run + 2000) {
                    if i == run {
                        builder.fresh(0, 0, 0, 0);
                    }
                    let mut byte = rng.below(256) as u8;
                    if byte == hole {
                        byte = byte.wrapping_add(1);
                    }
                    builder.literal(byte);
                }
                let packed = builder.finish(true, true);
                let mut plan = Plan::default();
                tape::plan(&packed, false, &mut plan).expect("a sound block chain");
                let (tables, from, admitted) = tables_of(&plan, &packed, 0, 0).expect("tables");
                assert!(admitted, "run {run}: the batch gate admits the shape");
                let what = format!("run {run} offset {offset}");
                let (region, checked, scalar) =
                    three_tapes(&tables, &packed, &plan.blocks[0], from);
                same(&region, &checked, &what);
                same(&scalar, &checked, &what);
                assert!(
                    region.failure.is_none() && region.parked_at.is_none(),
                    "{what}"
                );
                assert_eq!(region.verbatim.len(), checked.verbatim.len(), "{what}");
            }
        }
    }

    /// A block whose payload is damaged where a group is read: the region
    /// with the bulk step still gives the checked loop's tape, failure
    /// kind included, on every damaged copy.
    #[test]
    fn the_bulk_step_agrees_on_damaged_payloads() {
        let mut rng = rarkit_testdata::Seeded::new(0x6461_6d61_6765_6421);
        for case in 0..64usize {
            let hole = rng.below(256) as u8;
            let mut builder = BlockBuilder::default();
            builder.main = gap_lengths(hole, case % 2 == 0);
            for _ in 0..(200 + rng.below(1500)) {
                let mut byte = rng.below(256) as u8;
                if byte == hole {
                    byte = byte.wrapping_add(1);
                }
                builder.literal(byte);
                if rng.below(200) == 0 {
                    builder.fresh(0, 0, 0, 0);
                }
            }
            let mut packed = builder.finish(true, true);
            let len = packed.len();
            for _ in 0..3 {
                let at = len / 2 + rng.below((len / 2) as u64) as usize;
                packed[at] ^= 1 + rng.below(255) as u8;
            }
            let mut plan = Plan::default();
            if tape::plan(&packed, false, &mut plan).is_err() {
                continue;
            }
            let Ok((tables, from, _)) = tables_of(&plan, &packed, 0, 0) else {
                continue;
            };
            let (region, checked, scalar) = three_tapes(&tables, &packed, &plan.blocks[0], from);
            same(&region, &checked, &format!("damaged case {case}"));
            same(&scalar, &checked, &format!("damaged case {case}"));
        }
    }
}

/// A GROUP'S TABLES TAKE NO MEMORY ONCE THE THREAD IS WARM.
#[cfg(test)]
mod kept_sets_tests {
    use std::collections::VecDeque;

    use super::super::super::tables::MAIN_SYMBOLS;
    use super::super::super::vectors::BlockBuilder;
    use super::super::{self as tape, Plan, TAPE_UNIT_BLOCKS};
    use super::*;
    use crate::rar3_filters::tests::counting;

    /// The sets one lane has out at once: the unit it decodes, the unit
    /// queued for the apply stage and the unit being applied
    /// (`member_piped`), each of at most [`TAPE_UNIT_BLOCKS`] blocks.
    const IN_FLIGHT: usize = 3 * TAPE_UNIT_BLOCKS;
    const BLOCKS: usize = 240;
    /// Blocks decoded before the count starts: every set the thread will
    /// ever hold has been made by then, and the one tape has grown.
    const WARM: usize = 4 * IN_FLIGHT;

    /// SPEC-H2 section 4.2, no allocation per block, where a big member pays for
    /// it: a chain in which EVERY block carries a table set the gate
    /// admits, which is what the reference writes for media, decoded by
    /// this module's `decode_one` on one thread with as many sets out as a
    /// lane has, each let go in order as the apply stage would. Once the
    /// thread has made the sets it needs, a block takes nothing from the
    /// allocator: not for its group's set, not for the scratch its lengths
    /// are read into, not inside any table's build.
    ///
    /// NOT COUNTED, and said here so the count is not read as more than it
    /// is: the first lock of each group's cell. The standard library makes
    /// the system's lock on first use on some hosts (macOS is one; measured
    /// there, one take a fresh `Mutex`), which is a take a GROUP and none
    /// of the tables'. Every cell is locked once before the count starts.
    ///
    /// One thread (the test's own, which is the one counted), no pool, and
    /// under a megabyte held.
    #[test]
    fn a_block_with_tables_takes_no_memory_once_the_thread_is_warm() {
        // 255 literals at eight bits and four control symbols with codes
        // of nine to twelve, so the gate admits the set and every table
        // build writes a second level.
        let mut main = vec![0u8; MAIN_SYMBOLS];
        for length in main.iter_mut().take(256).skip(1) {
            *length = 8;
        }
        main[256] = 12;
        main[257] = 9;
        main[258] = 11;
        main[262] = 10;
        let mut packed = Vec::new();
        for block in 0..BLOCKS {
            let mut builder = BlockBuilder::default();
            builder.main = main.clone();
            for at in 0..600usize {
                builder.literal(1 + ((at * 7 + block) % 255) as u8);
            }
            packed.extend(builder.finish(true, block + 1 == BLOCKS));
        }
        let mut plan = Plan::default();
        tape::plan(&packed, false, &mut plan).expect("a sound block chain");
        assert_eq!(plan.blocks.len(), BLOCKS);
        assert_eq!(plan.groups.len(), BLOCKS, "a table set a block");
        for group in &plan.groups {
            drop(group.cell.lock().expect("nothing has held it"));
        }

        let mut tape = BlockTape::default();
        let mut out: VecDeque<Arc<Tables>> = VecDeque::with_capacity(IN_FLIGHT + 1);
        let mut before = 0;
        for index in 0..BLOCKS {
            if index == WARM {
                before = counting::count();
            }
            let held = decode_one(&plan, &packed, 0, None, index, &mut tape)
                .expect("the block's set is handed back");
            assert!(admits(&held), "block {index}: the gate admits the set");
            assert!(tape.failure.is_none(), "block {index} decodes");
            out.push_back(held);
            if out.len() > IN_FLIGHT {
                // The apply stage passes the oldest block: its tape's hold
                // goes, then its group's.
                out.pop_front();
                plan.release_below(index + 1 - IN_FLIGHT);
            }
        }
        let took = counting::count() - before;
        assert_eq!(
            took,
            0,
            "{took} takes from the allocator over {} blocks, each with a table set",
            BLOCKS - WARM
        );
    }
}
