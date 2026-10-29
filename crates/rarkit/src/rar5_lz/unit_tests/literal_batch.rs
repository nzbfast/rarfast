//! THE LITERAL BATCH above the tape decoder
//! (`tape::decode_block_tape_batched`).

use super::*;

// ---------------------------------------------------------------------
// THE LITERAL BATCH above the tape decoder (`tape::decode_block_tape_batched`).
// ---------------------------------------------------------------------

/// Decode one block both ways from `from`, following every park, and
/// assert the two tapes agree in every field the apply stage or the
/// serial resume reads: operations, literals, records, the parked bit and
/// the error's kind. Answers the blocks' literal count, so a caller can
/// see that it was not vacuous.
#[cfg(feature = "parallel")]
fn the_batch_agrees(
    tables: &super::tables::Tables,
    packed: &[u8],
    block: &super::block::Located,
    from: usize,
    what: &str,
) -> usize {
    use super::tape::{self, BlockTape};
    let ops = |tape: &BlockTape| -> Vec<(u32, usize, usize, u32)> {
        tape.steps
            .iter()
            .map(|op| (op.kind(), op.prefix(), op.length(), op.distance))
            .collect()
    };
    let mut plain = BlockTape::default();
    let mut batched = BlockTape::default();
    let mut checked = BlockTape::default();
    let mut batched_checked = BlockTape::default();
    let mut at = from;
    let mut literals = 0;
    loop {
        tape::decode_block_tape(tables, packed, block, at, &mut plain);
        tape::batch::decode_block_tape_batched(tables, packed, block, at, &mut batched);
        // THE CAP-FREE ADMISSION: the checked loops, whatever the block's
        // size, give the tape the admitted ones do (`tape::cap_free`).
        tape::decode_block_tape_checked(tables, packed, block, at, &mut checked);
        tape::batch::decode_block_tape_batched_checked(
            tables,
            packed,
            block,
            at,
            &mut batched_checked,
        );
        for (other, name) in [(&checked, "checked"), (&batched_checked, "batched checked")] {
            assert_eq!(
                ops(&plain),
                ops(other),
                "{what} from bit {at}: {name} operations"
            );
            assert_eq!(
                plain.verbatim, other.verbatim,
                "{what} from bit {at}: {name} literals"
            );
            assert_eq!(
                plain.records, other.records,
                "{what} from bit {at}: {name} records"
            );
            assert_eq!(
                plain.parked_at, other.parked_at,
                "{what} from bit {at}: {name} parked"
            );
            assert_eq!(
                plain
                    .failure
                    .as_ref()
                    .map(|err| format!("{:?}", err.kind())),
                other
                    .failure
                    .as_ref()
                    .map(|err| format!("{:?}", err.kind())),
                "{what} from bit {at}: {name} failure"
            );
        }
        assert_eq!(
            ops(&plain),
            ops(&batched),
            "{what} from bit {at}: operations"
        );
        assert_eq!(
            plain.verbatim, batched.verbatim,
            "{what} from bit {at}: literals"
        );
        assert_eq!(
            plain.records, batched.records,
            "{what} from bit {at}: records"
        );
        assert_eq!(
            plain.parked_at, batched.parked_at,
            "{what} from bit {at}: parked"
        );
        assert_eq!(
            plain
                .failure
                .as_ref()
                .map(|err| format!("{:?}", err.kind())),
            batched
                .failure
                .as_ref()
                .map(|err| format!("{:?}", err.kind())),
            "{what} from bit {at}: failure"
        );
        literals += plain.verbatim.len();
        match plain.parked_at {
            // A park always moves forward, or the resume would never end.
            Some(next) if next > at => at = next,
            Some(next) => panic!("{what}: parked at {next} from {at}"),
            None => return literals,
        }
    }
}

/// THE CAP-FREE ADMISSION AT ITS EDGE. One-bit codes are the fastest a
/// block can fill a tape: a block of nothing but symbol 257 at one bit
/// pushes one operation a bit. With exactly `CAP_FREE_BITS` symbol bits
/// the block is admitted and the checked loop, too, decodes it whole; one
/// bit more and it is refused, and the checked loop parks on its last
/// symbol, so the bound is the tightest one that holds.
#[cfg(feature = "parallel")]
#[test]
fn the_cap_free_admission_is_exact_at_its_edge() {
    use super::tape::{self, BlockTape, Plan, CAP_FREE_BITS};
    use super::vectors::BlockBuilder;
    for extra in [0usize, 1] {
        let symbols = CAP_FREE_BITS + extra;
        let mut builder = BlockBuilder::default().with_main(&[65, 257], 1);
        for _ in 0..symbols {
            builder.repeat_last();
        }
        let packed = builder.finish(true, true);
        let mut plan = Plan::default();
        tape::plan(&packed, false, &mut plan).unwrap();
        let (tables, from, _) = tape::batch::tables_of(&plan, &packed, 0, 0).unwrap();
        let block = &plan.blocks[0];
        assert_eq!(block.bits() - from, symbols, "the block's symbol bits");
        assert_eq!(
            tape::cap_free(block, from),
            extra == 0,
            "{symbols}: admitted"
        );
        let mut admitted = BlockTape::default();
        tape::decode_block_tape(&tables, &packed, block, from, &mut admitted);
        assert!(admitted.failure.is_none());
        if extra == 0 {
            assert_eq!(admitted.parked_at, None);
            assert_eq!(admitted.steps.len(), symbols);
        } else {
            assert_eq!(admitted.parked_at, Some(from + CAP_FREE_BITS));
            assert_eq!(admitted.steps.len(), CAP_FREE_BITS);
        }
        the_batch_agrees(&tables, &packed, block, from, "the edge");
    }
}

/// A fresh match whose distance is the ladder's `2^32`, slot 63 with
/// every extra bit set (section 3.5), is one more than a tape operation's
/// 32 bits hold. Each of the tape's symbol loops must stop AT that match,
/// with every symbol before it taken and none after, so that the serial
/// reader takes the block up from the match's first bit.
#[cfg(all(feature = "parallel", target_pointer_width = "64"))]
#[test]
fn a_distance_past_u32_parks_at_the_match_in_every_loop() {
    use super::tape::{self, BlockTape, Plan};
    use super::vectors::BlockBuilder;
    let mut builder = BlockBuilder::default().with_main(&[65, 66, 262], 2);
    for _ in 0..200 {
        builder.literal(65);
    }
    let (_, match_at) = builder.body_bits();
    builder.fresh(0, 0, 63, (1 << 30) - 1);
    for _ in 0..200 {
        builder.literal(66);
    }
    let packed = builder.finish(true, true);
    let mut plan = Plan::default();
    tape::plan(&packed, false, &mut plan).unwrap();
    let (tables, from, _) = tape::batch::tables_of(&plan, &packed, 0, 0).unwrap();
    let block = &plan.blocks[0];
    assert!(tape::cap_free(block, from), "admitted, so the region runs");
    // Not `the_batch_agrees`, which follows a park by decoding again from
    // it: a tape decode can never pass a match it parks on, and the serial
    // path is what finishes such a block.
    let mut tapes: [BlockTape; 4] = Default::default();
    tape::decode_block_tape(&tables, &packed, block, from, &mut tapes[0]);
    tape::decode_block_tape_checked(&tables, &packed, block, from, &mut tapes[1]);
    tape::batch::decode_block_tape_batched(&tables, &packed, block, from, &mut tapes[2]);
    tape::batch::decode_block_tape_batched_checked(&tables, &packed, block, from, &mut tapes[3]);
    let names = ["admitted", "checked", "batched", "batched checked"];
    for (name, tape) in names.iter().zip(&tapes) {
        assert!(tape.failure.is_none(), "{name}: no failure");
        assert_eq!(
            tape.parked_at,
            Some(from + match_at),
            "{name}: the match's first bit"
        );
        assert_eq!(tape.verbatim[..200], [65u8; 200][..], "{name}: literals");
        let ops: Vec<(u32, usize)> = tape
            .steps
            .iter()
            .map(|op| (op.kind(), op.prefix()))
            .collect();
        assert_eq!(ops, [(tape::tape_kind::LITS, 200)], "{name}: operations");
    }
}

/// A LITERAL RUN TOO LONG FOR A PREFIX (the sequence op):
/// 10,000 literals before a
/// match leave their head in a `LITS` operation of `PREFIX_MAX` and fold
/// the rest into the match, in all four loops alike, and the tape applies
/// to the bytes the stream means. (A test build's caps keep a block this
/// long out of the fast region; its cold call is held to the same tape by
/// `the_region_cold_call_writes_what_push_after_writes`.)
#[test]
fn a_run_past_the_prefix_folds_its_tail_in_every_loop() {
    use super::output::{NoFilters, Window};
    use super::tape::{self, tape_kind, BlockTape, Plan, PREFIX_MAX};
    use super::vectors::BlockBuilder;
    let mut builder = BlockBuilder::default().with_main(&[65, 66, 262], 2);
    let long = 10_000usize;
    for _ in 0..long {
        builder.literal(65);
    }
    // Length slot 0 (two bytes), distance slot 3 (distance 4, no extra).
    builder.fresh(0, 0, 3, 0);
    for _ in 0..3 {
        builder.literal(66);
    }
    builder.fresh(0, 0, 3, 0);
    for _ in 0..300 {
        builder.literal(65);
    }
    let packed = builder.finish(true, true);
    let mut plan = Plan::default();
    tape::plan(&packed, false, &mut plan).unwrap();
    let (tables, from, _) = tape::batch::tables_of(&plan, &packed, 0, 0).unwrap();
    let block = &plan.blocks[0];
    let mut tapes: [BlockTape; 4] = Default::default();
    tape::decode_block_tape(&tables, &packed, block, from, &mut tapes[0]);
    tape::decode_block_tape_checked(&tables, &packed, block, from, &mut tapes[1]);
    tape::batch::decode_block_tape_batched(&tables, &packed, block, from, &mut tapes[2]);
    tape::batch::decode_block_tape_batched_checked(&tables, &packed, block, from, &mut tapes[3]);
    let head = long / PREFIX_MAX;
    let mut want = vec![(tape_kind::LITS, PREFIX_MAX, 0); head];
    want.push((tape_kind::MATCH, long - head * PREFIX_MAX, 2));
    want.push((tape_kind::MATCH, 3, 2));
    want.push((tape_kind::LITS, 300, 0));
    let names = ["admitted", "checked", "batched", "batched checked"];
    for (name, t) in names.iter().zip(&tapes) {
        assert!(
            t.failure.is_none() && t.parked_at.is_none(),
            "{name}: whole"
        );
        let ops: Vec<(u32, usize, usize)> = t
            .steps
            .iter()
            .map(|op| (op.kind(), op.prefix(), op.length()))
            .collect();
        if tape::fold() {
            assert_eq!(ops, want, "{name}: operations");
        }
        assert_eq!(
            t.verbatim[..long + 303],
            tapes[0].verbatim[..long + 303],
            "{name}: literals"
        );
    }
    // The bytes: the run, "AA" from four back, "BBB", "AB" from four back
    // (the last "A" and the first "B"), and the last run.
    let mut expected = vec![65u8; long + 2];
    expected.extend_from_slice(b"BBBAB");
    expected.extend(std::iter::repeat_n(65u8, 300));
    for (name, t) in names.iter().zip(&tapes) {
        let mut window = Window::new(1 << 20, u64::MAX).unwrap();
        window.reset();
        let mut state = super::MatchState::default();
        let mut filters = super::filters::Filters::default();
        let mut sink: Vec<u8> = Vec::new();
        tape::apply(
            t,
            &mut state,
            &mut window,
            &mut filters,
            expected.len() as u64,
            &mut sink,
        )
        .unwrap();
        window.drain(&mut sink, &mut NoFilters, true).unwrap();
        assert_eq!(sink, expected, "{name}: bytes");
    }
}

/// The fast region's cold call ([`super::tape::make_room`]) and the
/// cursor write after it build, for every run length about the prefix's
/// edges and past two of them, exactly the operations `push_after` pushes,
/// so a region and a checked loop cannot write different tapes for one
/// run; and a room reopened for the long run is whole (two slots at least).
#[test]
fn the_region_cold_call_writes_what_push_after_writes() {
    use super::tape::{self, tape_kind, TapeOp, PREFIX_MAX};
    let op = TapeOp::new(tape_kind::MATCH, 5, 77);
    for run in [
        0,
        1,
        PREFIX_MAX - 1,
        PREFIX_MAX,
        PREFIX_MAX + 1,
        2 * PREFIX_MAX,
        2 * PREFIX_MAX + 1,
        3 * PREFIX_MAX + 17,
    ] {
        let seen = |ops: &[TapeOp]| -> Vec<(u32, usize, usize, u32)> {
            ops.iter()
                .map(|o| (o.kind(), o.prefix(), o.length(), o.distance))
                .collect()
        };
        let mut pushed = vec![TapeOp::lits(3)];
        tape::push_after(&mut pushed, true, run, op);
        let mut region = vec![TapeOp::lits(3)];
        let mut end = region.len();
        let (cursor, left) = tape::make_room(&mut region, 1, &mut end, run);
        assert!(cursor.len() >= 2, "run {run}: room for a control symbol");
        let rest = tape::put_op(cursor, true, left, op).len();
        let written = end - rest;
        region.truncate(written);
        assert_eq!(seen(&region), seen(&pushed), "run {run}");
    }
}

/// THE LADDERS AS BASES (lever 4 of the fresh match): the fast region
/// reads a length as `LENGTH_SLOT_BASE[slot] + extra` and a distance of a
/// slot under 30 extra bits as `DISTANCE_SLOT_BASE[slot] + extra + 1`.
/// Both are the ladders of section 3.5 for every slot and every extra
/// value at its edges.
#[test]
fn the_ladder_bases_are_the_ladders() {
    use super::ladders::{
        distance_named, length_from_slot, DISTANCE_SLOT_BASE, DISTANCE_SLOT_BITS, LENGTH_SLOTS,
        LENGTH_SLOT_BASE, LENGTH_SLOT_EXTRA_BITS,
    };
    for slot in 0..LENGTH_SLOTS {
        let top = (1u32 << LENGTH_SLOT_EXTRA_BITS[slot]) - 1;
        for extra in [0, top / 2, top] {
            assert_eq!(
                (LENGTH_SLOT_BASE[slot] + extra) as usize,
                length_from_slot(slot, extra),
                "length slot {slot} extra {extra}"
            );
        }
    }
    for slot in 0..62 {
        let bits = DISTANCE_SLOT_BITS[slot];
        assert!(bits < 30, "slot {slot} is read by its base");
        let top = (1u32 << bits) - 1;
        for extra in [0, top / 2, top] {
            assert_eq!(
                (DISTANCE_SLOT_BASE[slot] + extra) as usize + 1,
                distance_named(slot, extra),
                "distance slot {slot} extra {extra}"
            );
        }
    }
    assert!(DISTANCE_SLOT_BITS[62] >= 30, "slot 62 takes the far path");
}

/// AN EMPTY SIDE TABLE INSIDE THE FAST REGION (lever 4 of the fresh match):
/// the region reads the distance, alignment and length tables through
/// `region_lookup` with no `empty` test, an empty table through the shared
/// all-miss lookup, and the symbol that reads one still fails with
/// `EmptyTable`, at the same point and with the same tape as the checked
/// loops. Each table is emptied in its own block, the symbol that reads it
/// well inside the region.
#[cfg(feature = "parallel")]
#[test]
fn an_empty_side_table_fails_in_the_region_as_in_every_loop() {
    use super::tape::{self, BlockTape, Plan};
    use super::vectors::BlockBuilder;
    for which in ["distance", "align", "length"] {
        let control = if which == "length" { 258 } else { 262 };
        let mut builder = BlockBuilder::default().with_main(&[65, control], 1);
        match which {
            "distance" => builder.distance = vec![0; 64],
            "align" => builder = builder.with_align_lengths(&[0; 16]),
            _ => builder.length = vec![0; builder.length.len()],
        }
        for _ in 0..200 {
            builder.literal(65);
        }
        match which {
            // A distance slot of eight extra bits, so the alignment table
            // is read; with it empty the extras go plain, which the
            // decoder never reaches.
            "align" => builder.fresh(0, 0, 20, 0x35),
            // The control symbol's one bit code, then nothing it can read.
            _ => builder.raw(1, 1),
        }
        for _ in 0..400 {
            builder.raw(0, 1);
        }
        let packed = builder.finish(true, true);
        let mut plan = Plan::default();
        tape::plan(&packed, false, &mut plan).unwrap();
        let (tables, from, _) = tape::batch::tables_of(&plan, &packed, 0, 0).unwrap();
        let block = &plan.blocks[0];
        assert!(tape::cap_free(block, from), "{which}: admitted");
        let mut admitted = BlockTape::default();
        tape::decode_block_tape(&tables, &packed, block, from, &mut admitted);
        assert_eq!(
            admitted
                .failure
                .as_ref()
                .map(|err| format!("{:?}", err.kind())),
            Some(format!("{:?}", super::fault::empty_table().kind())),
            "{which}: EmptyTable"
        );
        assert_eq!(admitted.verbatim.len() - super::output::STRIDE_MAX, 200);
        the_batch_agrees(&tables, &packed, block, from, which);
    }
}

/// Decode block `index` by the control's `decode_one` and by the batch module's
/// own `decode_one` (the dispatch every caller reaches on aarch64) and
/// assert the two answer the same set and the same tape, on every target.
#[cfg(feature = "parallel")]
fn the_dispatch_agrees(
    plan: &super::tape::Plan,
    packed: &[u8],
    algorithm: u8,
    index: usize,
    what: &str,
) {
    use super::tape::{self, BlockTape};
    let ops = |tape: &BlockTape| -> Vec<(u32, usize, usize, u32)> {
        tape.steps
            .iter()
            .map(|op| (op.kind(), op.prefix(), op.length(), op.distance))
            .collect()
    };
    let mut plain = BlockTape::default();
    let mut dispatched = BlockTape::default();
    let held_plain = tape::decode_one(plan, packed, algorithm, None, index, &mut plain);
    let held_dispatched =
        tape::batch::decode_one(plan, packed, algorithm, None, index, &mut dispatched);
    assert_eq!(
        held_plain.is_some(),
        held_dispatched.is_some(),
        "{what}: held"
    );
    assert_eq!(ops(&plain), ops(&dispatched), "{what}: operations");
    assert_eq!(plain.verbatim, dispatched.verbatim, "{what}: literals");
    assert_eq!(plain.records, dispatched.records, "{what}: records");
    assert_eq!(plain.parked_at, dispatched.parked_at, "{what}: parked");
    assert_eq!(
        plain
            .failure
            .as_ref()
            .map(|err| format!("{:?}", err.kind())),
        dispatched
            .failure
            .as_ref()
            .map(|err| format!("{:?}", err.kind())),
        "{what}: failure"
    );
}

/// A random main table with `eights` length-8 literals among the rest, the
/// other symbols at random lengths the Kraft sum allows, and some left out
/// so the table is incomplete. Symbol 262 always has a code.
#[cfg(feature = "parallel")]
fn batch_table(rng: &mut rarkit_testdata::Seeded, eights: usize) -> Vec<u8> {
    let mut main = vec![0u8; super::tables::MAIN_SYMBOLS];
    let mut order: Vec<usize> = (0..256).collect();
    for i in (1..order.len()).rev() {
        order.swap(i, rng.below(i as u64 + 1) as usize);
    }
    // Space is counted in units of 2^-15.
    let mut space: i64 = 1 << 15;
    for &symbol in &order[..eights] {
        main[symbol] = 8;
        space -= 1 << 7;
    }
    let mut rest: Vec<usize> = order[eights..].to_vec();
    rest.extend(256..super::tables::MAIN_SYMBOLS);
    for i in (1..rest.len()).rev() {
        rest.swap(i, rng.below(i as u64 + 1) as usize);
    }
    // 262 first, so it always fits.
    if let Some(at) = rest.iter().position(|&s| s == 262) {
        rest.swap(0, at);
    }
    for &symbol in &rest {
        if symbol != 262 && rng.chance(80) {
            continue;
        }
        let length = 5 + rng.below(11) as u8;
        let cost = 1i64 << (15 - length);
        if cost <= space {
            main[symbol] = length;
            space -= cost;
        } else if space > 0 {
            main[symbol] = 15;
            space -= 1;
        }
    }
    main
}

/// THE BATCH IS THE SCALAR DECODE, on random tables of every shape: every
/// count of length-8 literals across the gate, shorter and longer codes
/// among them, long literal runs past the tape's cap (parks and resumes),
/// matches, repeats, incomplete tables hit in their holes, and damaged
/// payloads. Every block is decoded both ways whether or not the gate
/// admits its table, so the batch is tested on shapes it never sees too.
#[cfg(feature = "parallel")]
#[test]
fn the_literal_batch_is_the_scalar_decode_on_random_tables() {
    use super::tape::{self, Plan};
    use super::vectors::BlockBuilder;
    let mut rng = rarkit_testdata::Seeded::new(0x6c69_7462_6174_6368);
    let mut literals = 0usize;
    let mut admitted = 0usize;
    for case in 0..240 {
        let eights = [0, 128, 191, 192, 200, 239, 240, 248, 250, 255][case % 10];
        let mut builder = BlockBuilder::default();
        builder.main = batch_table(&mut rng, eights);
        let coded: Vec<usize> = (0..256).filter(|&s| builder.main[s] != 0).collect();
        let eight: Vec<usize> = coded
            .iter()
            .copied()
            .filter(|&s| builder.main[s] == 8)
            .collect();
        let symbols = if case % 3 == 0 { 40_000 } else { 3_000 };
        for _ in 0..symbols {
            let roll = rng.below(1000);
            if roll < 8 {
                builder.fresh(0, 0, rng.below(6) as usize, 0);
            } else if !eight.is_empty() && roll < 900 {
                builder.literal(eight[rng.below(eight.len() as u64) as usize] as u8);
            } else if !coded.is_empty() {
                builder.literal(coded[rng.below(coded.len() as u64) as usize] as u8);
            }
        }
        let mut packed = builder.finish(true, true);
        if case % 7 == 3 {
            // Damage: flip bytes in the back half, where symbols live.
            let len = packed.len();
            for _ in 0..4 {
                let at = len / 2 + rng.below((len / 2) as u64) as usize;
                packed[at] ^= 1 + rng.below(255) as u8;
            }
        }
        let mut plan = Plan::default();
        if tape::plan(&packed, false, &mut plan).is_err() {
            continue;
        }
        for index in 0..plan.blocks.len() {
            let Ok((tables, from, batch)) = tape::batch::tables_of(&plan, &packed, 0, index) else {
                continue;
            };
            admitted += usize::from(batch);
            let what = format!("case {case} ({eights} eights) block {index}");
            literals += the_batch_agrees(&tables, &packed, &plan.blocks[index], from, &what);
            the_dispatch_agrees(&plan, &packed, 0, index, &what);
        }
    }
    assert!(admitted >= 100, "only {admitted} blocks admitted");
    assert!(literals >= 1_000_000, "only {literals} literals decoded");
}

/// The same on every block of every archive of section 5.2, and the
/// batch's own `decode_one` (the dispatch every caller reaches on
/// aarch64) answers exactly as the control's `decode_one` does, on every target,
/// whether or not the gate admitted the set.
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
#[test]
fn the_literal_batch_is_the_scalar_decode_on_every_archive() {
    use super::tape::{self, Plan};
    let mut blocks = 0usize;
    let mut admitted = 0usize;
    for stem in ARCHIVES {
        let data = archive(stem);
        for member in members(&data) {
            if member.directory || member.method == 0 {
                continue;
            }
            let mut plan = Plan::default();
            if tape::plan(&member.packed, false, &mut plan).is_err() {
                continue;
            }
            for index in 0..plan.blocks.len() {
                let Ok((tables, from, batch)) =
                    tape::batch::tables_of(&plan, &member.packed, member.algorithm, index)
                else {
                    continue;
                };
                admitted += usize::from(batch);
                let what = format!("{stem} {} block {index}", member.name);
                the_batch_agrees(&tables, &member.packed, &plan.blocks[index], from, &what);
                the_dispatch_agrees(&plan, &member.packed, member.algorithm, index, &what);
                blocks += 1;
            }
        }
    }
    assert!(blocks >= 40, "only {blocks} blocks walked");
    // How many of the corpus's blocks the gate admitted, for the record;
    // the random-table test is what proves the admitted arm of the
    // dispatch, with at least 100 admitted blocks.
    eprintln!("the literal batch: {admitted} of {blocks} archive blocks admitted");
}
