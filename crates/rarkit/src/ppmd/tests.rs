//! Unit vectors derived from spec I, not stored (spec I section 5), and the
//! arena's own invariants, which no committed vector reaches: the three
//! archives that exhaust the arena (`i14`, `i15`, `i16`) are not committed
//! and need the genuine rar 4.2.0 package to regenerate.

use super::arena::{Arena, BASE, UNIT};
use super::model::Model;
use super::tables::{BIN_CLASS, CLASS_OF, ESC_CLASS, UNITS_OF};
use super::{record_extra, record_length};

#[test]
fn class_table_matches_the_units_table() {
    for (u, &class) in CLASS_OF.iter().enumerate().skip(1) {
        let k = class as usize;
        assert!(UNITS_OF[k] as usize >= u, "class {k} holds {u} units");
        assert!(
            k == 0 || (UNITS_OF[k - 1] as usize) < u,
            "class {k} is least"
        );
    }
    // Steps of 1, 2, 3, then 4, four classes per step up to 24 units.
    let steps: Vec<u8> = UNITS_OF.windows(2).map(|w| w[1] - w[0]).collect();
    assert_eq!(&steps[..3], &[1, 1, 1]);
    assert_eq!(&steps[3..7], &[2, 2, 2, 2]);
    assert_eq!(&steps[7..11], &[3, 3, 3, 3]);
    assert!(steps[11..].iter().all(|&s| s == 4));
    assert_eq!(UNITS_OF[UNITS_OF.len() - 1], 128);
}

#[test]
fn escape_and_binary_classes_match_the_spec_table() {
    assert_eq!(BIN_CLASS[0], 0);
    assert_eq!(BIN_CLASS[1], 2);
    assert!(BIN_CLASS[2..=10].iter().all(|&v| v == 4));
    assert!(BIN_CLASS[11..].iter().all(|&v| v == 6));
    for (indices, value) in [
        (0..1, 0u8),
        (1..2, 1),
        (2..3, 2),
        (3..4, 3),
        (4..6, 4),
        (6..9, 5),
        (9..13, 6),
        (13..18, 7),
        (18..24, 8),
        (24..31, 9),
        (31..39, 10),
        (39..48, 11),
        (48..58, 12),
        (58..69, 13),
        (69..81, 14),
        (81..94, 15),
        (94..108, 16),
        (108..123, 17),
        (123..139, 18),
        (139..156, 19),
        (156..174, 20),
        (174..193, 21),
        (193..213, 22),
        (213..234, 23),
        (234..256, 24),
    ] {
        for i in indices {
            assert_eq!(ESC_CLASS[i], value, "esc_class[{i}]");
        }
    }
}

/// The regions a model start lays out (spec I 3.4 and section 5).
#[test]
fn a_model_start_lays_out_the_regions_the_spec_states() {
    for mb in [1u32, 8, 25, 128] {
        let size = mb << 20;
        let mut model = Model::new();
        model.reserve(size);
        model.start(8);
        let a = &model.arena;
        assert_eq!(a.text_top, BASE);
        assert_eq!(a.units_floor, BASE + size - 84 * (size / 96));
        // The root took one unit from the top and 128 units from the bottom.
        assert_eq!(a.gap_hi, BASE + size - UNIT);
        assert_eq!(a.gap_lo, a.units_floor + 128 * UNIT);
        assert!(a.free_blocks().is_empty(), "every class starts empty");
        let root = a.gap_hi;
        assert_eq!(a.count(root), 256);
        assert_eq!(a.total(root), 257);
        assert_eq!(a.parent(root), 0);
        let array = a.array(root);
        for i in 0..256u32 {
            let s = array + i * 6;
            assert_eq!(a.sym(s), i as u8);
            assert_eq!(a.freq(s), 1);
            assert_eq!(a.succ(s), 0);
        }
    }
    let mut model = Model::new();
    model.reserve(1 << 20);
    model.start(8);
    assert_eq!(model.arena.units_floor, BASE + 131_128);
    assert_eq!(model.starts, 1);
}

/// Spec I 3.4.2: the allocator hands out blocks that never overlap, always
/// inside the unit region, and gives every byte back.
#[test]
fn the_allocator_never_hands_out_overlapping_blocks() {
    let size = 1u32 << 20;
    let mut arena = Arena::new();
    arena.reserve(size);
    arena.restart();
    // Stand in for the root, which the model would have taken.
    let mut live: Vec<(u32, u32)> = Vec::new();
    let mut rng = rarkit_testdata::Seeded::new(0x5EED_1234_ABCD_0001);
    let mut exhausted = 0u32;

    let check = |arena: &Arena, live: &[(u32, u32)]| {
        let mut all: Vec<(u32, u32)> = live.to_vec();
        all.extend(arena.free_blocks());
        all.sort_unstable();
        for w in all.windows(2) {
            assert!(
                w[0].0 + UNIT * w[0].1 <= w[1].0,
                "blocks {:?} and {:?} overlap",
                w[0],
                w[1]
            );
        }
        for &(pos, units) in &all {
            assert!(pos >= arena.units_floor, "{pos} is below the unit region");
            assert!(
                pos + UNIT * units <= BASE + arena.size(),
                "{pos} runs past the arena"
            );
            assert!(
                pos + UNIT * units <= arena.gap_lo || pos >= arena.gap_hi,
                "{pos} overlaps the untouched gap"
            );
        }
        assert!(arena.units_floor > arena.text_top);
    };

    for round in 0..40_000 {
        if round % 997 == 0 {
            arena.arm_glue();
        }
        let take_one = live.is_empty() || rng.index(3) != 0;
        if take_one {
            let wide = rng.index(4) == 0;
            let class = rng.index(if wide { 38 } else { 12 });
            let as_context = rng.index(8) == 0;
            let got = if as_context {
                arena.take_context()
            } else {
                arena.take(class)
            };
            match got {
                Some(pos) => {
                    // A context is always one unit, whatever class was asked.
                    let units = if as_context {
                        1
                    } else {
                        u32::from(UNITS_OF[class])
                    };
                    // Mark it in use so a merge cannot swallow it.
                    arena.set_u16(pos, 0xBEEF);
                    live.push((pos, units));
                }
                None => exhausted += 1,
            }
        } else {
            let at = rng.index(live.len());
            let (pos, units) = live.swap_remove(at);
            let class = CLASS_OF[units as usize] as usize;
            assert_eq!(
                u32::from(UNITS_OF[class]),
                units,
                "a block of a whole class"
            );
            arena.give(pos, class);
        }
        if round % 64 == 0 {
            check(&arena, &live);
        }
    }
    check(&arena, &live);
    assert!(exhausted > 0, "the stress run never reached exhaustion");
}

/// Drain the untouched gap one unit at a time, so the next allocation has
/// to go through `rare`.
fn drain_gap(arena: &mut Arena) -> Vec<u32> {
    let mut blocks = Vec::new();
    while arena.gap_hi != arena.gap_lo {
        blocks.push(arena.take(0).expect("the gap serves a single unit"));
    }
    blocks
}

/// Spec I 3.4.4: glue merges physically adjacent free blocks, and the units
/// it re-files add up to the units it was given.
#[test]
fn glue_merges_adjacent_blocks_and_conserves_units() {
    let size = 1u32 << 20;
    let mut arena = Arena::new();
    arena.reserve(size);
    arena.restart();
    let blocks = drain_gap(&mut arena);
    for (i, b) in blocks.iter().take(12).enumerate() {
        assert_eq!(
            *b,
            blocks[0] + UNIT * i as u32,
            "the gap hands out in order"
        );
    }
    // Free twelve adjacent units, out of order, and nothing else.
    for i in [1usize, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10] {
        arena.give(blocks[i], 0);
    }
    assert_eq!(arena.free_blocks().len(), 12);
    // Class 7 holds 12 units: only a merge of all twelve can serve it.
    arena.arm_glue();
    let merged = arena.take(7).expect("the merged run serves the request");
    assert_eq!(merged, blocks[0]);
    assert_eq!(u32::from(UNITS_OF[7]), 12);
    assert!(
        arena.free_blocks().is_empty(),
        "the merge left no remainder"
    );
    assert_eq!(arena.units_floor + 12 * UNIT, blocks[12], "no borrowing");
}

/// A merge splits what it cannot file whole, and never runs into a block
/// that is in use.
#[test]
fn glue_stops_at_a_block_in_use() {
    let size = 1u32 << 20;
    let mut arena = Arena::new();
    arena.reserve(size);
    arena.restart();
    let blocks = drain_gap(&mut arena);
    // Free 0..5 and 6..11, keeping 5 in use between them.
    for i in (0..5).chain(6..11) {
        arena.give(blocks[i], 0);
    }
    arena.set_u16(blocks[5], 0x1234);
    arena.arm_glue();
    // Class 4 holds 6 units; neither run of five can serve it.
    assert!(arena.take(4).is_none() || arena.units_floor < blocks[0]);
    let free: Vec<(u32, u32)> = arena.free_blocks();
    let total: u32 = free.iter().map(|&(_, u)| u).sum();
    assert!(total <= 10, "units are never invented");
}

/// Spec I 7.3 item 2: a restart rewrites the scalars, the free-list heads,
/// the root and the tables, and frees or allocates nothing.
#[test]
fn a_restart_resets_in_place() {
    let mut model = Model::new();
    model.reserve(1 << 20);
    model.start(16);
    let held = model.held_bytes();
    let (floor, hi) = (model.arena.units_floor, model.arena.gap_hi);
    for _ in 0..500 {
        let _ = model.arena.take(3);
    }
    model.arena.text_top += 4096;
    model.start(16);
    assert_eq!(model.held_bytes(), held, "a restart holds the same memory");
    assert_eq!(model.arena.units_floor, floor);
    assert_eq!(model.arena.gap_hi, hi, "the root comes off the top again");
    assert_eq!(model.arena.text_top, BASE);
    assert!(model.arena.free_blocks().is_empty());
    assert_eq!(model.starts, 2, "one start, one restart");
}

/// Spec I 3.3, escape code 3: the three length encodings a record's first
/// byte selects. No genuine archive carries one (rar 4.2.0 chose LZ blocks
/// for every filter this project could make it write), so this is the only
/// check the framing gets beside the fuzz targets.
#[test]
fn a_filter_record_frames_the_lengths_the_spec_states() {
    for flags in 0..=255u8 {
        let short = u32::from(flags & 7) + 1;
        match short {
            7 => {
                assert_eq!(record_extra(flags), 1);
                assert_eq!(record_length(flags, [0, 0]), 7);
                assert_eq!(record_length(flags, [255, 0]), 262);
            }
            8 => {
                assert_eq!(record_extra(flags), 2);
                assert_eq!(record_length(flags, [0, 0]), 0);
                assert_eq!(record_length(flags, [255, 255]), 65_535);
                assert_eq!(record_length(flags, [1, 2]), 258);
            }
            n => {
                assert_eq!(record_extra(flags), 0);
                assert!((1..=6).contains(&n));
                assert_eq!(record_length(flags, [7, 7]), n);
            }
        }
    }
}
