//! SPEC-API 8.2: the RAR 5 tape decode's lanes take TAPE
//! UNITS, runs of consecutive blocks whose packed bytes stay within one
//! block's per-tape cap, and a unit is scheduling only.
//!
//! The reference archives of spec H's vectors carry blocks of about 16 KiB,
//! the shape a reference writer gives media-like input, so a member of
//! several such blocks decodes in multi-block units at the shipped bound.
//! Every unit size must give the per-block form's bytes and error kind.

use rarkit::internals::rar5;

fn vector(stem: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../specs/vectors-H/archives/{stem}.rar",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Every RAR 5 vector archive of spec H, by stem.
fn stems() -> Vec<String> {
    let dir = format!(
        "{}/../../specs/vectors-H/archives",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut out: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{dir}: {e}"))
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().into_string().ok()?;
            let stem = name.strip_suffix(".rar")?.to_string();
            stem.starts_with("h5_").then_some(stem)
        })
        .collect();
    out.sort();
    out
}

/// The shipped bound, restated so a change to it is a change to this test.
const SHIPPED: usize = 64 << 10;

#[test]
fn units_tile_every_chain_and_a_small_block_member_takes_several_blocks_a_unit() {
    let mut widest_seen = 0;
    let mut members = 0;
    for stem in stems() {
        let data = vector(&stem);
        for member in rar5::members(&data) {
            if member.method == 0 || member.packed.is_empty() {
                continue;
            }
            let Ok((blocks, per_block, widest_one)) = rar5::tape_units(&member.packed, 0) else {
                continue;
            };
            members += 1;
            // A budget of nothing gives one block a unit: the per-block form.
            assert_eq!(
                per_block, blocks,
                "{stem}: budget 0 must give a unit per block"
            );
            assert_eq!(widest_one, 1.min(blocks), "{stem}");
            let (_, units, widest) = rar5::tape_units(&member.packed, SHIPPED).unwrap();
            // A unit holds at most four blocks, whatever their size.
            assert!(widest <= 4, "{stem}: a unit of {widest} blocks");
            assert!(
                units >= 1 && units <= blocks,
                "{stem}: {units} units for {blocks} blocks"
            );
            widest_seen = widest_seen.max(widest);
        }
    }
    assert!(
        members >= 10,
        "only {members} compressed members among the vectors"
    );
    assert!(
        widest_seen >= 2,
        "no vector member took more than one block a unit; the test has no teeth"
    );
}

#[test]
fn every_unit_size_gives_the_per_block_bytes() {
    let mut compared = 0;
    let mut multi_block = 0;
    for stem in stems() {
        let data = vector(&stem);
        for member in rar5::members(&data) {
            if member.method == 0 || member.solid || member.directory {
                continue;
            }
            let decode = |width: usize, unit: Option<usize>| {
                rar5::decode_member_units(
                    &member.packed,
                    member.unpacked,
                    member.window,
                    member.algorithm,
                    width,
                    unit,
                )
                .map_err(|e| format!("{:?}", e.kind()))
            };
            let per_block = decode(4, Some(0));
            // Counted at two lanes: the lane floor leaves a short chain
            // one block a unit at wider widths.
            if let Ok((blocks, units, _)) = rar5::tape_units_for_lanes(&member.packed, SHIPPED, 2) {
                if units < blocks {
                    multi_block += 1;
                }
            }
            for width in [2usize, 4] {
                for unit in [
                    Some(0),
                    Some(8 << 10),
                    Some(32 << 10),
                    None,
                    Some(usize::MAX),
                ] {
                    let got = decode(width, unit);
                    assert!(
                        got == per_block,
                        "{stem} {}: width {width}, unit {unit:?} differs from the per-block form",
                        member.name
                    );
                    compared += 1;
                }
            }
        }
    }
    assert!(compared >= 50, "only {compared} decodes compared");
    assert!(
        multi_block >= 1,
        "no member decoded in multi-block units at the shipped bound"
    );
}

/// A unit must never cost a chunk a lane: however the shipped bound cuts
/// the chain, the lanes it may open get at least the units one block a
/// unit would give them, and a cut that has that many is kept as it is.
#[test]
fn a_unit_never_leaves_a_chunk_fewer_lanes_than_one_block_a_unit() {
    let mut floored = 0;
    let mut kept_merged = 0;
    for stem in stems() {
        let data = vector(&stem);
        for member in rar5::members(&data) {
            if member.method == 0 || member.packed.is_empty() {
                continue;
            }
            let Ok((blocks, merged, _)) = rar5::tape_units(&member.packed, SHIPPED) else {
                continue;
            };
            for lanes in [2usize, 4, 16] {
                let (_, units, widest) =
                    rar5::tape_units_for_lanes(&member.packed, SHIPPED, lanes).unwrap();
                let floor = lanes.min(blocks);
                assert!(
                    units >= floor,
                    "{stem}: {units} units for {lanes} lanes over {blocks} blocks"
                );
                if merged >= floor {
                    assert_eq!(
                        units, merged,
                        "{stem}: a cut with units to spare was changed"
                    );
                    if units < blocks {
                        kept_merged += 1;
                    }
                } else {
                    assert_eq!(
                        (units, widest),
                        (blocks, 1),
                        "{stem}: a floored cut must be one block a unit"
                    );
                    floored += 1;
                }
            }
        }
    }
    assert!(
        floored >= 1,
        "no vector member met the lane floor; the test has no teeth"
    );
    assert!(
        kept_merged >= 1,
        "no vector member kept a multi-block cut under the floor"
    );
}
