//! SPEC-L 3.7, "Where the reference's repair goes wrong": what rarkit's
//! own RAR 4 repair does on protected areas whose sectors are equal, or
//! repeat with a period.
//!
//! The record `specs/vectors-L/l-evidence/equal-sectors.txt` lists 26
//! archives and 207 repair arms put to the reference's `rar r`: one
//! stored member of 40 or 134 sectors laid on the 512 byte grid, an `RR`
//! record of 2, 4 or 6 parity sectors, and 100 changed bytes in each
//! sector an arm names. The reference rebuilds 178 of the 207 and does
//! NOT rebuild 29: every damaged arm where all 40 sectors are one value
//! that is not zero, or where the sectors cycle through four values (a
//! member whose bytes repeat every 2,048), and one two-sector arm on a
//! run of eight equal sectors. On those it exits 0, says "Done" and
//! writes a file short by whole sectors.
//!
//! Section 3.7's rule for rarkit is that it "rebuilds every one of these
//! archives", and this is the test that holds it to that, judged the way
//! the section says a repair is judged: BY THE OUTPUT'S BYTES against the
//! archive before the damage, never by an `Ok`.
//!
//! The archives are written by rarkit's own writer. With a member name
//! of 460 bytes the member's data begins at byte 512, which is the
//! record's own layout: the lengths, the protected lengths and the counts
//! of distinct sectors and distinct tags below are the record's `built`
//! lines, number for number. Each shape is then written a second time
//! under a short name, which is what a caller would make and which puts
//! the data 57 bytes off the grid, and the same arms are run on it.
//!
//! One thread: the writer is given one worker and the repair runs on the
//! test's own thread. Memory: the largest archive is 72,523 bytes, a
//! repair's working memory is the record's data area (`2n + 512r`, at
//! most 3,342 bytes here) and the policy below holds it to 1 MiB of
//! repair work inside a 64 MiB limit.

use std::collections::BTreeSet;

use rarkit::memory::MemoryPolicy;
use rarkit::{
    FilterPolicy, HostOs, MemberSpec, Payload, Rar4Version, ReadOptions, WriteFormat, WriteMethod,
    WriteOptions, Writer,
};

const SECTOR: usize = 512;

/// The sector whose every byte comes from `seed`: no two seeds give the
/// same sector, and none gives a sector of zeros.
fn sector(seed: u64) -> [u8; SECTOR] {
    let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ seed.wrapping_mul(0xD134_2543_DE82_EF95);
    let mut out = [0u8; SECTOR];
    for byte in &mut out {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state >> 24) as u8;
    }
    out
}

/// What the sectors of a member are. Sector numbers are the ARCHIVE's, as
/// in the record: sector 0 holds the headers and the member's first
/// sector is sector 1.
#[derive(Clone, Copy)]
enum Fill {
    /// Every sector its own value.
    Different,
    /// The listed sectors share one value that is not zero.
    Equal(&'static [usize]),
    /// The listed sectors are zeros.
    Zero(&'static [usize]),
    /// Every sector the same value, not zero.
    AllEqual,
    /// Every sector zeros.
    AllZero,
    /// The sectors cycle through four values: bytes repeating every 2,048.
    Cycle,
    /// Every fourth sector is one value, from the member's first (34 of
    /// the 134, by the record's count), the rest all different.
    EveryFourth,
}

struct Shape {
    what: &'static str,
    sectors: usize,
    fill: Fill,
    /// The count of parity sectors, and the writer's percentage that
    /// gives it at this size.
    parity: &'static [(usize, u32)],
    /// The record's `built` line: distinct sectors, which is also its
    /// count of distinct tags.
    distinct: usize,
    /// The damage arms, each a list of sectors.
    arms: &'static [&'static [usize]],
    /// The arms the record shows the reference NOT rebuilding, per parity
    /// count, as indexes into `arms`.
    reference_fails: &'static [(usize, &'static [usize])],
}

const FORTY: &[&[usize]] = &[
    &[],
    &[9],
    &[10],
    &[11],
    &[12],
    &[17],
    &[18],
    &[30],
    &[11, 20],
];
const CYCLE_FORTY: &[&[usize]] = &[&[], &[9], &[20], &[9, 20]];
const WIDE: &[&[usize]] = &[&[], &[9], &[58], &[130], &[9, 78]];
const TWO_AND_FOUR: &[(usize, u32)] = &[(2, 5), (4, 10)];
const EVERY_DAMAGED_FORTY: &[usize] = &[1, 2, 3, 4, 5, 6, 7, 8];

const SHAPES: &[Shape] = &[
    Shape {
        what: "all 40 different",
        sectors: 40,
        fill: Fill::Different,
        parity: TWO_AND_FOUR,
        distinct: 41,
        arms: FORTY,
        reference_fails: &[],
    },
    Shape {
        what: "sectors 10 and 30 equal, the rest different",
        sectors: 40,
        fill: Fill::Equal(&[10, 30]),
        parity: TWO_AND_FOUR,
        distinct: 40,
        arms: FORTY,
        reference_fails: &[],
    },
    Shape {
        what: "sectors 10, 16, 22, 28 and 34 equal, the rest different",
        sectors: 40,
        fill: Fill::Equal(&[10, 16, 22, 28, 34]),
        parity: TWO_AND_FOUR,
        distinct: 37,
        arms: FORTY,
        reference_fails: &[],
    },
    Shape {
        what: "sectors 10 and 11 equal, the rest different",
        sectors: 40,
        fill: Fill::Equal(&[10, 11]),
        parity: TWO_AND_FOUR,
        distinct: 40,
        arms: FORTY,
        reference_fails: &[],
    },
    Shape {
        what: "sectors 10 to 12 equal, the rest different",
        sectors: 40,
        fill: Fill::Equal(&[10, 11, 12]),
        parity: TWO_AND_FOUR,
        distinct: 39,
        arms: FORTY,
        reference_fails: &[],
    },
    Shape {
        what: "sectors 10 to 13 equal, the rest different",
        sectors: 40,
        fill: Fill::Equal(&[10, 11, 12, 13]),
        parity: TWO_AND_FOUR,
        distinct: 38,
        arms: FORTY,
        reference_fails: &[],
    },
    Shape {
        what: "sectors 10 to 17 equal, the rest different",
        sectors: 40,
        fill: Fill::Equal(&[10, 11, 12, 13, 14, 15, 16, 17]),
        parity: TWO_AND_FOUR,
        distinct: 34,
        arms: FORTY,
        reference_fails: &[(2, &[8])],
    },
    Shape {
        what: "all 40 equal and not zero",
        sectors: 40,
        fill: Fill::AllEqual,
        parity: TWO_AND_FOUR,
        distinct: 2,
        arms: FORTY,
        reference_fails: &[(2, EVERY_DAMAGED_FORTY), (4, EVERY_DAMAGED_FORTY)],
    },
    Shape {
        what: "sectors 10 to 17 zero, the rest different",
        sectors: 40,
        fill: Fill::Zero(&[10, 11, 12, 13, 14, 15, 16, 17]),
        parity: TWO_AND_FOUR,
        distinct: 34,
        arms: FORTY,
        reference_fails: &[],
    },
    Shape {
        what: "all 40 zero",
        sectors: 40,
        fill: Fill::AllZero,
        parity: TWO_AND_FOUR,
        distinct: 2,
        arms: FORTY,
        reference_fails: &[],
    },
    Shape {
        what: "40 sectors cycling through four values",
        sectors: 40,
        fill: Fill::Cycle,
        parity: &[(2, 5), (4, 10), (6, 15)],
        distinct: 5,
        arms: CYCLE_FORTY,
        reference_fails: &[(2, &[1, 2, 3]), (4, &[1, 2, 3]), (6, &[1, 2, 3])],
    },
    Shape {
        what: "134 sectors all different",
        sectors: 134,
        fill: Fill::Different,
        parity: &[(6, 5)],
        distinct: 135,
        arms: WIDE,
        reference_fails: &[],
    },
    Shape {
        what: "134 sectors cycling through four values",
        sectors: 134,
        fill: Fill::Cycle,
        parity: &[(6, 5)],
        distinct: 5,
        arms: WIDE,
        reference_fails: &[(6, &[1, 2, 4])],
    },
    Shape {
        what: "134 sectors, every fourth one equal and the rest different",
        sectors: 134,
        fill: Fill::EveryFourth,
        parity: &[(6, 5)],
        distinct: 102,
        arms: WIDE,
        reference_fails: &[],
    },
];

fn member(shape: &Shape) -> Vec<u8> {
    let mut data = Vec::with_capacity(shape.sectors * SECTOR);
    for number in 1..=shape.sectors {
        let own = sector(number as u64);
        let shared = sector(1_000);
        let bytes = match shape.fill {
            Fill::Different => own,
            Fill::Equal(which) if which.contains(&number) => shared,
            Fill::Equal(_) => own,
            Fill::Zero(which) if which.contains(&number) => [0u8; SECTOR],
            Fill::Zero(_) => own,
            Fill::AllEqual => shared,
            Fill::AllZero => [0u8; SECTOR],
            Fill::Cycle => sector(2_000 + (number % 4) as u64),
            Fill::EveryFourth if number % 4 == 1 => shared,
            Fill::EveryFourth => own,
        };
        data.extend_from_slice(&bytes);
    }
    data
}

fn archive(name: &[u8], data: &[u8], percent: u32) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar4(Rar4Version::V40),
        method: WriteMethod::Stored,
        filters: FilterPolicy::Off,
        host_os: HostOs::Unix,
        recovery_percent: Some(percent),
        workers: Some(1),
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name,
            payload: Payload::Bytes(data),
            mtime: None,
            attributes: 0o100644,
            host_os: HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

/// Section 3.7's tag, worked out here and not taken from the engine.
fn tag(sector: &[u8]) -> u16 {
    let mut padded = [0u8; SECTOR];
    padded[..sector.len()].copy_from_slice(sector);
    !rarkit::checksum::crc32(&padded) as u16
}

fn options() -> ReadOptions {
    ReadOptions::default().with_memory(MemoryPolicy {
        repair_limit: 1 << 20,
        ..MemoryPolicy::from_limit(64 << 20)
    })
}

/// What one repair came to, in the words of the table.
fn verdict(whole: &[u8], damaged: &[u8]) -> String {
    let mut mended = Vec::new();
    match rarkit::recovery::repair_inline(&damaged.to_vec(), &options(), &mut mended) {
        Ok(_) if mended == whole => "rebuilt whole".to_owned(),
        Ok(_) if mended == damaged => "not rebuilt".to_owned(),
        Ok(_) => format!("wrong bytes ({} against {})", mended.len(), whole.len()),
        Err(error) => format!("refused: {:?}", error.kind()),
    }
}

#[test]
fn spec_l_3_7_every_equal_and_periodic_sector_arm_of_the_record_is_rebuilt_whole() {
    // The member's header is 32 bytes and its name, after a 7 byte
    // signature and a 13 byte archive header.
    let layouts: [(&str, Vec<u8>); 2] = [
        ("on the grid", vec![b'n'; SECTOR - 7 - 13 - 32]),
        ("57 bytes off the grid", b"a.bin".to_vec()),
    ];
    let (mut archives, mut arms, mut rebuilt, mut reference_failed) = (0, 0, 0, 0);
    let mut failures = Vec::new();
    for (layout, name) in &layouts {
        for shape in SHAPES {
            let data = member(shape);
            for &(parity, percent) in shape.parity {
                let whole = archive(name, &data, percent);
                archives += 1;
                let protected = 7 + 13 + 32 + name.len() + data.len();
                let count = protected.div_ceil(SECTOR);
                // The record's data area is the tags and then the parity
                // sectors, behind a 54 byte header; the end block is 7.
                assert_eq!(
                    whole.len(),
                    protected + 54 + 2 * count + SECTOR * parity + 7,
                    "{}; r={parity}, {layout}",
                    shape.what
                );
                assert_eq!(count, shape.sectors + 1);
                if name.len() == SECTOR - 52 {
                    assert_eq!(protected, (shape.sectors + 1) * SECTOR);
                    let sectors: BTreeSet<&[u8]> = whole[..protected].chunks(SECTOR).collect();
                    let tags: BTreeSet<u16> = whole[..protected].chunks(SECTOR).map(tag).collect();
                    assert_eq!(
                        (sectors.len(), tags.len()),
                        (shape.distinct, shape.distinct),
                        "{}",
                        shape.what
                    );
                }
                let fails = shape
                    .reference_fails
                    .iter()
                    .find(|(r, _)| *r == parity)
                    .map_or(&[][..], |(_, which)| which);
                for (index, arm) in shape.arms.iter().enumerate() {
                    let mut damaged = whole.clone();
                    for at in arm.iter() {
                        for byte in &mut damaged[at * SECTOR + 200..at * SECTOR + 300] {
                            *byte ^= 0x5A;
                        }
                    }
                    let said = verdict(&whole, &damaged);
                    let reference = if fails.contains(&index) {
                        reference_failed += 1;
                        "NOT rebuilt"
                    } else {
                        "rebuilt"
                    };
                    println!(
                        "{layout}\t{}; r={parity}\t{arm:?}\treference: {reference}\trarkit: {said}",
                        shape.what
                    );
                    arms += 1;
                    if said == "rebuilt whole" {
                        rebuilt += 1;
                    } else {
                        failures.push(format!(
                            "{layout}; {}; r={parity}; {arm:?}: {said}",
                            shape.what
                        ));
                    }
                }
            }
        }
    }
    println!("{archives} archives, {arms} arms, {rebuilt} rebuilt whole, reference not rebuilt on {reference_failed}");
    assert_eq!((archives, arms, reference_failed), (52, 414, 58));

    // The control: the verdict above can come out another way. Two
    // damaged sectors of ONE class (9 and 11 at r = 2) are past what the
    // record holds, and section 3.7 has that damage not recoverable.
    let whole = archive(&layouts[0].1, &member(&SHAPES[0]), 5);
    let mut damaged = whole.clone();
    for at in [9, 11] {
        for byte in &mut damaged[at * SECTOR + 200..at * SECTOR + 300] {
            *byte ^= 0x5A;
        }
    }
    let said = verdict(&whole, &damaged);
    println!("control, two sectors of one class: {said}");
    assert!(said.starts_with("refused: Recovery("), "{said}");
    assert!(failures.is_empty(), "{failures:#?}");
}
