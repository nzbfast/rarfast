//! The tree match finder's ANSWERS, pinned: levels 4 and 5 are the two
//! levels that walk the binary tree, and every change to how the walk is
//! done (which stores it makes, what it touches ahead, how it compares)
//! must leave every archive they write exactly as it was.
//!
//! The digests below were taken from the walk as it stood before the tree
//! walk cost work's first change; the
//! solid work's later walk writes the same ten. A row that moves is
//! a walk that answers differently, whatever its reason, and is a defect
//! until decided otherwise.
//!
//! The lazy tree parse moved the DEFAULT parse of both levels, not the
//! walk: those ten digests are now what `level4_optimal` and
//! `level5_optimal` write, unmoved, and each row carries a second digest
//! for the lazy parse reading one hint slot of the same walk (at level 4
//! TWO in a solid run since 1 Oct 2026, SPEC-H3 8.1). Level 4's DEFAULT left the
//! tree for the chains that day; `level4_tree` keeps the tree there, and
//! the level 4 rows are written with it. Level 5 went BY CLASS the same
//! day (the chains for a member whose head reads few far links, and for a
//! solid run); `level5_tree` keeps the tree for every member, the level 5
//! rows are written with it, and their digests did not move: the option
//! writes what level 5 wrote before.
//!
//! The input is built to reach every exit of a descent: long records that
//! agree to the comparison cap (the wholesale-replacement exit), text
//! whose buckets are deep enough to exhaust the cut, a run of one byte,
//! noise, and at the small dictionaries a window shorter than the input,
//! so descents stop at nodes that have fallen out of it. It is longer than
//! four walk chunks, so the parallel walk has several in flight, and each
//! row is written at one walker and at several, which must agree.
//!
//! **Pinned again on 11 Oct 2026, over new test data.** The members here
//! are made by the shared test data makers now, so every digest below
//! was taken again, from that day's build, whose engine was byte for byte
//! the one that passed the pins before them. They record the same
//! behaviour on new data and guard it from here on; they no longer prove
//! equality with the older build this header names.
use rarkit::{
    Entropy, MemberSpec, Payload, Rar4Version, Timestamp, WriteFormat, WriteMethod, WriteOptions,
    Writer,
};
use sha2::{Digest, Sha256};

/// The input the header describes, about 1.4 MiB, from `seed`.
fn input(seed: u64) -> Vec<u8> {
    let mut out = Vec::new();
    // Long records that agree for 5,000 bytes, past any comparison cap,
    // and then differ: forty of them, each ending in bytes of its own.
    let record = rarkit_testdata::chatter(seed, 5_000);
    for index in 0..40 {
        out.extend_from_slice(&record);
        out.extend_from_slice(&rarkit_testdata::scramble(seed + index, 96));
    }
    // Text of a small vocabulary: every bucket deep.
    out.extend_from_slice(&rarkit_testdata::chatter_of(seed + 100, 12, 500_000));
    // A run of one byte.
    out.resize(out.len() + 70_000, 0x5a);
    // Noise.
    out.extend_from_slice(&rarkit_testdata::scramble(seed + 200, 150_000));
    // Text again, of another vocabulary, and the records once more, a
    // megabyte on: at the small dictionaries their first copies have left
    // the window.
    out.extend_from_slice(&rarkit_testdata::chatter(seed + 300, 400_000));
    for index in 0..8 {
        out.extend_from_slice(&record);
        out.extend_from_slice(&rarkit_testdata::scramble(seed + 400 + index, 96));
    }
    out
}

fn write(members: &[(&str, &[u8])], options: WriteOptions) -> Vec<u8> {
    let mut writer = Writer::new(options).expect("options");
    for (name, bytes) in members {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(bytes),
                mtime: Some(Timestamp {
                    unix_seconds: 1_700_000_000,
                    nanos: 0,
                }),
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

fn options(
    format: WriteFormat,
    level: u8,
    dictionary: u64,
    solid: bool,
    workers: usize,
    optimal: bool,
) -> WriteOptions {
    WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level,
            dictionary: Some(dictionary),
        },
        solid,
        // The RAR 4 family writes no filter record (SPEC-J).
        filters: if matches!(format, WriteFormat::Rar4(_)) {
            rarkit::FilterPolicy::Off
        } else {
            rarkit::FilterPolicy::default()
        },
        level4_optimal: optimal,
        level5_optimal: optimal,
        // Level 4's default plan walks the chains since 1 Oct 2026; this
        // file pins the TREE's answers, so its level 4 rows are written
        // under the tree option (which `level4_optimal` overrides).
        level4_tree: true,
        // And level 5 goes by class since the same day (a member's head,
        // a solid run): its rows are written under its tree option too,
        // so every digest here is still the tree's answer.
        level5_tree: true,
        entropy: Entropy::Seeded([3; 32]),
        workers: Some(workers),
        ..WriteOptions::default()
    }
}

/// Each row: a name, its format, level, dictionary and solidity, and the
/// SHA-256 of the archive, first 16 hex digits, twice: with
/// `level4_optimal` / `level5_optimal` on (the optimal parse over the tree
/// at four hint slots, the digests this file has always pinned), and with
/// them off, the LAZY parse over the tree at one slot since 1 Oct 2026
/// (its full reach for a non-solid member longer than the reach, a solid
/// set too): level 5's default, and level 4's plan under
/// `level4_tree`, which every row here is written with. All ten LAZY
/// digests were re-taken on 1 Oct 2026, when the lazy tree plans took the
/// backward extension (SPEC-H3 8.1, the ladder's order; level 5 keeps
/// one hint slot in a solid run too); no optimal digest moved, and none
/// moved again when level 4's default went to the chains that day.
const ROWS: &[(&str, WriteFormat, u8, u64, bool, &str, &str)] = &[
    (
        "rar5 m4 128k",
        WriteFormat::Rar5,
        4,
        128 << 10,
        false,
        "69c77440d2a81606",
        "0642829832ac9dd1",
    ),
    (
        "rar5 m5 128k",
        WriteFormat::Rar5,
        5,
        128 << 10,
        false,
        "3d0fa8a2d188c13e",
        "19472f9b38140925",
    ),
    (
        "rar5 m4 1m",
        WriteFormat::Rar5,
        4,
        1 << 20,
        false,
        "04d4418bb611b9ce",
        "1dd6e7ffe0d58bf2",
    ),
    (
        "rar5 m5 1m",
        WriteFormat::Rar5,
        5,
        1 << 20,
        false,
        "53e8db363249a1e0",
        "1e0e76b945558a08",
    ),
    (
        "rar5 m5 4m",
        WriteFormat::Rar5,
        5,
        4 << 20,
        false,
        "af823570f4f4ed13",
        "b523882f0b4d6866",
    ),
    (
        "rar5 m5 256k solid",
        WriteFormat::Rar5,
        5,
        256 << 10,
        true,
        "1f4c289f64f6bdd8",
        "f26fcb2b3270dd96",
    ),
    (
        "rar5 m4 1m solid",
        WriteFormat::Rar5,
        4,
        1 << 20,
        true,
        "8c330fef8b406190",
        "abed6af3c5a2bdc6",
    ),
    (
        "rar4 m4 256k",
        WriteFormat::Rar4(Rar4Version::V30),
        4,
        256 << 10,
        false,
        "0fcabb8875fb6b65",
        "a10f11f222fb7f19",
    ),
    (
        "rar4 m5 256k",
        WriteFormat::Rar4(Rar4Version::V30),
        5,
        256 << 10,
        false,
        "eed4adec805a24f3",
        "2d0344065c534709",
    ),
    (
        "rar4 m5 4m solid",
        WriteFormat::Rar4(Rar4Version::V30),
        5,
        4 << 20,
        true,
        "8f38ced1c47ea51f",
        "fcc65f73e24f363a",
    ),
];

#[test]
fn tree_levels_write_the_pinned_archives_at_any_walker_count() {
    let whole = input(28);
    // The solid rows split the same bytes into members, so a descent
    // reaches back across member boundaries into carried history.
    let cuts = [0, 200_000, 210_000, 600_000, 900_000, whole.len()];
    let parts: Vec<(String, &[u8])> = cuts
        .windows(2)
        .enumerate()
        .map(|(i, w)| (format!("part{i}.bin"), &whole[w[0]..w[1]]))
        .collect();
    let mut wrong = Vec::new();
    for &(name, format, level, dictionary, solid, optimal, default) in ROWS {
        let members: Vec<(&str, &[u8])> = if solid {
            parts.iter().map(|(n, b)| (n.as_str(), *b)).collect()
        } else {
            vec![("whole.bin", &whole[..])]
        };
        for (arm, on, want) in [("optimal", true, optimal), ("lazy", false, default)] {
            let one = write(&members, options(format, level, dictionary, solid, 1, on));
            let many = write(&members, options(format, level, dictionary, solid, 6, on));
            assert!(one == many, "{name} {arm}: one walker and six disagree");
            let digest = Sha256::digest(&one);
            let got: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
            if got != want {
                wrong.push(format!(
                    "{name} {arm}: {got} ({} bytes), pinned {want}",
                    one.len()
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "moved:\n{}", wrong.join("\n"));
}
