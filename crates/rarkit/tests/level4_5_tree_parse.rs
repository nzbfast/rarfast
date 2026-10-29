//! The lazy tree parse (SPEC-H3 8.1, SPEC-G 3.8.1) through the public `Writer`: at
//! levels 4 and 5 a member that is not lone takes the lazy parse over the
//! tree by default, a member of a solid set included, and
//! `WriteOptions::level4_optimal` and `WriteOptions::level5_optimal` keep
//! the optimal parse the level had before, byte for byte.
//!
//! Which parse a member took is pinned at the encoder
//! (`encode::tests::levels_4_and_5_take_the_lazy_tree_plan_and_the_options_the_optimal_one`:
//! byte-identity with the spelled plans `lazy:tree:12:0` and
//! `lazy:tree:16:0` at one hint slot, the RAR 2.9 method included). What is
//! pinned here is what reaches the writer: with its option on each level
//! writes the DIGESTS the writer wrote before the change (an earlier
//! revision, taken there with this file's own `archive`), and lone
//! members and levels 1 to 3 write them with the options on and off (the
//! spec's acceptance tests 2 and 3); the same bytes at any
//! width (test 4); a lazy level with an optimal lone member in one run
//! (test 5); and every archive read back. Test 3's switch table is
//! `rarkit-cli`'s.
//!
//! **Pinned again on 11 Oct 2026, over new test data.** The members here
//! are made by the shared test data makers now, so every digest below
//! was taken again, from that day's build, whose engine was byte for byte
//! the one that passed the pins before them. They record the same
//! behaviour on new data and guard it from here on; they no longer prove
//! equality with the older build this header names.
use rarkit::{
    extract, Disposition, Entropy, FilterPolicy, MemberInfo, MemberSpec, Payload, RangeSource,
    Rar4Version, ReadOptions, Result, Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};
use std::sync::Arc;

/// A member of three parse blocks and a tail whose SECOND block is noise,
/// so the incompressible sample sends it to the floor effort, which over
/// the tree reads the level's own hints.
fn mixed() -> Vec<u8> {
    let mut out = rarkit_testdata::chatter(11, 262_144);
    out.extend_from_slice(&rarkit_testdata::scramble(12, 262_144));
    out.extend_from_slice(&rarkit_testdata::chatter(13, 60_000));
    out
}

/// The member sets the digests are taken on.
#[derive(Clone, Copy, Debug)]
enum Set {
    /// Non-solid: a member one byte past the lone bound, the mixed member
    /// and a lone member, in one run.
    Loose,
    /// Non-solid: one lone member alone.
    Lone,
    /// Solid: a lone-sized first member and one past the bound.
    Solid,
}

impl Set {
    fn members(self) -> Vec<Vec<u8>> {
        match self {
            Set::Loose => vec![
                rarkit_testdata::chatter(5, 262_145),
                mixed(),
                rarkit_testdata::chatter(7, 100_000),
            ],
            Set::Lone => vec![rarkit_testdata::chatter(7, 262_144)],
            Set::Solid => vec![
                rarkit_testdata::chatter(7, 100_000),
                rarkit_testdata::chatter(5, 262_145),
            ],
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Arm {
    set: Set,
    rar4: bool,
    level: u8,
    small_lazy: bool,
    /// The optimal-parse options.
    level4_optimal: bool,
    level5_optimal: bool,
    /// Level 4's tree option (SPEC-H3 8.1, "LEVEL 4 RUNS THE CHAINS").
    level4_tree: bool,
    workers: usize,
    reader: bool,
}

fn archive(arm: Arm) -> Vec<u8> {
    let members = arm.set.members();
    let mut writer = Writer::new(WriteOptions {
        format: if arm.rar4 {
            WriteFormat::Rar4(Rar4Version::V29)
        } else {
            WriteFormat::Rar5
        },
        method: WriteMethod::Compressed {
            level: arm.level,
            dictionary: None,
        },
        // The RAR 4 family writes no filter record (SPEC-J).
        filters: if arm.rar4 {
            FilterPolicy::Off
        } else {
            FilterPolicy::default()
        },
        solid: matches!(arm.set, Set::Solid),
        small_member_lazy: arm.small_lazy,
        // Level 3 as it was before its own parse change, which moved it: these pins
        // are of what the lazy tree parse moves and nothing else.
        level3_optimal: true,
        // And level 1 as it was before the fast parse, which moved it after
        // this change landed: the lazy parse over four byte chains.
        level1_priced: true,
        level4_optimal: arm.level4_optimal,
        level5_optimal: arm.level5_optimal,
        level4_tree: arm.level4_tree,
        entropy: Entropy::Seeded([5; 32]),
        workers: Some(arm.workers),
        ..WriteOptions::default()
    })
    .expect("options");
    let names: Vec<Vec<u8>> = (0..members.len())
        .map(|i| format!("m{i}.bin").into_bytes())
        .collect();
    let mut readers: Vec<&[u8]> = members.iter().map(|m| &m[..]).collect();
    for ((bytes, name), reader) in members.iter().zip(&names).zip(readers.iter_mut()) {
        let payload = if arm.reader {
            Payload::Reader {
                reader,
                size: bytes.len() as u64,
                crc32: None,
            }
        } else {
            Payload::Bytes(bytes)
        };
        writer
            .add(MemberSpec {
                name,
                payload,
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("write");
    reads_back(&out, &members);
    out
}

/// FNV-1a over the archive: a pin, not a checksum anything relies on.
fn digest(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

#[derive(Default)]
struct Collect(Vec<Vec<u8>>);

impl Sink for Collect {
    type Out = Vec<u8>;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        self.0.push(out.unwrap_or_default());
        Ok(())
    }
}

fn reads_back(archive: &[u8], members: &[Vec<u8>]) {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.to_vec())];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ()).expect("read back");
    assert!(sink.0 == members, "the archive reads back as its members");
}

/// What the writer wrote before the lazy tree parse, at an earlier revision:
/// (set, RAR 4, level, `small_member_lazy`) and the archive's digest, at
/// four workers from a byte slice.
const BEFORE: &[(&str, bool, u8, bool, u64)] = &[
    ("loose", false, 1, false, 0xdd066ac79c0d28b9),
    ("loose", false, 2, false, 0x5f69f897b51f794b),
    ("loose", false, 3, false, 0x9fef78ceffbeab24),
    ("loose", false, 4, false, 0x27275a737112bf7c),
    ("loose", false, 4, true, 0x9570ba14fd3060c3),
    ("loose", false, 5, false, 0xb30f31518cecf207),
    ("loose", false, 5, true, 0x1b3fd6c73edddc8c),
    ("loose", true, 3, false, 0x8833fa72fe53e49d),
    ("loose", true, 4, false, 0xe16e113af29f7309),
    ("loose", true, 4, true, 0xd242dfdfad8585ec),
    ("loose", true, 5, false, 0x6d25b36d7f46025c),
    ("loose", true, 5, true, 0xf0fba415aab18b21),
    ("lone", false, 1, false, 0xa14a5e7b17ae2dc6),
    ("lone", false, 2, false, 0x10133902c4f60d47),
    ("lone", false, 3, false, 0x62a9c253e2d7179f),
    ("lone", false, 4, false, 0xb4cc0e5768d2ffd4),
    ("lone", false, 4, true, 0x3590fde9fbb9bd23),
    ("lone", false, 5, false, 0xd4a11b2c8a3ea408),
    ("lone", false, 5, true, 0x74225f2e713b951b),
    ("lone", true, 3, false, 0xf0b5c140affba3c2),
    ("lone", true, 4, false, 0x3fec81fbd17cd043),
    ("lone", true, 4, true, 0x486baf81970d2e81),
    ("lone", true, 5, false, 0xd637dd21f32bdd6a),
    ("lone", true, 5, true, 0xd50ff9d2586695b8),
    ("solid", false, 1, false, 0x80741d1d94158b62),
    ("solid", false, 2, false, 0xec048fb3256dd026),
    ("solid", false, 3, false, 0x837030cfcf9994a5),
    ("solid", false, 4, false, 0x3f9aa4145a960523),
    ("solid", false, 4, true, 0x3f9aa4145a960523),
    ("solid", false, 5, false, 0xc276f70c7862728c),
    ("solid", false, 5, true, 0xc276f70c7862728c),
    ("solid", true, 3, false, 0x242afa7a8b5e92d7),
    ("solid", true, 4, false, 0x408432e0211ac6aa),
    ("solid", true, 4, true, 0x408432e0211ac6aa),
    ("solid", true, 5, false, 0x151e1e0cc3e16276),
    ("solid", true, 5, true, 0x151e1e0cc3e16276),
];

fn set_named(name: &str) -> Set {
    match name {
        "loose" => Set::Loose,
        "lone" => Set::Lone,
        _ => Set::Solid,
    }
}

fn arm(set: Set, rar4: bool, level: u8, small_lazy: bool, optimal: bool) -> Arm {
    Arm {
        set,
        rar4,
        level,
        small_lazy,
        level4_optimal: optimal,
        level5_optimal: optimal,
        level4_tree: false,
        workers: 4,
        reader: false,
    }
}

#[test]
fn with_the_options_on_every_level_writes_what_it_wrote_before_the_change() {
    // Acceptance test 2, and test 3's levels 1 to 3 with the options on.
    assert!(!BEFORE.is_empty());
    for &(name, rar4, level, small_lazy, before) in BEFORE {
        let set = set_named(name);
        assert_eq!(
            digest(&archive(arm(set, rar4, level, small_lazy, true))),
            before,
            "{set:?} rar4 {rar4} level {level} small_member_lazy {small_lazy}, options on"
        );
    }
}

#[test]
fn lone_members_and_levels_1_to_3_are_untouched_by_the_change() {
    // Acceptance test 3 with the options off (the default): everything the
    // change does not reach writes the digest it wrote before. A solid set
    // at levels 4 and 5 is reached too.
    for &(name, rar4, level, small_lazy, before) in BEFORE {
        let set = set_named(name);
        if level >= 4 && !matches!(set, Set::Lone) {
            continue;
        }
        assert_eq!(
            digest(&archive(arm(set, rar4, level, small_lazy, false))),
            before,
            "{set:?} rar4 {rar4} level {level} small_member_lazy {small_lazy}, options off"
        );
    }
}

#[test]
fn levels_4_and_5_parse_a_member_that_is_not_lone_lazily_by_default() {
    // Acceptance test 1 as it reaches the writer (the plans themselves are
    // pinned at the encoder): the default moves the members past the bound
    // at levels 4 and 5, non-solid and solid, for both
    // formats, and each option
    // reaches its own level only; a reader payload is written and reads
    // back too (its tree is sized from the run's streamed window, a slice's
    // from the member, so the tree levels' bytes may differ between the
    // two shapes, as they already do on main at a 3 MiB member: the
    // promise is the same bytes at any width, test 4);
    // test 5, a lazy level beside an optimal lone member (the loose set's
    // third member with `small_member_lazy` off) in one run, is written
    // without a panic.
    for set in [Set::Loose, Set::Solid] {
        for rar4 in [false, true] {
            for small_lazy in [false, true] {
                for level in [4u8, 5] {
                    let lazy = archive(arm(set, rar4, level, small_lazy, false));
                    let optimal = archive(arm(set, rar4, level, small_lazy, true));
                    assert!(lazy != optimal, "{set:?} rar4 {rar4} level {level}");
                    // `archive` reads every archive back.
                    archive(Arm {
                        reader: true,
                        ..arm(set, rar4, level, small_lazy, false)
                    });
                }
            }
        }
    }
    // Each option reaches its own level and no other.
    for (level, other) in [(4u8, 5u8), (5, 4)] {
        let only = |level4_optimal: bool, level5_optimal: bool| {
            archive(Arm {
                level4_optimal,
                level5_optimal,
                ..arm(Set::Loose, false, level, false, false)
            })
        };
        let (own, others) = if level == 4 {
            (only(true, false), only(false, true))
        } else {
            (only(false, true), only(true, false))
        };
        assert!(own == only(true, true), "level {level}: its own option");
        assert!(
            others == only(false, false),
            "level {level}: level {other}'s option does not reach it"
        );
    }
}

#[test]
fn the_tree_option_moves_level_4_only() {
    // SPEC-H3 8.1 acceptance test 10: `level4_tree` moves level 4's
    // members that are not lone and nothing else. With it on and off,
    // levels 1 to 3 and 5 and every lone member write the same bytes, RAR
    // 5 and the RAR 2.9 method, with `small_member_lazy` on and off (which
    // still reaches level 4's lone members: the lone set's digests of
    // before the change hold with the tree option on); with both level 4
    // options on, level 4 writes what `level4_optimal` alone writes. That
    // a default level 4 member holds no tree is pinned at the encoder
    // (`encode::tests::level_4_takes_the_chains_level_5_the_lazy_tree_and_the_options_the_plans_before`);
    // the switch table is `rarkit-cli`'s.
    assert!(!WriteOptions::default().level4_tree);
    let with = |tree: bool, arm: Arm| {
        archive(Arm {
            level4_tree: tree,
            ..arm
        })
    };
    for set in [Set::Loose, Set::Lone, Set::Solid] {
        for rar4 in [false, true] {
            for small_lazy in [false, true] {
                for level in 1u8..=5 {
                    let base = arm(set, rar4, level, small_lazy, false);
                    let (off, on) = (with(false, base), with(true, base));
                    let what =
                        format!("{set:?} rar4 {rar4} level {level} small_member_lazy {small_lazy}");
                    if level == 4 && !matches!(set, Set::Lone) {
                        assert!(off != on, "{what}: the tree option moved no byte");
                    } else {
                        assert!(off == on, "{what}: the tree option moved a byte");
                    }
                }
                let optimal = arm(set, rar4, 4, small_lazy, true);
                assert!(
                    with(true, optimal) == with(false, optimal),
                    "{set:?} rar4 {rar4}: with both options on, level4_optimal wins"
                );
            }
        }
    }
    for &(name, rar4, level, small_lazy, before) in BEFORE {
        if name == "lone" && level == 4 {
            assert_eq!(
                digest(&with(true, arm(Set::Lone, rar4, level, small_lazy, false))),
                before,
                "a lone member at level 4, rar4 {rar4}, small_member_lazy {small_lazy}, the tree option on"
            );
        }
    }
    // The same bytes at any width, a slice and a reader, under the option.
    for set in [Set::Loose, Set::Solid] {
        for reader in [false, true] {
            let at = |workers: usize| {
                archive(Arm {
                    level4_tree: true,
                    workers,
                    reader,
                    ..arm(set, false, 4, true, false)
                })
            };
            let one = at(1);
            for workers in [2, 8] {
                assert!(
                    at(workers) == one,
                    "{set:?} reader {reader}: {workers} workers under the tree option"
                );
            }
        }
    }
}

#[test]
fn the_default_writes_the_same_bytes_at_any_width() {
    // Acceptance test 4, for both payload shapes.
    for (set, reader) in [(Set::Loose, false), (Set::Loose, true), (Set::Solid, false)] {
        for level in [4u8, 5] {
            let at = |workers: usize| {
                archive(Arm {
                    workers,
                    reader,
                    ..arm(set, false, level, false, false)
                })
            };
            let four = at(4);
            for workers in [1, 2, 8] {
                assert!(
                    at(workers) == four,
                    "{set:?} reader {reader} level {level} at {workers} workers"
                );
            }
        }
    }
}

/// Reference `unrar t` on `archive`: `Some(true)` for a clean test, both
/// streams read (it reports a bad checksum on stderr and may still exit
/// 0); `None` where no `unrar` is installed.
fn unrar_tests_ok(tag: &str, archive: &[u8]) -> Option<bool> {
    let path = std::env::temp_dir().join(format!("rarkit-l45-{tag}-{}.rar", std::process::id()));
    std::fs::write(&path, archive).ok()?;
    let out = std::process::Command::new("unrar")
        .args(["t", "-idq"])
        .arg(&path)
        .output();
    let _ = std::fs::remove_file(&path);
    out.ok()
        .map(|o| o.status.success() && o.stdout.is_empty() && o.stderr.is_empty())
}

#[test]
fn a_non_solid_member_longer_than_the_reach_takes_the_wide_ring() {
    // SPEC-H3 section 4's acceptance tests 1 and 5 for the non-solid wide
    // ring: at a 2 MiB dictionary, a member of 2.3 MB whose first 400,000
    // bytes come again 1.9 MB later (past the narrow reach of 1.75 MiB,
    // within the dictionary) is written at levels 4 and 5 with the repeat
    // found: well under the option's optimal parse over the narrow ring,
    // which cannot see it. A slice and a reader alike; the same bytes at
    // any width; it reads back, and reference `unrar t` passes it.
    // Six bits a byte, so the far repeat is the one long match there is.
    let dense = |len: usize, seed: u64| -> Vec<u8> {
        let mut source = rarkit_testdata::Seeded::new(seed);
        (0..len)
            .map(|_| b'!' + (source.next_u64() >> 58) as u8)
            .collect()
    };
    let first = dense(400_000, 41);
    let mut member = first.clone();
    member.extend_from_slice(&dense(1_500_000, 42));
    member.extend_from_slice(&first);
    let write = |level: u8, optimal: bool, reader: bool, workers: usize| {
        let mut writer = Writer::new(WriteOptions {
            method: WriteMethod::Compressed {
                level,
                dictionary: Some(2 << 20),
            },
            level4_optimal: optimal,
            level5_optimal: optimal,
            entropy: Entropy::Seeded([5; 32]),
            workers: Some(workers),
            ..WriteOptions::default()
        })
        .expect("options");
        let mut source: &[u8] = &member;
        let payload = if reader {
            Payload::Reader {
                reader: &mut source,
                size: member.len() as u64,
                crc32: None,
            }
        } else {
            Payload::Bytes(&member)
        };
        writer
            .add(MemberSpec {
                name: b"long.bin",
                payload,
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
        let mut out = Vec::new();
        writer.finish_into(&mut out).expect("write");
        reads_back(&out, std::slice::from_ref(&member));
        out
    };
    for level in [4u8, 5] {
        for reader in [false, true] {
            let wide = write(level, false, reader, 4);
            let narrow = write(level, true, reader, 4);
            assert!(
                wide.len() + 200_000 < narrow.len(),
                "level {level} reader {reader}: the repeat is found ({} against {})",
                wide.len(),
                narrow.len()
            );
            for workers in [1, 8] {
                assert!(
                    write(level, false, reader, workers) == wide,
                    "level {level} reader {reader} at {workers} workers"
                );
            }
            if let Some(ok) = unrar_tests_ok(&format!("{level}-{reader}"), &wide) {
                assert!(ok, "level {level} reader {reader}: reference unrar t");
            }
        }
    }
}

/// A tree of source-like files: lines drawn with a skew from a pool, each
/// file also carrying runs copied from the files before it, as the files
/// of one source tree share text. Lengths `least` to `least + spread`.
fn source_tree(
    files: usize,
    seed: u64,
    (pool_lines, vocabulary): (usize, u64),
    least: usize,
    spread: u64,
) -> Vec<Vec<u8>> {
    let mut source = rarkit_testdata::Seeded::new(seed);
    let words: Vec<Vec<u8>> = (0..vocabulary)
        .map(|_| {
            let len = 2 + (source.next_u64() % 9) as usize;
            (0..len)
                .map(|_| b'a' + (source.next_u64() % 26) as u8)
                .collect()
        })
        .collect();
    let pool: Vec<Vec<u8>> = (0..pool_lines)
        .map(|_| {
            let mut line = Vec::new();
            for _ in 0..3 + source.next_u64() % 9 {
                let pick = source.next_u64();
                let rank = (pick % vocabulary) * (pick >> 40 & 0xFF) / 255;
                line.extend_from_slice(&words[rank as usize]);
                line.push(b' ');
            }
            line.push(b'\n');
            line
        })
        .collect();
    let mut out: Vec<Vec<u8>> = Vec::new();
    for _ in 0..files {
        let len = least + (source.next_u64() % spread) as usize;
        let mut file = Vec::with_capacity(len + 4096);
        while file.len() < len {
            let pick = source.next_u64();
            if pick.is_multiple_of(11) && !out.is_empty() {
                let from = &out[(pick >> 20) as usize % out.len()];
                let at = (pick >> 32) as usize % from.len();
                let run = (200 + (pick >> 8) % 3000) as usize;
                file.extend_from_slice(&from[at..(at + run).min(from.len())]);
            } else {
                let rank = (pick % pool_lines as u64) * (pick >> 40 & 0xFF) / 255;
                file.extend_from_slice(&pool[rank as usize]);
            }
        }
        out.push(file);
    }
    out
}

#[test]
fn the_ladder_is_ordered_in_bytes_on_a_solid_and_a_non_solid_tree() {
    // SPEC-H3 8.1 acceptance test 8, THE ORDER: at the default options the
    // archive's bytes are strictly level 3 > level 4 > level 5, on a solid
    // set and on a non-solid set whose members are past the lone bound; a
    // non-solid set of only lone members writes the same at the three
    // levels. A land that makes one level smaller re-counts its
    // neighbours; where it does not, this goes red: on 1 Oct 2026 level
    // 3's backward extension left level 4 LARGER than level 3 on a solid
    // tree, found only after it reached main.
    //
    // The solid set is sixty small files (lone-sized, so only a solid run
    // walks them as one); the non-solid set is six LINE-STRUCTURED files
    // of 300 to 800 KB from test 9's generator, each walked by its level's
    // own plan.
    let lines: Vec<Vec<u8>> = [
        (Lines::Code, 300_000, 3),
        (Lines::Log, 420_000, 4),
        (Lines::Code, 510_000, 5),
        (Lines::Log, 640_000, 6),
        (Lines::Code, 730_000, 7),
        (Lines::Log, 800_000, 8),
    ]
    .iter()
    .map(|&(kind, len, seed)| line_structured(kind, len, 1_200, seed))
    .collect();
    let sets = [
        (
            "solid",
            true,
            source_tree(60, 7, (12_000, 2_000), 8_000, 70_000),
        ),
        ("non-solid", false, lines),
    ];
    for (name, solid, members) in &sets {
        let size = |level: u8| ladder_size(level, *solid, members);
        let (three, four, five) = (size(3), size(4), size(5));
        println!("{name}: level 3 {three}, level 4 {four}, level 5 {five}");
        assert!(
            three > four && four > five,
            "{name}: level 3 > level 4 > level 5 in bytes, got {three}, {four}, {five}"
        );
    }
    // Only lone members: one parse at the three levels,
    // equal and not worse.
    let lone = source_tree(12, 9, (4_000, 800), 30_000, 200_000);
    assert!(lone.iter().all(|file| file.len() <= 262_144));
    let (three, four, five) = (
        ladder_size(3, false, &lone),
        ladder_size(4, false, &lone),
        ladder_size(5, false, &lone),
    );
    println!("lone members: level 3 {three}, level 4 {four}, level 5 {five}");
    assert!(
        three == four && four == five,
        "lone members write the same at levels 3 to 5, got {three}, {four}, {five}"
    );
    // WHAT WAS THE NAMED RESIDUE (SPEC-H3 8.1, "generated word-sampled
    // text"): the non-solid set this test first used, eight files of 300
    // to 800 KB whose lines are drawn word by word from a pool. With level
    // 4 on the chains at 64 links, level 5's TREE wrote more than level 4
    // on it (1 Oct 2026: 567,582 / 556,961 / 560,490, level 5 over level 4
    // by 0.63 percent). Since LEVEL 5 BY CLASS (SPEC-H3 8.1) a member
    // under a megabyte has no reading and takes the chains at 80 links,
    // which cannot write more than the same parse at 64 by much and here
    // write less: 567,582 / 556,961 / 555,490, level 5 under level 4 by
    // 0.26 percent. The order is asserted now; it is the chains' own
    // margin of 16 links, so a change to a chain level's depth re-counts
    // it.
    let sampled = source_tree(8, 7, (4_000, 800), 300_000, 500_000);
    let (three, four, five) = (
        ladder_size(3, false, &sampled),
        ladder_size(4, false, &sampled),
        ladder_size(5, false, &sampled),
    );
    println!("word-sampled text, non-solid: level 3 {three}, level 4 {four}, level 5 {five}");
    assert!(
        three > four && four > five,
        "word-sampled text: level 3 > level 4 > level 5 in bytes, got {three}, {four}, {five}"
    );
}

/// The archive's length at `level` and the default options, `members`
/// written as one solid run or as separate members.
fn ladder_size(level: u8, solid: bool, members: &[Vec<u8>]) -> usize {
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed {
            level,
            dictionary: None,
        },
        solid,
        entropy: Entropy::Seeded([5; 32]),
        workers: Some(4),
        ..WriteOptions::default()
    })
    .expect("options");
    let names: Vec<Vec<u8>> = (0..members.len())
        .map(|i| format!("src/f{i}.txt").into_bytes())
        .collect();
    for (bytes, name) in members.iter().zip(&names) {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(bytes),
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("write");
    out.len()
}

/// Which line-structured text [`line_structured`] writes.
#[derive(Clone, Copy, Debug)]
enum Lines {
    /// Statements of a program: indentation, a common opening, identifiers,
    /// a number.
    Code,
    /// A service's log: a rising timestamp, a severity, a component, a
    /// message of identifiers, a request id and a count.
    Log,
}

/// `len` bytes of line-structured text, cut at a line's end or inside
/// the last line: many near-identical lines that differ in a few bytes,
/// written from a vocabulary of `words` made up identifiers.
fn line_structured(kind: Lines, len: usize, words: usize, seed: u64) -> Vec<u8> {
    use std::io::Write;
    const OPENINGS: [&str; 6] = ["let ", "self.", "return ", "if ", "match ", "for item in "];
    const SEVERITIES: [&str; 4] = ["INFO", "INFO", "WARN", "ERROR"];
    let names = rarkit_testdata::vocabulary(seed, words);
    let mut source = rarkit_testdata::Seeded::new(seed ^ 0x6c69_6e65);
    let name = |source: &mut rarkit_testdata::Seeded| {
        // The product of two draws: a few identifiers are everywhere.
        let at = source.index(names.len()) * source.index(names.len()) / names.len();
        String::from_utf8_lossy(&names[at]).into_owned()
    };
    let mut out = Vec::with_capacity(len + 256);
    let mut clock = 1_700_000_000_000u64;
    while out.len() < len {
        match kind {
            Lines::Code => {
                let depth = source.between(1, 3);
                let opening = OPENINGS[source.index(OPENINGS.len())];
                let (a, b, c) = (name(&mut source), name(&mut source), name(&mut source));
                writeln!(
                    out,
                    "{:depth$}{opening}{a} = {b}.{c}({});",
                    "",
                    source.below(1_000),
                    depth = depth * 4
                )
            }
            Lines::Log => {
                clock += source.below(900);
                let severity = SEVERITIES[source.index(SEVERITIES.len())];
                let (unit, a, b) = (name(&mut source), name(&mut source), name(&mut source));
                writeln!(
                    out,
                    "{clock} {severity} {unit}: {a} {b} request={:08x} count={}",
                    source.next_u32(),
                    source.below(64)
                )
            }
        }
        .expect("a write into memory");
    }
    out.truncate(len);
    out
}

#[test]
fn the_ladder_is_ordered_in_bytes_on_line_structured_text() {
    // SPEC-H3 8.1 acceptance test 9, THE ORDER ON LINE-STRUCTURED TEXT:
    // generated code-like and log-like text (many near-identical lines
    // differing in a few bytes, a vocabulary of 1,200 words), as ONE member
    // past the lone bound and as a SOLID run of files, writes strictly
    // level 3 > level 4 > level 5 at the default options.
    //
    // It FAILS before the lazy tree plans of levels 4 and 5 took the
    // backward extension (1 Oct 2026): level 3 had it from 30 Sep, and on
    // input of this shape, which the gate's text64 is not, wrote LESS than
    // level 4 (real source code as one 36 MB member: 1.17 percent less).
    // The existing order test above, on text sampled word by word, passed
    // throughout.
    //
    // THE THIN STEPS, NAMED (decided 1 Oct 2026,
    // SPEC-H3 8.1, level 5 by class). A SOLID run
    // at level 5 is the chains at 72 links, eight more than level 4's, so
    // the step between them is thin by construction: the two generated
    // solid runs below are ordered by 0.13 percent (code) and 0.06 (log),
    // real solid sets by 0.03 to 0.26 percent (an install log 0.028, a
    // unified log 0.031, 4.2 GB of binaries 0.02), and the real source
    // tree the one-slot tree wrote MORE than level 4 on (a Python library
    // and the SDK's C headers solid, 5,755,563 at level 4 and 5,756,532
    // under the tree) is 5,750,833, 0.08 percent under. A NON-SOLID member
    // of the chains' class is at 80 links: 4.2 GB of binaries 0.042
    // percent under level 4, the one members below 1.7 to 1.9 (they are
    // 1.5 MB and read over the cut-off, so they keep the tree). What is
    // still not ordered, and not asserted anywhere: a sorted word list and
    // Unicode tables as single members (the real rows' named residue). A
    // change that gains a few hundredths of a percent at 64 links inverts
    // the solid step and fails here.
    let mut broken = Vec::new();
    for kind in [Lines::Code, Lines::Log] {
        let text = line_structured(kind, 1_500_000, 1_200, 9);
        // The solid run: the same text as fourteen files of unequal
        // lengths, cut at line ends.
        let mut files = Vec::new();
        let mut from = 0;
        for i in 0..14usize {
            let want = if i == 13 {
                text.len()
            } else {
                (from + 40_000 + (i * 37 % 9) * 17_000).min(text.len())
            };
            let to = match text[want.min(text.len() - 1)..]
                .iter()
                .position(|&b| b == b'\n')
            {
                Some(at) if i != 13 => want + at + 1,
                _ => text.len(),
            };
            files.push(text[from..to].to_vec());
            from = to;
        }
        assert_eq!(files.iter().map(Vec::len).sum::<usize>(), text.len());
        assert!(files.iter().all(|file| !file.is_empty()));
        let one = vec![text];
        for (name, solid, members) in [("one member", false, &one), ("solid run", true, &files)] {
            let (three, four, five) = (
                ladder_size(3, solid, members),
                ladder_size(4, solid, members),
                ladder_size(5, solid, members),
            );
            // The step from level 4 to level 5 is the thin one (see the
            // head of this test), so its margin is stated: a later change
            // to a chain level's finder that inverts it fails here.
            let margin = (four as f64 - five as f64) * 100.0 / four as f64;
            println!(
                "{kind:?}, {name}: level 3 {three}, level 4 {four}, level 5 {five} \
                 (level 5 under level 4 by {margin:.2} percent)"
            );
            if !(three > four && four > five) {
                broken.push(format!(
                    "{kind:?}, {name}: {three}, {four}, {five} \
                     (level 5 under level 4 by {margin:.2} percent)"
                ));
            }
        }
    }
    assert!(
        broken.is_empty(),
        "level 3 > level 4 > level 5 in bytes is broken on: {broken:?}"
    );
}

/// Collects a volume set's volumes.
#[derive(Default)]
struct VolumeSet(Vec<Vec<u8>>);

impl rarkit::VolumeOut for VolumeSet {
    type W = Vec<u8>;

    fn volume(&mut self, _index: u32) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn finished(&mut self, _index: u32, volume: Vec<u8>) -> Result<()> {
        self.0.push(volume);
        Ok(())
    }
}

#[test]
fn a_volume_set_and_an_encrypted_create_take_the_levels_plans() {
    // The shapes a level's plan must reach beside a plain archive: a
    // VOLUME SET (a member's packed data split over volumes) and an
    // ENCRYPTED create, solid and not, RAR 5 and the RAR 2.9 method. At
    // levels 4 and 5, and at level 4 under its tree option: the set is the
    // same at one worker and at eight, reads back to its members, the tree
    // option moves level 4's set and not level 5's, and the non-solid RAR 5
    // set is ordered level 3 > level 4 > level 5 in its total bytes
    // (line-structured members, the salt seeded, so the sizes are the
    // plans').
    let members = [
        line_structured(Lines::Code, 700_000, 1_200, 21),
        line_structured(Lines::Log, 400_000, 1_200, 22),
        rarkit_testdata::chatter(7, 100_000),
    ];
    let write = |rar4: bool, solid: bool, level: u8, tree: bool, workers: usize| {
        let password = (!rar4).then(|| rarkit::Password::new("ladder"));
        let mut writer = Writer::new(WriteOptions {
            format: if rar4 {
                WriteFormat::Rar4(Rar4Version::V29)
            } else {
                WriteFormat::Rar5
            },
            method: WriteMethod::Compressed {
                level,
                dictionary: None,
            },
            filters: if rar4 {
                FilterPolicy::Off
            } else {
                FilterPolicy::default()
            },
            solid,
            password,
            volume_size: Some(48 << 10),
            level4_tree: tree,
            entropy: Entropy::Seeded([9; 32]),
            workers: Some(workers),
            ..WriteOptions::default()
        })
        .expect("options");
        let names: Vec<Vec<u8>> = (0..members.len())
            .map(|i| format!("v{i}.txt").into_bytes())
            .collect();
        for (bytes, name) in members.iter().zip(&names) {
            writer
                .add(MemberSpec {
                    name,
                    payload: Payload::Bytes(bytes),
                    mtime: None,
                    attributes: 0o100644,
                    host_os: rarkit::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
        }
        let mut out = VolumeSet::default();
        writer.finish_volumes(&mut out).expect("write");
        out.0
    };
    let reads_back = |what: &str, rar4: bool, volumes: &[Vec<u8>]| {
        let sources: Vec<Arc<dyn RangeSource>> = volumes
            .iter()
            .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
            .collect();
        let read =
            ReadOptions::default().with_password((!rar4).then(|| rarkit::Password::new("ladder")));
        let mut sink = Collect::default();
        extract(sources, &read, &mut sink, &mut ()).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert!(
            sink.0 == members,
            "{what}: the set reads back as its members"
        );
    };
    let total = |volumes: &[Vec<u8>]| volumes.iter().map(Vec::len).sum::<usize>();
    for rar4 in [false, true] {
        for solid in [false, true] {
            let what = format!("rar4 {rar4} solid {solid}");
            let four = write(rar4, solid, 4, false, 8);
            let four_tree = write(rar4, solid, 4, true, 8);
            let five = write(rar4, solid, 5, false, 8);
            assert!(four.len() > 2, "{what}: a set of several volumes");
            assert!(
                four == write(rar4, solid, 4, false, 1),
                "{what}: -m4 at one worker"
            );
            assert!(
                four_tree == write(rar4, solid, 4, true, 1),
                "{what}: -m4 under the tree option at one worker"
            );
            assert!(
                five == write(rar4, solid, 5, false, 1),
                "{what}: -m5 at one worker"
            );
            assert!(
                four != four_tree,
                "{what}: the tree option moves level 4's set"
            );
            assert!(
                five == write(rar4, solid, 5, true, 8),
                "{what}: the tree option does not move level 5's set"
            );
            reads_back(&format!("{what} -m4"), rar4, &four);
            reads_back(&format!("{what} -m4 tree"), rar4, &four_tree);
            reads_back(&format!("{what} -m5"), rar4, &five);
            let three = write(rar4, solid, 3, false, 8);
            println!(
                "{what}: level 3 {}, level 4 {}, level 5 {}",
                total(&three),
                total(&four),
                total(&five)
            );
            if !rar4 && !solid {
                assert!(
                    total(&three) > total(&four) && total(&four) > total(&five),
                    "{what}: the set's bytes are ordered"
                );
            }
        }
    }
}
