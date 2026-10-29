//! The default dictionary at level 1 (spec G 3.8.1) through the public
//! `Writer`: a NON-SOLID level 1 RAR 5 archive with no dictionary named
//! compresses in a 4 MiB window; every other level, every solid archive,
//! the whole RAR 4 family and a caller who set
//! `WriteOptions::level1_dictionary_2mib` compress in the 2 MiB they
//! always had; a named dictionary always wins; and the
//! figure is the same on every machine, reduced only by a `MemoryPolicy`
//! that will not budget it and by the fit to the input.
//!
//! **How "as it always had" is held.** [`BEFORE`] pins the SHA-256 of
//! every cell's archive as an earlier revision wrote it, the commit
//! this change was cut from (taken there by this file's own `write`, with
//! `LEVEL1_DICTIONARY_PRINT_PINS=1` and the option's line taken out of
//! `Cell::options`). Levels 2 to 5, every solid cell and every RAR 4
//! cell must match their pin with the option off and on; RAR 5 level 1
//! non-solid must match its pin with the option on, and with it off must
//! be the archive a named 4 MiB writes.
//!
//! **Pinned again on 11 Oct 2026, over new test data.** The members here
//! are made by the shared test data makers now, so every digest below
//! was taken again, from that day's build, whose engine was byte for byte
//! the one that passed the pins before them. They record the same
//! behaviour on new data and guard it from here on; they no longer prove
//! equality with the older build this header names.
use rarkit::{
    extract, Disposition, Entropy, FilterPolicy, MemberInfo, MemberSpec, MemoryPolicy, Method,
    Payload, RangeSource, Rar4Version, ReadOptions, Result, Sink, WriteFormat, WriteMethod,
    WriteOptions, Writer,
};
use std::sync::Arc;

const MIB: u64 = 1 << 20;

/// One member of 6 MiB whose only large repeat lies 3 MiB back: half a
/// MiB of noise, 2.5 MiB of words, the same noise again, 2.5 MiB of other
/// words. A 4 MiB window reaches the first copy of the noise and a 2 MiB
/// one cannot, so which default ran shows in the archive's size. Beside
/// it a small member, so that a solid archive has something to chain.
fn members() -> Vec<Vec<u8>> {
    let repeat = rarkit_testdata::scramble(11, 512 << 10);
    let mut big = repeat.clone();
    big.extend_from_slice(&rarkit_testdata::chatter(12, 5 << 19));
    big.extend_from_slice(&repeat);
    big.extend_from_slice(&rarkit_testdata::chatter(13, 5 << 19));
    vec![big, rarkit_testdata::chatter(14, 40_000)]
}

#[derive(Clone, Copy)]
struct Cell {
    format: WriteFormat,
    level: u8,
    solid: bool,
    /// `WriteOptions::level1_dictionary_2mib`.
    keep: bool,
    dictionary: Option<u64>,
    workers: Option<usize>,
    memory: Option<MemoryPolicy>,
}

impl Cell {
    fn name(self) -> String {
        let format = match self.format {
            WriteFormat::Rar5 => "rar5",
            WriteFormat::Rar4(_) => "rar4v29",
        };
        let solid = if self.solid { "s" } else { "" };
        format!("{format}-m{}{solid}", self.level)
    }

    fn options(self) -> WriteOptions {
        WriteOptions {
            format: self.format,
            method: WriteMethod::Compressed {
                level: self.level,
                dictionary: self.dictionary,
            },
            solid: self.solid,
            // The RAR 4 family writes no filter record (SPEC-J).
            filters: match self.format {
                WriteFormat::Rar5 => FilterPolicy::Detect,
                WriteFormat::Rar4(_) => FilterPolicy::Off,
            },
            level1_dictionary_2mib: self.keep,
            // Level 3's own default (9 Oct 2026) is not this file's
            // subject: its cells keep the 2 MiB their pins were taken
            // at. `level3_default_dictionary` holds the default.
            level3_dictionary_2mib: true,
            // Nor is the solid default (10 Oct 2026), which
            // `solid_default_dictionary` holds.
            solid_dictionary_2mib: true,
            entropy: Entropy::Seeded([5; 32]),
            workers: self.workers,
            memory: self.memory.unwrap_or_default(),
            ..WriteOptions::default()
        }
    }
}

fn cell(format: WriteFormat, level: u8, solid: bool) -> Cell {
    Cell {
        format,
        level,
        solid,
        keep: false,
        dictionary: None,
        workers: Some(4),
        memory: None,
    }
}

fn write(members: &[Vec<u8>], cell: Cell) -> Vec<u8> {
    let mut writer = Writer::new(cell.options()).expect("options");
    let names: Vec<Vec<u8>> = (0..members.len())
        .map(|i| format!("m{i}.bin").into_bytes())
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
    out
}

/// What the archive reads back as, and the window each member's header
/// asks its extractor for.
#[derive(Default)]
struct Collect {
    members: Vec<Vec<u8>>,
    windows: Vec<u64>,
}

impl Sink for Collect {
    type Out = Vec<u8>;
    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        if let Method::Compressed { dictionary, .. } = member.method {
            self.windows.push(dictionary);
        }
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        assert_eq!(
            outcome.checksum_ok,
            Some(true),
            "a member failed its checksum"
        );
        self.members.push(out.unwrap_or_default());
        Ok(())
    }
}

/// Reads `archive` back, checks it against `members`, and answers the
/// largest window any member's header declares.
fn reads_back(what: &str, archive: &[u8], members: &[Vec<u8>]) -> u64 {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.to_vec())];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("{what}: {e}"));
    assert!(
        sink.members == members,
        "{what}: the archive reads back as its members"
    );
    sink.windows.iter().copied().max().unwrap_or(0)
}

fn have_unrar() -> bool {
    std::process::Command::new("unrar")
        .arg("-iver")
        .output()
        .map(|found| found.status.success())
        .unwrap_or(false)
}

/// Hand `archive` to reference `unrar t`. It reports a checksum error on
/// stderr and may still exit 0, so both are read.
fn unrar_admits(what: &str, archive: &[u8]) {
    let dir = std::env::temp_dir().join(format!("rarkit-l1dict-{what}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a work directory");
    std::fs::write(dir.join("test.rar"), archive).expect("the archive");
    let run = std::process::Command::new("unrar")
        .args(["t", "test.rar"])
        .current_dir(&dir)
        .output()
        .expect("unrar runs");
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        run.status.success() && stderr.trim().is_empty() && stdout.contains("All OK"),
        "{what}: unrar refused the archive\n{stdout}\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

const FORMATS: [WriteFormat; 2] = [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V29)];

/// SHA-256 of [`members`] written by [`write`] at an earlier revision,
/// the parent of this change, at each level, in each format, solid and
/// not, with no dictionary named: what every cell but RAR 5 level 1
/// non-solid must still write, and what `level1_dictionary_2mib = true`
/// must write there. The two solid level 4 rows were re-taken the same
/// way at the parent this change landed on: level 4's
/// solid plan moved between the two (its two hint slots), and nothing
/// else did. The eight level 4 and level 5 rows were re-taken again at
/// SPEC-H3 8.1's ladder land of 1 Oct 2026: level 4's
/// default plan went to the chains at 64 links and level 5's lazy tree
/// plan took the backward extension;
/// the rows of levels 1 to 3 are as taken at that earlier revision.
///
/// The four level 5 rows were re-taken once more that day, by the same
/// print, at the land of LEVEL 5 BY CLASS (SPEC-H3 8.1): these
/// members read under the cut-off or are a solid run, so level 5 writes
/// them over the chains at 80 links, 72 in a solid run; the rows of levels
/// 2 to 4 were printed beside them and had not moved.
const BEFORE: [(&str, &str); 20] = [
    (
        "rar5-m1",
        "5b4217b89f800de24d4efe346161751426781cb7aeb411279439a6ec72860911",
    ),
    (
        "rar5-m2",
        "669715955cfea2763580af78c9192dc87366379e2e4445d77cfb276f937e0b9a",
    ),
    (
        "rar5-m3",
        "cde1ee25e8ff73a001ed05005f39492762c8f31548ee0976c5b5d72058538055",
    ),
    (
        "rar5-m4",
        "2cd31f19886c0636e2a6f9f04977016635ecf708e0ac406da7c3ca7ebc2509ec",
    ),
    (
        "rar5-m5",
        "252c592d5b5255df0895bcbc03c16b8bd0bc7e2ae01ea74fb44ca103decd9717",
    ),
    (
        "rar5-m1s",
        "94a3adbe219f57f23398face40c2e7f8558ed6a5c9019e3e30ce1cd13f167f04",
    ),
    (
        "rar5-m2s",
        "32ee99f6df22e97553509be5641298b34f10a04d85fb0be345021aca683948fb",
    ),
    (
        "rar5-m3s",
        "b2af7846cde1d66aaf6574765c97aacecba2864dee12d84beee69f1a14aaf34a",
    ),
    (
        "rar5-m4s",
        "f42a3d8cfba86e1b2abcfb7758b4c1bdf5e14d5641a19e8d5c8d20ee61e75fd9",
    ),
    (
        "rar5-m5s",
        "d5f24a6653434e2e155f7b5fd073e8649d3cd0b5bd9d854a310396b1d9af7e91",
    ),
    (
        "rar4v29-m1",
        "56adba3d8605297d3ef4e4fd270e598f7deece3298df0fd6b3694ba386b63601",
    ),
    (
        "rar4v29-m2",
        "50b011a3d5859080c1da95bba38842374ceb8cbc5ceebd243cad263bd1e0c601",
    ),
    (
        "rar4v29-m3",
        "c033c10836eb3b1a4de6700fb55f100ba7eb159eef398f14919541bd82bd5ad5",
    ),
    (
        "rar4v29-m4",
        "734969ebcfb812bc48885f9777fb4c8ee5cfd81806a9d0f735fed7378351d8b3",
    ),
    (
        "rar4v29-m5",
        "7626b7cb331549c2ba5fce96619a41662abac61c8cebf16aefd0f783cb735c5b",
    ),
    (
        "rar4v29-m1s",
        "cca4e74493f96a55968363165b657786cf9f1b6bc574e686486b7325e16cceff",
    ),
    (
        "rar4v29-m2s",
        "5f6fa6a5d1a4208dbe71cd80340771dd5fbba43dfc21415644512f407537fe07",
    ),
    (
        "rar4v29-m3s",
        "9389a4a7c0a4db1ba2607b35bc9f4f7db4971022eb276583a73372d876bc746d",
    ),
    (
        "rar4v29-m4s",
        "18467e120d0b833adec80e562c2e9e4a885c8bea415ccfb1543462c18f618a1f",
    ),
    (
        "rar4v29-m5s",
        "a5a4eb72bb7f5584420ced1012c63b00d31ba62a61a37adb15e16ef6c57758d9",
    ),
];

#[test]
fn level_1_non_solid_takes_4_mib_and_nothing_else_moves() {
    assert!(!WriteOptions::default().level1_dictionary_2mib);
    let members = members();
    let print = std::env::var_os("LEVEL1_DICTIONARY_PRINT_PINS").is_some();
    let unrar = have_unrar();
    if !unrar {
        eprintln!("reference unrar is not on PATH: no archive here is admitted by it");
    }
    for format in FORMATS {
        for solid in [false, true] {
            for level in 1u8..=5 {
                let cell = cell(format, level, solid);
                let what = cell.name();
                let default = write(&members, cell);
                if print {
                    // Printing the pins, not judging them: run at the
                    // parent, where the option does not exist, with the
                    // option's line taken out of `Cell::options`.
                    eprintln!("PIN (\"{what}\", \"{}\"),", sha256_hex(&default));
                    continue;
                }
                let kept = write(&members, Cell { keep: true, ..cell });
                let pinned = BEFORE
                    .iter()
                    .find(|(name, _)| *name == what)
                    .map(|(_, sha)| *sha)
                    .expect("a pinned digest");
                assert_eq!(
                    sha256_hex(&kept),
                    pinned,
                    "{what}: with the option, not the archive the parent wrote"
                );
                let named_2 = write(
                    &members,
                    Cell {
                        dictionary: Some(2 * MIB),
                        ..cell
                    },
                );
                assert!(
                    kept == named_2,
                    "{what}: with the option, not what a named 2 MiB writes"
                );
                if level == 1 && !solid && format == WriteFormat::Rar5 {
                    let named_4 = write(
                        &members,
                        Cell {
                            dictionary: Some(4 * MIB),
                            ..cell
                        },
                    );
                    assert!(
                        default == named_4,
                        "{what}: the default is not what a named 4 MiB writes"
                    );
                    assert!(
                        default.len() + (256 << 10) < kept.len(),
                        "{what}: 4 MiB wrote {} bytes and 2 MiB {}: the repeat 3 MiB back \
                         was not reached",
                        default.len(),
                        kept.len()
                    );
                    assert_eq!(reads_back(&what, &default, &members), 4 * MIB, "{what}");
                    assert_eq!(reads_back(&what, &kept, &members), 2 * MIB, "{what}");
                    if unrar {
                        unrar_admits(&what, &default);
                        unrar_admits(&format!("{what}-kept"), &kept);
                    }
                    // One byte for one pool: the default's bytes do not
                    // depend on the width either.
                    for workers in [Some(1), Some(3), Some(8), Some(32)] {
                        assert!(
                            write(&members, Cell { workers, ..cell }) == default,
                            "{what}: {workers:?} workers wrote other bytes"
                        );
                    }
                } else {
                    assert!(
                        default == kept,
                        "{what}: the option moved a byte outside RAR 5 level 1 non-solid"
                    );
                    assert_eq!(reads_back(&what, &default, &members), 2 * MIB, "{what}");
                }
            }
        }
    }
}

/// A named dictionary always wins, with the option off and on, and under
/// and over the default.
#[test]
fn a_named_dictionary_wins() {
    let members = members();
    for format in FORMATS {
        for named in [MIB, 2 * MIB, 4 * MIB] {
            let cell = Cell {
                dictionary: Some(named),
                ..cell(format, 1, false)
            };
            let what = format!("{}-md{}m", cell.name(), named / MIB);
            let off = write(&members, cell);
            let on = write(&members, Cell { keep: true, ..cell });
            assert!(off == on, "{what}: the option moved a named dictionary");
            assert_eq!(reads_back(&what, &off, &members), named, "{what}");
        }
    }
    // Over the default, where the format has the room: RAR 5 only (4 MiB
    // is the RAR 4 family's largest window).
    let cell = Cell {
        dictionary: Some(8 * MIB),
        ..cell(WriteFormat::Rar5, 1, false)
    };
    let archive = write(&members, cell);
    assert_eq!(reads_back("rar5-m1-md8m", &archive, &members), 8 * MIB);
}

/// The default is an allowance's subject like any other default: a policy
/// that budgets less reduces it and never refuses it, and a policy that
/// budgets more does not raise it. Nothing else about the machine is
/// consulted.
#[test]
fn a_policy_reduces_the_default_and_never_raises_it() {
    let members = members();
    for format in FORMATS {
        for (allowed, expected) in [
            (MIB, MIB),
            (2 * MIB, 2 * MIB),
            (4 * MIB, 4 * MIB),
            (1024 * MIB, 4 * MIB),
        ] {
            let memory = MemoryPolicy {
                max_dictionary: allowed,
                ..MemoryPolicy::default()
            };
            let cell = Cell {
                memory: Some(memory),
                ..cell(format, 1, false)
            };
            let what = format!("{}-allowed{}m", cell.name(), allowed / MIB);
            // The RAR 4 family's default is the general one.
            let expected = match format {
                WriteFormat::Rar5 => expected,
                WriteFormat::Rar4(_) => expected.min(2 * MIB),
            };
            let default = write(&members, cell);
            let named = write(
                &members,
                Cell {
                    dictionary: Some(expected),
                    ..cell
                },
            );
            assert!(default == named, "{what}: not a named {expected} window");
            assert_eq!(reads_back(&what, &default, &members), expected, "{what}");
        }
    }
}

/// The fit to the input (spec G 3.8.1 step 3) still runs after the
/// default: a level 1 archive whose largest member is a MiB declares the
/// 2 MiB it declared before, and is the same archive with the option on.
#[test]
fn a_small_input_is_fitted_as_before() {
    let members = vec![
        rarkit_testdata::chatter(21, 1 << 20),
        rarkit_testdata::chatter(22, 300_000),
    ];
    for format in FORMATS {
        let cell = cell(format, 1, false);
        let what = format!("{}-small", cell.name());
        let default = write(&members, cell);
        let kept = write(&members, Cell { keep: true, ..cell });
        assert!(
            default == kept,
            "{what}: the default moved a fitted archive"
        );
        assert_eq!(reads_back(&what, &default, &members), 2 * MIB, "{what}");
    }
}

/// The fit's edge (spec G 3.8.1 step 3 keeps the smallest power of two
/// STRICTLY above the largest member): a largest member one byte under
/// 2 MiB declares the 2 MiB it declared before, and is the same archive
/// with the option on; one of exactly 2 MiB now declares 4 MiB at level 1
/// in a non-solid RAR 5 archive, and 2 MiB with the option on, at any
/// other level, in a solid archive and in the RAR 4 family.
#[test]
fn the_fit_edge_sits_at_a_largest_member_of_exactly_2_mib() {
    for format in FORMATS {
        let under = vec![
            rarkit_testdata::chatter(31, (2 << 20) - 1),
            rarkit_testdata::chatter(32, 50_000),
        ];
        let cell = cell(format, 1, false);
        let what = format!("{}-2mib-less-1", cell.name());
        let default = write(&under, cell);
        let kept = write(&under, Cell { keep: true, ..cell });
        assert!(
            default == kept,
            "{what}: the default moved a fitted archive"
        );
        assert_eq!(reads_back(&what, &default, &under), 2 * MIB, "{what}");

        let exact = vec![
            rarkit_testdata::chatter(31, 2 << 20),
            rarkit_testdata::chatter(32, 50_000),
        ];
        let what = format!("{}-2mib", cell.name());
        let default = write(&exact, cell);
        let kept = write(&exact, Cell { keep: true, ..cell });
        let moved = match format {
            WriteFormat::Rar5 => 4 * MIB,
            WriteFormat::Rar4(_) => 2 * MIB,
        };
        assert_eq!(reads_back(&what, &default, &exact), moved, "{what}");
        assert_eq!(reads_back(&what, &kept, &exact), 2 * MIB, "{what} kept");
        for (level, solid) in [(1, true), (2, false), (3, false), (5, false)] {
            let other = Cell {
                level,
                solid,
                ..cell
            };
            let what = format!("{}-2mib", other.name());
            let archive = write(&exact, other);
            assert_eq!(reads_back(&what, &archive, &exact), 2 * MIB, "{what}");
        }
    }
}
