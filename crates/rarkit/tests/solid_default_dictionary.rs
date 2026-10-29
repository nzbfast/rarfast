//! The default dictionary of a SOLID archive (spec G 3.8.1) through the
//! public `Writer`: a solid RAR 5 archive with no dictionary named
//! at levels 2 to 5 compresses in a 32 MiB window, fitted to the set,
//! searched under a far-link budget of 1, which is the archive a caller
//! who names 32 MiB and that budget writes; level 1 keeps 2 MiB (the
//! level picked for wall); a caller who names a dictionary gets the search they
//! always had; `WriteOptions::solid_dictionary_2mib` and a memory
//! ceiling the caller named bring back the 2 MiB archive; and no
//! non-solid archive and nothing of the RAR 4 family moves by a byte.
//! Reference `rar` 7.23's own solid default is 32 MiB at every level,
//! halved to the set (measured by calling it, 10 Oct 2026).
//!
//! Threads: every cell is written at 4 workers, and the default again at
//! 1, 3, 8 and 32. Memory: sets of 18 MiB and under, a 32 MiB window;
//! under 500 MiB at any width.
use rarkit::{
    extract, Disposition, Entropy, FilterPolicy, MemberInfo, MemberSpec, MemoryPolicy, Method,
    Payload, RangeSource, Rar4Version, ReadOptions, Result, Sink, WriteFormat, WriteMethod,
    WriteOptions, Writer,
};
use std::sync::Arc;

const MIB: u64 = 1 << 20;

/// The default this file is about.
const SOLID: u64 = 32 * MIB;

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Words that compress, `len` bytes of them.
fn text(len: usize, seed: u64) -> Vec<u8> {
    let words = [
        "window ", "sixteen ", "two ", "level ", "three ", "solid ", "named ", "default ",
        "fitted ", "budget ", "reach ",
    ];
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        out.extend_from_slice(
            words[(xorshift(&mut state) >> 29) as usize % words.len()].as_bytes(),
        );
    }
    out.truncate(len);
    out
}

/// A quarter MiB of six-byte words drawn at random from 4,096 of them.
/// Each word comes about ten times, so the bytes pack, the encoder gives
/// them the level's own search, and every position's chain holds about
/// ten earlier places that begin with its word, one of which goes on.
fn salad(seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let words: Vec<[u8; 6]> = (0..4096)
        .map(|_| {
            (xorshift(&mut state) >> 8).to_le_bytes()[..6]
                .try_into()
                .unwrap()
        })
        .collect();
    let mut out = Vec::with_capacity(256 << 10);
    while out.len() < 256 << 10 {
        out.extend_from_slice(&words[(xorshift(&mut state) >> 20) as usize % words.len()]);
    }
    out.truncate(256 << 10);
    out
}

/// Three members, 9.5 MiB in all, where the third repeats a quarter MiB
/// of the first: the copy lies about 7 MiB back, in another member.
///
/// A 2 MiB window does not reach it, and neither does a longer one
/// searched under a far-link budget of 0; a window that follows one far
/// link does, and codes the repeat as a few long matches. So which
/// default ran, and whose budget, shows in the archive's size. The set
/// is under 16 MiB, so the 32 MiB default is fitted to 16 MiB.
fn members() -> Vec<Vec<u8>> {
    let repeat = salad(31);
    let mut first = text(1 << 20, 32);
    first.extend_from_slice(&repeat);
    first.extend_from_slice(&text((3 << 20) - first.len(), 33));
    let second = text(6 << 20, 34);
    let mut third = text(1 << 18, 35);
    third.extend_from_slice(&repeat);
    third.extend_from_slice(&text((1 << 19) - third.len(), 36));
    vec![first, second, third]
}

#[derive(Clone, Copy)]
struct Cell {
    format: WriteFormat,
    level: u8,
    solid: bool,
    /// `WriteOptions::solid_dictionary_2mib`.
    keep: bool,
    dictionary: Option<u64>,
    far_link_budget: Option<u32>,
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
            solid_dictionary_2mib: self.keep,
            far_link_budget: self.far_link_budget,
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
        far_link_budget: None,
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

/// Hand `archive` to reference `unrar x` and compare every file it
/// writes with its member. unrar reports a checksum error on stderr and
/// may still exit 0, so both are read.
fn unrar_extracts(what: &str, archive: &[u8], members: &[Vec<u8>]) {
    let dir = std::env::temp_dir().join(format!("rarkit-soliddict-{what}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a work directory");
    std::fs::write(dir.join("test.rar"), archive).expect("the archive");
    let run = std::process::Command::new("unrar")
        .args(["x", "-y", "test.rar"])
        .current_dir(&dir)
        .output()
        .expect("unrar runs");
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        run.status.success() && stderr.trim().is_empty() && stdout.contains("All OK"),
        "{what}: unrar refused the archive\n{stdout}\n{stderr}"
    );
    for (i, member) in members.iter().enumerate() {
        let read = std::fs::read(dir.join(format!("m{i}.bin"))).expect("an extracted member");
        assert!(
            read == *member,
            "{what}: unrar wrote other bytes for m{i}.bin"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

const FORMATS: [WriteFormat; 2] = [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V29)];

/// The default's bytes at every level: at levels 2 to 5 what a named
/// 32 MiB under a budget of 1 writes, declared as the 16 MiB the set
/// fits and smaller than the 2 MiB archive; at level 1 what a named
/// 2 MiB writes; and extracted by reference unrar to the members' own
/// bytes.
#[test]
fn a_solid_archive_takes_32_mib_under_a_far_link_budget_of_1() {
    let members = members();
    for level in 1u8..=5 {
        let solid = cell(WriteFormat::Rar5, level, true);
        let what = solid.name();
        let default = write(&members, solid);
        let named = write(
            &members,
            if level >= 2 {
                Cell {
                    dictionary: Some(SOLID),
                    far_link_budget: Some(1),
                    ..solid
                }
            } else {
                Cell {
                    dictionary: Some(2 * MIB),
                    ..solid
                }
            },
        );
        assert!(
            default == named,
            "{what}: the default ({} bytes) is not what its named dictionary writes ({})",
            default.len(),
            named.len()
        );
        let window = if level >= 2 { 16 * MIB } else { 2 * MIB };
        assert_eq!(reads_back(&what, &default, &members), window, "{what}");
        if level >= 2 {
            let named_2 = write(
                &members,
                Cell {
                    dictionary: Some(2 * MIB),
                    ..solid
                },
            );
            assert!(
                default.len() + (64 << 10) < named_2.len(),
                "{what}: the default wrote {} bytes and a named 2 MiB {}: the repeat 7 MiB back was not reached",
                default.len(),
                named_2.len()
            );
        }
        if have_unrar() {
            unrar_extracts(&what, &default, &members);
        } else {
            eprintln!("reference unrar is not on PATH: {what} is not extracted by it");
        }
    }
}

/// One byte for one pool, and a budget the caller set is the caller's.
#[test]
fn the_solid_default_is_one_archive_at_every_width_and_keeps_a_callers_budget() {
    let members = members();
    let solid = cell(WriteFormat::Rar5, 3, true);
    let default = write(&members, solid);
    for workers in [Some(1), Some(3), Some(8), Some(32)] {
        assert!(
            write(&members, Cell { workers, ..solid }) == default,
            "{workers:?} workers wrote other bytes"
        );
    }
    let own_budget = write(
        &members,
        Cell {
            far_link_budget: Some(0),
            ..solid
        },
    );
    assert!(
        default.len() + (64 << 10) < own_budget.len(),
        "a budget of 0 wrote {} bytes and the default {}: the caller's budget was not taken",
        own_budget.len(),
        default.len()
    );
    assert_eq!(reads_back("rar5-m3s-f0", &own_budget, &members), 16 * MIB);
    // A named dictionary declares what was named, fitted to the set.
    let named_4 = write(
        &members,
        Cell {
            dictionary: Some(4 * MIB),
            ..solid
        },
    );
    assert_eq!(reads_back("rar5-m3s-md4m", &named_4, &members), 4 * MIB);
}

/// A set over 16 MiB declares the whole 32 MiB, and one under 1 MiB what
/// it fits: the default is a ceiling the fit brings down.
#[test]
fn the_solid_default_is_fitted_to_the_set() {
    let solid = cell(WriteFormat::Rar5, 3, true);
    let large: Vec<Vec<u8>> = (0..3).map(|i| text(6 << 20, 41 + i)).collect();
    let archive = write(&large, solid);
    assert_eq!(reads_back("rar5-m3s-18m", &archive, &large), SOLID);
    if have_unrar() {
        unrar_extracts("large", &archive, &large);
    }
    let small: Vec<Vec<u8>> = (0..3).map(|i| text(100_000, 51 + i)).collect();
    let archive = write(&small, solid);
    assert_eq!(reads_back("rar5-m3s-300k", &archive, &small), 512 << 10);
}

/// The option brings back the 2 MiB archive in a solid RAR 5 archive at
/// levels 2 to 5, and moves no byte anywhere else.
#[test]
fn the_option_keeps_2_mib_and_reaches_nothing_else() {
    assert!(!WriteOptions::default().solid_dictionary_2mib);
    let members = members();
    for format in FORMATS {
        for solid in [false, true] {
            for level in 1u8..=5 {
                let cell = cell(format, level, solid);
                let what = cell.name();
                let default = write(&members, cell);
                let kept = write(&members, Cell { keep: true, ..cell });
                if solid && format == WriteFormat::Rar5 && level >= 2 {
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
                    assert!(default != kept, "{what}: the option changed nothing");
                    assert_eq!(reads_back(&what, &kept, &members), 2 * MIB, "{what}");
                } else {
                    assert!(
                        default == kept,
                        "{what}: the option moved a byte outside a solid RAR 5 archive above level 1"
                    );
                    if solid {
                        // Level 1 and the RAR 4 family keep 2 MiB.
                        assert_eq!(reads_back(&what, &default, &members), 2 * MIB, "{what}");
                    }
                }
            }
        }
    }
}

/// The default is an allowance's subject like any other default: a
/// policy that budgets less reduces it and never refuses it, and one
/// that budgets more does not raise it. A memory ceiling the caller
/// NAMED, of any size, keeps the 2 MiB archive: a named budget is a
/// promise.
#[test]
fn a_memory_policy_reduces_the_solid_default_and_a_named_ceiling_keeps_2_mib() {
    let members = members();
    let solid = cell(WriteFormat::Rar5, 3, true);
    let small = MemoryPolicy {
        max_dictionary: 4 * MIB,
        ..MemoryPolicy::default()
    };
    let reduced = write(
        &members,
        Cell {
            memory: Some(small),
            ..solid
        },
    );
    assert_eq!(reads_back("rar5-m3s-4m", &reduced, &members), 4 * MIB);
    let large = MemoryPolicy {
        working_limit: 8 << 30,
        ..MemoryPolicy::default()
    };
    assert!(!large.limit_named);
    let roomy = write(
        &members,
        Cell {
            memory: Some(large),
            ..solid
        },
    );
    assert!(
        roomy == write(&members, solid),
        "a larger policy moved the default's bytes"
    );
    let named_2 = write(
        &members,
        Cell {
            dictionary: Some(2 * MIB),
            ..solid
        },
    );
    for named in [
        MemoryPolicy::from_limit(8 << 30),
        MemoryPolicy::for_process(512 << 20, 0),
    ] {
        assert!(named.limit_named);
        let kept = write(
            &members,
            Cell {
                memory: Some(named),
                ..solid
            },
        );
        assert!(
            kept == named_2,
            "under a named ceiling, not the archive a named 2 MiB writes"
        );
    }
}
