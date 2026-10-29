//! The default dictionary at level 3 (spec G 3.8.1) through the public
//! `Writer`: a NON-SOLID level 3 RAR 5 archive with no dictionary named
//! compresses in a 16 MiB window searched under a far-link budget of 1,
//! which is the archive a caller who names 16 MiB and that budget writes;
//! a caller who names a dictionary gets the search they always had, with
//! no budget; `WriteOptions::level3_dictionary_2mib` brings back the
//! 2 MiB archive; and no other level, no solid archive and nothing of
//! the RAR 4 family is moved by that option.
//!
//! Threads: every cell is written at 4 workers, and the default again at
//! 1, 3, 8 and 32. Memory: three members of 9 MiB and under, a 16 MiB
//! window; under 300 MiB at any width.
use rarkit::{
    extract, Disposition, Entropy, FilterPolicy, MemberInfo, MemberSpec, MemoryPolicy, Method,
    Payload, RangeSource, Rar4Version, ReadOptions, Result, Sink, WriteFormat, WriteMethod,
    WriteOptions, Writer,
};
use std::sync::Arc;

const MIB: u64 = 1 << 20;

/// The default this file is about.
const LEVEL3: u64 = 16 * MIB;

/// One member of 9 MiB whose only large repeat lies 3.5 MiB back, and a
/// small one beside it so a solid archive has something to chain.
///
/// The large member holds 512 KiB of noise at 4.5 MiB and again at
/// 8 MiB, text between. A 2 MiB window does not reach the first copy, and neither
/// does a 16 MiB one searched under a far-link budget of 0; a 16 MiB
/// window that follows one far link does, and codes the second copy as
/// a few long matches. So which default ran, and whose budget, shows in
/// the archive's size.
///
/// What bytes cannot show is that a NAMED 16 MiB is searched with no
/// budget: one far link finds this repeat as surely as every link does
/// (which is why the budget is 1). `write::tests` holds that, on what
/// the options resolve to.
fn members() -> Vec<Vec<u8>> {
    let repeat = rarkit_testdata::scramble(21, 512 << 10);
    let mut big = rarkit_testdata::chatter(22, 9 << 19);
    big.extend_from_slice(&repeat);
    big.extend_from_slice(&rarkit_testdata::chatter(24, (8 << 20) - big.len()));
    big.extend_from_slice(&repeat);
    big.extend_from_slice(&rarkit_testdata::chatter(25, (9 << 20) - big.len()));
    vec![big, rarkit_testdata::chatter(26, 40_000)]
}

#[derive(Clone, Copy)]
struct Cell {
    format: WriteFormat,
    level: u8,
    solid: bool,
    /// `WriteOptions::level3_dictionary_2mib`.
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
            level3_dictionary_2mib: self.keep,
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

/// Hand `archive` to reference `unrar t`. It reports a checksum error on
/// stderr and may still exit 0, so both are read.
fn unrar_admits(what: &str, archive: &[u8]) {
    let dir = std::env::temp_dir().join(format!("rarkit-l3dict-{what}-{}", std::process::id()));
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

const FORMATS: [WriteFormat; 2] = [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V29)];

/// The default's bytes: what a named 16 MiB under a budget of 1 writes,
/// smaller than the 2 MiB archive, the same at every width, a caller's
/// own budget taken in its place, and admitted by both readers.
#[test]
fn level_3_non_solid_takes_16_mib_under_a_far_link_budget_of_1() {
    let members = members();
    let level3 = cell(WriteFormat::Rar5, 3, false);
    let default = write(&members, level3);
    let named_budgeted = write(
        &members,
        Cell {
            dictionary: Some(LEVEL3),
            far_link_budget: Some(1),
            ..level3
        },
    );
    assert!(
        default == named_budgeted,
        "the default ({} bytes) is not what a named 16 MiB under a budget of 1 writes ({})",
        default.len(),
        named_budgeted.len()
    );
    assert_eq!(reads_back("rar5-m3", &default, &members), LEVEL3);

    let named_2 = write(
        &members,
        Cell {
            dictionary: Some(2 * MIB),
            ..level3
        },
    );
    assert!(
        default.len() + (64 << 10) < named_2.len(),
        "the default wrote {} bytes and a named 2 MiB {}: the repeat 3.5 MiB back was not reached",
        default.len(),
        named_2.len()
    );
    // A named dictionary declares what was named.
    let named_16 = write(
        &members,
        Cell {
            dictionary: Some(LEVEL3),
            ..level3
        },
    );
    assert_eq!(reads_back("rar5-m3-md16m", &named_16, &members), LEVEL3);

    // One byte for one pool: the default's bytes do not depend on the
    // width.
    for workers in [Some(1), Some(3), Some(8), Some(32)] {
        assert!(
            write(&members, Cell { workers, ..level3 }) == default,
            "{workers:?} workers wrote other bytes"
        );
    }
    // A budget the caller set is the caller's, at the default dictionary
    // too.
    let own_budget = write(
        &members,
        Cell {
            far_link_budget: Some(0),
            ..level3
        },
    );
    assert!(
        default.len() + (64 << 10) < own_budget.len(),
        "a budget of 0 wrote {} bytes and the default {}: the caller's budget was not taken",
        own_budget.len(),
        default.len()
    );
    assert_eq!(reads_back("rar5-m3-f0", &own_budget, &members), LEVEL3);

    if have_unrar() {
        unrar_admits("default", &default);
    } else {
        eprintln!("reference unrar is not on PATH: no archive here is admitted by it");
    }
}

/// The option brings back the 2 MiB archive at RAR 5 level 3 non-solid,
/// and moves no byte anywhere else.
#[test]
fn the_option_keeps_2_mib_and_reaches_nothing_else() {
    assert!(!WriteOptions::default().level3_dictionary_2mib);
    let members = members();
    for format in FORMATS {
        for solid in [false, true] {
            for level in 1u8..=5 {
                let cell = cell(format, level, solid);
                let what = cell.name();
                let default = write(&members, cell);
                let kept = write(&members, Cell { keep: true, ..cell });
                if level == 3 && !solid && format == WriteFormat::Rar5 {
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
                        "{what}: the option moved a byte outside RAR 5 level 3 non-solid"
                    );
                    // Level 1 non-solid RAR 5 has its own default, and
                    // so has a solid RAR 5 archive above level 1 (32 MiB
                    // since 10 Oct 2026, fitted to this set's 9 MiB).
                    let window = if solid && format == WriteFormat::Rar5 && level >= 2 {
                        16 * MIB
                    } else if level == 1 && !solid && format == WriteFormat::Rar5 {
                        4 * MIB
                    } else {
                        2 * MIB
                    };
                    assert_eq!(reads_back(&what, &default, &members), window, "{what}");
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
fn a_memory_policy_reduces_the_default_and_never_refuses_it() {
    let members = members();
    let level3 = cell(WriteFormat::Rar5, 3, false);
    let small = MemoryPolicy {
        max_dictionary: 4 * MIB,
        ..MemoryPolicy::default()
    };
    let reduced = write(
        &members,
        Cell {
            memory: Some(small),
            ..level3
        },
    );
    assert_eq!(reads_back("rar5-m3-4m", &reduced, &members), 4 * MIB);
    let large = MemoryPolicy {
        working_limit: 8 << 30,
        ..MemoryPolicy::default()
    };
    assert!(!large.limit_named);
    let roomy = write(
        &members,
        Cell {
            memory: Some(large),
            ..level3
        },
    );
    assert!(
        roomy == write(&members, level3),
        "a larger policy moved the default's bytes"
    );
    let named_2 = write(
        &members,
        Cell {
            dictionary: Some(2 * MIB),
            ..level3
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
                ..level3
            },
        );
        assert!(
            kept == named_2,
            "under a named ceiling, not the archive a named 2 MiB writes"
        );
    }
}
