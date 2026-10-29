//! The far-link budget (`WriteOptions::far_link_budget`) through the
//! public `Writer`: off by default; no byte moved at a dictionary of 2 MiB
//! or less, whatever the budget; at a longer dictionary, a budget of one
//! link finds a repeat that lies 3 MiB back and a budget of none does not;
//! a budget no chain can spend is the search with no budget; level 1 and
//! the tree of level 5 read nothing of it; and the bytes are
//! the same at any encoder width.
//!
//! That a create with the option OFF writes what it wrote before the
//! option existed is held by the pins other files carry
//! (`level1_default_dictionary.rs`, `level3_parse.rs`), which this change
//! leaves as they were.
use rarkit::{
    extract, Disposition, Entropy, FilterPolicy, MemberInfo, MemberSpec, Method, Payload,
    RangeSource, Rar4Version, ReadOptions, Result, Sink, WriteFormat, WriteMethod, WriteOptions,
    Writer,
};
use std::sync::Arc;

const MIB: u64 = 1 << 20;

/// How long the repeat of [`members`] is.
const REPEAT: usize = 512 << 10;

/// One member of 6 MiB whose only large repeat lies 3 MiB back: half a
/// MiB of noise, 2.5 MiB of words, the same noise again, 2.5 MiB of other
/// words. The noise's four byte words are its own, so the nearest earlier
/// position on the chain of a position in its second copy is, nearly
/// always, the same position of the first: a FAR link, 3 MiB back, and
/// the first one past 2 MiB. Beside it a small member, so that a solid
/// archive has something to chain.
fn members() -> Vec<Vec<u8>> {
    let repeat = rarkit_testdata::scramble(21, REPEAT);
    let mut big = repeat.clone();
    big.extend_from_slice(&rarkit_testdata::chatter(22, 5 << 19));
    big.extend_from_slice(&repeat);
    big.extend_from_slice(&rarkit_testdata::chatter(23, 5 << 19));
    vec![big, rarkit_testdata::chatter(24, 40_000)]
}

#[derive(Clone, Copy)]
struct Cell {
    format: WriteFormat,
    level: u8,
    solid: bool,
    dictionary: Option<u64>,
    budget: Option<u32>,
    /// Levels 4 and 5 over the tree (`level4_tree`, `level5_tree`).
    tree: bool,
    workers: usize,
}

impl Cell {
    fn name(self) -> String {
        let format = match self.format {
            WriteFormat::Rar5 => "rar5",
            WriteFormat::Rar4(_) => "rar4v29",
        };
        format!(
            "{format}-m{}{}-md{:?}-far{:?}-w{}",
            self.level,
            if self.solid { "s" } else { "" },
            self.dictionary.map(|d| d / MIB),
            self.budget,
            self.workers
        )
    }

    fn with(self, budget: Option<u32>) -> Cell {
        Cell { budget, ..self }
    }
}

fn cell(format: WriteFormat, level: u8, solid: bool, dictionary: Option<u64>) -> Cell {
    Cell {
        format,
        level,
        solid,
        dictionary,
        budget: None,
        tree: false,
        workers: 4,
    }
}

fn write(members: &[Vec<u8>], cell: Cell) -> Vec<u8> {
    let options = WriteOptions {
        format: cell.format,
        method: WriteMethod::Compressed {
            level: cell.level,
            dictionary: cell.dictionary,
        },
        solid: cell.solid,
        // The RAR 4 family writes no filter record (SPEC-J).
        filters: match cell.format {
            WriteFormat::Rar5 => FilterPolicy::Detect,
            WriteFormat::Rar4(_) => FilterPolicy::Off,
        },
        far_link_budget: cell.budget,
        level4_tree: cell.tree,
        level5_tree: cell.tree,
        entropy: Entropy::Seeded([5; 32]),
        workers: Some(cell.workers),
        ..WriteOptions::default()
    };
    let mut writer = Writer::new(options).expect("options");
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
    let dir = std::env::temp_dir().join(format!("rarkit-farlink-{what}-{}", std::process::id()));
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

#[test]
fn the_budget_is_off_by_default() {
    assert_eq!(WriteOptions::default().far_link_budget, None);
}

/// At 2 MiB, default or named, and at 1 MiB, no candidate is farther back
/// than 2 MiB, so no budget moves a byte: at every level, in both
/// families, solid and not.
#[test]
fn no_budget_moves_a_byte_at_two_mib_or_less() {
    let members = members();
    for format in FORMATS {
        for level in 1..=5u8 {
            for solid in [false, true] {
                for dictionary in [None, Some(2 * MIB), Some(MIB)] {
                    // Level 1's own default is 4 MiB in a non-solid RAR 5
                    // archive, which the next tests cover, and level 3's
                    // is 16 MiB there since 9 Oct 2026
                    // (`level3_default_dictionary`).
                    if dictionary.is_none() && (level == 1 || level == 3) {
                        continue;
                    }
                    // A solid RAR 5 archive's default is 32 MiB since
                    // 10 Oct 2026 (`solid_default_dictionary`).
                    if dictionary.is_none() && solid && format == WriteFormat::Rar5 {
                        continue;
                    }
                    let base = cell(format, level, solid, dictionary);
                    let off = write(&members, base);
                    for budget in [0, 1, 7] {
                        let on = write(&members, base.with(Some(budget)));
                        assert!(
                            on == off,
                            "{}: a budget of {budget} moved bytes at 2 MiB or less",
                            base.name()
                        );
                    }
                }
            }
        }
    }
}

/// At a named 4 MiB the chain levels 2, 3 and 4 find the repeat 3 MiB back
/// with a budget of one link and not with a budget of none; the archive
/// declares 4 MiB either way and reads back. So does level 5, which goes
/// by class (SPEC-H3 8.1): the member's head reads few far links, so it
/// takes the chains, and a solid run goes by that first member.
#[test]
fn one_far_link_finds_the_repeat_three_mib_back() {
    let members = members();
    let unrar = have_unrar();
    for format in FORMATS {
        for level in [2u8, 3, 4, 5] {
            for solid in [false, true] {
                let base = cell(format, level, solid, Some(4 * MIB));
                let none = write(&members, base.with(Some(0)));
                let one = write(&members, base.with(Some(1)));
                let full = write(&members, base);
                for (what, archive) in [("far0", &none), ("far1", &one), ("full", &full)] {
                    let what = format!("{}-{what}", base.name());
                    let window = reads_back(&what, archive, &members);
                    // The RAR 4 family's header carries its window in
                    // another form; RAR 5's is the figure named.
                    if format == WriteFormat::Rar5 {
                        assert_eq!(window, 4 * MIB, "{what}: the window declared");
                    }
                }
                if unrar {
                    unrar_admits(&format!("{}-far1", base.name()), &one);
                }
                // The repeat is noise: found, it is a few hundred bytes of
                // matches; missed, its half MiB goes out as literals.
                assert!(
                    none.len() > one.len() + REPEAT * 9 / 10,
                    "{}: a budget of one link did not find the far repeat ({} against {})",
                    base.name(),
                    one.len(),
                    none.len()
                );
                assert!(
                    one.len() < full.len() + REPEAT / 10,
                    "{}: one far link wrote far more than the whole search ({} against {})",
                    base.name(),
                    one.len(),
                    full.len()
                );
            }
        }
    }
}

/// A budget no search can spend is the search with no budget: each search
/// follows at most its depth in links, far or near.
#[test]
fn a_budget_past_the_depth_is_no_budget() {
    let members = members();
    for format in FORMATS {
        for level in [2u8, 3, 4, 5] {
            for solid in [false, true] {
                let base = cell(format, level, solid, Some(4 * MIB));
                let off = write(&members, base);
                let on = write(&members, base.with(Some(u32::MAX)));
                assert!(
                    on == off,
                    "{}: an unspendable budget moved bytes",
                    base.name()
                );
            }
        }
    }
}

/// Level 1 takes no budget (its searches follow one link, and its empty
/// blocks' floor scan asks the chains too: the members' noise is such
/// blocks), and the tree reads none: levels 4 and 5 kept on the tree by
/// their options move no byte, at any dictionary.
#[test]
fn level_1_and_the_tree_read_no_budget() {
    let members = members();
    for (level, tree) in [(1u8, false), (4, true), (5, true)] {
        for solid in [false, true] {
            let base = Cell {
                tree,
                ..cell(WriteFormat::Rar5, level, solid, Some(4 * MIB))
            };
            let off = write(&members, base);
            for budget in [0, 1] {
                let on = write(&members, base.with(Some(budget)));
                assert!(
                    on == off,
                    "{}{}: a budget of {budget} moved bytes",
                    base.name(),
                    if tree { "-tree" } else { "" }
                );
            }
        }
    }
}

/// The budget is a rule of the search and never of the width: the same
/// bytes on one encoder thread and on eight.
#[test]
fn the_budgeted_bytes_are_the_same_at_any_width() {
    let members = members();
    for level in [2u8, 3, 4] {
        for solid in [false, true] {
            for dictionary in [4 * MIB, 8 * MIB] {
                let base = Cell {
                    budget: Some(1),
                    workers: 1,
                    ..cell(WriteFormat::Rar5, level, solid, Some(dictionary))
                };
                let narrow = write(&members, base);
                let wide = write(&members, Cell { workers: 8, ..base });
                assert!(
                    narrow == wide,
                    "{}: the budgeted archive differs between one thread and eight",
                    base.name()
                );
            }
        }
    }
}
