//! By design, by default rarfast opens every archive unrar opens, and a
//! STATED memory limit stays a hard cap whose refusal is clean.
//!
//! The archives are reference `rar` 7.23's, made by
//! `tests/large-dictionary/make.sh`, which also checks that reference
//! `unrar` 7.23 tests and extracts each one to the zero bytes it was made
//! from; `SHA256SUMS` pins them. `dict512m.rar` is the reference-writer
//! sweep's fixture, byte for byte: the default policy refused it
//! ("Window wanted 536870912 bytes and the policy allows 268435456"),
//! printed `OK` beside the refusal, exited 2 and left a zero-byte file.
//!
//! | archive | declared | members | window needed |
//! |---|---|---|---|
//! | `dict512m.rar` | 512 MiB | one of 300,000,000 bytes | 300,000,000 |
//! | `dict1g.rar` | 1 GiB | one of 600,000,000 bytes | 600,000,000 |
//! | `dict1g-solid.rar` | 1 GiB | two of 300,000,000, solid | 1 GiB |
//!
//! A non-solid member's window is its unpacked size; a solid
//! stream's is its declared dictionary. The runs here are serialised on
//! one lock, so the file never holds more than one of these windows at
//! once whatever width the harness runs tests at.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;

const MIB: u64 = 1 << 20;

/// One large window at a time across the file's tests.
static HEAVY: Mutex<()> = Mutex::new(());

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/large-dictionary")
        .join(name)
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-largedict-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `rarfast <cmd> -y <switches> <archive> [dest/]`, with the progress
/// lines ON so an `OK` would show.
fn run(cmd: &str, switches: &[&str], archive: &Path, dest: Option<&Path>) -> Output {
    let mut c = Command::new(rarfast());
    c.args([cmd, "-y"]).args(switches).arg(archive);
    if let Some(d) = dest {
        c.arg(format!("{}/", d.display()));
    }
    c.output().unwrap()
}

fn said(done: &Output) -> String {
    format!(
        "exit {:?}\nstdout:\n{}\nstderr:\n{}",
        done.status.code(),
        String::from_utf8_lossy(&done.stdout),
        String::from_utf8_lossy(&done.stderr)
    )
}

struct Case {
    archive: &'static str,
    /// Each member's name under `src/` and its length in zero bytes.
    members: &'static [(&'static str, u64)],
    /// The window the archive needs, in bytes.
    window: u64,
}

const CASES: [Case; 3] = [
    Case {
        archive: "dict512m.rar",
        members: &[("zeros", 300_000_000)],
        window: 300_000_000,
    },
    Case {
        archive: "dict1g.rar",
        members: &[("big", 600_000_000)],
        window: 600_000_000,
    },
    Case {
        archive: "dict1g-solid.rar",
        members: &[("a", 300_000_000), ("b", 300_000_000)],
        window: 1024 * MIB,
    },
];

/// `path` holds exactly `len` zero bytes, read in pieces.
fn assert_zeros(path: &Path, len: u64) {
    use std::io::Read;
    let mut file = std::fs::File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut buf = vec![0u8; 8 << 20];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        assert!(
            buf[..n].iter().all(|&b| b == 0),
            "{}: a non-zero byte",
            path.display()
        );
        total += n as u64;
    }
    assert_eq!(total, len, "{}", path.display());
}

/// The refusal a stated limit asks for: non-zero exit, the engine's named
/// error, no `OK` on any member's line nor `All OK`, and no member file
/// left in `out`. The `src` DIRECTORY's `Creating ... OK` line stands: the
/// directory was created, as the reference creates it. A
/// STATED budget below the archive's one-member floor is refused before
/// any member, naming working memory: `-mm` is a whole-process budget,
/// and the floor is one window and the fixed part beside the process's
/// headroom (SPEC-API 8.4.1), which is what these archives' members
/// exceed.
fn assert_refused(done: &Output, case: &Case, out: Option<&Path>, what: &str) {
    let text = said(done);
    assert!(!done.status.success(), "{what}: refused but exit 0\n{text}");
    assert!(
        text.contains("WorkingMemory wanted"),
        "{what}: no named working-memory refusal\n{text}"
    );
    let stdout = String::from_utf8_lossy(&done.stdout);
    assert!(
        stdout
            .lines()
            .all(|line| !line.contains("OK") || line.starts_with("Creating")),
        "{what}: an OK beside the refusal\n{text}"
    );
    if let Some(out) = out {
        for (name, _) in case.members {
            let path = out.join("src").join(name);
            assert!(
                !path.exists(),
                "{what}: {} left behind\n{text}",
                path.display()
            );
        }
    }
}

/// By DEFAULT every archive opens, `t` at both read paths and `x` at one
/// of them, and extracts the zero bytes unrar 7.23 extracts. On a machine
/// whose half of physical memory is under an archive's window the default
/// refuses it, cleanly; every box this crate is tested on holds all three.
#[test]
fn each_large_dictionary_opens_by_default_as_unrar_opens_it() {
    let _heavy = HEAVY.lock().unwrap_or_else(|p| p.into_inner());
    let ceiling = rarkit::MemoryPolicy::default().max_window;
    for (turn, case) in CASES.iter().enumerate() {
        let fits = case.window <= ceiling;
        for width in ["-mt1", "-mt4"] {
            let done = run("t", &[width], &fixture(case.archive), None);
            if fits {
                assert!(
                    done.status.success(),
                    "t {} {width}: {}",
                    case.archive,
                    said(&done)
                );
            } else {
                assert_refused(&done, case, None, &format!("t {} {width}", case.archive));
            }
        }
        let width = if turn % 2 == 0 { "-mt4" } else { "-mt1" };
        let out = work(&format!("default{turn}"));
        let done = run("x", &[width, "-idq"], &fixture(case.archive), Some(&out));
        if fits {
            assert!(
                done.status.success(),
                "x {} {width}: {}",
                case.archive,
                said(&done)
            );
            for (name, len) in case.members {
                assert_zeros(&out.join("src").join(name), *len);
            }
        } else {
            assert_refused(&done, case, Some(&out), &format!("x {}", case.archive));
        }
        let _ = std::fs::remove_dir_all(&out);
    }
}

/// A STATED limit is hard: `-mm<size>` is a budget for the whole process,
/// and a member whose one window does not fit it beside the process's
/// 32 MiB of headroom is refused whatever the width.
/// Under `-mm256m` every archive is refused by `t` and by `x`,
/// with and without `-kb`, at both read paths; the refusal exits non-zero,
/// names the window, prints no `OK` and leaves no member file.
#[test]
fn a_stated_limit_refuses_cleanly() {
    let _heavy = HEAVY.lock().unwrap_or_else(|p| p.into_inner());
    for (turn, case) in CASES.iter().enumerate() {
        for width in ["-mt1", "-mt4"] {
            let what = format!("{} {width} -mm256m", case.archive);
            let done = run("t", &[width, "-mm256m"], &fixture(case.archive), None);
            assert_refused(&done, case, None, &format!("t {what}"));
            for keep in [None, Some("-kb")] {
                let out = work(&format!("cap{turn}{width}{}", keep.is_some()));
                let mut switches = vec![width, "-mm256m"];
                switches.extend(keep);
                let done = run("x", &switches, &fixture(case.archive), Some(&out));
                assert_refused(&done, case, Some(&out), &format!("x {what} {keep:?}"));
                let _ = std::fs::remove_dir_all(&out);
            }
        }
    }
}

/// The cap binds on what a member NEEDS, not on what it declares.
///
/// `-mm1g` holds one window of 300,000,000 bytes and one of 600,000,000,
/// so both of those members open (the second was refused while a stated
/// limit asked for two windows; SPEC-API 8.4.1 has the account at a width
/// of one), and the solid archive, whose window is its declared 1 GiB, is
/// refused. `-mm700m` is under `dict512m.rar`'s DECLARED 512 MiB beside
/// the headroom, and the member still opens: only a window sized to the
/// member's own 300,000,000 bytes fits there, which is the member-sized
/// window seen from outside the process.
#[test]
fn a_stated_limit_binds_on_the_window_a_member_needs() {
    let _heavy = HEAVY.lock().unwrap_or_else(|p| p.into_inner());
    for width in ["-mt1", "-mt4"] {
        for cap in ["-mm1g", "-mm700m"] {
            let done = run("t", &[width, cap], &fixture("dict512m.rar"), None);
            assert!(
                done.status.success(),
                "t dict512m {width} {cap}: {}",
                said(&done)
            );
        }
        let done = run("t", &[width, "-mm1g"], &fixture(CASES[1].archive), None);
        assert!(
            done.status.success(),
            "t dict1g {width} -mm1g: {}",
            said(&done)
        );
        let case = &CASES[2];
        let done = run("t", &[width, "-mm1g"], &fixture(case.archive), None);
        assert_refused(
            &done,
            case,
            None,
            &format!("t {} {width} -mm1g", case.archive),
        );
    }
    let out = work("mm700m");
    let done = run(
        "x",
        &["-mm700m", "-idq"],
        &fixture("dict512m.rar"),
        Some(&out),
    );
    assert!(done.status.success(), "x dict512m -mm700m: {}", said(&done));
    assert_zeros(&out.join("src/zeros"), 300_000_000);
    let _ = std::fs::remove_dir_all(&out);
}
