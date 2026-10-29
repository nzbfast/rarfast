//! Two properties a create must hold whatever the command line says: it
//! spends a BOUNDED number of open descriptors, and it is never silent
//! about having failed.
//!
//! Both were defects, both were measured on a 32 core aarch64 Mac at
//! macOS's default soft limit of 256 on 19 Sep 2026, and each row below
//! FAILS on the code as it stood before the fix:
//!
//! | files added with `a -r` | before |
//! | --- | --- |
//! | 252 | exit 0 |
//! | 256 | exit 2, no archive |
//! | 4,000 | exit 2, no archive |
//! | 4,000 under `ulimit -Sn 10240` | exit 0 |
//!
//! Under `-idq` that failure printed NOTHING: stderr was empty and the
//! only signal a script had was the exit code, which is the shape spec
//! R.2 calls the worse failure.
//!
//! **Why the budget is lowered in a child and not here.** The workspace
//! forbids `unsafe`, so neither `libc::setrlimit` nor `CommandExt::pre_exec`
//! is open to this crate, and lowering a process-wide limit inside a test
//! binary would reach every other test sharing the process anyway. A shell
//! calling `ulimit -n` before `exec` performs the same `setrlimit(2)` on
//! the process that actually does the work, leaves this one untouched so
//! there is nothing to restore, and keeps the row hermetic and safe beside
//! its neighbours. The tree it works over is 300 files rather than
//! thousands, which is what the small budget buys.

// Unix only by its nature: a descriptor budget is `ulimit -n` in a Unix shell, and the
// unopenable source is shut by a Unix mode.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// The soft descriptor budget the create is given, well under the member
/// count and well under macOS's own default of 256.
const BUDGET: usize = 96;

/// How many members the create writes. More than `BUDGET`, so a creator
/// holding one descriptor per member cannot finish, and small enough that
/// building the tree costs nothing.
const MEMBERS: usize = 300;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// A directory of one test's own under the system's temporary directory,
/// emptied first: an archive an earlier run wrote there is not found.
fn work(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("rarfast-descriptors-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs `rarfast` in `dir` with the soft descriptor limit lowered to
/// `budget` for the run, and answers its exit code, stdout and stderr.
fn run_with_budget(dir: &Path, budget: usize, args: &[&str]) -> (Option<i32>, String, String) {
    let line = format!(
        "ulimit -n {budget} && exec {} {}",
        shell_word(&rarfast().to_string_lossy()),
        args.iter()
            .map(|arg| shell_word(arg))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let out = Command::new("/bin/sh")
        .arg("-c")
        .arg(&line)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|err| panic!("the shell could not be run: {err}"));
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// One argument, quoted so a path with a space in it survives the shell.
fn shell_word(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// The create must finish over far more members than it has descriptors.
///
/// This is the whole defect: every member was added and reported `OK`,
/// and the run then failed at the CLOSE with `Too many open files` and
/// removed the half-written archive, so the work was done and thrown
/// away. Before the fix this row fails with exit 2 and no archive.
#[test]
fn a_create_outlasts_a_small_descriptor_budget() {
    let dir = work("budget");
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    for index in 0..MEMBERS {
        std::fs::write(
            tree.join(format!("f{index}.txt")),
            format!("member {index}\n"),
        )
        .unwrap();
    }

    let (exit, _, stderr) =
        run_with_budget(&dir, BUDGET, &["a", "-r", "-y", "-m0", "arc.rar", "tree"]);
    assert_eq!(
        exit,
        Some(0),
        "a create of {MEMBERS} members under a budget of {BUDGET} descriptors failed: {stderr}"
    );

    // The archive is not merely present: it holds every member, so the
    // budget was met by writing the files and not by dropping them.
    let listed = Command::new(rarfast())
        .args(["lb", "arc.rar"])
        .current_dir(&dir)
        .output()
        .unwrap();
    let listed = String::from_utf8_lossy(&listed.stdout);
    let held = listed
        .lines()
        .filter(|line| line.trim_end().ends_with(".txt"))
        .count();
    assert_eq!(
        held, MEMBERS,
        "the archive holds {held} of {MEMBERS} members"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A create that failed must say so on stderr under `-idq`.
///
/// `-idq` folded into the same flag as `-inul` before this, so a quiet
/// run that could not write the archive printed nothing at all and left
/// the exit code as the only report. The reference does not do that:
/// measured 19 Sep 2026, `rar a -idq /nope/arc.rar text.txt` exits 9 with
/// an empty stdout and `Cannot create /nope/arc.rar` on stderr.
#[test]
fn a_failed_create_is_loud_under_idq() {
    let dir = work("idq");
    std::fs::write(dir.join("one.txt"), b"payload\n").unwrap();
    // A directory that is not there, so the archive cannot be created.
    let target = "nosuchdir/arc.rar";

    let (exit, stdout, stderr) =
        run_with_budget(&dir, 1024, &["a", "-y", "-m0", "-idq", target, "one.txt"]);
    assert_ne!(exit, Some(0), "the create should not have succeeded");
    assert!(
        stdout.is_empty(),
        "`-idq` should still silence stdout, and printed: {stdout}"
    );
    assert!(
        stderr.contains("Cannot create") && stderr.contains("arc.rar"),
        "`-idq` swallowed the only report of a failed create; stderr was {stderr:?}"
    );

    // `-inul` is the switch that really does silence everything, and the
    // reference agrees: the same run under it exits 9 with both streams
    // empty. Pinned here so the two are not folded back together.
    let (silent_exit, silent_out, silent_err) =
        run_with_budget(&dir, 1024, &["a", "-y", "-m0", "-inul", target, "one.txt"]);
    assert_ne!(silent_exit, Some(0));
    assert!(
        silent_out.is_empty() && silent_err.is_empty(),
        "`-inul` should silence both streams, and printed {silent_out:?} / {silent_err:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A source that will not open is reported AT THAT MEMBER, by name, and
/// nothing claims it went into the archive.
///
/// Before this, the run printed `Adding  no1.txt  100%  OK` for BOTH
/// unreadable files and then failed at the close with `the caller's own
/// code failed: Permission denied (os error 13)`, which names no member
/// at all: `Report::finish` filled in every member the writer never
/// reached as though it had been written. Now the failure is announced
/// where it happens, in the reference's own two lines, the run stops, and
/// the exit code is the reference's 6 for this cause rather than a
/// general 2.
///
/// **Since 8 Oct 2026 the rest is archived, as the reference archives
/// it**: it stores what it could read, prints `WARNING: Cannot open 2
/// files` on stdout and exits 6. Until then this crate wrote NO archive,
/// a difference it reported, because the up-front probe that buys the
/// skip costs one `open` and one `close` per member - a measured 57 ms on
/// a 4,000 member create, a 1.27x regression on a create that is not
/// otherwise slower at all. The walk now reads the answer from the mode
/// in the stat it has already taken, and asks the system only about a
/// file whose owner may not read it (`select::owner_cannot_read`), so a
/// readable file pays nothing. A file that will not open for another
/// reason is still met by the writer, reported at its member as below,
/// and still ends the create with no archive.
#[test]
fn an_unopenable_source_is_reported_at_its_member() {
    use std::os::unix::fs::PermissionsExt;

    let dir = work("unopenable");
    std::fs::write(dir.join("ok.txt"), b"hi\n").unwrap();
    for name in ["no1.txt", "no2.txt"] {
        let path = dir.join(name);
        std::fs::write(&path, b"x\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    }

    // Root opens a mode 000 file, so there is nothing to measure there.
    if std::fs::File::open(dir.join("no1.txt")).is_ok() {
        eprintln!("not measured: a mode 000 file opens for this user, so no source is unopenable");

        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    let (exit, stdout, stderr) = run_with_budget(
        &dir,
        1024,
        &["a", "-y", "-m0", "arc.rar", "ok.txt", "no1.txt", "no2.txt"],
    );

    assert_eq!(
        exit,
        Some(6),
        "the reference's exit code for a source it cannot open is 6; \
         stdout was {stdout:?}, stderr was {stderr:?}"
    );
    assert!(
        stderr.contains("Cannot open no1.txt") && stderr.contains("Permission denied"),
        "the member that refused was not named where it refused: {stderr:?}"
    );
    assert!(
        !stdout.contains("no1.txt") && !stdout.contains("no2.txt"),
        "a file that was never added must not be reported `OK`: {stdout:?}"
    );
    assert!(
        stdout.contains("WARNING: Cannot open 2 files"),
        "the count of files left out was not said: {stdout:?}"
    );
    let (listed, names, _) = run_with_budget(&dir, 1024, &["lb", "arc.rar"]);
    assert_eq!(
        (listed, names.as_str()),
        (Some(0), "ok.txt\n"),
        "the archive should hold the one file that could be read"
    );

    for name in ["no1.txt", "no2.txt"] {
        let path = dir.join(name);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}
