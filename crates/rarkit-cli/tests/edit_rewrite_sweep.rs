//! The rewriting commands (`d`, `rn`, `k`, `c`) on the cases a bug sweep
//! of 4 Oct 2026 found them wrong on.
//!
//! Every expectation below was MEASURED on 4 Oct 2026 against `rar` 7.23
//! on macOS, over the same archives:
//!
//! - an archive holding two members of one name (`rar a -ep a/same.txt
//!   b/same.txt` makes one, and so does rarfast): `rar d arc.rar same.txt`
//!   prints `Deleting same.txt` twice and leaves NEITHER; `rar rn arc.rar
//!   same.txt other.txt` renames BOTH;
//! - a locked archive: `rar c -z<file> arc.rar` prints `Processing archive
//!   arc.rar` and `Done` on stdout, `ERROR: Locked archive` on stderr,
//!   exits 4 and leaves the archive as it was. The comment file is not
//!   read first: one that is not there gets the same answer. `rn`, `k`,
//!   `ch` and `rr3` over a locked archive answer in the same words, the
//!   same exit and the archive untouched; `d` alone says `Program
//!   aborted` in place of the two stdout lines.
//!
//! The rewrite's own file handling is not the reference's and is pinned
//! here as rarfast's: the new archive is made under a name nothing else
//! holds and never through a link somebody left at a guessable one, and
//! it carries the permissions the archive had (the reference itself gives
//! a rewritten archive the umask's, measured: 0600 comes back 0644).
//!
//! Width and memory: every archive here is a few hundred bytes and every
//! rarfast call states `-mt1`, so no test depends on the machine's width.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-editsweep-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(&dir).unwrap()
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(rarfast())
        .current_dir(dir)
        .arg(args[0])
        .arg("-mt1")
        .args(&args[1..])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap()
}

fn ok(dir: &Path, args: &[&str]) -> Output {
    let output = run(dir, args);
    assert!(
        output.status.success(),
        "rarfast {args:?}: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn names(dir: &Path, archive: &str) -> Vec<String> {
    let output = ok(dir, &["lb", archive]);
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// `arc.rar` holding `same.txt`, `same.txt` and `keep.txt`, in that order.
fn twice_named(tag: &str) -> PathBuf {
    let dir = work(tag);
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    std::fs::write(dir.join("a/same.txt"), "one\n").unwrap();
    std::fs::write(dir.join("b/same.txt"), "two-two\n").unwrap();
    std::fs::write(dir.join("keep.txt"), "k\n").unwrap();
    ok(
        &dir,
        &[
            "a",
            "-idq",
            "-ep",
            "arc.rar",
            "a/same.txt",
            "b/same.txt",
            "keep.txt",
        ],
    );
    assert_eq!(names(&dir, "arc.rar"), ["same.txt", "same.txt", "keep.txt"]);
    dir
}

/// `arc.rar` holding `keep.txt` alone.
fn plain(tag: &str) -> PathBuf {
    let dir = work(tag);
    std::fs::write(dir.join("keep.txt"), "k\n").unwrap();
    ok(&dir, &["a", "-idq", "arc.rar", "keep.txt"]);
    dir
}

#[test]
fn d_drops_every_member_that_stores_the_name() {
    let dir = twice_named("d-twice");
    let output = ok(&dir, &["d", "arc.rar", "same.txt"]);
    let said = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(said.matches("Deleting same.txt\n").count(), 2, "{said}");
    assert_eq!(names(&dir, "arc.rar"), ["keep.txt"]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rn_renames_every_member_that_stores_the_name() {
    let dir = twice_named("rn-twice");
    let output = ok(&dir, &["rn", "arc.rar", "same.txt", "other.txt"]);
    let said = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(
        said.matches("Renaming same.txt to other.txt\n").count(),
        2,
        "{said}"
    );
    assert_eq!(
        names(&dir, "arc.rar"),
        ["other.txt", "other.txt", "keep.txt"]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn c_refuses_a_locked_archive() {
    let dir = plain("c-locked");
    std::fs::write(dir.join("c.txt"), "a new comment\n").unwrap();
    ok(&dir, &["k", "arc.rar"]);
    let before = std::fs::read(dir.join("arc.rar")).unwrap();
    for comment in ["-zc.txt", "-znosuch.txt"] {
        let output = run(&dir, &["c", comment, "arc.rar"]);
        let said = String::from_utf8_lossy(&output.stdout).into_owned();
        let warned = String::from_utf8_lossy(&output.stderr).into_owned();
        assert_eq!(output.status.code(), Some(4), "{comment}: {said}{warned}");
        assert_eq!(said, "\nProcessing archive arc.rar\nDone\n", "{comment}");
        assert!(
            warned.contains("ERROR: Locked archive"),
            "{comment}: {warned}"
        );
        assert_eq!(std::fs::read(dir.join("arc.rar")).unwrap(), before);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rn_k_ch_and_rr_refuse_a_locked_archive() {
    let dir = plain("others-locked");
    ok(&dir, &["k", "arc.rar"]);
    let before = std::fs::read(dir.join("arc.rar")).unwrap();
    let cases: [&[&str]; 5] = [
        &["rn", "arc.rar", "keep.txt", "other.txt"],
        &["k", "arc.rar"],
        &["ch", "arc.rar"],
        &["ch", "-k", "arc.rar"],
        &["rr3", "arc.rar"],
    ];
    for args in cases {
        let output = run(&dir, args);
        let said = String::from_utf8_lossy(&output.stdout).into_owned();
        let warned = String::from_utf8_lossy(&output.stderr).into_owned();
        assert_eq!(output.status.code(), Some(4), "{args:?}: {said}{warned}");
        assert_eq!(said, "\nProcessing archive arc.rar\nDone\n", "{args:?}");
        assert!(
            warned.contains("ERROR: Locked archive"),
            "{args:?}: {warned}"
        );
        assert_eq!(
            std::fs::read(dir.join("arc.rar")).unwrap(),
            before,
            "{args:?}"
        );
    }
    // `d` keeps its own words.
    let output = run(&dir, &["d", "arc.rar", "keep.txt"]);
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "\nProgram aborted\n"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rn_says_nothing_of_a_name_no_member_stores() {
    let dir = plain("rn-none");
    let output = ok(&dir, &["rn", "arc.rar", "nosuch.txt", "x.txt"]);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "\nProcessing archive arc.rar\nDone\n"
    );
    assert_eq!(names(&dir, "arc.rar"), ["keep.txt"]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Unix only by its nature: the permissions are a Unix mode.
#[cfg(unix)]
#[test]
fn a_rewrite_keeps_the_archives_permissions() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = plain("mode");
    let archive = dir.join("arc.rar");
    std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o600)).unwrap();
    ok(&dir, &["k", "arc.rar"]);
    let mode = std::fs::metadata(&archive).unwrap().permissions().mode();
    assert_eq!(mode & 0o7777, 0o600, "{mode:o}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Unix only by its nature: the link is made with the Unix call, which
/// asks no privilege of the user.
#[cfg(unix)]
#[test]
fn a_rewrite_never_writes_through_a_link_left_beside_the_archive() {
    let dir = plain("link");
    std::fs::write(dir.join("victim"), "not an archive\n").unwrap();
    std::os::unix::fs::symlink("victim", dir.join("arc.rar.rarfast-new")).unwrap();
    ok(&dir, &["k", "arc.rar"]);
    assert_eq!(
        std::fs::read(dir.join("victim")).unwrap(),
        b"not an archive\n"
    );
    // The archive itself is still a regular file, rewritten and locked.
    assert!(std::fs::symlink_metadata(dir.join("arc.rar"))
        .unwrap()
        .file_type()
        .is_file());
    let output = run(&dir, &["d", "arc.rar", "keep.txt"]);
    assert_eq!(output.status.code(), Some(4));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_rewrite_leaves_nothing_beside_the_archive() {
    let dir = plain("leftover");
    ok(&dir, &["k", "arc.rar"]);
    let mut left: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, ["arc.rar", "keep.txt"]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Spec CLI 11.3 E7: a link at the archive's name is replaced by the new
/// archive, an ordinary file, and the archive it pointed at is left as
/// it was. One process at a time, files of a few bytes. Unix only by
/// its nature: the link is made with the Unix call.
#[cfg(unix)]
#[test]
fn a_rewrite_replaces_a_link_at_the_name_and_leaves_what_it_pointed_at() {
    let dir = plain("name-is-link");
    std::fs::rename(dir.join("arc.rar"), dir.join("real.rar")).unwrap();
    let before = std::fs::read(dir.join("real.rar")).unwrap();
    std::os::unix::fs::symlink("real.rar", dir.join("arc.rar")).unwrap();
    ok(&dir, &["rn", "arc.rar", "keep.txt", "kept.txt"]);
    assert!(std::fs::symlink_metadata(dir.join("arc.rar"))
        .unwrap()
        .file_type()
        .is_file());
    assert_eq!(names(&dir, "arc.rar"), ["kept.txt"]);
    assert!(std::fs::read(dir.join("real.rar")).unwrap() == before);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Spec CLI 11.3 E5, and rarkit's choice where E4 differs: an archive its owner may not write,
/// in a directory that can be written, is edited, and the new archive
/// keeps the mode the old one had. One process at a time, files of a few
/// bytes. Unix only by its nature: the permissions are a Unix mode.
#[cfg(unix)]
#[test]
fn a_read_only_archive_is_edited_and_keeps_its_mode() {
    use std::os::unix::fs::PermissionsExt as _;
    for (tag, edit, after) in [
        (
            "ro-rn",
            &["rn", "arc.rar", "keep.txt", "kept.txt"][..],
            "kept.txt",
        ),
        ("ro-k", &["k", "arc.rar"][..], "keep.txt"),
    ] {
        let dir = plain(tag);
        let archive = dir.join("arc.rar");
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o444)).unwrap();
        ok(&dir, edit);
        assert_eq!(names(&dir, "arc.rar"), [after], "{tag}");
        let mode = std::fs::metadata(&archive).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o444, "{tag}: {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A rewrite the engine refuses leaves the archive byte for byte what it
/// was and nothing of its own beside it (spec CLI 11.4), and `rn` on one
/// volume of a set is such a refusal, as `d` is (rarkit's choice where
/// H11 differs): by name, on stderr, with the exit the reference gives
/// `d` there, 4. One process at a time, 30 KB.
#[test]
fn rn_on_one_volume_of_a_set_is_refused_and_leaves_it_as_it_was() {
    let dir = work("rn-volume");
    let noise: Vec<u8> = (0..30_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    std::fs::write(dir.join("big.bin"), noise).unwrap();
    ok(&dir, &["a", "-idq", "-m0", "-v8k", "set.rar", "big.bin"]);
    let first = dir.join("set.part1.rar");
    let before = std::fs::read(&first).unwrap();
    let mut held: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    held.sort();
    let output = run(&dir, &["rn", "set.part1.rar", "big.bin", "z.bin"]);
    assert_eq!(output.status.code(), Some(4));
    let warned = String::from_utf8_lossy(&output.stderr);
    assert!(
        warned.contains("rarfast: cannot change set.part1.rar: "),
        "{warned}"
    );
    assert!(std::fs::read(&first).unwrap() == before);
    let mut left: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    left.sort();
    assert_eq!(left, held);
    let _ = std::fs::remove_dir_all(&dir);
}
