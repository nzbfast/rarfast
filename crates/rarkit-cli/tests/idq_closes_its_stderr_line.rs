//! Item 1 of the 28 Sep 2026 CLI parity leftovers: `-idq` closes its own
//! last stderr line.
//!
//! Measured against `rar`/`unrar` 7.23 on a Mac, both streams captured
//! SEPARATELY (a shell's `2>&1` reorders them, since stdout is fully
//! buffered once it is not a terminal and stderr is not - it says nothing
//! reliable about which byte came from which stream):
//!
//! | run | reference stderr |
//! | --- | --- |
//! | `unrar t arc.rar` (data corrupted, plain) | `\n<name>          - checksum error` (no trailing `\n`) |
//! | `unrar t -idq arc.rar` (same damage) | `\n<name>          - checksum error\n` (one more byte) |
//! | `unrar l nosuch.rar` (plain) | `\nCannot open nosuch.rar\nNo such file or directory` (no trailing `\n`) |
//! | `unrar l -idq nosuch.rar` | the same, `\n` at the end |
//!
//! So the newline belongs to `-idq` closing out whatever it left on
//! stderr, not to the checksum-error message itself - a plain run already
//! matched the reference before this fix (the row a subsequent stdout
//! line, or the shell prompt, moves the cursor down for). `lb` is the one
//! spelling that keeps its line open even under `-idq` (measured with a
//! missing archive AND with a corrupt header, both ending with no `\n`
//! at the reference on `lb` where `l` gets one in the same spot), and is
//! pinned here too so the fix does not overreach.

use std::path::{Path, PathBuf};
use std::process::Command;

// The copy of the binary run under another name, and its spawns, kept
// clear of Linux's "Text file busy" (`support/exe_copy.rs`).
#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-idq-close-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A copy of `rarfast` named `unrar`, the whole of how the binary picks
/// that dialect (a copy and not a symlink, so `argv[0]` reads `unrar`
/// wherever this test runs it from).
fn ours_as_unrar(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rarfast-idq-close-asunrar-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let named = dir.join("unrar");
    copy_executable(&rarfast(), &named);
    named
}

fn run(binary: &Path, dir: &Path, args: &[&str]) -> (String, String, i32) {
    let out = output_of(Command::new(binary).args(args).current_dir(dir))
        .unwrap_or_else(|err| panic!("{binary:?} could not be run: {err}"));
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// A two member stored archive, built by rarfast itself (this test needs
/// no copy of `rar` on the box), then the LAST member's data flipped -
/// the same shape `tests/reference.rs`'s `Damage::LastMemberData` uses,
/// which leaves every header alone and only the checksum wrong.
fn build_damaged_archive(dir: &Path, _tag: &str) {
    std::fs::write(dir.join("a.txt"), b"hello world\n").unwrap();
    std::fs::write(dir.join("b.txt"), b"second file content here\n").unwrap();
    // `rarfast`'s own name is the `rar` dialect (argv[0] is neither `rar`
    // nor `unrar`), which is what the creator commands answer to.
    let (_, stderr, exit) = run(
        &rarfast(),
        dir,
        &["a", "-y", "-idq", "-m0", "arc.rar", "a.txt", "b.txt"],
    );
    assert_eq!(exit, 0, "setup create failed: {stderr}");
    let path = dir.join("arc.rar");
    let mut bytes = std::fs::read(&path).unwrap();
    let needle = b"second file";
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("payload bytes present in a stored archive");
    for byte in &mut bytes[at..at + 4] {
        *byte ^= 0xff;
    }
    std::fs::write(&path, &bytes).unwrap();
}

#[test]
fn quiet_test_closes_the_checksum_complaint_with_a_newline() {
    let dir = work("checksum");
    build_damaged_archive(&dir, "checksum");
    let unrar = ours_as_unrar("checksum-test");

    let (stdout, stderr, exit) = run(&unrar, &dir, &["t", "-idq", "arc.rar"]);
    assert!(
        stdout.is_empty(),
        "-idq: stdout should stay empty, got {stdout:?}"
    );
    assert_eq!(exit, 3, "a checksum failure exits 3");
    assert!(
        stderr.contains("checksum error"),
        "should still report the failure, got {stderr:?}"
    );
    assert!(
        stderr.ends_with('\n'),
        "-idq should close its last stderr line with a newline, got {stderr:?}"
    );
    assert!(
        !stderr.ends_with("\n\n"),
        "and only ONE newline, not a blank line, got {stderr:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(unrar.parent().unwrap());
}

/// The same archive without `-idq` keeps matching the reference exactly
/// as it did before this fix: no trailing newline on the complaint, since
/// nothing here closes a plain run's line.
#[test]
fn plain_test_does_not_gain_a_newline() {
    let dir = work("checksum-plain");
    build_damaged_archive(&dir, "checksum-plain");
    let unrar = ours_as_unrar("checksum-test-plain");

    let (_, stderr, exit) = run(&unrar, &dir, &["t", "arc.rar"]);
    assert_eq!(exit, 3, "a checksum failure exits 3");
    assert!(
        stderr.contains("checksum error"),
        "should report the failure, got {stderr:?}"
    );
    assert!(
        !stderr.ends_with('\n'),
        "a plain run must not gain the -idq-only closing newline, got {stderr:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(unrar.parent().unwrap());
}

#[test]
fn quiet_missing_archive_closes_with_a_newline() {
    let dir = work("missing");
    let unrar = ours_as_unrar("missing");

    let (stdout, stderr, exit) = run(&unrar, &dir, &["l", "-idq", "nosuch.rar"]);
    assert!(stdout.is_empty(), "-idq: stdout should stay empty");
    assert_eq!(exit, 10, "a missing archive exits 10");
    assert!(
        stderr.ends_with('\n'),
        "-idq should close the `Cannot open` line, got {stderr:?}"
    );
    assert!(
        !stderr.ends_with("\n\n"),
        "and only ONE newline, got {stderr:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(unrar.parent().unwrap());
}

/// `lb` is measured to keep its line open even under `-idq`: this fix
/// must not reach it (see the module doc).
#[test]
fn quiet_bare_listing_does_not_gain_a_closing_newline() {
    let dir = work("missing-bare");
    let unrar = ours_as_unrar("missing-bare");

    let (stdout, stderr, exit) = run(&unrar, &dir, &["lb", "-idq", "nosuch.rar"]);
    assert!(stdout.is_empty(), "-idq: stdout should stay empty");
    assert_eq!(exit, 10, "a missing archive exits 10");
    assert!(
        !stderr.ends_with('\n'),
        "`lb` should NOT gain the closing newline, got {stderr:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(unrar.parent().unwrap());
}

/// `-inul` silences the report entirely, so there is nothing to close.
#[test]
fn silent_still_prints_nothing_at_all() {
    let dir = work("silent");
    let unrar = ours_as_unrar("silent");

    let (stdout, stderr, exit) = run(&unrar, &dir, &["l", "-inul", "nosuch.rar"]);
    assert!(stdout.is_empty(), "-inul: stdout should be empty");
    assert!(stderr.is_empty(), "-inul: stderr should be empty too");
    assert_eq!(exit, 10);

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(unrar.parent().unwrap());
}
