//! Two open items from 19 Sep 2026, closed here:
//!
//! 1. **`-idq` and `-ierr` order.** They share one destination rather than
//!    acting as two independent flags: measured against `rar`/`unrar` 7.23
//!    on 20 Sep 2026 and written up in the crate's own README section 8,
//!    `unrar p -idq -ierr good.rar` puts the whole progress on stderr (the
//!    LATER `-ierr` wins) and `unrar p -ierr -idq good.rar` puts nothing
//!    there at all (the later `-idq` wins, and it takes the destination
//!    away rather than narrowing it). The rows below pin that with `l`,
//!    which needs no archive comment or damage to show the same shape, on
//!    both dialects.
//! 2. **A listing's trailing blank line.** `l`, `v` and `lt` end on one more
//!    `\n` at the reference than rarfast did before this. The fixture here
//!    is built and listed with rarfast itself so the row needs no copy of
//!    `rar`/`unrar` on the box, and freezes everything the plain row and
//!    the header line can vary on (mtime, permissions, time zone) so the
//!    whole `l` listing can be pinned literally rather than approximately.

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

/// A directory of one test's own under the system's temporary directory,
/// emptied first: an archive an earlier run wrote there is not found.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-idqierr-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A copy of `rarfast` named `unrar`, the whole of how the binary picks
/// that dialect. A copy and not a symlink, the same reason
/// `tests/reference.rs`'s `ours_as_unrar` gives.
fn ours_as_unrar(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rarfast-idqierr-asunrar-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let named = dir.join("unrar");
    copy_executable(&rarfast(), &named);
    named
}

/// Runs `binary` in `dir` with `TZ=UTC`, so a listing's date column is the
/// same wherever this test runs, and answers stdout and stderr.
fn run(binary: &Path, dir: &Path, args: &[&str]) -> (String, String) {
    let out = output_of(
        Command::new(binary)
            .args(args)
            .current_dir(dir)
            .env("TZ", "UTC"),
    )
    .unwrap_or_else(|err| panic!("{binary:?} could not be run: {err}"));
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Builds a one member stored archive, both dialects can read.
fn build_archive(dir: &Path) {
    std::fs::write(dir.join("hello.txt"), b"hi\n").unwrap();
    let (_, stderr) = run(&rarfast(), dir, &["a", "-y", "-m0", "arc.rar", "hello.txt"]);
    assert!(stderr.is_empty(), "setup create failed: {stderr}");
}

// --- item 1: `-idq` and `-ierr` share one destination, ORDER decides ---

#[test]
fn idq_then_ierr_sends_the_whole_listing_to_stderr() {
    let dir = work("idq-ierr");
    build_archive(&dir);

    let (stdout, stderr) = run(&rarfast(), &dir, &["l", "-idq", "-ierr", "arc.rar"]);
    assert!(
        stdout.is_empty(),
        "-idq -ierr: stdout should be empty, got {stdout:?}"
    );
    assert!(
        stderr.contains("Archive: arc.rar") && stderr.contains("hello.txt"),
        "-idq -ierr: the whole listing should be on stderr, got {stderr:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ierr_then_idq_prints_nothing_on_either_stream() {
    let dir = work("ierr-idq");
    build_archive(&dir);

    let (stdout, stderr) = run(&rarfast(), &dir, &["l", "-ierr", "-idq", "arc.rar"]);
    assert!(
        stdout.is_empty(),
        "-ierr -idq: stdout should be empty, got {stdout:?}"
    );
    assert!(
        stderr.is_empty(),
        "-ierr -idq: stderr should be empty too, got {stderr:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn idq_then_ierr_sends_the_whole_listing_to_stderr_as_unrar() {
    let dir = work("idq-ierr-unrar");
    build_archive(&dir);
    let unrar = ours_as_unrar("idq-then-ierr");

    let (stdout, stderr) = run(&unrar, &dir, &["l", "-idq", "-ierr", "arc.rar"]);
    assert!(
        stdout.is_empty(),
        "unrar -idq -ierr: stdout should be empty, got {stdout:?}"
    );
    assert!(
        stderr.contains("Archive: arc.rar") && stderr.contains("hello.txt"),
        "unrar -idq -ierr: the whole listing should be on stderr, got {stderr:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(unrar.parent().unwrap());
}

#[test]
fn ierr_then_idq_prints_nothing_on_either_stream_as_unrar() {
    let dir = work("ierr-idq-unrar");
    build_archive(&dir);
    let unrar = ours_as_unrar("ierr-then-idq");

    let (stdout, stderr) = run(&unrar, &dir, &["l", "-ierr", "-idq", "arc.rar"]);
    assert!(
        stdout.is_empty(),
        "unrar -ierr -idq: stdout should be empty, got {stdout:?}"
    );
    assert!(
        stderr.is_empty(),
        "unrar -ierr -idq: stderr should be empty too, got {stderr:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(unrar.parent().unwrap());
}

/// `-ierr` alone still moves everything to stderr (unaffected by this
/// change: there is no `-idq` in the line to contend with it).
#[test]
fn ierr_alone_still_moves_the_listing_to_stderr() {
    let dir = work("ierr-alone");
    build_archive(&dir);

    let (stdout, stderr) = run(&rarfast(), &dir, &["l", "-ierr", "arc.rar"]);
    assert!(stdout.is_empty(), "-ierr: stdout should be empty");
    assert!(
        stderr.contains("hello.txt"),
        "-ierr: the listing should be on stderr, got {stderr:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `-idq` alone still silences stdout and prints nothing, which is the
/// case this fix must not disturb.
#[test]
fn idq_alone_still_prints_nothing() {
    let dir = work("idq-alone");
    build_archive(&dir);

    let (stdout, stderr) = run(&rarfast(), &dir, &["l", "-idq", "arc.rar"]);
    assert!(stdout.is_empty(), "-idq: stdout should be empty");
    assert!(stderr.is_empty(), "-idq: stderr should be empty");

    let _ = std::fs::remove_dir_all(&dir);
}

// --- item 2: a listing's trailing blank line ---------------------------

/// `l`'s header and rule, copied verbatim from
/// `src/dialect/unrar/list.rs` rather than exported, so this pins the
/// literal shape without widening that module's own visibility for a
/// test.
#[cfg(unix)]
const PLAIN_HEADER: &str = " Attributes       Size     Date    Time   Name";
#[cfg(unix)]
const PLAIN_RULE: &str = "----------- ----------  ---------- -----  ----";

// Unix only: it pins the attributes column with an explicit `chmod`,
// which is a POSIX mode and has no Windows equivalent for
// `std::os::unix::fs::PermissionsExt` to carry.
#[cfg(unix)]
#[test]
fn a_plain_listing_ends_on_exactly_one_blank_line() {
    let dir = work("listing-blank");
    std::fs::write(dir.join("hello.txt"), b"hi\n").unwrap();
    // A whole-second stamp: sub-second precision lists with a blank
    // Date/Time column (README section 8, a different open item), which
    // would make this row non-deterministic instead of pinned.
    let stamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
    let file = dir.join("hello.txt");
    let times = std::fs::FileTimes::new()
        .set_accessed(stamp)
        .set_modified(stamp);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&file)
        .unwrap()
        .set_times(times)
        .unwrap();
    std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();

    let (_, stderr) = run(
        &rarfast(),
        &dir,
        &["a", "-y", "-m0", "arc.rar", "hello.txt"],
    );
    assert!(stderr.is_empty(), "setup create failed: {stderr}");

    let (stdout, stderr) = run(&rarfast(), &dir, &["l", "arc.rar"]);
    assert!(
        stderr.is_empty(),
        "l: stderr should be empty, got {stderr:?}"
    );

    // Reproduces `plain_row`'s own format string (`src/dialect/unrar/
    // list.rs`) rather than hand-counting the column widths, so a typo
    // here cannot silently widen or narrow a column the source does not.
    let marker = ' ';
    let attrs = "-rw-r--r--";
    let size: u64 = 3;
    let date = "2001-09-09 01:46";
    let row = format!("{marker}{attrs:>10} {size:>10}  {date}  hello.txt");
    let totals = format!("{:11} {size:>10}  {:10} {:5}  {}", "", "", "", 1);
    let expected = format!(
        "\nArchive: arc.rar\nDetails: RAR 5\n\n{PLAIN_HEADER}\n{PLAIN_RULE}\n{row}\n{PLAIN_RULE}\n{totals}\n\n"
    );
    assert_eq!(
        stdout, expected,
        "l: full listing text\n--- ours ---\n{stdout:?}\n--- expected ---\n{expected:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The general shape holds for `v` and `lt` too, without pinning every
/// column: both end their content on exactly one blank line, where
/// rarfast used to end on none.
#[test]
fn wide_and_technical_listings_end_on_exactly_one_blank_line_too() {
    let dir = work("listing-blank-vt");
    build_archive(&dir);

    for command in ["v", "lt"] {
        let (stdout, stderr) = run(&rarfast(), &dir, &[command, "arc.rar"]);
        assert!(
            stderr.is_empty(),
            "{command}: stderr should be empty, got {stderr:?}"
        );
        assert!(
            stdout.ends_with("\n\n") && !stdout.ends_with("\n\n\n"),
            "{command}: should end on exactly one blank line, got {stdout:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// A bare listing (`lb`) never carried the header or the totals this fix
/// touches, and does not grow a blank line either.
#[test]
fn a_bare_listing_is_unaffected() {
    let dir = work("listing-blank-lb");
    build_archive(&dir);

    let (stdout, stderr) = run(&rarfast(), &dir, &["lb", "arc.rar"]);
    assert!(
        stderr.is_empty(),
        "lb: stderr should be empty, got {stderr:?}"
    );
    assert_eq!(stdout, "hello.txt\n", "lb: should print only the name");

    let _ = std::fs::remove_dir_all(&dir);
}
