//! `rarfast r` never exits 0 over a recovery record that is itself
//! damaged, or over damage it judged and did not mend (bug sweep of 8 Oct
//! 2026, item 09).
//!
//! Measured on 8 Oct 2026 with `rar` 7.23 (macOS, aarch64) on byte-equal
//! copies of the archives this file builds, which rarfast itself writes
//! (stored, `-rr3`, one member of 1,000,000 bytes: 200 shards, 6 rows):
//!
//! - bytes flipped inside the record's own data area, the protected bytes
//!   whole: `0 blocks are recovered, 0 blocks are relocated`, then
//!   `Recovery record is corrupt.`, `Done`, exit 3, no file written;
//! - the same and one damaged slice the surviving rows mend: the slice is
//!   `data recovered`, `fixed.a.rar` is written and tests clean, and the
//!   run still says `Recovery record is corrupt.` and exits 3;
//! - the record whole and more damaged slices than rows: the reference
//!   reconstructs and exits 0. THAT IS NOT FOLLOWED: the rule here is
//!   that a repair that did not mend everything it judged damaged never
//!   exits 0, so the run ends as the reference's does and exits 3. It
//!   does not say the record is corrupt, which it is not.
//!
//! That last row is A CHOSEN DIFFERENCE from the reference, and its
//! reason is the exit code's only use: a caller that reads it must not
//! be told a repair succeeded when slices it judged damaged are still
//! damaged. Five rows of `tests/repair_parity.rs` pinned the reference's
//! answer there and now pin this one, each exit 0 before and 3 now, with
//! stdout and the files written unchanged:
//!
//! - `beyond` (`-rr3`, seven slices against six rows): 0, now 3;
//! - `ten21` (`-rr10`, twenty-one slices against twenty rows): 0, now 3;
//! - the `-y` run of the partly recoverable archive, which mends one
//!   group and rebuilds over the other: 0, now 3;
//! - `falsified-one` and `falsified-two`, a slice whose rebuild fails
//!   its own check: 0, now 3;
//! - `fresh-rebuilt` (seven slices against six rows): 0, now 3.
//!
//! Before this the verdict looked only for a group with NO row left, so
//! each of the three exited 0.
//!
//! Width and memory: each run is one `rarfast` process on the machine's
//! own pool; the archives are just over 1 MiB.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MEMBER: usize = 1_000_000;
const CORRUPT: &str = "Recovery record is corrupt.\n";

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

struct Work(PathBuf);

impl Work {
    fn new(tag: &str) -> Work {
        let dir =
            std::env::temp_dir().join(format!("rarfast-unmended-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Work(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn noise(len: usize) -> Vec<u8> {
    rarkit_testdata::scramble(0x756e, len)
}

/// `a.rar` in a fresh directory: stored, a 3 percent record, written by
/// rarfast. Returns the directory and the archive's bytes.
fn built(tag: &str) -> (Work, Vec<u8>) {
    let work = Work::new(tag);
    std::fs::write(work.path("d.bin"), noise(MEMBER)).unwrap();
    let status = Command::new(rarfast())
        .args(["a", "-idq", "-m0", "-ep", "-rr3", "a.rar", "d.bin"])
        .current_dir(&work.0)
        .status()
        .unwrap();
    assert!(status.success(), "rarfast a");
    let bytes = std::fs::read(work.path("a.rar")).unwrap();
    (work, bytes)
}

/// `rarfast r -y a.rar` with nothing on standard input: the exit code and
/// stdout with every counter redraw taken out.
fn repair(dir: &Path) -> (i32, String) {
    let out = Command::new(rarfast())
        .args(["r", "-y", "a.rar"])
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut plain = String::new();
    let mut rest = text.as_str();
    while let Some(at) = rest.find("\u{8}\u{8}\u{8}\u{8}") {
        plain.push_str(&rest[..at]);
        let tail = &rest[at + 4..];
        rest = &tail[tail.find('%').expect("a counter ends in %") + 1..];
    }
    plain.push_str(rest);
    (out.status.code().unwrap_or(-1), plain)
}

/// Where each record of the data area starts: every `{RB}` after the
/// member's bytes. (The member is noise from a fixed seed and holds none.)
fn records(archive: &[u8]) -> Vec<usize> {
    let found: Vec<usize> = archive
        .windows(4)
        .enumerate()
        .skip(MEMBER)
        .filter_map(|(at, w)| (w == b"{RB}").then_some(at))
        .collect();
    assert_eq!(found.len(), 6, "3 percent of 200 shards is 6 rows");
    found
}

fn flip(bytes: &mut [u8], at: usize, len: usize) {
    for byte in &mut bytes[at..at + len] {
        *byte ^= 0xa5;
    }
}

#[test]
fn a_damaged_record_over_whole_data_is_said_and_exits_3() {
    let (work, mut bytes) = built("record");
    let rows = records(&bytes);
    // 600 bytes of the last row's parity, well inside its record.
    flip(&mut bytes, rows[5] + 1_000, 600);
    std::fs::write(work.path("a.rar"), &bytes).unwrap();
    let (code, stdout) = repair(&work.0);
    assert!(
        stdout.ends_with(&format!(
            "\n0 blocks are recovered, 0 blocks are relocated\n{CORRUPT}Done\n"
        )),
        "{stdout}"
    );
    assert_eq!(code, 3, "{stdout}");
    assert!(!work.path("fixed.a.rar").exists());
    assert!(!work.path("rebuilt.a.rar").exists());
}

#[test]
fn a_damaged_record_that_still_mends_is_said_and_exits_3() {
    let (work, mut bytes) = built("both");
    let whole = bytes.clone();
    let rows = records(&bytes);
    flip(&mut bytes, rows[5] + 1_000, 600);
    flip(&mut bytes, 50_000, 100);
    std::fs::write(work.path("a.rar"), &bytes).unwrap();
    let (code, stdout) = repair(&work.0);
    assert!(stdout.contains(" - data recovered"), "{stdout}");
    assert!(!stdout.contains("cannot recover data"), "{stdout}");
    assert!(
        stdout.ends_with(&format!(
            " blocks are recovered, 0 blocks are relocated\n{CORRUPT}Done\n"
        )),
        "{stdout}"
    );
    assert_eq!(code, 3, "{stdout}");
    // What could be mended was: the protected bytes are the original's.
    let fixed = std::fs::read(work.path("fixed.a.rar")).expect("the fixed file");
    assert!(
        fixed[..rows[0]] == whole[..rows[0]],
        "the mend is not exact"
    );
}

/// The item's second scenario: every row of the record area overwritten
/// with the first, so one row survives where six were written.
#[test]
fn a_record_of_one_repeated_row_is_said_and_exits_3() {
    let (work, mut bytes) = built("repeated");
    let rows = records(&bytes);
    let span = rows[1] - rows[0];
    for row in 1..rows.len() {
        bytes.copy_within(rows[0]..rows[0] + span, rows[row]);
    }
    std::fs::write(work.path("a.rar"), &bytes).unwrap();
    let (code, stdout) = repair(&work.0);
    assert!(stdout.contains(CORRUPT), "{stdout}");
    assert_eq!(code, 3, "{stdout}");
}

#[test]
fn damage_the_record_cannot_mend_does_not_exit_0() {
    let (work, mut bytes) = built("beyond");
    // Twelve slices of about 5,000 bytes, against six rows.
    for slice in 0..12 {
        flip(&mut bytes, 20_000 + slice * 6_000, 50);
    }
    std::fs::write(work.path("a.rar"), &bytes).unwrap();
    let (code, stdout) = repair(&work.0);
    assert!(stdout.contains(" - cannot recover data"), "{stdout}");
    assert!(
        stdout.contains("\n0 blocks are recovered, 0 blocks are relocated\n"),
        "{stdout}"
    );
    // The record is whole, and is not called corrupt.
    assert!(!stdout.contains(CORRUPT), "{stdout}");
    assert_eq!(code, 3, "{stdout}");
}

/// The control: a whole record that mends everything it judged is `Done`,
/// exit 0, as before.
#[test]
fn a_whole_record_that_mends_everything_exits_0() {
    let (work, mut bytes) = built("mended");
    flip(&mut bytes, 50_000, 100);
    std::fs::write(work.path("a.rar"), &bytes).unwrap();
    let (code, stdout) = repair(&work.0);
    assert!(stdout.contains(" - data recovered"), "{stdout}");
    assert!(!stdout.contains(CORRUPT), "{stdout}");
    assert!(stdout.ends_with("Done\n"), "{stdout}");
    assert_eq!(code, 0, "{stdout}");
    assert!(work.path("fixed.a.rar").exists());
}
