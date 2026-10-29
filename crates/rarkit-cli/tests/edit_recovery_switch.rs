//! `ch -rr<n>` honours its switch, and a percentage of 0 means no record
//! (bug sweep of 8 Oct 2026, item 06).
//!
//! Measured on 8 Oct 2026 with `rar` 7.23 (macOS, aarch64) over archives
//! rarfast wrote (stored, one member of 400,000 bytes, with no record and
//! with `-rr1`):
//!
//! - `ch -rr5` is `rr5`: `Processing archive`, `Adding the data recovery
//!   record` and its counter, `Done`, exit 0, and a 5 percent record,
//!   whether the archive had none or had another; bare `ch -rr` is `rr3`;
//! - `rr0` and `ch -rr0` are `Processing archive`, `Done`, exit 0, and the
//!   archive has NO record after, whether or not it had one;
//! - `ch -k -rr5` says `Adding the data recovery record`, then `Locking
//!   archive`, and leaves a locked archive with a 5 percent record.
//!
//! Before this `ch` did not look at `-rr` at all (the archive came back
//! byte for byte, exit 0), and `rr0` wrote a 1 percent record.
//!
//! Width and memory: every rarfast call states `-mt1`; the archives are
//! under 500 KiB.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const MEMBER: usize = 400_000;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

struct Work(PathBuf);

impl Work {
    /// A fresh directory holding `n.rar` (no record) and `r1.rar` (`-rr1`).
    fn new(tag: &str) -> Work {
        let dir = std::env::temp_dir().join(format!("rarfast-chrr-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let work = Work(dir);
        let mut state = 0x9e37_79b9u32;
        let noise: Vec<u8> = (0..MEMBER)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        std::fs::write(work.0.join("d.bin"), noise).unwrap();
        work.ok(&["a", "-idq", "-m0", "-ep", "n.rar", "d.bin"]);
        work.ok(&["a", "-idq", "-m0", "-ep", "-rr1", "r1.rar", "d.bin"]);
        work
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(rarfast())
            .current_dir(&self.0)
            .arg(args[0])
            .arg("-mt1")
            .args(&args[1..])
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "rarfast {args:?}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// `args` run over a copy of `base`, the copy's bytes after and stdout.
    fn over(&self, base: &str, args: &[&str]) -> (Vec<u8>, String) {
        let copy = self.0.join("w.rar");
        std::fs::copy(self.0.join(base), &copy).unwrap();
        let mut line = args.to_vec();
        line.push("w.rar");
        let stdout = self.ok(&line);
        (std::fs::read(&copy).unwrap(), stdout)
    }

    fn bytes(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.0.join(name)).unwrap()
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Whether the archive carries an inline record: its marker after the
/// member's bytes. (The member is noise from a fixed seed and holds none.)
fn has_record(archive: &[u8]) -> bool {
    archive[MEMBER..].windows(4).any(|w| w == b"{RB}")
}

const ADDING: &str = "Adding the data recovery record     ";

#[test]
fn ch_with_rr_is_the_rr_command() {
    let work = Work::new("ch");
    for base in ["n.rar", "r1.rar"] {
        let (by_command, _) = work.over(base, &["rr5"]);
        let (by_switch, stdout) = work.over(base, &["ch", "-rr5"]);
        assert!(has_record(&by_switch), "{base}: ch -rr5 left no record");
        assert!(
            by_switch == by_command,
            "{base}: ch -rr5 is not rr5's archive ({} and {} bytes)",
            by_switch.len(),
            by_command.len()
        );
        assert!(
            stdout.starts_with(&format!("\nProcessing archive w.rar\n{ADDING}")),
            "{base}: {stdout:?}"
        );
        assert!(stdout.ends_with("\nDone\n"), "{base}: {stdout:?}");
        assert!(!stdout.contains("Locking archive"), "{base}: {stdout:?}");
    }
    // The bare switch is 3 percent, as the bare command is.
    let (by_command, _) = work.over("n.rar", &["rr3"]);
    let (by_switch, _) = work.over("n.rar", &["ch", "-rr"]);
    assert!(by_switch == by_command, "ch -rr is not rr3's archive");
    // And a `ch` with no switch is still the two lines, nothing changed.
    let (unchanged, stdout) = work.over("n.rar", &["ch"]);
    assert!(unchanged == work.bytes("n.rar"));
    assert_eq!(stdout, "\nProcessing archive w.rar\nDone\n");
}

#[test]
fn a_percentage_of_0_is_no_record() {
    let work = Work::new("zero");
    let plain = work.bytes("n.rar");
    for line in [&["rr0"][..], &["ch", "-rr0"]] {
        // None before: none after, and nothing rewritten.
        let (after, stdout) = work.over("n.rar", line);
        assert!(after == plain, "{line:?} changed an archive with no record");
        assert_eq!(stdout, "\nProcessing archive w.rar\nDone\n", "{line:?}");
        // One before: gone after.
        let (after, stdout) = work.over("r1.rar", line);
        assert!(!has_record(&after), "{line:?} left a record");
        assert!(
            after.len() <= plain.len() + 64,
            "{line:?}: {} bytes, {} with no record",
            after.len(),
            plain.len()
        );
        assert_eq!(stdout, "\nProcessing archive w.rar\nDone\n", "{line:?}");
        // The archive still tests.
        work.ok(&["t", "-idq", "w.rar"]);
    }
}

#[test]
fn ch_with_rr_and_k_does_both() {
    let work = Work::new("both");
    let (by_command, _) = work.over("n.rar", &["rr5"]);
    let (after, stdout) = work.over("n.rar", &["ch", "-k", "-rr5"]);
    assert!(has_record(&after));
    // The lock is one flag of the main header: the length is rr5's.
    assert_eq!(after.len(), by_command.len());
    assert!(
        stdout.starts_with(&format!("\nProcessing archive w.rar\n{ADDING}")),
        "{stdout:?}"
    );
    assert!(stdout.ends_with("\nLocking archive\nDone\n"), "{stdout:?}");
    // Locked: the next change is refused, exit 4.
    let refused = work.run(&["rr3", "w.rar"]);
    assert_eq!(refused.status.code(), Some(4));
    assert!(std::fs::read(work.0.join("w.rar")).unwrap() == after);
    work.ok(&["t", "-idq", "w.rar"]);
}
