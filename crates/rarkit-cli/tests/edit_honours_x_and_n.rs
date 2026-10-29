//! `d` and `rn` honour `-x` and `-n`, and the answers are rar 7.23's.
//!
//! Until 27 Oct 2026 both switches were parsed beside `d` and `rn` and
//! never reached them: `rarfast d -x'*.txt' arc.rar '*'` deleted every
//! member and erased the archive, where the reference keeps the four text
//! files, and `rn` renamed members `-x` named and members `-n` did not.
//!
//! [`ROWS`] was measured on 27 Oct 2026 with `rar` 7.23 (an Apple silicon
//! Mac) over a stored archive of [`TREE`], a fresh copy of it a row:
//!
//! ```text
//! <arguments after the command> => <exit> | <members left, sorted>
//! ```
//!
//! What it shows, beside the read commands' rules for a `-x` or `-n` mask
//! (one rule, `Screen` in the decoder's `mask` module):
//!
//! - a member `-x` covers is neither deleted nor renamed, and a mask
//!   with no wildcard covers what lies beneath the directory it names
//!   (`d -xs arc.rar '*'` keeps `s` and all in it; `rn -xs arc.rar s Z`
//!   renames nothing);
//! - with `-n`, only a member it covers is deleted or renamed (`rn
//!   -ns/a.txt arc.rar s Z` moves `s/a.txt` alone, to `Z/a.txt`);
//! - a directory member is screened as itself: `d -x'*.txt' arc.rar '*'`
//!   deletes `s` and `s/d` and keeps the text files inside them;
//! - a `d` that the switches leave with nothing says so and exits 10,
//!   the archive as it was; an `rn` left with nothing exits 0.
//!
//! Width and memory: every rarfast call states `-mt1`; the archive is
//! under 2 KiB.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

/// Three files at the top, two of them `.txt`; a directory holding a
/// `.txt` with a top level twin and a `.bin`; and a directory in that.
const TREE: [&str; 6] = ["a.txt", "b.txt", "c.bin", "s/a.txt", "s/b.bin", "s/d/e.txt"];

/// The members of the archive, sorted: the files and their directories.
const MEMBERS: &str = "a.txt b.txt c.bin s s/a.txt s/b.bin s/d s/d/e.txt";

/// rar 7.23, 27 Oct 2026. The arguments are typed with no shell between,
/// so `*` is the program's own.
const ROWS: &str = "\
d -x*.txt arc.rar * => 0 | a.txt b.txt s/a.txt s/d/e.txt
d -xa.txt arc.rar *.txt => 0 | a.txt c.bin s s/b.bin s/d
d -n*.bin arc.rar * => 0 | a.txt b.txt s s/a.txt s/d s/d/e.txt
d -na.txt arc.rar *.txt => 0 | b.txt c.bin s s/a.txt s/b.bin s/d s/d/e.txt
d -xs arc.rar * => 0 | s s/a.txt s/b.bin s/d s/d/e.txt
d -x* arc.rar *.txt => 10 | a.txt b.txt c.bin s s/a.txt s/b.bin s/d s/d/e.txt
rn -xa.txt arc.rar *.txt *.q => 0 | a.txt b.q c.bin s s/a.txt s/b.bin s/d s/d/e.txt
rn -na.txt arc.rar *.txt *.q => 0 | a.q b.txt c.bin s s/a.txt s/b.bin s/d s/d/e.txt
rn -xs arc.rar s Z => 0 | a.txt b.txt c.bin s s/a.txt s/b.bin s/d s/d/e.txt
rn -xs/a.txt arc.rar s Z => 0 | Z Z/b.bin Z/d Z/d/e.txt a.txt b.txt c.bin s/a.txt
rn -ns/a.txt arc.rar s Z => 0 | Z/a.txt a.txt b.txt c.bin s s/b.bin s/d s/d/e.txt
rn -x* arc.rar a.txt Q => 0 | a.txt b.txt c.bin s s/a.txt s/b.bin s/d s/d/e.txt";

struct Work(PathBuf);

impl Work {
    /// A fresh directory holding `first.rar`, the tree stored.
    fn new() -> Work {
        let dir = std::env::temp_dir().join(format!("rarfast-edit-x-n-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let work = Work(dir);
        for name in TREE {
            let path = work.0.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, name).unwrap();
        }
        let made = work.run(&[
            "a",
            "-idq",
            "-r",
            "-m0",
            "first.rar",
            "a.txt",
            "b.txt",
            "c.bin",
            "s",
        ]);
        assert!(made.status.success(), "{made:?}");
        work
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_rarfast"))
            .current_dir(&self.0)
            .arg(args[0])
            .arg("-mt1")
            .args(&args[1..])
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// The members of `arc.rar`, sorted, or `(erased)` when it is gone.
    fn members(&self) -> String {
        if !self.0.join("arc.rar").exists() {
            return "(erased)".to_owned();
        }
        let listed = self.run(&["lb", "arc.rar"]);
        assert!(listed.status.success(), "{listed:?}");
        let text = String::from_utf8(listed.stdout).unwrap();
        let mut names: Vec<&str> = text.lines().collect();
        names.sort_unstable();
        names.join(" ")
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn d_and_rn_screen_by_x_and_n_as_the_reference_does() {
    let work = Work::new();
    std::fs::copy(work.0.join("first.rar"), work.0.join("arc.rar")).unwrap();
    assert_eq!(work.members(), MEMBERS);
    let mut wrong = Vec::new();
    let mut count = 0;
    for row in ROWS.lines() {
        let (typed, rest) = row.split_once(" => ").expect("a row");
        let (exit, members) = rest.split_once(" | ").expect("an exit and the members");
        let exit: i32 = exit.parse().expect("an exit");
        std::fs::copy(work.0.join("first.rar"), work.0.join("arc.rar")).unwrap();
        let args: Vec<&str> = typed.split(' ').collect();
        let ran = work.run(&args);
        let got = (ran.status.code(), work.members());
        if got != (Some(exit), members.to_owned()) {
            wrong.push(format!(
                "{typed}: exit {:?}, left {}\n  the reference: exit {exit}, left {members}",
                got.0, got.1
            ));
        }
        count += 1;
    }
    assert_eq!(count, 12);
    assert!(
        wrong.is_empty(),
        "{} rows:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
