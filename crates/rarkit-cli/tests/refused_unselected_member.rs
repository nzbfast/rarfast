//! A member that was NOT selected and is refused for its password on the
//! way to one that was: what is said of it, and when it is no error.
//!
//! In a solid RAR 5 archive every member before a selected one is decoded
//! for the chain, and one whose password check value refuses the password
//! is refused all the same (spec K 3.7.3, "A refused member inside a
//! solid chain"). Until 9 Oct 2026 rarfast, where none of the refused
//! members was selected, said `Incorrect password for <the archive>`, and
//! said it, with exit 11, even when the refused member stood AFTER the
//! last member selected and every selected member had come out right.
//!
//! Measured on 9 Oct 2026 with unrar 7.23 (an Apple silicon Mac) over the
//! twelve archives of `specs/vectors-K/check-value-in-chain` (six members
//! `f0.txt` to `f5.txt`, solid and not, the check values of some altered),
//! under the right password, `t`, `x` and `p`, with six selections:
//!
//! - the reference names the MEMBER, never the archive: `unrar t -pPASS
//!   solid.refuse-2.rar f3.txt f5.txt` says `Incorrect password for
//!   f2.txt`, tests both, `Total errors: 1`, exit 11;
//! - it reads no further than the last member selected, so a refused
//!   member after it is nothing: `unrar t -pPASS solid.refuse-5.rar
//!   f1.txt` is `All OK`, exit 0.
//!
//! `refused-unselected/unrar723.tsv` is every such run with a selection
//! where rarfast answers as the reference does, 159 of them, 39 of which
//! it answered otherwise before:
//!
//! ```text
//! archive  command  selection  exit  stderr  the last line of stdout  files written  changed or same
//! ```
//!
//! Compared: the exit, stderr whole, the last line of stdout (`All OK` or
//! `Total errors: N`) and the files written. NOT compared: the
//! reference's `Skipping    <name>` line for each member it decodes on
//! the way, which rarfast does not print.
//!
//! NOT MATCHED, measured the same day, 57 runs with a selection, all of
//! one cause: where SEVERAL refused members are met, the reference says
//! `Incorrect password for <name>` for each one up to the last member
//! selected and counts each (`unrar t solid.refuse-1-2-3-4.rar f5.txt`:
//! four lines, `Total errors: 4`); rarfast says it for the selected ones
//! and for the FIRST one that was not, which is all the engine's error
//! names. Owed to the engine: a refused member the sink skipped has to
//! reach the tool. Two smaller ones ride on it: under `-ierr` the line
//! for an unselected member comes where the member stands, here at the
//! end; and a selection that matches NO member still walks a solid
//! archive at the reference and names every refused member (exit 11),
//! where rarfast says `No files to extract` (exit 10).
//!
//! Width and memory: every call states `-mt1`; each archive is under 4
//! KiB and its key derivation is 2^15 rounds, once a salt.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn vector(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../specs/vectors-K/check-value-in-chain")
        .join(name)
}

struct Ran {
    exit: Option<i32>,
    stdout: String,
    stderr: String,
    files: Vec<String>,
}

/// One run in a scratch directory of its own, the archive named by its
/// whole path.
fn run(row: usize, archive: &str, command: &str, selection: &str) -> Ran {
    let dir = std::env::temp_dir().join(format!(
        "rarfast-refused-unselected-{}-{row}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ran = Command::new(env!("CARGO_BIN_EXE_rarfast"))
        .current_dir(&dir)
        .args([command, "-mt1", "-y", "-pPASS"])
        .arg(vector(archive))
        .args(selection.split(' '))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    files.sort_unstable();
    let _ = std::fs::remove_dir_all(&dir);
    Ran {
        exit: ran.status.code(),
        stdout: String::from_utf8_lossy(&ran.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&ran.stderr).into_owned(),
        files,
    }
}

#[test]
fn a_refused_member_that_was_not_selected_is_said_as_the_reference_says_it() {
    let table = include_str!("refused-unselected/unrar723.tsv");
    let mut wrong = Vec::new();
    let mut rows = 0;
    for (row, line) in table.lines().enumerate() {
        let cells: Vec<&str> = line.split('\t').collect();
        let (archive, command, selection) = (cells[0], cells[1], cells[2]);
        let exit: i32 = cells[3].parse().expect("an exit");
        let dash = |cell: &str| {
            if cell == "-" {
                String::new()
            } else {
                cell.to_owned()
            }
        };
        let stderr = dash(cells[4]).replace("\\n", "\n");
        let (last, files) = (dash(cells[5]), dash(cells[6]));
        let ran = run(row, archive, command, selection);
        let said_last = if command == "p" {
            String::new()
        } else {
            ran.stdout
                .lines()
                .rfind(|line| !line.is_empty())
                .unwrap_or_default()
                .to_owned()
        };
        let got = (ran.exit, ran.stderr, said_last, ran.files.join(" "));
        let want = (Some(exit), stderr, last, files);
        if got != want {
            wrong.push(format!(
                "{command} {archive} {selection}:\n  rarfast   {got:?}\n  reference {want:?}"
            ));
        }
        rows += 1;
    }
    assert_eq!(rows, 159);
    assert!(
        wrong.is_empty(),
        "{} rows:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
