//! A list file (`@list`, `-x@list`, `-n@list`) that cannot be read, or is
//! not UTF-8, is never an empty list.
//!
//! Sweep L-8, 4 Oct 2026. `read_mask_list` turned every failure into no
//! masks at all: a list that is not there, and one `read_to_string`
//! refuses (a UTF-16 file as Notepad saves it, a Latin-1 one). No masks
//! selects EVERYTHING, so `unrar x arc.rar @files.lst` extracted the whole
//! archive, and `-x@<list>` extracted what it was told to skip. A UTF-8
//! byte order mark was kept on the first mask, which then matched nothing.
//!
//! What reference unrar 7.23 does, measured that day on macOS arm64 with
//! `lb`, `t` and `x` over a set of `a.txt`, `sub/b.txt` and `sub`:
//!
//! - a list that cannot be opened, in any of the three forms: `Cannot open
//!   <list>` and the reason on stderr, `Program aborted`, exit 6, nothing
//!   read or written;
//! - a UTF-8 list with a byte order mark, and a UTF-16 one with either
//!   mark: read as the names they hold;
//! - a list that stops being UTF-8 part way: the lines before the line
//!   that breaks are read, and nothing from that line on matches anything
//!   (`a.txt` after a Latin-1 line selects nothing; before it, `a.txt`).
//!   The list is not empty: `-n@` of one that breaks in its first line
//!   lists nothing, `-x@` of it excludes nothing;
//! - a positional list that holds no name (empty, or blank lines) selects
//!   NOTHING: `lb` prints no name, `x` and `t` say `No files to extract`,
//!   exit 10. An empty `-n@` or `-x@` list adds no filter.
//!
//! Run under the name `unrar`. rarfast's own name reads a line the
//! decoder's parser accepts with this same reader; a line only the
//! creator's parser accepts (a read command beside a creator's switch)
//! goes through that parser's own list reader, which has the same fault
//! and is owed by the lane that owns it.
//!
//! Assumes: no thread pool to speak of (members of a few bytes; every run
//! states `-mt1`), under 16 MiB of memory.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

struct Bench {
    dir: PathBuf,
    unrar: PathBuf,
}

impl Bench {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rarfast-l8-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src").join("sub")).unwrap();
        let unrar = dir.join(format!("unrar{}", std::env::consts::EXE_SUFFIX));
        copy_executable(&rarfast(), &unrar);
        std::fs::write(dir.join("src").join("a.txt"), b"a\n").unwrap();
        std::fs::write(dir.join("src").join("sub").join("b.txt"), b"b\n").unwrap();
        let out = output_of(
            Command::new(rarfast())
                .args([
                    "a",
                    "-m0",
                    "-idq",
                    "-mt1",
                    "../set.rar",
                    "a.txt",
                    "sub/b.txt",
                ])
                .current_dir(dir.join("src")),
        )
        .expect("rarfast a runs");
        assert_eq!(out.status.code(), Some(0), "building the set: {out:?}");
        let utf16 = |big: bool| {
            let mut bytes = if big {
                vec![0xfe, 0xff]
            } else {
                vec![0xff, 0xfe]
            };
            for unit in "a.txt\r\n".encode_utf16() {
                bytes.extend(if big {
                    unit.to_be_bytes()
                } else {
                    unit.to_le_bytes()
                });
            }
            bytes
        };
        for (name, bytes) in [
            ("u8.lst", b"a.txt\n".to_vec()),
            ("u8bom.lst", b"\xef\xbb\xbfa.txt\n".to_vec()),
            ("u16le.lst", utf16(false)),
            ("u16be.lst", utf16(true)),
            ("latin-first.lst", b"caf\xe9.txt\na.txt\n".to_vec()),
            ("latin-last.lst", b"a.txt\ncaf\xe9.txt\n".to_vec()),
            ("empty.lst", Vec::new()),
            ("blank.lst", b"\n  \n\n".to_vec()),
        ] {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
        Bench { dir, unrar }
    }

    /// `unrar <args>` beside the lists, standard input closed.
    fn run(&self, args: &[&str]) -> Output {
        output_of(
            Command::new(&self.unrar)
                .args(args)
                .current_dir(&self.dir)
                .stdin(Stdio::null()),
        )
        .expect("the command runs")
    }

    /// The names `lb <switches and masks>` prints, and its exit code.
    fn listed(&self, rest: &[&str]) -> (Option<i32>, Vec<String>) {
        let mut args = vec!["lb", "-mt1"];
        args.extend(rest);
        let out = self.run(&args);
        let names = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_owned)
            .collect();
        (out.status.code(), names)
    }
}

fn said(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn exists(path: &Path) -> bool {
    path.exists()
}

/// `sub/b.txt` as a listing prints it on this system. The reference
/// prints a member's name with the system's own separator: UnRAR.exe and
/// Rar.exe 7.23 x64 on Windows 11 print `sub\b.txt` under `lb`, `l` and
/// `t` (measured 4 Oct 2026), where the Unix builds print `sub/b.txt`.
fn sub_b() -> String {
    format!("sub{}b.txt", std::path::MAIN_SEPARATOR)
}

/// Every file of the set, as `lb` prints them.
fn all() -> Vec<String> {
    vec!["a.txt".to_owned(), sub_b()]
}

/// The list whose first line is not UTF-8.
const BROKEN: &str = "latin-first.lst";

#[test]
fn a_list_that_cannot_be_opened_stops_the_run() {
    let bench = Bench::new("missing");
    for form in [
        vec!["set.rar", "@missing-list"],
        vec!["-x@missing-list", "set.rar"],
        vec!["-n@missing-list", "set.rar"],
    ] {
        for command in ["lb", "t", "x"] {
            let mut args = vec![command, "-mt1", "-o+"];
            args.extend(&form);
            if command == "x" {
                args.push("out/");
            }
            let out = bench.run(&args);
            let told = format!("{args:?}: {}", said(&out));
            assert_eq!(out.status.code(), Some(6), "{told}");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("Cannot open missing-list"),
                "{told}"
            );
            assert!(!exists(&bench.dir.join("out")), "{told}");
        }
    }
    let _ = std::fs::remove_dir_all(&bench.dir);
}

#[test]
fn a_list_is_read_in_the_encodings_the_reference_reads() {
    let bench = Bench::new("encodings");
    for list in [
        "u8.lst",
        "u8bom.lst",
        "u16le.lst",
        "u16be.lst",
        "latin-last.lst",
    ] {
        let positional = format!("@{list}");
        assert_eq!(
            bench.listed(&["set.rar", &positional]),
            (Some(0), vec!["a.txt".to_owned()]),
            "{list} as a positional"
        );
        assert_eq!(
            bench.listed(&[&format!("-n{positional}"), "set.rar"]),
            (Some(0), vec!["a.txt".to_owned()]),
            "-n@{list}"
        );
        assert_eq!(
            bench.listed(&[&format!("-x{positional}"), "set.rar"]),
            (Some(0), vec![sub_b()]),
            "-x@{list}"
        );
    }
    // The sweep's own line: a Notepad list names one file, and one file
    // is what `x` writes.
    let out = bench.run(&["x", "-mt1", "-o+", "set.rar", "@u16le.lst", "out/"]);
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert!(
        exists(&bench.dir.join("out").join("a.txt")),
        "{}",
        said(&out)
    );
    assert!(
        !exists(&bench.dir.join("out").join("sub")),
        "{}",
        said(&out)
    );
    let _ = std::fs::remove_dir_all(&bench.dir);
}

#[test]
fn a_list_that_breaks_in_its_first_line_matches_nothing_and_is_not_empty() {
    let bench = Bench::new("broken");
    assert_eq!(
        bench.listed(&["set.rar", "@latin-first.lst"]),
        (Some(0), Vec::new())
    );
    assert_eq!(
        bench.listed(&[&format!("-n@{BROKEN}"), "set.rar"]),
        (Some(0), Vec::new())
    );
    assert_eq!(
        bench.listed(&[&format!("-x@{BROKEN}"), "set.rar"]),
        (Some(0), all())
    );
    let out = bench.run(&["x", "-mt1", "-o+", "set.rar", "@latin-first.lst", "out/"]);
    assert_eq!(out.status.code(), Some(10), "{}", said(&out));
    assert!(
        !exists(&bench.dir.join("out").join("a.txt")),
        "{}",
        said(&out)
    );
    let _ = std::fs::remove_dir_all(&bench.dir);
}

#[test]
fn a_positional_list_with_no_name_selects_nothing() {
    let bench = Bench::new("empty");
    for list in ["empty.lst", "blank.lst"] {
        let positional = format!("@{list}");
        assert_eq!(
            bench.listed(&["set.rar", &positional]),
            (Some(0), Vec::new()),
            "{list} as a positional"
        );
        for command in ["x", "t"] {
            let out = bench.run(&[command, "-mt1", "-o+", "set.rar", &positional, "out/"]);
            let told = format!("{command} {list}: {}", said(&out));
            assert_eq!(out.status.code(), Some(10), "{told}");
            assert!(
                String::from_utf8_lossy(&out.stdout).contains("No files to extract"),
                "{told}"
            );
            assert!(!exists(&bench.dir.join("out").join("a.txt")), "{told}");
        }
        // As a filter it adds nothing.
        for switch in ["-n", "-x"] {
            assert_eq!(
                bench.listed(&[&format!("{switch}{positional}"), "set.rar"]),
                (Some(0), all()),
                "{switch}@{list}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&bench.dir);
}
