//! The `-m` family under the name `unrar`, through the whole command.
//!
//! Reference unrar 7.23 ACCEPTS `-m0` to `-m5`, `-mm...`, `-md<size>`,
//! `-ms...` and `-mc...` on every read command and reads the archive as if
//! the switch were not there (measured 3 Oct 2026 on macOS and
//! Linux). Until then a binary
//! called `unrar` answered each with `Unknown option`, exit 7, so a line
//! the reference runs was a usage error. Here the command is run under
//! both names on a small set, and what must hold is:
//!
//! - under `unrar`: the accepted spellings exit 0 and `x` writes the bytes
//!   it writes without the switch; the refused ones exit 7, write nothing
//!   and say `Unknown option`;
//! - under `unrar` a `-mm<size>` is swallowed and is NOT a memory ceiling:
//!   a member the named size could not hold is still extracted, exit 0, as
//!   the reference has it (its `t -mm64m` on a `-md32m` member exits 0);
//! - under rarfast's OWN name nothing moved: `-mm<size>` is its memory
//!   ceiling as before, and a `-mm` it cannot read as a size is refused.
//!
//! The parser's own table, every spelling of it, is
//! `dialect::unrar::args`'s unit test. This runs on every system: the
//! finding was first read on Windows and is not a Windows one.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

struct Bench {
    dir: PathBuf,
    unrar: PathBuf,
    own: PathBuf,
}

/// Noise a stored member is made of (a linear congruential stream).
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 56) as u8
        })
        .collect()
}

impl Bench {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("rarfast-unrar-m-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        // The name picks the dialect: a copy called `unrar`, and one that
        // keeps the binary's own name.
        let exe = std::env::consts::EXE_SUFFIX;
        let unrar = dir.join(format!("unrar{exe}"));
        let own = dir.join(format!("rarfast{exe}"));
        copy_executable(&rarfast(), &unrar);
        copy_executable(&rarfast(), &own);
        std::fs::write(dir.join("src").join("full.mkv"), noise(300_000, 31)).unwrap();
        std::fs::write(dir.join("src").join("full.nfo"), b"notes\n").unwrap();
        let out = output_of(
            Command::new(rarfast())
                .args(["a", "-m0", "-idq", "../set.rar", "full.mkv", "full.nfo"])
                .current_dir(dir.join("src")),
        )
        .expect("rarfast a runs");
        assert!(out.status.success(), "the set was not made");
        Self { dir, unrar, own }
    }

    /// `<tool> <command> -idq [-o+] <switch> set.rar [<into>/]`.
    fn run(&self, tool: &Path, command: &str, switch: Option<&str>, into: &str) -> Output {
        let dest = self.dir.join(into);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest).unwrap();
        let mut line = Command::new(tool);
        line.arg(command).arg("-idq").current_dir(&self.dir);
        if command == "x" {
            line.arg("-o+");
        }
        if let Some(switch) = switch {
            line.arg(switch);
        }
        line.arg("set.rar");
        if command == "x" {
            line.arg(format!("{into}/"));
        }
        output_of(&mut line).expect("the tool runs")
    }

    /// The names `x` left in `into`, and whether each holds its source.
    fn wrote(&self, into: &str) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.dir.join(into))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for name in &names {
            let want = std::fs::read(self.dir.join("src").join(name)).unwrap();
            let got = std::fs::read(self.dir.join(into).join(name)).unwrap();
            assert!(want == got, "{into}/{name} differs from its source");
        }
        names
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// What the reference accepts and swallows.
const ACCEPTED: [&str; 16] = [
    "-m0",
    "-m3",
    "-m5",
    "-m5x",
    "-M3",
    "-mm",
    "-mm64m",
    "-mm128m",
    "-mm512m",
    "-mm128x",
    "-md64m",
    "-md128k",
    "-ms",
    "-mc",
    "-mc63:128t+",
    "-MT4",
];

/// What it refuses, exit 7.
const REFUSED: [&str; 10] = [
    "-m", "-m6", "-mx", "-mq", "-mta", "-ma5", "-md", "-mdx", "-md64k", "-md64x",
];

#[test]
fn the_unrar_name_reads_the_m_family_as_the_reference_does() {
    let bench = Bench::new("unrar");
    let plain = bench.run(&bench.unrar, "x", None, "plain");
    assert_eq!(plain.status.code(), Some(0));
    let files = bench.wrote("plain");
    assert_eq!(files, ["full.mkv", "full.nfo"]);
    for switch in ACCEPTED {
        for command in ["l", "t", "p", "v", "lb"] {
            let out = bench.run(&bench.unrar, command, Some(switch), "none");
            assert_eq!(out.status.code(), Some(0), "unrar {command} {switch}");
        }
        let out = bench.run(&bench.unrar, "x", Some(switch), "taken");
        assert_eq!(out.status.code(), Some(0), "unrar x {switch}");
        assert_eq!(bench.wrote("taken"), files, "unrar x {switch}");
        assert_eq!(
            out.stdout, plain.stdout,
            "unrar x {switch} said something else"
        );
    }
    for switch in REFUSED {
        for command in ["l", "t", "x", "p", "v", "lb"] {
            let out = bench.run(&bench.unrar, command, Some(switch), "refused");
            assert_eq!(out.status.code(), Some(7), "unrar {command} {switch}");
            let said = String::from_utf8_lossy(&out.stdout);
            assert!(
                said.contains(&format!("ERROR: Unknown option: {}", &switch[1..])),
                "unrar {command} {switch} said {said:?}"
            );
            assert!(
                bench.wrote("refused").is_empty(),
                "unrar {command} {switch}"
            );
        }
    }
}

#[test]
fn rarfasts_own_name_keeps_its_own_mm() {
    let bench = Bench::new("own");
    // A size it reads: its memory ceiling, on every read command.
    for switch in ["-mm64m", "-mm128m", "-mm512m"] {
        for command in ["l", "t", "p", "v", "lb"] {
            let out = bench.run(&bench.own, command, Some(switch), "none");
            assert_eq!(out.status.code(), Some(0), "rarfast {command} {switch}");
        }
        let out = bench.run(&bench.own, "x", Some(switch), "taken");
        assert_eq!(out.status.code(), Some(0), "rarfast x {switch}");
        assert_eq!(bench.wrote("taken"), ["full.mkv", "full.nfo"]);
    }
    // A `-mm` it cannot read as a size is still refused there: a named
    // `-mm` is a promise, and a promise it cannot read is not kept quietly.
    for switch in ["-mm", "-mm128x"] {
        let out = bench.run(&bench.own, "x", Some(switch), "refused");
        assert_eq!(out.status.code(), Some(7), "rarfast x {switch}");
        assert!(bench.wrote("refused").is_empty(), "rarfast x {switch}");
    }
}

/// Under the `unrar` name `-mm<size>` is no ceiling. The member here is
/// packed with a 32 MiB dictionary, which `-mm8m` cannot hold: rarfast's
/// own name refuses it for memory, exit 2, and the `unrar` name extracts
/// it, exit 0, as the reference `unrar` does with the same line.
#[test]
fn a_named_mm_refuses_nothing_under_the_unrar_name() {
    let bench = Bench::new("limit");
    let mut text = String::new();
    let mut state = 1u64;
    for line in 0..40_000 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        text.push_str(&format!("line {line} word {:x}\n", state >> 40));
    }
    std::fs::remove_file(bench.dir.join("set.rar")).unwrap();
    std::fs::remove_file(bench.dir.join("src").join("full.mkv")).unwrap();
    std::fs::remove_file(bench.dir.join("src").join("full.nfo")).unwrap();
    std::fs::write(bench.dir.join("src").join("words.txt"), &text).unwrap();
    let out = output_of(
        Command::new(rarfast())
            .args(["a", "-m3", "-md32m", "-idq", "../set.rar", "words.txt"])
            .current_dir(bench.dir.join("src")),
    )
    .expect("rarfast a runs");
    assert!(out.status.success(), "the set was not made");

    for command in ["t", "x"] {
        let own = bench.run(&bench.own, command, Some("-mm8m"), "own");
        assert_eq!(own.status.code(), Some(2), "rarfast {command} -mm8m");
        let out = bench.run(&bench.unrar, command, Some("-mm8m"), "taken");
        assert_eq!(out.status.code(), Some(0), "unrar {command} -mm8m");
    }
    // `wrote` compares each file with its source.
    assert_eq!(bench.wrote("taken"), ["words.txt"]);
}
