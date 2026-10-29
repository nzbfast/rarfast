//! An extraction switch that is read and not honoured is REFUSED by name;
//! `-op<path>` is honoured.
//!
//! Sweep H-4, 4 Oct 2026. `-op<path>`, `-ep`, `-ep4<path>`, `-ap<path>`,
//! `-ad`, `-ad1`, `-ad2`, `-f`, `-u` and a bare `-p` were parsed into the
//! options and read by nothing. `x -o+ -op/some/dir arc.rar` extracted
//! into the CURRENT directory and overwrote there, and every one of them
//! ended `All OK`, exit 0, having done something else.
//!
//! **`-op<path>` is honoured**, as reference unrar 7.23 has it (measured
//! on macOS arm64 the same day): the path is the destination of `x` and
//! `e`, made if it is not there, with or without a trailing separator; a
//! destination given as a positional (`out/`) wins over it; an empty
//! `-op` is no destination; `t` ignores it.
//!
//! **The rest are refused on `x` and `e`**, exit 7 and nothing written,
//! each named on stderr. The reference ignores them all on `t`, `l` and
//! `p` (measured: the same output and exit with and without, but for
//! `t -ep`, which drops the directory's own line), so there they are
//! still accepted. **A bare `-p` is refused on every command**: the
//! reference asks for the password before it opens the archive, encrypted
//! or not, and rarfast asks nothing.
//!
//! **`-cl`, `-cu` and `-ep1` are refused on `x` and `e` too** (sweep 2
//! items 31 and 32, 8 Oct 2026). They were accepted and the names were
//! written unchanged, exit 0. The reference (unrar 7.23, measured that
//! day) writes every name in lower or upper case under `-cl` and `-cu`,
//! and compares a mask with the converted name; under `-ep1` it drops
//! the mask's own directory from each name it writes (`x -ep1 arc
//! 'Dir/Sub/*'` writes `Eps.txt` at the top). Neither is done here yet,
//! so neither is taken in silence. `-ep2` and `-ep3` change nothing the
//! reference writes on extraction and stay accepted; a listing already
//! honours `-cl` and `-cu`.
//!
//! Under rarfast's OWN name a line is read by the decoder's parser first,
//! so every row here holds under both names. What is left is a line that
//! parser refuses and the creator's accepts (`x -ep -m5 arc.rar`): there
//! `-ep` and `-f` sit in fields of the creator's own that the read
//! dispatch is not handed, and their refusal waits on that parser.
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
    own: PathBuf,
}

const A: &[u8] = b"the archive's a.txt\n";
const B: &[u8] = b"the archive's sub/b.txt\n";
const DECOY: &[u8] = b"a file of the caller's own, not to be touched\n";

impl Bench {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rarfast-h4-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src").join("sub")).unwrap();
        // The name picks the dialect.
        let exe = std::env::consts::EXE_SUFFIX;
        let unrar = dir.join(format!("unrar{exe}"));
        let own = dir.join(format!("rarfast{exe}"));
        copy_executable(&rarfast(), &unrar);
        copy_executable(&rarfast(), &own);
        std::fs::write(dir.join("src").join("a.txt"), A).unwrap();
        std::fs::write(dir.join("src").join("sub").join("b.txt"), B).unwrap();
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
        Bench { dir, unrar, own }
    }

    fn names(&self) -> [(&'static str, &Path); 2] {
        [("unrar", &self.unrar), ("rarfast", &self.own)]
    }

    /// A fresh directory to run in, holding the caller's own `a.txt`.
    fn room(&self, tag: &str) -> PathBuf {
        let room = self.dir.join(tag);
        let _ = std::fs::remove_dir_all(&room);
        std::fs::create_dir_all(&room).unwrap();
        std::fs::write(room.join("a.txt"), DECOY).unwrap();
        room
    }

    /// `<exe> <args>` in `room`, standard input closed.
    fn run(&self, exe: &Path, room: &Path, args: &[&str]) -> Output {
        output_of(
            Command::new(exe)
                .args(args)
                .current_dir(room)
                .stdin(Stdio::null()),
        )
        .expect("the command runs")
    }
}

/// Every name in `room`, sorted: what a run left there.
fn left_in(room: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(room)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn said(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn each_unhonoured_extract_switch_exits_7_naming_it_with_nothing_written() {
    let bench = Bench::new("refused");
    // The switch as typed and the name the refusal gives it.
    let rows = [
        ("-ep", "-ep"),
        ("-ep4sub", "-ep4"),
        ("-apsub", "-ap"),
        ("-ad", "-ad"),
        ("-ad1", "-ad"),
        ("-ad2", "-ad"),
        ("-f", "-f"),
        ("-u", "-u"),
        ("-p", "-p"),
        // Sweep 2 items 31 and 32, 8 Oct 2026.
        ("-cl", "-cl"),
        ("-cu", "-cu"),
        ("-ep1", "-ep1"),
    ];
    for (name, exe) in bench.names() {
        for (switch, named) in rows {
            for command in ["x", "e"] {
                let room = bench.room("room");
                let out = bench.run(exe, &room, &[command, "-mt1", "-o+", switch, "../set.rar"]);
                let told = format!("{name} {command} {switch}: {}", said(&out));
                assert_eq!(out.status.code(), Some(7), "{told}");
                let stderr = String::from_utf8_lossy(&out.stderr);
                assert!(
                    stderr
                        .lines()
                        .any(|line| line.contains("rarfast") && line.contains(&format!("{named} "))),
                    "the refusal does not name {named}: {told}"
                );
                assert_eq!(left_in(&room), ["a.txt"], "{told}");
                assert_eq!(std::fs::read(room.join("a.txt")).unwrap(), DECOY, "{told}");
            }
        }
        // A bare `-p` asks nothing on any command.
        for command in ["t", "l", "p"] {
            let room = bench.room("room");
            let out = bench.run(exe, &room, &[command, "-mt1", "-p", "../set.rar"]);
            let told = format!("{name} {command} -p: {}", said(&out));
            assert_eq!(out.status.code(), Some(7), "{told}");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("-p "),
                "{told}"
            );
            assert!(out.stdout.is_empty() || command != "p", "{told}");
        }
    }
    let _ = std::fs::remove_dir_all(&bench.dir);
}

#[test]
fn the_same_switches_change_nothing_where_the_reference_ignores_them() {
    let bench = Bench::new("ignored");
    for (name, exe) in bench.names() {
        for command in ["t", "l", "p"] {
            let room = bench.room("room");
            let plain = bench.run(exe, &room, &[command, "-mt1", "../set.rar"]);
            let with = bench.run(
                exe,
                &room,
                &[
                    command,
                    "-mt1",
                    "-ad",
                    "-u",
                    "-apsub",
                    "-ep4sub",
                    "-opZ",
                    "../set.rar",
                ],
            );
            let told = format!("{name} {command}: {}", said(&with));
            assert_eq!(
                plain.status.code(),
                Some(0),
                "{name} {command}: {}",
                said(&plain)
            );
            assert_eq!(with.status.code(), Some(0), "{told}");
            assert_eq!(with.stdout, plain.stdout, "{told}");
            assert_eq!(left_in(&room), ["a.txt"], "{told}");
        }
    }
    let _ = std::fs::remove_dir_all(&bench.dir);
}

#[test]
fn op_is_the_destination_and_the_current_directory_is_left_alone() {
    let bench = Bench::new("op");
    for (name, exe) in bench.names() {
        // The sweep's own line: `x -o+ -op<dir>` beside a file of the same
        // name as a member.
        for (dest, at) in [
            ("-opout", "out"),
            ("-opout/", "out"),
            ("-opdeep/er", "deep/er"),
        ] {
            let room = bench.room("room");
            let out = bench.run(exe, &room, &["x", "-mt1", "-o+", dest, "../set.rar"]);
            let told = format!("{name} x {dest}: {}", said(&out));
            assert_eq!(out.status.code(), Some(0), "{told}");
            assert_eq!(std::fs::read(room.join("a.txt")).unwrap(), DECOY, "{told}");
            assert!(!room.join("sub").exists(), "{told}");
            assert_eq!(
                std::fs::read(room.join(at).join("a.txt")).unwrap(),
                A,
                "{told}"
            );
            assert_eq!(
                std::fs::read(room.join(at).join("sub").join("b.txt")).unwrap(),
                B,
                "{told}"
            );
        }
        // `e` flattens into it.
        let room = bench.room("room");
        let out = bench.run(exe, &room, &["e", "-mt1", "-o+", "-opflat", "../set.rar"]);
        let told = format!("{name} e -opflat: {}", said(&out));
        assert_eq!(out.status.code(), Some(0), "{told}");
        assert_eq!(std::fs::read(room.join("a.txt")).unwrap(), DECOY, "{told}");
        assert_eq!(
            std::fs::read(room.join("flat").join("a.txt")).unwrap(),
            A,
            "{told}"
        );
        assert_eq!(
            std::fs::read(room.join("flat").join("b.txt")).unwrap(),
            B,
            "{told}"
        );
        // A destination given as a positional wins.
        let room = bench.room("room");
        let out = bench.run(
            exe,
            &room,
            &["x", "-mt1", "-o+", "-opA", "../set.rar", "B/"],
        );
        let told = format!("{name} x -opA set B/: {}", said(&out));
        assert_eq!(out.status.code(), Some(0), "{told}");
        assert_eq!(left_in(&room), ["B", "a.txt"], "{told}");
        assert_eq!(
            std::fs::read(room.join("B").join("a.txt")).unwrap(),
            A,
            "{told}"
        );
        assert_eq!(std::fs::read(room.join("a.txt")).unwrap(), DECOY, "{told}");
        // An empty `-op` is no destination: the current directory, as the
        // reference has it, and under `-o-` the caller's file is kept.
        let room = bench.room("room");
        let out = bench.run(exe, &room, &["x", "-mt1", "-o-", "-op", "../set.rar"]);
        let told = format!("{name} x -op: {}", said(&out));
        assert_eq!(std::fs::read(room.join("a.txt")).unwrap(), DECOY, "{told}");
        assert_eq!(
            std::fs::read(room.join("sub").join("b.txt")).unwrap(),
            B,
            "{told}"
        );
        // `t` makes nothing of it.
        let room = bench.room("room");
        let out = bench.run(exe, &room, &["t", "-mt1", "-opT", "../set.rar"]);
        assert_eq!(out.status.code(), Some(0), "{name} t -opT: {}", said(&out));
        assert_eq!(left_in(&room), ["a.txt"], "{name} t -opT");
    }
    let _ = std::fs::remove_dir_all(&bench.dir);
}
