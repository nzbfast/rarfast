//! What a file argument, `-x<mask>` and `-n<mask>` select on the read
//! commands, against reference unrar 7.23.
//!
//! Sweep 2 item 33, 8 Oct 2026. Until then one rule served all three: the
//! mask as a wildcard over the whole name, and over the base name where
//! the mask held no separator. So `-xDir` excluded nothing and the files
//! under `Dir` were WRITTEN (over existing ones under `-o+`), a bare
//! `name` matched at any depth, and `Dir` as an argument selected the
//! directory's own entry and nothing beneath it.
//!
//! The reference's rules, measured as a black box (`unrar lb` over 1,856
//! masks three ways, then 7,374 random ones; the rows kept here are in
//! `selection-masks/tables.rs`):
//!
//! * a mask with no wildcard is the exact path, or a directory and all
//!   beneath it; never a base name at depth;
//! * a wildcard mask with no directory is matched against the base name
//!   at any depth; with a plain directory, that directory is a prefix and
//!   the rest is matched against the base name; with a wildcard in the
//!   directory, the whole mask is matched against the whole name;
//! * `-x` and `-n` share one rule, which is the argument's with four
//!   differences: leading `./`, `../` and `/` are dropped, a leading `*/`
//!   also matches no directory at all, a directory entry is not matched
//!   by a wildcard in the last part (but for `*` and `*.*`), and a
//!   trailing separator names a directory and all beneath it;
//! * the wildcard matcher has the reference's dot rules: `*.*` is every
//!   name, `*.` a name with no dot, a mask's `.` matches the end of a
//!   name.
//!
//! And one rule of the command line that the same fix needs: on `x` and
//! `e` an argument with no wildcard that names a directory ALREADY ON
//! DISK is the destination, not a mask, unless a destination was given
//! before it; the last of `-op<path>` and a `path/` argument wins.
//! Without it `x -o+ set.rar Dir` over an earlier extraction would
//! replace the files under `Dir`, where the reference writes the whole
//! archive into `Dir`.
//!
//! Measured on macOS only: the rows hold on every system here, and what
//! reference UnRAR.exe does with letter case and `\` is owed.
//!
//! Assumes: no thread pool to speak of (members of a few bytes; every run
//! states `-mt1`), under 16 MiB of memory.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

#[path = "selection-masks/tables.rs"]
mod tables;

/// Every file of the set, and the two directories that hold none.
const FILES: &[&str] = &[
    "top.txt",
    "noext",
    "b.txt",
    "a/noext",
    "a/b.txt",
    "a/b/c.txt",
    "a/b/c/noext",
    "a/b/c/d.txt",
    "a.d/noext",
    "a.d/e.txt",
    "x/a/b.txt",
    "x/Sub/s.txt",
    "x/top.txt",
    "q/a.b.txt",
];
const EMPTY_DIRECTORIES: &[&str] = &["a/emptydir", "e.dir"];
const DECOY: &[u8] = b"a file of the caller's own\n";

struct Bench {
    dir: PathBuf,
    unrar: PathBuf,
    own: PathBuf,
}

impl Bench {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rarfast-s33-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let src = dir.join("src");
        for name in FILES {
            let path = src.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, format!("the archive's {name}\n")).unwrap();
        }
        for name in EMPTY_DIRECTORIES {
            std::fs::create_dir_all(src.join(name)).unwrap();
        }
        // The name picks the dialect.
        let exe = std::env::consts::EXE_SUFFIX;
        let unrar = dir.join(format!("unrar{exe}"));
        let own = dir.join(format!("rarfast{exe}"));
        copy_executable(&rarfast(), &unrar);
        copy_executable(&rarfast(), &own);
        let out = output_of(
            Command::new(rarfast())
                .args(["a", "-m0", "-idq", "-mt1", "-r", "../set.rar"])
                .args(["top.txt", "noext", "b.txt", "a", "a.d", "e.dir", "x", "q"])
                .current_dir(&src),
        )
        .expect("rarfast a runs");
        assert_eq!(out.status.code(), Some(0), "building the set: {out:?}");
        Bench { dir, unrar, own }
    }

    fn names(&self) -> [(&'static str, &Path); 2] {
        [("unrar", &self.unrar), ("rarfast", &self.own)]
    }

    /// A fresh directory to run in.
    fn room(&self, tag: &str) -> PathBuf {
        let room = self.dir.join(tag);
        let _ = std::fs::remove_dir_all(&room);
        std::fs::create_dir_all(&room).unwrap();
        room
    }

    /// A fresh directory holding a file of the caller's at every path the
    /// archive has a file at.
    fn planted(&self, tag: &str) -> PathBuf {
        let room = self.room(tag);
        for name in FILES {
            let path = room.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, DECOY).unwrap();
        }
        room
    }

    /// `<exe> <args>` in `room`, standard input closed; `set.rar` among
    /// the arguments is the archive.
    fn run(&self, exe: &Path, room: &Path, args: &[&str]) -> Output {
        let set = self.dir.join("set.rar");
        let args: Vec<&std::ffi::OsStr> = args
            .iter()
            .map(|arg| match *arg {
                "set.rar" => set.as_os_str(),
                other => std::ffi::OsStr::new(other),
            })
            .collect();
        output_of(
            Command::new(exe)
                .args(args)
                .current_dir(room)
                .stdin(Stdio::null()),
        )
        .expect("the command runs")
    }

    /// The names `lb <args>` lists, with `/` on every system.
    fn listed(&self, exe: &Path, args: &[&str]) -> BTreeSet<String> {
        let room = self.room("list");
        let mut line = vec!["lb", "-mt1"];
        line.extend_from_slice(args);
        let out = self.run(exe, &room, &line);
        assert_eq!(out.status.code(), Some(0), "lb {args:?}: {}", said(&out));
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|name| name.replace('\\', "/"))
            .collect()
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
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

fn set_of(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

/// Every path under `room`, relative, with `/`, sorted.
fn tree(room: &Path) -> BTreeSet<String> {
    fn walk(root: &Path, at: &Path, into: &mut BTreeSet<String>) {
        for entry in std::fs::read_dir(at).unwrap() {
            let path = entry.unwrap().path();
            let relative = path.strip_prefix(root).unwrap();
            into.insert(relative.to_string_lossy().replace('\\', "/"));
            if path.is_dir() {
                walk(root, &path, into);
            }
        }
    }
    let mut all = BTreeSet::new();
    walk(room, room, &mut all);
    all
}

/// The files of the set under `room` that no longer hold the caller's
/// bytes: what a run replaced.
fn replaced(room: &Path) -> BTreeSet<String> {
    FILES
        .iter()
        .filter(|name| std::fs::read(room.join(name)).unwrap() != DECOY)
        .map(|name| (*name).to_owned())
        .collect()
}

#[test]
fn a_file_argument_selects_what_the_reference_selects() {
    let bench = Bench::new("argument");
    for (name, exe) in bench.names() {
        for (mask, expected) in tables::ARGUMENT {
            let listed = bench.listed(exe, &["set.rar", mask]);
            assert_eq!(listed, set_of(expected), "{name} lb set.rar {mask}");
        }
    }
}

#[test]
fn an_exclude_and_an_include_mask_select_what_the_reference_selects() {
    let bench = Bench::new("screen");
    for (name, exe) in bench.names() {
        let all = bench.listed(exe, &["set.rar"]);
        assert_eq!(all.len(), 24, "{name}: the set's own names: {all:?}");
        for (mask, taken) in tables::SCREEN {
            let taken = set_of(taken);
            let left: BTreeSet<String> = all.difference(&taken).cloned().collect();
            let exclude = format!("-x{mask}");
            assert_eq!(
                bench.listed(exe, &[&exclude, "set.rar"]),
                left,
                "{name} lb {exclude} set.rar"
            );
            let include = format!("-n{mask}");
            assert_eq!(
                bench.listed(exe, &[&include, "set.rar"]),
                taken,
                "{name} lb {include} set.rar"
            );
        }
    }
}

/// Rule (d) of the item: nothing is written that the reference leaves
/// alone, in an empty directory and over existing files, with `-o+` and
/// with `-o-`.
#[test]
fn extraction_writes_the_reference_s_tree_and_replaces_only_its_files() {
    let bench = Bench::new("extract");
    for (name, exe) in bench.names() {
        for row in tables::EXTRACTED {
            let told = format!("{name} x {:?}", row.args);
            let mut line = vec!["x", "-mt1", "-o+"];
            line.extend_from_slice(row.args);

            let room = bench.room("fresh");
            let out = bench.run(exe, &room, &line);
            assert_eq!(
                out.status.code(),
                Some(row.fresh.0),
                "{told}: {}",
                said(&out)
            );
            assert_eq!(tree(&room), set_of(row.fresh.1), "{told}: the tree");

            let room = bench.planted("over");
            let out = bench.run(exe, &room, &line);
            assert_eq!(
                out.status.code(),
                Some(row.over.0),
                "{told}: {}",
                said(&out)
            );
            assert_eq!(replaced(&room), set_of(row.over.1), "{told}: replaced");

            let room = bench.planted("kept");
            line[2] = "-o-";
            let out = bench.run(exe, &room, &line);
            assert_eq!(out.status.code(), Some(row.kept), "{told}: {}", said(&out));
            assert_eq!(replaced(&room), set_of(&[]), "{told}: under -o-");
        }
    }
}

/// The four scenarios of the item itself, each over files of the caller's
/// own under `-o+`.
#[test]
fn the_sweep_s_four_scenarios() {
    let bench = Bench::new("scenarios");
    for (name, exe) in bench.names() {
        // (1) `-x<directory>`: nothing under it is written.
        let room = bench.planted("one");
        let out = bench.run(exe, &room, &["x", "-mt1", "-o+", "-xa", "set.rar"]);
        assert_eq!(out.status.code(), Some(0), "{name}: {}", said(&out));
        let under: Vec<String> = replaced(&room)
            .into_iter()
            .filter(|path| path.starts_with("a/"))
            .collect();
        assert!(under.is_empty(), "{name} -xa replaced {under:?}");

        // (2) `-x<name>` is the exact path: the one at depth is written.
        let room = bench.planted("two");
        let out = bench.run(exe, &room, &["x", "-mt1", "-o+", "-xb.txt", "set.rar"]);
        assert_eq!(out.status.code(), Some(0), "{name}: {}", said(&out));
        let changed = replaced(&room);
        assert!(!changed.contains("b.txt"), "{name} -xb.txt: {changed:?}");
        assert!(changed.contains("a/b.txt"), "{name} -xb.txt: {changed:?}");

        // (3) a bare name that is nowhere at the top: nothing, exit 10.
        let room = bench.planted("three");
        let out = bench.run(exe, &room, &["x", "-mt1", "-o+", "set.rar", "d.txt"]);
        assert_eq!(out.status.code(), Some(10), "{name}: {}", said(&out));
        assert_eq!(replaced(&room), set_of(&[]), "{name} d.txt");

        // (4) a directory as an argument selects all beneath it.
        let room = bench.room("four");
        let out = bench.run(exe, &room, &["x", "-mt1", "-o+", "set.rar", "x/Sub"]);
        assert_eq!(out.status.code(), Some(0), "{name}: {}", said(&out));
        assert_eq!(
            tree(&room),
            set_of(&["x", "x/Sub", "x/Sub/s.txt"]),
            "{name} x/Sub"
        );
    }
}

/// An argument that names a directory already on disk is the destination
/// of `x` and `e`. Each row: the directories made first, the arguments
/// after `x -mt1 -o+`, and the tree the reference leaves.
#[test]
fn an_existing_directory_named_as_an_argument_is_the_destination() {
    let bench = Bench::new("destination");
    let rows: &[(&[&str], &[&str], &[&str])] = &[
        // Alone it takes the whole archive.
        (
            &["x"],
            &["set.rar", "x"],
            &[
                "x",
                "x/a",
                "x/a.d",
                "x/a.d/e.txt",
                "x/a.d/noext",
                "x/a/b",
                "x/a/b.txt",
                "x/a/b/c",
                "x/a/b/c.txt",
                "x/a/b/c/d.txt",
                "x/a/b/c/noext",
                "x/a/emptydir",
                "x/a/noext",
                "x/b.txt",
                "x/e.dir",
                "x/noext",
                "x/q",
                "x/q/a.b.txt",
                "x/top.txt",
                "x/x",
                "x/x/Sub",
                "x/x/Sub/s.txt",
                "x/x/a",
                "x/x/a/b.txt",
                "x/x/top.txt",
            ],
        ),
        // Before a mask and after one.
        (&["a"], &["set.rar", "a", "b.txt"], &["a", "a/b.txt"]),
        (&["a"], &["set.rar", "b.txt", "a"], &["a", "a/b.txt"]),
        (&["a"], &["set.rar", "b.txt", "./a"], &["a", "a/b.txt"]),
        // One that is not in the archive at all.
        (&["zz"], &["set.rar", "b.txt", "zz"], &["zz", "zz/b.txt"]),
        // The first of two; the second is a mask.
        (
            &["a", "x"],
            &["set.rar", "a", "x/Sub"],
            &["a", "a/x", "a/x/Sub", "a/x/Sub/s.txt", "x"],
        ),
        // A wildcard is never a destination.
        (
            &["a"],
            &["set.rar", "a*"],
            &["a", "a.d", "q", "q/a.b.txt", "x", "x/a"],
        ),
        // A destination given BEFORE it leaves it a mask.
        (
            &["q"],
            &["-opout", "set.rar", "q"],
            &["out", "out/q", "out/q/a.b.txt", "q"],
        ),
        (
            &["q"],
            &["set.rar", "out/", "q"],
            &["out", "out/q", "out/q/a.b.txt", "q"],
        ),
        // One given AFTER it wins, and the directory is still no mask.
        (
            &["q"],
            &["set.rar", "b.txt", "q", "-opout"],
            &["out", "out/b.txt", "q"],
        ),
        (
            &["q"],
            &["set.rar", "b.txt", "q", "out/"],
            &["out", "out/b.txt", "q"],
        ),
        // The last of `-op` and `path/` wins.
        (
            &[],
            &["set.rar", "out/", "-opq", "b.txt"],
            &["q", "q/b.txt"],
        ),
        (
            &[],
            &["-opq", "set.rar", "out/", "b.txt"],
            &["out", "out/b.txt"],
        ),
        // A `path/` in the middle is a destination too.
        (
            &["x"],
            &["set.rar", "b.txt", "a/", "x/Sub"],
            &["a", "a/b.txt", "a/x", "a/x/Sub", "a/x/Sub/s.txt", "x"],
        ),
    ];
    for (name, exe) in bench.names() {
        for (made, args, expected) in rows {
            let room = bench.room("room");
            for directory in *made {
                std::fs::create_dir_all(room.join(directory)).unwrap();
            }
            let mut line = vec!["x", "-mt1", "-o+"];
            line.extend_from_slice(args);
            let out = bench.run(exe, &room, &line);
            let told = format!("{name} x {args:?} over {made:?}");
            assert_eq!(out.status.code(), Some(0), "{told}: {}", said(&out));
            assert_eq!(tree(&room), set_of(expected), "{told}");
        }
        // `e` has the rule; `t` and a listing do not.
        let room = bench.room("room");
        std::fs::create_dir_all(room.join("a")).unwrap();
        let out = bench.run(exe, &room, &["e", "-mt1", "-o+", "set.rar", "b.txt", "a"]);
        assert_eq!(out.status.code(), Some(0), "{name} e: {}", said(&out));
        assert_eq!(tree(&room), set_of(&["a", "a/b.txt"]), "{name} e");
        let out = bench.run(exe, &room, &["lb", "-mt1", "set.rar", "x/Sub"]);
        std::fs::create_dir_all(room.join("x/Sub")).unwrap();
        let again = bench.run(exe, &room, &["lb", "-mt1", "set.rar", "x/Sub"]);
        assert_eq!(out.stdout, again.stdout, "{name} lb with x/Sub on disk");
        assert_eq!(
            String::from_utf8_lossy(&again.stdout).lines().count(),
            2,
            "{name} lb x/Sub: {}",
            said(&again)
        );
    }
}
