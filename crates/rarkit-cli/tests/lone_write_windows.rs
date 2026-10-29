//! THE WINDOWS LONE WRITE (`dialect::unrar::extract::lone_written_stored`):
//! `x` and `e` of one stored member alone, from 16 MiB, are read by the
//! serial walk and written behind it on a thread of their own, into a file
//! whose end is set to the member's declared size before the first write.
//! Through the whole command, in a build that reads the knobs.
//!
//! What must hold: on Windows the member of that shape is taken and every
//! shape the rule leaves alone is not, and on every other system nothing
//! is taken; and on every system NO BYTE, NO LENGTH, NO TIME AND NO VERDICT
//! moves with it: the bytes and the modification time are the source's, a
//! longer file standing at the name is cut to the member, and a member cut
//! short in its archive is removed, or kept under `-kb` at the bytes that
//! arrived and no further (the end set ahead is given back).
//!
//! Width and memory: the default width of the box the test runs on (the
//! lone write wants a second thread; hosted runners are 2 to 4 wide), and
//! archives of 15 to 33 MiB plus their outputs, about 200 MiB on disk at
//! once; the writer holds about 2 MiB of pieces in flight.
//!
//! The knobs exist only under the feature `read-depth-knob`; the knob test
//! runner (`make test-knob-spawn`) builds it and runs this:
//!
//! ```text
//! cargo test -p rarkit-cli --features read-depth-knob --test lone_write_windows
//! ```
#![cfg(feature = "read-depth-knob")]

use std::path::PathBuf;
use std::process::{Command, Output};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

const MIB: usize = 1 << 20;

/// Whether this system takes the lone write: Windows alone.
const SHIPPED: bool = cfg!(windows);

struct Bench {
    dir: PathBuf,
    unrar: PathBuf,
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
            std::env::temp_dir().join(format!("rarfast-lone-write-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        // A copy named `unrar` is how the binary picks that dialect.
        let unrar = dir.join("unrar");
        copy_executable(&rarfast(), &unrar);
        Self { dir, unrar }
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.dir.join("src").join(name), bytes).unwrap();
    }

    /// `rarfast a -m0 <archive> <files>` in the source directory.
    fn create(&self, archive: &str, files: &[&str]) {
        let out = output_of(
            Command::new(rarfast())
                .args(["a", "-m0", "-idq", &format!("../{archive}")])
                .args(files)
                .current_dir(self.dir.join("src")),
        )
        .expect("rarfast a runs");
        ok(&out, &format!("rarfast a {archive}"));
    }

    /// `<tool> <command> -idq -y <extra> <archive> <into>/`, the cache's
    /// answer stated as in memory and the lone write said. `fresh` empties
    /// `into` first.
    fn extract_by(
        &self,
        tool: &PathBuf,
        command: &str,
        archive: &str,
        into: &str,
        extra: &[&str],
        fresh: bool,
    ) -> Output {
        let dest = self.dir.join(into);
        if fresh {
            let _ = std::fs::remove_dir_all(&dest);
        }
        std::fs::create_dir_all(&dest).unwrap();
        let target = format!("{into}/");
        let mut args = vec![command, "-idq", "-y"];
        args.extend_from_slice(extra);
        args.push(archive);
        args.push(&target);
        output_of(
            Command::new(tool)
                .args(&args)
                .current_dir(&self.dir)
                .env("RARFAST_RESIDENT", "1")
                .env("RARFAST_LONE_WRITE_SAY", "1")
                .env_remove("RARFAST_LONE_WRITE")
                .env_remove("RARFAST_LONE_WIDE")
                .env_remove("RARFAST_POOL")
                .env_remove("RARFAST_X_READ_AHEAD_MIB")
                .env_remove("RARKIT_SEAM_FROM_MIB")
                .env_remove("RARFAST_COLD_WINDOW"),
        )
        .expect("unrar runs")
    }

    fn extract(&self, command: &str, archive: &str, into: &str, extra: &[&str]) -> Output {
        self.extract_by(&self.unrar, command, archive, into, extra, true)
    }

    /// Each named file in `into` is its source's bytes, and carries its
    /// source's modification time to the second.
    fn same(&self, into: &str, names: &[&str]) {
        for name in names {
            let source = self.dir.join("src").join(name);
            let made = self.dir.join(into).join(name);
            let want = std::fs::read(&source).unwrap();
            let got = std::fs::read(&made).unwrap_or_else(|e| panic!("{into}/{name}: {e}"));
            assert!(want == got, "{into}/{name} differs from its source");
            let seconds = |path: &PathBuf| {
                std::fs::metadata(path)
                    .unwrap()
                    .modified()
                    .unwrap()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            };
            assert_eq!(
                seconds(&made),
                seconds(&source),
                "{into}/{name}: the member's time"
            );
        }
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what}: {:?} {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Whether the run said the lone write took its member.
fn taken(out: &Output) -> bool {
    let text = String::from_utf8_lossy(&out.stderr);
    text.lines()
        .filter_map(|line| {
            line.split_once("rarfast lone write: ")
                .map(|(_, rest)| rest)
        })
        .next_back()
        .unwrap_or_else(|| panic!("no lone write line in {text:?}"))
        .trim()
        == "taken"
}

/// The rule's shape: one clear stored member alone in its archive, at
/// 16 MiB (the floor) and at 33 MiB (where the lone wide rule took it on
/// Windows before), for `x` and for `e`: taken on Windows alone, and the
/// same bytes and time everywhere.
#[test]
fn a_lone_member_is_written_behind_on_windows() {
    let bench = Bench::new("lone");
    for mib in [16, 33] {
        let name = format!("st{mib}m.bin");
        let archive = format!("lone{mib}.rar");
        bench.write(&name, &noise(mib * MIB, mib as u64));
        bench.create(&archive, &[&name]);
        for command in ["x", "e"] {
            let into = format!("out-{mib}-{command}");
            let out = bench.extract(command, &archive, &into, &[]);
            let what = format!("{command} {mib} MiB");
            ok(&out, &what);
            bench.same(&into, &[&name]);
            assert_eq!(taken(&out), SHIPPED, "{what}");
        }
    }
}

/// Every shape the rule leaves alone is not taken, byte for byte: a stated
/// `-mt1`, a stated `-mm` (by `rarfast` itself, which carries it), a member
/// under the floor, and two files where there was one.
#[test]
fn the_shapes_it_leaves_alone_are_not_taken() {
    let bench = Bench::new("alone");
    bench.write("st16m.bin", &noise(16 * MIB, 2));
    bench.write("small.bin", &noise(15 * MIB, 3));
    bench.write("note.nfo", b"release notes\n");
    bench.create("lone.rar", &["st16m.bin"]);
    bench.create("small.rar", &["small.bin"]);
    bench.create("two.rar", &["st16m.bin", "note.nfo"]);
    let rarfast = rarfast();
    // (the tool, the archive, its switches, the files)
    type Case<'a> = (&'a PathBuf, &'a str, &'a [&'a str], &'a [&'a str]);
    let cases: [Case; 4] = [
        (&bench.unrar, "lone.rar", &["-mt1"], &["st16m.bin"]),
        (&rarfast, "lone.rar", &["-mm256m"], &["st16m.bin"]),
        (&bench.unrar, "small.rar", &[], &["small.bin"]),
        (&bench.unrar, "two.rar", &[], &["st16m.bin", "note.nfo"]),
    ];
    for (i, (tool, archive, extra, names)) in cases.iter().enumerate() {
        let into = format!("out-{i}");
        let out = bench.extract_by(tool, "x", archive, &into, extra, true);
        let what = format!("x {extra:?} {archive}");
        ok(&out, &what);
        bench.same(&into, names);
        assert!(!taken(&out), "{what}: the rule leaves it alone");
    }
}

/// A LONGER file standing at the member's name is written over (`-o+`)
/// and cut to the member: the end set ahead is the member's declared size,
/// never the old file's.
#[test]
fn a_longer_file_at_the_name_is_cut_to_the_member() {
    let bench = Bench::new("longer");
    bench.write("st16m.bin", &noise(16 * MIB, 5));
    bench.create("lone.rar", &["st16m.bin"]);
    let into = "over";
    let dest = bench.dir.join(into);
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(dest.join("st16m.bin"), noise(20 * MIB, 6)).unwrap();
    let out = bench.extract_by(&bench.unrar, "x", "lone.rar", into, &["-o+"], false);
    ok(&out, "x -o+ over a longer file");
    bench.same(into, &["st16m.bin"]);
    assert_eq!(taken(&out), SHIPPED, "x -o+");
}

/// A member CUT SHORT in its archive: `x` fails it and removes it, and
/// `-kb` keeps it at the bytes that arrived, a prefix of the source and
/// shorter than the member: the end set ahead of the bytes is given back.
#[test]
fn a_member_cut_short_keeps_only_the_bytes_that_arrived() {
    let bench = Bench::new("cut");
    let source = noise(16 * MIB, 7);
    bench.write("st16m.bin", &source);
    bench.create("whole.rar", &["st16m.bin"]);
    let whole = std::fs::read(bench.dir.join("whole.rar")).unwrap();
    std::fs::write(bench.dir.join("cut.rar"), &whole[..whole.len() / 2]).unwrap();
    // (switches, whether the member is kept)
    for (extra, kept) in [(&[][..], false), (&["-kb"][..], true)] {
        let into = format!("cut{}", extra.len());
        let out = bench.extract("x", "cut.rar", &into, extra);
        let what = format!("x {extra:?} of the cut archive");
        assert!(!out.status.success(), "{what}: fails");
        assert_eq!(taken(&out), SHIPPED, "{what}");
        let made = bench.dir.join(&into).join("st16m.bin");
        if kept {
            let got = std::fs::read(&made).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert!(
                !got.is_empty() && got.len() < source.len(),
                "{what}: {} bytes",
                got.len()
            );
            assert!(got == source[..got.len()], "{what}: a prefix of the source");
        } else {
            assert!(!made.exists(), "{what}: removed");
        }
    }
}

/// A run STOPPED mid member (`lone_write_end`'s promise): where the lone write takes
/// the member, the run is ended outright once 5 MiB are written
/// (`RARFAST_LONE_WRITE_STOP_AT`, an abort, which is a kill: nothing is
/// flushed, cut back or named after it). The file it leaves, under the
/// member's own name, is SHORTER than the member, its bytes the source's:
/// never a file of the member's length, which a downloader reads as
/// complete. Off Windows the lone write takes nothing and the run is whole.
#[test]
fn a_run_stopped_mid_member_never_leaves_the_declared_length() {
    let bench = Bench::new("stop");
    let source = noise(16 * MIB, 8);
    bench.write("st16m.bin", &source);
    bench.create("lone.rar", &["st16m.bin"]);
    let into = "stopped";
    let dest = bench.dir.join(into);
    let _ = std::fs::remove_dir_all(&dest);
    std::fs::create_dir_all(&dest).unwrap();
    let out = output_of(
        Command::new(&bench.unrar)
            .args(["x", "-idq", "-y", "lone.rar", "stopped/"])
            .current_dir(&bench.dir)
            .env("RARFAST_RESIDENT", "1")
            .env("RARFAST_LONE_WRITE_SAY", "1")
            .env("RARFAST_LONE_WRITE_STOP_AT", (5 * MIB).to_string())
            .env_remove("RARFAST_LONE_WRITE")
            .env_remove("RARFAST_LONE_WIDE")
            .env_remove("RARFAST_POOL")
            .env_remove("RARFAST_COLD_WINDOW"),
    )
    .expect("unrar runs");
    let got = std::fs::read(dest.join("st16m.bin")).expect("the file the run left");
    if SHIPPED {
        assert!(!out.status.success(), "the run was stopped");
        assert!(taken(&out), "the lone write took it");
        assert!(
            got.len() < source.len(),
            "a stopped run left {} bytes, the member's whole length",
            got.len()
        );
        assert!(got.len() >= 5 * MIB, "{} bytes", got.len());
        assert!(got[..5 * MIB] == source[..5 * MIB], "the bytes written");
    } else {
        ok(&out, "x off Windows");
        assert!(!taken(&out));
        assert!(got == source, "whole");
    }
}
