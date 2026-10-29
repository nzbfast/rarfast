//! `x` under a CGROUP MEMORY CAP smaller than what it writes: the extract
//! completes, exit 0, with the members' bytes, and is not killed.
//!
//! **The fault this holds (counted 3 Oct 2026, x86-64 Linux, kernel 7.0,
//! ext4 on an EBS volume of about 135 MB/s).** A cgroup's limit counts the
//! page cache its processes dirty. `rarfast x` at the default width wrote
//! faster than the drive, the kernel found what the process left of the cap
//! all dirty and not yet under writeback, and killed it: exit 137, nothing
//! said, a partial file left; 6 of 6 under `MemoryMax=512M`, and the same
//! for 20,000 small files. The writes are now PACED under a cap
//! (`writeback`): writeback is started behind the cursor and the writer
//! waits once its unwritten output passes an eighth of the cap.
//! Counted 3 Oct 2026.
//!
//! **What a run here proves, and what it cannot.** The kill needs a drive
//! slower than the decoders, which a test cannot choose: on a fast drive
//! the rows pass with the pacing or without it. So the rows hold what is
//! true on every box (under a cap smaller than the output: exit 0, every
//! byte, at the default width and at one thread, a big member and many
//! small ones), and in a `reserve-knob` build also that the pace was TAKEN
//! under the cap and NOT taken with none, from the build's own line. The
//! kill table is the boxes'.
//!
//! **Where it runs.** Linux with glibc, where `systemd-run --user --scope
//! -p MemoryMax=` can make a cgroup for this user (a login session with a
//! user manager, cgroup v2 with the memory controller delegated).
//! Elsewhere every row SKIPS, and says so on stderr.
// Linux only by its nature: the cap is a cgroup made by `systemd-run`.
#![cfg(all(target_os = "linux", target_env = "gnu"))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rarkit::{HostOs, MemberOrder, MemberSpec, Payload, WriteOptions, Writer};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{output_of, rarfast};

/// The cap, and the big member: more than the cap by itself.
const CAP: &str = "192M";
const BIG: usize = 224 << 20;
const SMALL: usize = 1024;
const SMALL_LEN: usize = 64 << 10;

/// A scratch directory on the build's own disk (the system's temporary
/// directory is a tmpfs on some boxes, whose pages no writeback frees),
/// removed when it goes out of scope.
struct BuildDiskDir(PathBuf);

impl Drop for BuildDiskDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn work(tag: &str) -> BuildDiskDir {
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("paced-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    BuildDiskDir(dir)
}

fn noise(len: usize, seed: u32) -> Vec<u8> {
    (0..len as u32)
        .map(|i| ((i ^ seed).wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

/// Whether this user can run a command in a memory-capped scope here.
fn scopes_work() -> bool {
    Command::new("systemd-run")
        .args(["--user", "--scope", "-q", "-p", "MemoryMax=64M", "true"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// A stored RAR 5 archive of `members`, in this order.
fn archive(path: &Path, members: &[(String, Vec<u8>)]) {
    let mut writer = Writer::new(WriteOptions {
        order: MemberOrder::AsAdded,
        host_os: HostOs::Unix,
        ..WriteOptions::default()
    })
    .unwrap();
    for (name, bytes) in members {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(bytes),
                mtime: None,
                attributes: 0o100_644,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .unwrap();
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).unwrap();
    std::fs::write(path, out).unwrap();
}

/// `rarfast x` of `archive` into `out`, inside a scope capped at `cap`
/// where one is given.
fn extract(archive: &Path, out: &Path, cap: Option<&str>, width: Option<&str>) -> Output {
    std::fs::create_dir_all(out).unwrap();
    let mut command = match cap {
        Some(cap) => {
            let mut command = Command::new("systemd-run");
            command
                .args(["--user", "--scope", "-q", "-p"])
                .arg(format!("MemoryMax={cap}"))
                .arg("--")
                .arg(rarfast());
            command
        }
        None => Command::new(rarfast()),
    };
    command.args(["x", "-o+"]);
    if let Some(width) = width {
        command.arg(width);
    }
    command.arg(archive).arg(format!("{}/", out.display()));
    output_of(&mut command).expect("rarfast runs")
}

fn check(what: &str, run: &Output, out: &Path, members: &[(String, Vec<u8>)], paced: bool) {
    let (stdout, stderr) = (
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr),
    );
    assert_eq!(
        run.status.code(),
        Some(0),
        "{what}: {:?}\n{}\n{stderr}",
        run.status,
        stdout.lines().rev().take(3).collect::<Vec<_>>().join("\n")
    );
    assert!(stdout.contains("All OK"), "{what}: no All OK");
    for (name, bytes) in members {
        let back = std::fs::read(out.join(name)).unwrap_or_else(|e| panic!("{what}: {name}: {e}"));
        assert!(back == *bytes, "{what}: {name} differs");
    }
    // The knob build's line is said when the first member is written
    // through the cache. Small members always are; a big one may stay past
    // the cache to its end on a fast drive and then says nothing.
    if cfg!(feature = "reserve-knob") {
        let taken = stderr
            .lines()
            .find(|line| line.starts_with("rarfast pace window:"));
        match taken {
            Some(taken) => assert_eq!(taken.contains("Some("), paced, "{what}: {taken}"),
            None => assert!(members.len() == 1, "{what}: no pace line in {stderr}"),
        }
    }
}

#[test]
fn x_under_a_cap_smaller_than_its_output_completes_with_every_byte() {
    if !scopes_work() {
        eprintln!(
            "not measured: `systemd-run --user --scope -p MemoryMax=` makes no cgroup for this user"
        );

        return;
    }
    let dir = work("x");
    let big = vec![("big.bin".to_string(), noise(BIG, 1))];
    let small: Vec<(String, Vec<u8>)> = (0..SMALL)
        .map(|at| {
            (
                format!("small/f{at:04}.bin"),
                noise(SMALL_LEN, at as u32 + 7),
            )
        })
        .collect();
    let (big_rar, small_rar) = (dir.0.join("big.rar"), dir.0.join("small.rar"));
    archive(&big_rar, &big);
    archive(&small_rar, &small);
    for (shape, rar, members) in [("big", &big_rar, &big), ("small", &small_rar, &small)] {
        for width in [None, Some("-mt1")] {
            let what = format!("{shape}, cap {CAP}, width {width:?}");
            let out = dir.0.join("out");
            let run = extract(rar, &out, Some(CAP), width);
            check(&what, &run, &out, members, true);
            std::fs::remove_dir_all(&out).unwrap();
        }
    }
    // With no cap the pace is not taken (a box whose own session is capped
    // is not one this row can speak for).
    let out = dir.0.join("out");
    let run = extract(&small_rar, &out, None, None);
    let capped_here = String::from_utf8_lossy(&run.stderr).contains("pace window: Some(");
    if cfg!(feature = "reserve-knob") && capped_here {
        eprintln!("the row with no cap is not judged: a cap already holds this run and the pace was taken");
    } else {
        check("small, no cap", &run, &out, &small, false);
    }
}
