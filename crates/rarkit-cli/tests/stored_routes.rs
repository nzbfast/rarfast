//! `x` and `t` of an archive of STORED members say and write the same by
//! every route the unrar dialect can take them (1 Oct 2026).
//!
//! The dialect chooses between the engine's member pool and its sequential
//! walk (`Run::drive`): on macOS `x` of an archive whose members are all
//! stored and clear takes the walk, everything else of two or more members
//! the pool, and inside the pool a worker reads a stored member wide or on
//! its own thread by a rule of the engine's. Which is FASTER is a timed
//! question (measured 1 Oct 2026); what none of them may move is
//! what `x` leaves on disk, what `t` reports and the exit code. Each case
//! runs the shipped route, the walk (`RARFAST_POOL=0`), the pool
//! (`RARFAST_POOL=1`) and the pool with every worker's wide read off, on
//! (whatever is written) and on for a clear written member, and compares.
//!
//! The members are over the wide read's floor (16 MiB), so the wide arms
//! really are taken; fixtures are written by this crate's own `rar`
//! dialect, so nothing is needed on PATH.
//!
//! A shipped `rarfast` reads no environment word; the read path's exist only
//! under the feature `reader-knobs`, which this test builds with:
//!
//! ```text
//! cargo test -p rarkit-cli --features reader-knobs --test stored_routes
//! ```
#![cfg(feature = "reader-knobs")]

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, tool_named};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-routes-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A copy of `rarfast` named `unrar`, which is how the binary picks that
/// dialect.
fn as_unrar(tag: &str) -> PathBuf {
    let dir = work(&format!("bin-{tag}"));
    let named = tool_named(&dir, "unrar");
    copy_executable(&rarfast(), &named);
    named
}

/// The route knobs, cleared for every run and then set as the arm asks.
const KNOBS: [&str; 8] = [
    "RARFAST_POOL",
    "RARKIT_STORED_CUT",
    "RARKIT_STORED_CUT_CIPHER",
    "RARKIT_STORED_CUT_WHEN",
    "RARKIT_JOB_WIDE",
    "RARKIT_JOB_WIDE_CLEAR",
    "RARKIT_JOB_WIDE_WRITE",
    "RARKIT_JOB_WIDE_WRITTEN",
];

/// Each arm: its name, and the knobs it sets.
const ARMS: [(&str, &[(&str, &str)]); 14] = [
    ("shipped", &[]),
    // The cut of a stored member by the thread that writes it
    // (`RARKIT_STORED_CUT`): off, and on in both orders by each route.
    ("the cut off", &[("RARKIT_STORED_CUT", "0")]),
    (
        "pool, the cut off",
        &[("RARFAST_POOL", "1"), ("RARKIT_STORED_CUT", "0")],
    ),
    (
        "pool, cut in order whenever",
        &[
            ("RARFAST_POOL", "1"),
            ("RARKIT_STORED_CUT", "seq"),
            ("RARKIT_STORED_CUT_WHEN", "always"),
        ],
    ),
    (
        "pool, cut at once, alone",
        &[
            ("RARFAST_POOL", "1"),
            ("RARKIT_STORED_CUT", "wide"),
            ("RARKIT_STORED_CUT_WHEN", "alone"),
        ],
    ),
    // The cipher's cut is a system's default: both, by each route.
    (
        "pool, the cipher's cut on, whenever",
        &[
            ("RARFAST_POOL", "1"),
            ("RARKIT_STORED_CUT_CIPHER", "1"),
            ("RARKIT_STORED_CUT_WHEN", "always"),
        ],
    ),
    (
        "walk, the cipher's cut off",
        &[("RARFAST_POOL", "0"), ("RARKIT_STORED_CUT_CIPHER", "0")],
    ),
    (
        "walk, cut at once",
        &[
            ("RARFAST_POOL", "0"),
            ("RARKIT_STORED_CUT", "wide:1024"),
            ("RARKIT_STORED_CUT_CIPHER", "1"),
        ],
    ),
    ("walk", &[("RARFAST_POOL", "0")]),
    ("pool", &[("RARFAST_POOL", "1")]),
    (
        "pool, workers narrow",
        &[("RARFAST_POOL", "1"), ("RARKIT_JOB_WIDE", "0")],
    ),
    (
        "pool, every written member on its worker (the knobs' parent path)",
        &[
            ("RARFAST_POOL", "1"),
            ("RARKIT_JOB_WIDE_WRITTEN", "never"),
            ("RARKIT_JOB_WIDE_WRITE", "0"),
        ],
    ),
    (
        "pool, a written member wide",
        &[
            ("RARFAST_POOL", "1"),
            ("RARKIT_JOB_WIDE", "2"),
            ("RARKIT_JOB_WIDE_WRITTEN", "always"),
        ],
    ),
    (
        "pool, a clear written member wide",
        &[
            ("RARFAST_POOL", "1"),
            ("RARKIT_JOB_WIDE", "2"),
            ("RARKIT_JOB_WIDE_WRITTEN", "always"),
            ("RARKIT_JOB_WIDE_WRITE", "1"),
        ],
    ),
];

struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(binary: &Path, dir: &Path, args: &[&str], knobs: &[(&str, &str)]) -> Ran {
    let mut command = Command::new(binary);
    command.args(args).current_dir(dir).env("TZ", "UTC");
    for knob in KNOBS {
        command.env_remove(knob);
    }
    for (knob, value) in knobs {
        command.env(knob, value);
    }
    let out =
        output_of(&mut command).unwrap_or_else(|err| panic!("{binary:?} could not be run: {err}"));
    Ran {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Incompressible, deterministic bytes.
fn noise(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// A big member over the wide floor, a sample over it too, and an nfo far under
/// the offload floor: the release shape.
const MEMBERS: [(&str, usize); 3] = [
    ("Full.mkv", (36 << 20) + 5),
    ("Sample.mkv", (18 << 20) + 9),
    ("Full.nfo", 4096),
];

/// The members stored in `set.rar` under `dir/in`, with `extra` switches
/// (`-hpSecret`, or none).
fn archive(dir: &Path, extra: &[&str]) {
    let input = dir.join("in");
    std::fs::create_dir_all(&input).unwrap();
    for (at, (name, len)) in MEMBERS.iter().enumerate() {
        std::fs::write(input.join(name), noise(71 + at as u64, *len)).unwrap();
    }
    let mut args = vec!["a", "-y", "-idq", "-m0", "-ep"];
    args.extend(extra);
    args.push("../set.rar");
    args.extend(MEMBERS.iter().map(|(name, _)| *name));
    let made = run(&rarfast(), &input, &args, &[]);
    assert_eq!(made.code, Some(0), "setup create failed: {}", made.stderr);
}

/// The set's first volume under `dir`: `set.rar`, or the first of the
/// volumes `-v` made.
fn first_volume(dir: &Path) -> String {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("set.") && name.ends_with(".rar"))
        .collect();
    names.sort();
    names.into_iter().next().expect("the set was made")
}

/// `x` into a fresh directory by one arm: the exit code and every file's
/// bytes as (name, length, CRC32).
fn extracted(
    unrar: &Path,
    dir: &Path,
    arm: usize,
    password: &[&str],
) -> (Option<i32>, Vec<(String, usize, u32)>) {
    let out = dir.join(format!("out-{arm}"));
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    let target = format!("out-{arm}/");
    let first = first_volume(dir);
    let mut args = vec!["x", "-o+", "-idq"];
    args.extend(password);
    args.extend([first.as_str(), &target]);
    let ran = run(unrar, dir, &args, ARMS[arm].1);
    let mut files: Vec<(String, usize, u32)> = std::fs::read_dir(&out)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let bytes = std::fs::read(entry.path()).unwrap();
            (
                entry.file_name().to_string_lossy().into_owned(),
                bytes.len(),
                rarkit::checksum::crc32(&bytes),
            )
        })
        .collect();
    files.sort();
    let _ = std::fs::remove_dir_all(&out);
    (ran.code, files)
}

fn truth() -> Vec<(String, usize, u32)> {
    let mut files: Vec<(String, usize, u32)> = MEMBERS
        .iter()
        .enumerate()
        .map(|(at, (name, len))| {
            let bytes = noise(71 + at as u64, *len);
            (name.to_string(), *len, rarkit::checksum::crc32(&bytes))
        })
        .collect();
    files.sort();
    files
}

/// Each route of the same members stored in one volume, and in volumes of
/// 8 MiB, where the big member and the sample are both split: a SPLIT
/// SET, which on macOS takes the stored route (`SPLIT_SET_MEMBERS`),
/// clear and encrypted.
#[test]
fn every_route_extracts_and_tests_a_stored_archive_the_same() {
    for (tag, switches, password) in [
        ("clear", &[][..], &[][..]),
        ("hp", &["-hpSecret"][..], &["-pSecret"][..]),
        ("volumes", &["-v8m"][..], &[][..]),
        ("hp-volumes", &["-hpSecret", "-v8m"][..], &["-pSecret"][..]),
    ] {
        let dir = work(tag);
        archive(&dir, switches);
        let unrar = as_unrar(tag);
        let want = truth();
        for (arm, (name, knobs)) in ARMS.iter().enumerate() {
            let (code, files) = extracted(&unrar, &dir, arm, password);
            assert_eq!(code, Some(0), "{tag}, {name}: x");
            assert_eq!(files, want, "{tag}, {name}: what x left on disk");
            let first = first_volume(&dir);
            let mut args = vec!["t", "-idq"];
            args.extend(password);
            args.push(first.as_str());
            let tested = run(&unrar, &dir, &args, knobs);
            assert_eq!(tested.code, Some(0), "{tag}, {name}: t {}", tested.stderr);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A flipped byte in the big member: every route reports the checksum error and
/// the same exit code, and none of them reports the other members.
#[test]
fn every_route_reports_a_damaged_stored_member_the_same() {
    for (tag, switches, password) in [
        ("clear-bad", &[][..], &[][..]),
        ("hp-bad", &["-hpSecret"][..], &["-pSecret"][..]),
    ] {
        let dir = work(tag);
        archive(&dir, switches);
        let path = dir.join("set.rar");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[9 << 20] ^= 0x40;
        std::fs::write(&path, bytes).unwrap();
        let unrar = as_unrar(tag);
        let mut said: Option<(Option<i32>, Option<i32>)> = None;
        for (arm, (name, knobs)) in ARMS.iter().enumerate() {
            let (x_code, _) = extracted(&unrar, &dir, arm, password);
            let mut args = vec!["t"];
            args.extend(password);
            args.push("set.rar");
            let tested = run(&unrar, &dir, &args, knobs);
            assert_ne!(
                tested.code,
                Some(0),
                "{tag}, {name}: t passed a damaged member"
            );
            assert_ne!(x_code, Some(0), "{tag}, {name}: x passed a damaged member");
            let both = tested.stdout.clone() + &tested.stderr;
            assert!(
                both.contains("Full.mkv"),
                "{tag}, {name}: the damaged member is not named: {both}"
            );
            match said {
                None => said = Some((x_code, tested.code)),
                Some(first) => assert_eq!(
                    (x_code, tested.code),
                    first,
                    "{tag}, {name}: the exit codes, against the shipped route"
                ),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
