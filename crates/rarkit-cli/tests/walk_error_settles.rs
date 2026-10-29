//! A member the walk did not finish is never reported `OK`.
//!
//! Found in the large-dictionary default work and reproduced
//! on 27 Sep 2026: `Run::finish` closed every progress line still open
//! with `OK`. A walk that ends well leaves none open, so any line open
//! there belongs to a member the engine never closed, which was never
//! verified. With a file size limit under one member, `x` printed
//! `Extracting  out/f06.bin  OK` for a member whose write had failed
//! partway, kept its partial file without `-kb`, and exited 2, on the
//! concurrent path and on the sequential one (`-mt1`, and every solid
//! set) alike.
//!
//! unrar 7.23, measured on an M3 Mac the same day over the same shape
//! (twelve members, the seventh larger than the limit, RAR 5 `-m3`, plain
//! and solid, with and without `-kb`): the failed member's line ends with
//! no `OK`, stderr says `Write error in the file out/f06.bin`, the exit
//! code is 5, and the partial file is removed unless `-kb` asked to keep
//! it. The rows below hold rarkit to exactly that, and to the property
//! underneath it: every `OK` names a file that is complete.
//!
//! Two differences from the reference are left, and pinned as such: it
//! prints `Program aborted` and stops at the failed member, where the
//! concurrent walk has already decoded, closed and verified members after
//! it (their `OK` is true, and the files are whole); and its second
//! stderr line is an unrelated errno, where rarkit prints the real reason.
//!
//! **Why the limit is set in a child shell.** The workspace denies
//! `unsafe`, so `setrlimit` is not open to this crate (`descriptors.rs`
//! says the same). `trap '' XFSZ` makes an over-limit write fail with
//! `EFBIG` instead of killing the process, and `ulimit -f` sets the
//! limit; both survive the `exec`. `ulimit -f` counts 512-byte blocks in
//! a POSIX shell and 1024-byte blocks in plain bash, so the limit is
//! 2,048,000 or 4,096,000 bytes, and the payload is sized to fail under
//! either: every member but one is far below it and that one is above
//! both.
//!
//! Every archive here is written by rarfast itself, so no reference
//! binary is needed.

// Unix only by its nature: the write is cut short by `ulimit -f` in a Unix
// shell.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-walkerr-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `ulimit -f` in blocks: see the module comment for why this one figure
/// sits between the small members and the large one in either unit.
const LIMIT_BLOCKS: u32 = 4000;

/// The members, in archive order, and the one larger than the limit.
const MEMBERS: usize = 12;
const LARGE: usize = 6;

fn name(index: usize) -> String {
    format!("f{index:02}.bin")
}

fn payload(index: usize) -> Vec<u8> {
    let len = if index == LARGE { 8 << 20 } else { 256 << 10 };
    rarkit_testdata::chatter(index as u64 + 1, len)
}

/// Writes the twelve members and archives them with rarfast.
fn archive(dir: &Path, solid: bool) {
    let mut args = vec!["a", "-idq", "-m1", "-ep"];
    if solid {
        args.push("-s");
    }
    args.push("arc.rar");
    let names: Vec<String> = (0..MEMBERS).map(name).collect();
    for (index, member) in names.iter().enumerate() {
        std::fs::write(dir.join(member), payload(index)).unwrap();
    }
    args.extend(names.iter().map(String::as_str));
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(&args)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "building the archive: {out:?}");
    for member in &names {
        std::fs::remove_file(dir.join(member)).unwrap();
    }
}

/// `rarfast <args>` in `dir` under the file size limit: exit code, stdout
/// with the progress redraws taken out, stderr.
fn run_limited(dir: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new("/bin/sh")
        .current_dir(dir)
        .arg("-c")
        .arg(format!(
            "trap '' XFSZ; ulimit -f {LIMIT_BLOCKS} || exit 99; exec \"$0\" \"$@\""
        ))
        .arg(rarfast())
        .args(args)
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(99), "the shell refused the limit");
    let stdout = String::from_utf8_lossy(&out.stdout).replace('\u{8}', "");
    (
        out.status.code(),
        stdout,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The member a progress line names and whether it ends in `OK`.
fn member_lines(stdout: &str) -> Vec<(String, bool)> {
    stdout
        .lines()
        .filter(|line| line.starts_with("Extracting  "))
        .filter_map(|line| {
            let named = line.split_whitespace().nth(1)?;
            let member = named.rsplit('/').next()?.to_owned();
            Some((member, line.trim_end().ends_with("OK")))
        })
        .collect()
}

/// One row: extract under the limit, then check what the reference does.
fn row(solid: bool, width: Option<&str>, keep_broken: bool) {
    let tag = format!(
        "{}-{}-{}",
        if solid { "solid" } else { "plain" },
        width.unwrap_or("default").trim_start_matches('-'),
        if keep_broken { "kb" } else { "nokb" }
    );
    let dir = work(&tag);
    archive(&dir, solid);
    let mut args = vec!["x", "-y"];
    if keep_broken {
        args.push("-kb");
    }
    args.extend(width);
    args.extend(["arc.rar", "out/"]);
    let (code, stdout, stderr) = run_limited(&dir, &args);
    let said = format!("{tag}: exit {code:?}\nstdout {stdout}\nstderr {stderr}");

    // THE DEFECT: the member whose write failed was reported OK.
    let lines = member_lines(&stdout);
    let large = name(LARGE);
    assert!(
        lines.iter().any(|(member, _)| *member == large),
        "{said}\nno line for {large}"
    );
    assert!(
        !lines.iter().any(|(member, ok)| *member == large && *ok),
        "{said}\n{large} was reported OK"
    );
    // The property underneath: every OK names a whole file.
    for (member, ok) in &lines {
        if !ok {
            continue;
        }
        let index: usize = member[1..3].parse().unwrap();
        assert_eq!(
            std::fs::read(dir.join("out").join(member)).ok(),
            Some(payload(index)),
            "{said}\n{member} was reported OK and is not whole"
        );
    }
    // Every member before the failed one is whole on both paths.
    for index in 0..LARGE {
        assert_eq!(
            std::fs::read(dir.join("out").join(name(index))).ok(),
            Some(payload(index)),
            "{said}\n{} is not whole",
            name(index)
        );
    }
    // The reference's words, its exit class, and no verdict of success.
    assert!(
        stderr.contains(&format!("Write error in the file out/{large}")),
        "{said}"
    );
    assert_eq!(code, Some(5), "{said}");
    assert!(!stdout.contains("All OK"), "{said}");
    // The partial file: removed, unless `-kb` asked to keep it.
    let partial = std::fs::metadata(dir.join("out").join(&large)).ok();
    if keep_broken {
        let kept = partial.unwrap_or_else(|| panic!("{said}\n-kb lost the partial file"));
        assert!(kept.len() < payload(LARGE).len() as u64, "{said}");
    } else {
        assert!(partial.is_none(), "{said}\nthe partial file was kept");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The concurrent path at the default width, and at an explicit `-mt4`
/// so a box whose default resolves narrower still runs it wide.
#[test]
fn a_failed_write_is_not_ok_on_the_concurrent_path() {
    for keep_broken in [false, true] {
        row(false, None, keep_broken);
        row(false, Some("-mt4"), keep_broken);
    }
}

/// The sequential path: `-mt1`, and a solid set at any width.
#[test]
fn a_failed_write_is_not_ok_on_the_sequential_path() {
    for keep_broken in [false, true] {
        row(false, Some("-mt1"), keep_broken);
        row(true, None, keep_broken);
        row(true, Some("-mt1"), keep_broken);
    }
}
