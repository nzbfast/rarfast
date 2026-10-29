//! An extract that takes the IN-ORDER walk holds no more decoded ahead of
//! the file being written than its ceiling on admission (1,024 MiB),
//! read from OUTSIDE the process as its peak (SPEC-API 8.4.1's measure:
//! `phys_footprint` on macOS, the child's maximum resident set on Linux).
//!
//! Found 10 Oct 2026: such a run took members ahead up to the working
//! limit, which on a machine of 64 GB is 16 GiB, and so held every member
//! of an ordinary set decoded in front of its writer: six 320 MiB
//! members, 1,277 to 1,847 MB. Two runs take that walk at any width: one
//! that may have to ASK about a file already there, and one over members
//! that cannot go to the pool.
//!
//! THE SHAPE: eight members of 256 MiB that pack about two to one (every
//! other mebibyte is one 4 KiB block repeated), each beside a small
//! file: 2 GiB in all, twice the ceiling. Unbounded the process peaks
//! near the whole set; bounded, at the ceiling and the workers' windows.
//! The ceiling asserted is 1,500 MiB, between the two.
//!
//! `#[ignore]`d for its size and its encode time: `cargo test --release
//! -p rarkit-cli --test ahead_peak -- --ignored`. It needs a machine
//! whose working limit is above 2 GiB (8 GB of memory or more, no `-mm`,
//! no cap under that), 2.5 GiB of memory and 5 GiB of disk; every row
//! states `-mt24`, which starts at most eight worker threads here (one a
//! member in flight). Its own test binary, so no other test's child
//! shares the measurement.

// Linux and macOS only by its nature: the peak is read from `wait4`'s
// resource usage, or by macOS's `time -l`.
#![cfg(any(target_os = "linux", target_os = "macos"))]
#![allow(unsafe_code)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const MIB: u64 = 1 << 20;
const MEMBERS: usize = 8;
const EACH: usize = 256 << 20;
/// What a bounded run stays under, and an unbounded one passes.
const CEILING: u64 = 1500 * MIB;

/// Bytes that pack about two to one: a mebibyte with no structure, then a
/// mebibyte of one 4 KiB block repeated, and so on.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut word = || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes()
    };
    let mut out = Vec::with_capacity(len + (1 << 20));
    let mut plain = true;
    while out.len() < len {
        if plain {
            for _ in 0..(1 << 20) / 8 {
                out.extend_from_slice(&word());
            }
        } else {
            let block: Vec<u8> = (0..4096 / 8).flat_map(|_| word()).collect();
            for _ in 0..256 {
                out.extend_from_slice(&block);
            }
        }
        plain = !plain;
    }
    out.truncate(len);
    out
}

/// Run rarfast with `args` in `dir` and `answer` on its standard input:
/// what it said and the process's peak in bytes.
fn run(dir: &Path, args: &[&str], answer: &str) -> (Output, u64) {
    let mut command = if cfg!(target_os = "macos") {
        let mut command = Command::new("/usr/bin/time");
        command.arg("-l").arg(env!("CARGO_BIN_EXE_rarfast"));
        command
    } else {
        Command::new(env!("CARGO_BIN_EXE_rarfast"))
    };
    let mut child = command
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(answer.as_bytes())
        .unwrap();
    if cfg!(target_os = "macos") {
        let done = child.wait_with_output().unwrap();
        let text = String::from_utf8_lossy(&done.stderr).to_string();
        let footprint = text
            .lines()
            .find(|l| l.contains("peak memory footprint"))
            .and_then(|l| l.split_whitespace().next())
            .and_then(|n| n.parse::<u64>().ok())
            .expect("a peak footprint line");
        (done, footprint)
    } else {
        let pid = child.id() as libc::pid_t;
        wait_with_rusage(child, pid)
    }
}

fn wait_with_rusage(mut child: std::process::Child, pid: libc::pid_t) -> (Output, u64) {
    use std::io::Read;
    // What these runs say is a few hundred bytes, far under a pipe's
    // room, so reading one stream to its end and then the other cannot
    // leave the child waiting on the second.
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        out.read_to_end(&mut stdout).unwrap();
    }
    if let Some(mut err) = child.stderr.take() {
        err.read_to_end(&mut stderr).unwrap();
    }
    let mut status: libc::c_int = 0;
    // SAFETY: `rusage` is plain integers and timevals, all zeroes valid.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `pid` is this child, not yet waited for; `status` and
    // `usage` are live and writable, and wait4 writes only inside them.
    let rc = unsafe { libc::wait4(pid, &mut status, 0, &mut usage) };
    assert_eq!(rc, pid, "wait4");
    use std::os::unix::process::ExitStatusExt;
    let status = std::process::ExitStatus::from_raw(status);
    // Linux reports ru_maxrss in KiB.
    let peak = u64::try_from(usage.ru_maxrss).unwrap() * 1024;
    (
        Output {
            status,
            stdout,
            stderr,
        },
        peak,
    )
}

/// Member `i`'s bytes.
fn body(i: usize) -> Vec<u8> {
    noise(EACH, 0x2026_1010 + i as u64)
}

/// The set of many members in `dir/src`, archived as `dir/subset.rar`.
///
/// NOTHING OF IT IS KEPT in this process: on Linux a child's maximum
/// resident set starts from what its parent held when it was started, so
/// a test holding 144 MiB of members read 290 MiB for every child,
/// whatever the child did (counted on x86-64 Linux, 11 Oct 2026). Each
/// member is made again when it is compared.
fn many(dir: &Path) {
    for i in 0..MEMBERS {
        let folder = dir.join("src").join(format!("s{i}"));
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join(format!("element{i}.bin")), body(i)).unwrap();
        std::fs::write(folder.join("info.nfo"), format!("folder {i}\n")).unwrap();
    }
    let (made, _) = run(
        &dir.join("src"),
        &["a", "-m3", "-r", "-y", "-idq", "../subset.rar", "."],
        "",
    );
    assert!(made.status.success(), "{made:?}");
}

fn said(done: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&done.stdout),
        String::from_utf8_lossy(&done.stderr)
    )
}

/// `x` with the default rule and ONE small file already there may have to
/// ask, so it takes the in-order walk: answered `A`, every member is
/// written whole and the process stays under the ceiling at `-mt24`.
#[test]
#[ignore = "2 GiB of members: run in release with --ignored"]
fn an_extract_that_may_ask_holds_no_more_than_its_ceiling() {
    let dir = std::env::temp_dir().join(format!("rarkit-ahead-hold-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    many(&dir);
    let out = dir.join("out");
    // The LAST folder's small file stands, so every large member is
    // written before the question is reached.
    let last = MEMBERS - 1;
    std::fs::create_dir_all(out.join(format!("s{last}"))).unwrap();
    std::fs::write(out.join(format!("s{last}/info.nfo")), "standing\n").unwrap();
    let (done, peak) = run(&out, &["x", "-mt24", "../subset.rar"], "A\n");
    assert!(done.status.success(), "{}", said(&done));
    for i in 0..MEMBERS {
        let got = std::fs::read(out.join(format!("s{i}/element{i}.bin"))).unwrap();
        assert!(got == body(i), "member {i} differs");
    }
    assert_eq!(
        std::fs::read(out.join(format!("s{last}/info.nfo"))).unwrap(),
        format!("folder {last}\n").as_bytes()
    );
    eprintln!("x that may ask, -mt24: process peak {} MiB", peak / MIB);
    assert!(
        peak < CEILING,
        "the process peaked at {} MiB: the look-ahead passed its ceiling",
        peak / MIB
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `e` writes every folder's small file to ONE file. Whichever walk such a
/// run takes for it, the members are whole, the last folder's small file
/// stands and the process stays under the ceiling at `-mt24`.
#[test]
#[ignore = "2 GiB of members: run in release with --ignored"]
fn an_extract_of_members_sharing_a_file_holds_no_more_than_its_ceiling() {
    let dir = std::env::temp_dir().join(format!("rarkit-ahead-hold-e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    many(&dir);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let (done, peak) = run(&out, &["e", "-o+", "-mt24", "../subset.rar"], "");
    assert!(done.status.success(), "{}", said(&done));
    for i in 0..MEMBERS {
        let got = std::fs::read(out.join(format!("element{i}.bin"))).unwrap();
        assert!(got == body(i), "member {i} differs");
    }
    // The file one thread leaves.
    let one = dir.join("one");
    std::fs::create_dir_all(&one).unwrap();
    let (done, _) = run(&one, &["e", "-o+", "-mt1", "../subset.rar"], "");
    assert!(done.status.success(), "{}", said(&done));
    assert_eq!(
        std::fs::read(out.join("info.nfo")).unwrap(),
        std::fs::read(one.join("info.nfo")).unwrap()
    );
    eprintln!(
        "e of members sharing a file, -mt24: process peak {} MiB",
        peak / MIB
    );
    assert!(
        peak < CEILING,
        "the process peaked at {} MiB: the look-ahead passed its ceiling",
        peak / MIB
    );
    let _ = std::fs::remove_dir_all(&dir);
}
