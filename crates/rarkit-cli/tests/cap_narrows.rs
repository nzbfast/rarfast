//! A reader under a stated cap NARROWS BEFORE IT REFUSES (SPEC-API 8.4.1):
//! the account for one decoded member is one window and the fixed part
//! at a width of one, so a member whose window fits the cap that way is
//! read, at the widest arrangement that fits, and only a member whose
//! account at one does not fit is refused.
//!
//! Seen from OUTSIDE the process: `-mm` is the whole process's budget,
//! and the process's own peak (the child's maximum resident set on
//! Linux, its `phys_footprint` on macOS) is at or under it at every
//! width asked for.
//!
//! | archive | window | cap | before | now |
//! |---|---|---|---|---|
//! | 16 MiB member, `-md16m` | 16 MiB | `-mm64m` | refused | read |
//! | 64 MiB member, `-md64m` | 64 MiB | `-mm128m` | refused | read |
//! | 128 MiB member, `-md128m` | 128 MiB | `-mm64m` | refused | refused |
//!
//! Its own test binary, so no other test's child shares the measurement.

// Linux and macOS only by its nature: the peak is read from `wait4`'s resource usage.
#![cfg(any(target_os = "linux", target_os = "macos"))]
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const MIB: u64 = 1 << 20;

/// Write `bytes` bytes of text and noise to `path`, a megabyte at a time.
///
/// Nothing of the member is kept in this process: on Linux a child's
/// maximum resident set starts from what its parent held when it was
/// started, so a test that held the member would measure itself.
fn write_body(path: &Path, bytes: u64, seed: u64) {
    use std::io::Write;
    let mut file = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    let mut piece = Vec::with_capacity(256);
    let (mut seed, mut left) = (seed, bytes);
    while left > 0 {
        piece.clear();
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        piece.extend_from_slice(format!("{:016x} ", seed >> 24).as_bytes());
        piece.extend_from_slice(b"a reader under a cap narrows before it refuses ");
        for _ in 0..8 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            piece.extend_from_slice(&seed.to_le_bytes());
        }
        let take = (piece.len() as u64).min(left) as usize;
        file.write_all(&piece[..take]).unwrap();
        left -= take as u64;
    }
    file.flush().unwrap();
}

/// Whether two files hold the same bytes, read a megabyte at a time.
fn same_bytes(a: &Path, b: &Path) -> bool {
    use std::io::Read;
    let (mut a, mut b) = (
        std::fs::File::open(a).unwrap(),
        std::fs::File::open(b).unwrap(),
    );
    let (mut x, mut y) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
    loop {
        let n = a.read(&mut x).unwrap();
        let mut m = 0;
        while m < n {
            match b.read(&mut y[m..n]).unwrap() {
                0 => return false,
                got => m += got,
            }
        }
        if n == 0 {
            return b.read(&mut y[..1]).unwrap() == 0;
        }
        if x[..n] != y[..n] {
            return false;
        }
    }
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarkit-cap-narrows-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One member of `mib` MiB written by rarfast at `-m1` with a dictionary
/// of the same size, so the member's window is `mib` MiB: the archive
/// and a file of the bytes it was made from.
fn fixture(dir: &Path, mib: u64) -> (PathBuf, PathBuf) {
    write_body(&dir.join("member.dat"), mib * MIB, 0x2026_1012 + mib);
    let archive = dir.join(format!("window{mib}m.rar"));
    let done = Command::new(env!("CARGO_BIN_EXE_rarfast"))
        .current_dir(dir)
        .args(["a", "-m1", "-y", "-idq"])
        .arg(format!("-md{mib}m"))
        .arg(&archive)
        .arg("member.dat")
        .output()
        .unwrap();
    assert!(done.status.success(), "{done:?}");
    let made_from = dir.join("member.src");
    std::fs::rename(dir.join("member.dat"), &made_from).unwrap();
    (archive, made_from)
}

/// Run `rarfast <args>` and return what it said with the process's peak
/// in bytes.
fn run(args: &[String]) -> (Output, u64) {
    if cfg!(target_os = "macos") {
        let done = Command::new("/usr/bin/time")
            .arg("-l")
            .arg(env!("CARGO_BIN_EXE_rarfast"))
            .args(args)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&done.stderr).to_string();
        let footprint = text
            .lines()
            .find(|l| l.contains("peak memory footprint"))
            .and_then(|l| l.split_whitespace().next())
            .and_then(|n| n.parse::<u64>().ok())
            .expect("a peak footprint line");
        (done, footprint)
    } else {
        let child = Command::new(env!("CARGO_BIN_EXE_rarfast"))
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;
        child.wait_with_output_and_rusage(pid)
    }
}

trait WaitRusage {
    fn wait_with_output_and_rusage(self, pid: libc::pid_t) -> (Output, u64);
}

impl WaitRusage for std::process::Child {
    fn wait_with_output_and_rusage(mut self, pid: libc::pid_t) -> (Output, u64) {
        use std::io::Read;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        if let Some(mut out) = self.stdout.take() {
            out.read_to_end(&mut stdout).unwrap();
        }
        if let Some(mut err) = self.stderr.take() {
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
}

fn said(done: &Output) -> String {
    format!(
        "exit {:?}\nstdout:\n{}\nstderr:\n{}",
        done.status.code(),
        String::from_utf8_lossy(&done.stdout),
        String::from_utf8_lossy(&done.stderr)
    )
}

/// `cmd` over `archive` under `-mm<cap>m` at `width` (empty: the default
/// width), into `dest` for an `x`.
fn capped(cmd: &str, archive: &Path, cap: u64, width: &str, dest: Option<&Path>) -> (Output, u64) {
    let mut args: Vec<String> = vec![cmd.into(), "-y".into(), format!("-mm{cap}m")];
    if !width.is_empty() {
        args.push(width.into());
    }
    args.push(archive.display().to_string());
    if let Some(dest) = dest {
        args.push(format!("{}/", dest.display()));
    }
    run(&args)
}

/// A window one width holds under the cap is read, by `t` and by `x`, at
/// the default width, at one thread and at a named eight; the bytes are
/// the member's whatever the width, and the process never passes the cap.
#[test]
fn a_window_that_fits_at_a_width_of_one_is_read_under_the_cap() {
    for (window, cap) in [(16u64, 64u64), (64, 128)] {
        let dir = work(&format!("fits{window}"));
        let (archive, data) = fixture(&dir, window);
        for width in ["", "-mt1", "-mt8"] {
            let what = format!("{window} MiB window under -mm{cap}m {width}");
            let began = std::time::Instant::now();
            let (done, peak) = capped("t", &archive, cap, width, None);
            let wall = began.elapsed().as_secs_f64();
            assert!(done.status.success(), "t {what}: {}", said(&done));
            eprintln!("t {what}: wall {wall:.3} s, process peak {peak} bytes");
            assert!(peak <= cap * MIB, "t {what}: the process peaked at {peak}");

            let out = dir.join("out");
            let began = std::time::Instant::now();
            let (done, peak) = capped("x", &archive, cap, width, Some(&out));
            let wall = began.elapsed().as_secs_f64();
            assert!(done.status.success(), "x {what}: {}", said(&done));
            eprintln!("x {what}: wall {wall:.3} s, process peak {peak} bytes");
            assert!(peak <= cap * MIB, "x {what}: the process peaked at {peak}");
            assert!(
                same_bytes(&out.join("member.dat"), &data),
                "x {what}: the bytes are not the member's"
            );
            std::fs::remove_dir_all(&out).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A window no width holds under the cap is refused as it always was:
/// exit 2, working memory named, no `OK`, no member file.
#[test]
fn a_window_that_does_not_fit_at_a_width_of_one_is_still_refused() {
    let dir = work("refused");
    let (archive, _data) = fixture(&dir, 128);
    for width in ["", "-mt1", "-mt8"] {
        let what = format!("128 MiB window under -mm64m {width}");
        let out = dir.join("out");
        for (cmd, dest) in [("t", None), ("x", Some(out.as_path()))] {
            let (done, _peak) = capped(cmd, &archive, 64, width, dest);
            let text = said(&done);
            assert_eq!(done.status.code(), Some(2), "{cmd} {what}: {text}");
            assert!(
                text.contains("WorkingMemory wanted"),
                "{cmd} {what}: no named working-memory refusal\n{text}"
            );
            assert!(
                String::from_utf8_lossy(&done.stdout)
                    .lines()
                    .all(|l| !l.contains("OK")),
                "{cmd} {what}: an OK beside the refusal\n{text}"
            );
        }
        assert!(
            !out.join("member.dat").exists(),
            "x {what}: a member file left behind"
        );
        let _ = std::fs::remove_dir_all(&out);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

const NARROWED: &str =
    "ran at 1 thread, not the 8 asked for: the memory limit leaves room for no more";

/// How many lines of what `done` wrote to standard error are the note.
fn notes(done: &Output) -> usize {
    String::from_utf8_lossy(&done.stderr)
        .lines()
        .filter(|l| l.contains("asked for: the memory limit"))
        .count()
}

/// SPEC-CLI 14: a width the user NAMED that the memory limit narrowed is
/// said in one line on standard error, and only then: not for the
/// default width, not without a limit, not for a width the limit holds,
/// and not under `-inul`. The exit and standard output are what they are
/// without it.
#[test]
fn a_named_width_the_limit_narrowed_is_said_in_one_line() {
    let dir = work("line");
    let (archive, _made_from) = fixture(&dir, 16);
    let run_t = |switches: &[&str]| {
        let mut args: Vec<String> = vec!["t".into(), "-y".into()];
        args.extend(switches.iter().map(|s| (*s).to_string()));
        args.push(archive.display().to_string());
        run(&args).0
    };

    let said_once = run_t(&["-mm64m", "-mt8"]);
    assert!(said_once.status.success(), "{}", said(&said_once));
    assert!(
        String::from_utf8_lossy(&said_once.stderr)
            .lines()
            .any(|l| l == NARROWED),
        "no line for a named width narrowed: {}",
        said(&said_once)
    );
    assert_eq!(notes(&said_once), 1, "{}", said(&said_once));
    assert!(
        !String::from_utf8_lossy(&said_once.stdout).contains("asked for"),
        "the note is on standard output: {}",
        said(&said_once)
    );

    // `-idq` does not suppress a statement about what the user asked for.
    let quiet = run_t(&["-mm64m", "-mt8", "-idq"]);
    assert!(quiet.status.success(), "{}", said(&quiet));
    assert_eq!(notes(&quiet), 1, "{}", said(&quiet));

    for silent in [
        &["-mm64m", "-mt8", "-inul"][..],
        &["-mm64m"][..],
        &["-mt8"][..],
        &["-mm64m", "-mt1"][..],
        &["-mm1g", "-mt8"][..],
    ] {
        let done = run_t(silent);
        assert!(done.status.success(), "{silent:?}: {}", said(&done));
        assert_eq!(notes(&done), 0, "{silent:?}: {}", said(&done));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Restate the first block of `archive`'s one member, in place, to
/// declare 4,194,303 bytes of payload (three size bytes, the header's
/// check made to hold): a block no genuine writer makes, and under what
/// the member packs to, so it is not cut short by the member's own end.
/// The file is patched where it lies, so the test holds none of it.
fn restate_the_first_block(archive: &Path) {
    use std::io::{Read, Seek, SeekFrom, Write};
    let at = {
        let source: std::sync::Arc<dyn rarkit::RangeSource> =
            std::sync::Arc::new(std::fs::File::open(archive).unwrap());
        rarkit::Archive::open(source, &rarkit::ReadOptions::default())
            .unwrap()
            .members()
            .find(|m| !m.is_directory)
            .unwrap()
            .data
            .start
    };
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(archive)
        .unwrap();
    let mut flags = [0u8; 1];
    file.seek(SeekFrom::Start(at)).unwrap();
    file.read_exact(&mut flags).unwrap();
    let flags = (flags[0] & !0x18) | (2 << 3);
    file.seek(SeekFrom::Start(at)).unwrap();
    let size = [0xff, 0xff, 0x3f];
    file.write_all(&[
        flags,
        0x5a ^ flags ^ size[0] ^ size[1] ^ size[2],
        size[0],
        size[1],
        size[2],
    ])
    .unwrap();
}

/// SPEC-API 8.4.1, the account's item 7, from outside the process: a
/// member whose window fits the cap is begun, and a block whose packed
/// bytes the cap does not hold beside that window is refused at the
/// block. The tool names the block buffer, exits non-zero, says no `OK`
/// and leaves no file at the member's name. The cap is `-mm52m`: the
/// process's 32 MiB of headroom, the 16 MiB window, and under 3 MiB
/// beside it, which a block of 4 MiB does not fit.
#[test]
fn a_block_the_cap_does_not_hold_is_refused_and_the_file_withheld() {
    let dir = work("block");
    let (archive, _made_from) = fixture(&dir, 16);
    restate_the_first_block(&archive);
    for width in ["", "-mt1", "-mt8"] {
        let what = format!("a 4 MiB block under -mm52m {width}");
        let out = dir.join("out");
        for (cmd, dest) in [("t", None), ("x", Some(out.as_path()))] {
            let (done, _peak) = capped(cmd, &archive, 52, width, dest);
            let text = said(&done);
            assert!(!done.status.success(), "{cmd} {what}: exit 0\n{text}");
            assert!(
                text.contains("BlockBuffer wanted"),
                "{cmd} {what}: the block buffer is not named\n{text}"
            );
            assert!(
                String::from_utf8_lossy(&done.stdout)
                    .lines()
                    .all(|l| !l.contains("OK") || l.starts_with("Creating")),
                "{cmd} {what}: an OK beside the refusal\n{text}"
            );
        }
        assert!(
            !out.join("member.dat").exists(),
            "x {what}: a file left at the member's name"
        );
        let _ = std::fs::remove_dir_all(&out);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
