//! Spec G 3.5's held-member rule (of 30 Sep 2026)
//! from OUTSIDE the process, acceptance test 1 at S8's shape: a solid
//! `rarfast a -s -m1`, `-m3` and `-m5` of one incompressible member of 360
//! MB, with no `-mm`, STREAMS it, and the process peaks under
//! 512 MiB (SPEC-API 8.4.1's measure: `phys_footprint` on macOS,
//! the child's maximum resident set on Linux). Before the rule the
//! member's packed bound alone (under 512 MiB) was compared with
//! `DEFAULT_LIMIT`, and it was held at 746 to 826 MiB of process peak.
//! The archive passes reference `unrar t` where one is on the PATH, and
//! extracts to the input.
//!
//! `#[ignore]`d for its encode time: `cargo test --release -p rarkit-cli
//! --test held_member_process_peak -- --ignored`. Its own test binary, so
//! no other test's child shares the measurement.

// Linux and macOS only by its nature: the peak is read from `wait4`'s resource usage.
#![cfg(any(target_os = "linux", target_os = "macos"))]
#![allow(unsafe_code)]

use std::path::Path;
use std::process::{Command, Output};

const MIB: u64 = 1 << 20;

/// Bytes with no structure, as S8's video is to a compressor.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.extend_from_slice(&state.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Run rarfast with `args` in `dir`, answering what it said and the
/// process's peak in bytes.
fn run(dir: &Path, args: &[&str]) -> (Output, u64) {
    if cfg!(target_os = "macos") {
        let done = Command::new("/usr/bin/time")
            .current_dir(dir)
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
            .current_dir(dir)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;
        wait_with_rusage(child, pid)
    }
}

fn wait_with_rusage(mut child: std::process::Child, pid: libc::pid_t) -> (Output, u64) {
    use std::io::Read;
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

#[test]
#[ignore = "360 MB at three levels: run in release with --ignored"]
fn s8_shape_member_streams_under_the_process_ceiling() {
    let dir = std::env::temp_dir().join(format!("rarkit-held-member-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let data = noise(360_000_000, 0x2026_0930);
    std::fs::write(dir.join("video.bin"), &data).unwrap();
    for level in ["-m1", "-m3", "-m5"] {
        let archive = format!("s8{level}.rar");
        let (made, peak) = run(
            &dir,
            &["a", "-s", level, "-y", "-idq", &archive, "video.bin"],
        );
        assert!(made.status.success(), "{level}: {made:?}");
        assert!(
            peak < 512 * MIB,
            "{level}: the process peaked at {} MiB",
            peak / MIB
        );
        eprintln!("{level}: process peak {} MiB", peak / MIB);
        if let Ok(tested) = Command::new("unrar")
            .current_dir(&dir)
            .args(["t", &archive])
            .output()
        {
            let out = String::from_utf8_lossy(&tested.stdout);
            let err = String::from_utf8_lossy(&tested.stderr);
            assert!(
                tested.status.success() && out.contains("All OK") && err.trim().is_empty(),
                "{level}: unrar t: {out} {err}"
            );
        }
        let into = dir.join(format!("x{level}"));
        std::fs::create_dir_all(&into).unwrap();
        let (extracted, _) = run(&into, &["x", "-y", "-idq", &format!("../{archive}")]);
        assert!(extracted.status.success(), "{level}: {extracted:?}");
        assert!(
            std::fs::read(into.join("video.bin")).unwrap() == data,
            "{level}: extracted bytes differ"
        );
        std::fs::remove_dir_all(&into).unwrap();
        std::fs::remove_file(dir.join(&archive)).unwrap();
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
