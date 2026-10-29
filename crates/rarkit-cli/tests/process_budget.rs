//! The whole-process budget from OUTSIDE the process (SPEC-API 8.4.1): under a
//! stated `-mm` the rarfast PROCESS peaks at or under the budget, read as
//! the child's maximum resident set on Linux and its `phys_footprint` on
//! macOS; below the archive's one-member floor the run is
//! refused before any member, naming working memory, non-zero, no `OK`.
//!
//! Its own test binary, so no other test's child shares the measurement.

// Linux and macOS only by its nature: the peak is read from `wait4`'s resource usage.
#![cfg(any(target_os = "linux", target_os = "macos"))]
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const MIB: u64 = 1 << 20;

fn body(bytes: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 64);
    let mut seed = seed;
    while out.len() < bytes {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.extend_from_slice(format!("{:016x} ", seed >> 24).as_bytes());
        out.extend_from_slice(b"the whole process answers to the budget ");
        for _ in 0..8 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            out.extend_from_slice(&seed.to_le_bytes());
        }
    }
    out.truncate(bytes);
    out
}

/// Sixteen members of 3 MiB and one of 6 MiB, written by rarfast at -m1.
fn fixture(dir: &Path) -> PathBuf {
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    for i in 0..17u64 {
        let size = if i == 16 { 6 << 20 } else { 3 << 20 };
        std::fs::write(src.join(format!("m{i}.dat")), body(size, 0x2026_0929 + i)).unwrap();
    }
    let archive = dir.join("fixture.rar");
    let done = Command::new(env!("CARGO_BIN_EXE_rarfast"))
        .current_dir(&src)
        .args(["a", "-m1", "-md32m", "-y", "-idq"])
        .arg(&archive)
        .args((0..17).map(|i| format!("m{i}.dat")))
        .output()
        .unwrap();
    assert!(done.status.success(), "{done:?}");
    archive
}

/// Run `rarfast t` over `archive` with `budget` (None: the default) and
/// return what it said with the process's peak in bytes.
fn run(archive: &Path, budget: Option<u64>) -> (Output, u64) {
    let mut args: Vec<String> = vec!["t".into(), "-y".into()];
    if let Some(bytes) = budget {
        args.push(format!("-mm{}k", bytes / 1024));
    }
    args.push(archive.display().to_string());
    if cfg!(target_os = "macos") {
        let done = Command::new("/usr/bin/time")
            .arg("-l")
            .arg(env!("CARGO_BIN_EXE_rarfast"))
            .args(&args)
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
            .args(&args)
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

#[test]
fn a_stated_budget_bounds_the_process_and_below_the_floor_is_refused_up_front() {
    let dir = std::env::temp_dir().join(format!("rarkit-process-budget-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let archive = fixture(&dir);

    // The smallest budget the run accepts, in 1 MiB steps from the headroom.
    let floor = (32..=512u64)
        .map(|m| m * MIB)
        .find(|&budget| run(&archive, Some(budget)).0.status.success())
        .expect("some budget reads it");

    // Under it: refused before any member, naming working memory.
    let (under, _) = run(&archive, Some(floor - MIB));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&under.stdout),
        String::from_utf8_lossy(&under.stderr)
    );
    assert!(!under.status.success(), "refused but exit 0\n{text}");
    assert!(text.contains("WorkingMemory wanted"), "{text}");
    assert!(
        String::from_utf8_lossy(&under.stdout)
            .lines()
            .all(|l| !l.contains("OK")),
        "an OK beside the refusal\n{text}"
    );

    // At the floor and above it, and at the default: the process's own peak
    // is at or under the budget.
    for budget in [floor, floor + 4 * MIB, 128 * MIB] {
        let (done, peak) = run(&archive, Some(budget));
        assert!(done.status.success(), "{done:?}");
        eprintln!("-mm {} MiB: process peak {} bytes", budget / MIB, peak);
        assert!(
            peak <= budget,
            "-mm {} MiB: the process peaked at {peak} bytes",
            budget / MIB
        );
    }
    let (done, peak) = run(&archive, None);
    assert!(done.status.success(), "{done:?}");
    assert!(peak <= 512 * MIB, "the default run peaked at {peak} bytes");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Sixty-four members of 1 to 8 MiB, each one seeded 64 KiB block repeated,
/// written by rarfast at -m1: many rings of many sizes, read through the
/// concurrent path (`t` on a non-solid set).
fn fixture_of_many(dir: &Path) -> PathBuf {
    let src = dir.join("many");
    std::fs::create_dir_all(&src).unwrap();
    let mut seed = 0x2026_0929_u64;
    let mut next = || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        seed >> 16
    };
    for i in 0..64 {
        let size = (1 << 20) + (next() % (7 << 20)) as usize;
        let block: Vec<u8> = (0..65536).map(|_| next() as u8).collect();
        let body: Vec<u8> = block.iter().copied().cycle().take(size).collect();
        std::fs::write(src.join(format!("m{i:02}.dat")), body).unwrap();
    }
    let archive = dir.join("many.rar");
    let done = Command::new(env!("CARGO_BIN_EXE_rarfast"))
        .current_dir(&src)
        .args(["a", "-m1", "-md32m", "-y", "-idq"])
        .arg(&archive)
        .args((0..64).map(|i| format!("m{i:02}.dat")))
        .output()
        .unwrap();
    assert!(done.status.success(), "{done:?}");
    archive
}

/// The concurrent path's workers give their dropped rings back under a
/// stated budget. Before they did, a ring freed into the allocator's cache
/// stayed resident: in a release build this fixture's process peaked 7 to
/// 12 MiB over every budget from 48 to 128 MiB on an aarch64 Mac
/// (footprint). A debug build decodes slowly enough that the cache stays
/// under the budget itself, so on macOS the test holds the process to the
/// ENGINE's share, the budget less `MemoryPolicy::PROCESS_HEADROOM` (measured in debug:
/// 19 and 39 MiB with the rings given back, 46 and 76 MiB without, against
/// 32 and 64). On Linux the resident set also carries the debug binary's
/// own pages, so there it holds to the budget as stated.
#[test]
fn many_rings_of_many_sizes_stay_under_a_stated_budget() {
    let dir = std::env::temp_dir().join(format!("rarkit-process-many-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let archive = fixture_of_many(&dir);
    for budget in [64 * MIB, 96 * MIB] {
        let (done, peak) = run(&archive, Some(budget));
        assert!(done.status.success(), "{done:?}");
        eprintln!("-mm {} MiB: process peak {} bytes", budget / MIB, peak);
        let bound = if cfg!(target_os = "macos") {
            budget - rarkit::MemoryPolicy::PROCESS_HEADROOM
        } else {
            budget
        };
        assert!(
            peak <= bound,
            "-mm {} MiB: the process peaked at {peak} bytes, over {bound}",
            budget / MIB
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
