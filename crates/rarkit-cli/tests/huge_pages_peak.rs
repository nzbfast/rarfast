//! The encoder's huge page advice (`rarkit`'s `pages` module, 1 Oct 2026)
//! from OUTSIDE the process: `rarfast a` of a set of many small members
//! and one large one writes the SAME archive with the advice on, with the
//! encoder's part off (`RARKIT_HUGE_PAGES=ring`) and with all of it off
//! (`=0`), at levels 1, 3 and 5 and solid; and on Linux the process's
//! peak with the advice on stays within the rounding it can cost of the
//! peak without.
//!
//! **Why the set is small members.** A huge page rounds what a table has
//! touched up to 2 MiB, so the tables that are touched sparsely are where
//! the advice could cost memory: a short member's links and the heads its
//! few positions hash to. Tables written whole (the tree's slots, the
//! hints) round nothing.
//!
//! **Why it passes where there are no huge pages.** Transparent huge
//! pages may be off on the box that runs it (`never`, a container, any
//! target but Linux): the advice is then refused or compiled out, both
//! arms run alike, and the bound holds with nothing to round. Where they
//! are on (`madvise`, `always`) it is the bound itself that is tested.
//! The walls and the page walks the advice buys were counted on Linux boxes
//! (1 Oct 2026).
//!
//! Its own test binary, so no other test's child shares the measurement.

// Linux and macOS only by its nature: the peak is read from `wait4`'s resource usage.
// The word is read only under `reader-knobs`: a shipped `rarfast` reads no
// environment word.
#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
    feature = "reader-knobs"
))]
#![allow(unsafe_code)]

use std::path::Path;
use std::process::{Command, Output};

const MIB: u64 = 1 << 20;

/// What the advice may add to the peak of a create two threads wide: 2 MiB
/// of rounding for each sparsely touched table that asks (an engine's
/// heads, links and history, a builder's heads), for the two engines and
/// two builders such a run has at most, and as much again for the noise
/// between two runs of one binary.
const ROUNDING: u64 = 32 * MIB;

/// Run rarfast with `args` in `dir` and `RARKIT_HUGE_PAGES` as `knob` (or
/// unset), answering what it said and, on Linux, the child's peak
/// resident set in bytes.
fn run(dir: &Path, knob: Option<&str>, args: &[&str]) -> (Output, u64) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rarfast"));
    command
        .current_dir(dir)
        .args(args)
        .env_remove("RARKIT_HUGE_PAGES")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(knob) = knob {
        command.env("RARKIT_HUGE_PAGES", knob);
    }
    let child = command.spawn().unwrap();
    let pid = child.id() as libc::pid_t;
    wait_with_rusage(child, pid)
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
    // Linux reports ru_maxrss in KiB, macOS in bytes; only Linux's is
    // judged below.
    let unit = if cfg!(target_os = "linux") { 1024 } else { 1 };
    let peak = u64::try_from(usage.ru_maxrss).unwrap() * unit;
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
fn the_advice_moves_no_byte_and_its_peak_stays_inside_its_rounding() {
    let dir = std::env::temp_dir().join(format!("rarkit-huge-pages-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("set")).unwrap();
    // Many small members, each a short span over sparsely touched tables,
    // and one that runs past the default dictionary.
    for index in 0..160u64 {
        let len = 3_000 + (index as usize * 977) % 40_000;
        std::fs::write(
            dir.join("set").join(format!("small-{index:03}.txt")),
            rarkit_testdata::chatter(0x0110_2026 + index, len),
        )
        .unwrap();
    }
    std::fs::write(
        dir.join("set").join("large.txt"),
        rarkit_testdata::chatter(0x5eed, 5 << 20),
    )
    .unwrap();

    for form in [&["-m1"][..], &["-m3"][..], &["-m5"][..], &["-m3", "-s"][..]] {
        let name = form.concat().replace('-', "");
        // The same archive whatever asks, and the lower of two peaks an
        // arm, so one run's noise does not decide the bound.
        let mut archives: Vec<Vec<u8>> = Vec::new();
        let mut peaks: Vec<u64> = Vec::new();
        for (arm, knob) in [("ring", Some("ring")), ("all", None), ("off", Some("0"))] {
            let mut low = u64::MAX;
            // (The arm with every advice off is there for its bytes.)
            for round in 0..if arm == "off" { 1 } else { 2 } {
                let archive = format!("{name}-{arm}-{round}.rar");
                let mut args = vec!["a", "-r", "-y", "-idq", "-mt2"];
                args.extend_from_slice(form);
                args.extend_from_slice(&[&archive, "set"]);
                let (made, peak) = run(&dir, knob, &args);
                assert!(made.status.success(), "{name} {arm}: {made:?}");
                low = low.min(peak);
                let bytes = std::fs::read(dir.join(&archive)).unwrap();
                std::fs::remove_file(dir.join(&archive)).unwrap();
                if round == 0 {
                    archives.push(bytes);
                }
            }
            peaks.push(low);
        }
        assert!(
            archives[0] == archives[1] && archives[0] == archives[2],
            "{name}: the advice moved a byte of the archive"
        );
        let (ring, all) = (peaks[0], peaks[1]);
        eprintln!(
            "{name}: peak {} KiB with the encoder's advice, {} KiB without",
            all >> 10,
            ring >> 10
        );
        if cfg!(target_os = "linux") {
            assert!(
                all <= ring + ROUNDING,
                "{name}: the process peaked at {} KiB with the encoder's advice and {} KiB \
                 without, more than {} MiB of rounding",
                all >> 10,
                ring >> 10,
                ROUNDING / MIB
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
