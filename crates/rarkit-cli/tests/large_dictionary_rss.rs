//! Peak RSS of `rarfast t` over a NON-SOLID member whose declared
//! dictionary (512 MiB) is larger than the member (300,000,000 bytes):
//! the process peaks under the declared dictionary.
//!
//! Its own test binary with ONE test, because `getrusage(RUSAGE_CHILDREN)`
//! reports the largest child this PROCESS has waited for, and another
//! test's child would count.
//!
//! What this can and cannot show. The ring is zeroed memory from the
//! allocator, whose pages become resident only when written, and a member
//! of N bytes writes at most N bytes of ring whatever length the ring was
//! given. So a peak under the declared dictionary is necessary, not
//! sufficient: it catches a window that is TOUCHED past the member, not
//! one merely reserved past it. `large_dictionary.rs`'s `-mm700m` row is
//! the sharper proof, a 350 MiB cap that admits the 512 MiB-declared
//! member only because its window is sized to its 300,000,000 bytes.

// Linux and macOS only by its nature: the peak is read from `getrusage`.
#![cfg(any(target_os = "linux", target_os = "macos"))]
#![allow(unsafe_code)]

use std::path::Path;
use std::process::Command;

/// Peak RSS of every child waited for so far, in bytes.
fn children_peak_rss() -> u64 {
    // SAFETY: `rusage` is plain integers and timevals, for which all
    // zeroes is a valid value.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a live, writable `rusage` and `getrusage` writes
    // only inside it.
    let rc = unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) };
    assert_eq!(rc, 0, "getrusage");
    let max = u64::try_from(usage.ru_maxrss).unwrap();
    // Linux reports KiB, macOS bytes.
    if cfg!(target_os = "linux") {
        max * 1024
    } else {
        max
    }
}

#[test]
fn a_non_solid_member_peaks_under_its_declared_dictionary() {
    let archive = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/large-dictionary/dict512m.rar");
    let done = Command::new(env!("CARGO_BIN_EXE_rarfast"))
        .args(["t", "-y", "-idq", "-mt1"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(done.status.success(), "{done:?}");
    let peak = children_peak_rss();
    eprintln!("rarfast t dict512m.rar -mt1: peak RSS {peak} bytes");
    assert!(
        peak < 512 << 20,
        "peak RSS {peak} is not under the declared 512 MiB dictionary"
    );
    assert!(
        peak >= 300_000_000 / 2,
        "peak RSS {peak} is too small to have held the member's window at all"
    );
}
