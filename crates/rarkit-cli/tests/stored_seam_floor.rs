//! WHERE THE SEAM TAKES A STORED MEMBER `x` WRITES, through the whole
//! command, in a build that reads the knobs.
//!
//! One clear stored member under a CRC32, alone in one archive, is walked
//! and asks the engine's size floor (rarkit's `read::seam`, `LENT_FLOOR`,
//! which `dialect::unrar::extract::route::SEAM_TAKES_FROM` mirrors): from
//! 32 MiB a second thread writes it while the walk reads, and under it one
//! thread does both. The line `RARKIT_SEAM_SAY=1` prints says which, and
//! NO BYTE moves with it.
//!
//! That word exists only under the feature `read-depth-knob`;
//! the knob test runner (`make test-knob-spawn`) builds it and runs this:
//!
//! ```text
//! cargo test -p rarkit-cli --features read-depth-knob --test stored_seam_floor
//! ```
//!
//! Windows keeps a gibibyte until it has rows of its own, so there both
//! members run in sequence, and this says so.
//!
//! The lone wide rule (`dialect::unrar::extract::route::lone_wide_stored`)
//! would take both members off the seam's route, warm on macOS and on
//! Windows from 32 MiB, so it is pinned OFF here (`RARFAST_LONE_WIDE=0`):
//! this is the route the seam still serves for every member the rule
//! declines. `tests/lone_wide_stored.rs` covers the rule's own route.
//! `-mt2` states the width: the seam spends one thread beside the walk.
//! It holds one member of 33 MiB and its archive on disk at once.
#![cfg(feature = "read-depth-knob")]

use std::path::PathBuf;
use std::process::Command;

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

const MIB: usize = 1 << 20;

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

/// `unrar x` of one stored member of `len` bytes: what the seam said of
/// it, after the bytes are checked.
fn said_of(len: usize, tag: &str) -> String {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("rarfast-seam-floor-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::create_dir_all(dir.join("out")).unwrap();
    let member = noise(len, 31);
    std::fs::write(dir.join("src").join("one.bin"), &member).unwrap();
    let made = output_of(
        Command::new(rarfast())
            .args(["a", "-m0", "-idq", "../one.rar", "one.bin"])
            .current_dir(dir.join("src")),
    )
    .expect("rarfast a runs");
    assert!(made.status.success(), "rarfast a: {made:?}");
    // A copy named `unrar` is how the binary picks that dialect.
    let unrar = dir.join("unrar");
    copy_executable(&rarfast(), &unrar);
    let out = output_of(
        Command::new(&unrar)
            .args(["x", "-idq", "-y", "-mt2", "one.rar", "out/"])
            .current_dir(&dir)
            .env("RARKIT_SEAM_SAY", "1")
            .env("RARFAST_LONE_WIDE", "0")
            .env_remove("RARKIT_SEAM_FROM_MIB")
            .env_remove("RARKIT_WHOLE_SLAB_FROM_MIB")
            .env_remove("RARFAST_POOL"),
    )
    .expect("unrar runs");
    let text = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "{tag}: {:?} {text}",
        out.status.code()
    );
    let got = std::fs::read(dir.join("out").join("one.bin")).unwrap();
    assert!(got == member, "{tag}: the bytes differ from the member's");
    let _ = std::fs::remove_dir_all(&dir);
    text
}

#[test]
fn a_stored_member_of_33_mib_is_the_seams_and_one_of_31_runs_in_sequence() {
    let over = said_of(33 * MIB, "over");
    let taken = if cfg!(windows) { "in sequence" } else { "seam" };
    assert!(
        over.contains(&format!("stored member of {} bytes: {taken}", 33 * MIB)),
        "33 MiB: {over:?}"
    );
    let under = said_of(31 * MIB, "under");
    assert!(
        under.contains(&format!("stored member of {} bytes: in sequence", 31 * MIB)),
        "31 MiB: {under:?}"
    );
}
