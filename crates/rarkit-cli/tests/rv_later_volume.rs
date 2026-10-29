//! `rarfast rv` when the volume named is not the set's first.
//!
//! Measured on 4 Oct 2026 with `rar` 7.23 (macOS, aarch64) over a
//! three-volume set written by rarfast (`a -m0 -v200k`, 500,000 bytes of
//! noise): `rar rv2 arc.part2.rar` and `rar rv2 arc.part3.rar` print
//! nothing on stdout past the banner, a blank line and `<name> is not the
//! first volume` on stderr, write no `.rev` file and exit 0; `rar rv2 arc.part1.rar`
//! writes `arc.part1.rev` and `arc.part2.rev` over all three volumes.
//!
//! rarfast used to build the parity over the volumes from the NAMED one
//! onwards and write it under the whole set's names, over any `.rev`
//! already there. One process at a time, a few MiB.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// Seeded bytes that do not compress.
fn noise(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn run(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(rarfast())
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn revs(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".rev"))
        .collect();
    names.sort();
    names
}

#[test]
fn a_later_volume_is_refused_and_no_rev_file_is_touched() {
    let dir = std::env::temp_dir().join(format!("rarfast-rv-later-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/rand.bin"), noise(1, 300_000)).unwrap();
    std::fs::write(dir.join("src/text.bin"), noise(2, 200_000)).unwrap();
    let (code, _, stderr) = run(&dir, &["a", "-idq", "-m0", "-v200k", "arc.rar", "src/"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(dir.join("arc.part3.rar").exists() && !dir.join("arc.part4.rar").exists());

    // A recovery volume already there under the set's first name.
    std::fs::write(dir.join("arc.part1.rev"), b"old\n").unwrap();
    for named in ["arc.part2.rar", "arc.part3.rar"] {
        let (code, stdout, stderr) = run(&dir, &["rv2", named]);
        assert_eq!(code, 0, "{named}");
        // The blank line is where the reference's banner ends, and the
        // closing newline is rarfast's own, both exactly as its `is not
        // volume` answer has them.
        assert_eq!(stdout, "\n", "{named}");
        assert_eq!(stderr, format!("\n{named} is not the first volume\n"));
        assert_eq!(revs(&dir), ["arc.part1.rev"], "{named}");
        assert_eq!(
            std::fs::read(dir.join("arc.part1.rev")).unwrap(),
            b"old\n",
            "{named}"
        );
    }

    // The first volume named: the whole set's recovery volumes.
    let (code, stdout, stderr) = run(&dir, &["rv2", "-y", "arc.part1.rar"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.ends_with("Done\n"), "{stdout}");
    assert_eq!(revs(&dir), ["arc.part1.rev", "arc.part2.rev"]);
    assert_eq!(
        std::fs::metadata(dir.join("arc.part1.rev")).unwrap().len(),
        204_863,
        "measured: the reference's and rarfast's are this long, and the same bytes"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
