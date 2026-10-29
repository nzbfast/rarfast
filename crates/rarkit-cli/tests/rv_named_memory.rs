//! `rarfast rv` under a named `-mm<size>`: when the parity one recovery
//! volume holds, plus the encoder's fixed read buffer, cannot fit inside
//! the named size, the run is refused before anything is written, with a
//! named error and a non-zero exit.
//! With no `-mm` named, or one that fits, the recovery volumes are written
//! as before. A `-rv` on a create stays refused before writing.
//!
//! The set is three volumes of `a -m0 -v2m` over 5,000,000 bytes of
//! noise, so its largest volume is about 2 MiB and one recovery volume
//! needs about 3 MiB: `-mm2m` cannot hold it and `-mm4m` can. One process
//! at a time, a few MiB.

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

fn named(dir: &Path, suffix: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(suffix))
        .collect();
    names.sort();
    names
}

fn remove_revs(dir: &Path) {
    for name in named(dir, ".rev") {
        std::fs::remove_file(dir.join(name)).unwrap();
    }
}

#[test]
fn a_named_mm_too_small_for_one_recovery_volume_is_refused_before_writing() {
    let dir = std::env::temp_dir().join(format!("rarfast-rv-mm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/rand.bin"), noise(7, 5_000_000)).unwrap();
    let (code, _, stderr) = run(&dir, &["a", "-idq", "-m0", "-v2m", "arc.rar", "src/"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        named(&dir, ".rar"),
        ["arc.part1.rar", "arc.part2.rar", "arc.part3.rar"]
    );

    // Too small: the command's own count, and the `-rv` switch beside it.
    for args in [
        &["rv2", "-mm2m", "arc.part1.rar"][..],
        &["rv", "-rv2", "-mm2m", "arc.part1.rar"][..],
    ] {
        let (code, stdout, stderr) = run(&dir, args);
        assert_ne!(code, 0, "{args:?}: {stdout}{stderr}");
        assert_eq!(code, 8, "{args:?}: the code for not enough memory");
        assert!(stderr.contains("-mm"), "{args:?}: {stderr}");
        assert!(stderr.contains("recovery volume"), "{args:?}: {stderr}");
        assert!(!stdout.contains("Creating"), "{args:?}: {stdout}");
        assert!(named(&dir, ".rev").is_empty(), "{args:?}: a .rev written");
    }

    // A named size that holds it: written as before.
    let (code, stdout, stderr) = run(&dir, &["rv2", "-y", "-mm4m", "arc.part1.rar"]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(stdout.ends_with("Done\n"), "{stdout}");
    assert_eq!(named(&dir, ".rev"), ["arc.part1.rev", "arc.part2.rev"]);
    let fitted: Vec<Vec<u8>> = named(&dir, ".rev")
        .iter()
        .map(|name| std::fs::read(dir.join(name)).unwrap())
        .collect();
    remove_revs(&dir);

    // No `-mm` named: unchanged, the same bytes.
    let (code, stdout, stderr) = run(&dir, &["rv2", "-y", "arc.part1.rar"]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(stdout.ends_with("Done\n"), "{stdout}");
    let unbounded: Vec<Vec<u8>> = named(&dir, ".rev")
        .iter()
        .map(|name| std::fs::read(dir.join(name)).unwrap())
        .collect();
    assert!(
        fitted == unbounded,
        "-mm4m and no -mm wrote different bytes"
    );
    remove_revs(&dir);

    // `-rv` on a create, under the same `-mm`: refused, nothing written.
    let (code, stdout, stderr) = run(
        &dir,
        &[
            "a", "-idq", "-m0", "-v2m", "-rv2", "-mm2m", "new.rar", "src/",
        ],
    );
    assert_ne!(code, 0, "{stdout}{stderr}");
    assert!(
        named(&dir, ".rar")
            .iter()
            .all(|name| name.starts_with("arc.")),
        "a create with -rv wrote {:?}",
        named(&dir, ".rar")
    );
    assert!(named(&dir, ".rev").is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
