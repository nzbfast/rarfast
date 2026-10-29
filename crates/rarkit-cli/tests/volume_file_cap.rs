//! `rarfast a -v<size>` never writes a volume longer than `<size>`.
//!
//! `-v<size>` is the volume FILE's cap to the reference (spec G 3.10, and
//! `WriteOptions::volume_file_size`, which the dialect passes it as). A
//! Usenet poster splits to it, so the cap is a promise: every volume at
//! most the size, never over, and never padded up to it (spec G question
//! 5). Found on 29 Sep 2026
//! over every combination the dialect can write: header encryption cost
//! each volume its framing's prefix and padding on top of the cap (a
//! 120,000 byte `-hp` set wrote volumes of 120,030), because the budget
//! reserved each header's plain image.
//!
//! Where reference `unrar` is on PATH every set is also tested through it,
//! with its stderr required empty; without it those checks are skipped and
//! say so.

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn unrar() -> Option<&'static str> {
    Command::new("unrar")
        .arg("-?")
        .output()
        .ok()
        .map(|_| "unrar")
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-volcap-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Bytes no compressor shrinks, the same every run.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[2]
        })
        .collect()
}

/// The inputs: one large member, or twelve small ones.
fn inputs(dir: &Path, many: bool) -> Vec<String> {
    if many {
        (1..=12u64)
            .map(|i| {
                let name = format!("s{i}.dat");
                std::fs::write(dir.join(&name), noise(700 * i as usize, i)).unwrap();
                name
            })
            .collect()
    } else {
        std::fs::write(dir.join("big.bin"), noise(200_000, 99)).unwrap();
        vec!["big.bin".to_owned()]
    }
}

fn volumes(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "rar"))
        .collect();
    found.sort();
    found
}

#[test]
fn no_volume_is_longer_than_its_v_size() {
    let reference = unrar();
    if reference.is_none() {
        eprintln!("unrar is not on PATH: the sets are measured but not tested through it");
    }
    let modes: &[&[&str]] = &[
        &["-m0"],
        &["-m3"],
        &["-m0", "-psecret"],
        &["-m0", "-hpsecret"],
        &["-m3", "-hpsecret"],
        &["-m0", "-rr1%"],
        &["-m0", "-rr5%"],
        &["-m3", "-rr10%"],
        &["-m0", "-hpsecret", "-rr5%"],
        &["-m0", "-psecret", "-rr3%"],
    ];
    for many in [false, true] {
        for size in [60_000u64, 9_000, 2_000, 900] {
            for mode in modes {
                // A recovery record's reserve does not fit a 900 byte
                // volume beside the volume's own blocks: that size is
                // refused, which `a_size_below_a_volumes_own_blocks_is_
                // refused` pins.
                if size < 2_000 && mode.iter().any(|m| m.starts_with("-rr")) {
                    continue;
                }
                let what = format!("{mode:?} -v{size}b, many={many}");
                let dir = work(&format!("{many}-{size}-{}", mode.join("").replace('%', "")));
                let files = inputs(&dir, many);
                let out = dir.join("out");
                std::fs::create_dir_all(&out).unwrap();
                let volume = format!("-v{size}b");
                let mut args: Vec<&str> = vec!["a", "-ma5", "-y", "-idq", &volume];
                args.extend_from_slice(mode);
                args.push("out/x.rar");
                args.extend(files.iter().map(String::as_str));
                let made = Command::new(rarfast())
                    .current_dir(&dir)
                    .args(&args)
                    .output()
                    .unwrap();
                assert_eq!(
                    made.status.code(),
                    Some(0),
                    "{what}: not written: {}",
                    String::from_utf8_lossy(&made.stderr)
                );
                let set = volumes(&out);
                let input: u64 = files
                    .iter()
                    .map(|f| std::fs::metadata(dir.join(f)).unwrap().len())
                    .sum();
                if input > size {
                    assert!(set.len() > 1, "{what}: a set, not {} volume", set.len());
                }
                for volume in &set {
                    let len = std::fs::metadata(volume).unwrap().len();
                    assert!(len <= size, "{what}: {} is {len} bytes", volume.display());
                }
                if let Some(unrar) = reference {
                    let password = if mode.iter().any(|m| m.contains("secret")) {
                        "-psecret"
                    } else {
                        "-p-"
                    };
                    let tested = Command::new(unrar)
                        .args(["t", "-idq", password])
                        .arg(&set[0])
                        .output()
                        .unwrap();
                    assert_eq!(tested.status.code(), Some(0), "{what}: unrar t");
                    assert!(
                        tested.stderr.is_empty(),
                        "{what}: unrar said: {}",
                        String::from_utf8_lossy(&tested.stderr)
                    );
                }
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }
}

/// A size too small for a volume's own blocks is refused, and nothing is
/// written, rather than a volume written over it: 50 bytes for any
/// volume, and 900 for one that must also hold a recovery record.
#[test]
fn a_size_below_a_volumes_own_blocks_is_refused() {
    for (tag, switches) in [
        ("tiny", &["-m0", "-v50b"][..]),
        ("rr", &["-m0", "-rr5%", "-v900b"][..]),
    ] {
        let dir = work(&format!("refused-{tag}"));
        let files = inputs(&dir, false);
        std::fs::create_dir_all(dir.join("out")).unwrap();
        let mut args = vec!["a", "-ma5", "-y", "-idq"];
        args.extend_from_slice(switches);
        args.extend_from_slice(&["out/x.rar", &files[0]]);
        let made = Command::new(rarfast())
            .current_dir(&dir)
            .args(&args)
            .output()
            .unwrap();
        assert_ne!(made.status.code(), Some(0), "{switches:?} was accepted");
        assert!(
            String::from_utf8_lossy(&made.stderr).contains("volume file size"),
            "{switches:?}: {}",
            String::from_utf8_lossy(&made.stderr)
        );
        assert!(
            volumes(&dir.join("out")).is_empty(),
            "{switches:?}: a volume was written"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
