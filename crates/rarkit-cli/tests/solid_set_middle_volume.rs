//! A SOLID volume set entered at a middle volume (SWEEP3-08OCT-02).
//!
//! Measured against unrar 7.23 on a Mac on 9 Oct 2026 over a nine-part
//! set written by rar 7.23 (`a -ma5 -v50k -m3 -s`, eight members), naming
//! parts three, five, seven and nine with one member named: the reference
//! says the named volume's banner, walks the set from its first volume
//! and delivers the member with its own bytes, `All OK`, exit 0, whether
//! the member begins after the named volume, ends before it, or is the
//! one continued into it. rarfast began the solid chain at the named
//! volume unless the continued member was the one selected: the member
//! failed its checksum, exit 3, and no file was written.
//!
//! The set here is rarfast's own (`a -ma5 -m3 -s -v60k`, six members of
//! text and noise). Every run is `-mt2` (a pool two threads wide) under
//! the default memory policy; the set is under 1 MiB.

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// Half text that compresses, half bytes that do not.
fn body(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9) | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len / 2 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.extend_from_slice(format!("w{:03} ", state % 700).as_bytes());
    }
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.push((state >> 11) as u8);
    }
    out.truncate(len);
    out
}

const MEMBERS: [(&str, usize); 6] = [
    ("f0_a.bin", 9_000),
    ("f1_b.bin", 70_000),
    ("f2_c.bin", 150_000),
    ("f3_d.bin", 40_001),
    ("f4_e.bin", 110_000),
    ("f5_f.bin", 30_003),
];

fn volumes(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".rar"))
        .collect();
    names.sort();
    names
}

#[test]
fn a_member_named_from_any_volume_of_a_solid_set_is_delivered_whole() {
    let dir = std::env::temp_dir().join(format!("rarfast-solid-middle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    for (index, (name, len)) in MEMBERS.iter().enumerate() {
        std::fs::write(dir.join("src").join(name), body(index as u32 + 1, *len)).unwrap();
    }
    let mut args = vec!["a", "-idq", "-ma5", "-m3", "-s", "-v60k", "../set.rar"];
    args.extend(MEMBERS.iter().map(|(name, _)| *name));
    let made = Command::new(rarfast())
        .current_dir(dir.join("src"))
        .args(&args)
        .output()
        .unwrap();
    assert_eq!(made.status.code(), Some(0), "{made:?}");
    let set = volumes(&dir);
    assert!(set.len() >= 4, "a set of {} volumes", set.len());

    let mut failed = Vec::new();
    for volume in &set {
        for (index, (name, len)) in MEMBERS.iter().enumerate() {
            let out = dir.join("out");
            let _ = std::fs::remove_dir_all(&out);
            std::fs::create_dir_all(&out).unwrap();
            let run = Command::new(rarfast())
                .current_dir(&dir)
                .args(["x", "-mt2", "-y", volume.as_str(), name, "out/"])
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&run.stdout);
            let stderr = String::from_utf8_lossy(&run.stderr);
            let whole = std::fs::read(out.join(name)).ok() == Some(body(index as u32 + 1, *len));
            let only = std::fs::read_dir(&out).unwrap().count() == 1;
            // A later volume's banner comes first, as the reference's.
            // (Named first, a volume none of whose members is delivered
            // has no banner line in rarfast, as before this test: that is
            // a difference of the progress lines and is not judged here.)
            let banner =
                volume == &set[0] || stdout.contains(&format!("Extracting from {volume}\n"));
            if run.status.code() != Some(0) || !whole || !only || !banner || !stderr.is_empty() {
                failed.push(format!(
                    "{volume} {name}: exit {:?} whole {whole} only {only} banner {banner} stderr {stderr:?}",
                    run.status.code()
                ));
            }
        }
        // And a test of everything from that volume: every member, exit 0.
        let run = Command::new(rarfast())
            .current_dir(&dir)
            .args(["t", "-mt2", volume.as_str()])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&run.stdout);
        if run.status.code() != Some(0) || !stdout.contains("All OK") {
            failed.push(format!("t {volume}: exit {:?}", run.status.code()));
        }
    }
    assert!(failed.is_empty(), "{failed:#?}");
    let _ = std::fs::remove_dir_all(&dir);
}
