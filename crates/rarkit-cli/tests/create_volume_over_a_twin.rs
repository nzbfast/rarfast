//! A volume is never written over a file the run did not create.
//!
//! A create with `-v<size>` looked once, before it wrote, for a file at
//! any name of the set, folding ASCII case only, and then opened each
//! volume with a create that takes whatever is there. On a disk that
//! treats two spellings as one name, a file whose name differs from a
//! volume's in the case of a letter outside ASCII (or in how an accent
//! is composed) was not seen by the look and was overwritten with volume
//! data: exit 0 and no word. So was a file that appeared at a volume's
//! name after the look.
//!
//! Measured against rar 7.23 on 8 Oct 2026 (macOS, a case-insensitive
//! volume): over an existing `év.part2.rar`, `rar a -m0 -v1m ÉV.rar
//! b.bin` asks `Overwrite ÉV.part2.rar?`; with nothing on standard input
//! it answers `Read error`, exits 12, and the file keeps its bytes.
//!
//! rarfast now creates each volume so that the SYSTEM refuses a name
//! that is already there, in any spelling it holds to be the same. The
//! run stops, names the volume, removes the volumes it did write and
//! leaves the file as it was.
//!
//! The row needs a directory where `É` and `é` are one name; where they
//! are two it has nothing to show and says so. One run, `-mt2`, over
//! 300,000 bytes: a pool two threads wide and a few MiB of memory.

use std::process::{Command, Stdio};

#[test]
fn a_volume_does_not_overwrite_a_twin_in_another_case() {
    let dir = std::env::temp_dir().join(format!("rarfast-voltwin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("v")).unwrap();
    std::fs::write(dir.join("v/év.part2.rar"), b"0123456789").unwrap();
    if !dir.join("v/ÉV.part2.rar").exists() {
        println!("SKIPPED: this directory keeps names that differ in case apart");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let noise: Vec<u8> = (0..300_000_u32)
        .map(|n| (n.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    std::fs::write(dir.join("b.bin"), noise).unwrap();
    let run = Command::new(env!("CARGO_BIN_EXE_rarfast"))
        .args(["a", "-idq", "-mt2", "-m0", "-v100k", "ÉV.rar", "../b.bin"])
        .current_dir(dir.join("v"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let warned = String::from_utf8_lossy(&run.stderr);
    assert!(
        std::fs::read(dir.join("v/év.part2.rar")).unwrap() == b"0123456789",
        "the file was written over; exit {:?}, stderr {warned}",
        run.status.code()
    );
    assert_ne!(run.status.code(), Some(0), "{warned}");
    assert!(
        warned.contains("part2.rar"),
        "the volume is not named: {warned}"
    );
    let left: Vec<String> = std::fs::read_dir(dir.join("v"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left.len(), 1, "the run left its own volumes: {left:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
