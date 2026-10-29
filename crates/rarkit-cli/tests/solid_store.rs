//! The store rule inside a solid set, on the command line (SPEC-G 3.8.3):
//! `rarfast a -s` writes a
//! member of 1 MiB and more that will not compress STORED inside the solid
//! set by default; `RARKIT_SOLID_STORE=0` keeps every solid member in the
//! compressor, and reaches the library as `WriteOptions::solid_store`; no
//! rar dialect switch sets it, so a command line written for rar writes
//! the default however its switches are spelled.
//!
//! A shipped `rarfast` reads no environment word; the create path's exist only
//! under the feature `writer-knobs`, which this test builds with:
//!
//! ```text
//! cargo test -p rarkit-cli --features writer-knobs --test solid_store
//! ```
#![cfg(feature = "writer-knobs")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("rarfast-solid-store-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Bytes with nothing in them to compress.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x2026_1001_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

const FILES: [&str; 3] = ["a.txt", "clip.mkv", "z.txt"];

/// `rarfast a <switches> <name>.rar` of the three files in `dir`, with
/// `RARKIT_SOLID_STORE` as given, and the archive's bytes.
fn create(dir: &Path, name: &str, switches: &[&str], knob: Option<&str>) -> Vec<u8> {
    let archive = format!("{name}.rar");
    let mut command = Command::new(rarfast());
    command
        .current_dir(dir)
        .arg("a")
        .args(switches)
        .arg(&archive)
        .args(FILES)
        .env_remove("RARKIT_SOLID_STORE");
    if let Some(value) = knob {
        command.env("RARKIT_SOLID_STORE", value);
    }
    let out = command.output().unwrap();
    assert!(out.status.success(), "rarfast a: {:?}", out);
    std::fs::read(dir.join(archive)).unwrap()
}

fn holds(archive: &[u8], needle: &[u8]) -> bool {
    archive.windows(needle.len()).any(|at| at == needle)
}

#[test]
fn rarkit_solid_store_0_keeps_a_solid_member_compressed_and_no_rar_switch_does() {
    let dir = work("m3");
    let clip = noise((1 << 20) + 300_000);
    std::fs::write(dir.join("a.txt"), rarkit_testdata::chatter(1, 300_000)).unwrap();
    std::fs::write(dir.join("clip.mkv"), &clip).unwrap();
    std::fs::write(dir.join("z.txt"), rarkit_testdata::chatter(2, 300_000)).unwrap();

    let default = create(&dir, "default", &["-m3", "-s", "-idq"], None);
    // Stored: the member's own bytes are in the archive, whole.
    assert!(
        holds(&default, &clip),
        "the incompressible member is stored inside the solid set by default"
    );
    let on = create(&dir, "on", &["-m3", "-s", "-idq"], Some("1"));
    assert!(on == default, "RARKIT_SOLID_STORE=1 is the default");
    let off = create(&dir, "off", &["-m3", "-s", "-idq"], Some("0"));
    assert!(
        off != default && !holds(&off, &clip),
        "RARKIT_SOLID_STORE=0 keeps the member in the compressor"
    );
    // rar's own switches, however spelled, write the default.
    let spelled = create(
        &dir,
        "spelled",
        &["-m3", "-s", "-mt4", "-ma5", "-idq"],
        None,
    );
    assert!(spelled == default, "no rar switch sets the option");

    // Both are sound archives that give the files back.
    for archive in ["default.rar", "off.rar"] {
        let test = Command::new(rarfast())
            .current_dir(&dir)
            .args(["t", "-idq", archive])
            .output()
            .unwrap();
        assert!(test.status.success(), "rarfast t {archive}: {:?}", test);
        let out = dir.join(format!("out-{archive}"));
        std::fs::create_dir_all(&out).unwrap();
        let extract = Command::new(rarfast())
            .current_dir(&out)
            .args(["x", "-idq"])
            .arg(dir.join(archive))
            .output()
            .unwrap();
        assert!(
            extract.status.success(),
            "rarfast x {archive}: {:?}",
            extract
        );
        for file in FILES {
            assert!(
                std::fs::read(out.join(file)).unwrap() == std::fs::read(dir.join(file)).unwrap(),
                "{archive}: {file} extracts to its input"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
