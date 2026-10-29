//! The level 3 floor option on the command line (SPEC-G 3.8.3): `rarfast` reads
//! `RARKIT_L3_FLOOR_LAZY` (`1` on, unset or `0` off) and passes it to the
//! library as `WriteOptions::level3_floor_lazy`, which gives level 3's
//! empty blocks the floor's lazy parse instead of the floor scan; no rar
//! dialect switch sets it, and it reaches no other level.
//!
//! A shipped `rarfast` reads no environment word; the create path's exist only
//! under the feature `writer-knobs`, which this test builds with:
//!
//! ```text
//! cargo test -p rarkit-cli --features writer-knobs --test level3_floor_lazy
//! ```
#![cfg(feature = "writer-knobs")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-l3-floor-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// SPEC-G 3.8.3's acceptance member: 524,288 bytes of noise holding a 96 KiB
/// copy of its own earlier bytes, so that its parse blocks sample as empty
/// and go to the floor, the store rule does not sample it (under 1 MiB) and
/// it is not a lone member (over 256 KiB).
fn noise_with_a_copy() -> Vec<u8> {
    let mut state = 0x0930_2026_u64 | 1;
    let mut out = Vec::with_capacity(524_288 + 8);
    while out.len() < 524_288 {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.extend_from_slice(&state.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes());
    }
    out.truncate(524_288);
    let copy = out[16 << 10..(16 << 10) + (96 << 10)].to_vec();
    let at = (300 << 10) + 7;
    out[at..at + copy.len()].copy_from_slice(&copy);
    out
}

/// `rarfast a <switches> <name>.rar member.bin` in `dir`, with
/// `RARKIT_L3_FLOOR_LAZY` as given, and the archive's bytes.
fn create(dir: &Path, name: &str, switches: &[&str], lazy: Option<&str>) -> Vec<u8> {
    let archive = format!("{name}.rar");
    // `rarfast a` onto an existing archive edits it, and the loop below
    // reuses its names.
    let _ = std::fs::remove_file(dir.join(&archive));
    let mut command = Command::new(rarfast());
    command
        .current_dir(dir)
        .arg("a")
        .args(switches)
        .arg(&archive)
        .arg("member.bin")
        .env_remove("RARKIT_L3_FLOOR_LAZY");
    if let Some(value) = lazy {
        command.env("RARKIT_L3_FLOOR_LAZY", value);
    }
    let out = command.output().unwrap();
    assert!(out.status.success(), "rarfast a: {:?}", out);
    std::fs::read(dir.join(archive)).unwrap()
}

#[test]
fn rarkit_l3_floor_lazy_reaches_level_3_only_and_no_rar_switch_does() {
    let dir = work("m3");
    std::fs::write(dir.join("member.bin"), noise_with_a_copy()).unwrap();
    let default = create(&dir, "default", &["-m3", "-idq"], None);
    assert!(default == create(&dir, "zero", &["-m3", "-idq"], Some("0")));
    let lazy = create(&dir, "lazy", &["-m3", "-idq"], Some("1"));
    assert!(
        lazy != default,
        "RARKIT_L3_FLOOR_LAZY=1 reaches the member's floored block at -m3"
    );
    // Levels 1 and 2 always scan, and 4 and 5 never do: the option is not
    // theirs.
    for level in ["-m1", "-m2", "-m4", "-m5"] {
        let off = create(&dir, "off", &[level, "-idq"], None);
        let on = create(&dir, "on", &[level, "-idq"], Some("1"));
        assert!(on == off, "RARKIT_L3_FLOOR_LAZY=1 moved a byte at {level}");
    }
    // rar's own switches, however spelled, write the default.
    let spelled = create(
        &dir,
        "spelled",
        &["-m3", "-mt4", "-s-", "-ma5", "-idq"],
        None,
    );
    assert!(spelled == default, "no rar switch sets the option");
    // And the lazy archive is a sound one.
    let test = Command::new(rarfast())
        .current_dir(&dir)
        .args(["t", "-idq", "lazy.rar"])
        .output()
        .unwrap();
    assert!(test.status.success(), "rarfast t lazy.rar: {:?}", test);
    let _ = std::fs::remove_dir_all(&dir);
}
