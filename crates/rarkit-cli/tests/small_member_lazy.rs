//! The small-member lazy option on the command line, ON by default
//! (SPEC-G 3.8.1, SPEC-H3 8.1 acceptance test 7): `rarfast` reads
//! `RARKIT_SMALL_LAZY` (`0` off, unset or `1` on) and passes it to the
//! library as
//! `WriteOptions::small_member_lazy`; no rar dialect switch sets it, so a
//! command line written for rar writes the default however its switches
//! are spelled.
//!
//! A shipped `rarfast` reads no environment word; the create path's exist only
//! under the feature `writer-knobs`, which this test builds with:
//!
//! ```text
//! cargo test -p rarkit-cli --features writer-knobs --test small_member_lazy
//! ```
#![cfg(feature = "writer-knobs")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-small-lazy-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `rarfast a <switches> <name>.rar small.txt` in `dir`, with
/// `RARKIT_SMALL_LAZY` as given, and the archive's bytes.
fn create(dir: &Path, name: &str, switches: &[&str], lazy: Option<&str>) -> Vec<u8> {
    let archive = format!("{name}.rar");
    let mut command = Command::new(rarfast());
    command
        .current_dir(dir)
        .arg("a")
        .args(switches)
        .arg(&archive)
        .arg("small.txt")
        .env_remove("RARKIT_SMALL_LAZY");
    if let Some(value) = lazy {
        command.env("RARKIT_SMALL_LAZY", value);
    }
    let out = command.output().unwrap();
    assert!(out.status.success(), "rarfast a: {:?}", out);
    std::fs::read(dir.join(archive)).unwrap()
}

#[test]
fn rarkit_small_lazy_0_reaches_a_small_member_at_level_5_and_no_rar_switch_does() {
    let dir = work("m5");
    std::fs::write(
        dir.join("small.txt"),
        rarkit_testdata::chatter(0x736d, 200_000),
    )
    .unwrap();
    let default = create(&dir, "default", &["-m5", "-idq"], None);
    let lazy = create(&dir, "lazy", &["-m5", "-idq"], Some("1"));
    assert!(lazy == default, "the lazy parse is the default");
    let optimal = create(&dir, "zero", &["-m5", "-idq"], Some("0"));
    assert!(
        optimal != default,
        "RARKIT_SMALL_LAZY=0 reaches a 200 KB member at -m5"
    );
    // rar's own switches, however spelled, write the default.
    let spelled = create(
        &dir,
        "spelled",
        &["-m5", "-mt4", "-s-", "-ma5", "-idq"],
        None,
    );
    assert!(spelled == default, "no rar switch sets the option");
    // And both archives are sound ones.
    for archive in ["lazy.rar", "zero.rar"] {
        let test = Command::new(rarfast())
            .current_dir(&dir)
            .args(["t", "-idq", archive])
            .output()
            .unwrap();
        assert!(test.status.success(), "rarfast t {archive}: {:?}", test);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
