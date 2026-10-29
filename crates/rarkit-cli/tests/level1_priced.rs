//! The level 1 parse option on the command line: `rarfast` reads
//! `RARKIT_L1_PRICED` (`1` on, unset or anything else off) and passes it to
//! the library as `WriteOptions::level1_priced`, which gives `-m1` the lazy
//! parse over four byte chains it had before the fast parse became the default, instead of the fast
//! parse. No rar dialect switch sets it, and it reaches `-m1` only. (The
//! RAR 4 family, which no `rarfast a` switch writes, is held to the same in
//! the library's `tests/level1_parse.rs`.)
//!
//! A shipped `rarfast` reads no environment word; the create path's exist only
//! under the feature `writer-knobs`, which this test builds with:
//!
//! ```text
//! cargo test -p rarkit-cli --features writer-knobs --test level1_priced
//! ```
#![cfg(feature = "writer-knobs")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-l1-priced-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `rarfast a <switches> <name>.rar member.txt` in `dir`, with
/// `RARKIT_L1_PRICED` as given, and the archive's bytes.
fn create(dir: &Path, name: &str, switches: &[&str], priced: Option<&str>) -> Vec<u8> {
    let archive = format!("{name}.rar");
    // `rarfast a` onto an existing archive edits it, and the loops below
    // reuse their names.
    let _ = std::fs::remove_file(dir.join(&archive));
    let mut command = Command::new(rarfast());
    command
        .current_dir(dir)
        .arg("a")
        .args(switches)
        .arg(&archive)
        .arg("member.txt")
        .env_remove("RARKIT_L1_PRICED")
        .env_remove("RARKIT_L12_EXTEND");
    if let Some(value) = priced {
        command.env("RARKIT_L1_PRICED", value);
    }
    let out = command.output().unwrap();
    assert!(out.status.success(), "rarfast a: {:?}", out);
    std::fs::read(dir.join(archive)).unwrap()
}

fn tests(dir: &Path, archive: &str) {
    let test = Command::new(rarfast())
        .current_dir(dir)
        .args(["t", "-idq", archive])
        .output()
        .unwrap();
    assert!(test.status.success(), "rarfast t {archive}: {:?}", test);
}

#[test]
fn rarkit_l1_priced_reaches_level_1_only_and_no_rar_switch_does() {
    let dir = work("m1");
    std::fs::write(
        dir.join("member.txt"),
        rarkit_testdata::chatter(0x4c31, 400_000),
    )
    .unwrap();
    for format in ["-ma5"] {
        let default = create(&dir, "default", &["-m1", format, "-idq"], None);
        assert!(default == create(&dir, "zero", &["-m1", format, "-idq"], Some("0")));
        let priced = create(&dir, "priced", &["-m1", format, "-idq"], Some("1"));
        assert!(priced != default, "RARKIT_L1_PRICED=1 reaches -m1 {format}");
        tests(&dir, "default.rar");
        tests(&dir, "priced.rar");
        // The same bytes at any width, in both forms.
        for (name, value) in [("default", None), ("priced", Some("1"))] {
            let one = create(&dir, "one", &["-m1", "-mt1", format, "-idq"], value);
            let four = create(&dir, "four", &["-m1", "-mt4", format, "-idq"], value);
            assert!(one == four, "{name} -m1 {format}: -mt1 and -mt4 differ");
        }
        for level in ["-m2", "-m3", "-m4", "-m5"] {
            let off = create(&dir, "off", &[level, format, "-idq"], None);
            let on = create(&dir, "on", &[level, format, "-idq"], Some("1"));
            assert!(
                on == off,
                "RARKIT_L1_PRICED=1 moved a byte at {level} {format}"
            );
        }
    }
    let default = create(&dir, "default", &["-m1", "-idq"], None);
    let spelled = create(
        &dir,
        "spelled",
        &["-m1", "-mt4", "-s-", "-ma5", "-idq"],
        None,
    );
    assert!(spelled == default, "no rar switch sets the option");
    let _ = std::fs::remove_dir_all(&dir);
}
