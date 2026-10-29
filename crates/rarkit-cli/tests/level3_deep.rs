//! The backward extension's two options on the command line: `rarfast`
//! reads `RARKIT_L3_DEEP` (`WriteOptions::level3_deep`: level 3's lazy
//! parse 64 chain links instead of 32) and `RARKIT_L12_EXTEND`
//! (`WriteOptions::low_levels_extend`: the extension at levels 1 and 2),
//! each `1` on, unset or `0` off; no rar dialect switch sets either, and
//! each reaches only its own levels. Level 1's default is now
//! the fast parse, which has no extension: `RARKIT_L12_EXTEND` reaches
//! `-m1` only beside `RARKIT_L1_PRICED=1`, the lazy level 1 of before.
//!
//! A shipped `rarfast` reads no environment word; the create path's exist only
//! under the feature `writer-knobs`, which this test builds with:
//!
//! ```text
//! cargo test -p rarkit-cli --features writer-knobs --test level3_deep
//! ```
#![cfg(feature = "writer-knobs")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-l3-deep-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `rarfast a <switches> <name>.rar member.txt` in `dir`, with
/// `RARKIT_L3_DEEP` as given, and the archive's bytes.
fn create(dir: &Path, name: &str, switches: &[&str], deep: Option<&str>) -> Vec<u8> {
    create_with(dir, name, switches, "RARKIT_L3_DEEP", deep)
}

/// The same, with `var` (one of the two options) as given.
fn create_with(
    dir: &Path,
    name: &str,
    switches: &[&str],
    var: &str,
    value: Option<&str>,
) -> Vec<u8> {
    let set: Vec<(&str, &str)> = value.map(|value| (var, value)).into_iter().collect();
    create_env(dir, name, switches, &set)
}

/// The same, with every variable of `set` as given and the other options'
/// variables unset.
fn create_env(dir: &Path, name: &str, switches: &[&str], set: &[(&str, &str)]) -> Vec<u8> {
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
        .arg("member.txt")
        .env_remove("RARKIT_L3_DEEP")
        .env_remove("RARKIT_L12_EXTEND")
        .env_remove("RARKIT_L3_OPTIMAL")
        .env_remove("RARKIT_L1_PRICED");
    for (var, value) in set {
        command.env(var, value);
    }
    let out = command.output().unwrap();
    assert!(out.status.success(), "rarfast a: {:?}", out);
    std::fs::read(dir.join(archive)).unwrap()
}

#[test]
fn rarkit_l3_deep_reaches_level_3_only_and_no_rar_switch_does() {
    let dir = work("m3");
    std::fs::write(
        dir.join("member.txt"),
        rarkit_testdata::chatter(0x4c33, 400_000),
    )
    .unwrap();
    let default = create(&dir, "default", &["-m3", "-idq"], None);
    assert!(default == create(&dir, "zero", &["-m3", "-idq"], Some("0")));
    let deep = create(&dir, "deep", &["-m3", "-idq"], Some("1"));
    assert!(deep != default, "RARKIT_L3_DEEP=1 reaches level 3");
    for level in ["-m1", "-m2", "-m4", "-m5"] {
        let off = create(&dir, "off", &[level, "-idq"], None);
        let on = create(&dir, "on", &[level, "-idq"], Some("1"));
        assert!(on == off, "RARKIT_L3_DEEP=1 moved a byte at {level}");
    }
    let spelled = create(
        &dir,
        "spelled",
        &["-m3", "-mt4", "-s-", "-ma5", "-idq"],
        None,
    );
    assert!(spelled == default, "no rar switch sets the option");
    let test = Command::new(rarfast())
        .current_dir(&dir)
        .args(["t", "-idq", "deep.rar"])
        .output()
        .unwrap();
    assert!(test.status.success(), "rarfast t deep.rar: {:?}", test);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rarkit_l12_extend_reaches_levels_1_and_2_only() {
    let dir = work("m12");
    std::fs::write(
        dir.join("member.txt"),
        rarkit_testdata::chatter(0x4c33, 400_000),
    )
    .unwrap();
    let var = "RARKIT_L12_EXTEND";
    // `-m1` in its priced form, the lazy parse; `-m2` as it stands.
    let priced = ("RARKIT_L1_PRICED", "1");
    for (level, form) in [("-m1", &[priced][..]), ("-m2", &[][..])] {
        let with = |value: &'static str| [form, &[(var, value)][..]].concat();
        let off = create_env(&dir, "off", &[level, "-idq"], form);
        assert!(off == create_env(&dir, "zero", &[level, "-idq"], &with("0")));
        let on = create_env(&dir, "on", &[level, "-idq"], &with("1"));
        assert!(on != off, "{var}=1 reaches {level}");
        let test = Command::new(rarfast())
            .current_dir(&dir)
            .args(["t", "-idq", "on.rar"])
            .output()
            .unwrap();
        assert!(test.status.success(), "rarfast t on.rar: {:?}", test);
    }
    // The fast level 1 has no extension, and levels 3 to 5 have their own
    // rule for it.
    for level in ["-m1", "-m3", "-m4", "-m5"] {
        let off = create_with(&dir, "off", &[level, "-idq"], var, None);
        let on = create_with(&dir, "on", &[level, "-idq"], var, Some("1"));
        assert!(on == off, "{var}=1 moved a byte at {level}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
