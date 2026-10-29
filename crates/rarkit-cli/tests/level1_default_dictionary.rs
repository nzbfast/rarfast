//! The level 1 default dictionary (spec G 3.8.1) from `rarfast`: with no
//! `-md`, a non-solid `rarfast a -m1` writes the archive `-md4m` writes;
//! `RARKIT_L1_DICT_2M=1` brings back the archive `-md2m` writes; a solid
//! `-m1`, and `-m2`, write what `-md2m` writes whatever the switch says;
//! and a named `-md` wins over both. Every archive passes `rarfast t`,
//! and reference `unrar t` where one is on the PATH.
//!
//! A shipped `rarfast` reads no environment word; the create path's exist only
//! under the feature `writer-knobs`, which this test builds with:
//!
//! ```text
//! cargo test -p rarkit-cli --features writer-knobs --test level1_default_dictionary
//! ```
#![cfg(feature = "writer-knobs")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// 6 MiB whose only large repeat lies 3 MiB back: a 4 MiB window reaches
/// it and a 2 MiB one cannot.
fn big() -> Vec<u8> {
    let repeat = rarkit_testdata::scramble(11, 512 << 10);
    let mut out = repeat.clone();
    out.extend_from_slice(&rarkit_testdata::chatter(12, 5 << 19));
    out.extend_from_slice(&repeat);
    out.extend_from_slice(&rarkit_testdata::chatter(13, 5 << 19));
    out
}

/// `rarfast a <switches> <name>.rar big.bin small.txt` in `dir`, with the
/// environment switch set to `keep` or absent, answering the archive.
fn create(dir: &Path, name: &str, switches: &[&str], keep: Option<&str>) -> Vec<u8> {
    let archive = format!("{name}.rar");
    let _ = std::fs::remove_file(dir.join(&archive));
    let mut run = Command::new(rarfast());
    run.current_dir(dir)
        .arg("a")
        .args(switches)
        .args(["-y", "-idq", &archive, "big.bin", "small.txt"])
        .env_remove("RARKIT_L1_DICT_2M");
    if let Some(value) = keep {
        run.env("RARKIT_L1_DICT_2M", value);
    }
    let made = run.output().expect("rarfast runs");
    assert!(made.status.success(), "{name}: {made:?}");
    let tested = Command::new(rarfast())
        .current_dir(dir)
        .args(["t", "-idq", &archive])
        .output()
        .expect("rarfast runs");
    assert!(tested.status.success(), "{name}: rarfast t: {tested:?}");
    // Reference unrar reports a checksum error on stderr and may still
    // exit 0, so both streams are read.
    if let Ok(tested) = Command::new("unrar")
        .current_dir(dir)
        .args(["t", &archive])
        .output()
    {
        let out = String::from_utf8_lossy(&tested.stdout);
        let err = String::from_utf8_lossy(&tested.stderr);
        assert!(
            tested.status.success() && out.contains("All OK") && err.trim().is_empty(),
            "{name}: unrar t: {out} {err}"
        );
    }
    std::fs::read(dir.join(&archive)).expect("the archive")
}

#[test]
fn rarfast_m1_takes_4_mib_non_solid_and_the_switch_keeps_2_mib() {
    let dir = std::env::temp_dir().join(format!("rarkit-l1dict-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("big.bin"), big()).unwrap();
    std::fs::write(dir.join("small.txt"), rarkit_testdata::chatter(14, 40_000)).unwrap();

    // RAR 5 named and unnamed: `rarfast a` is a rar 7.23 dialect and
    // writes no RAR 4 archive (`-ma4` is refused); that family's default
    // did not move, which rarkit's test of the same name holds.
    for format in ["-ma5", "-m1"] {
        let at = |name: &str, switches: &[&str], keep: Option<&str>| {
            let mut all = vec![format];
            all.extend_from_slice(switches);
            create(&dir, &format!("{}{name}", &format[1..]), &all, keep)
        };
        let default = at("-m1", &["-m1"], None);
        let named_4 = at("-m1-md4m", &["-m1", "-md4m"], None);
        let named_2 = at("-m1-md2m", &["-m1", "-md2m"], None);
        assert!(default == named_4, "{format} -m1 is not -m1 -md4m");
        assert!(
            default.len() + (256 << 10) < named_2.len(),
            "{format} -m1 wrote {} bytes and -md2m {}: the repeat 3 MiB back was not reached",
            default.len(),
            named_2.len()
        );

        // The switch: `1` on, anything else off.
        let kept = at("-m1-kept", &["-m1"], Some("1"));
        assert!(
            kept == named_2,
            "{format} -m1 under the switch is not -md2m"
        );
        let not_one = at("-m1-zero", &["-m1"], Some("0"));
        assert!(not_one == default, "{format}: a switch of 0 turned it on");

        // A named dictionary wins over the default and over the switch.
        let named_1 = at("-m1-md1m", &["-m1", "-md1m"], None);
        let named_1_kept = at("-m1-md1m-kept", &["-m1", "-md1m"], Some("1"));
        assert!(named_1 == named_1_kept, "{format}: the switch moved -md1m");
        let named_4_kept = at("-m1-md4m-kept", &["-m1", "-md4m"], Some("1"));
        assert!(named_4 == named_4_kept, "{format}: the switch moved -md4m");

        // A non-solid level 2 stays at 2 MiB, and the switch moves
        // neither it nor a solid level 1 (level 3 has a default of its
        // own since 9 Oct 2026, which `level3_default_dictionary` holds,
        // and a solid archive since 10 Oct, `solid_default_dictionary`).
        for (name, switches) in [("-m1-s", ["-m1", "-s"].as_slice()), ("-m2", &["-m2"])] {
            let default = at(name, switches, None);
            let mut with_2 = switches.to_vec();
            with_2.push("-md2m");
            let named_2 = at(&format!("{name}-md2m"), &with_2, None);
            let kept = at(&format!("{name}-kept"), switches, Some("1"));
            if name == "-m2" {
                assert!(default == named_2, "{format} {name} is not {name} -md2m");
            }
            assert!(default == kept, "{format} {name}: the switch moved it");
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
