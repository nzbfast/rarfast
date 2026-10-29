//! The level 3 default dictionary (spec G 3.8.1) from `rarfast`: with no
//! `-md`, a non-solid `rarfast a -m3` (and `rarfast a` with no `-m`,
//! which is level 3) writes the archive `-md16m` writes under
//! `RARKIT_FAR_LINKS=1`; `RARKIT_L3_DICT_2M=1` brings back the archive
//! `-md2m` writes; a solid `-m3` is not moved by the switch; and a named
//! `-md` wins over both. Every archive passes
//! `rarfast t`, and reference `unrar t` where one is on the PATH.
//!
//! Threads: the default width of the machine. Memory: one member of
//! 9 MiB in a 16 MiB window, under 300 MiB.
//!
//! A shipped `rarfast` reads no environment word; the create path's exist only
//! under the feature `writer-knobs`, which this test builds with:
//!
//! ```text
//! cargo test -p rarkit-cli --features writer-knobs --test level3_default_dictionary
//! ```
#![cfg(feature = "writer-knobs")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// 9 MiB whose only large repeat lies 3.5 MiB back: a 16 MiB window
/// reaches it and a 2 MiB one cannot.
fn big() -> Vec<u8> {
    let repeat = rarkit_testdata::scramble(21, 512 << 10);
    let mut out = repeat.clone();
    out.extend_from_slice(&rarkit_testdata::chatter(22, 3 << 20));
    out.extend_from_slice(&repeat);
    out.extend_from_slice(&rarkit_testdata::chatter(23, 5 << 20));
    out
}

/// `rarfast a <switches> <name>.rar big.bin small.txt` in `dir`, with
/// `RARKIT_L3_DICT_2M` set to `keep` and `RARKIT_FAR_LINKS` to `far`, or
/// absent, answering the archive.
fn create(
    dir: &Path,
    name: &str,
    switches: &[&str],
    keep: Option<&str>,
    far: Option<&str>,
) -> Vec<u8> {
    let archive = format!("{name}.rar");
    let _ = std::fs::remove_file(dir.join(&archive));
    let mut run = Command::new(rarfast());
    run.current_dir(dir)
        .arg("a")
        .args(switches)
        .args(["-y", "-idq", &archive, "big.bin", "small.txt"])
        .env_remove("RARKIT_L3_DICT_2M")
        .env_remove("RARKIT_FAR_LINKS");
    if let Some(value) = keep {
        run.env("RARKIT_L3_DICT_2M", value);
    }
    if let Some(value) = far {
        run.env("RARKIT_FAR_LINKS", value);
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
fn rarfast_m3_takes_16_mib_under_one_far_link_and_the_switch_keeps_2_mib() {
    let dir = std::env::temp_dir().join(format!("rarkit-l3dict-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("big.bin"), big()).unwrap();
    std::fs::write(dir.join("small.txt"), rarkit_testdata::chatter(26, 40_000)).unwrap();

    // `-m3` spelled and left out: level 3 is `rarfast a`'s default.
    for (tag, level) in [("m3", ["-m3"].as_slice()), ("plain", &[])] {
        let at = |name: &str, switches: &[&str], keep: Option<&str>, far: Option<&str>| {
            let mut all = level.to_vec();
            all.extend_from_slice(switches);
            create(&dir, &format!("{tag}{name}"), &all, keep, far)
        };
        let default = at("", &[], None, None);
        let named_16_one_link = at("-md16m-f1", &["-md16m"], None, Some("1"));
        let named_2 = at("-md2m", &["-md2m"], None, None);
        assert!(
            default == named_16_one_link,
            "{tag}: the default is not -md16m under RARKIT_FAR_LINKS=1"
        );
        assert!(
            default.len() + (64 << 10) < named_2.len(),
            "{tag}: the default wrote {} bytes and -md2m {}: the repeat 3.5 MiB back was not \
             reached",
            default.len(),
            named_2.len()
        );

        // The switch: `1` on, anything else off.
        let kept = at("-kept", &[], Some("1"), None);
        assert!(kept == named_2, "{tag}: under the switch it is not -md2m");
        let not_one = at("-zero", &[], Some("0"), None);
        assert!(not_one == default, "{tag}: a switch of 0 turned it on");

        // A named dictionary wins over the default and over the switch.
        let named_4 = at("-md4m", &["-md4m"], None, None);
        let named_4_kept = at("-md4m-kept", &["-md4m"], Some("1"), None);
        assert!(named_4 == named_4_kept, "{tag}: the switch moved -md4m");
        let named_16 = at("-md16m", &["-md16m"], None, None);
        let named_16_kept = at("-md16m-kept", &["-md16m"], Some("1"), None);
        assert!(named_16 == named_16_kept, "{tag}: the switch moved -md16m");

        // A solid archive has its own default (`solid_default_dictionary`
        // holds it), which this switch does not reach.
        let solid = at("-s", &["-s"], None, None);
        let solid_kept = at("-s-kept", &["-s"], Some("1"), None);
        assert!(solid == solid_kept, "{tag}: the switch moved -s");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
