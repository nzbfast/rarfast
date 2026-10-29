//! The solid default dictionary (spec G 3.8.1) from `rarfast`: with no
//! `-md`, `rarfast a -s` at levels 2 to 5 writes the archive `-md32m`
//! writes under `RARKIT_FAR_LINKS=1` (level 1 keeps `-md2m`'s);
//! `RARKIT_SOLID_DICT_2M=1` and a named `-mm` ceiling bring back the
//! archive `-md2m` writes; and a named `-md` wins over the switch. Every
//! archive passes `rarfast t`, and reference `unrar` extracts it to the
//! source's own bytes where one is on the PATH.
//!
//! Threads: the default width of the machine. Memory: 9 MiB of members
//! in a window fitted to 16 MiB, under 400 MiB.
//!
//! A shipped `rarfast` reads no environment word; the create path's exist only
//! under the feature `writer-knobs`, which this test builds with:
//!
//! ```text
//! cargo test -p rarkit-cli --features writer-knobs --test solid_default_dictionary
//! ```
#![cfg(feature = "writer-knobs")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Words that compress, `len` bytes of them.
fn text(len: usize, seed: u64) -> Vec<u8> {
    let words = [
        "window ", "sixteen ", "two ", "level ", "three ", "solid ", "named ", "default ",
    ];
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        out.extend_from_slice(
            words[(xorshift(&mut state) >> 29) as usize % words.len()].as_bytes(),
        );
    }
    out.truncate(len);
    out
}

/// 9 MiB whose only large repeat lies 3.5 MiB back: a quarter MiB of
/// six-byte words drawn from 4,096 of them, at 4.5 MiB and again at
/// 8 MiB. A window that follows one far link reaches it and a 2 MiB one
/// cannot.
fn big() -> Vec<u8> {
    let mut state = 21u64;
    let words: Vec<[u8; 6]> = (0..4096)
        .map(|_| {
            (xorshift(&mut state) >> 8).to_le_bytes()[..6]
                .try_into()
                .unwrap()
        })
        .collect();
    let mut repeat = Vec::with_capacity(256 << 10);
    while repeat.len() < 256 << 10 {
        repeat.extend_from_slice(&words[(xorshift(&mut state) >> 20) as usize % words.len()]);
    }
    let mut out = text(9 << 19, 22);
    out.extend_from_slice(&repeat);
    out.extend_from_slice(&text((8 << 20) - out.len(), 24));
    out.extend_from_slice(&repeat);
    out.extend_from_slice(&text((9 << 20) - out.len(), 25));
    out
}

/// `rarfast a -s <switches> <name>.rar big.bin small.txt` in `dir`, with
/// `RARKIT_SOLID_DICT_2M` set to `keep` and `RARKIT_FAR_LINKS` to `far`,
/// or absent, answering the archive.
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
        .args(["a", "-s"])
        .args(switches)
        .args(["-y", "-idq", &archive, "big.bin", "small.txt"])
        .env_remove("RARKIT_SOLID_DICT_2M")
        .env_remove("RARKIT_L3_DICT_2M")
        .env_remove("RARKIT_FAR_LINKS");
    if let Some(value) = keep {
        run.env("RARKIT_SOLID_DICT_2M", value);
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
    // exit 0, so both streams are read; then its files are compared.
    let out = dir.join(format!("{name}.out"));
    std::fs::create_dir_all(&out).unwrap();
    if let Ok(read) = Command::new("unrar")
        .current_dir(&out)
        .args(["x", "-y", &format!("../{archive}")])
        .output()
    {
        let said = String::from_utf8_lossy(&read.stdout);
        let err = String::from_utf8_lossy(&read.stderr);
        assert!(
            read.status.success() && said.contains("All OK") && err.trim().is_empty(),
            "{name}: unrar x: {said} {err}"
        );
        for member in ["big.bin", "small.txt"] {
            assert!(
                std::fs::read(out.join(member)).unwrap()
                    == std::fs::read(dir.join(member)).unwrap(),
                "{name}: unrar wrote other bytes for {member}"
            );
        }
    }
    std::fs::remove_dir_all(&out).unwrap();
    std::fs::read(dir.join(&archive)).expect("the archive")
}

#[test]
fn rarfast_s_takes_32_mib_under_one_far_link_and_the_switch_keeps_2_mib() {
    let dir = std::env::temp_dir().join(format!("rarkit-soliddict-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("big.bin"), big()).unwrap();
    std::fs::write(dir.join("small.txt"), text(40_000, 26)).unwrap();

    // Every level, and `-m` left out (level 3).
    for (tag, level) in [
        ("m1", ["-m1"].as_slice()),
        ("m2", &["-m2"]),
        ("m3", &["-m3"]),
        ("m4", &["-m4"]),
        ("m5", &["-m5"]),
        ("plain", &[]),
    ] {
        let at = |name: &str, switches: &[&str], keep: Option<&str>, far: Option<&str>| {
            let mut all = level.to_vec();
            all.extend_from_slice(switches);
            create(&dir, &format!("{tag}{name}"), &all, keep, far)
        };
        let default = at("", &[], None, None);
        let named_32 = at("-md32m", &["-md32m"], None, Some("1"));
        let named_2 = at("-md2m", &["-md2m"], None, None);
        if tag == "m1" {
            // Level 1 keeps 2 MiB: the level picked for wall.
            assert!(default == named_2, "{tag}: the default is not -md2m");
        } else {
            assert!(
                default == named_32,
                "{tag}: the default is not -md32m under RARKIT_FAR_LINKS=1"
            );
            assert!(
                default.len() + (64 << 10) < named_2.len(),
                "{tag}: the default wrote {} bytes and -md2m {}: the repeat 3.5 MiB back was \
                 not reached",
                default.len(),
                named_2.len()
            );
        }

        // The switch: `1` on, anything else off.
        let kept = at("-kept", &[], Some("1"), None);
        assert!(kept == named_2, "{tag}: under the switch it is not -md2m");
        let not_one = at("-zero", &[], Some("0"), None);
        assert!(not_one == default, "{tag}: a switch of 0 turned it on");

        // A named dictionary wins over the default and over the switch.
        let named_4 = at("-md4m", &["-md4m"], None, None);
        let named_4_kept = at("-md4m-kept", &["-md4m"], Some("1"), None);
        assert!(named_4 == named_4_kept, "{tag}: the switch moved -md4m");
    }

    // A memory ceiling the caller NAMED keeps the 2 MiB archive.
    let ceiling = create(&dir, "mm", &["-m3", "-mm512m"], None, None);
    let ceiling_2 = create(&dir, "mm-md2m", &["-m3", "-mm512m", "-md2m"], None, None);
    assert!(ceiling == ceiling_2, "-s -mm512m is not -s -mm512m -md2m");
    std::fs::remove_dir_all(&dir).unwrap();
}
