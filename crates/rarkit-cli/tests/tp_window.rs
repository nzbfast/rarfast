//! `t` and `p` of a large STORED member say and print the same with the
//! wide read-ahead of a wide box on as with it off (2 Oct 2026).
//!
//! `RARFAST_TP_WINDOW` (the rule as shipped on Linux, off elsewhere) gives `t` and `p` a read-ahead of
//! 256 KiB for every lane of the read's width where that is more than the
//! shipped one, so a box of more than sixteen threads reads a stored member
//! in larger pieces under a deeper window (`wide_test_read_ahead`). The
//! rule (`on`) is for members of 4 GiB and more, which a test does not
//! write; `always` takes the deeper window for any member, so that is the
//! arm that reads this test's member under it. How
//! much FASTER is a timed question (measured 2 Oct 2026); what it
//! may not move is what `t` reports, the bytes `p` prints and the exit
//! code, for a sound member and for a damaged one, at the default width
//! and at a stated one.
//!
//! The member is over the wide read's floor (16 MiB), so the wide read is
//! really taken; the fixture is written by this crate's own `rar` dialect,
//! so nothing is needed on PATH.
//!
//! A shipped `rarfast` reads no environment word; the read path's exist only
//! under the feature `reader-knobs`, which this test builds with:
//!
//! ```text
//! cargo test -p rarkit-cli --features reader-knobs --test tp_window
//! ```
#![cfg(feature = "reader-knobs")]

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, tool_named};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-tpwin-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A copy of `rarfast` named `unrar`, which is how the binary picks that
/// dialect.
fn as_unrar(dir: &Path) -> PathBuf {
    let named = tool_named(dir, "unrar");
    copy_executable(&rarfast(), &named);
    named
}

/// 40 MiB that no two 4 KiB pages of share: a counter through a
/// multiplier, so a piece joined out of place changes the bytes.
fn payload() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(40 << 20);
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    while bytes.len() < 40 << 20 {
        x = x
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        bytes.extend_from_slice(&x.to_le_bytes());
    }
    bytes
}

struct Ran {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
}

fn run(binary: &Path, dir: &Path, args: &[&str], knob: Option<&str>) -> Ran {
    let mut command = Command::new(binary);
    command.args(args).current_dir(dir).env("TZ", "UTC");
    command.env_remove("RARFAST_TP_WINDOW");
    if let Some(value) = knob {
        command.env("RARFAST_TP_WINDOW", value);
    }
    let out =
        output_of(&mut command).unwrap_or_else(|err| panic!("{binary:?} could not be run: {err}"));
    Ran {
        code: out.status.code(),
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The archive of one stored member, and the member's bytes.
fn fixture(dir: &Path) -> (PathBuf, Vec<u8>) {
    let bytes = payload();
    std::fs::write(dir.join("member.bin"), &bytes).unwrap();
    let made = run(
        &rarfast(),
        dir,
        &["a", "-y", "-idq", "-m0", "-ep", "set.rar", "member.bin"],
        None,
    );
    assert_eq!(made.code, Some(0), "create: {}", made.stderr);
    (dir.join("set.rar"), bytes)
}

#[test]
fn a_sound_member_tests_and_prints_the_same_with_the_window_on() {
    let dir = work("sound");
    let unrar = as_unrar(&dir);
    let (_, bytes) = fixture(&dir);
    for width in [&[][..], &["-mt2"][..], &["-mt64"][..]] {
        let mut test = vec!["t", "-y"];
        test.extend_from_slice(width);
        test.push("set.rar");
        let off = run(&unrar, &dir, &test, None);
        assert_eq!(off.code, Some(0), "{width:?}: {}", off.stderr);
        let mut print = vec!["p", "-y", "-inul"];
        print.extend_from_slice(width);
        print.push("set.rar");
        let printed = run(&unrar, &dir, &print, None);
        assert_eq!(printed.code, Some(0), "{width:?}: {}", printed.stderr);
        assert!(
            printed.stdout == bytes,
            "{width:?}: p off prints the member"
        );
        for on in ["always", "on", "off"] {
            let ran = run(&unrar, &dir, &test, Some(on));
            assert_eq!(ran.code, off.code, "{width:?} {on}: {}", ran.stderr);
            assert!(ran.stdout == off.stdout, "{width:?} {on}: t says the same");
            assert_eq!(ran.stderr, off.stderr, "{width:?} {on}");
            let ran = run(&unrar, &dir, &print, Some(on));
            assert_eq!(ran.code, Some(0), "{width:?} {on}: {}", ran.stderr);
            assert!(ran.stdout == bytes, "{width:?} {on}: p prints the member");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_damaged_member_is_reported_the_same_with_the_window_on() {
    let dir = work("damaged");
    let unrar = as_unrar(&dir);
    let (archive, _) = fixture(&dir);
    // One byte of the member's data, well past its headers and into a
    // later piece of any plan.
    let mut raw = std::fs::read(&archive).unwrap();
    let at = raw.len() - (9 << 20);
    raw[at] ^= 0x40;
    std::fs::write(&archive, &raw).unwrap();
    for width in [&[][..], &["-mt64"][..]] {
        let mut test = vec!["t", "-y"];
        test.extend_from_slice(width);
        test.push("set.rar");
        let off = run(&unrar, &dir, &test, None);
        assert_ne!(off.code, Some(0), "{width:?}: the damage is seen");
        let on = run(&unrar, &dir, &test, Some("always"));
        assert_eq!(on.code, off.code, "{width:?}");
        assert!(on.stdout == off.stdout, "{width:?}: t says the same");
        assert_eq!(on.stderr, off.stderr, "{width:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
