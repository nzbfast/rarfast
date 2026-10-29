//! A switch whose text is not ASCII is refused, never a panic, under the
//! name `rarfast` too (`dialect/rar/args.rs`).
//!
//! The rar dialect's parser, which reads the switches first when the
//! binary runs under its own name, split the text after the dash at byte
//! 1, inside a multibyte character: a Rust panic and exit 101. MEASURED
//! against rar 7.23 and unrar 7.23 on macOS (arm64), 4 Oct 2026:
//! `-\u{e9}`, `-\u{20ac}` and `-t\u{e9}` are each `ERROR: Unknown option`
//! on standard output, exit 7, and nothing is listed, extracted or
//! written. rarfast under its own name answers the first two the same
//! way; `-t` and a character it does not know it reads as it reads
//! `-tq`, without a panic.
//!
//! The unrar dialect's half of this is `tests/unrar_switch_bytes.rs`.
//!
//! Each run states `-mt1`; the archive is one small member, so no memory
//! to speak of.

use std::path::PathBuf;
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// This parser's own split: a switch that OPENS with such a character,
/// on a creating command, which no other parser reads.
#[test]
fn a_create_refuses_a_switch_that_opens_with_a_character_that_is_not_ascii() {
    refused(&["a"], false);
}

/// Every row. A listing and an extraction hand their switches on to the
/// unrar dialect's parser, and so does this one for a `-t` it does not
/// know, so these rows need that parser's half as well
/// (`tests/unrar_switch_bytes.rs`).
#[test]
fn a_switch_that_is_not_ascii_is_refused_and_never_a_panic_under_rarfasts_own_name() {
    refused(&["lb", "x", "a"], true);
}

fn refused(words: &[&str], inner: bool) {
    let dir = std::env::temp_dir().join(format!(
        "rarfast-rar-switch-bytes-{}-{inner}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("one.txt"), "one").unwrap();
    let made = Command::new(rarfast())
        .current_dir(&dir)
        .args(["a", "-mt1", "-idq", "a.rar", "one.txt"])
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    // Grown only where a command line can carry a byte that is no UTF-8.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut switches: Vec<std::ffi::OsString> = vec!["-\u{e9}".into(), "-\u{20ac}".into()];
    if inner {
        switches.push("-t\u{e9}".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        switches.push(std::ffi::OsString::from_vec(b"-\xff".to_vec()));
        if inner {
            switches.push(std::ffi::OsString::from_vec(b"-t\xff".to_vec()));
        }
    }
    for switch in &switches {
        for word in words {
            let target = if *word == "a" { "b.rar" } else { "a.rar" };
            let done = Command::new(rarfast())
                .current_dir(&dir)
                .args([word, "-mt1"])
                .arg(switch)
                .arg(target)
                .arg("one.txt")
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap();
            let said = String::from_utf8_lossy(&done.stdout);
            if switch.to_string_lossy().starts_with("-t") {
                // `-t` and a character it does not know is refused on
                // a create (`tests/rar_followup_sweep.rs`) and NOT yet
                // on a listing or an extraction under this name, which
                // the unrar dialect's parser reads first and passes,
                // `-tq` as these (rar 7.23 says `Unknown option`, exit
                // 7, measured; that half is owed and is not this
                // test's). What is pinned for every word is that the
                // run ends as a run and not as a panic.
                let warned = String::from_utf8_lossy(&done.stderr);
                assert_ne!(done.status.code(), Some(101), "{word} {switch:?}");
                assert!(!warned.contains("panicked"), "{word} {switch:?}: {warned}");
                continue;
            }
            // The refusal is on standard output, as the reference's is.
            assert_eq!(done.status.code(), Some(7), "{word} {switch:?}: {done:?}");
            assert!(
                said.contains("ERROR: Unknown option"),
                "{word} {switch:?}: {said}"
            );
            assert!(!said.contains("one.txt"), "{word} {switch:?}: {said}");
            assert!(done.stderr.is_empty(), "{word} {switch:?}: {done:?}");
        }
        if !switch.to_string_lossy().starts_with("-t") {
            assert!(!dir.join("b.rar").exists(), "{switch:?} wrote an archive");
        }
        let _ = std::fs::remove_file(dir.join("b.rar"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}
