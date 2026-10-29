//! A switch whose text is not ASCII is refused, never a panic (`args.rs`).
//!
//! The unrar dialect's parser split the text after the dash at byte 1,
//! and its `-t` arm at byte 1 of its tail, inside a multibyte character:
//! a Rust panic and exit 101. MEASURED against unrar 7.23 on macOS
//! (arm64), 4 Oct 2026: `-\u{e9}`, `-\u{20ac}` and `-t\u{e9}` are each
//! `ERROR: Unknown option` on standard output, exit 7, and nothing is
//! listed.
//!
//! Run through a copy of the binary named `unrar`, which is how it picks
//! that dialect and its parser.
//!
//! Each run states `-mt1`; the archive is one small member, so no memory
//! to speak of.

use std::process::Command;

use rarkit::{HostOs, MemberSpec, Payload, WriteOptions, Writer};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

#[test]
fn a_switch_that_is_not_ascii_is_refused_and_never_a_panic() {
    let dir = std::env::temp_dir().join(format!("rarfast-switch-bytes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let unrar = dir.join(if cfg!(windows) { "unrar.exe" } else { "unrar" });
    copy_executable(&rarfast(), &unrar);
    let archive = dir.join("a.rar");
    {
        let mut writer = Writer::new(WriteOptions::default()).expect("options");
        writer
            .add(MemberSpec {
                name: b"one.txt",
                payload: Payload::Bytes(b"one"),
                mtime: None,
                attributes: 0o100_644,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
        let mut bytes = Vec::new();
        writer.finish_into(&mut bytes).expect("finish");
        std::fs::write(&archive, bytes).unwrap();
    }
    // Grown only where a command line can carry a byte that is no UTF-8.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut switches: Vec<std::ffi::OsString> = ["-\u{e9}", "-\u{20ac}", "-t\u{e9}"]
        .iter()
        .map(Into::into)
        .collect();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        switches.push(std::ffi::OsString::from_vec(b"-\xff".to_vec()));
        switches.push(std::ffi::OsString::from_vec(b"-t\xff".to_vec()));
    }
    for switch in &switches {
        let done = output_of(
            Command::new(&unrar)
                .args(["lb", "-mt1"])
                .arg(switch)
                .arg(&archive),
        )
        .unwrap();
        // The refusal is on standard output, as the reference's is.
        let said = String::from_utf8_lossy(&done.stdout);
        assert_eq!(done.status.code(), Some(7), "{switch:?}: {done:?}");
        assert!(said.contains("ERROR: Unknown option"), "{switch:?}: {said}");
        assert!(!said.contains("one.txt"), "{switch:?}: {said}");
        assert!(done.stderr.is_empty(), "{switch:?}: {done:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
