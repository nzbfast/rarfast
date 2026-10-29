//! `x -o+` over a symbolic link that stands at a member's path, on
//! Windows.
//!
//! The member replaces the LINK, never what the link points at (spec F
//! 3.8.2), as it does on Unix, where the overwriting open refuses a link
//! at the final component. On Windows that open carried no such
//! protection: it went through the link, and the member's bytes truncated
//! and replaced the link's target, a file outside the destination.
//!
//! Windows only, and only where this user may create a symbolic link
//! (the privilege, or developer mode): without it the test SAYS so and
//! passes, having tested nothing.
//!
//! Each run states its width, `-mt1` or `-mt4`; the archive is one small
//! member, so no memory to speak of.
#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;

use rarkit::{HostOs, MemberSpec, Payload, WriteOptions, Writer};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

#[test]
fn an_overwrite_replaces_a_link_and_never_writes_through_it() {
    for width in ["-mt1", "-mt4"] {
        let dir = std::env::temp_dir().join(format!(
            "rarfast-winoverwrite-{}-{}",
            std::process::id(),
            width.trim_start_matches('-')
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("o")).unwrap();
        let victim = dir.join("important.doc");
        std::fs::write(&victim, b"precious").unwrap();
        let link = dir.join("o").join("report.txt");
        if let Err(err) = std::os::windows::fs::symlink_file(&victim, &link) {
            eprintln!("this user may not create a symbolic link ({err}): skipped");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        let mut writer = Writer::new(WriteOptions::default()).expect("options");
        writer
            .add(MemberSpec {
                name: b"report.txt",
                payload: Payload::Bytes(b"the member's own bytes"),
                mtime: None,
                attributes: 0o100_644,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
        let mut bytes = Vec::new();
        writer.finish_into(&mut bytes).expect("finish");
        std::fs::write(dir.join("a.rar"), bytes).unwrap();

        let done = Command::new(rarfast())
            .current_dir(&dir)
            .args(["x", "-o+", "-idq", width, "a.rar", "o\\"])
            .output()
            .unwrap();
        assert_eq!(done.status.code(), Some(0), "{width}: {done:?}");
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"precious",
            "{width}: the link's target was written through the link"
        );
        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(
            meta.is_file() && !meta.file_type().is_symlink(),
            "{width}: the member's path is still a link"
        );
        assert_eq!(
            std::fs::read(&link).unwrap(),
            b"the member's own bytes",
            "{width}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
