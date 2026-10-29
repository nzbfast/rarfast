//! A Unix symbolic link whose target is written with backslashes, extracted
//! for real on Windows (spec F 3.8.2).
//!
//! Windows reads `\` as a separator in a link's content whatever kind the
//! archive says the link is, so a Unix link stored as `..\..\x` or `C:\x`
//! leaves the destination there. It is skipped with the reference's words
//! and counted (exit 1), and nothing is created in its place. An earlier
//! revision split a Unix link's target on `/` only, judged these safe and
//! created them.
//!
//! Windows only: on every other host these targets are one name each, and
//! `links.rs` pins both readings in a unit test that runs everywhere.
//!
//! Width and memory: each run states `-mt1` or `-mt4`; the archives hold
//! no data area, so the test needs no memory to speak of and passes on a
//! runner two threads wide.
#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;

#[path = "../../rarkit/tests/redirection/rewrite.rs"]
mod rewrite;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// A stored RAR 5 archive of Unix symbolic links, one per `(name,
/// target)`, built from spec F 3.2.2, 3.2.6 and 3.2.6.2 as
/// `redirection.rs` builds its own.
fn unix_links(links: &[(&[u8], &[u8])]) -> Vec<u8> {
    fn block(body: &[u8], out: &mut Vec<u8>) {
        let mut sized = rewrite::vint(body.len() as u64);
        sized.extend_from_slice(body);
        out.extend_from_slice(&rewrite::crc32(&sized).to_le_bytes());
        out.extend_from_slice(&sized);
    }
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &mut out);
    for (name, target) in links {
        let extra = rewrite::area(&[(5, rewrite::redirect(1, 0, target))]);
        let mut body = rewrite::vint(2); // file header
        body.extend(rewrite::vint(0x0001)); // an extra area, no data area
        body.extend(rewrite::vint(extra.len() as u64));
        body.extend(rewrite::vint(0x0004)); // CRC32 present
        body.extend(rewrite::vint(0)); // unpacked size
        body.extend(rewrite::vint(0o120_777)); // a symbolic link's mode
        body.extend_from_slice(&rewrite::crc32(b"").to_le_bytes());
        body.extend(rewrite::vint(0)); // stored
        body.extend(rewrite::vint(1)); // Unix
        body.extend(rewrite::vint(name.len() as u64));
        body.extend_from_slice(name);
        body.extend(extra);
        block(&body, &mut out);
    }
    block(&[5, 0, 0], &mut out);
    out
}

#[test]
fn a_unix_link_with_a_backslash_target_cannot_leave_the_destination() {
    let links: [(&[u8], &[u8]); 4] = [
        (b"climb", b"..\\..\\..\\Users\\victim"),
        (b"drive", b"C:\\Windows\\System32"),
        (b"d/mixed", b"..\\..\\x"),
        (b"rooted", b"\\Windows"),
    ];
    let archive = unix_links(&links);
    for width in ["-mt1", "-mt4"] {
        let dir = std::env::temp_dir().join(format!(
            "rarfast-winlinks-{}-{}",
            std::process::id(),
            width.trim_start_matches('-')
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("o")).unwrap();
        std::fs::write(dir.join("a.rar"), &archive).unwrap();
        let done = Command::new(rarfast())
            .current_dir(&dir)
            .args(["x", "-y", width, "a.rar", "o\\"])
            .output()
            .unwrap();
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&done.stdout),
            String::from_utf8_lossy(&done.stderr)
        );
        // Skipped and counted, never attempted: without the privilege to
        // create links an attempt would end in exit 9 instead.
        assert_eq!(done.status.code(), Some(1), "{width}: {said}");
        assert!(said.contains("Total errors: 4"), "{width}: {said}");
        for (name, target) in &links {
            let name = String::from_utf8_lossy(name);
            let target = String::from_utf8_lossy(target);
            assert!(
                said.contains(&format!("-> {target} link.")),
                "{width}: {name}: {said}"
            );
            let at = dir.join("o").join(name.replace('/', "\\"));
            assert!(
                std::fs::symlink_metadata(&at).is_err(),
                "{width}: {name} was created: {said}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
