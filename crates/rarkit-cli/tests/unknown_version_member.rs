//! A member whose version the engine does not know fails ALONE, in the
//! reference's words (spec F 3.2.6 and 3.3.5; decided
//! 28 Sep 2026).
//!
//! Until then a RAR 5 compressed member of an unknown compression version
//! failed the whole open (exit 10), and a RAR 4 member of any unpack
//! version above 29 was decoded as 2.9. The spec now reads 29 alone as the
//! RAR 2.9 decoder and refuses a COMPRESSED member of a version it does not
//! know, that member only; a stored member or a directory of any version
//! opens.
//!
//! unrar 7.23 (homebrew's, aarch64 macOS, 28 Sep 2026) on the genuine
//! rar 3.93 fixture `r393_m3.rar` with `BIG.TXT`'s unpack version (byte 24
//! of its header, the CRC recomputed) set to 36 or 99: stderr `Unknown
//! method in BIG.TXT` and `You may need a newer version of RAR.`, the other
//! eleven members `OK`, `Total errors: 2`, exit 2. The same words and exit
//! on a RAR 5 `-m3 -qo-` member rewritten to compression version 2 (5, 63
//! and `0x3d82` likewise), under `t` and under `x`, where the refused
//! member's file is not left behind.
//!
//! The reference prints no progress line for the member, and since 28 Sep
//! 2026 neither does rarkit; several such members are each named, in
//! `every_refused_member.rs`.

use std::path::PathBuf;
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "fixtures",
        "legacy",
        "archives",
        name,
    ]
    .iter()
    .collect();
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-unkver-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The RAR 1.5 to 4.x file header named `member`: its offset. Blocks are
/// CRC16, type, flags, size, and an added size after a file header or
/// wherever flag 0x8000 says so (spec F 3.3).
fn rar4_member(archive: &[u8], member: &[u8]) -> usize {
    let mut at = 7;
    while at + 7 <= archive.len() {
        let kind = archive[at + 2];
        let flags = u16::from_le_bytes([archive[at + 3], archive[at + 4]]);
        let size = usize::from(u16::from_le_bytes([archive[at + 5], archive[at + 6]]));
        let add = if kind == 0x74 || flags & 0x8000 != 0 {
            u32::from_le_bytes(archive[at + 7..at + 11].try_into().unwrap()) as usize
        } else {
            0
        };
        if kind == 0x74 {
            let len = usize::from(u16::from_le_bytes([archive[at + 26], archive[at + 27]]));
            if &archive[at + 32..at + 32 + len] == member {
                return at;
            }
        }
        at += size + add;
    }
    panic!("no member {}", String::from_utf8_lossy(member));
}

/// `name` from the fixtures with `member`'s unpack version set to
/// `version`, the header's CRC16 recomputed.
fn with_version(name: &str, member: &[u8], version: u8) -> Vec<u8> {
    let mut archive = fixture(name);
    let at = rar4_member(&archive, member);
    archive[at + 24] = version;
    let size = usize::from(u16::from_le_bytes([archive[at + 5], archive[at + 6]]));
    let crc = rarkit::checksum::crc32(&archive[at + 2..at + size]) as u16;
    archive[at..at + 2].copy_from_slice(&crc.to_le_bytes());
    archive
}

/// `rarfast <args>` in `dir`: exit code, stdout without the progress
/// redraws, stderr.
fn run(dir: &PathBuf, args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).replace('\u{8}', ""),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The members a progress line ends `OK` for.
fn oks(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter(|line| line.trim_end().ends_with("OK"))
        .filter_map(|line| line.split_whitespace().nth(1).map(str::to_owned))
        .collect()
}

#[test]
fn a_rar4_member_above_29_is_unknown_method_and_the_rest_extract() {
    for version in [36u8, 99] {
        let dir = work(&format!("r4-{version}"));
        std::fs::write(
            dir.join("a.rar"),
            with_version("r393_m3.rar", b"BIG.TXT", version),
        )
        .unwrap();

        let (code, stdout, stderr) = run(&dir, &["t", "a.rar"]);
        assert_eq!(code, Some(2), "{version}: {stdout}{stderr}");
        assert!(
            stderr.contains("Unknown method in BIG.TXT\nYou may need a newer version of RAR."),
            "{version}: {stderr}"
        );
        assert!(stdout.contains("Total errors: 2"), "{version}: {stdout}");
        // A refusal, not damage: the reference makes no checksum complaint.
        assert!(!stderr.contains("checksum error"), "{version}: {stderr}");
        let ok = oks(&stdout);
        assert_eq!(ok.len(), 11, "{version}: {stdout}");
        assert!(!ok.iter().any(|m| m == "BIG.TXT"), "{version}: {stdout}");

        let (code, stdout, stderr) = run(&dir, &["x", "-idq", "a.rar", "out/"]);
        assert_eq!(code, Some(2), "{version}: {stdout}{stderr}");
        assert!(!dir.join("out/BIG.TXT").exists(), "{version}");
        assert!(dir.join("out/HELLO.TXT").is_file(), "{version}");
        assert!(dir.join("out/SUB/NESTED/DEEP.TXT").is_file(), "{version}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A STORED member of an unknown version opens, its version ignored: no
/// codec runs (spec F 3.3.5; unrar 7.23 All OK, exit 0, at 30, 50, 200).
#[test]
fn a_rar4_stored_member_of_any_version_opens() {
    for version in [30u8, 50, 200] {
        let dir = work(&format!("r4s-{version}"));
        std::fs::write(
            dir.join("a.rar"),
            with_version("r420_m0.rar", b"BIG.TXT", version),
        )
        .unwrap();
        let (code, stdout, stderr) = run(&dir, &["t", "a.rar"]);
        assert_eq!(code, Some(0), "{version}: {stdout}{stderr}");
        assert!(stdout.contains("All OK"), "{version}: {stdout}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
