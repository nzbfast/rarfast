//! A RAR 5 file header whose attribute word has a bit above the low 32.
//!
//! THE RULE: the attributes of a member are the LOW 32 BITS of the word
//! its header carries (spec F 3.2.6 writes it as a variable length
//! number, which can hold more). The bits above them say nothing.
//!
//! Before 10 Oct 2026 a word that did not fit 32 bits was read as all
//! ones: `l` printed `ICADSHR` for a Windows member and `-rwsrwsrwt` for
//! a Unix one, and `x` gave the Unix file every permission with the
//! set-user-id and sticky bits.
//!
//! MEASURED against rar 7.23 and unrar 7.23 on macOS (arm64), 10 Oct
//! 2026, the archives below: each bit from 32 to 39 alone lists as seven
//! points (Windows) and ten hyphens (Unix), the same bits beside 0x20 and
//! beside 0o100644 list as those low words do alone, and `x` of the last
//! makes a file of mode 0644.
//!
//! Width and memory: every run states `-mt1`; a stored member of five
//! bytes, so the test needs no memory to speak of.

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../../rarkit/tests/redirection/rewrite.rs"]
mod rewrite;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// Stands watch over the directory one row of this file works in. The
/// row holds it beside the directory's path and never uses it; when it
/// is let go, at the row's end or because an assertion failed, the
/// directory is deleted.
struct DirWatch(PathBuf);

impl Drop for DirWatch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn work(tag: &str) -> (PathBuf, DirWatch) {
    let dir = std::env::temp_dir().join(format!("rarfast-wideattr-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    (dir.clone(), DirWatch(dir))
}

fn block(body: &[u8], out: &mut Vec<u8>) {
    let mut sized = rewrite::vint(body.len() as u64);
    sized.extend_from_slice(body);
    out.extend_from_slice(&rewrite::crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
}

/// A RAR 5 archive of one stored file `f` of five bytes, with this
/// attribute word and this host system (0 Windows, 1 Unix), built from
/// spec F 3.2.2 and 3.2.6.
fn archive(attributes: u64, host: u64) -> Vec<u8> {
    let data = b"hello";
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &mut out);
    let mut body = rewrite::vint(2);
    body.extend(rewrite::vint(0x2)); // a data area follows
    body.extend(rewrite::vint(data.len() as u64));
    body.extend(rewrite::vint(0x4)); // a CRC32 is present
    body.extend(rewrite::vint(data.len() as u64));
    body.extend(rewrite::vint(attributes));
    body.extend_from_slice(&rewrite::crc32(data).to_le_bytes());
    body.extend(rewrite::vint(0)); // stored
    body.extend(rewrite::vint(host));
    body.extend(rewrite::vint(1));
    body.push(b'f');
    block(&body, &mut out);
    out.extend_from_slice(data);
    block(&[5, 0, 0], &mut out);
    out
}

/// The attribute column `l` prints for the one member.
fn listed(dir: &Path, attributes: u64, host: u64) -> String {
    let path = dir.join("a.rar");
    std::fs::write(&path, archive(attributes, host)).unwrap();
    let done = Command::new(rarfast())
        .current_dir(dir)
        .args(["l", "-mt1", "a.rar"])
        .output()
        .unwrap();
    assert!(done.status.success(), "{attributes:#x}: {done:?}");
    let text = String::from_utf8_lossy(&done.stdout).into_owned();
    let line = text
        .lines()
        .find(|line| line.ends_with("  f"))
        .unwrap_or_else(|| panic!("{attributes:#x}: no line for the member in {text:?}"));
    line.split_whitespace().next().unwrap().to_owned()
}

#[test]
fn a_bit_above_32_says_nothing_in_a_listing() {
    let (dir, _watch) = work("list");
    for bit in 32..40 {
        let high = 1_u64 << bit;
        assert_eq!(listed(&dir, high, 0), ".......", "Windows, bit {bit}");
        assert_eq!(listed(&dir, high, 1), "----------", "Unix, bit {bit}");
        assert_eq!(
            listed(&dir, high | 0x20, 0),
            "..A....",
            "Windows, bit {bit}"
        );
        assert_eq!(
            listed(&dir, high | 0o100_644, 1),
            "-rw-r--r--",
            "Unix, bit {bit}"
        );
    }
    // The low words alone, which the rows above must equal.
    assert_eq!(listed(&dir, 0x20, 0), "..A....");
    assert_eq!(listed(&dir, 0o100_644, 1), "-rw-r--r--");
    // A word of 32 ones is itself.
    assert_eq!(listed(&dir, 0xffff_ffff, 0), "ICADSHR");
}

#[cfg(unix)]
#[test]
fn a_bit_above_32_gives_an_extracted_file_no_permission() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, _watch) = work("extract");
    std::fs::write(dir.join("a.rar"), archive((1 << 35) | 0o100_644, 1)).unwrap();
    let done = Command::new(rarfast())
        .current_dir(&dir)
        .args(["x", "-mt1", "a.rar", "out/"])
        .output()
        .unwrap();
    assert!(done.status.success(), "{done:?}");
    let mode = std::fs::metadata(dir.join("out/f"))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    // 0644 less whatever this process's mask takes away, and nothing more.
    assert_eq!(mode & !0o644, 0, "mode {mode:o}");
}
