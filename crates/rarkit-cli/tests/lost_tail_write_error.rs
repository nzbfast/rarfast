//! A big member whose LAST bytes cannot be written is a write error.
//!
//! Sweep H-1 (and M-12, the same defect), 4 Oct 2026. A member of 64 MiB
//! or more is written past the OS cache on Linux and Windows, in whole
//! sectors, and what is left under a sector (or under a staging block)
//! was written only when the file handle was dropped, with the error
//! discarded and the file then set to the member's length. The engine's
//! checksum is over the bytes it HANDED to the writer, so the member's
//! line ended `OK` and the run said `All OK`, exit 0, over a file whose
//! tail had not been written.
//!
//! The row: one stored member of 64 MiB, three sectors and 1,536 bytes,
//! extracted under a file size limit 512 bytes short of it. Every whole
//! sector fits; the tail does not. What a write error gets on the cached
//! path is what this must get (`walk_error_settles.rs`, measured there
//! against unrar 7.23): no `OK` on the member's line, `Write error in the
//! file <path>` on stderr, exit 5, and the partial file removed.
//!
//! **Where it bites.** On a target with no past-the-cache open (macOS)
//! and on a tmpfs, the member is written cached and this row passed
//! before the fix too. It fails on the parent on Linux over ext4 or xfs.
//!
//! **Windows has no form of this row, and here is what stands in its
//! place.** There is no file size limit a process can be started under
//! there, and the only other way to fail the last cluster's write is a
//! volume that is full to that cluster, which needs an elevated disk tool
//! and a drive letter: not a thing a test does to the machine it runs on.
//! So on Windows the defect is held by the unit test beside `TimedFile`
//! (`extract/output.rs`, `lost_tail`), which runs on every system at the
//! depth Windows ships, and it was proved end to end once, by hand, on a
//! Windows 11 PC (4 Oct 2026, NTFS, this same member, a 200 MB volume
//! file filled until only the member's whole sectors fit): the parent
//! binary said `OK`, `All OK`, exit 0 over a file 13,824 bytes short of
//! the member; this one says `Write error in the file`, `There is not
//! enough space on the disk.`, exit 5, and leaves no file. With one
//! cluster more free both write the member whole.
//!
//! The limit is set in a child shell, as `walk_error_settles.rs` sets
//! its own and for its reason. `ulimit -f` counts 512 byte blocks in a
//! POSIX shell and 1024 byte blocks in plain bash, so the unit is
//! MEASURED first.
//!
//! Assumes: a thread pool 1 and 2 wide (`-mt1`, `-mt2`, stated on each
//! run; hosted runners are 2 to 4 wide), about 80 MiB of memory (the
//! payload, held once to write it), and 200 MiB of scratch.

// Unix only by its nature: the write is cut short by `ulimit -f` in a Unix
// shell.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-losttail-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 64 MiB, three sectors and 1,536 bytes: the last 1,536 are the tail.
const LEN: usize = (64 << 20) + 3 * 4096 + 1536;

/// The limit: 512 bytes short of the member, inside its last sector, and
/// a whole number of either block.
const LIMIT: usize = LEN - 512;

/// Bytes that do not repeat at a sector's period.
fn payload() -> Vec<u8> {
    let mut state = 0x9e37_79b9_u32;
    (0..LEN)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

/// `sh -c <script> <args>` in `dir`, with `SIGXFSZ` ignored so that a
/// write over the limit fails with `EFBIG`.
fn limited(dir: &Path, blocks: usize, args: &[&str]) -> std::process::Output {
    let out = Command::new("/bin/sh")
        .current_dir(dir)
        .arg("-c")
        .arg(format!(
            "trap '' XFSZ; ulimit -f {blocks} || exit 99; exec \"$0\" \"$@\""
        ))
        .args(args)
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(99), "the shell refused the limit");
    out
}

/// The bytes one `ulimit -f` block is, here: 16 blocks let 8,192 or
/// 16,384 bytes of a larger write through.
fn block(dir: &Path) -> usize {
    let _ = limited(
        dir,
        16,
        &["/bin/sh", "-c", "head -c 65536 /dev/zero > unit.probe"],
    );
    let len = std::fs::metadata(dir.join("unit.probe")).unwrap().len() as usize;
    let _ = std::fs::remove_file(dir.join("unit.probe"));
    assert!(
        len == 8192 || len == 16384,
        "16 blocks let {len} bytes through"
    );
    len / 16
}

#[test]
fn a_big_member_whose_tail_cannot_be_written_is_a_write_error() {
    let dir = work("row");
    std::fs::write(dir.join("big.bin"), payload()).unwrap();
    let made = Command::new(rarfast())
        .current_dir(&dir)
        .args(["a", "-idq", "-m0", "-mt1", "-ep", "arc.rar", "big.bin"])
        .output()
        .unwrap();
    assert_eq!(
        made.status.code(),
        Some(0),
        "building the archive: {made:?}"
    );
    std::fs::remove_file(dir.join("big.bin")).unwrap();
    let blocks = LIMIT / block(&dir);
    let bin = rarfast();
    for width in ["-mt1", "-mt2"] {
        let out = limited(
            &dir,
            blocks,
            &[bin.to_str().unwrap(), "x", width, "-o+", "arc.rar", "out/"],
        );
        let stdout = String::from_utf8_lossy(&out.stdout).replace('\u{8}', "");
        let stderr = String::from_utf8_lossy(&out.stderr);
        let said = format!("{width}\nstdout:\n{stdout}\nstderr:\n{stderr}");
        let kept = std::fs::metadata(dir.join("out/big.bin")).map(|m| m.len());
        assert!(
            !stdout.lines().any(|line| {
                line.starts_with("Extracting  ") && line.trim_end().ends_with("OK")
            }),
            "a member short of its tail (on disk: {kept:?}) was reported OK: {said}"
        );
        assert!(!stdout.contains("All OK"), "{said}");
        assert!(
            stderr.contains("Write error in the file out/big.bin"),
            "{said}"
        );
        assert_eq!(out.status.code(), Some(5), "{said}");
        assert!(kept.is_err(), "the partial file was kept: {kept:?}\n{said}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
