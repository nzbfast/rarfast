//! A RAR 4 link REFUSED before its `open` (no decoder claims its method)
//! is never left unwritten under a success report: asked for, whole or
//! by name, the run fails with exit 2 and no `All OK`; NOT asked for, it
//! is none of the run's failures and the run exits 0, the members it was
//! asked for written. Plain and solid alike.
//!
//! MEASURED against reference unrar 7.23 run whole on macOS, 28 Oct 2026,
//! over the same archives: exit 2 whole and by name (`Unknown method in
//! sym_rel`), exit 0 and `All OK` with only `a.txt` named, plain and
//! solid. This pins the D2 follow-up as REFUTED: the library counts such
//! a link when the sink skips it and carries no failure for it, and the
//! sink skips it only when it was not asked for.
//!
//! The archive is the committed `links4.rar` (genuine Linux rar 4.2.0,
//! `crates/rarkit/tests/redirection/make.sh`) with `sym_rel`'s unpack
//! version set to 5 and its method to 0x33, its header CRC16 recomputed
//! (spec F 3.3: the low half of the CRC32 over the header from its type
//! byte), and for the solid rows the main header's solid flag set too.
//!
//! Unix only: the archive's other members are links. Width and memory:
//! each run states `-mt1` or `-mt4`; the archive is a few hundred bytes.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Restamps the header at `pos`, `size` bytes long.
fn stamp(archive: &mut [u8], pos: usize, size: usize) {
    let crc = (crc32(&archive[pos + 2..pos + size]) & 0xFFFF) as u16;
    archive[pos..pos + 2].copy_from_slice(&crc.to_le_bytes());
}

/// `links4.rar` with `sym_rel` refused, and solid where asked.
fn refused_link(solid: bool) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rarkit/tests/redirection/links4.rar");
    let mut archive = std::fs::read(&path).unwrap();
    let mut pos = 7;
    loop {
        let kind = archive[pos + 2];
        let flags = u16::from_le_bytes([archive[pos + 3], archive[pos + 4]]);
        let size = usize::from(u16::from_le_bytes([archive[pos + 5], archive[pos + 6]]));
        assert_ne!(kind, 0x7B, "no sym_rel in {}", path.display());
        let add = if kind == 0x74 || flags & 0x8000 != 0 {
            u32::from_le_bytes(archive[pos + 7..pos + 11].try_into().unwrap()) as usize
        } else {
            0
        };
        if kind == 0x73 && solid {
            archive[pos + 3] |= 0x08;
            stamp(&mut archive, pos, size);
        }
        if kind == 0x74 {
            let len = usize::from(u16::from_le_bytes([archive[pos + 26], archive[pos + 27]]));
            if &archive[pos + 32..pos + 32 + len] == b"sym_rel" {
                archive[pos + 24] = 5;
                archive[pos + 25] = 0x33;
                stamp(&mut archive, pos, size);
                return archive;
            }
        }
        pos += size + add;
    }
}

/// A scratch directory per row, removed when dropped.
struct Work(PathBuf);

impl Work {
    fn new(tag: &str, archive: &[u8]) -> Work {
        let dir =
            std::env::temp_dir().join(format!("rarfast-r4refused-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("o")).unwrap();
        std::fs::write(dir.join("a.rar"), archive).unwrap();
        Work(dir)
    }

    fn run(&self, cmd: &str, width: &str, named: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_rarfast"))
            .current_dir(&self.0)
            .args([cmd, "-y", width, "a.rar"])
            .args(named)
            .arg("o/")
            .output()
            .unwrap()
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_refused_rar4_link_is_never_unwritten_under_a_success_report() {
    for solid in [false, true] {
        let archive = refused_link(solid);
        for cmd in ["x", "e"] {
            for width in ["-mt1", "-mt4"] {
                let rows: [(&[&str], i32); 3] = [(&[], 2), (&["sym_rel"], 2), (&["a.txt"], 0)];
                for (named, exit) in rows {
                    let tag = format!("{solid}-{cmd}{width}-{}", named.join(""));
                    let work = Work::new(&tag, &archive);
                    let done = work.run(cmd, width, named);
                    let stdout = String::from_utf8_lossy(&done.stdout);
                    assert_eq!(done.status.code(), Some(exit), "{tag}: {done:?}");
                    assert_eq!(stdout.contains("All OK"), exit == 0, "{tag}: {stdout}");
                    assert!(
                        std::fs::symlink_metadata(work.0.join("o/sym_rel")).is_err(),
                        "{tag}: the refused link was made"
                    );
                    if exit == 0 {
                        assert_eq!(
                            std::fs::read(work.0.join("o/a.txt")).unwrap().len(),
                            10,
                            "{tag}"
                        );
                    }
                }
            }
        }
    }
}
