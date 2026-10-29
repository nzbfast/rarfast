//! Extraction under a file size limit (SWEEP3-08OCT-19).
//!
//! With `ulimit -f` in force and the signal's default disposition, an
//! extraction that passed the limit was killed by `SIGXFSZ`: shell status
//! 153, nothing printed, and partial files of members never verified left
//! on disk. Measured against unrar 7.23 on a Mac on 9 Oct 2026 over the
//! sweep's archive (members of 340,000, 3,000,000 and 4,288,890 bytes,
//! `x -idq -o+` under `ulimit -f 2000`, stdin at end of file): `Write
//! error in the file <dir>/b.bin`, its Retry or Abort question, `Read
//! error in the file stdin`, exit 12, and only the first member left.
//! rarfast asks no question: it names the member with the system's
//! reason, removes what it wrote of it, leaves the first member whole and
//! exits 5, which is what it already did when the caller ignored the
//! signal.
//!
//! The archive is made here (three stored members, about 1.7 MiB). The
//! limit is set in a child shell, so this test's own process keeps its
//! own. `-mt2` and `-mt1`, the default memory policy.
#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn noise(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 11) as u8
        })
        .collect()
}

#[test]
fn a_write_past_the_file_size_limit_is_a_write_error_not_a_signal() {
    let dir = std::env::temp_dir().join(format!("rarfast-xfsz-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    let first = noise(1, 100_000);
    std::fs::write(dir.join("src/a.txt"), &first).unwrap();
    std::fs::write(dir.join("src/b.bin"), noise(2, 900_000)).unwrap();
    std::fs::write(dir.join("src/c.txt"), noise(3, 700_000)).unwrap();
    let made = Command::new(rarfast())
        .current_dir(dir.join("src"))
        .args(["a", "-idq", "-m0", "../a.rar", "a.txt", "b.bin", "c.txt"])
        .output()
        .unwrap();
    assert_eq!(made.status.code(), Some(0), "{made:?}");

    for width in ["-mt2", "-mt1"] {
        let _ = std::fs::remove_dir_all(dir.join("tx"));
        std::fs::create_dir_all(dir.join("tx")).unwrap();
        // 600 blocks, which a shell counts in 512 bytes or in 1024: the
        // limit is 307,200 or 614,400 bytes, above the first member and
        // below the other two either way. The signal's disposition is
        // put back to the default in the child, whatever this test's
        // parent had made of it.
        let script = format!(
            "trap - XFSZ; ulimit -f 600; exec \"{}\" x -idq -o+ {width} a.rar tx/",
            rarfast().display()
        );
        let out = Command::new("sh")
            .current_dir(&dir)
            .args(["-c", &script])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(5),
            "{width}: {:?} {stderr}",
            out.status
        );
        assert!(
            stderr.contains("Write error in the file tx/b.bin"),
            "{width}: {stderr}"
        );
        assert_eq!(
            std::fs::read(dir.join("tx/a.txt")).ok().as_ref(),
            Some(&first),
            "{width}: the member under the limit is whole"
        );
        for name in ["b.bin", "c.txt"] {
            let left = std::fs::metadata(dir.join("tx").join(name)).map(|m| m.len());
            assert!(
                !matches!(left, Ok(len) if len > 0),
                "{width}: {name} left with {left:?} bytes"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
