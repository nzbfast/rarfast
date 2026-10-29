//! A lone small member is read on a pool of one at the default width, and
//! a member of exactly 4 MiB is one (FROM-STUDIO 454 B).
//!
//! Counted 15 Oct 2026 on an Apple M5 Max: before this, `t` and `x` of
//! one member of 1 MiB made 18 threads at the default width where `-mt1`
//! made one, 1.8M to 7.5M instructions more. The session's options asked
//! the engine for its read width before the walk sized the pool, which
//! built rayon's global pool at one thread a core, so the walk's pool of
//! one was never built; and a member of exactly 4 MiB was not taken as
//! small (`size < LONE_MEMBER_MAX`).
//!
//! It reads `RARFAST_POOL_SAY=1`, which only an `h2-probes` build says
//! (`workers::build`): whether the walk's own call built the pool, and
//! how wide. Any box width; a few MiB of disk and memory.

#![cfg(feature = "h2-probes")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-one-member-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A stored one member archive of `size` bytes, `name`.rar in `dir`.
fn archive(dir: &Path, name: &str, size: usize) {
    let src = dir.join(name);
    std::fs::create_dir_all(&src).unwrap();
    let mut state = 0x2026_1015_u64;
    let bytes: Vec<u8> = (0..size)
        .map(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (state >> 56) as u8
        })
        .collect();
    std::fs::write(src.join("member.bin"), bytes).unwrap();
    let made = Command::new(rarfast())
        .args([
            "a",
            "-idq",
            "-y",
            "-m0",
            &format!("../{name}.rar"),
            "member.bin",
        ])
        .current_dir(&src)
        .output()
        .unwrap();
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    std::fs::remove_dir_all(&src).unwrap();
}

/// The pool lines `args` said, run in `dir`.
fn said(dir: &Path, args: &[&str]) -> String {
    let out = Command::new(rarfast())
        .args(args)
        .env("RARFAST_POOL_SAY", "1")
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|line| line.starts_with("rarfast pool:") || line.starts_with("rarfast read:"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn a_lone_small_member_builds_a_pool_of_one_at_the_default_width() {
    let dir = work("pool");
    let max = 4 << 20;
    for (name, size) in [("one", 1 << 20), ("edge", max), ("over", max + 1)] {
        archive(&dir, name, size);
        let rar = format!("{name}.rar");
        let out = format!("out-{name}/");
        for args in [
            vec!["t", "-idq", rar.as_str()],
            vec!["x", "-idq", "-o+", rar.as_str(), out.as_str()],
        ] {
            let pool = said(&dir, &args);
            if size <= max {
                assert_eq!(
                    pool,
                    "rarfast pool: asked 1 serial true built true width 1\n\
                     rarfast read: width 1",
                    "{size} bytes, {args:?}"
                );
            } else {
                // Past the bound the member is not small, and being one
                // clear stored member it takes the idle pool (FROM-STUDIO
                // 518 C): serial too, but read at the box's width, which
                // `tests/idle_pool.rs` pins against a pool that is built.
                assert!(
                    pool.starts_with(
                        "rarfast pool: asked 1 serial true built true width 1\n\
                         rarfast read: width "
                    ),
                    "{size} bytes, {args:?}: {pool:?}"
                );
            }
        }
    }
    // A stated width is the run's, small member or not.
    let pool = said(&dir, &["t", "-idq", "-mt1", "one.rar"]);
    assert_eq!(
        pool,
        "rarfast pool: asked 1 serial false built true width 1\nrarfast read: width 1"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
