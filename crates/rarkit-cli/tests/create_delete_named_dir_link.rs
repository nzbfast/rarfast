//! Nothing is deleted or wiped through a directory link at or below the
//! folder the command runs in (SPEC-CLI section 8, K3 and K4; the
//! owner's rule of 27 Oct 2026), however the path behind it was named:
//! the link itself (`tree/dirlink`, `tree/dirlink/`), a mask through it
//! (`tree/dirlink/*`) or one file through it (`tree/dirlink/one.bin`).
//! What lies behind the link is archived and left; the link is removed
//! as a link, and the run says so in its one line. A linked folder ABOVE
//! the run (`/tmp` on macOS) is an ordinary path and is never refused.
//!
//! On 471661fda `a -df -r arc.rar tree/dirlink/` deleted every file
//! behind the link and answered 0 with nothing said; on 37f777cbc the
//! mask and the one-file forms still did.
//!
//! No case reaches past the one directory made for it: the "outside"
//! directory lies inside it, beside the tree. Each run is `-mt2` over a
//! few files of a few bytes: a pool two threads wide and a few KiB of
//! memory.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BYTES: &[u8] = b"KNOWN-BYTES-0123456789abcdef\n";

/// The one line a run prints when it left a link's target in place.
const LEFT: &str = "left in place";

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rarfast-delete-named-dir-link-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `tree/dirlink` leads to `outside`, a directory beside the tree holding
/// a file and a subdirectory with a second.
fn tree_with_a_directory_link(tag: &str) -> PathBuf {
    let dir = work(tag);
    std::fs::create_dir_all(dir.join("tree")).unwrap();
    std::fs::create_dir_all(dir.join("outside/sub")).unwrap();
    std::fs::write(dir.join("tree/own.bin"), BYTES).unwrap();
    std::fs::write(dir.join("outside/one.bin"), BYTES).unwrap();
    std::fs::write(dir.join("outside/sub/three.bin"), b"three\n").unwrap();
    std::os::unix::fs::symlink("../outside", dir.join("tree/dirlink")).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> (Option<i32>, String) {
    let done = Command::new(env!("CARGO_BIN_EXE_rarfast"))
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        done.status.code(),
        String::from_utf8_lossy(&done.stderr).into_owned(),
    )
}

fn gone(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_err()
}

/// Every way of naming what lies behind `tree/dirlink`, under `-df` and
/// `m`: nothing behind the link is deleted, the link is removed as a
/// link, and the one line is said once.
#[test]
fn nothing_behind_a_directory_link_is_deleted_however_it_is_named() {
    for command in [&["a", "-df"][..], &["m"]] {
        for name in ["dirlink", "dirlink/", "dirlink/*", "dirlink/one.bin"] {
            let tag = format!("{}{}", command.join(""), name.replace(['/', '*', '.'], "_"));
            let dir = tree_with_a_directory_link(&tag);
            let named = format!("tree/{name}");
            let mut args = command.to_vec();
            args.extend(["-r", "-idq", "-mt2", "arc.rar", &named]);
            let (code, stderr) = run(&dir, &args);
            let behind = [
                std::fs::read(dir.join("outside/one.bin")).ok(),
                std::fs::read(dir.join("outside/sub/three.bin")).ok(),
            ];
            let link_gone = gone(&dir.join("tree/dirlink"));
            let own = std::fs::read(dir.join("tree/own.bin")).ok();
            let _ = std::fs::remove_dir_all(&dir);
            assert_eq!(code, Some(0), "{command:?} {name}: {stderr}");
            assert_eq!(
                behind,
                [Some(BYTES.to_vec()), Some(b"three\n".to_vec())],
                "{command:?} {name}: a file behind the link was deleted ({stderr:?})"
            );
            assert!(link_gone, "{command:?} {name}: the link was left");
            assert_eq!(
                own,
                Some(BYTES.to_vec()),
                "{command:?} {name}: a file the run did not name was deleted"
            );
            assert_eq!(
                stderr.matches(LEFT).count(),
                1,
                "{command:?} {name}: the one line: {stderr:?}"
            );
        }
    }
}

/// The control: the command runs under a LEADING linked folder (`top`, a
/// link to `real`), as a run under `/tmp` does on macOS. A file named
/// below it, and one named by an absolute path spelled through it, are
/// ordinary paths and are deleted; nothing is said of a link.
#[test]
fn a_linked_folder_above_the_run_is_an_ordinary_path() {
    let dir = work("above");
    std::fs::create_dir_all(dir.join("real/tree")).unwrap();
    std::fs::write(dir.join("real/tree/a.bin"), BYTES).unwrap();
    std::fs::write(dir.join("real/tree/b.bin"), BYTES).unwrap();
    std::os::unix::fs::symlink("real", dir.join("top")).unwrap();
    let through = dir.join("top/tree/b.bin");
    let through = through.to_str().unwrap();
    let (code, stderr) = run(
        &dir.join("top"),
        &["a", "-df", "-idq", "-mt2", "arc.rar", "tree/a.bin", through],
    );
    let left = [
        dir.join("real/tree/a.bin").exists(),
        dir.join("real/tree/b.bin").exists(),
    ];
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(
        left,
        [false, false],
        "a file under the run was kept: {stderr:?}"
    );
    assert!(!stderr.contains(LEFT), "{stderr:?}");
}

/// An ordinary `-df -r` with no link anywhere deletes the whole tree.
#[test]
fn an_ordinary_delete_still_deletes() {
    let dir = work("plain");
    std::fs::create_dir_all(dir.join("tree/sub")).unwrap();
    std::fs::write(dir.join("tree/a.bin"), BYTES).unwrap();
    std::fs::write(dir.join("tree/sub/b.bin"), BYTES).unwrap();
    let (code, stderr) = run(&dir, &["a", "-df", "-r", "-idq", "-mt2", "arc.rar", "tree"]);
    let tree_gone = gone(&dir.join("tree"));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(tree_gone, "the tree was left: {stderr:?}");
    assert_eq!(stderr, "");
}
