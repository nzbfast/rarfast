//! The delete switches of the create side never touch anything through a
//! link, on Windows: a junction and a file symbolic link (SPEC-CLI section
//! 8, K1 to K4; `create_delete_links.rs` holds the Unix rows).
//!
//! Measured on a Windows 11 PC, 10 Oct 2026, before the mend and against
//! Rar.exe 7.23, which agree: with `tree\junc` a JUNCTION to a directory
//! beside the tree and `tree` named with `-r`, `a -dw`, `a -df` and `m`
//! all delete the files behind the junction and the subdirectory there,
//! exit 0; and `a -dw` of a file symbolic link leaves the file it points
//! at all zero (Rar.exe: of no bytes).
//!
//! CHOSEN DIFFERENCES from Rar.exe 7.23, on purpose: nothing behind a
//! junction is deleted and the junction itself is removed; a file link's
//! target keeps its bytes and the link is removed.
//!
//! A junction needs no privilege to make (`mklink /J`). A symbolic link
//! does, so the file link rows run where the account may make one and are
//! passed over, saying so, where it may not.
//!
//! Every tree is built in a temporary directory of the test's own, the
//! "outside" directory inside it too. Each run is `-mt2` over three files
//! of a few bytes: a pool two threads wide and a few KiB of memory.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BYTES: &[u8] = b"KNOWN-BYTES-0123456789abcdef\r\n";

/// The one line a run prints when it left a link's target in place.
const LEFT: &str = "left in place";

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rarfast-delete-links-win-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("outside").join("sub")).unwrap();
    std::fs::create_dir_all(dir.join("tree")).unwrap();
    std::fs::write(dir.join("outside").join("one.bin"), BYTES).unwrap();
    std::fs::write(dir.join("outside").join("sub").join("two.bin"), BYTES).unwrap();
    std::fs::write(dir.join("tree").join("own.bin"), BYTES).unwrap();
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

fn members(dir: &Path) -> Vec<String> {
    let listed = Command::new(env!("CARGO_BIN_EXE_rarfast"))
        .args(["lb", "arc.rar"])
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let mut names: Vec<String> = String::from_utf8_lossy(&listed.stdout)
        .lines()
        .map(|line| line.replace('\\', "/"))
        .collect();
    names.sort_unstable();
    names
}

fn gone(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_err()
}

fn once(text: &str) -> bool {
    text.lines().filter(|line| line.contains(LEFT)).count() == 1
}

/// A junction to a directory beside the named tree, `-dw`, `-df` and `m`
/// under `-r`: the files behind it are intact, the junction is removed as
/// itself and the tree with it, the one line is printed, exit 0.
#[test]
fn nothing_behind_a_junction_is_deleted() {
    for command in [&["a", "-dw"][..], &["a", "-df"], &["m"]] {
        let dir = work(&format!("junc{}", command.join("")));
        let made = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(dir.join("tree").join("junc"))
            .arg(dir.join("outside"))
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(made.status.success(), "the junction was not made: {made:?}");
        let mut args = command.to_vec();
        args.extend(["-r", "-idq", "-mt2", "arc.rar", "tree"]);
        let (code, stderr) = run(&dir, &args);
        assert_eq!(code, Some(0), "{command:?}: {stderr}");
        assert_eq!(
            std::fs::read(dir.join("outside").join("one.bin")).unwrap(),
            BYTES,
            "{command:?}"
        );
        assert_eq!(
            std::fs::read(dir.join("outside").join("sub").join("two.bin")).unwrap(),
            BYTES,
            "{command:?}"
        );
        assert!(gone(&dir.join("tree")), "{command:?}: the tree was left");
        // What the walk stored is not changed by the rule.
        assert_eq!(
            members(&dir),
            [
                "tree",
                "tree/junc",
                "tree/junc/one.bin",
                "tree/junc/sub",
                "tree/junc/sub/two.bin",
                "tree/own.bin",
            ],
            "{command:?}"
        );
        assert!(once(&stderr), "{command:?}: the one line: {stderr:?}");
        assert!(!stderr.contains("Cannot delete"), "{command:?}: {stderr:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A file symbolic link to a file beside the tree, `-dw`, `-df` and `m`:
/// the file keeps its bytes, the link is removed, the one line is
/// printed, exit 0. Passed over where the account may not make a link.
#[test]
fn a_file_link_s_target_keeps_its_bytes() {
    for command in [&["a", "-dw"][..], &["a", "-df"], &["m"]] {
        let dir = work(&format!("file{}", command.join("")));
        let link = dir.join("link.bin");
        if std::os::windows::fs::symlink_file(dir.join("outside").join("one.bin"), &link).is_err() {
            eprintln!("passed over: this account may not make a symbolic link");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let mut args = command.to_vec();
        args.extend(["-idq", "-mt2", "arc.rar", "link.bin"]);
        let (code, stderr) = run(&dir, &args);
        assert_eq!(code, Some(0), "{command:?}: {stderr}");
        assert_eq!(
            std::fs::read(dir.join("outside").join("one.bin")).unwrap(),
            BYTES,
            "{command:?}"
        );
        assert!(gone(&link), "{command:?}: the link was left");
        assert_eq!(members(&dir), ["link.bin"], "{command:?}");
        assert!(once(&stderr), "{command:?}: the one line: {stderr:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
