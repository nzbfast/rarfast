//! The delete switches of the create side never touch anything through a
//! link (SPEC-CLI section 8, K1 to K5).
//!
//! Until 10 Oct 2026 `a -dw arc.rar link`, with `link` a symbolic link to
//! another file, wrote zeros over the file the link points at and then
//! removed only the link; made a read-only target writable through the
//! link; and under `-r` a directory link was walked into and the files
//! behind it were wiped or deleted, by `-dw`, `-df` and `m` alike. A tree
//! holding a link and its own target ended half deleted, exit 0.
//!
//! CHOSEN DIFFERENCES from rar 7.23 (measured 10 Oct 2026 on an Apple
//! silicon Mac, section 8.1 R1, R3 and R5), each on purpose:
//!
//! - rar's `-dw` leaves a link's target a file of no bytes. Here the link
//!   is removed as the link it is and the target keeps its bytes (K2).
//! - rar changes a 0444 target's mode through the link. Here the mode is
//!   left (K1).
//! - rar deletes the files reached through a directory link under `-r`.
//!   Here nothing behind the link is touched and the link itself is
//!   removed (K3).
//!
//! What the archive holds is not changed by any of this: the walk still
//! follows links, so a link's target is stored under the link's name. The
//! run says so in one line (K4).
//!
//! No case reaches past the one directory made for it:
//! the "outside" file or directory of a case lies inside that directory
//! too, beside the tree that is named. Each run is `-mt2` over a few files
//! of a few bytes: a pool two threads wide and a few KiB of memory.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BYTES: &[u8] = b"KNOWN-BYTES-0123456789abcdef\n";

/// The one line a run prints when it left a link's target in place.
const LEFT: &str = "left in place";

fn work(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("rarfast-delete-links-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Done {
    code: Option<i32>,
    stderr: String,
}

fn run(dir: &Path, args: &[&str]) -> Done {
    let done = Command::new(env!("CARGO_BIN_EXE_rarfast"))
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    Done {
        code: done.status.code(),
        stderr: String::from_utf8_lossy(&done.stderr).into_owned(),
    }
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
        .map(str::to_owned)
        .collect();
    names.sort_unstable();
    names
}

/// The bytes the archive holds under `name`.
fn stored(dir: &Path, name: &str) -> Vec<u8> {
    let printed = Command::new(env!("CARGO_BIN_EXE_rarfast"))
        .args(["p", "-inul", "arc.rar", name])
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    printed.stdout
}

fn gone(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_err()
}

fn once(text: &str) -> bool {
    text.matches(LEFT).count() == 1 && text.lines().filter(|l| l.contains(LEFT)).count() == 1
}

/// (a) `a -dw arc.rar link`: the link goes, the target keeps its bytes.
/// rar 7.23 leaves the target a file of no bytes.
#[test]
fn a_wipe_of_a_link_leaves_the_file_it_points_at() {
    let dir = work("a");
    std::fs::write(dir.join("target.bin"), BYTES).unwrap();
    std::os::unix::fs::symlink("target.bin", dir.join("link")).unwrap();
    let done = run(&dir, &["a", "-dw", "-idq", "-mt2", "arc.rar", "link"]);
    assert_eq!(done.code, Some(0), "{}", done.stderr);
    assert_eq!(std::fs::read(dir.join("target.bin")).unwrap(), BYTES);
    assert!(gone(&dir.join("link")), "the link was left");
    assert_eq!(members(&dir), ["link"]);
    assert_eq!(stored(&dir, "link"), BYTES);
    assert!(once(&done.stderr), "the one line: {:?}", done.stderr);
    let _ = std::fs::remove_dir_all(&dir);
}

/// (b) `a -df arc.rar link`: the same end state, which was already so and
/// is the reference's too (R2); the line is new.
#[test]
fn a_delete_of_a_link_leaves_the_file_it_points_at() {
    let dir = work("b");
    std::fs::write(dir.join("target.bin"), BYTES).unwrap();
    std::os::unix::fs::symlink("target.bin", dir.join("link")).unwrap();
    let done = run(&dir, &["a", "-df", "-idq", "-mt2", "arc.rar", "link"]);
    assert_eq!(done.code, Some(0), "{}", done.stderr);
    assert_eq!(std::fs::read(dir.join("target.bin")).unwrap(), BYTES);
    assert!(gone(&dir.join("link")));
    assert_eq!(stored(&dir, "link"), BYTES);
    assert!(once(&done.stderr), "the one line: {:?}", done.stderr);
    let _ = std::fs::remove_dir_all(&dir);
}

/// (c) A tree holding a link and its own target, `-dw -r`: both are paths
/// of the named tree and both go, and the tree with them. Until the mend
/// the target went first, the wipe of the then dangling link failed, the
/// link and the tree stayed, and the run still answered 0. The target is
/// a path of the tree in its own right and was wiped as itself, so no
/// target was left in place and the line is not printed.
#[test]
fn a_tree_holding_a_link_and_its_target_is_removed_whole() {
    for switch in ["-dw", "-df"] {
        let dir = work(&format!("c{switch}"));
        std::fs::create_dir(dir.join("tree")).unwrap();
        std::fs::write(dir.join("tree/target.bin"), BYTES).unwrap();
        std::os::unix::fs::symlink("target.bin", dir.join("tree/link")).unwrap();
        let done = run(
            &dir,
            &["a", switch, "-r", "-idq", "-mt2", "arc.rar", "tree"],
        );
        assert_eq!(done.code, Some(0), "{switch}: {}", done.stderr);
        assert!(gone(&dir.join("tree")), "{switch}: the tree was left");
        assert_eq!(members(&dir), ["tree", "tree/link", "tree/target.bin"]);
        assert_eq!(stored(&dir, "tree/link"), BYTES, "{switch}");
        assert_eq!(stored(&dir, "tree/target.bin"), BYTES, "{switch}");
        assert!(
            !done.stderr.contains("Cannot delete"),
            "{switch}: {:?}",
            done.stderr
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// (d) A link in the named tree to a file OUTSIDE it, `-dw -r`: the
/// outside file keeps its bytes; the link and the tree go. rar 7.23
/// empties the outside file.
#[test]
fn a_wipe_leaves_a_file_outside_the_named_tree() {
    let dir = work("d");
    std::fs::create_dir(dir.join("tree")).unwrap();
    std::fs::create_dir(dir.join("outside")).unwrap();
    std::fs::write(dir.join("outside/target.bin"), BYTES).unwrap();
    std::os::unix::fs::symlink("../outside/target.bin", dir.join("tree/link")).unwrap();
    let done = run(&dir, &["a", "-dw", "-r", "-idq", "-mt2", "arc.rar", "tree"]);
    assert_eq!(done.code, Some(0), "{}", done.stderr);
    assert_eq!(
        std::fs::read(dir.join("outside/target.bin")).unwrap(),
        BYTES
    );
    assert!(gone(&dir.join("tree")));
    assert_eq!(stored(&dir, "tree/link"), BYTES);
    assert!(once(&done.stderr), "the one line: {:?}", done.stderr);
    let _ = std::fs::remove_dir_all(&dir);
}

/// (e) `-ol` with `-dw`: refused by name before anything is written, as it
/// was (K5): exit 2, no archive, link and target as they were, and no word
/// of bytes left in place, since none were stored. rar 7.23 stores the
/// link alone and empties its target, whose bytes are then nowhere.
#[test]
fn ol_with_a_wipe_is_refused_and_touches_nothing() {
    let dir = work("e");
    std::fs::write(dir.join("target.bin"), BYTES).unwrap();
    std::os::unix::fs::symlink("target.bin", dir.join("link")).unwrap();
    let done = run(&dir, &["a", "-ol", "-dw", "-mt2", "arc.rar", "link"]);
    assert_eq!(done.code, Some(2), "{}", done.stderr);
    assert!(done.stderr.contains("`-ol`"), "{:?}", done.stderr);
    assert!(
        done.stderr.contains("arc.rar was not touched"),
        "{:?}",
        done.stderr
    );
    assert!(!done.stderr.contains(LEFT), "{:?}", done.stderr);
    assert_eq!(std::fs::read(dir.join("target.bin")).unwrap(), BYTES);
    assert!(std::fs::symlink_metadata(dir.join("link"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(gone(&dir.join("arc.rar")));
    let _ = std::fs::remove_dir_all(&dir);
}

/// (f) A link to a READ-ONLY file, `-dw`, `-df` and `m`: the target keeps
/// its bytes and its mode. rar 7.23 leaves it mode 0700 under all three
/// (R3), and empty under `-dw`.
#[test]
fn a_read_only_target_keeps_its_bytes_and_its_mode() {
    for command in [&["a", "-dw"][..], &["a", "-df"], &["m"]] {
        let dir = work(&format!("f{}", command.join("")));
        std::fs::write(dir.join("target.bin"), BYTES).unwrap();
        std::fs::set_permissions(
            dir.join("target.bin"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        std::os::unix::fs::symlink("target.bin", dir.join("link")).unwrap();
        let mut args = command.to_vec();
        args.extend(["-idq", "-mt2", "arc.rar", "link"]);
        let done = run(&dir, &args);
        assert_eq!(done.code, Some(0), "{command:?}: {}", done.stderr);
        assert_eq!(
            std::fs::read(dir.join("target.bin")).unwrap(),
            BYTES,
            "{command:?}"
        );
        let mode = std::fs::metadata(dir.join("target.bin"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o444, "{command:?}");
        assert!(gone(&dir.join("link")), "{command:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The tree of (g) and (h): `tree/dirlink` leads to `outside`, a directory
/// beside the tree holding two files and a subdirectory with a third.
fn tree_with_a_directory_link(tag: &str) -> PathBuf {
    let dir = work(tag);
    std::fs::create_dir(dir.join("tree")).unwrap();
    std::fs::create_dir_all(dir.join("outside/sub")).unwrap();
    std::fs::write(dir.join("tree/own.bin"), BYTES).unwrap();
    std::fs::write(dir.join("outside/one.bin"), BYTES).unwrap();
    std::fs::write(dir.join("outside/two.bin"), b"two\n").unwrap();
    std::fs::write(dir.join("outside/sub/three.bin"), b"three\n").unwrap();
    std::os::unix::fs::symlink("../outside", dir.join("tree/dirlink")).unwrap();
    dir
}

fn nothing_behind_the_directory_link_is_touched(command: &[&str]) {
    let dir = tree_with_a_directory_link(&format!("gh{}", command.join("")));
    let mut args = command.to_vec();
    args.extend(["-r", "-idq", "-mt2", "arc.rar", "tree"]);
    let done = run(&dir, &args);
    assert_eq!(done.code, Some(0), "{command:?}: {}", done.stderr);
    assert_eq!(
        std::fs::read(dir.join("outside/one.bin")).unwrap(),
        BYTES,
        "{command:?}"
    );
    assert_eq!(
        std::fs::read(dir.join("outside/two.bin")).unwrap(),
        b"two\n",
        "{command:?}"
    );
    assert_eq!(
        std::fs::read(dir.join("outside/sub/three.bin")).unwrap(),
        b"three\n",
        "{command:?}"
    );
    // The link is removed as a link, and with it gone the tree is empty
    // and goes too.
    assert!(gone(&dir.join("tree")), "{command:?}: the tree was left");
    // What the walk stored is not changed by the rule.
    assert_eq!(
        members(&dir),
        [
            "tree",
            "tree/dirlink",
            "tree/dirlink/one.bin",
            "tree/dirlink/sub",
            "tree/dirlink/sub/three.bin",
            "tree/dirlink/two.bin",
            "tree/own.bin",
        ],
        "{command:?}"
    );
    assert_eq!(stored(&dir, "tree/dirlink/one.bin"), BYTES, "{command:?}");
    assert!(
        once(&done.stderr),
        "{command:?}: the one line: {:?}",
        done.stderr
    );
    assert!(
        !done.stderr.contains("Cannot delete"),
        "{command:?}: {:?}",
        done.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// (g) A directory link to an outside directory, `-dw -r`. rar 7.23 wipes
/// and removes every file behind the link.
#[test]
fn a_wipe_does_not_go_through_a_directory_link() {
    nothing_behind_the_directory_link_is_touched(&["a", "-dw"]);
}

/// (h) The same under `-df` and `m`. rar 7.23 deletes the files behind the
/// link and leaves the link.
#[test]
fn a_delete_does_not_go_through_a_directory_link() {
    nothing_behind_the_directory_link_is_touched(&["a", "-df"]);
    nothing_behind_the_directory_link_is_touched(&["m"]);
}

/// `mf` moves files only and leaves every directory: a directory link is
/// left as the directory it stands for, and nothing behind it is touched.
#[test]
fn mf_leaves_a_directory_link_and_what_is_behind_it() {
    let dir = tree_with_a_directory_link("mf");
    let done = run(&dir, &["mf", "-r", "-idq", "-mt2", "arc.rar", "tree"]);
    assert_eq!(done.code, Some(0), "{}", done.stderr);
    assert_eq!(std::fs::read(dir.join("outside/one.bin")).unwrap(), BYTES);
    assert_eq!(
        std::fs::read(dir.join("outside/sub/three.bin")).unwrap(),
        b"three\n"
    );
    assert!(std::fs::symlink_metadata(dir.join("tree/dirlink"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(gone(&dir.join("tree/own.bin")));
    assert!(once(&done.stderr), "the one line: {:?}", done.stderr);
    let _ = std::fs::remove_dir_all(&dir);
}

/// (i) `m arc.rar link`, the link's target in another directory: the link
/// goes and the target is left, as it was and as the reference leaves it.
#[test]
fn a_move_of_a_link_leaves_the_file_it_points_at() {
    let dir = work("i");
    std::fs::create_dir(dir.join("outside")).unwrap();
    std::fs::write(dir.join("outside/target.bin"), BYTES).unwrap();
    std::os::unix::fs::symlink("outside/target.bin", dir.join("link")).unwrap();
    let done = run(&dir, &["m", "-idq", "-mt2", "arc.rar", "link"]);
    assert_eq!(done.code, Some(0), "{}", done.stderr);
    assert_eq!(
        std::fs::read(dir.join("outside/target.bin")).unwrap(),
        BYTES
    );
    assert!(gone(&dir.join("link")));
    assert_eq!(stored(&dir, "link"), BYTES);
    assert!(once(&done.stderr), "the one line: {:?}", done.stderr);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A run that deletes no link says nothing of one.
#[test]
fn a_run_with_no_link_prints_no_such_line() {
    let dir = work("plain");
    std::fs::create_dir(dir.join("tree")).unwrap();
    std::fs::write(dir.join("tree/a.bin"), BYTES).unwrap();
    let done = run(&dir, &["a", "-dw", "-r", "-idq", "-mt2", "arc.rar", "tree"]);
    assert_eq!(done.code, Some(0), "{}", done.stderr);
    assert_eq!(done.stderr, "");
    assert!(gone(&dir.join("tree")));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A delete that FAILS is not exit 0 (since 10 Oct 2026): a directory
/// that may not be written keeps its file, the run says so and answers 1.
/// Skipped for root, who may write any directory. A directory kept only
/// because it holds paths the run did not archive still answers 0, as
/// the reference does (`create_exclude_include_masks`).
#[test]
fn a_delete_that_fails_is_not_exit_zero() {
    let dir = work("fail");
    std::fs::create_dir(dir.join("tree")).unwrap();
    std::fs::write(dir.join("tree/a.bin"), BYTES).unwrap();
    std::fs::set_permissions(dir.join("tree"), std::fs::Permissions::from_mode(0o555)).unwrap();
    let refused = std::fs::write(dir.join("tree/probe"), b"").is_err();
    if refused {
        let done = run(&dir, &["a", "-df", "-r", "-idq", "-mt2", "arc.rar", "tree"]);
        assert!(done.stderr.contains("Cannot delete"), "{:?}", done.stderr);
        assert_eq!(done.code, Some(1), "{}", done.stderr);
        assert!(dir.join("tree/a.bin").exists());
    }
    std::fs::set_permissions(dir.join("tree"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
