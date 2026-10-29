//! A wrong password must never cost the caller a file this run did not
//! write.
//!
//! Found on 25 Sep 2026 in the multivolume-hp correctness work:
//! `rarfast t -p<wrong> arc.rar` DELETED a file in the current directory
//! that shared a name with an archive member, because the dialect's
//! wrong-password cleanup removed the member's target in every mode, and
//! in `t` that target resolves against the current directory. The rows
//! below pin the fix: in `t` nothing is removed, in `x` only a file this
//! run created and wrote is removed, and a correct password still
//! extracts.
//!
//! **Which archives reach the defect.** A RAR 5 `-p` archive carries a
//! password check value, so a wrong password is refused before the walk
//! and no member ever fails on its own key. A RAR 4 archive has no check
//! value (SPEC-K), so the wrong key is found only when the member's
//! checksum fails, and that is the arm that removed files. The reference
//! `rar` 4.2.0 fixtures `r420_pw` and `r420_hp` are therefore the rows
//! that fail on the code as it stood; the rarkit-written RAR 5 rows pin
//! that the check-value path stays as it was.

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-wrongpw-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// What a rarkit-written member holds, and what sits under a member's
/// name before a run. Different lengths, so no accident makes them equal.
const MEMBER: &[u8] = b"the archived member, which a wrong password must not reveal\n";
const BYSTANDER: &[u8] = b"a file the caller owns\n";

/// One archive under test: how it is put in place as `arc.rar`, and the
/// switch that opens it.
struct Case {
    tag: &'static str,
    place: fn(&Path),
    right: &'static str,
}

fn rarkit_written(dir: &Path, lock: &str) {
    std::fs::write(dir.join("data.txt"), MEMBER).unwrap();
    // `-m3` so the key reaches a decoder, not only a stored copy.
    let (code, _) = run(dir, &["a", "-y", "-m3", lock, "arc.rar", "data.txt"]);
    assert_eq!(code, Some(0));
    std::fs::remove_file(dir.join("data.txt")).unwrap();
}

fn legacy(dir: &Path, name: &str) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/legacy/archives")
        .join(name);
    std::fs::copy(source, dir.join("arc.rar")).unwrap();
}

const CASES: [Case; 4] = [
    Case {
        tag: "rarkit-p",
        place: |dir| rarkit_written(dir, "-prightpass"),
        right: "-prightpass",
    },
    Case {
        tag: "rarkit-hp",
        place: |dir| rarkit_written(dir, "-hprightpass"),
        right: "-prightpass",
    },
    Case {
        tag: "r420-p",
        place: |dir| legacy(dir, "r420_pw.rar"),
        right: "-pSecret",
    },
    Case {
        tag: "r420-hp",
        place: |dir| legacy(dir, "r420_hp.rar"),
        right: "-pSecret",
    },
];

const WRONG: &str = "-pwrongpass";

/// The FILE members of `arc.rar` in `dir`: every name `lb` prints that is
/// not the directory of another. A listed name carries the system's
/// separator, so that is what ends a directory's name here.
fn file_members(dir: &Path, right: &str) -> Vec<String> {
    let (code, listing) = run(dir, &["lb", right, "arc.rar"]);
    assert_eq!(code, Some(0));
    let names: Vec<String> = listing.lines().map(str::to_owned).collect();
    let files: Vec<String> = names
        .iter()
        .filter(|name| {
            let prefix = format!("{name}{}", std::path::MAIN_SEPARATOR);
            !names.iter().any(|other| other.starts_with(&prefix))
        })
        .cloned()
        .collect();
    assert!(!files.is_empty());
    files
}

/// Puts a caller's own file under every member's name, beneath `root`.
fn plant(root: &Path, files: &[String]) {
    for name in files {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, BYSTANDER).unwrap();
    }
}

fn assert_untouched(root: &Path, files: &[String], tag: &str, what: &str) {
    for name in files {
        assert_eq!(
            std::fs::read(root.join(name)).ok().as_deref(),
            Some(BYSTANDER),
            "{tag}: {what} removed or changed {name}, a file it never wrote"
        );
    }
}

#[test]
fn test_with_a_wrong_password_leaves_a_same_named_cwd_file_alone() {
    for case in CASES {
        let dir = work(&format!("t-{}", case.tag));
        (case.place)(&dir);
        let files = file_members(&dir, case.right);
        plant(&dir, &files);
        let (code, _) = run(&dir, &["t", WRONG, "arc.rar"]);
        assert_ne!(code, Some(0), "{}: a wrong password must fail", case.tag);
        assert_untouched(&dir, &files, case.tag, "`t`");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn extract_never_overwrite_with_a_wrong_password_leaves_an_existing_file_alone() {
    for case in CASES {
        let dir = work(&format!("xo-{}", case.tag));
        (case.place)(&dir);
        let files = file_members(&dir, case.right);
        plant(&dir.join("out"), &files);
        let _ = run(&dir, &["x", "-o-", WRONG, "arc.rar", "out/"]);
        assert_untouched(&dir.join("out"), &files, case.tag, "`x -o-`");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn extract_with_a_wrong_password_leaves_no_partial_file() {
    for case in CASES {
        let dir = work(&format!("x-{}", case.tag));
        (case.place)(&dir);
        let files = file_members(&dir, case.right);
        let (code, _) = run(&dir, &["x", "-y", WRONG, "arc.rar", "out/"]);
        assert_ne!(code, Some(0), "{}: a wrong password must fail", case.tag);
        // A zero-length member needs no key and is written whatever the
        // password; anything with bytes in it is what the key protected.
        for name in &files {
            // An empty directory member lists like a file, and is made.
            let left = std::fs::metadata(dir.join("out").join(name))
                .ok()
                .filter(std::fs::Metadata::is_file)
                .map_or(0, |m| m.len());
            assert_eq!(
                left, 0,
                "{}: a wrong password left a partial {name}",
                case.tag
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn extract_with_the_right_password_still_extracts() {
    for case in CASES {
        let dir = work(&format!("ok-{}", case.tag));
        (case.place)(&dir);
        let files = file_members(&dir, case.right);
        let (code, _) = run(&dir, &["x", "-y", case.right, "arc.rar", "out/"]);
        assert_eq!(code, Some(0), "{}", case.tag);
        for name in &files {
            // An empty directory member lists like a file; either will do.
            assert!(dir.join("out").join(name).exists(), "{}: {name}", case.tag);
        }
        if case.tag.starts_with("rarkit") {
            assert_eq!(
                std::fs::read(dir.join("out/data.txt")).ok().as_deref(),
                Some(MEMBER),
                "{}",
                case.tag
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
