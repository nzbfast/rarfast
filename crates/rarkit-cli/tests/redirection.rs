//! `x`, `e` and `t` over symbolic links, hard links and file copies (spec F
//! 3.8, normative for this dialect; the acceptance rows of 3.8.9).
//!
//! The archives are `crates/rarkit/tests/redirection/`, written by
//! reference rar 7.23 and genuine rar 4.2.0 (`make.sh` there); rows no
//! Linux writer produces are rewritten from them by `rewrite.rs` beside
//! them. Each test names its row and what reference unrar 7.23 did,
//! MEASURED on x86-64 Linux on 27 Sep 2026; where rarfast deliberately
//! differs (spec F question 14) the test says so and pins the difference.

#![cfg(unix)]

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "../../rarkit/tests/redirection/rewrite.rs"]
mod rewrite;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rarkit/tests/redirection")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// A scratch directory of its own per test and width, holding the archive
/// under `a.rar` and the output under `o/`.
struct Work {
    dir: PathBuf,
}

impl Work {
    fn new(tag: &str, archive: &[u8]) -> Work {
        let dir = std::env::temp_dir().join(format!("rarfast-redir-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("o")).unwrap();
        std::fs::write(dir.join("a.rar"), archive).unwrap();
        Work { dir }
    }

    fn out(&self) -> PathBuf {
        self.dir.join("o")
    }

    /// `rarfast <args> a.rar [members] o/` from inside the scratch, so the
    /// progress lines and messages read `o/...` as the reference's did.
    fn run(&self, cmd: &str, switches: &[&str], members: &[&str]) -> Output {
        let mut c = Command::new(rarfast());
        c.current_dir(&self.dir)
            .arg(cmd)
            .args(switches)
            .arg("a.rar")
            .args(members);
        if cmd != "t" {
            c.arg("o/");
        }
        c.output().unwrap()
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const WIDTHS: [&str; 2] = ["-mt1", "-mt4"];

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Every entry of `root` as the reference tree listings were taken: kind,
/// relative path, link content. Sorted.
fn tree(root: &Path) -> Vec<String> {
    fn walk(root: &Path, at: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(at).unwrap() {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(root).unwrap().display().to_string();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path).unwrap();
                out.push(format!("l {rel} -> {}", target.display()));
            } else if meta.is_dir() {
                out.push(format!("d {rel}"));
                walk(root, &path, out);
            } else {
                out.push(format!("f {rel}"));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn lines(expected: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = expected.iter().map(|s| (*s).to_owned()).collect();
    v.sort();
    v
}

fn skipping(name: &str, target: &str) -> String {
    format!(
        "Skipping the potentially unsafe {name} -> {target} link. For archives from a trustworthy \
         source use -ola to extract it anyway."
    )
}

/// The tree reference unrar 7.23 left from `x -y links5.rar o/`.
const LINKS5_SAFE: [&str; 15] = [
    "d d",
    "d d/e",
    "f a.txt",
    "f hard_a",
    "f top.txt",
    "l backslash -> d\\f.txt",
    "l d/e/up_in2 -> ../../top.txt",
    "l d/up_in -> ../top.txt",
    "l dotslash -> ./top.txt",
    "l junc_abs -> \\??\\C:\\x",
    "l junc_rel -> d",
    "l sym_dangling -> nothere",
    "l sym_dir -> d",
    "l sym_rel -> a.txt",
    "l win_abs -> C:\\x\\a.txt",
];

/// 3.8.2's safety table, `x` at the default: the safe links are created as
/// links, verbatim and unfollowed (a dangling one too), the five unsafe
/// ones skipped with the reference's words, counted, exit 1. The hard link
/// shares the inode of the file this run wrote (3.8.4).
#[test]
fn x_creates_safe_links_and_skips_unsafe_ones_as_the_reference_does() {
    let archive = fixture_bytes("links5.rar");
    for width in WIDTHS {
        let work = Work::new(&format!("links-x{width}"), &archive);
        let done = work.run("x", &["-y", width], &[]);
        assert_eq!(code(&done), 1, "{width}: {done:?}");
        assert_eq!(tree(&work.out()), lines(&LINKS5_SAFE), "{width}");
        let err = stderr(&done);
        for (name, target) in [
            ("d/up_out", "../../top.txt"),
            ("sym_abs", "/etc/hostname"),
            ("dotdot_mid", "d/../top.txt"),
            ("sym_up", "../../escape"),
            ("dotdot_only", ".."),
        ] {
            assert!(
                err.contains(&skipping(name, target)),
                "{width}: {name} in {err}"
            );
        }
        assert!(
            String::from_utf8_lossy(&done.stdout).contains("Total errors: 5"),
            "{width}"
        );
        let a = std::fs::metadata(work.out().join("a.txt")).unwrap();
        let hard = std::fs::metadata(work.out().join("hard_a")).unwrap();
        assert_eq!(
            (a.ino(), a.nlink()),
            (hard.ino(), 2),
            "{width}: hard_a is a.txt"
        );
        assert_eq!(
            std::fs::read(work.out().join("hard_a")).unwrap(),
            b"a-content\n"
        );
    }
}

/// `-ola` creates every link as stored, "All OK"; `-ol-` skips every
/// symbolic link silently and still makes the hard link (3.8.2).
#[test]
fn ola_creates_every_link_and_ol_minus_skips_them_all() {
    let archive = fixture_bytes("links5.rar");
    for width in WIDTHS {
        let work = Work::new(&format!("links-ola{width}"), &archive);
        let done = work.run("x", &["-y", "-ola", width], &[]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        let got = tree(&work.out());
        for link in [
            "l d/up_out -> ../../top.txt",
            "l dotdot_mid -> d/../top.txt",
            "l dotdot_only -> ..",
            "l sym_abs -> /etc/hostname",
            "l sym_up -> ../../escape",
        ] {
            assert!(got.contains(&link.to_owned()), "{width}: {link} in {got:?}");
        }
        assert_eq!(got.len(), 20, "{width}: {got:?}");

        let work = Work::new(&format!("links-oln{width}"), &archive);
        let done = work.run("x", &["-y", "-ol-", width], &[]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        assert!(stderr(&done).is_empty(), "{width}: {}", stderr(&done));
        assert_eq!(
            tree(&work.out()),
            lines(&["d d", "d d/e", "f a.txt", "f hard_a", "f top.txt"]),
            "{width}"
        );
    }
}

/// Depth is the OUTPUT path's: under `e` the reference also skipped
/// `d/up_in` and `d/e/up_in2`, whose `..` climbs out once flattened.
#[test]
fn e_judges_a_link_by_its_flattened_depth() {
    let archive = fixture_bytes("links5.rar");
    for width in WIDTHS {
        let work = Work::new(&format!("links-e{width}"), &archive);
        let done = work.run("e", &["-y", width], &[]);
        assert_eq!(code(&done), 1, "{width}: {done:?}");
        assert_eq!(
            tree(&work.out()),
            lines(&[
                "f a.txt",
                "f hard_a",
                "f top.txt",
                "l backslash -> d\\f.txt",
                "l dotslash -> ./top.txt",
                "l junc_abs -> \\??\\C:\\x",
                "l junc_rel -> d",
                "l sym_dangling -> nothere",
                "l sym_dir -> d",
                "l sym_rel -> a.txt",
                "l win_abs -> C:\\x\\a.txt",
            ]),
            "{width}"
        );
        let err = stderr(&done);
        assert!(err.contains(&skipping("d/up_in", "../top.txt")), "{width}");
        assert!(
            err.contains(&skipping("d/e/up_in2", "../../top.txt")),
            "{width}"
        );
    }
}

/// 3.8.8: `t` checks the record and its checksum and nothing on any disk;
/// a link skipped as unsafe by `x` tests OK, as in the reference.
#[test]
fn t_tests_every_redirection_member_ok() {
    for archive in [
        "links5.rar",
        "copies5.rar",
        "solid5.rar",
        "blake5.rar",
        "links4.rar",
    ] {
        let bytes = fixture_bytes(archive);
        for width in WIDTHS {
            let work = Work::new(&format!("t-{archive}{width}"), &bytes);
            let done = work.run("t", &[width], &[]);
            assert_eq!(code(&done), 0, "{archive} {width}: {done:?}");
            assert!(
                String::from_utf8_lossy(&done.stdout).contains("All OK"),
                "{archive}"
            );
        }
    }
    let bytes = fixture_bytes("crypt5.rar");
    let work = Work::new("t-crypt", &bytes);
    let done = work.run("t", &["-predir"], &[]);
    assert_eq!(code(&done), 0, "{done:?}");
}

/// 3.8.5: `x` of the whole archive makes independent files with the
/// target's bytes and inodes of their own; `e` flattens `e/big3` beside
/// `big1` and copies it from there.
#[test]
fn a_file_copy_is_an_independent_copy_of_its_targets_bytes() {
    let archive = fixture_bytes("copies5.rar");
    for width in WIDTHS {
        let work = Work::new(&format!("copies-x{width}"), &archive);
        let done = work.run("x", &["-y", width], &[]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        let big1 = std::fs::read(work.out().join("big1")).unwrap();
        assert_eq!(big1.len(), 300_000);
        for copy in ["big2", "e/big3"] {
            let path = work.out().join(copy);
            assert_eq!(std::fs::read(&path).unwrap(), big1, "{width}: {copy}");
            assert_eq!(
                std::fs::metadata(&path).unwrap().nlink(),
                1,
                "{width}: {copy}"
            );
        }

        let work = Work::new(&format!("copies-e{width}"), &archive);
        let done = work.run("e", &["-y", width], &[]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        assert_eq!(
            std::fs::read(work.out().join("big3")).unwrap(),
            std::fs::read(work.out().join("big1")).unwrap()
        );
    }
}

/// 3.8.5 and question 14 (c): a copy whose target is not selected is FILLED
/// from the target's decode. The reference agrees for a name selection (it
/// extracts the source to a temporary and removes it; only `big2` remains)
/// and REFUSES under `-x` (exit 6, "You need to unpack the entire archive to
/// create file reference entries."): the recommendation, adopted, differs
/// there, and this pins it.
#[test]
fn a_copy_of_an_unselected_target_is_filled_from_its_decode() {
    let archive = fixture_bytes("copies5.rar");
    let big1 = {
        let work = Work::new("copies-ref", &archive);
        work.run("x", &["-y"], &["big1"]);
        std::fs::read(work.out().join("big1")).unwrap()
    };
    for width in WIDTHS {
        let work = Work::new(&format!("copies-sel{width}"), &archive);
        let done = work.run("x", &["-y", width], &["big2"]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        assert_eq!(tree(&work.out()), lines(&["f big2"]), "{width}");
        assert_eq!(
            std::fs::read(work.out().join("big2")).unwrap(),
            big1,
            "{width}"
        );

        // DIFFERS from the reference, which exits 6 here (question 14 (c)).
        let work = Work::new(&format!("copies-xbig1{width}"), &archive);
        let done = work.run("x", &["-y", "-xbig1", width], &[]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        assert_eq!(
            tree(&work.out()),
            lines(&["d e", "f big2", "f e/big3", "f s.txt"]),
            "{width}"
        );
        assert_eq!(
            std::fs::read(work.out().join("e/big3")).unwrap(),
            big1,
            "{width}"
        );
    }
}

/// Question 14 (b): a copy or a hard link is made only from what THIS RUN
/// wrote. The reference copies a stale file already at the target's path
/// ("All OK") and hard-links to one; rarfast fills the copy from the decode
/// and refuses the hard link. Both pinned as differences.
#[test]
fn a_stale_file_at_the_targets_path_is_never_the_source() {
    let archive = fixture_bytes("copies5.rar");
    for width in WIDTHS {
        let work = Work::new(&format!("copies-stale{width}"), &archive);
        std::fs::write(work.out().join("big1"), b"stale\n").unwrap();
        let done = work.run("x", &["-y", width], &["big2"]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        assert_eq!(std::fs::read(work.out().join("big1")).unwrap(), b"stale\n");
        assert_eq!(
            std::fs::metadata(work.out().join("big2")).unwrap().len(),
            300_000,
            "{width}"
        );

        // `-o-` keeps the stale target, and the copy is still the archive's.
        let work = Work::new(&format!("copies-keep{width}"), &archive);
        std::fs::write(work.out().join("big1"), b"stale\n").unwrap();
        let done = work.run("x", &["-o-", width], &[]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        assert_eq!(std::fs::read(work.out().join("big1")).unwrap(), b"stale\n");
        assert_eq!(
            std::fs::metadata(work.out().join("big2")).unwrap().len(),
            300_000,
            "{width}"
        );
    }

    let archive = fixture_bytes("links5.rar");
    for width in WIDTHS {
        // The reference's own row: target not selected, nothing on disk:
        // "Cannot create hard link", exit 9, nothing created.
        let work = Work::new(&format!("hard-alone{width}"), &archive);
        let done = work.run("x", &["-y", width], &["hard_a"]);
        assert_eq!(code(&done), 9, "{width}: {done:?}");
        let err = stderr(&done);
        assert!(
            err.contains("Cannot create hard link o/hard_a"),
            "{width}: {err}"
        );
        assert!(
            err.contains("You need to unpack the link target first"),
            "{width}: {err}"
        );
        assert!(tree(&work.out()).is_empty(), "{width}");

        // DIFFERS: an unrelated a.txt on disk; the reference links to it.
        let work = Work::new(&format!("hard-stale{width}"), &archive);
        std::fs::write(work.out().join("a.txt"), b"stale\n").unwrap();
        let done = work.run("x", &["-y", width], &["hard_a"]);
        assert_eq!(code(&done), 9, "{width}: {done:?}");
        assert!(!work.out().join("hard_a").exists(), "{width}");
    }
}

/// 3.8.3: nothing is ever written through a link. MEASURED on the
/// reference: by default `dl` is skipped as unsafe and `dl/` made a real
/// directory, and `dl2` is created and then replaced by a real directory
/// when `dl2/evil2` arrives; nothing lands in `sub/`.
#[test]
fn nothing_is_written_through_a_link() {
    let archive = fixture_bytes("attack5.rar");
    for width in WIDTHS {
        let work = Work::new(&format!("attack{width}"), &archive);
        let done = work.run("x", &["-y", width], &[]);
        assert_eq!(code(&done), 1, "{width}: {done:?}");
        assert_eq!(
            tree(&work.out()),
            lines(&[
                "d dl",
                "d dl2",
                "d sub",
                "f dl/evil",
                "f dl2/evil2",
                "f sub/keep"
            ]),
            "{width}"
        );
        assert!(stderr(&done).contains(&skipping("dl", "/nonexistent-rarkit-victim")));

        // Question 14 (a), DIFFERS: under `-ola` the reference writes
        // `evil2` into `sub/` through `dl2` (and fails `dl/evil`, exit 9).
        // Here `-ola` creates unsafe LINKS and never follows one.
        let work = Work::new(&format!("attack-ola{width}"), &archive);
        let done = work.run("x", &["-y", "-ola", width], &[]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        assert_eq!(
            tree(&work.out()),
            lines(&[
                "d dl",
                "d dl2",
                "d sub",
                "f dl/evil",
                "f dl2/evil2",
                "f sub/keep"
            ]),
            "{width}"
        );
        assert!(!Path::new("/nonexistent-rarkit-victim").exists());

        // Links planted on the disk beforehand are replaced the same way.
        let work = Work::new(&format!("attack-planted{width}"), &archive);
        std::fs::create_dir(work.dir.join("victim")).unwrap();
        std::os::unix::fs::symlink("../victim", work.out().join("dl2")).unwrap();
        std::os::unix::fs::symlink("../victim", work.out().join("dl")).unwrap();
        let done = work.run("x", &["-y", width], &[]);
        assert!(code(&done) <= 1, "{width}: {done:?}");
        assert_eq!(
            std::fs::read_dir(work.dir.join("victim")).unwrap().count(),
            0,
            "{width}"
        );
        assert!(std::fs::symlink_metadata(work.out().join("dl2"))
            .unwrap()
            .is_dir());
    }
}

/// 3.8.2, "Replacing what is there": a regular member over a planted link
/// replaces the LINK and leaves what it pointed at alone; a link member
/// over a regular file replaces it under `-o+`, and `-o-` keeps the file.
#[test]
fn a_member_replaces_a_link_and_a_link_replaces_a_file() {
    let archive = fixture_bytes("links5.rar");
    for width in WIDTHS {
        let work = Work::new(&format!("replace{width}"), &archive);
        std::fs::create_dir(work.dir.join("victim")).unwrap();
        std::fs::write(work.dir.join("victim/t"), b"victim\n").unwrap();
        std::os::unix::fs::symlink("../victim/t", work.out().join("a.txt")).unwrap();
        std::fs::write(work.out().join("sym_rel"), b"old file\n").unwrap();
        let done = work.run("x", &["-o+", width], &[]);
        assert_eq!(code(&done), 1, "{width}: {done:?}");
        assert_eq!(
            std::fs::read(work.dir.join("victim/t")).unwrap(),
            b"victim\n",
            "{width}"
        );
        let a = std::fs::symlink_metadata(work.out().join("a.txt")).unwrap();
        assert!(a.is_file(), "{width}: a.txt is a regular file again");
        assert_eq!(
            std::fs::read_link(work.out().join("sym_rel")).unwrap(),
            Path::new("a.txt")
        );

        let work = Work::new(&format!("keep{width}"), &archive);
        std::fs::write(work.out().join("sym_rel"), b"old file\n").unwrap();
        let done = work.run("x", &["-o-", width], &[]);
        assert_eq!(code(&done), 1, "{width}: {done:?}");
        assert_eq!(
            std::fs::read(work.out().join("sym_rel")).unwrap(),
            b"old file\n"
        );
    }
}

/// 3.8.6: a kind this program does not make is declined LOUDLY, by name,
/// counted, and nothing is created. The reference prints "Unknown extra
/// field in" and ends "All OK", exit 0, for an unknown type: that silent
/// loss is deliberately not matched.
#[test]
fn an_unknown_type_is_declined_loudly() {
    let archive = rewrite::with_redirect(
        &fixture_bytes("links5.rar"),
        "sym_rel",
        rewrite::redirect(9, 0, b"a.txt"),
    );
    for width in WIDTHS {
        for cmd in ["x", "t"] {
            let work = Work::new(&format!("unknown-{cmd}{width}"), &archive);
            let done = work.run(cmd, &["-y", "-ola", width], &[]);
            assert_ne!(code(&done), 0, "{cmd} {width}: {done:?}");
            assert!(
                stderr(&done).contains("sym_rel: unsupported redirection type 9"),
                "{cmd} {width}: {}",
                stderr(&done)
            );
            assert!(std::fs::symlink_metadata(work.out().join("sym_rel")).is_err());
        }
    }
}

/// 3.8.1 and 3.2.6.2's table: a record the engine cannot use (an empty
/// target, a NUL in it, a copy naming itself) fails the member and the run,
/// and is never an empty file. The reference writes an empty file for the
/// first and third, exit 0.
#[test]
fn an_unusable_record_fails_and_creates_nothing() {
    let links = fixture_bytes("links5.rar");
    let empty = {
        let mut body = rewrite::redirect(1, 0, b"");
        body.extend_from_slice(b"a.txt");
        rewrite::with_redirect(&links, "sym_rel", body)
    };
    let nul = rewrite::with_redirect(&links, "sym_rel", rewrite::redirect(1, 0, b"a\0txt"));
    let self_copy = rewrite::with_redirect(
        &fixture_bytes("copies5.rar"),
        "big2",
        rewrite::redirect(5, 0, b"big2"),
    );
    for (row, archive, name) in [
        ("empty target", &empty, "sym_rel"),
        ("NUL target", &nul, "sym_rel"),
        ("self copy", &self_copy, "big2"),
    ] {
        for width in WIDTHS {
            for cmd in ["x", "t"] {
                let work = Work::new(&format!("bad-{cmd}{width}"), archive);
                let done = work.run(cmd, &["-y", "-ola", width], &[]);
                assert_ne!(code(&done), 0, "{row} {cmd} {width}: {done:?}");
                assert!(
                    std::fs::symlink_metadata(work.out().join(name)).is_err(),
                    "{row} {cmd} {width}: {name} was created"
                );
                assert!(
                    !stderr(&done).contains("checksum error"),
                    "{row} {cmd} {width}"
                );
            }
        }
    }
}

/// 3.8.7 and question 14 (d), on a Unix host: Windows forms are converted
/// (`\` to `/`, `\??\` dropped), and a Windows target that is ABSOLUTE as
/// stored is unsafe here. DIFFERS from the reference, which creates
/// `C:/x/a.txt` by default: pinned.
#[test]
fn windows_forms_are_converted_and_an_absolute_one_is_unsafe() {
    let archive = rewrite::with_redirect(
        &fixture_bytes("links5.rar"),
        "win_abs",
        rewrite::redirect(2, 0, b"C:\\x\\a.txt"),
    );
    let archive = rewrite::with_redirect(
        &archive,
        "junc_abs",
        rewrite::redirect(3, 1, b"\\??\\C:\\x"),
    );
    let archive = rewrite::with_redirect(&archive, "junc_rel", rewrite::redirect(3, 1, b"d"));
    let archive =
        rewrite::with_redirect(&archive, "backslash", rewrite::redirect(2, 0, b"d\\f.txt"));
    for width in WIDTHS {
        let work = Work::new(&format!("win{width}"), &archive);
        let done = work.run("x", &["-y", width], &[]);
        assert_eq!(code(&done), 1, "{width}: {done:?}");
        let got = tree(&work.out());
        assert!(
            got.contains(&"l junc_rel -> d".to_owned()),
            "{width}: {got:?}"
        );
        assert!(
            got.contains(&"l backslash -> d/f.txt".to_owned()),
            "{width}: {got:?}"
        );
        assert!(
            !got.iter().any(|l| l.starts_with("l win_abs")),
            "{width}: {got:?}"
        );
        assert!(
            !got.iter().any(|l| l.starts_with("l junc_abs")),
            "{width}: {got:?}"
        );
        let err = stderr(&done);
        assert!(
            err.contains(&skipping("win_abs", "C:\\x\\a.txt")),
            "{width}: {err}"
        );

        let work = Work::new(&format!("win-ola{width}"), &archive);
        let done = work.run("x", &["-y", "-ola", width], &[]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        let got = tree(&work.out());
        assert!(
            got.contains(&"l win_abs -> C:/x/a.txt".to_owned()),
            "{width}: {got:?}"
        );
        assert!(
            got.contains(&"l junc_abs -> C:/x".to_owned()),
            "{width}: {got:?}"
        );
    }
}

/// Every kind inside one solid stream, a link FIRST: the chain decodes
/// across them (3.2.6.2), the hard link shares its target's inode and the
/// copy has its target's bytes.
#[test]
fn a_solid_stream_runs_across_every_kind() {
    let archive = fixture_bytes("solid5.rar");
    for width in WIDTHS {
        let work = Work::new(&format!("solid{width}"), &archive);
        let done = work.run("x", &["-y", width], &[]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        assert_eq!(
            tree(&work.out()),
            lines(&[
                "f f1.txt",
                "f f2.txt",
                "f f3.txt",
                "f h2.txt",
                "l a_link -> f1.txt"
            ]),
            "{width}"
        );
        let f1 = std::fs::read(work.out().join("f1.txt")).unwrap();
        assert_eq!(f1.len(), 71_582);
        assert!(f1.starts_with(b"alpha 0 beta 0 gamma\n"));
        assert_eq!(
            std::fs::read(work.out().join("f3.txt")).unwrap(),
            f1,
            "{width}"
        );
        let f2 = std::fs::metadata(work.out().join("f2.txt")).unwrap();
        let h2 = std::fs::metadata(work.out().join("h2.txt")).unwrap();
        assert_eq!((f2.ino(), f2.nlink()), (h2.ino(), 2), "{width}");
    }
}

/// BLAKE2sp and encryption (3.2.6.2): the empty string's digest verifies,
/// and an encrypted link needs the password. With none, the reference
/// prints "Incorrect password" for each member and creates none (exit 11).
#[test]
fn blake_and_encrypted_links_extract_and_need_their_password() {
    for width in WIDTHS {
        let work = Work::new(&format!("blake{width}"), &fixture_bytes("blake5.rar"));
        let done = work.run("x", &["-y", width], &[]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        assert_eq!(
            std::fs::read_link(work.out().join("b_link")).unwrap(),
            Path::new("b.txt")
        );
        assert_eq!(
            std::fs::metadata(work.out().join("b_hard"))
                .unwrap()
                .nlink(),
            2
        );

        let work = Work::new(&format!("crypt{width}"), &fixture_bytes("crypt5.rar"));
        let done = work.run("x", &["-y", "-predir", width], &[]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        assert_eq!(
            std::fs::read_link(work.out().join("p_link")).unwrap(),
            Path::new("p.txt")
        );
        assert_eq!(
            std::fs::read(work.out().join("p_hard")).unwrap(),
            b"secret-data\n"
        );

        let work = Work::new(&format!("crypt-nopw{width}"), &fixture_bytes("crypt5.rar"));
        let done = work.run("x", &["-y", "-p-", width], &[]);
        assert_ne!(code(&done), 0, "{width}: {done:?}");
        assert!(
            std::fs::symlink_metadata(work.out().join("p_link")).is_err(),
            "{width}"
        );
        assert!(
            std::fs::symlink_metadata(work.out().join("p_hard")).is_err(),
            "{width}"
        );
    }
}

/// 3.3.12: the older family's links, the target decoded from the content;
/// the absolute and the escaping one skipped as unsafe, exit 1, as the
/// reference does.
#[test]
fn rar4_links_extract_under_the_same_rule() {
    let archive = fixture_bytes("links4.rar");
    for width in WIDTHS {
        let work = Work::new(&format!("r4{width}"), &archive);
        let done = work.run("x", &["-y", width], &[]);
        assert_eq!(code(&done), 1, "{width}: {done:?}");
        assert_eq!(
            tree(&work.out()),
            lines(&["d d", "f a.txt", "l sym_dir -> d", "l sym_rel -> a.txt"]),
            "{width}"
        );
        let err = stderr(&done);
        assert!(
            err.contains(&skipping("sym_abs", "/etc/hostname")),
            "{width}: {err}"
        );
        assert!(
            err.contains(&skipping("sym_up", "../../escape")),
            "{width}: {err}"
        );
    }
}

/// The technical listing names the kind and the target as the reference
/// prints them.
#[test]
fn lt_prints_the_type_and_the_target() {
    let work = Work::new("lt", &fixture_bytes("links5.rar"));
    let done = Command::new(rarfast())
        .current_dir(&work.dir)
        .args(["lt", "a.rar"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&done.stdout);
    assert!(
        text.contains("        Name: hard_a\n        Type: Hard link\n      Target: a.txt\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "        Name: sym_rel\n        Type: Unix symbolic link\n      Target: a.txt\n"
        ),
        "{text}"
    );
}

/// MEASURED on Rar.exe 7.23 for Windows (a Windows desktop, 27 Sep 2026): a
/// directory link is stored as type 2 with the directory flag in the FILE
/// header as well as the record, a junction as type 3 with `/??/C:/...`,
/// and a relative target with forward slashes. On this host the directory
/// link is a link and never a directory made in its place; the junction is
/// absolute, so unsafe by default (as the reference skips it on Windows)
/// and, under `-ola`, the link `C:/x`.
#[test]
fn windows_written_links_as_the_genuine_writer_stores_them() {
    let links = fixture_bytes("links5.rar");
    let dirlink = |archive: &[u8], name: &str, body: Vec<u8>| {
        rewrite::rewrite_with_flags(archive, name, 1, |records| {
            records
                .into_iter()
                .map(|(kind, old)| {
                    if kind == 5 {
                        (5, body.clone())
                    } else {
                        (kind, old)
                    }
                })
                .collect()
        })
    };
    let archive = dirlink(&links, "sym_dir", rewrite::redirect(2, 1, b"d"));
    let archive = dirlink(&archive, "junc_abs", rewrite::redirect(3, 1, b"/??/C:/x"));
    let archive =
        rewrite::with_redirect(&archive, "d/up_in", rewrite::redirect(2, 0, b"../top.txt"));
    for width in WIDTHS {
        let work = Work::new(&format!("winreal{width}"), &archive);
        let done = work.run("x", &["-y", width], &[]);
        assert_eq!(code(&done), 1, "{width}: {done:?}");
        let got = tree(&work.out());
        assert!(
            got.contains(&"l sym_dir -> d".to_owned()),
            "{width}: {got:?}"
        );
        assert!(
            got.contains(&"l d/up_in -> ../top.txt".to_owned()),
            "{width}: {got:?}"
        );
        assert!(
            !got.iter().any(|l| l.contains("junc_abs")),
            "{width}: {got:?}"
        );
        assert!(
            stderr(&done).contains(&skipping("junc_abs", "/??/C:/x")),
            "{width}"
        );

        let work = Work::new(&format!("winreal-ola{width}"), &archive);
        let done = work.run("x", &["-y", "-ola", width], &[]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        assert!(
            tree(&work.out()).contains(&"l junc_abs -> C:/x".to_owned()),
            "{width}"
        );

        let work = Work::new(&format!("winreal-t{width}"), &archive);
        let done = work.run("t", &[width], &[]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
    }
}

/// A stored RAR 5 archive of Unix symbolic links, one per `(name,
/// target)`, built from spec F 3.2.2, 3.2.6 and 3.2.6.2: a file header
/// with no data area and an extra area holding one redirection record of
/// type 1.
fn unix_links(links: &[(&[u8], &[u8])]) -> Vec<u8> {
    fn block(body: &[u8], out: &mut Vec<u8>) {
        let mut sized = rewrite::vint(body.len() as u64);
        sized.extend_from_slice(body);
        out.extend_from_slice(&rewrite::crc32(&sized).to_le_bytes());
        out.extend_from_slice(&sized);
    }
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &mut out);
    for (name, target) in links {
        let extra = rewrite::area(&[(5, rewrite::redirect(1, 0, target))]);
        let mut body = rewrite::vint(2); // file header
        body.extend(rewrite::vint(0x0001)); // an extra area, no data area
        body.extend(rewrite::vint(extra.len() as u64));
        body.extend(rewrite::vint(0x0004)); // CRC32 present
        body.extend(rewrite::vint(0)); // unpacked size
        body.extend(rewrite::vint(0o120_777)); // a symbolic link's mode
        body.extend_from_slice(&rewrite::crc32(b"").to_le_bytes());
        body.extend(rewrite::vint(0)); // stored
        body.extend(rewrite::vint(1)); // Unix
        body.extend(rewrite::vint(name.len() as u64));
        body.extend_from_slice(name);
        body.extend(extra);
        block(&body, &mut out);
    }
    block(&[5, 0, 0], &mut out);
    out
}

/// A link's DEPTH is counted on the separators the host splits its name
/// on. On Unix a `\` is a character of the name (`disk_name`), so `a\b\c`
/// is one component at depth 0 and its target `../../x` leaves the
/// destination: skipped, as `d/a\b\c` (depth 1) with the same target is.
/// An earlier revision split on `\` too, counted `a\b\c` as depth 2 and
/// created a link pointing two levels outside `o/`.
#[test]
fn a_backslash_in_a_unix_link_name_adds_no_depth() {
    let archive = unix_links(&[
        (b"a\\b\\c", b"../../x"),
        (b"d/a\\b\\c", b"../../x"),
        (b"d/a\\b", b"../x"),
        (b"e\\f", b"g"),
    ]);
    for width in WIDTHS {
        let work = Work::new(&format!("bsdepth{width}"), &archive);
        let done = work.run("x", &["-y", width], &[]);
        assert_eq!(code(&done), 1, "{width}: {done:?}");
        assert_eq!(
            tree(&work.out()),
            lines(&["d d", "l d/a\\b -> ../x", "l e\\f -> g"]),
            "{width}: {done:?}"
        );
        assert!(
            String::from_utf8_lossy(&done.stdout).contains("Total errors: 2"),
            "{width}: {done:?}"
        );
        // `-ola` is the caller saying the archive is trusted: every link
        // is created as stored, the escaping one included.
        let trusted = Work::new(&format!("bsdepth-ola{width}"), &archive);
        let done = trusted.run("x", &["-y", "-ola", width], &[]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        assert!(tree(&trusted.out()).contains(&"l a\\b\\c -> ../../x".to_owned()));
    }
}
