//! An extraction whose line only the creator's parser reads still
//! refuses `-ep` and `-f`.
//!
//! Under its own name rarfast reads a line with the decoder's parser
//! first and offers it to the creator's parser only where the decoder
//! refuses it. `x -ep -m5 arc.rar` is such a line (`-m5` is a creator
//! switch), and the creator's parser keeps `-ep` and `-f` in fields of
//! its own that an extraction never looked at: until 4 Oct 2026 the run
//! rebuilt the whole tree, or replaced every file, and exited 0.
//!
//! **Measured against rar 7.23 on 4 Oct 2026** (an Apple silicon Mac),
//! over an archive of `sub/a.txt` and `top.txt`, into an empty
//! directory: `rar x -ep -m5 arc.rar` writes `a.txt` and `top.txt` with
//! no `sub`, exit 0; `rar x -f -m5 arc.rar` writes nothing, exit 10.
//! rarfast does neither yet, so both are refused by name, exit 7,
//! before the archive is opened: on `x` and `e` only, as on a line the
//! decoder's parser reads.
//!
//! Every run here is `-mt2` over two files of a few bytes: a pool two
//! threads wide and a few MiB of memory.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// A directory of one test's own, made afresh under the system's
/// temporary directory, with `sub/a.txt` and `top.txt`, an `arc.rar`
/// made of the two, and an empty `out`.
fn work(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("rarfast-read-refused-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub/a.txt"), b"a\n").unwrap();
    std::fs::write(dir.join("top.txt"), b"top\n").unwrap();
    let made = run(&dir, &["a", "-mt2", "-r", "arc.rar", "sub", "top.txt"]);
    assert_eq!(made.status.code(), Some(0), "{}", text(&made.stderr));
    std::fs::create_dir(dir.join("out")).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(rarfast())
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|err| panic!("rarfast could not be run: {err}"))
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// How many entries `out` holds.
fn written(dir: &Path) -> usize {
    std::fs::read_dir(dir.join("out")).unwrap().count()
}

/// One refusal: exit 7, the switch named, nothing written.
fn is_refused(tag: &str, args: &[&str], named: &str) {
    let dir = work(tag);
    let out = run(&dir.join("out"), args);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(
        out.status.code(),
        Some(7),
        "{args:?}; stdout: {stdout} stderr: {stderr}"
    );
    assert!(
        stderr.contains(&format!("rarfast: {named} is read and not honoured yet")),
        "{args:?}; stderr: {stderr}"
    );
    assert_eq!(written(&dir), 0, "{args:?} wrote something: {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The line that was named: the tree was rebuilt in full, exit 0.
#[test]
fn x_with_ep_on_a_creator_parsed_line_is_refused() {
    is_refused("x-ep", &["x", "-mt2", "-ep", "-m5", "../arc.rar"], "-ep");
}

#[test]
fn e_with_ep_on_a_creator_parsed_line_is_refused() {
    is_refused("e-ep", &["e", "-mt2", "-ep", "-m5", "../arc.rar"], "-ep");
}

#[test]
fn x_and_e_with_f_on_a_creator_parsed_line_are_refused() {
    is_refused("x-f", &["x", "-mt2", "-f", "-m5", "../arc.rar"], "-f");
    is_refused("e-f", &["e", "-mt2", "-f", "-m5", "../arc.rar"], "-f");
}

/// Controls: the same creator-parsed line without the two switches
/// still extracts, and a test with them still tests.
#[test]
fn the_rest_of_a_creator_parsed_read_line_still_runs() {
    let dir = work("plain");
    let out = run(&dir.join("out"), &["x", "-mt2", "-m5", "../arc.rar"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(dir.join("out/sub/a.txt").is_file());
    assert!(dir.join("out/top.txt").is_file());

    for switch in ["-ep", "-f"] {
        let out = run(
            &dir.join("out"),
            &["t", "-mt2", switch, "-m5", "../arc.rar"],
        );
        assert_eq!(
            out.status.code(),
            Some(0),
            "t {switch}: {}",
            text(&out.stderr)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
