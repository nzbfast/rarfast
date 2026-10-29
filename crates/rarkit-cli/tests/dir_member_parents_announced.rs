//! `x` of a DIRECTORY member whose parent directories are not there.
//!
//! THE RULE: every directory `x` makes is announced, a directory member's
//! missing parents as a file member's are: one `Creating` line each,
//! outermost first, each once in a run, and none for a directory that
//! was there before the run.
//!
//! Before 10 Oct 2026 the parents of a directory member were made without
//! a word: `x` of the one member `a/b` printed `Creating    out/a/b`
//! alone.
//!
//! MEASURED against unrar 7.23 on macOS (arm64), 10 Oct 2026, hand-built
//! archives of directory members (and one file), with nothing, the
//! destination, `a` and `a/b` there before the run: 64 rows at `-mt1` and
//! `-mt4`. The rows below are six of them.
//!
//! ON WINDOWS a line shows the destination as it was typed and the
//! archived part with a backslash: typed `out/`, the lines read `out/a`
//! and then `out/a\b`. MEASURED with the genuine unrar on a hosted
//! Windows runner, 11 Oct 2026. The rows below are written with `/` and
//! read that way on Windows ([`as_shown_here`]): until then the test
//! asked Windows for the Unix spelling and was red there, the tool's
//! line being the reference's.
//!
//! Width and memory: each run states `-mt1` or `-mt4`; the archives hold
//! directories and a file of three bytes, so the test needs no memory to
//! speak of and passes on a runner two threads wide.

use std::path::PathBuf;
use std::process::Command;

#[path = "../../rarkit/tests/redirection/rewrite.rs"]
mod rewrite;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// Stands watch over the directory one row of this file works in. The
/// row holds it beside the directory's path and never uses it; when it
/// is let go, at the row's end or because an assertion failed, the
/// directory is deleted.
struct DirWatch(PathBuf);

impl Drop for DirWatch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn work(tag: &str) -> (PathBuf, DirWatch) {
    let dir = std::env::temp_dir().join(format!("rarfast-dirparents-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    (dir.clone(), DirWatch(dir))
}

fn block(body: &[u8], out: &mut Vec<u8>) {
    let mut sized = rewrite::vint(body.len() as u64);
    sized.extend_from_slice(body);
    out.extend_from_slice(&rewrite::crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
}

/// A RAR 5 archive of these members in this order, a name that ends in
/// `/` a directory (stored without it) and any other a stored file of
/// three bytes, built from spec F 3.2.2 and 3.2.6.
fn archive(members: &[&str]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &mut out);
    for member in members {
        let (name, data, file_flags, attributes): (&str, &[u8], u64, u64) =
            match member.strip_suffix('/') {
                Some(name) => (name, b"", 0x5, 0o040_755),
                None => (member, b"abc", 0x4, 0o100_644),
            };
        let mut body = rewrite::vint(2);
        body.extend(rewrite::vint(if data.is_empty() { 0 } else { 0x2 }));
        if !data.is_empty() {
            body.extend(rewrite::vint(data.len() as u64));
        }
        body.extend(rewrite::vint(file_flags));
        body.extend(rewrite::vint(data.len() as u64));
        body.extend(rewrite::vint(attributes));
        body.extend_from_slice(&rewrite::crc32(data).to_le_bytes());
        body.extend(rewrite::vint(0)); // stored
        body.extend(rewrite::vint(1)); // Unix
        body.extend(rewrite::vint(name.len() as u64));
        body.extend_from_slice(name.as_bytes());
        block(&body, &mut out);
        out.extend_from_slice(data);
    }
    block(&[5, 0, 0], &mut out);
    out
}

/// The paths of the `Creating` lines of `x` into `out/`, in order, with
/// these directories made under the scratch before the run.
fn announced(tag: &str, width: &str, members: &[&str], there: &[&str]) -> Vec<String> {
    let (dir, _watch) = work(&format!("{tag}{width}"));
    std::fs::write(dir.join("a.rar"), archive(members)).unwrap();
    for made in there {
        std::fs::create_dir_all(dir.join(made)).unwrap();
    }
    let done = Command::new(rarfast())
        .current_dir(&dir)
        .args(["x", width, "a.rar", "out/"])
        .output()
        .unwrap();
    assert!(done.status.success(), "{tag} {width}: {done:?}");
    let text = String::from_utf8_lossy(&done.stdout).into_owned();
    for member in members {
        let made = dir.join("out").join(member);
        assert!(made.exists(), "{tag} {width}: {member} was not made");
    }
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("Creating")).then(|| {
                let path = words.next().unwrap_or_default().to_owned();
                assert_eq!(words.next(), Some("OK"), "{tag} {width}: {line:?}");
                path
            })
        })
        .collect()
}

/// A `Creating` path of the rows below as this system shows it: on
/// Windows the destination as typed (`out/`) and a backslash for every
/// separator after it; anywhere else as written.
fn as_shown_here(path: &str) -> String {
    match path.strip_prefix("out/") {
        Some(archived) if cfg!(windows) => format!("out/{}", archived.replace('/', "\\")),
        _ => path.to_owned(),
    }
}

/// A row's tag, the archive's members, what is there before the run, and
/// unrar's `Creating` paths.
type Row = (
    &'static str,
    &'static [&'static str],
    &'static [&'static str],
    &'static [&'static str],
);

#[test]
fn a_directory_member_announces_each_parent_it_makes() {
    let rows: [Row; 6] = [
        ("one", &["a/b/"], &[], &["out", "out/a", "out/a/b"]),
        ("dest", &["a/b/"], &["out"], &["out/a", "out/a/b"]),
        ("deep", &["a/b/c/"], &["out/a"], &["out/a/b", "out/a/b/c"]),
        (
            "twice",
            &["a/b/", "a/c/"],
            &[],
            &["out", "out/a", "out/a/b", "out/a/c"],
        ),
        (
            "later",
            &["a/b/c/", "a/"],
            &["out"],
            &["out/a", "out/a/b", "out/a/b/c"],
        ),
        (
            "file",
            &["a/b/", "a/b/f"],
            &[],
            &["out", "out/a", "out/a/b"],
        ),
    ];
    for width in ["-mt1", "-mt4"] {
        for (tag, members, there, expected) in rows {
            let owed: Vec<String> = expected.iter().map(|path| as_shown_here(path)).collect();
            assert_eq!(announced(tag, width, members, there), owed, "{tag} {width}");
        }
    }
}
