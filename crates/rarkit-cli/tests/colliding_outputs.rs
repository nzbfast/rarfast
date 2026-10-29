//! Two members written to ONE file settle in archive order, whatever the
//! width: the file left is the one a one-thread run leaves.
//!
//! Found by an outside review on 10 Oct 2026, by running the tool: `e -o+`
//! over `first/same` (8 MiB of `A`) and `second/same` (1,024 bytes of `B`),
//! and `x -o+` over two members both named `same`, left 8,388,608 bytes of
//! `A` at the default width, at `-mt2` and at `-mt8`, five runs of five,
//! with both members called `OK` and exit 0. `-mt1` left the 1,024 `B`.
//! The pool opened the second member's file, which emptied the first's,
//! while a worker was still writing the first.
//!
//! unrar 7.23 (homebrew's, aarch64 macOS, 10 Oct 2026) over the same two
//! archives: `e -o+` and `x -o+` leave the 1,024 `B` bytes, two `OK`
//! lines, exit 0; with no switch it asks about the second member once the
//! first is whole (`8388608 bytes` in the question), and an empty standard
//! input ends it, exit 12, the first member standing; `-o-` keeps the
//! first, exit 0.
//!
//! A NAMED LIMIT of the mend: a run that holds ANY two members of one
//! destination takes the in-order walk for the whole run, every member
//! of it; only a run of members that each have a file of their own keeps
//! the pool. Holding just the members that collide needs a change in the
//! engine. The run says so in one line of rarfast's own
//! (`the_run_says_when_it_leaves_the_pool`).
//!
//! NOT SEEN by the comparison, and not tested: two spellings of one
//! accented letter, composed and decomposed, which macOS holds as one
//! file (the tool does not normalise names); a Windows short alias; two
//! names of one file made by a hard link before the run.
//!
//! WIDTHS: every row runs at the DEFAULT width (the machine's own: a
//! hosted runner is 2 to 4 threads wide), at `-mt2` and at `-mt8`, and is
//! compared with `-mt1`. A race that passes once proves nothing, so each
//! width is run [`ROUNDS`] times. MEMORY: the largest member is 8 MiB,
//! stored; nothing here needs more than the tool's floor.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// How many times each width is run for one row.
const ROUNDS: usize = 20;

const BIG: usize = 8 << 20;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-collide-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

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

fn vint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let low = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

/// One block: CRC32, size, then `body` (spec F 3.2.2), then `data`.
fn block(body: &[u8], data: &[u8], out: &mut Vec<u8>) {
    let mut sized = Vec::new();
    vint(body.len() as u64, &mut sized);
    sized.extend_from_slice(body);
    out.extend_from_slice(&crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
    out.extend_from_slice(data);
}

/// One stored file member; `sound` false gives it a checksum its bytes do
/// not have.
struct Entry<'a> {
    name: &'a str,
    data: &'a [u8],
    sound: bool,
}

fn file<'a>(name: &'a str, data: &'a [u8]) -> Entry<'a> {
    Entry {
        name,
        data,
        sound: true,
    }
}

fn damaged<'a>(name: &'a str, data: &'a [u8]) -> Entry<'a> {
    Entry {
        name,
        data,
        sound: false,
    }
}

/// A stored RAR 5 archive of `entries`, written by a Unix host.
fn rar5(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &[], &mut out);
    for entry in entries {
        let crc = crc32(entry.data) ^ u32::from(!entry.sound);
        let mut body = Vec::new();
        vint(2, &mut body); // a file header
        vint(2, &mut body); // with a data area
        vint(entry.data.len() as u64, &mut body);
        vint(4, &mut body); // CRC32 present
        vint(entry.data.len() as u64, &mut body);
        vint(0o100_644, &mut body);
        body.extend_from_slice(&crc.to_le_bytes());
        vint(0, &mut body); // stored
        vint(1, &mut body); // Unix
        vint(entry.name.len() as u64, &mut body);
        body.extend_from_slice(entry.name.as_bytes());
        block(&body, entry.data, &mut out);
    }
    block(&[5, 0, 0], &[], &mut out);
    out
}

/// What a run left: its exit code and every file under the destination,
/// by name, sorted.
#[derive(Debug, PartialEq, Eq)]
struct Left {
    code: Option<i32>,
    files: Vec<(String, Summary)>,
}

/// A file's bytes, said shortly: its length, its first byte and whether
/// every byte is that one.
#[derive(Debug, PartialEq, Eq)]
struct Summary {
    len: usize,
    first: Option<u8>,
    uniform: bool,
}

fn summary(bytes: &[u8]) -> Summary {
    Summary {
        len: bytes.len(),
        first: bytes.first().copied(),
        uniform: bytes.iter().all(|b| Some(b) == bytes.first()),
    }
}

fn left(dir: &Path, base: &Path, into: &mut Vec<(String, Summary)>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            left(&path, base, into);
        } else {
            let name = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            into.push((name, summary(&std::fs::read(&path).unwrap())));
        }
    }
}

/// One run into a fresh destination, standard input empty.
fn run(dir: &Path, command: &str, switches: &[&str], archive: &str) -> (Left, Output) {
    let out = dir.join("out");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    let output = Command::new(rarfast())
        .current_dir(dir)
        .arg(command)
        .args(switches)
        .arg(archive)
        .arg("out/")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let mut files = Vec::new();
    left(&out, &out, &mut files);
    (
        Left {
            code: output.status.code(),
            files,
        },
        output,
    )
}

/// The row: `-mt1` first, then the default width, `-mt2` and `-mt8`,
/// [`ROUNDS`] times each, every one leaving what `-mt1` left. Returns
/// `-mt1`'s result, for the caller to hold against what is right.
fn settles_as_one_thread(tag: &str, command: &str, switches: &[&str], archive: &[u8]) -> Left {
    let dir = work(tag);
    std::fs::write(dir.join("a.rar"), archive).unwrap();
    let mut one = switches.to_vec();
    one.push("-mt1");
    let (expected, _) = run(&dir, command, &one, "a.rar");
    for width in [None, Some("-mt2"), Some("-mt8")] {
        let mut wide = switches.to_vec();
        wide.extend(width);
        for round in 0..ROUNDS {
            let (got, output) = run(&dir, command, &wide, "a.rar");
            assert_eq!(
                got,
                expected,
                "{command} {wide:?}, round {round}: not what -mt1 leaves\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    expected
}

fn only(name: &str, len: usize, byte: u8) -> Vec<(String, Summary)> {
    vec![(
        name.to_owned(),
        Summary {
            len,
            first: Some(byte),
            uniform: true,
        },
    )]
}

/// `e` flattens `first/same` and `second/same` onto one file: the later
/// member's bytes stand.
#[test]
fn e_over_two_members_of_one_base_name_leaves_the_later() {
    let a = vec![b'A'; BIG];
    let b = vec![b'B'; 1024];
    let archive = rar5(&[file("first/same", &a), file("second/same", &b)]);
    let one = settles_as_one_thread("e-plus", "e", &["-o+"], &archive);
    assert_eq!(one.code, Some(0));
    assert_eq!(one.files, only("same", 1024, b'B'));
}

/// `x` over two members of the same name: the later member's bytes stand.
#[test]
fn x_over_two_members_of_one_name_leaves_the_later() {
    let a = vec![b'A'; BIG];
    let b = vec![b'B'; 1024];
    let archive = rar5(&[file("same", &a), file("same", &b)]);
    let one = settles_as_one_thread("x-plus", "x", &["-o+"], &archive);
    assert_eq!(one.code, Some(0));
    assert_eq!(one.files, only("same", 1024, b'B'));
}

/// The small member first and the large one last, and three of a name.
#[test]
fn the_last_of_several_stands_whatever_their_sizes() {
    let a = vec![b'A'; 1024];
    let b = vec![b'B'; BIG];
    let c = vec![b'C'; BIG / 2];
    let archive = rar5(&[file("same", &a), file("same", &b)]);
    let one = settles_as_one_thread("small-first", "x", &["-o+"], &archive);
    assert_eq!(one.files, only("same", BIG, b'B'));
    let archive = rar5(&[
        file("d1/same", &b),
        file("d2/same", &c),
        file("d3/same", &a),
    ]);
    let one = settles_as_one_thread("three", "e", &["-o+"], &archive);
    assert_eq!(one.code, Some(0));
    assert_eq!(one.files, only("same", 1024, b'A'));
}

/// The default rule ASKS about the second member, once the first is
/// whole; with no answer to read the run stops there, exit 12, and the
/// first member stands. `-o-` keeps the first without a word. `-y`
/// answers yes.
#[test]
fn the_default_rule_asks_after_the_earlier_member_is_whole() {
    let a = vec![b'A'; BIG];
    let b = vec![b'B'; 1024];
    for (tag, command, archive) in [
        (
            "ask-e",
            "e",
            rar5(&[file("first/same", &a), file("second/same", &b)]),
        ),
        ("ask-x", "x", rar5(&[file("same", &a), file("same", &b)])),
    ] {
        let one = settles_as_one_thread(tag, command, &[], &archive);
        assert_eq!(one.code, Some(12));
        assert_eq!(one.files, only("same", BIG, b'A'));
        // The question shows the file as the earlier member left it.
        let dir = work(&format!("{tag}-said"));
        std::fs::write(dir.join("a.rar"), &archive).unwrap();
        for round in 0..ROUNDS {
            let (_, output) = run(&dir, command, &[], "a.rar");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("8388608 bytes"),
                "{command}, round {round}: asked before the first member was whole\n{stderr}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);

        let one = settles_as_one_thread(&format!("{tag}-never"), command, &["-o-"], &archive);
        assert_eq!(one.code, Some(0));
        assert_eq!(one.files, only("same", BIG, b'A'));

        let one = settles_as_one_thread(&format!("{tag}-yes"), command, &["-y"], &archive);
        assert_eq!(one.code, Some(0));
        assert_eq!(one.files, only("same", 1024, b'B'));
    }
}

/// An EARLIER member that fails its checksum is removed at its own close,
/// and the later member of its name, written after it, stands whole. A
/// LATER member that fails leaves the earlier one's file as it was, as at
/// one thread: SPEC-CLI 9.4 W7, a chosen difference from the reference
/// (until 10 Oct 2026 the later member took the earlier one's place
/// first, and nothing was left). `-kb` keeps the later member's bytes
/// under the name, as the reference keeps them.
#[test]
fn a_failed_member_never_takes_another_members_file_with_it() {
    let a = vec![b'A'; BIG];
    let b = vec![b'B'; 1024];
    let earlier_fails = rar5(&[damaged("first/same", &a), file("second/same", &b)]);
    let one = settles_as_one_thread("fail-first", "e", &["-o+"], &earlier_fails);
    assert_eq!(one.code, Some(3));
    assert_eq!(one.files, only("same", 1024, b'B'));

    let small_fails_first = rar5(&[damaged("same", &b), file("same", &a)]);
    let one = settles_as_one_thread("fail-first-small", "x", &["-o+"], &small_fails_first);
    assert_eq!(one.code, Some(3));
    assert_eq!(one.files, only("same", BIG, b'A'));

    let later_fails = rar5(&[file("first/same", &a), damaged("second/same", &b)]);
    let one = settles_as_one_thread("fail-last", "e", &["-o+"], &later_fails);
    assert_eq!(one.code, Some(3));
    assert_eq!(one.files, only("same", BIG, b'A'));

    let one = settles_as_one_thread("fail-last-kept", "e", &["-o+", "-kb"], &later_fails);
    assert_eq!(one.code, Some(3));
    assert_eq!(one.files, only("same", 1024, b'B'));
}

/// Two names that differ only in case are one file on a volume that folds
/// case and two on one that does not: either way the run leaves what one
/// thread leaves.
#[test]
fn names_differing_only_in_case_settle_as_one_thread_does() {
    let a = vec![b'A'; BIG];
    let b = vec![b'B'; 1024];
    let archive = rar5(&[file("Same.BIN", &a), file("same.bin", &b)]);
    let one = settles_as_one_thread("case", "x", &["-o+"], &archive);
    assert_eq!(one.code, Some(0));
    let folded = one.files.len() == 1;
    if folded {
        assert_eq!(one.files[0].1, summary(&b));
    } else {
        assert_eq!(one.files.len(), 2);
    }
}

/// Members that share no destination are untouched by any of this: every
/// one is written whole at every width.
#[test]
fn members_of_their_own_names_are_all_written() {
    let a = vec![b'A'; BIG];
    let b = vec![b'B'; BIG];
    let c = vec![b'C'; 1024];
    let archive = rar5(&[file("d1/a", &a), file("d2/b", &b), file("d3/c", &c)]);
    let one = settles_as_one_thread("unique", "e", &["-o+"], &archive);
    assert_eq!(one.code, Some(0));
    assert_eq!(one.files.len(), 3);
    assert_eq!(one.files[0], ("a".to_owned(), summary(&a)));
    assert_eq!(one.files[1], ("b".to_owned(), summary(&b)));
    assert_eq!(one.files[2], ("c".to_owned(), summary(&c)));
}

const NOTICE: &str = "\nSeveral members share one output file: extracting one member at a time\n";

/// The one line a run says when it leaves the pool for members that share
/// a destination: printed when two do and the width is above one, before
/// the banner, on the progress lines' stream; never for members of their
/// own names, never at `-mt1` (which was never pooled), never under `t`,
/// and dropped by `-idq`. It is no error: the exit code is 0.
///
/// Stated at `-mt2` and `-mt8`, not at the default width, which is one
/// thread on a machine of one.
#[test]
fn the_run_says_when_it_leaves_the_pool() {
    let a = vec![b'A'; BIG];
    let b = vec![b'B'; 1024];
    let dir = work("notice");
    let twins = rar5(&[file("first/same", &a), file("second/same", &b)]);
    let apart = rar5(&[file("first/one", &a), file("second/two", &b)]);
    std::fs::write(dir.join("twins.rar"), &twins).unwrap();
    std::fs::write(dir.join("apart.rar"), &apart).unwrap();
    let said = |output: &Output| {
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        (stdout, stderr)
    };
    for width in ["-mt2", "-mt8"] {
        // `e` drops the directories: one file. Said once, before the banner.
        let (left, output) = run(&dir, "e", &["-o+", width], "twins.rar");
        let (stdout, stderr) = said(&output);
        assert_eq!(left.code, Some(0), "{width}: {stdout}{stderr}");
        assert_eq!(stdout.matches(NOTICE).count(), 1, "{width}: {stdout}");
        assert!(
            stdout.starts_with(&format!("{NOTICE}\nExtracting from twins.rar\n")),
            "{width}: {stdout:?}"
        );
        assert!(stdout.ends_with("All OK\n"), "{width}: {stdout}");
        assert_eq!(stderr, "", "{width}");

        // `x` keeps the directories: two files, the pool, no line.
        let (left, output) = run(&dir, "x", &["-o+", width], "twins.rar");
        assert_eq!(left.code, Some(0));
        assert_eq!(left.files.len(), 2);
        assert!(
            !said(&output).0.contains("one member at a time"),
            "x {width}"
        );

        // Members of their own names, under `e` and `x`: no line.
        for command in ["e", "x"] {
            let (left, output) = run(&dir, command, &["-o+", width], "apart.rar");
            assert_eq!(left.code, Some(0));
            assert!(
                !said(&output).0.contains("one member at a time"),
                "{command} {width}"
            );
        }

        // `-idq` drops it with the progress lines; `-ierr` sends it with
        // them; `t` writes nothing and says nothing of it.
        let (left, output) = run(&dir, "e", &["-o+", "-idq", width], "twins.rar");
        assert_eq!(left.code, Some(0));
        assert_eq!(said(&output), (String::new(), String::new()), "{width}");
        let (_, output) = run(&dir, "e", &["-o+", "-ierr", width], "twins.rar");
        let (stdout, stderr) = said(&output);
        assert_eq!(stdout, "", "{width}");
        assert_eq!(stderr.matches(NOTICE).count(), 1, "{width}: {stderr}");
        let (_, output) = run(&dir, "t", &[width], "twins.rar");
        let (stdout, stderr) = said(&output);
        assert!(
            !stdout.contains("one member at a time") && stderr.is_empty(),
            "t {width}"
        );
    }
    // One thread asked for: nothing was left, nothing is said.
    let (left, output) = run(&dir, "e", &["-o+", "-mt1"], "twins.rar");
    assert_eq!(left.code, Some(0));
    assert!(!said(&output).0.contains("one member at a time"));
    let _ = std::fs::remove_dir_all(&dir);
}
