//! EVERY member refused for its version is named, each in its own place,
//! and each counts (spec F 3.2.6 and 3.3.5; the target, set on 28
//! Sep 2026, is unrar 7.23's behaviour).
//!
//! Until then the CLI named only the FIRST such member, once the walk had
//! finished, opened a progress line for every one of them, counted one
//! error for each after the first where the reference counts two, and on
//! `x` created, then removed, the file of each: an existing file of that
//! name under `-o+` was deleted, and `-kb` left an empty one.
//!
//! unrar 7.23 (homebrew's, aarch64 macOS, 28 Sep 2026) over five RAR 5
//! members with two (`b`, `d`) or three (`b`, `c`, `d`) rewritten to
//! compression version 2, and over the rar 3.93 fixture `r393_m3.rar` with
//! two or three members at unpack version 36:
//!
//! ```text
//! Testing     a.txt          OK
//! Unknown method in b.txt                     <- stderr
//! You may need a newer version of RAR.        <- stderr
//! Testing     c.txt          OK
//! Unknown method in d.txt                     <- stderr
//! You may need a newer version of RAR.        <- stderr
//! Testing     e.txt          OK
//! Total errors: 4
//! ```
//!
//! No progress line for a refused member, the two lines where it would
//! have been, TWO errors per member (`Total errors: 6` for three), exit 2,
//! the same under `t`, `x`, `e` and `p`. On separate streams stderr is
//! `\nUnknown method in b.txt\nYou may need a newer version of RAR.` per
//! member, run together; under `-ierr` each pair follows the `OK` line
//! before it with no blank line between. `x -o+` leaves an existing file
//! of a refused member's name as it was, and `x -kb` leaves none. `l`
//! lists the members and exits 0.
//!
//! One difference stays, and is pinned here: a SOLID archive, where the
//! reference stops at the first refused member (`Total errors: 2`, nothing
//! after it tested) and spec F 3.2.6 has the walk go on: the members
//! continuing the broken chain fail their checksums, and every later
//! refused member is named too.
//!
//! A second was pinned here until 30 Sep 2026: under `-idq` the reference
//! ends its stderr with one more newline, as after a checksum complaint.
//! rarfast does too now (`a_quiet_run_ends_its_stderr_with_one_newline`;
//! the same change carries `Out::close_dangling_stderr` for the other
//! read-only commands, `tests/idq_closes_its_stderr_line.rs`).

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-refused-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/legacy/archives")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

const NAMES: [&str; 5] = ["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"];

/// Five members of 24 KiB, archived by rarfast in RAR 5, `-m3`.
fn rar5(dir: &Path, solid: bool) -> Vec<u8> {
    for (index, name) in NAMES.iter().enumerate() {
        std::fs::write(
            dir.join(name),
            rarkit_testdata::chatter(index as u64 + 1, 24 << 10),
        )
        .unwrap();
    }
    let mut args = vec!["a", "-idq", "-m3", "-ep"];
    if solid {
        args.push("-s");
    }
    args.push("src.rar");
    args.extend_from_slice(&NAMES);
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(&args)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "building the archive: {out:?}");
    for name in NAMES {
        std::fs::remove_file(dir.join(name)).unwrap();
    }
    let bytes = std::fs::read(dir.join("src.rar")).unwrap();
    std::fs::remove_file(dir.join("src.rar")).unwrap();
    bytes
}

fn vint(bytes: &[u8], mut at: usize) -> (u64, usize) {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = bytes[at];
        at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return (value, at);
        }
    }
}

/// `archive` with the compression version (bits 0 to 5 of the compression
/// information, spec F 3.2.6) of each RAR 5 member named in `members` set
/// to `version`, and that header's CRC32 recomputed.
fn rar5_with_version(mut archive: Vec<u8>, members: &[&str], version: u8) -> Vec<u8> {
    let mut at = 8;
    while at < archive.len() {
        let (size, fields) = vint(&archive, at + 4);
        let end = fields + size as usize;
        let (kind, next) = vint(&archive, fields);
        let (flags, mut next) = vint(&archive, next);
        if flags & 1 != 0 {
            next = vint(&archive, next).1;
        }
        let mut data = 0;
        if flags & 2 != 0 {
            (data, next) = vint(&archive, next);
        }
        if kind == 2 {
            let (file_flags, next) = vint(&archive, next);
            let next = vint(&archive, next).1;
            let mut next = vint(&archive, next).1;
            if file_flags & 2 != 0 {
                next += 4;
            }
            if file_flags & 4 != 0 {
                next += 4;
            }
            let info = next;
            let next = vint(&archive, vint(&archive, info).1).1;
            let (len, name) = vint(&archive, next);
            if members
                .iter()
                .any(|m| m.as_bytes() == &archive[name..name + len as usize])
            {
                archive[info] = (archive[info] & 0xc0) | version;
                let crc = rarkit::checksum::crc32(&archive[at + 4..end]);
                archive[at..at + 4].copy_from_slice(&crc.to_le_bytes());
            }
        }
        if kind == 5 {
            break;
        }
        at = end + data as usize;
    }
    archive
}

/// `archive` with the unpack version (byte 24 of the header, spec F 3.3.5)
/// of each RAR 1.5 to 4.x member named in `members` set to `version`, the
/// header's CRC16 recomputed.
fn rar4_with_version(mut archive: Vec<u8>, members: &[&str], version: u8) -> Vec<u8> {
    let mut at = 7;
    while at + 7 <= archive.len() {
        let kind = archive[at + 2];
        let flags = u16::from_le_bytes([archive[at + 3], archive[at + 4]]);
        let size = usize::from(u16::from_le_bytes([archive[at + 5], archive[at + 6]]));
        let add = if kind == 0x74 || flags & 0x8000 != 0 {
            u32::from_le_bytes(archive[at + 7..at + 11].try_into().unwrap()) as usize
        } else {
            0
        };
        if kind == 0x74 {
            let len = usize::from(u16::from_le_bytes([archive[at + 26], archive[at + 27]]));
            if members
                .iter()
                .any(|m| m.as_bytes() == &archive[at + 32..at + 32 + len])
            {
                archive[at + 24] = version;
                let crc = rarkit::checksum::crc32(&archive[at + 2..at + size]) as u16;
                archive[at..at + 2].copy_from_slice(&crc.to_le_bytes());
            }
        }
        if kind == 0x7b {
            break;
        }
        at += size + add;
    }
    archive
}

struct Ran {
    code: Option<i32>,
    /// Stdout with each progress counter's redraws taken out.
    stdout: String,
    stderr: String,
}

/// `rarfast <args>` in `dir`.
fn run(dir: &Path, args: &[&str]) -> Ran {
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    Ran {
        code: out.status.code(),
        stdout: without_counters(&String::from_utf8_lossy(&out.stdout)),
        stderr: without_counters(&String::from_utf8_lossy(&out.stderr)),
    }
}

/// A progress line as the eye reads it: every `NN%` and the backspaces
/// that overwrite it taken out.
fn without_counters(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('\u{8}') {
        out.push_str(&rest[..at]);
        rest = rest[at..].trim_start_matches('\u{8}');
        let counter = rest.len() >= 4
            && rest.as_bytes()[3] == b'%'
            && rest[..3].trim_start().bytes().all(|b| b.is_ascii_digit());
        if counter {
            rest = &rest[4..];
        }
    }
    out.push_str(rest);
    out
}

/// The members a progress line names, in order, with whether it ended
/// `OK`: each by its last component, under either separator the line may
/// print it with. A line shows a member's path with the system's own
/// separator, so on Windows `r393_m3.rar`'s nested members read
/// `SUB\SIB.TXT` and `SUB\NESTED\DEEP.TXT` (and, extracted,
/// `out/SUB\SIB.TXT`), and a split on `/` alone kept the whole path there:
/// two good members matched no name and the RAR 4 test counted five lines
/// for seven (a Windows desktop, 1 Oct 2026). On Unix both separators are
/// `/`, so a backslash stays part of a name as before.
fn lines(stdout: &str, verb: &str) -> Vec<(String, bool)> {
    stdout
        .lines()
        .filter(|line| line.starts_with(&format!("{verb:12}")))
        .map(|line| {
            let name = line[12..].split_whitespace().next().unwrap_or("");
            let name = name
                .rsplit(['/', std::path::MAIN_SEPARATOR])
                .next()
                .unwrap_or(name)
                .to_owned();
            (name, line.trim_end().ends_with("OK"))
        })
        .collect()
}

/// What the reference writes to stderr for these refused members, in
/// order, on separate streams.
fn refusals(names: &[&str]) -> String {
    names
        .iter()
        .map(|name| format!("\nUnknown method in {name}\nYou may need a newer version of RAR."))
        .collect()
}

fn oks(names: &[&str]) -> Vec<(String, bool)> {
    names.iter().map(|n| ((*n).to_owned(), true)).collect()
}

/// `t`, `x` and `e` over one archive with `refused` members refused: the
/// reference's stderr exactly, a line ending `OK` for each of `good` and
/// none for a refused member, `Total errors` two per refused member, exit
/// 2, and on disk the good members' files and no refused member's.
fn every_command(tag: &str, archive: &[u8], refused: &[&str], good: &[&str]) {
    let dir = work(tag);
    std::fs::write(dir.join("a.rar"), archive).unwrap();
    let total = format!("Total errors: {}\n", 2 * refused.len());
    for (command, verb) in [("t", "Testing"), ("x", "Extracting"), ("e", "Extracting")] {
        let _ = std::fs::remove_dir_all(dir.join("out"));
        let args: &[&str] = if command == "t" {
            &["t", "a.rar"]
        } else {
            &[command, "a.rar", "out/"]
        };
        let ran = run(&dir, args);
        let all = format!("{tag} {command}: {}{}", ran.stdout, ran.stderr);
        assert_eq!(ran.code, Some(2), "{all}");
        assert_eq!(ran.stderr, refusals(refused), "{all}");
        assert!(ran.stdout.ends_with(&total), "{all}");
        let files: Vec<_> = lines(&ran.stdout, verb)
            .into_iter()
            .filter(|(name, _)| good.contains(&name.as_str()) || refused.contains(&name.as_str()))
            .collect();
        assert_eq!(files, oks(good), "{all}");
        if command != "t" {
            for name in refused {
                let path = dir.join("out").join(name);
                assert!(!path.exists(), "{all}: {} left", path.display());
            }
        }
        if command == "e" {
            for name in good {
                let base = name.rsplit('/').next().unwrap();
                assert!(dir.join("out").join(base).is_file(), "{all}: {name}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn two_and_three_rar5_members_are_each_named_and_each_counts_two() {
    let dir = work("r5-build");
    let archive = rar5(&dir, false);
    every_command(
        "r5-two",
        &rar5_with_version(archive.clone(), &["b.txt", "d.txt"], 2),
        &["b.txt", "d.txt"],
        &["a.txt", "c.txt", "e.txt"],
    );
    every_command(
        "r5-three",
        &rar5_with_version(archive, &["b.txt", "c.txt", "d.txt"], 2),
        &["b.txt", "c.txt", "d.txt"],
        &["a.txt", "e.txt"],
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn two_and_three_rar4_members_above_29_are_each_named_and_each_counts_two() {
    // Archive order in r393_m3.rar: AUDIO.RAW BIG.TXT EMPTY.DAT ONE.DAT
    // SUB/SIB.TXT SUB/NESTED/DEEP.TXT TABLE.BIN HELLO.TXT DATA.BIN, then
    // three directories. EMPTY.DAT and ONE.DAT are stored.
    every_command(
        "r4-two",
        &rar4_with_version(fixture("r393_m3.rar"), &["BIG.TXT", "TABLE.BIN"], 36),
        &["BIG.TXT", "TABLE.BIN"],
        &[
            "AUDIO.RAW",
            "EMPTY.DAT",
            "ONE.DAT",
            "SIB.TXT",
            "DEEP.TXT",
            "HELLO.TXT",
            "DATA.BIN",
        ],
    );
    every_command(
        "r4-three",
        &rar4_with_version(
            fixture("r393_m3.rar"),
            &["BIG.TXT", "TABLE.BIN", "DATA.BIN"],
            99,
        ),
        &["BIG.TXT", "TABLE.BIN", "DATA.BIN"],
        &[
            "AUDIO.RAW",
            "EMPTY.DAT",
            "ONE.DAT",
            "SIB.TXT",
            "DEEP.TXT",
            "HELLO.TXT",
        ],
    );
}

/// `-ierr`, one stream: unrar 7.23 prints each pair right after the `OK`
/// line before it, no blank line between, and the next member's line
/// right after it:
///
/// ```text
/// Testing     a.txt   OK \nUnknown method in b.txt\nYou may need a newer
/// version of RAR.\nTesting     c.txt   OK \nUnknown method in d.txt\n...
/// ```
#[test]
fn on_one_stream_each_refusal_sits_between_the_lines_around_it() {
    let dir = work("ierr");
    let archive = rar5_with_version(rar5(&dir, false), &["b.txt", "d.txt"], 2);
    std::fs::write(dir.join("a.rar"), archive).unwrap();
    let ran = run(&dir, &["t", "-ierr", "a.rar"]);
    assert_eq!(ran.code, Some(2), "{}", ran.stderr);
    assert_eq!(ran.stdout, "");
    let wanted = [
        "Testing     a.txt",
        "Unknown method in b.txt",
        "You may need a newer version of RAR.",
        "Testing     c.txt",
        "Unknown method in d.txt",
        "You may need a newer version of RAR.",
        "Testing     e.txt",
        "Total errors: 4",
    ];
    let got: Vec<_> = ran
        .stderr
        .lines()
        .skip_while(|line| !line.starts_with("Testing     "))
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(got.len(), wanted.len(), "{}", ran.stderr);
    for (line, want) in got.iter().zip(wanted) {
        assert!(
            line.starts_with(want),
            "{line:?} for {want:?}: {}",
            ran.stderr
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Where the stdout messages are dropped (`-idq`, and `p`), stderr ends
/// with ONE newline after the pairs, whether some members were refused or
/// all of them (unrar 7.23, 30 Sep 2026, `t`, `x` and `p`). Until then rarfast ended it
/// on the last pair's text.
#[test]
fn a_quiet_run_ends_its_stderr_with_one_newline() {
    let pair =
        |name: &str| format!("\nUnknown method in {name}\nYou may need a newer version of RAR.");
    for (tag, refused) in [("some", &["b.txt", "d.txt"][..]), ("all", &NAMES[..])] {
        let dir = work(&format!("idq-{tag}"));
        let archive = rar5_with_version(rar5(&dir, false), refused, 2);
        std::fs::write(dir.join("a.rar"), archive).unwrap();
        let pairs: String = refused.iter().map(|name| pair(name)).collect();
        for args in [
            &["t", "-idq", "a.rar"][..],
            &["x", "-idq", "a.rar", "out/"],
            &["p", "a.rar"],
            &["p", "-idq", "a.rar"],
        ] {
            let ran = run(&dir, args);
            assert_eq!(ran.code, Some(2), "{tag} {args:?}: {}", ran.stderr);
            assert_eq!(ran.stderr, format!("{pairs}\n"), "{tag} {args:?}");
            let _ = std::fs::remove_dir_all(dir.join("out"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// `p`: the good members' bytes on stdout, the refused ones named on
/// stderr (unrar 7.23: 540,090 bytes of three members, the two pairs,
/// exit 2).
#[test]
fn print_writes_the_good_members_and_names_the_refused_ones() {
    let dir = work("print");
    let archive = rar5_with_version(rar5(&dir, false), &["b.txt", "d.txt"], 2);
    std::fs::write(dir.join("a.rar"), archive).unwrap();
    let out = Command::new(rarfast())
        .current_dir(&dir)
        .args(["p", "-inul", "a.rar"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let mut wanted = rarkit_testdata::chatter(1, 24 << 10);
    wanted.extend(rarkit_testdata::chatter(3, 24 << 10));
    wanted.extend(rarkit_testdata::chatter(5, 24 << 10));
    assert!(out.stdout == wanted, "{} bytes", out.stdout.len());

    let out = Command::new(rarfast())
        .current_dir(&dir)
        .args(["p", "a.rar"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.starts_with(&refusals(&["b.txt", "d.txt"])),
        "{stderr:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Nothing of a refused member reaches the disk: an existing file of its
/// name stays as it was under `-o+`, and `-kb` keeps no empty file for it
/// (unrar 7.23: `old` left in `b.txt`, no `d.txt`). Until 28 Sep 2026
/// rarkit created the file, and on the refusal removed it: the user's own
/// `b.txt` was deleted.
#[test]
fn a_refused_member_touches_no_file() {
    let dir = work("disk");
    let archive = rar5_with_version(rar5(&dir, false), &["b.txt", "d.txt"], 2);
    std::fs::write(dir.join("a.rar"), archive).unwrap();
    std::fs::create_dir_all(dir.join("out")).unwrap();
    std::fs::write(dir.join("out/b.txt"), b"old\n").unwrap();
    let ran = run(&dir, &["x", "-o+", "-kb", "a.rar", "out/"]);
    assert_eq!(ran.code, Some(2), "{}{}", ran.stdout, ran.stderr);
    assert_eq!(std::fs::read(dir.join("out/b.txt")).unwrap(), b"old\n");
    assert!(!dir.join("out/d.txt").exists());
    for name in ["a.txt", "c.txt", "e.txt"] {
        assert!(dir.join("out").join(name).is_file(), "{name}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `l` has nothing to refuse: unrar 7.23 lists all five, exit 0.
#[test]
fn a_listing_lists_every_member_and_exits_0() {
    let dir = work("list");
    let archive = rar5_with_version(rar5(&dir, false), &["b.txt", "d.txt"], 2);
    std::fs::write(dir.join("a.rar"), archive).unwrap();
    for command in ["l", "lb"] {
        let ran = run(&dir, &[command, "a.rar"]);
        assert_eq!(ran.code, Some(0), "{command}: {}{}", ran.stdout, ran.stderr);
        assert!(!ran.stderr.contains("Unknown method"), "{command}");
        for name in NAMES {
            assert!(ran.stdout.contains(name), "{command}: {name}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// PINNED DIFFERENCE, spec F 3.2.6. A solid archive: unrar 7.23 tests
/// `a.txt`, names `b.txt`, and stops (`Total errors: 2`, exit 2). The
/// spec has the walk go on past a refused member, the chain broken, so
/// here the members continuing it fail their checksums and `d.txt` is
/// named in its own place as well.
#[test]
fn pinned_solid_every_refused_member_is_named_where_unrar_stops_at_the_first() {
    let dir = work("solid");
    let archive = rar5_with_version(rar5(&dir, true), &["b.txt", "d.txt"], 2);
    std::fs::write(dir.join("a.rar"), archive).unwrap();
    let ran = run(&dir, &["t", "a.rar"]);
    assert_eq!(ran.code, Some(2), "{}{}", ran.stdout, ran.stderr);
    assert_eq!(
        ran.stderr,
        format!(
            "{}\nc.txt                - checksum error{}\ne.txt                - checksum error",
            refusals(&["b.txt"]),
            refusals(&["d.txt"]),
        )
    );
    assert!(ran.stdout.ends_with("Total errors: 6\n"), "{}", ran.stdout);
    assert_eq!(
        lines(&ran.stdout, "Testing"),
        vec![
            ("a.txt".to_owned(), true),
            ("c.txt".to_owned(), false),
            ("e.txt".to_owned(), false),
        ]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The dialect reads a refusal off the header before the engine makes it,
/// so the two readings of spec F 3.3.5's table (and of 3.2.6's version
/// field) must agree for EVERY version, or a member the engine decodes
/// would be withheld from the disk. Each version is either named as a
/// refusal or tested on a line of its own, never passed over; a debug
/// build also asserts it at the close.
#[test]
fn each_version_either_names_its_refusal_or_gets_a_testing_line() {
    let dir = work("sweep");
    let rar5_archive = rar5(&dir, false);
    let mut cases = Vec::new();
    for version in 0..=255u8 {
        cases.push((
            format!("rar4 {version}"),
            "BIG.TXT",
            rar4_with_version(fixture("r393_m3.rar"), &["BIG.TXT"], version),
        ));
    }
    for version in 0..64u8 {
        cases.push((
            format!("rar5 {version}"),
            "b.txt",
            rar5_with_version(rar5_archive.clone(), &["b.txt"], version),
        ));
    }
    for (label, member, archive) in cases {
        std::fs::write(dir.join("a.rar"), archive).unwrap();
        let ran = run(&dir, &["t", "a.rar"]);
        let named = ran
            .stderr
            .contains(&format!("Unknown method in {member}\n"));
        let tested = lines(&ran.stdout, "Testing")
            .iter()
            .any(|(name, _)| name == member);
        assert!(
            named != tested,
            "{label}: named {named}, tested {tested}, exit {:?}: {}{}",
            ran.code,
            ran.stdout,
            ran.stderr
        );
        assert_ne!(ran.code, Some(101), "{label}: {}", ran.stderr);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Refused members ALONE selected: nothing is processed, so unrar 7.23
/// closes with `No files to extract` where `Total errors` would be, no
/// blank line before it, the pairs on stderr, exit 2 (28 Sep 2026, `t` and
/// `x` of `BIG.TXT` at unpack version 36; `t` of `b.txt` and `d.txt` at
/// compression version 2).
#[test]
fn refused_members_selected_alone_are_no_files_to_extract() {
    let dir = work("alone");
    let archive = rar5_with_version(rar5(&dir, false), &["b.txt", "d.txt"], 2);
    std::fs::write(dir.join("a.rar"), archive).unwrap();
    let ran = run(&dir, &["t", "a.rar", "b.txt", "d.txt"]);
    assert_eq!(ran.code, Some(2), "{}{}", ran.stdout, ran.stderr);
    assert_eq!(ran.stderr, refusals(&["b.txt", "d.txt"]));
    assert!(
        ran.stdout
            .ends_with("Testing archive a.rar\n\nNo files to extract\n"),
        "{:?}",
        ran.stdout
    );

    std::fs::write(
        dir.join("b.rar"),
        rar4_with_version(fixture("r393_m3.rar"), &["BIG.TXT"], 36),
    )
    .unwrap();
    let ran = run(&dir, &["x", "b.rar", "BIG.TXT", "out/"]);
    assert_eq!(ran.code, Some(2), "{}{}", ran.stdout, ran.stderr);
    assert_eq!(ran.stderr, refusals(&["BIG.TXT"]));
    assert!(
        ran.stdout
            .ends_with("Extracting from b.rar\n\nNo files to extract\n"),
        "{:?}",
        ran.stdout
    );
    assert!(!dir.join("out/BIG.TXT").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A refused member the selection does NOT take, in a SOLID archive, with
/// selected members behind it: the chain is decoded through it, so those
/// members cannot be had, and the refused member is the one named.
///
/// Measured against unrar 7.23 on 9 Oct 2026 (an Apple silicon Mac): five
/// members `a.txt` to `e.txt` written solid by rar 7.23 `-m3 -s`, `c.txt`'s
/// algorithm version set to 9 and its header checksum redone; `x`, `e`,
/// `t` and `p`, plain, `-ierr` and `-idq`, ten selections, 160 runs, at
/// `-mt1` and the default width. Asked for `e.txt`, or `d.txt` and
/// `e.txt`: `Unknown method in c.txt` and `You may need a newer version
/// of RAR.` on stderr, no line for a member behind it, nothing written,
/// `No files to extract`, exit 2. Asked for `a.txt` and `e.txt`: `a.txt`
/// is written, then the same two lines, `Total errors: 2`, exit 2. A
/// name the archive does not hold: the same two lines, `No files to
/// extract`, exit 2 (the reference reads the whole chain then). Asked
/// for `a.txt` alone, which stands in front: `All OK`, exit 0.
///
/// Until then rarfast never named `c.txt`: it opened a line for each
/// selected member behind it and said `- checksum error` of each, exit 3,
/// and for a name the archive does not hold `No files to extract`, exit
/// 10. All 160 runs are now the reference's, its `Skipping    <name>`
/// lines apart, which rarfast does not print.
///
/// Where the refused member IS selected nothing changes, and the
/// difference pinned above stays (the walk goes on past it).
///
/// Width and memory: `-mt1` and `-mt2`, stated; five members of 24 KiB.
#[test]
fn a_refused_member_not_taken_stops_the_solid_chain_behind_it() {
    let dir = work("chain");
    let archive = rar5_with_version(rar5(&dir, true), &["c.txt"], 9);
    std::fs::write(dir.join("a.rar"), archive).unwrap();
    let named = refusals(&["c.txt"]);
    for width in ["-mt1", "-mt2"] {
        for command in ["t", "x"] {
            let go = |selection: &[&str]| {
                let _ = std::fs::remove_dir_all(dir.join("out"));
                std::fs::create_dir_all(dir.join("out")).unwrap();
                let mut args = vec![command, width, "-y", "a.rar"];
                args.extend_from_slice(selection);
                if command == "x" {
                    args.push("out/");
                }
                let ran = run(&dir, &args);
                let mut written: Vec<String> = std::fs::read_dir(dir.join("out"))
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                    .collect();
                written.sort_unstable();
                (ran, written)
            };
            let verb = if command == "t" {
                "Testing"
            } else {
                "Extracting"
            };
            // Behind the refused member, and nothing in front of it taken.
            for selection in [&["e.txt"][..], &["d.txt", "e.txt"], &["nomatch.txt"]] {
                let (ran, written) = go(selection);
                let said = format!(
                    "{command} {width} {selection:?}: {}{}",
                    ran.stdout, ran.stderr
                );
                assert_eq!(ran.code, Some(2), "{said}");
                assert_eq!(ran.stderr, named, "{said}");
                assert!(ran.stdout.ends_with("\nNo files to extract\n"), "{said}");
                assert_eq!(lines(&ran.stdout, verb), vec![], "{said}");
                assert!(written.is_empty(), "{said}");
            }
            // One in front of it and one behind: the first is had.
            let (ran, written) = go(&["a.txt", "e.txt"]);
            let said = format!("{command} {width}: {}{}", ran.stdout, ran.stderr);
            assert_eq!(ran.code, Some(2), "{said}");
            assert_eq!(ran.stderr, named, "{said}");
            assert!(ran.stdout.ends_with("Total errors: 2\n"), "{said}");
            assert_eq!(lines(&ran.stdout, verb), oks(&["a.txt"]), "{said}");
            if command == "x" {
                assert_eq!(written, ["a.txt"], "{said}");
            }
            // In front of it alone: the refused member is never reached.
            let (ran, _) = go(&["a.txt", "b.txt"]);
            let said = format!("{command} {width}: {}{}", ran.stdout, ran.stderr);
            assert_eq!((ran.code, ran.stderr.as_str()), (Some(0), ""), "{said}");
            assert!(ran.stdout.ends_with("All OK\n"), "{said}");
        }
    }
    // Not solid: a member behind it leans on nothing, and a refused
    // member that was not asked for is not this run's business.
    let apart = rar5_with_version(rar5(&dir, false), &["c.txt"], 9);
    std::fs::write(dir.join("a.rar"), apart).unwrap();
    let ran = run(&dir, &["t", "-mt1", "a.rar", "e.txt"]);
    assert_eq!(
        (ran.code, ran.stderr.as_str()),
        (Some(0), ""),
        "{}",
        ran.stdout
    );
    let _ = std::fs::remove_dir_all(&dir);
}
