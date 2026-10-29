//! A cut archive, a damaged later header, a cut volume in a set, and a
//! member whose compressed stream is damaged.
//!
//! Until 28 Sep 2026 rarkit refused at open an archive cut short or
//! carrying a header it could not step over (`<path> is not RAR archive`,
//! exit 10), where the reference tests and extracts every member in front
//! of the damage; a set whose middle volume was cut dropped the members
//! behind the cut silently and exited 1; and a member whose LZ stream was
//! damaged near its start printed the engine's reason and exited 2.
//!
//! Spec F settles what is read: a source cut at a block boundary is a
//! complete read (3.2.7 item 2, 3.5.5); one cut inside a header or a data
//! area is `Truncated` (4.1); a header whose checksum fails is used for
//! nothing, the walk stops there and the members in front of it are
//! delivered, the failure reported after them (4.6); a failed member is
//! reported through its own close (section 8). The words and the exit
//! codes are the reference's, measured with unrar 7.23 on a Mac on 27
//! Sep 2026 over RAR 5 archives written `-m3`, solid and not, and the
//! genuine rar 4.2.0 vectors `specs/vectors-J/archives/r420_mixed_*.rar`:
//!
//! | Shape | unrar 7.23 |
//! |---|---|
//! | cut at a block boundary | the members in front `OK`, `All OK`, exit 0 |
//! | cut inside a later header | the members in front `OK`, stderr `\nUnexpected end of archive`, exit 1 |
//! | cut inside a member's data | in front `OK`, `<name> - checksum error`, `Unexpected end of archive`, exit 3 |
//! | a later header the walk cannot step over (RAR 5, size broken) | in front `OK`, `Corrupt header is found`, exit 3 |
//! | a member's stream damaged, any family, solid or not | `<name> - checksum error`, nothing else, exit 3 |
//! | `l` over a cut / over a broken header | the members in front listed, the same line once, exit 1 / exit 3 |
//! | a set whose middle volume is cut in a member's data | in front `OK`, `<name> - checksum error`, `Unexpected end of archive`, exit 3 |
//!
//! Two more rows were pinned here against the reference until 8 Oct 2026
//! and now follow it: rarfast delivers every member the reference
//! delivers from the same damaged input, and exits with its code
//! (`tests/damaged_archive_walk.rs` holds the measurements):
//!
//! - a header whose CHECKSUM alone fails is read anyway (`<name> - the
//!   file header is corrupt`), and its member and every later one is
//!   tested, extracted and listed, exit 3;
//! - a RAR 5 archive whose main header carries a quick open LOCATOR
//!   pointing past a cut at a block boundary is cut, exit 1. (The
//!   reference says `Unexpected end of archive` a SECOND time, before any
//!   member, on a cut inside a member; that is said once here.)
//!
//! One difference is left, settled by the specification and pinned by a
//! row below that names the section:
//!
//! - a RAR 4 archive cut inside a header: the reference reads the header
//!   it has as a whole one (`- the file header is corrupt`, `Unknown
//!   method in`, exit 3). Spec F 4.1 says a header running past the source
//!   is `Truncated`, so this is a cut: `Unexpected end of archive`, exit 1.

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-cut-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const NAMES: [&str; 4] = ["a.txt", "b.txt", "c.txt", "d.txt"];

/// Four members of 32 KiB, archived by rarfast, `-m3`, with no quick open
/// record and so no locator. Returns the archive's bytes.
fn rar5(dir: &Path, solid: bool, extra: &[&str]) -> Vec<u8> {
    for (index, name) in NAMES.iter().enumerate() {
        std::fs::write(
            dir.join(name),
            rarkit_testdata::chatter(index as u64 + 1, 32 << 10),
        )
        .unwrap();
    }
    let mut args = vec!["a", "-idq", "-m3", "-ep"];
    if solid {
        args.push("-s");
    }
    args.extend_from_slice(extra);
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

/// A genuine rar 4.2.0 archive from the committed vectors.
fn rar4(solid: bool) -> Vec<u8> {
    let name = if solid {
        "r420_mixed_solid.rar"
    } else {
        "r420_mixed_nonsolid.rar"
    };
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../specs/vectors-J/archives")
            .join(name),
    )
    .unwrap()
}

/// One block of either family: where its header starts, where its header
/// ends and where its data ends, and whether it is a member's.
struct Block {
    start: usize,
    header_end: usize,
    end: usize,
    file: bool,
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

/// The block map, read the way spec F 3.2.2 and 3.3.1 frame it.
fn blocks(bytes: &[u8]) -> Vec<Block> {
    let mut out = Vec::new();
    if bytes[6] == 1 {
        let mut at = 8;
        while at < bytes.len() {
            let (size, fields) = vint(bytes, at + 4);
            let header_end = fields + size as usize;
            let (kind, next) = vint(bytes, fields);
            let (flags, mut next) = vint(bytes, next);
            if flags & 1 != 0 {
                next = vint(bytes, next).1;
            }
            let data = if flags & 2 != 0 {
                vint(bytes, next).0
            } else {
                0
            };
            let end = header_end + data as usize;
            out.push(Block {
                start: at,
                header_end,
                end,
                file: kind == 2,
            });
            if kind == 5 {
                break;
            }
            at = end;
        }
    } else {
        let mut at = 7;
        while at + 7 <= bytes.len() {
            let kind = bytes[at + 2];
            let flags = u16::from_le_bytes([bytes[at + 3], bytes[at + 4]]);
            let size = usize::from(u16::from_le_bytes([bytes[at + 5], bytes[at + 6]]));
            let data = if kind == 0x74 || flags & 0x8000 != 0 {
                u32::from_le_bytes(bytes[at + 7..at + 11].try_into().unwrap()) as usize
            } else {
                0
            };
            out.push(Block {
                start: at,
                header_end: at + size,
                end: at + size + data,
                file: kind == 0x74,
            });
            if kind == 0x7b {
                break;
            }
            at += size + data;
        }
    }
    out
}

/// The members' blocks only.
fn members(bytes: &[u8]) -> Vec<Block> {
    blocks(bytes).into_iter().filter(|b| b.file).collect()
}

struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Ran {
    /// How many members' progress lines end `OK`.
    fn oks(&self) -> usize {
        self.stdout
            .lines()
            .filter(|line| line.trim_end().ends_with(" OK") && !line.starts_with("All OK"))
            .count()
    }
}

/// `rarfast <args>` in `dir`, with stdout's backspaces taken out.
fn run(dir: &Path, args: &[&str]) -> Ran {
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    Ran {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).replace('\u{8}', ""),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Writes `bytes` as `name` in `dir` and runs `t` over it.
fn test_over(dir: &Path, name: &str, bytes: &[u8], extra: &[&str]) -> Ran {
    std::fs::write(dir.join(name), bytes).unwrap();
    let mut args = vec!["t"];
    args.extend_from_slice(extra);
    args.push(name);
    run(dir, &args)
}

/// The four sources every row runs over: RAR 5 and RAR 4, solid and not.
fn sources(dir: &Path) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("r5", rar5(dir, false, &[])),
        ("r5s", rar5(dir, true, &[])),
        ("r4", rar4(false)),
        ("r4s", rar4(true)),
    ]
}

/// unrar 7.23: `\nUnexpected end of archive` on stderr, once, exit 1; the
/// members in front of the cut `OK`. Nothing was refused at open.
#[test]
fn a_cut_inside_a_later_header_tests_the_members_in_front() {
    let dir = work("cuthdr");
    for (tag, bytes) in sources(&dir) {
        let files = members(&bytes);
        let mid = &files[files.len() / 2];
        let cut = &bytes[..(mid.start + mid.header_end) / 2];
        for mt in [&[][..], &["-mt1"][..], &["-mt4"][..]] {
            let ran = test_over(&dir, &format!("{tag}.rar"), cut, mt);
            assert_eq!(
                ran.code,
                Some(1),
                "{tag} {mt:?}: {}{}",
                ran.stdout,
                ran.stderr
            );
            assert_eq!(ran.stderr, "\nUnexpected end of archive", "{tag} {mt:?}");
            assert_eq!(ran.oks(), files.len() / 2, "{tag} {mt:?}: {}", ran.stdout);
            assert!(
                ran.stdout.contains("Total errors: 1"),
                "{tag}: {}",
                ran.stdout
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// unrar 7.23: the member the cut goes through `- checksum error`, then
/// `Unexpected end of archive`, `Total errors: 2`, exit 3. `x` keeps the
/// whole members and removes the broken one; `-kb` keeps it.
#[test]
fn a_cut_inside_a_members_data_fails_that_member_and_says_so() {
    let dir = work("cutdata");
    for (tag, bytes) in sources(&dir) {
        let files = members(&bytes);
        for victim in [files.len() / 2, files.len() - 1] {
            let block = &files[victim];
            let cut = &bytes[..(block.header_end + block.end) / 2];
            let ran = test_over(&dir, &format!("{tag}.rar"), cut, &[]);
            assert_eq!(
                ran.code,
                Some(3),
                "{tag}/{victim}: {}{}",
                ran.stdout,
                ran.stderr
            );
            assert!(
                ran.stderr
                    .ends_with("- checksum error\nUnexpected end of archive"),
                "{tag}/{victim}: {:?}",
                ran.stderr
            );
            assert_eq!(ran.stderr.matches("Unexpected end").count(), 1, "{tag}");
            assert_eq!(ran.oks(), victim, "{tag}/{victim}: {}", ran.stdout);
            assert!(
                ran.stdout.contains("Total errors: 2"),
                "{tag}: {}",
                ran.stdout
            );

            let out = dir.join(format!("x-{tag}-{victim}"));
            std::fs::create_dir_all(&out).unwrap();
            let archive = dir.join(format!("{tag}.rar"));
            let ran = run(&out, &["x", "-y", archive.to_str().unwrap()]);
            assert_eq!(ran.code, Some(3), "x {tag}/{victim}: {}", ran.stderr);
            let written = std::fs::read_dir(&out).unwrap().count();
            assert_eq!(
                written, victim,
                "x {tag}/{victim}: the broken member stays only on -kb"
            );
            let _ = std::fs::remove_dir_all(&out);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Spec F 3.2.7 E3, a RAR 5 file cut inside a header's first four bytes,
/// its checksum, before any of its size is there: a cut like any other
/// cut inside a header. rar and unrar 7.23 agree (28 Oct 2026, the brief 4
/// sweep's `rar5-cut-*` rows): the members in front `OK`, `\nUnexpected
/// end of archive`, exit 1. Until 28 Oct 2026 rarkit said `Corrupt header
/// is found`, exit 3. Cut inside the MAIN header's checksum the reference
/// says more lines than one; the exit is the row here.
#[test]
fn a_cut_inside_a_rar5_headers_checksum_is_a_cut() {
    let dir = work("cutcrc");
    for (tag, bytes) in [
        ("r5", rar5(&dir, false, &[])),
        ("r5s", rar5(&dir, true, &[])),
    ] {
        let files = members(&bytes);
        let mid = &files[files.len() / 2];
        for kept in 1..=4 {
            let cut = &bytes[..mid.start + kept];
            for mt in [&["-mt1"][..], &["-mt4"][..]] {
                let ran = test_over(&dir, &format!("{tag}.rar"), cut, mt);
                assert_eq!(
                    ran.code,
                    Some(1),
                    "{tag} {kept} {mt:?}: {}{}",
                    ran.stdout,
                    ran.stderr
                );
                assert_eq!(ran.stderr, "\nUnexpected end of archive", "{tag} {kept}");
                assert_eq!(ran.oks(), files.len() / 2, "{tag} {kept}: {}", ran.stdout);
            }
            let out = dir.join(format!("x-{tag}-{kept}"));
            std::fs::create_dir_all(&out).unwrap();
            let archive = dir.join(format!("{tag}.rar"));
            let ran = run(&out, &["x", "-y", archive.to_str().unwrap()]);
            assert_eq!(ran.code, Some(1), "x {tag} {kept}: {}", ran.stderr);
            assert_eq!(std::fs::read_dir(&out).unwrap().count(), files.len() / 2);
            let _ = std::fs::remove_dir_all(&out);

            let main = &bytes[..8 + kept];
            let ran = test_over(&dir, &format!("{tag}.rar"), main, &[]);
            assert_eq!(ran.code, Some(1), "main {tag} {kept}: {}", ran.stderr);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Spec F 3.2.7 item 2: a source cut at a block boundary, with no member
/// split open, is a complete read. unrar 7.23 agrees on an archive with no
/// locator: the members in front `OK`, `All OK`, exit 0.
#[test]
fn a_cut_at_a_block_boundary_is_a_complete_read() {
    let dir = work("cutblk");
    for (tag, bytes) in sources(&dir) {
        let files = members(&bytes);
        let cut = &bytes[..files[files.len() / 2].start];
        let ran = test_over(&dir, &format!("{tag}.rar"), cut, &[]);
        assert_eq!(ran.code, Some(0), "{tag}: {}{}", ran.stdout, ran.stderr);
        assert_eq!(ran.stderr, "", "{tag}");
        assert_eq!(ran.oks(), files.len() / 2, "{tag}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// unrar 7.23, a RAR 5 later header whose size field is broken: the
/// members in front `OK`, `Corrupt header is found`, exit 3. (It prints the
/// line twice and counts three errors; rarkit says it once and counts one,
/// as for a cut.)
///
/// A header whose CHECKSUM alone fails is another thing: the reference
/// reads it anyway, says `<name> - the file header is corrupt` (after
/// `Corrupt header is found` in RAR 5, alone in RAR 4), tests and extracts
/// EVERY member and exits 3, and so does rarkit since 8 Oct 2026 (unrar
/// 7.23 on that day, over these four sources). Until then the walk
/// stopped there by spec F 4.6 and the members behind were not extracted.
#[test]
fn a_later_header_the_walk_cannot_pass_ends_the_walk_there() {
    let dir = work("badhdr");
    for (tag, bytes) in sources(&dir) {
        let files = members(&bytes);
        let mid = &files[files.len() / 2];
        // The shape, the bytes, how many members are delivered, and
        // whether stderr is the one line of a walk that stopped.
        let mut shapes = vec![(
            "crc",
            {
                let mut b = bytes.clone();
                b[mid.start] ^= 1;
                b
            },
            files.len(),
            false,
        )];
        if tag.starts_with("r5") {
            shapes.push((
                "size",
                {
                    let mut b = bytes.clone();
                    b[mid.start + 4] ^= 0x20;
                    b
                },
                files.len() / 2,
                true,
            ));
        }
        for (shape, damaged, delivered, stopped) in shapes {
            let ran = test_over(&dir, &format!("{tag}.rar"), &damaged, &[]);
            assert_eq!(
                ran.code,
                Some(3),
                "{tag} {shape}: {}{}",
                ran.stdout,
                ran.stderr
            );
            if stopped {
                assert_eq!(ran.stderr, "\nCorrupt header is found", "{tag} {shape}");
            } else {
                assert!(
                    ran.stderr.ends_with(" - the file header is corrupt"),
                    "{tag} {shape}: {}",
                    ran.stderr
                );
                assert_eq!(
                    ran.stderr.contains("Corrupt header is found"),
                    tag.starts_with("r5"),
                    "{tag} {shape}: {}",
                    ran.stderr
                );
            }
            assert_eq!(ran.oks(), delivered, "{tag} {shape}: {}", ran.stdout);

            let out = dir.join(format!("x-{tag}-{shape}"));
            std::fs::create_dir_all(&out).unwrap();
            let archive = dir.join(format!("{tag}.rar"));
            let ran = run(&out, &["x", "-y", archive.to_str().unwrap()]);
            assert_eq!(ran.code, Some(3), "x {tag} {shape}: {}", ran.stderr);
            let written = std::fs::read_dir(&out).unwrap().count();
            assert_eq!(written, delivered, "x {tag} {shape}");
            let _ = std::fs::remove_dir_all(&out);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// unrar 7.23 `l`: the members in front of the damage are listed, the
/// damage is said once on stderr, and the code is the damage's: 1 for a
/// cut, 3 for a header. A header whose checksum alone fails is read, so
/// EVERY member is listed, with the reference's line naming the member
/// (unrar 7.23, 8 Oct 2026; until then the listing stopped at it).
#[test]
fn a_damaged_archive_lists_what_is_in_front_of_the_damage() {
    let dir = work("list");
    for (tag, bytes) in sources(&dir) {
        let files = members(&bytes);
        let mid = &files[files.len() / 2];
        let cut = bytes[..(mid.header_end + mid.end) / 2].to_vec();
        let mut broken = bytes.clone();
        broken[mid.start] ^= 1;
        for (shape, damaged, code, line, listed) in [
            (
                "cut",
                cut,
                1,
                "\nUnexpected end of archive",
                files.len() / 2 + 1,
            ),
            (
                "header",
                broken,
                3,
                " - the file header is corrupt",
                files.len(),
            ),
        ] {
            std::fs::write(dir.join("l.rar"), &damaged).unwrap();
            let ran = run(&dir, &["lb", "l.rar"]);
            assert_eq!(
                ran.code,
                Some(code),
                "{tag} {shape}: {}{}",
                ran.stdout,
                ran.stderr
            );
            assert!(
                ran.stderr.starts_with('\n') && ran.stderr.ends_with(line),
                "{tag} {shape}: {}",
                ran.stderr
            );
            assert_eq!(
                ran.stdout.lines().count(),
                listed,
                "{tag} {shape}: {}",
                ran.stdout
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// unrar 7.23 over the same members with their stream damaged near its
/// start, where an LZ block's tables are, so the decoder faults rather
/// than mis-produces: `<name> - checksum error` for that member (and, in
/// a solid archive, for the members whose history it spoiled), nothing
/// else on stderr, exit 3. Until 28 Sep 2026 rarkit printed the engine's
/// reason (`malformed archive: Rar5(InvalidCode)`) with no checksum line
/// for a member that had produced no bytes, and exited 2.
#[test]
fn a_damaged_stream_is_a_checksum_error_and_exits_3() {
    let dir = work("lz");
    for (tag, bytes) in sources(&dir) {
        let first = &members(&bytes)[0];
        for at in [1, 2, 3, 6, 12] {
            let mut damaged = bytes.clone();
            for byte in &mut damaged[first.header_end + at..first.header_end + at + 4] {
                *byte ^= 0xa5;
            }
            for mt in [&[][..], &["-mt1"][..]] {
                let ran = test_over(&dir, &format!("{tag}.rar"), &damaged, mt);
                assert_eq!(
                    ran.code,
                    Some(3),
                    "{tag}@{at} {mt:?}: {}{}",
                    ran.stdout,
                    ran.stderr
                );
                assert!(
                    ran.stderr.starts_with('\n') && !ran.stderr.contains("malformed"),
                    "{tag}@{at} {mt:?}: {:?}",
                    ran.stderr
                );
                let complaints = ran.stderr.matches("- checksum error").count();
                assert_eq!(
                    ran.stderr.lines().filter(|l| !l.is_empty()).count(),
                    complaints,
                    "{tag}@{at}: only checksum complaints: {:?}",
                    ran.stderr
                );
                assert!(complaints >= 1, "{tag}@{at}");
                assert!(!ran.stderr.contains("Unexpected end"), "{tag}@{at}");
                if !tag.ends_with('s') {
                    // Not solid: the one member fails and the rest are whole.
                    assert_eq!(complaints, 1, "{tag}@{at}: {:?}", ran.stderr);
                    assert_eq!(ran.oks(), members(&bytes).len() - 1, "{tag}@{at}");
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A three-volume set whose middle volume is cut inside a member's data.
/// unrar 7.23: the members in front `OK`, the one the cut goes through
/// `- checksum error`, `Unexpected end of archive`, exit 3. Until 28 Sep
/// 2026 rarkit left the cut volume out of the chain, never named that
/// member, and exited 1.
#[test]
fn a_cut_volume_fails_the_member_it_cuts_and_says_so() {
    let dir = work("vol");
    for solid in [false, true] {
        for (index, name) in NAMES.iter().enumerate() {
            std::fs::write(
                dir.join(name),
                rarkit_testdata::chatter(index as u64 + 1, 32 << 10),
            )
            .unwrap();
        }
        let mut args = vec!["a", "-idq", "-m3", "-ep", "-v10k"];
        if solid {
            args.push("-s");
        }
        args.push("set.rar");
        args.extend_from_slice(&NAMES);
        let built = run(&dir, &args);
        assert_eq!(built.code, Some(0), "{}", built.stderr);
        for name in NAMES {
            std::fs::remove_file(dir.join(name)).unwrap();
        }
        let mut volumes: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.to_string_lossy().contains(".part"))
            .collect();
        volumes.sort();
        assert!(volumes.len() >= 3, "{volumes:?}");
        let first = volumes[0].file_name().unwrap().to_str().unwrap().to_owned();
        let part2 = volumes[1].clone();
        let bytes = std::fs::read(&part2).unwrap();
        // The first member that STARTS in the second volume, cut half way
        // through its data.
        let victim = members(&bytes)
            .into_iter()
            .nth(1)
            .expect("a member starting in volume two");
        std::fs::write(&part2, &bytes[..(victim.header_end + victim.end) / 2]).unwrap();
        for mt in [&[][..], &["-mt1"][..]] {
            let mut args = vec!["t"];
            args.extend_from_slice(mt);
            args.push(&first);
            let ran = run(&dir, &args);
            assert_eq!(
                ran.code,
                Some(3),
                "solid {solid} {mt:?}: {}{}",
                ran.stdout,
                ran.stderr
            );
            assert!(
                ran.stderr
                    .ends_with("- checksum error\nUnexpected end of archive"),
                "solid {solid} {mt:?}: {:?}",
                ran.stderr
            );
            assert_eq!(ran.stderr.matches("checksum error").count(), 1, "{solid}");
        }
        for entry in std::fs::read_dir(&dir).unwrap() {
            let _ = std::fs::remove_file(entry.unwrap().path());
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// An archive the reference `rar` writes carries a quick open record and
/// a LOCATOR to it in the main header. Cut at a block boundary, the
/// locator points past the end of the file: the reference says
/// `Unexpected end of archive` and exits 1, and so does rarkit since 8 Oct
/// 2026 (until then it read a complete archive and exited 0, by spec F
/// 4.1 and question 4; `tests/damaged_archive_walk.rs` has the same row
/// over rarfast's own archive). Cut inside a member the reference says
/// the line once more than rarkit, first; that is still said once here.
/// Skipped where no `rar` is on PATH.
#[test]
fn a_locator_past_the_cut_says_the_archive_is_cut() {
    let Some(rar) = reference_rar() else {
        eprintln!("skipped a_locator_past_the_cut_says_the_archive_is_cut: no `rar` on PATH");
        return;
    };
    let dir = work("locator");
    for (index, name) in NAMES.iter().enumerate() {
        std::fs::write(
            dir.join(name),
            rarkit_testdata::chatter(index as u64 + 1, 32 << 10),
        )
        .unwrap();
    }
    let mut args = vec!["a", "-idq", "-m3", "-ep", "-qo+", "src.rar"];
    args.extend_from_slice(&NAMES);
    let built = Command::new(rar)
        .current_dir(&dir)
        .args(&args)
        .output()
        .unwrap();
    assert_eq!(built.status.code(), Some(0), "{built:?}");
    let bytes = std::fs::read(dir.join("src.rar")).unwrap();
    let files = members(&bytes);
    let at_block = &bytes[..files[2].start];
    let ran = test_over(&dir, "cut.rar", at_block, &[]);
    assert_eq!(ran.code, Some(1), "{}{}", ran.stdout, ran.stderr);
    assert_eq!(ran.stderr, "\nUnexpected end of archive");
    let in_data = &bytes[..(files[3].header_end + files[3].end) / 2];
    let ran = test_over(&dir, "cut.rar", in_data, &[]);
    assert_eq!(ran.code, Some(3), "{}{}", ran.stdout, ran.stderr);
    assert_eq!(ran.stderr.matches("Unexpected end of archive").count(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The reference `rar`, where one is on PATH.
fn reference_rar() -> Option<PathBuf> {
    let output = Command::new("which").arg("rar").output().ok()?;
    let path = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (output.status.success() && !path.is_empty()).then(|| PathBuf::from(path))
}
