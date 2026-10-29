//! A member whose header names no checksum is never printed as `OK`.
//!
//! Nothing vouches for such a member's bytes: the library's verdict for it
//! is `None` (`MemberOutcome::checksum_ok`), nothing was checked. Until 10
//! Oct 2026 the tool closed its line with the `  OK ` of a member that
//! passed. The reference closes it with a question mark, and so does the
//! tool now.
//!
//! **Measured** against unrar 7.23 and rar 7.23 (aarch64 macOS, 10 Oct
//! 2026) over genuine rar 7.23 archives whose file headers were rewritten
//! as [`unvouched`] rewrites them, `t`, `x`, `e` and `p`, at the default
//! width and `-mt1`, plain and under `-idq`, `-inul` and `-ierr`, stored,
//! compressed, solid and split, with a payload bit changed and without:
//!
//! - the member's line closes with `   ? ` in the five columns where a
//!   verified member has `  OK `, over the counter where there is one,
//!   and under `-idp` in the same place;
//! - it is the member's OWN header that decides: a file copy, a symbolic
//!   link and an empty file each show the mark when their own header names
//!   no checksum, and `OK` when it does, whatever the copy's or the link's
//!   target carries;
//! - a directory, which never carries one, keeps its `OK`;
//! - the run still closes with `All OK` and exits 0, and the member is
//!   extracted whole;
//! - `p` prints no mark for any member, and `-idn`, `-idq` and `-inul`
//!   show none, so those are as they were.
//!
//! **Fixtures**, in `no-checksum-member/`, all GENUINE rar 7.23 for macOS
//! with `-qo-`: `genuine.rar` (`-m0 -oi:1 -ol`: a file, a copy of it, an
//! empty file, a link, a second file and a directory), `solid.rar` (`-m3
//! -s`, two text members) and `set.part{1,2}.rar` (`-m0 -v1000b`, one
//! member). The headers are rewritten here and every other byte is left
//! alone. No genuine writer is known to make a file header without a
//! checksum.
//!
//! Every row runs at `-mt1` and at `-mt4`; the archives are under 2 KB and
//! the runs hold the tool's ordinary working memory, nothing sized here.

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast, tool_named};

const GENUINE: &[u8] = include_bytes!("no-checksum-member/genuine.rar");
const SOLID: &[u8] = include_bytes!("no-checksum-member/solid.rar");
const PART1: &[u8] = include_bytes!("no-checksum-member/set.part1.rar");
const PART2: &[u8] = include_bytes!("no-checksum-member/set.part2.rar");

/// The mark of a member nothing vouches for, and of one that passed.
const UNVOUCHED: &str = "   ? ";
const PASSED: &str = "  OK ";

// ---- rewriting RAR 5 file headers ------------------------------------------

fn vint(bytes: &[u8], at: &mut usize) -> u64 {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let b = bytes[*at];
        *at += 1;
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

fn put_vint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

/// `archive` with the file headers `which` selects (counted from 0) left
/// naming no checksum: the CRC32 field taken out and its flag cleared, a
/// hash record (extra record type 2) removed, the header's size and its
/// own CRC32 redone. With `flip` given, one bit of that file's data area
/// is inverted too.
fn unvouched(archive: &[u8], which: impl Fn(usize) -> bool, flip: Option<usize>) -> Vec<u8> {
    let mut out = archive[..8].to_vec();
    let mut at = 8;
    let mut file = 0;
    while at < archive.len() {
        let start = at;
        let mut p = at + 4;
        let size = vint(archive, &mut p) as usize;
        let end = p + size;
        let kind = vint(archive, &mut p);
        let flags = vint(archive, &mut p);
        let extra = if flags & 1 != 0 {
            vint(archive, &mut p) as usize
        } else {
            0
        };
        let data_size = if flags & 2 != 0 {
            vint(archive, &mut p) as usize
        } else {
            0
        };
        let mut data = archive[end..end + data_size].to_vec();
        at = end + data_size;
        if kind != 2 {
            out.extend_from_slice(&archive[start..end]);
            out.extend_from_slice(&data);
            continue;
        }
        let index = file;
        file += 1;
        if flip == Some(index) {
            let middle = data.len() / 2;
            data[middle] ^= 0x01;
        }
        if !which(index) {
            out.extend_from_slice(&archive[start..end]);
            out.extend_from_slice(&data);
            continue;
        }
        let mut fields = archive[p..end - extra].to_vec();
        let file_flags = fields[0];
        assert_eq!(file_flags & 0x80, 0, "the file flags are one byte");
        let mut q = 1;
        vint(&fields, &mut q); // unpacked size
        vint(&fields, &mut q); // attributes
        if file_flags & 0x02 != 0 {
            q += 4;
        }
        if file_flags & 0x04 != 0 {
            fields.drain(q..q + 4);
            fields[0] = file_flags & !0x04;
        }
        let mut records = Vec::new();
        let mut r = end - extra;
        while r < end {
            let from = r;
            let len = vint(archive, &mut r) as usize;
            let mut t = r;
            if vint(archive, &mut t) != 2 {
                records.extend_from_slice(&archive[from..r + len]);
            }
            r += len;
        }
        let mut rest = Vec::new();
        put_vint(&mut rest, 2);
        put_vint(
            &mut rest,
            if records.is_empty() {
                flags & !1
            } else {
                flags | 1
            },
        );
        if !records.is_empty() {
            put_vint(&mut rest, records.len() as u64);
        }
        if flags & 2 != 0 {
            put_vint(&mut rest, data_size as u64);
        }
        rest.extend_from_slice(&fields);
        rest.extend_from_slice(&records);
        let mut body = Vec::new();
        put_vint(&mut body, rest.len() as u64);
        body.extend_from_slice(&rest);
        out.extend_from_slice(&rarkit::checksum::crc32(&body).to_le_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&data);
    }
    out
}

// ---- running ---------------------------------------------------------------

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-nochecksum-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_tool(tool: &Path, dir: &Path, args: &[&str]) -> Ran {
    let out = output_of(Command::new(tool).current_dir(dir).args(args)).unwrap();
    Ran {
        code: out.status.code(),
        stdout: counters_masked(&String::from_utf8_lossy(&out.stdout)),
        stderr: counters_masked(&String::from_utf8_lossy(&out.stderr)),
    }
}

/// `command` with its switches over `archive`, at one worker and at four:
/// both runs must print the same, which is returned.
fn at_both_widths(dir: &Path, command: &str, switches: &[&str], archive: &str) -> Ran {
    let run = |width: &str| {
        let out = dir.join("o");
        let _ = std::fs::remove_dir_all(&out);
        let mut args = vec![command, width];
        args.extend_from_slice(switches);
        args.push(archive);
        if command == "x" || command == "e" {
            std::fs::create_dir_all(&out).unwrap();
            args.push("o/");
        }
        run_tool(&rarfast(), dir, &args)
    };
    let one = run("-mt1");
    let four = run("-mt4");
    assert_eq!(
        one.stdout, four.stdout,
        "{command} {archive}: stdout by width"
    );
    assert_eq!(
        one.stderr, four.stderr,
        "{command} {archive}: stderr by width"
    );
    assert_eq!(one.code, four.code, "{command} {archive}: exit by width");
    four
}

// ---- the reference's lines -------------------------------------------------

/// The counter as these rows compare it: its place and width kept, its
/// digits not. The tool's counter reads one lower than the reference's on
/// some members of an archive this small (79% where unrar 7.23 shows 80%
/// for `empty` in `genuine.rar`), which is the counter's own matter and
/// is not pinned either way here.
const COUNTER: &str = "\x08\x08\x08\x08nnn%";

/// `text` with every counter (four backspaces, three columns, `%`)
/// replaced by [`COUNTER`].
fn counters_masked(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("\x08\x08\x08\x08") {
        let tail = &rest[at + 4..];
        let counter = tail.len() >= 4
            && tail.as_bytes()[3] == b'%'
            && tail.as_bytes()[..3]
                .iter()
                .all(|b| *b == b' ' || b.is_ascii_digit());
        out.push_str(&rest[..at]);
        if counter {
            out.push_str(COUNTER);
            rest = &tail[4..];
        } else {
            out.push_str("\x08\x08\x08\x08");
            rest = tail;
        }
    }
    out.push_str(rest);
    out
}

/// A file's line: the verb and name padded to column 73, the counter where
/// the reference shows one, then the mark over it.
fn file_line(verb: &str, name: &str, counter: bool, mark: &str) -> String {
    let mut line = format!("{:<73}", format!("{verb:<12}{name}"));
    if counter {
        line.push_str(COUNTER);
    }
    line.push_str(&format!("\x08\x08\x08\x08\x08{mark}\n"));
    line
}

/// A directory's line: padded to column 70, then its bare `OK`.
fn dir_line(verb: &str, name: &str) -> String {
    format!("{:<70}OK\n", format!("{verb:<12}{name}"))
}

// ---- the rows --------------------------------------------------------------

/// Every file header of `genuine.rar` left without a checksum: the file,
/// the copy, the empty file, the link and the second file each close with
/// the question mark, the directory keeps `OK`, and the run is `All OK`,
/// exit 0 (the reference's stdout, byte for byte).
#[test]
fn test_marks_every_member_whose_header_names_no_checksum() {
    let dir = work("t-all");
    std::fs::write(dir.join("none.rar"), unvouched(GENUINE, |_| true, None)).unwrap();
    let ran = at_both_widths(&dir, "t", &[], "none.rar");
    let expected = [
        "\nTesting archive none.rar\n\n".to_owned(),
        file_line("Testing", "one.bin", true, UNVOUCHED),
        file_line("Testing", "two.bin", false, UNVOUCHED),
        file_line("Testing", "empty", true, UNVOUCHED),
        file_line("Testing", "link", false, UNVOUCHED),
        file_line("Testing", "z.txt", true, UNVOUCHED),
        dir_line("Testing", "d"),
        "All OK\n".to_owned(),
    ]
    .concat();
    assert_eq!(ran.stdout, expected);
    assert_eq!(ran.stderr, "");
    assert_eq!(ran.code, Some(0));
}

/// A changed payload bit under a member with no checksum changes nothing
/// that is printed: the mark was already the question mark, and nothing
/// could have told.
#[test]
fn a_changed_bit_under_no_checksum_is_still_the_question_mark() {
    let dir = work("t-flip");
    std::fs::write(dir.join("none.rar"), unvouched(GENUINE, |_| true, Some(0))).unwrap();
    let ran = at_both_widths(&dir, "t", &[], "none.rar");
    assert!(
        ran.stdout
            .contains(&file_line("Testing", "one.bin", true, UNVOUCHED)),
        "{:?}",
        ran.stdout
    );
    assert!(!ran.stdout.contains(PASSED), "{:?}", ran.stdout);
    assert!(ran.stdout.ends_with("All OK\n"), "{:?}", ran.stdout);
    assert_eq!(ran.code, Some(0));
}

/// One header of six without a checksum: that member alone is marked, and
/// each neighbour keeps the `OK` its own checksum earned. Under `-ierr`
/// the same bytes go to stderr; under `-idp` the mark sits where the `OK`
/// does; `-idd` drops `All OK` and keeps the marks.
#[test]
fn test_marks_only_the_member_without_a_checksum() {
    let dir = work("t-one");
    std::fs::write(dir.join("one.rar"), unvouched(GENUINE, |i| i == 4, None)).unwrap();
    let members = [
        file_line("Testing", "one.bin", true, PASSED),
        file_line("Testing", "two.bin", false, PASSED),
        file_line("Testing", "empty", true, PASSED),
        file_line("Testing", "link", false, PASSED),
        file_line("Testing", "z.txt", true, UNVOUCHED),
        dir_line("Testing", "d"),
    ]
    .concat();
    let expected = format!("\nTesting archive one.rar\n\n{members}All OK\n");

    let plain = at_both_widths(&dir, "t", &[], "one.rar");
    assert_eq!(plain.stdout, expected);
    assert_eq!(plain.stderr, "");
    assert_eq!(plain.code, Some(0));

    let moved = at_both_widths(&dir, "t", &["-ierr"], "one.rar");
    assert_eq!(moved.stdout, "");
    assert_eq!(moved.stderr, expected);
    assert_eq!(moved.code, Some(0));

    let no_verdict = at_both_widths(&dir, "t", &["-idd"], "one.rar");
    assert_eq!(
        no_verdict.stdout,
        format!("\nTesting archive one.rar\n\n{members}")
    );
    assert_eq!(no_verdict.code, Some(0));
}

/// The link's own header, and the copy's own, decide their marks: with
/// only the link's checksum gone the link is marked, with only the copy's
/// the copy, and with only the copy's TARGET's the target and not the
/// copy.
#[test]
fn a_link_and_a_copy_are_marked_by_their_own_headers() {
    let dir = work("t-own");
    let marks = |only: usize| {
        let name = format!("only{only}.rar");
        std::fs::write(dir.join(&name), unvouched(GENUINE, |i| i == only, None)).unwrap();
        let ran = at_both_widths(&dir, "t", &[], &name);
        assert_eq!(ran.code, Some(0), "{name}");
        assert!(ran.stdout.ends_with("All OK\n"), "{name}: {:?}", ran.stdout);
        ["one.bin", "two.bin", "empty", "link", "z.txt"].map(|member| {
            let line = ran
                .stdout
                .lines()
                .find(|line| line.starts_with(&format!("Testing     {member} ")))
                .unwrap_or_else(|| panic!("{name}: no line for {member}"));
            if line.ends_with(UNVOUCHED) {
                '?'
            } else if line.ends_with(PASSED) {
                'K'
            } else {
                panic!("{name}: {line:?}")
            }
        })
    };
    assert_eq!(marks(0), ['?', 'K', 'K', 'K', 'K'], "the copy's target");
    assert_eq!(marks(1), ['K', '?', 'K', 'K', 'K'], "the copy");
    assert_eq!(marks(2), ['K', 'K', '?', 'K', 'K'], "the empty file");
    assert_eq!(marks(3), ['K', 'K', 'K', '?', 'K'], "the link");
}

/// `-idp` hides the counter and the mark keeps its place, five columns
/// before the end of the line as an `OK` is.
#[test]
fn the_mark_keeps_its_place_without_the_counter() {
    let dir = work("t-idp");
    std::fs::write(dir.join("none.rar"), unvouched(GENUINE, |_| true, None)).unwrap();
    let ran = at_both_widths(&dir, "t", &["-idp"], "none.rar");
    let bare = |name: &str| format!("{:<68}{UNVOUCHED}\n", format!("Testing     {name}"));
    let expected = [
        "\nTesting archive none.rar\n\n".to_owned(),
        bare("one.bin"),
        bare("two.bin"),
        bare("empty"),
        bare("link"),
        bare("z.txt"),
        dir_line("Testing", "d"),
        "All OK\n".to_owned(),
    ]
    .concat();
    assert_eq!(ran.stdout, expected);
    assert_eq!(ran.code, Some(0));
}

/// The switches that show no mark show none still: `-idn` runs the
/// counters together and ends them once, `-idq` and `-inul` print
/// nothing, and `p` prints the members' bytes and no mark. Exit 0 each.
#[test]
fn the_switches_that_show_no_mark_are_unchanged() {
    let dir = work("quiet");
    std::fs::write(dir.join("none.rar"), unvouched(GENUINE, |_| true, None)).unwrap();
    let names_hidden = at_both_widths(&dir, "t", &["-idn"], "none.rar");
    assert_eq!(
        names_hidden.stdout,
        format!("\nTesting archive none.rar\n{COUNTER}{COUNTER}{COUNTER}\nAll OK\n")
    );
    assert_eq!(names_hidden.code, Some(0));
    for switch in ["-idq", "-inul"] {
        let quiet = at_both_widths(&dir, "t", &[switch], "none.rar");
        assert_eq!(quiet.stdout, "", "{switch}");
        assert_eq!(quiet.stderr, "", "{switch}");
        assert_eq!(quiet.code, Some(0), "{switch}");
    }
    std::fs::write(dir.join("solid.rar"), unvouched(SOLID, |_| true, None)).unwrap();
    let printed = at_both_widths(&dir, "p", &["-inul"], "solid.rar");
    let text = [
        "the quick brown fox jumps over the lazy dog\n".repeat(40),
        "pack my box with five dozen liquor jugs\n".repeat(40),
    ]
    .concat();
    assert_eq!(printed.stdout, text);
    assert_eq!(printed.code, Some(0));
    let headed = at_both_widths(&dir, "p", &["-ierr"], "solid.rar");
    assert_eq!(headed.stdout, text);
    assert!(!headed.stderr.contains('?'), "{:?}", headed.stderr);
    assert!(headed.stderr.ends_with("All OK\n"), "{:?}", headed.stderr);
    assert_eq!(headed.code, Some(0));
}

/// Compressed and solid: both members of the stream are marked.
#[test]
fn a_solid_compressed_stream_is_marked_member_by_member() {
    let dir = work("solid");
    std::fs::write(dir.join("solid.rar"), unvouched(SOLID, |_| true, None)).unwrap();
    let ran = at_both_widths(&dir, "t", &[], "solid.rar");
    let expected = [
        "\nTesting archive solid.rar\n\n".to_owned(),
        file_line("Testing", "p.txt", true, UNVOUCHED),
        file_line("Testing", "q.txt", true, UNVOUCHED),
        "All OK\n".to_owned(),
    ]
    .concat();
    assert_eq!(ran.stdout, expected);
    assert_eq!(ran.code, Some(0));
}

/// A member split over two volumes with no checksum in either header: the
/// mark closes its LAST volume's line.
#[test]
fn a_split_member_is_marked_on_its_last_volume_line() {
    let dir = work("split");
    std::fs::write(dir.join("set.part1.rar"), unvouched(PART1, |_| true, None)).unwrap();
    std::fs::write(dir.join("set.part2.rar"), unvouched(PART2, |_| true, None)).unwrap();
    let ran = at_both_widths(&dir, "t", &[], "set.part1.rar");
    let expected = [
        "\nTesting archive set.part1.rar\n\n".to_owned(),
        format!("{:<73}{COUNTER}\n", "Testing     s.bin"),
        "\nTesting archive set.part2.rar\n\n".to_owned(),
        file_line("...", "s.bin", true, UNVOUCHED),
        "All OK\n".to_owned(),
    ]
    .concat();
    assert_eq!(ran.stdout, expected);
    assert_eq!(ran.stderr, "");
    assert_eq!(ran.code, Some(0));
}

/// `x` and `e`: the same mark on the `Extracting` lines, every member
/// written whole, the link made, `All OK`, exit 0. Unix, for the link and
/// for the `/` the lines are measured with.
#[cfg(unix)]
#[test]
fn extract_marks_the_member_and_writes_it_whole() {
    let dir = work("x-all");
    std::fs::write(dir.join("none.rar"), unvouched(GENUINE, |_| true, None)).unwrap();
    let members = [
        file_line("Extracting", "o/one.bin", true, UNVOUCHED),
        file_line("Extracting", "o/two.bin", true, UNVOUCHED),
        file_line("Extracting", "o/empty", true, UNVOUCHED),
        file_line("Extracting", "o/link", false, UNVOUCHED),
        file_line("Extracting", "o/z.txt", true, UNVOUCHED),
    ]
    .concat();
    for command in ["x", "e"] {
        let ran = at_both_widths(&dir, command, &[], "none.rar");
        let directory = if command == "x" {
            dir_line("Creating", "o/d")
        } else {
            String::new()
        };
        assert_eq!(
            ran.stdout,
            format!("\nExtracting from none.rar\n\n{members}{directory}All OK\n"),
            "{command}"
        );
        assert_eq!(ran.stderr, "", "{command}");
        assert_eq!(ran.code, Some(0), "{command}");
        let one = std::fs::read(dir.join("o/one.bin")).unwrap();
        assert_eq!(one.len(), 300, "{command}");
        assert_eq!(
            std::fs::read(dir.join("o/two.bin")).unwrap(),
            one,
            "{command}"
        );
        assert_eq!(
            std::fs::read(dir.join("o/z.txt")).unwrap(),
            b"tail\n",
            "{command}"
        );
        assert_eq!(
            std::fs::read(dir.join("o/empty")).unwrap(),
            b"",
            "{command}"
        );
        assert_eq!(
            std::fs::read_link(dir.join("o/link")).unwrap(),
            Path::new("one.bin"),
            "{command}"
        );
    }
}

/// `x` of the split member: the mark on the last volume's line, the
/// member whole on disk.
#[cfg(unix)]
#[test]
fn extract_marks_a_split_member_on_its_last_volume_line() {
    let dir = work("x-split");
    std::fs::write(dir.join("set.part1.rar"), unvouched(PART1, |_| true, None)).unwrap();
    std::fs::write(dir.join("set.part2.rar"), unvouched(PART2, |_| true, None)).unwrap();
    let ran = at_both_widths(&dir, "x", &[], "set.part1.rar");
    let expected = [
        "\nExtracting from set.part1.rar\n\n".to_owned(),
        format!("{:<73}{COUNTER}\n", "Extracting  o/s.bin"),
        "\nExtracting from set.part2.rar\n\n".to_owned(),
        file_line("...", "s.bin", true, UNVOUCHED),
        "All OK\n".to_owned(),
    ]
    .concat();
    assert_eq!(ran.stdout, expected);
    assert_eq!(ran.code, Some(0));
    assert_eq!(std::fs::read(dir.join("o/s.bin")).unwrap().len(), 1500);
}

/// The control: the genuine archive, every header as rar wrote it, is `OK`
/// on every line. The copy, the empty file and the link carry a CRC32
/// field of 0 there, and that is a checksum named.
#[test]
fn the_genuine_archive_is_ok_on_every_line() {
    let dir = work("control");
    std::fs::write(dir.join("genuine.rar"), GENUINE).unwrap();
    let ran = at_both_widths(&dir, "t", &[], "genuine.rar");
    let expected = [
        "\nTesting archive genuine.rar\n\n".to_owned(),
        file_line("Testing", "one.bin", true, PASSED),
        file_line("Testing", "two.bin", false, PASSED),
        file_line("Testing", "empty", true, PASSED),
        file_line("Testing", "link", false, PASSED),
        file_line("Testing", "z.txt", true, PASSED),
        dir_line("Testing", "d"),
        "All OK\n".to_owned(),
    ]
    .concat();
    assert_eq!(ran.stdout, expected);
    assert_eq!(ran.code, Some(0));
}

/// Both dialects: the binary named `rar` and the binary named `unrar`
/// print what the binary under its own name prints (rar 7.23 and unrar
/// 7.23 print the same lines here, measured).
#[test]
fn both_dialects_print_the_mark() {
    let dir = work("dialects");
    std::fs::write(dir.join("one.rar"), unvouched(GENUINE, |i| i == 4, None)).unwrap();
    let own = run_tool(&rarfast(), &dir, &["t", "-mt1", "one.rar"]);
    assert!(
        own.stdout
            .contains(&file_line("Testing", "z.txt", true, UNVOUCHED)),
        "{:?}",
        own.stdout
    );
    for tool in ["rar", "unrar"] {
        let named = tool_named(&dir, tool);
        copy_executable(&rarfast(), &named);
        let ran = run_tool(&named, &dir, &["t", "-mt1", "one.rar"]);
        assert_eq!(ran.stdout, own.stdout, "{tool}");
        assert_eq!(ran.stderr, own.stderr, "{tool}");
        assert_eq!(ran.code, Some(0), "{tool}");
    }
}
