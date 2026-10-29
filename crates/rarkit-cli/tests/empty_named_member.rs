//! A member whose name is EMPTY as the command will use it is passed over
//! whole by `t`, `x`, `e` and `p`: no progress line, no error, no count,
//! none of its bytes printed, nothing created. When that leaves nothing
//! processed the run says `No files to extract` and exits 10.
//!
//! Measured on 10 Oct 2026 against rar 7.23 and unrar 7.23 (homebrew's,
//! aarch64 macOS), which agree byte for byte and by exit code on every
//! row here:
//!
//! | archive | `t`, `x`, `e` | `p` |
//! |---|---|---|
//! | one file, name of zero bytes | banner, blank, `No files to extract`, exit 10, nothing created | nothing on either stream, exit 10 |
//! | one directory, name of zero bytes | the same | the same |
//! | two files, both names of zero bytes | the same | the same |
//! | an empty-named file, then `good.txt` (and the other order) | one line, `good.txt`'s, `All OK`, exit 0; `good.txt` alone created | `good.txt`'s bytes alone |
//! | one file `d/` (a name that ends in its separator) | `e` with no destination: `No files to extract`, exit 10, since the name without its path is empty. `e` with a destination `dst/`: stderr `Cannot create dst/`, `Is a directory`, `Directory with such name already exists`, exit 9 | (printed, as any file) |
//! | `listing-names/r4-two.rar` on macOS, where the two bytes of its name read as no name | as the first row | as the first row |
//!
//! Before this, rarfast tested such a member under a line with no name,
//! printed its bytes under `p`, and closed a run that processed nothing
//! with `All OK`, exit 0. Under `x` and `e` it created nothing for one,
//! which is kept. The rule is SPEC-CLI 2.1 M18.
//!
//! The archives are built here, by hand, in the oldest container: a name
//! of zero bytes is one no writer of ours or the reference's makes. Each
//! is under 200 bytes. Every run is one child process at the width its
//! switch names (`-mt1`, `-mt4`) holding a few MiB.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// A scratch directory of this test's own, emptied first.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-noname-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The CRC-32 of the member checksums and, by its low half, of the
/// headers.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

/// A block with its size and its checksum filled in.
fn block(mut header: Vec<u8>) -> Vec<u8> {
    let size = header.len() as u16;
    header[5..7].copy_from_slice(&size.to_le_bytes());
    let sum = crc32(&header[2..]) as u16;
    header[..2].copy_from_slice(&sum.to_le_bytes());
    header
}

/// One entry: a stored file of `data`, or a directory when `data` is
/// `None`. The fields are the ones genuine rar 4.2.0 wrote on Linux for
/// `listing-names/r4-two.rar` (a file) and rar 3.93 for a directory.
fn entry(name: &[u8], data: Option<&[u8]>) -> Vec<u8> {
    let body = data.unwrap_or(&[]);
    let (flags, mode): (u16, u32) = match data {
        Some(_) => (0x8020, 0o100_644),
        None => (0x80E0, 0o040_755),
    };
    let mut header = vec![0, 0, 0x74];
    header.extend_from_slice(&flags.to_le_bytes());
    header.extend_from_slice(&[0; 2]);
    header.extend_from_slice(&(body.len() as u32).to_le_bytes());
    header.extend_from_slice(&(body.len() as u32).to_le_bytes());
    header.push(3); // host: Unix
    header.extend_from_slice(&data.map_or(0, crc32).to_le_bytes());
    header.extend_from_slice(&[0x82, 0x18, 0x22, 0x50]); // 2020-01-02 03:04
    header.extend_from_slice(&[0x14, 0x30]); // version 2.0, stored
    header.extend_from_slice(&(name.len() as u16).to_le_bytes());
    header.extend_from_slice(&mode.to_le_bytes());
    header.extend_from_slice(name);
    let mut out = block(header);
    out.extend_from_slice(body);
    out
}

/// `entries` as one archive at `dir/name`.
fn archive(dir: &Path, name: &str, entries: &[Vec<u8>]) -> PathBuf {
    let mut bytes = b"Rar!\x1a\x07\x00".to_vec();
    bytes.extend_from_slice(&block(vec![0, 0, 0x73, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    for entry in entries {
        bytes.extend_from_slice(entry);
    }
    bytes.extend_from_slice(&block(vec![0, 0, 0x7B, 0x00, 0x40, 0, 0]));
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

/// Both read paths: the sequential one and the concurrent one.
const WIDTHS: [&str; 2] = ["-mt1", "-mt4"];

/// `rarfast <command> -y <width> <archive>`, run in a new empty directory
/// `dir/out-<tag>`, which is returned with what the run gave.
fn run(dir: &Path, tag: &str, command: &str, width: &str, archive: &Path) -> (Output, PathBuf) {
    let out = dir.join(format!("out-{tag}-{command}{width}"));
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    let ran = Command::new(rarfast())
        .current_dir(&out)
        .args([command, "-y", width])
        .arg(archive)
        .output()
        .unwrap();
    (ran, out)
}

/// The names in a directory, sorted.
fn left_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The banner's word for each command.
fn banner(command: &str) -> &'static str {
    match command {
        "t" => "Testing archive",
        _ => "Extracting from",
    }
}

/// The run processed nothing, said so as the reference does, and left
/// nothing behind.
fn nothing_to_extract(dir: &Path, tag: &str, archive: &Path, commands: &[&str]) {
    for &command in commands {
        for width in WIDTHS {
            let (ran, out) = run(dir, tag, command, width, archive);
            let all = format!("{tag} {command} {width}: {ran:?}");
            assert_eq!(ran.status.code(), Some(10), "{all}");
            assert!(ran.stderr.is_empty(), "{all}");
            let want = match command {
                "p" => String::new(),
                _ => format!(
                    "\n{} {}\n\nNo files to extract\n",
                    banner(command),
                    archive.display()
                ),
            };
            assert_eq!(String::from_utf8_lossy(&ran.stdout), want, "{all}");
            assert_eq!(left_in(&out), Vec::<String>::new(), "{all}");
        }
    }
}

const EVERY: [&str; 4] = ["t", "x", "e", "p"];

#[test]
fn a_file_with_no_name_alone_is_no_files_to_extract() {
    let dir = work("file");
    let arc = archive(&dir, "one.rar", &[entry(b"", Some(b"x"))]);
    nothing_to_extract(&dir, "file", &arc, &EVERY);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_directory_with_no_name_alone_is_no_files_to_extract() {
    let dir = work("dir");
    let arc = archive(&dir, "dir.rar", &[entry(b"", None)]);
    nothing_to_extract(&dir, "dir", &arc, &EVERY);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn two_files_with_no_name_are_no_files_to_extract() {
    let dir = work("two");
    let arc = archive(
        &dir,
        "two.rar",
        &[entry(b"", Some(b"x")), entry(b"", Some(b"w"))],
    );
    nothing_to_extract(&dir, "two", &arc, &EVERY);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Beside a named file the nameless one is not tested under a line of
/// its own, not printed and not counted: the run is the named file's.
#[test]
fn a_file_with_no_name_beside_a_named_one_is_passed_over() {
    let dir = work("beside");
    let nameless = || entry(b"", Some(b"x"));
    let named = || entry(b"good.txt", Some(b"y"));
    for (tag, entries) in [
        ("first", vec![nameless(), named()]),
        ("last", vec![named(), nameless()]),
    ] {
        let arc = archive(&dir, &format!("{tag}.rar"), &entries);
        for width in WIDTHS {
            for command in ["t", "x", "e"] {
                let (ran, out) = run(&dir, tag, command, width, &arc);
                let all = format!("{tag} {command} {width}: {ran:?}");
                assert_eq!(ran.status.code(), Some(0), "{all}");
                assert!(ran.stderr.is_empty(), "{all}");
                let stdout = String::from_utf8_lossy(&ran.stdout);
                let verb = if command == "t" {
                    "Testing     "
                } else {
                    "Extracting  "
                };
                let lines: Vec<&str> = stdout
                    .lines()
                    .filter(|line| line.starts_with(verb))
                    .collect();
                assert_eq!(lines.len(), 1, "{all}");
                assert!(lines[0].starts_with(&format!("{verb}good.txt ")), "{all}");
                assert!(lines[0].ends_with("OK "), "{all}");
                assert!(stdout.ends_with("\nAll OK\n"), "{all}");
                let want: &[&str] = if command == "t" { &[] } else { &["good.txt"] };
                assert_eq!(left_in(&out), want, "{all}");
            }
            let (ran, _) = run(&dir, tag, "p", width, &arc);
            let all = format!("{tag} p {width}: {ran:?}");
            assert_eq!(ran.status.code(), Some(0), "{all}");
            assert_eq!(ran.stdout, b"y", "{all}");
            assert!(ran.stderr.is_empty(), "{all}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `e` drops a member's path, and what is left of a file named `d/` is no
/// name: the reference's `e` says `No files to extract`, exit 10. (Its
/// `t` and `p` process the member, as ours do; `x` is another matter,
/// held by the tests of a name that ends in a separator.)
#[test]
fn a_file_whose_name_is_all_path_is_no_files_to_extract_under_e() {
    let dir = work("allpath");
    let arc = archive(&dir, "allpath.rar", &[entry(b"d\\", Some(b"x"))]);
    nothing_to_extract(&dir, "allpath", &arc, &["e"]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `e` into a named destination: what is left of a file named `d/` names
/// the destination itself, and the reference says it cannot create that,
/// counts it and exits 9; alone it closes with `No files to extract`.
/// rarfast says the same and touches NOTHING on disk for the member: an
/// existing destination stays empty, and one that is not there is not
/// made for its sake: M18's CHOSEN DIFFERENCE on the safe side (for this
/// shape alone, `e -y alone.rar new/sub/`, the reference makes `new/sub`,
/// prints its two `Creating` lines and then exits 9; rarfast makes no
/// destination and prints no `Creating` line). Unix only: the second
/// line is the system's own words.
#[cfg(unix)]
#[test]
fn a_file_whose_name_is_all_path_cannot_be_created_under_e_into_a_destination() {
    let dir = work("intodest");
    let alone = archive(&dir, "alone.rar", &[entry(b"d\\", Some(b"x"))]);
    let beside = archive(
        &dir,
        "beside.rar",
        &[entry(b"good.txt", Some(b"y")), entry(b"d\\", Some(b"x"))],
    );
    let complaint = |dest: &str| {
        format!("\nCannot create {dest}\nIs a directory\nDirectory with such name already exists")
    };
    for width in WIDTHS {
        for (dest, there) in [("dst/", true), ("new/sub/", false)] {
            let tag = format!("{}{width}", if there { "there" } else { "new" });
            let run_in = |arc: &Path, name: &str| {
                let cwd = dir.join(format!("cwd-{name}-{tag}"));
                let _ = std::fs::remove_dir_all(&cwd);
                std::fs::create_dir_all(&cwd).unwrap();
                if there {
                    std::fs::create_dir(cwd.join("dst")).unwrap();
                }
                let ran = Command::new(rarfast())
                    .current_dir(&cwd)
                    .args(["e", "-y", width])
                    .arg(arc)
                    .arg(dest)
                    .output()
                    .unwrap();
                (ran, cwd)
            };

            let (ran, cwd) = run_in(&alone, "alone");
            let all = format!("alone {tag}: {ran:?}");
            assert_eq!(ran.status.code(), Some(9), "{all}");
            assert_eq!(
                String::from_utf8_lossy(&ran.stderr),
                complaint(dest),
                "{all}"
            );
            assert_eq!(
                String::from_utf8_lossy(&ran.stdout),
                format!(
                    "\nExtracting from {}\n\nNo files to extract\n",
                    alone.display()
                ),
                "{all}"
            );
            if there {
                assert_eq!(left_in(&cwd), ["dst"], "{all}");
                assert_eq!(left_in(&cwd.join("dst")), Vec::<String>::new(), "{all}");
            } else {
                assert_eq!(left_in(&cwd), Vec::<String>::new(), "{all}");
            }

            let (ran, cwd) = run_in(&beside, "beside");
            let all = format!("beside {tag}: {ran:?}");
            assert_eq!(ran.status.code(), Some(9), "{all}");
            assert_eq!(
                String::from_utf8_lossy(&ran.stderr),
                complaint(dest),
                "{all}"
            );
            let stdout = String::from_utf8_lossy(&ran.stdout);
            assert!(stdout.ends_with("OK \nTotal errors: 1\n"), "{all}");
            let into = cwd.join(dest);
            assert_eq!(left_in(&into), ["good.txt"], "{all}");
            assert_eq!(std::fs::read(into.join("good.txt")).unwrap(), b"y", "{all}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A variable length integer of the newer container at `at`, and where
/// the next field starts.
fn vint(bytes: &[u8], mut at: usize) -> (u64, usize) {
    let (mut value, mut shift) = (0u64, 0);
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

/// A stored archive of the NEWER container made by rarfast from the files
/// `ab` (`x`) and, when `beside`, `good.txt` (`y`), with the first byte
/// of the name `ab` then set to zero in its file header and that header's
/// checksum set again: a name that begins with a zero byte reads empty.
fn newer_with_a_zero_first(dir: &Path, name: &str, beside: bool) -> PathBuf {
    std::fs::write(dir.join("ab"), b"x").unwrap();
    std::fs::write(dir.join("good.txt"), b"y").unwrap();
    let mut args = vec!["a", "-idq", "-m0", "-ep", name, "ab"];
    if beside {
        args.push("good.txt");
    }
    let made = Command::new(rarfast())
        .current_dir(dir)
        .args(&args)
        .output()
        .unwrap();
    assert_eq!(made.status.code(), Some(0), "{made:?}");
    let path = dir.join(name);
    let mut bytes = std::fs::read(&path).unwrap();
    let (mut at, mut changed) = (8, 0);
    while at < bytes.len() {
        let (size, fields) = vint(&bytes, at + 4);
        let end = fields + size as usize;
        let (kind, next) = vint(&bytes, fields);
        let (flags, mut next) = vint(&bytes, next);
        if flags & 1 != 0 {
            next = vint(&bytes, next).1;
        }
        let data = if flags & 2 != 0 {
            vint(&bytes, next).0
        } else {
            0
        };
        // The name's length, then the name: the one place in a header
        // of this size where those three bytes stand.
        let found = bytes[fields..end]
            .windows(3)
            .position(|three| three == [2, b'a', b'b']);
        if let (2, Some(found)) = (kind, found) {
            bytes[fields + found + 1] = 0;
            let sum = crc32(&bytes[at + 4..end]);
            bytes[at..at + 4].copy_from_slice(&sum.to_le_bytes());
            changed += 1;
        }
        if kind == 5 {
            break;
        }
        at = end + data as usize;
    }
    assert_eq!(changed, 1, "the header of `ab` was not found");
    std::fs::write(&path, bytes).unwrap();
    path
}

/// The newer container answers the same (M18: the shapes built in both
/// containers answer alike): a name that begins with a zero byte, alone
/// and beside a named file.
#[test]
fn a_name_that_begins_with_a_zero_byte_in_the_newer_container_is_the_same() {
    let dir = work("newer");
    let alone = newer_with_a_zero_first(&dir, "alone.rar", false);
    nothing_to_extract(&dir, "newer", &alone, &EVERY);
    let beside = newer_with_a_zero_first(&dir, "beside.rar", true);
    for width in WIDTHS {
        let (ran, _) = run(&dir, "newer-beside", "t", width, &beside);
        let all = format!("t {width}: {ran:?}");
        assert_eq!(ran.status.code(), Some(0), "{all}");
        let stdout = String::from_utf8_lossy(&ran.stdout);
        let lines: Vec<&str> = stdout
            .lines()
            .filter(|line| line.starts_with("Testing     "))
            .collect();
        assert_eq!(lines.len(), 1, "{all}");
        assert!(lines[0].starts_with("Testing     good.txt "), "{all}");
        let (ran, out) = run(&dir, "newer-beside", "x", width, &beside);
        assert_eq!(ran.status.code(), Some(0), "x {width}: {ran:?}");
        assert_eq!(left_in(&out), ["good.txt"], "x {width}");
        let (ran, _) = run(&dir, "newer-beside", "p", width, &beside);
        assert_eq!(ran.status.code(), Some(0), "p {width}: {ran:?}");
        assert_eq!(ran.stdout, b"y", "p {width}: {ran:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// M18's last part: to `e` and `p` a DIRECTORY entry is no member either,
/// whatever the mask, so an archive of directories alone (or a mask that
/// takes only a directory) leaves them nothing: `e` says `No files to
/// extract`, exit 10, and makes no destination that is not there; `p`
/// prints nothing and exits 10. `t` and `x` keep their lines, `All OK`,
/// exit 0, and `x` makes the directories. rar and unrar 7.23 (aarch64
/// macOS, 11 Oct 2026), both containers; before this rarfast closed `e`
/// with `All OK`, exit 0, and `p` with exit 0.
#[test]
fn directories_alone_are_no_files_to_extract_under_e_and_p() {
    let dir = work("dirs");
    let one = archive(&dir, "one.rar", &[entry(b"d", None)]);
    let nested = archive(
        &dir,
        "nested.rar",
        &[entry(b"d", None), entry(b"e2", None), entry(b"d\\s", None)],
    );
    // The newer container, written by rarfast from two empty directories.
    std::fs::create_dir_all(dir.join("src/d")).unwrap();
    std::fs::create_dir_all(dir.join("src/e2")).unwrap();
    let made = Command::new(rarfast())
        .current_dir(dir.join("src"))
        .args(["a", "-idq", "-r", "../newer.rar", "d", "e2"])
        .output()
        .unwrap();
    assert_eq!(made.status.code(), Some(0), "{made:?}");
    let newer = dir.join("newer.rar");
    for (tag, arc) in [("one", &one), ("nested", &nested), ("newer", &newer)] {
        nothing_to_extract(&dir, tag, arc, &["e", "p"]);
        for width in WIDTHS {
            // A destination that is not there is not made.
            let cwd = dir.join(format!("cwd-{tag}{width}"));
            std::fs::create_dir_all(&cwd).unwrap();
            let ran = Command::new(rarfast())
                .current_dir(&cwd)
                .args(["e", "-y", width])
                .arg(arc)
                .arg("new/sub/")
                .output()
                .unwrap();
            let all = format!("{tag} e new/sub/ {width}: {ran:?}");
            assert_eq!(ran.status.code(), Some(10), "{all}");
            assert!(ran.stdout.ends_with(b"\n\nNo files to extract\n"), "{all}");
            assert_eq!(left_in(&cwd), Vec::<String>::new(), "{all}");
            // `t` and `x` are as they were.
            let (ran, _) = run(&dir, tag, "t", width, arc);
            let all = format!("{tag} t {width}: {ran:?}");
            assert_eq!(ran.status.code(), Some(0), "{all}");
            assert!(ran.stdout.ends_with(b"OK\nAll OK\n"), "{all}");
            let (ran, out) = run(&dir, tag, "x", width, arc);
            let all = format!("{tag} x {width}: {ran:?}");
            assert_eq!(ran.status.code(), Some(0), "{all}");
            assert!(out.join("d").is_dir(), "{all}");
        }
    }
    // A mask that takes the directory alone, with a file beside it in the
    // archive: nothing for `e` and `p` to do; and with no mask, the file.
    let beside = archive(
        &dir,
        "beside.rar",
        &[entry(b"d", None), entry(b"good.txt", Some(b"y"))],
    );
    for width in WIDTHS {
        for command in ["e", "p"] {
            let cwd = dir.join(format!("mask-{command}{width}"));
            std::fs::create_dir_all(&cwd).unwrap();
            let ran = Command::new(rarfast())
                .current_dir(&cwd)
                .args([command, "-y", width])
                .arg(&beside)
                .arg("d")
                .output()
                .unwrap();
            let all = format!("{command} beside.rar d {width}: {ran:?}");
            assert_eq!(ran.status.code(), Some(10), "{all}");
            assert!(ran.stderr.is_empty(), "{all}");
            if command == "p" {
                assert!(ran.stdout.is_empty(), "{all}");
            } else {
                assert!(ran.stdout.ends_with(b"\n\nNo files to extract\n"), "{all}");
            }
            assert_eq!(left_in(&cwd), Vec::<String>::new(), "{all}");
        }
        let (ran, out) = run(&dir, "beside", "e", width, &beside);
        assert_eq!(ran.status.code(), Some(0), "e {width}: {ran:?}");
        assert_eq!(left_in(&out), ["good.txt"], "e {width}");
        let (ran, _) = run(&dir, "beside", "p", width, &beside);
        assert_eq!(ran.status.code(), Some(0), "p {width}: {ran:?}");
        assert_eq!(ran.stdout, b"y", "p {width}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The genuine archive (rar 4.2.0 on Linux) whose one name is the bytes
/// E9 E8, which macOS reads as no name at all. On Linux the reference
/// reads three characters there, so the row is this system's only.
#[cfg(target_os = "macos")]
#[test]
fn the_genuine_name_macos_cannot_read_is_no_files_to_extract() {
    let dir = work("genuine");
    let arc = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/listing-names/r4-two.rar");
    nothing_to_extract(&dir, "genuine", &arc, &EVERY);
    let _ = std::fs::remove_dir_all(&dir);
}
