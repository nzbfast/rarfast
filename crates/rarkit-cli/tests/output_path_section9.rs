//! What extraction does to a file it writes: SPEC-CLI section 9.4, the
//! rules W6 to W9 as rows, each naming its rule.
//!
//! The NEW behaviour here is W7: a member that replaces a file already at
//! its name is written BESIDE it and takes the name only when it is whole
//! and verified, so the old file survives any failure. A SMALL member (up
//! to 1 MiB) is instead held in memory and written IN PLACE once it is
//! whole and verified (the second form, 11 Oct 2026, for the wall of a
//! replace): a bad archive never costs the old file; a write the system
//! refuses part way can. Until 10 Oct 2026
//! the old file was opened and emptied in place, and a member that then
//! failed its checksum took the old bytes with it (as the reference does,
//! section 9.3 O14: a chosen difference).
//!
//! RED FIRST: `RARFAST_SECTION9_ARM` names another `rarfast` to run these
//! rows against. Set to a build of 47fd69e1f (the tree before this
//! change), the W7 and W8 rows fail.
//!
//! `-kb` over a failed replace keeps the broken NEW file under the
//! member's name, as the reference keeps it (O15), and the old file goes:
//! the one case where a failed replace does not leave the old file, asked
//! for by the switch (`kb_keeps_the_broken_new_file_under_the_name`).
//!
//! ONE CASE where the old file is NOT protected, settled on 10 Oct 2026
//! and not yet in section 9's text: a taken name in a directory that may
//! not be written to. No file can be made beside it, so the member is
//! written IN PLACE, as the reference writes it (O9,
//! `taken-in-no-write-directory`): an extraction that worked must not
//! start failing. The run says so once on standard error.
//!
//! A directory at the name (O12, W10 (d)) is refused before a byte is
//! written, and its bits are as they were.
//!
//! NOT PINNED here: W1's count of calls (a tracing tool's record, taken on
//! a Linux box), W4's bits while a member is being written (a race to
//! observe), an interrupt (the tool has no handler: owed).
//!
//! WIDTHS: every row runs at `-mt1` and at the default width (a hosted
//! runner is 2 to 4 threads wide). MEMORY: the largest member is 64 KiB,
//! stored.

// Unix only: the rows are about permission bits and symbolic links.
#![cfg(unix)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, SystemTime};

fn rarfast() -> PathBuf {
    std::env::var_os("RARFAST_SECTION9_ARM").map_or_else(
        || PathBuf::from(env!("CARGO_BIN_EXE_rarfast")),
        PathBuf::from,
    )
}

/// Stands watch over the directory one row of this file works in. The
/// row holds it beside the directory's path and never uses it; when it
/// is let go, at the row's end or because an assertion failed, the
/// directory is made writable again and deleted. A FAILED row matters
/// most here: what it leaves is directories with no write permission,
/// and those defeat a plain `rm -rf` of the build's temporary files.
struct DirWatch(PathBuf);

impl Drop for DirWatch {
    fn drop(&mut self) {
        clean(&self.0);
    }
}

fn work(tag: &str) -> (PathBuf, DirWatch) {
    let dir = std::env::temp_dir().join(format!("rarfast-s9-{}-{tag}", std::process::id()));
    clean(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    (dir.clone(), DirWatch(dir))
}

/// Removes a tree this test made, opening up what it closed first.
fn clean(dir: &Path) {
    if !dir.exists() {
        return;
    }
    let _ = Command::new("chmod")
        .arg("-R")
        .arg("u+rwx")
        .arg(dir)
        .status();
    let _ = std::fs::remove_dir_all(dir);
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

/// The members' modification time: 14 Mar 2021 09:26:53 UTC.
const STORED: u32 = 1_615_714_013;

/// The stored bits of every member.
const BITS: u32 = 0o640;

/// One stored file member; `sound` false gives it a checksum its bytes do
/// not have.
struct Entry<'a> {
    name: &'a str,
    data: &'a [u8],
    sound: bool,
    bits: u32,
    /// A directory member: no data area, the directory type in its word.
    dir: bool,
}

/// A stored RAR 5 archive of `entries`, written by a Unix host, each with
/// its own bits ([`BITS`] unless it says otherwise) and the time
/// [`STORED`].
fn rar5(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &[], &mut out);
    for entry in entries {
        let crc = crc32(entry.data) ^ u32::from(!entry.sound);
        let mut body = Vec::new();
        vint(2, &mut body); // a file header
        if entry.dir {
            vint(0, &mut body); // no data area
            vint(1 | 2, &mut body); // a directory, with a Unix time
            vint(0, &mut body);
            vint(u64::from(0o040_000 | entry.bits), &mut body);
            body.extend_from_slice(&STORED.to_le_bytes());
        } else {
            vint(2, &mut body); // with a data area
            vint(entry.data.len() as u64, &mut body);
            vint(2 | 4, &mut body); // a Unix time and a CRC32
            vint(entry.data.len() as u64, &mut body);
            vint(u64::from(0o100_000 | entry.bits), &mut body);
            body.extend_from_slice(&STORED.to_le_bytes());
            body.extend_from_slice(&crc.to_le_bytes());
        }
        vint(0, &mut body); // stored
        vint(1, &mut body); // Unix
        vint(entry.name.len() as u64, &mut body);
        body.extend_from_slice(entry.name.as_bytes());
        block(&body, if entry.dir { &[] } else { entry.data }, &mut out);
    }
    block(&[5, 0, 0], &[], &mut out);
    out
}

fn sound<'a>(name: &'a str, data: &'a [u8]) -> Entry<'a> {
    Entry {
        name,
        data,
        sound: true,
        bits: BITS,
        dir: false,
    }
}

fn unsound<'a>(name: &'a str, data: &'a [u8]) -> Entry<'a> {
    Entry {
        name,
        data,
        sound: false,
        bits: BITS,
        dir: false,
    }
}

/// `rarfast x` (or `e`) of `archive` into `out`, the answers on standard
/// input, under umask 022.
fn extract(dir: &Path, command: &str, switches: &[&str], answers: &str) -> Output {
    use std::io::Write;
    let line = format!(
        "umask 022; exec \"$0\" {command} {} a.rar out/",
        switches.join(" ")
    );
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(line)
        .arg(rarfast())
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(answers.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// Every name in `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut all: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    all.sort();
    all
}

/// An old file's time: 1 Jan 2010 00:00:00 UTC.
fn old_time() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_262_304_000)
}

/// Puts the old file at `path`: `bytes`, the bits `bits`, [`old_time`].
fn plant(path: &Path, bytes: &[u8], bits: u32) {
    std::fs::write(path, bytes).unwrap();
    let file = std::fs::File::options().write(true).open(path).unwrap();
    file.set_modified(old_time()).unwrap();
    drop(file);
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
}

/// The file at `path` is the old one, untouched: bytes, bits and time.
fn assert_old(path: &Path, bytes: &[u8], bits: u32, row: &str) {
    let meta = std::fs::symlink_metadata(path).unwrap_or_else(|e| panic!("{row}: {e}"));
    assert!(meta.is_file(), "{row}: not a regular file");
    assert_eq!(meta.mode() & 0o7777, bits, "{row}: the old file's bits");
    assert_eq!(meta.modified().unwrap(), old_time(), "{row}: its time");
    assert_eq!(std::fs::read(path).unwrap(), bytes, "{row}: its bytes");
}

/// The file at `path` is the member's: bytes, stored bits, stored time.
fn assert_member(path: &Path, bytes: &[u8], row: &str) {
    let meta = std::fs::symlink_metadata(path).unwrap_or_else(|e| panic!("{row}: {e}"));
    assert!(meta.is_file(), "{row}: not a regular file");
    assert_eq!(meta.mode() & 0o7777, BITS, "{row}: the member's bits");
    assert_eq!(
        meta.modified().unwrap(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(STORED)),
        "{row}: the member's time"
    );
    assert_eq!(
        std::fs::read(path).unwrap(),
        bytes,
        "{row}: the member's bytes"
    );
}

const WIDTHS: [&[&str]; 2] = [&["-mt1"], &[]];

/// A member small enough to be HELD IN MEMORY when it replaces a file
/// (the tool's bound is 1 MiB), and one too large for it, which is
/// written beside the file and renamed.
const SMALL: usize = 64 << 10;
const LARGE: usize = (1 << 20) + 4096;

/// A sound member stored with `bits`.
fn with_bits<'a>(name: &'a str, data: &'a [u8], bits: u32) -> Entry<'a> {
    Entry {
        bits,
        ..sound(name, data)
    }
}

/// A directory member stored with `bits`.
fn dir(name: &str, bits: u32) -> Entry<'_> {
    Entry {
        bits,
        dir: true,
        ..sound(name, &[])
    }
}

/// Whether these rows run as the superuser.
fn superuser() -> bool {
    let id = Command::new("id").arg("-u").output().unwrap();
    String::from_utf8_lossy(&id.stdout).trim() == "0"
}

/// W3: the three bits above the nine (set user, set group, sticky) are
/// restored only when the run is the superuser's. An ordinary user's run
/// leaves the nine bits, and says so ONCE on standard error however many
/// members it happened to; the superuser's leaves all twelve and says
/// nothing. A chosen difference from the reference (O2), which restores
/// them for anyone. At a free name and over a file that is replaced.
#[test]
fn the_three_high_bits_are_the_superusers_and_are_said_once() {
    const SAID: &str = "only for the superuser";
    let data = b"runs as its owner";
    let archive = rar5(&[
        with_bits("u.bin", data, 0o4755),
        with_bits("g.bin", data, 0o2755),
        with_bits("t.txt", data, 0o1644),
        with_bits("p.txt", data, 0o640),
    ]);
    let plain = rar5(&[with_bits("p.txt", data, 0o640)]);
    let root = superuser();
    for replace in [false, true] {
        for width in WIDTHS {
            let row = format!("replace {replace}, {width:?}, superuser {root}");
            let (dir, _watch) = work("high-bits");
            std::fs::write(dir.join("a.rar"), &archive).unwrap();
            let out = dir.join("out");
            std::fs::create_dir(&out).unwrap();
            if replace {
                for name in ["u.bin", "g.bin", "t.txt", "p.txt"] {
                    plant(&out.join(name), b"old bytes", 0o600);
                }
            }
            let switches: Vec<&str> = ["-o+"].iter().chain(width).copied().collect();
            let ran = extract(&dir, "x", &switches, "");
            assert_eq!(ran.status.code(), Some(0), "{row}: {ran:?}");
            let stderr = String::from_utf8_lossy(&ran.stderr);
            for (name, stored) in [
                ("u.bin", 0o4755),
                ("g.bin", 0o2755),
                ("t.txt", 0o1644),
                ("p.txt", 0o640),
            ] {
                let want = if root { stored } else { stored & 0o777 };
                let got = std::fs::symlink_metadata(out.join(name)).unwrap().mode() & 0o7777;
                assert_eq!(got, want, "{row}: {name} stored {stored:o}\n{stderr}");
            }
            let said = stderr.matches(SAID).count();
            assert_eq!(
                said,
                usize::from(!root),
                "{row}: said {said} times\n{stderr}"
            );
            assert!(
                String::from_utf8_lossy(&ran.stdout).contains("All OK"),
                "{row}: {ran:?}"
            );
        }
    }
    // A run that left no such bit off says nothing.
    let (dir, _watch) = work("high-bits-none");
    std::fs::write(dir.join("a.rar"), &plain).unwrap();
    let ran = extract(&dir, "x", &[], "");
    assert_eq!(ran.status.code(), Some(0), "{ran:?}");
    assert!(
        !String::from_utf8_lossy(&ran.stderr).contains(SAID),
        "{ran:?}"
    );
}

/// W7: a member that fails over a taken name leaves the old file as it
/// was, bytes, bits and time, and no other name in the destination. The
/// failures: a checksum that does not agree, and an archive that ends
/// early. The ways to say "replace": `-o+`, `-y`, and `y` at the question.
#[test]
fn a_failed_replace_leaves_the_old_file_as_it_was() {
    for size in [SMALL, LARGE] {
        a_failed_replace_of(size);
    }
}

fn a_failed_replace_of(size: usize) {
    let new = vec![b'N'; size];
    let other = b"another member";
    let bad = rar5(&[sound("b.txt", other), unsound("a.txt", &new)]);
    let whole = rar5(&[sound("b.txt", other), sound("a.txt", &new)]);
    // Cut inside the last member's data area.
    let cut = whole[..whole.len() - (32 << 10)].to_vec();
    for (failure, archive) in [("checksum", &bad), ("cut", &cut)] {
        for (how, switches, answers) in [
            ("-o+", &["-o+"][..], ""),
            ("-y", &["-y"][..], ""),
            ("answered y", &[][..], "y\ny\n"),
        ] {
            for command in ["x", "e"] {
                for width in WIDTHS {
                    let row = format!("{size} bytes, {failure}, {how}, {command}, {width:?}");
                    let (dir, _watch) = work("failed-replace");
                    std::fs::write(dir.join("a.rar"), archive).unwrap();
                    let out = dir.join("out");
                    std::fs::create_dir(&out).unwrap();
                    plant(&out.join("a.txt"), b"old bytes", 0o604);
                    plant(&out.join("b.txt"), b"old b", 0o600);
                    let switches: Vec<&str> = switches.iter().chain(width).copied().collect();
                    let ran = extract(&dir, command, &switches, answers);
                    assert_eq!(ran.status.code(), Some(3), "{row}: {ran:?}");
                    assert_old(&out.join("a.txt"), b"old bytes", 0o604, &row);
                    // The member before it was whole, and replaced its own.
                    assert_member(&out.join("b.txt"), other, &row);
                    assert_eq!(names(&out), ["a.txt", "b.txt"], "{row}: a name was left");
                }
            }
        }
    }
}

/// W7 with `-kb`: the broken new file is kept under the member's name
/// with the member's bits and time (O15), the old file goes, and no name
/// of the program's own is left.
#[test]
fn kb_keeps_the_broken_new_file_under_the_name() {
    let new = vec![b'N'; 64 << 10];
    let bad = rar5(&[unsound("a.txt", &new)]);
    for width in WIDTHS {
        let row = format!("{width:?}");
        let (dir, _watch) = work("kb");
        std::fs::write(dir.join("a.rar"), &bad).unwrap();
        let out = dir.join("out");
        std::fs::create_dir(&out).unwrap();
        plant(&out.join("a.txt"), b"old bytes", 0o604);
        let switches: Vec<&str> = ["-o+", "-kb"].iter().chain(width).copied().collect();
        let ran = extract(&dir, "x", &switches, "");
        assert_eq!(ran.status.code(), Some(3), "{row}: {ran:?}");
        assert_member(&out.join("a.txt"), &new, &row);
        assert_eq!(names(&out), ["a.txt"], "{row}");
    }
}

/// W9: at a FREE name a failed member leaves no file, and with `-kb` the
/// bytes written stay at the name with the member's bits and time (O15).
#[test]
fn a_failed_member_at_a_free_name() {
    let new = vec![b'N'; 64 << 10];
    let bad = rar5(&[unsound("a.txt", &new)]);
    for width in WIDTHS {
        let row = format!("{width:?}");
        let (dir, _watch) = work("free-fail");
        std::fs::write(dir.join("a.rar"), &bad).unwrap();
        let out = dir.join("out");
        let ran = extract(&dir, "x", width, "");
        assert_eq!(ran.status.code(), Some(3), "{row}: {ran:?}");
        assert!(names(&out).is_empty(), "{row}: {:?}", names(&out));
        let switches: Vec<&str> = ["-kb"].iter().chain(width).copied().collect();
        let ran = extract(&dir, "x", &switches, "");
        assert_eq!(ran.status.code(), Some(3), "{row}: {ran:?}");
        assert_member(&out.join("a.txt"), &new, &row);
        assert_eq!(names(&out), ["a.txt"], "{row}");
    }
}

/// W6: what "replaced" leaves is a regular file with the member's bytes,
/// bits and time, whatever the old file's bits were, 444 and 000 among
/// them (O9), and no other name.
#[test]
fn a_replace_that_succeeds_leaves_the_members_file_whatever_the_old_bits() {
    let new = vec![b'N'; 64 << 10];
    let archive = rar5(&[sound("a.txt", &new)]);
    for bits in [0o644, 0o444, 0o000, 0o755] {
        for width in WIDTHS {
            let row = format!("old bits {bits:o}, {width:?}");
            let (dir, _watch) = work("replace");
            std::fs::write(dir.join("a.rar"), &archive).unwrap();
            let out = dir.join("out");
            std::fs::create_dir(&out).unwrap();
            plant(&out.join("a.txt"), b"old bytes", bits);
            let switches: Vec<&str> = ["-o+"].iter().chain(width).copied().collect();
            let ran = extract(&dir, "x", &switches, "");
            assert_eq!(ran.status.code(), Some(0), "{row}: {ran:?}");
            assert_member(&out.join("a.txt"), &new, &row);
            assert_eq!(names(&out), ["a.txt"], "{row}");
        }
    }
}

/// W8: a link at the member's name is never written through. Replaced,
/// the link is gone and a regular file stands at the name; what the link
/// named is untouched, and a link to nothing made no file where it led.
/// A member that FAILS leaves the link as it was.
#[test]
fn a_link_at_the_name_is_replaced_and_never_written_through() {
    let new = vec![b'N'; 64 << 10];
    let whole = rar5(&[sound("a.txt", &new)]);
    let bad = rar5(&[unsound("a.txt", &new)]);
    for leads_to in ["a file", "nothing"] {
        for (fails, archive) in [(false, &whole), (true, &bad)] {
            for width in WIDTHS {
                let row = format!("a link to {leads_to}, fails {fails}, {width:?}");
                let (dir, _watch) = work("link");
                std::fs::write(dir.join("a.rar"), archive).unwrap();
                let out = dir.join("out");
                std::fs::create_dir(&out).unwrap();
                let outside = dir.join("outside.txt");
                if leads_to == "a file" {
                    plant(&outside, b"outside bytes", 0o600);
                }
                std::os::unix::fs::symlink(&outside, out.join("a.txt")).unwrap();
                let switches: Vec<&str> = ["-o+"].iter().chain(width).copied().collect();
                let ran = extract(&dir, "x", &switches, "");
                if leads_to == "a file" {
                    assert_old(&outside, b"outside bytes", 0o600, &row);
                } else {
                    assert!(
                        std::fs::symlink_metadata(&outside).is_err(),
                        "{row}: a file was made where the link led"
                    );
                }
                if fails {
                    assert_eq!(ran.status.code(), Some(3), "{row}: {ran:?}");
                    let meta = std::fs::symlink_metadata(out.join("a.txt")).unwrap();
                    assert!(meta.file_type().is_symlink(), "{row}: the link is gone");
                } else {
                    assert_eq!(ran.status.code(), Some(0), "{row}: {ran:?}");
                    assert_member(&out.join("a.txt"), &new, &row);
                }
                assert_eq!(names(&out), ["a.txt"], "{row}");
            }
        }
    }
}

/// O12 and W9: a directory at the name cannot be replaced. The member is
/// refused, the run goes on, exit 9; the directory stands with the bits
/// it had (W9 (a) is awaited: nothing changes them here).
#[test]
fn a_directory_at_the_name_is_refused_and_left_alone() {
    let new = vec![b'N'; 64 << 10];
    let other = b"another member";
    let archive = rar5(&[sound("a.txt", &new), sound("b.txt", other)]);
    for width in WIDTHS {
        let row = format!("{width:?}");
        let (dir, _watch) = work("directory");
        std::fs::write(dir.join("a.rar"), &archive).unwrap();
        let out = dir.join("out");
        std::fs::create_dir_all(out.join("a.txt")).unwrap();
        std::fs::set_permissions(out.join("a.txt"), std::fs::Permissions::from_mode(0o750))
            .unwrap();
        let switches: Vec<&str> = ["-o+"].iter().chain(width).copied().collect();
        let ran = extract(&dir, "x", &switches, "");
        assert_eq!(ran.status.code(), Some(9), "{row}: {ran:?}");
        let stderr = String::from_utf8_lossy(&ran.stderr);
        assert!(
            stderr.contains("Cannot create out/a.txt"),
            "{row}: {stderr}"
        );
        assert!(
            stderr.contains("Directory with such name already exists"),
            "{row}: {stderr}"
        );
        let meta = std::fs::symlink_metadata(out.join("a.txt")).unwrap();
        assert!(meta.is_dir(), "{row}");
        assert_eq!(meta.mode() & 0o7777, 0o750, "{row}: the directory's bits");
        assert_member(&out.join("b.txt"), other, &row);
        assert_eq!(names(&out), ["a.txt", "b.txt"], "{row}");
    }
}

/// A taken name in a directory that may not be written to: no file can
/// be made beside it, so the member is written in place, as the reference
/// writes it (O9), whatever the old file's bits. A LARGE member is
/// written there as its bytes come, so one that fails does not leave the
/// old file, and the run says once that it wrote in place. A SMALL one
/// is written only when whole and verified: nothing is said, and one
/// that fails leaves the old file as it was.
#[test]
fn a_taken_name_in_a_directory_closed_to_writing_is_written_in_place() {
    const SAID: &str = "written in place";
    for (size, held) in [(SMALL, true), (LARGE, false)] {
        let new = vec![b'N'; size];
        let whole = rar5(&[sound("d/a.txt", &new), sound("d/b.txt", &new)]);
        let bad = rar5(&[unsound("d/a.txt", &new)]);
        for bits in [0o644, 0o444] {
            for width in WIDTHS {
                let row = format!("{size} bytes, old bits {bits:o}, {width:?}");
                let (dir, _watch) = work("closed");
                std::fs::write(dir.join("a.rar"), &whole).unwrap();
                let closed = dir.join("out/d");
                std::fs::create_dir_all(&closed).unwrap();
                plant(&closed.join("a.txt"), b"old bytes", bits);
                plant(&closed.join("b.txt"), b"old bytes", bits);
                std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o555)).unwrap();
                if std::fs::write(closed.join("probe"), b"").is_ok() {
                    eprintln!("no mode refuses this user (root): skipped");
                    return;
                }
                let switches: Vec<&str> = ["-o+"].iter().chain(width).copied().collect();
                let ran = extract(&dir, "x", &switches, "");
                assert_eq!(ran.status.code(), Some(0), "{row}: {ran:?}");
                assert_member(&closed.join("a.txt"), &new, &row);
                assert_member(&closed.join("b.txt"), &new, &row);
                assert_eq!(names(&closed), ["a.txt", "b.txt"], "{row}");
                let stderr = String::from_utf8_lossy(&ran.stderr);
                assert_eq!(
                    stderr.matches(SAID).count(),
                    usize::from(!held),
                    "{row}: {stderr}"
                );
                // A member that fails there.
                plant_in(&closed, "a.txt", b"old bytes", bits);
                std::fs::write(dir.join("a.rar"), &bad).unwrap();
                let ran = extract(&dir, "x", &switches, "");
                assert_eq!(ran.status.code(), Some(3), "{row}: {ran:?}");
                let left = std::fs::read(closed.join("a.txt")).ok();
                if held {
                    assert_eq!(left.as_deref(), Some(&b"old bytes"[..]), "{row}");
                } else {
                    assert_ne!(left.as_deref(), Some(&b"old bytes"[..]), "{row}");
                }
            }
        }
    }
    // A run that wrote nothing in place says nothing of it.
    let new = vec![b'N'; LARGE];
    let whole = rar5(&[sound("d/a.txt", &new)]);
    let (dir, _watch) = work("closed-none");
    std::fs::write(dir.join("a.rar"), &whole).unwrap();
    let ran = extract(&dir, "x", &[], "");
    assert_eq!(ran.status.code(), Some(0), "{ran:?}");
    assert!(
        !String::from_utf8_lossy(&ran.stderr).contains(SAID),
        "{ran:?}"
    );
}

/// [`plant`] for a file in a directory closed to writing: the directory
/// is opened for it and put back.
fn plant_in(dir: &Path, name: &str, bytes: &[u8], bits: u32) {
    let had = std::fs::metadata(dir).unwrap().mode() & 0o7777;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = dir.join(name);
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
    let _ = std::fs::remove_file(&path);
    plant(&path, bytes, bits);
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(had)).unwrap();
}

/// The second form of W7 (11 Oct 2026). A SMALL member that replaces a
/// file is held in memory and written IN PLACE once it is whole and
/// verified; a LARGE one is written beside and renamed. Either way the
/// name holds the member, and a member that fails leaves the old file
/// under both names.
///
/// The owner's rule of 27 Oct 2026, "Break the link always": a file with
/// another name (a hard link, here `other-name`, outside the destination)
/// is never written in place, since its bytes would change under that
/// name too. The small member is then written beside and renamed as a
/// large one is, and the other name keeps the old bytes at both sizes.
#[test]
fn a_small_member_is_written_in_place_once_verified_and_a_large_one_beside() {
    for (size, in_place) in [(SMALL, false), (LARGE, false)] {
        let new = vec![b'N'; size];
        let whole = rar5(&[sound("a.txt", &new)]);
        let bad = rar5(&[unsound("a.txt", &new)]);
        for width in WIDTHS {
            let row = format!("{size} bytes, {width:?}");
            let (dir, _watch) = work("in-place");
            let out = dir.join("out");
            std::fs::create_dir(&out).unwrap();
            plant(&out.join("a.txt"), b"old bytes", 0o644);
            let other = dir.join("other-name");
            std::fs::hard_link(out.join("a.txt"), &other).unwrap();
            let switches: Vec<&str> = ["-o+"].iter().chain(width).copied().collect();
            std::fs::write(dir.join("a.rar"), &bad).unwrap();
            let ran = extract(&dir, "x", &switches, "");
            assert_eq!(ran.status.code(), Some(3), "{row}: {ran:?}");
            assert_eq!(
                std::fs::read(out.join("a.txt")).unwrap(),
                b"old bytes",
                "{row}"
            );
            assert_eq!(std::fs::read(&other).unwrap(), b"old bytes", "{row}");
            std::fs::write(dir.join("a.rar"), &whole).unwrap();
            let ran = extract(&dir, "x", &switches, "");
            assert_eq!(ran.status.code(), Some(0), "{row}: {ran:?}");
            assert_member(&out.join("a.txt"), &new, &row);
            let through_other = std::fs::read(&other).unwrap();
            if in_place {
                assert_eq!(through_other, new, "{row}: not written in place");
            } else {
                assert_eq!(through_other, b"old bytes", "{row}: not written beside");
            }
            assert_eq!(names(&out), ["a.txt"], "{row}");
        }
    }
}

/// W10 (c): W3 holds for a DIRECTORY member as for a file. Its stored
/// nine bits are set at the end; the three above them only for the
/// superuser, and an ordinary user's run says so once. A directory that
/// was made by the run and one that was already there alike.
#[test]
fn a_directory_members_high_bits_are_the_superusers_too() {
    const SAID: &str = "only for the superuser";
    let archive = rar5(&[
        dir("sticky", 0o1777),
        dir("setgid", 0o2750),
        dir("there", 0o1755),
        dir("plain", 0o750),
    ]);
    let root = superuser();
    for width in WIDTHS {
        let row = format!("{width:?}, superuser {root}");
        let (work, _watch) = work("dir-high-bits");
        std::fs::write(work.join("a.rar"), &archive).unwrap();
        let out = work.join("out");
        std::fs::create_dir_all(out.join("there")).unwrap();
        let ran = extract(&work, "x", width, "");
        assert_eq!(ran.status.code(), Some(0), "{row}: {ran:?}");
        let stderr = String::from_utf8_lossy(&ran.stderr);
        // A directory that was THERE takes its stored bits exactly; one
        // the run MADE takes what the system's own create gives them
        // under the umask (022 here), as the reference leaves it. Only
        // the nine are pinned for a made one: the system may hand a new
        // directory a set group bit from its parent.
        let there = std::fs::symlink_metadata(out.join("there")).unwrap().mode() & 0o7777;
        let want = if root { 0o1755 } else { 0o755 };
        assert_eq!(there, want, "{row}: there, stored 1755\n{stderr}");
        for (name, nine) in [("sticky", 0o755), ("setgid", 0o750), ("plain", 0o750)] {
            let got = std::fs::symlink_metadata(out.join(name)).unwrap().mode();
            assert_eq!(got & 0o777, nine, "{row}: {name}\n{stderr}");
            if !root {
                assert_eq!(got & 0o5000, 0, "{row}: {name} kept a high bit\n{stderr}");
            }
        }
        let said = stderr.matches(SAID).count();
        assert_eq!(
            said,
            usize::from(!root),
            "{row}: said {said} times\n{stderr}"
        );
    }
}

/// The one narrowing of form two, pinned: a write the system REFUSES
/// while a held member is written in place (here a file size limit of
/// 16 of the shell's blocks, 8 or 16 KiB, under a 64 KiB member) is a
/// write error like any other: the
/// reference's `Write error in the file`, the run ends, exit 5 (W9,
/// O17), and no part is left at the name. The old file is lost: it was
/// emptied first. A member that is bad never gets this far.
#[test]
fn a_refused_write_of_a_held_member_is_a_write_error_and_costs_the_old_file() {
    let new = vec![b'N'; SMALL];
    let archive = rar5(&[sound("a.txt", &new)]);
    for width in WIDTHS {
        let row = format!("{width:?}");
        let (dir, _watch) = work("held-write-error");
        std::fs::write(dir.join("a.rar"), &archive).unwrap();
        let out = dir.join("out");
        std::fs::create_dir(&out).unwrap();
        plant(&out.join("a.txt"), b"old bytes", 0o644);
        let line = format!(
            "umask 022; ulimit -f 16; exec \"$0\" x -o+ {} a.rar out/",
            width.join(" ")
        );
        let ran = Command::new("sh")
            .arg("-c")
            .arg(line)
            .arg(rarfast())
            .current_dir(&dir)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(ran.status.code(), Some(5), "{row}: {ran:?}");
        let stderr = String::from_utf8_lossy(&ran.stderr);
        assert!(
            stderr.contains("Write error in the file"),
            "{row}: {stderr}"
        );
        assert!(names(&out).is_empty(), "{row}: {:?}", names(&out));
        // With -kb the part that was written stays at the name.
        plant(&out.join("a.txt"), b"old bytes", 0o644);
        let ran = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "umask 022; ulimit -f 16; exec \"$0\" x -o+ -kb {} a.rar out/",
                width.join(" ")
            ))
            .arg(rarfast())
            .current_dir(&dir)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(ran.status.code(), Some(5), "{row}, -kb: {ran:?}");
        assert_eq!(names(&out), ["a.txt"], "{row}, -kb");
        let kept = std::fs::read(out.join("a.txt")).unwrap();
        assert!(
            !kept.is_empty() && kept.len() < SMALL && kept.iter().all(|b| *b == b'N'),
            "{row}, -kb: {} bytes kept",
            kept.len()
        );
    }
}
