//! Item 3 of the 28 Sep 2026 CLI parity leftovers: `l`/`v` of a RAR 5
//! member whose compression version is unknown must show its stored
//! attributes and ratio like any other member.
//!
//! `crates/rarkit-cli/src/engine.rs`'s `host_of` used
//! `info.algorithm_version == 2` alone to detect the RAR 1.3 container
//! (which stores no host byte at all and declares that constant in every
//! archive), but 2 is ALSO an ordinary RAR 5 compression version the
//! engine and the reference do not know - the same value
//! `tests/every_refused_member.rs` rewrites a member to for its own
//! refusal rows. A RAR 5 member refused for THAT version fell into the
//! RAR 1.3 case too and listed `HostOs::Unrecorded`'s DOS-shaped
//! attributes (`..A.S..`) where the header's Unix mode was sitting right
//! there, unaffected by the unknown codec.
//!
//! Measured against unrar 7.23 (homebrew's, aarch64 macOS, 28 Sep 2026)
//! over five RAR 5 members (`rarfast a -m3 -ep`, the same build
//! `every_refused_member.rs` uses) with `b.txt` and `d.txt` rewritten to
//! compression version 2 - `rar5_with_version`, copied from that file
//! rather than exported, so a change to its shape cannot silently drift
//! both suites apart:
//!
//! ```text
//! $ unrar l a.rar
//!  Attributes       Size     Date    Time   Name
//! ----------- ----------  ---------- -----  ----
//!  -rw-r--r--      24576  <mtime>  a.txt
//!  -rw-r--r--      24576  <mtime>  b.txt      <- was `..A.S..`
//!  ...
//! $ unrar v a.rar
//!  Attributes       Size     Packed Ratio    Date    Time   Checksum  Name
//! ----------- ---------- ---------- ----- ---------- -----  --------  ----
//!  -rw-r--r--      24576      <n>   <r>%  <mtime>  <crc>  a.txt
//!  -rw-r--r--      24576      <n>   <r>%  <mtime>  <crc>  b.txt   <- attributes were `..A.S..`, ratio already matched
//! ```
//!
//! Every member's attributes and ratio are Unix-shaped and equal to a
//! same-sized member of a known version; only `l`'s omission of the
//! `Packed`/`Ratio` columns (which this row does not touch) tells `l`
//! and `v` apart.
//!
//! The members are archived by the system the test runs on, so the column
//! takes that system's form: a Unix mode above, and on Windows the
//! seven-position word, `..A....` for these files (host byte 0 and
//! attribute 0x20 in the header). The subject is the same either way: a
//! member rewritten to version 2 lists exactly as its unrewritten
//! neighbour does, and never as the RAR 1.3 case's `..A.S..`, which no
//! member here prints on either system. `STATED` and `state_attributes`
//! below say which attributes the source files carry, so the sanity line
//! does not lean on the process's umask.

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("rarfast-unkver-cols-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const NAMES: [&str; 5] = ["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"];

/// The attribute column every member [`rar5`] archives must list with:
/// what [`state_attributes`] gave its source file, in the form the listing
/// prints for the system that archived it (a Unix mode, or on Windows the
/// seven-position word with `A` for the archive bit and nothing else).
#[cfg(unix)]
const STATED: &str = "-rw-r--r--";
#[cfg(windows)]
const STATED: &str = "..A....";

/// Makes `path`'s attributes the ones [`STATED`] names, so the listing's
/// column is this test's own statement and not the environment's.
///
/// On Unix that is mode 0644, set outright. Until 1 Oct 2026 the file kept
/// whatever `std::fs::write` and the process's umask left it, and the
/// sanity lines below read `-rw-r--r--` only under umask 022: under an
/// Ubuntu default of 0002 a new file is 0664, the listing says
/// `-rw-rw-r--`, and both tests failed on any tree (seen 1 Oct 2026).
#[cfg(unix)]
fn state_attributes(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

/// On Windows a file just written carries the archive bit, and the bits
/// the listing has a letter for besides it (read-only, hidden, system,
/// directory, reparse point, compressed) only where its directory hands
/// them down. The standard library sets none of them, so this checks what
/// the file HAS and says so where a scratch directory (a compressed
/// `%TEMP%`, say) gives it more, which would otherwise show up as a
/// listing that reads wrong.
#[cfg(windows)]
fn state_attributes(path: &Path) {
    use std::os::windows::fs::MetadataExt;
    let attributes = std::fs::metadata(path).unwrap().file_attributes();
    assert_eq!(
        attributes & 0x0c37,
        0x0020,
        "{}: a new file here has attributes {attributes:#x}, not the archive \
         bit alone, so its listing cannot be {STATED}",
        path.display()
    );
}

/// Five members of 24 KiB, archived by rarfast in RAR 5, `-m3`, each from
/// a file whose attributes are [`STATED`].
fn rar5(dir: &Path) -> Vec<u8> {
    for (index, name) in NAMES.iter().enumerate() {
        std::fs::write(
            dir.join(name),
            rarkit_testdata::chatter(index as u64 + 1, 24 << 10),
        )
        .unwrap();
        state_attributes(&dir.join(name));
    }
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(["a", "-idq", "-m3", "-ep", "src.rar"])
        .args(NAMES)
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
/// to `version`, and that header's CRC32 recomputed. Copied from
/// `tests/every_refused_member.rs::rar5_with_version` verbatim.
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

fn run(dir: &Path, args: &[&str]) -> String {
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: exit {:?}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The attribute column a KNOWN-version member of this same build prints
/// (`a.txt`, never rewritten), so the refused members are compared
/// against a real row rather than a literal this test invented.
fn attributes_column(stdout: &str, name: &str) -> String {
    stdout
        .lines()
        .find(|line| line.trim_end().ends_with(name))
        .unwrap_or_else(|| panic!("no line for {name} in:\n{stdout}"))
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

#[test]
fn plain_listing_shows_the_stored_attributes_for_an_unknown_version_member() {
    let dir = work("l");
    let archive = rar5_with_version(rar5(&dir), &["b.txt", "d.txt"], 2);
    std::fs::write(dir.join("a.rar"), archive).unwrap();

    let stdout = run(&dir, &["l", "a.rar"]);
    let known = attributes_column(&stdout, "a.txt");
    assert_eq!(known, STATED, "sanity: a known member's own attributes");
    for refused in ["b.txt", "d.txt"] {
        assert_eq!(
            attributes_column(&stdout, refused),
            known,
            "{refused}: an unknown compression version must not change how \
             its attributes render\nfull listing:\n{stdout}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wide_listing_shows_the_stored_attributes_and_ratio_for_an_unknown_version_member() {
    let dir = work("v");
    let archive = rar5_with_version(rar5(&dir), &["b.txt", "d.txt"], 2);
    std::fs::write(dir.join("a.rar"), archive).unwrap();

    let stdout = run(&dir, &["v", "a.rar"]);
    let known_line = stdout
        .lines()
        .find(|line| line.trim_end().ends_with("a.txt"))
        .unwrap();
    let known_fields: Vec<&str> = known_line.split_whitespace().collect();
    let known_attrs = known_fields[0];
    assert_eq!(known_attrs, STATED, "sanity: a known member's attributes");

    for refused in ["b.txt", "d.txt"] {
        let line = stdout
            .lines()
            .find(|line| line.trim_end().ends_with(refused))
            .unwrap_or_else(|| panic!("no line for {refused} in:\n{stdout}"));
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(
            fields[0], known_attrs,
            "{refused}: attributes should match a known member's, got {line:?}"
        );
        // The ratio column reads the header's own packed/unpacked sizes
        // and never runs the codec, so it is unaffected by an unknown
        // compression version either way; what this row pins is that it
        // is still THERE and shaped as unrar's own floored percentage
        // (`packed * 100 / size`), computed from the same row's own
        // `Size` and `Packed` fields rather than against another
        // member's, whose independently-seeded text compresses to a
        // slightly different ratio.
        let size: u64 = fields[1].parse().unwrap();
        let packed: u64 = fields[2].parse().unwrap();
        let expected_ratio = format!("{}%", packed.saturating_mul(100) / size);
        assert_eq!(
            fields[3], expected_ratio,
            "{refused}: ratio should be the header's own packed/size floor, got {line:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
