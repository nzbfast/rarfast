//! Three follow-ups of the 27 Sep 2026 CLI train, each MEASURED against
//! reference unrar 7.23 on macOS (an M3 Mac) and Linux (a small VPS), 28
//! Sep 2026, over the archives this file builds (spec F 3.2 framing and
//! file header, 3.2.6.2 redirection record) and a genuine rar 4.2.0
//! archive with one header byte rewritten (spec F 3.3):
//!
//! 1. a hard link's or a copy's target reaches the member it names by that
//!    member's ON-DISK name, not its display text (`extract/links.rs`);
//! 2. `lt` shows a redirection member's target as it shows a name, and
//!    drops the `Target:` line where it cannot print it (`list.rs`);
//! 3. a member this run did not select, which the engine refuses, is none
//!    of the run's failures: exit 0 (`extract.rs`).

//!
//! Items 1 and 2 are Unix only: 1 by its nature (names of raw bytes and
//! control characters on disk, a link told from a copy by its inode), 2
//! because what `lt` prints was measured per system and no Windows column
//! is measured yet. Item 3 runs everywhere. Off Unix the archive builder
//! the first two use is unused.

#![cfg_attr(not(unix), allow(dead_code))]

#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const WINDOWS: u8 = 0;
const UNIX: u8 = 1;
const HARD_LINK: u64 = 4;
const FILE_COPY: u64 = 5;
const UNIX_SYMLINK: u64 = 1;
const WINDOWS_SYMLINK: u64 = 2;

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

/// One member of a stored RAR 5 archive: a file with `data`, or a
/// redirection of `kind` to `target`, whose data area is empty and whose
/// declared size is its target's, as rar 7.23 writes one.
struct Entry<'a> {
    host: u8,
    name: &'a [u8],
    data: &'a [u8],
    redirect: Option<(u64, &'a [u8])>,
}

fn file<'a>(name: &'a [u8], data: &'a [u8]) -> Entry<'a> {
    Entry {
        host: UNIX,
        name,
        data,
        redirect: None,
    }
}

fn link<'a>(kind: u64, name: &'a [u8], target: &'a [u8]) -> Entry<'a> {
    Entry {
        host: UNIX,
        name,
        data: b"",
        redirect: Some((kind, target)),
    }
}

fn rar5(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &[], &mut out);
    for entry in entries {
        let mut extra = Vec::new();
        let (size, crc) = match entry.redirect {
            Some((kind, target)) => {
                let mut record = Vec::new();
                vint(5, &mut record); // the redirection record
                vint(kind, &mut record);
                vint(0, &mut record);
                vint(target.len() as u64, &mut record);
                record.extend_from_slice(target);
                vint(record.len() as u64, &mut extra);
                extra.extend_from_slice(&record);
                (6, 0)
            }
            None => (entry.data.len() as u64, crc32(entry.data)),
        };
        let mut body = Vec::new();
        vint(2, &mut body); // file header
        if extra.is_empty() {
            vint(0x0002, &mut body); // a data area follows
        } else {
            vint(0x0003, &mut body); // an extra area, and a data area
            vint(extra.len() as u64, &mut body);
        }
        vint(entry.data.len() as u64, &mut body);
        vint(0x0006, &mut body); // mtime and CRC32 present
        vint(size, &mut body);
        vint(if entry.host == UNIX { 0o100_644 } else { 0x20 }, &mut body);
        body.extend_from_slice(&1_700_000_000_u32.to_le_bytes());
        body.extend_from_slice(&crc.to_le_bytes());
        vint(0, &mut body); // stored
        vint(u64::from(entry.host), &mut body);
        vint(entry.name.len() as u64, &mut body);
        body.extend_from_slice(entry.name);
        body.extend_from_slice(&extra);
        block(&body, entry.data, &mut out);
    }
    block(&[5, 0, 0], &[], &mut out);
    out
}

/// A scratch directory per test and width, the archive at `a.rar`, the
/// output under `o/`, the commands run from inside it so paths read `o/`.
struct Work {
    dir: PathBuf,
}

impl Work {
    fn new(tag: &str, archive: &[u8]) -> Work {
        let dir = std::env::temp_dir().join(format!("rarfast-nle-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("o")).unwrap();
        std::fs::write(dir.join("a.rar"), archive).unwrap();
        Work { dir }
    }

    fn out(&self) -> PathBuf {
        self.dir.join("o")
    }

    fn run(&self, args: &[&str], members: &[&str]) -> Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_rarfast"));
        c.current_dir(&self.dir)
            .args(args)
            .arg("a.rar")
            .args(members);
        if matches!(args[0], "x" | "e") {
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

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(unix)]
fn at(root: &Path, name: &[u8]) -> PathBuf {
    root.join(OsStr::from_bytes(name))
}

/// A tag, the member's stored name, the target as stored, and the name
/// the member is written under.
type TargetCase = (&'static str, &'static [u8], &'static [u8], &'static [u8]);

/// Item 1: every target the reference resolved, and the file it resolved
/// to, which rarfast now reaches the same way. `a\xffb` is written as `a`
/// (a RAR 5 name ends at its first invalid UTF-8), and a target spelled
/// `a\xffb`, or `a\xfec`, cut the same way, names it; before, the target
/// was looked up by its lossy display text and missed.
#[cfg(unix)]
#[test]
fn a_target_names_its_member_by_the_on_disk_name() {
    let cases: [TargetCase; 6] = [
        ("ff", b"a\xffb", b"a\xffb", b"a"),
        ("ff-other", b"a\xffb", b"a\xfec", b"a"),
        ("ff-cut", b"a\xffb", b"a", b"a"),
        ("tab", b"tab\tthere", b"tab\tthere", b"tab\tthere"),
        ("esc", b"e\x1bx", b"e\x1bx", b"e\x1bx"),
        ("dir-tab", b"d\tx/f", b"d\tx/f", b"d\tx/f"),
    ];
    for (tag, name, target, disk) in cases {
        for (kind, word) in [(HARD_LINK, "hl"), (FILE_COPY, "cp")] {
            let archive = rar5(&[file(name, b"hello\n"), link(kind, b"L", target)]);
            for width in WIDTHS {
                let work = Work::new(&format!("{word}-{tag}{width}"), &archive);
                let done = work.run(&["x", "-y", width], &[]);
                assert_eq!(code(&done), 0, "{word} {tag} {width}: {done:?}");
                let made = work.out().join("L");
                assert_eq!(std::fs::read(&made).unwrap(), b"hello\n", "{word} {tag}");
                let source = std::fs::metadata(at(&work.out(), disk)).unwrap();
                let linked = std::fs::metadata(&made).unwrap();
                // One inode for a hard link; two for a copy.
                assert_eq!(
                    source.ino() == linked.ino(),
                    kind == HARD_LINK,
                    "{word} {tag} {width}"
                );
            }
        }
    }
}

/// Item 1: a `\` in a target is a SEPARATOR to the reference, whatever
/// the link's host: `bs\x` resolves to `bs/x`, never to a Unix member
/// named `bs\x` (which is written as that one name), and where there is
/// no `bs/x` the member is refused (hard link: exit 9; copy: exit 6,
/// naming `o/bs/x`, and no ` 0%` counter on its line). A Windows member
/// `w\x` is written `w_x`, and a target `w_x` reaches it.
#[cfg(unix)]
#[test]
fn a_backslash_in_a_target_separates() {
    let only_bs = |kind| rar5(&[file(b"bs\\x", b"back\n"), link(kind, b"L", b"bs\\x")]);
    let both = |kind| {
        rar5(&[
            file(b"bs\\x", b"back\n"),
            file(b"bs/x", b"slash\n"),
            link(kind, b"L", b"bs\\x"),
        ])
    };
    let windows_link = rar5(&[
        file(b"bs/x", b"slash\n"),
        Entry {
            host: WINDOWS,
            ..link(HARD_LINK, b"L", b"bs\\x")
        },
    ]);
    let windows_name = |target: &'static [u8]| {
        rar5(&[
            Entry {
                host: WINDOWS,
                ..file(b"w\\x", b"win\n")
            },
            link(HARD_LINK, b"L", target),
        ])
    };
    for width in WIDTHS {
        let work = Work::new(&format!("bs-hl{width}"), &only_bs(HARD_LINK));
        let done = work.run(&["x", "-y", width], &[]);
        assert_eq!(code(&done), 9, "{width}: {done:?}");
        assert!(
            text(&done.stderr).contains("Cannot create hard link o/L"),
            "{width}: {done:?}"
        );
        assert!(!work.out().join("L").exists(), "{width}");

        let work = Work::new(&format!("bs-cp{width}"), &only_bs(FILE_COPY));
        let done = work.run(&["x", "-y", width], &[]);
        assert_eq!(code(&done), 6, "{width}: {done:?}");
        let err = text(&done.stderr);
        assert!(
            err.contains("Cannot open o/bs/x") && err.contains("Cannot copy o/bs/x to o/L."),
            "{width}: {err}"
        );
        let out = text(&done.stdout);
        let line = out.lines().find(|l| l.contains("o/L")).unwrap();
        assert!(!line.contains('%'), "{width}: {line:?}");
        assert!(!work.out().join("L").exists(), "{width}");

        for (kind, word) in [(HARD_LINK, "hl"), (FILE_COPY, "cp")] {
            let work = Work::new(&format!("both-{word}{width}"), &both(kind));
            let done = work.run(&["x", "-y", width], &[]);
            assert_eq!(code(&done), 0, "{word} {width}: {done:?}");
            assert_eq!(std::fs::read(work.out().join("L")).unwrap(), b"slash\n");
        }

        let work = Work::new(&format!("winlink{width}"), &windows_link);
        let done = work.run(&["x", "-y", width], &[]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        assert_eq!(std::fs::read(work.out().join("L")).unwrap(), b"slash\n");

        let work = Work::new(&format!("winname-us{width}"), &windows_name(b"w_x"));
        let done = work.run(&["x", "-y", width], &[]);
        assert_eq!(code(&done), 0, "{width}: {done:?}");
        assert_eq!(std::fs::read(work.out().join("L")).unwrap(), b"win\n");

        let work = Work::new(&format!("winname-bs{width}"), &windows_name(b"w\\x"));
        let done = work.run(&["x", "-y", width], &[]);
        assert_eq!(code(&done), 9, "{width}: {done:?}");
    }
}

/// The `lt` block's `Target:` line, or `None` where there is none.
fn target_line(archive: &[u8], tag: &str) -> Option<String> {
    let work = Work::new(tag, archive);
    let done = work.run(&["lt"], &[]);
    assert_eq!(code(&done), 0, "{tag}: {done:?}");
    text(&done.stdout)
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("Target: ").map(str::to_owned))
}

/// Item 2: `lt` shows a target as the reference shows a RAR 5 name, and
/// leaves the line out where it cannot print it. Before, a target was
/// shown lossily (`a\u{fffd}b`), and printed where the reference drops it.
#[cfg(unix)]
#[test]
fn lt_shows_a_target_as_it_shows_a_name() {
    let symlink =
        |target: &[u8], tag: &str| target_line(&rar5(&[link(UNIX_SYMLINK, b"s", target)]), tag);
    assert_eq!(symlink(b"a\xffb", "t-ff").as_deref(), Some("a"));
    assert_eq!(symlink(b"a\xc0\xafb", "t-ovl").as_deref(), Some("a/b"));
    assert_eq!(
        symlink(b"a\xf4\x90\x80\x80b", "t-u10").as_deref(),
        Some("ab")
    );
    assert_eq!(symlink(b"a\tb", "t-tab").as_deref(), Some("a\tb"));
    assert_eq!(symlink(b"a\\b", "t-bs").as_deref(), Some("a\\b"));
    assert_eq!(
        symlink("café".as_bytes(), "t-cafe").as_deref(),
        Some("café")
    );
    // A surrogate: `?` on Linux, and the whole line gone on macOS, where
    // the reference cannot print it; the member's own `Name:` line stays.
    let surrogate = symlink(b"a\xed\xa0\x80b", "t-sur");
    if cfg!(target_os = "macos") {
        assert_eq!(surrogate, None);
    } else {
        assert_eq!(surrogate.as_deref(), Some("a?b"));
    }
    let hard = target_line(
        &rar5(&[file(b"f", b"x\n"), link(HARD_LINK, b"L", b"f\xed\xa0\x80")]),
        "t-hl-sur",
    );
    if cfg!(target_os = "macos") {
        assert_eq!(hard, None);
    } else {
        assert_eq!(hard.as_deref(), Some("f?"));
    }
    // A Windows link keeps its `\` in the listing, where a Windows NAME
    // lists it as `_`.
    let windows = Entry {
        host: WINDOWS,
        ..link(WINDOWS_SYMLINK, b"s", b"..\\a")
    };
    assert_eq!(
        target_line(&rar5(&[windows]), "t-win").as_deref(),
        Some("..\\a")
    );
}

/// `r420_m3.rar` (genuine rar 4.2.0) with BIG.TXT's unpack version set to
/// 5, which no decoder claims, and its header CRC16 recomputed (spec F
/// 3.3: the low half of the CRC32 over the header from its type byte).
fn with_unknown_version() -> Vec<u8> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/legacy/archives/r420_m3.rar");
    let mut archive = std::fs::read(&path).unwrap();
    let mut pos = 7;
    loop {
        let kind = archive[pos + 2];
        let flags = u16::from_le_bytes([archive[pos + 3], archive[pos + 4]]);
        let size = usize::from(u16::from_le_bytes([archive[pos + 5], archive[pos + 6]]));
        assert_ne!(kind, 0x7B, "no BIG.TXT in {}", path.display());
        let add = if kind == 0x74 || flags & 0x8000 != 0 {
            u32::from_le_bytes(archive[pos + 7..pos + 11].try_into().unwrap()) as usize
        } else {
            0
        };
        if kind == 0x74 {
            let len = usize::from(u16::from_le_bytes([archive[pos + 26], archive[pos + 27]]));
            if &archive[pos + 32..pos + 32 + len] == b"BIG.TXT" {
                archive[pos + 24] = 5;
                let crc = (crc32(&archive[pos + 2..pos + size]) & 0xFFFF) as u16;
                archive[pos..pos + 2].copy_from_slice(&crc.to_le_bytes());
                return archive;
            }
        }
        pos += size + add;
    }
}

/// Item 3: the reference says nothing about a member it was not asked
/// for and exits 0; asked for it, it refuses it with exit 2. rarfast
/// exited 2 in every row, reporting the refusal of a member it skipped.
#[test]
fn an_unselected_member_the_engine_refuses_is_not_a_failure() {
    let archive = with_unknown_version();
    let rows: [(&[&str], &[&str]); 5] = [
        (&["x", "-y"], &["HELLO.TXT"]),
        (&["x", "-y", "-xBIG.TXT"], &[]),
        (&["e", "-y"], &["HELLO.TXT"]),
        (&["t"], &["HELLO.TXT"]),
        (&["p", "-inul"], &["HELLO.TXT"]),
    ];
    for width in WIDTHS {
        for (i, (args, members)) in rows.iter().enumerate() {
            let mut args = args.to_vec();
            args.push(width);
            let work = Work::new(&format!("ver-{i}{width}"), &archive);
            let done = work.run(&args, members);
            assert_eq!(code(&done), 0, "{args:?} {members:?}: {done:?}");
            assert!(
                !text(&done.stderr).contains("BIG.TXT"),
                "{args:?}: {done:?}"
            );
            if args[0] != "p" {
                assert!(text(&done.stdout).contains("All OK"), "{args:?}: {done:?}");
            }
        }
        // Every member of `-xBIG.TXT` came out, BIG.TXT's neighbours too.
        let work = Work::new(&format!("ver-tree{width}"), &archive);
        work.run(&["x", "-y", "-xBIG.TXT", width], &[]);
        assert!(work.out().join("HELLO.TXT").is_file(), "{width}");
        assert!(work.out().join("EMPTY.DAT").is_file(), "{width}");
        assert!(!work.out().join("BIG.TXT").exists(), "{width}");

        // Asked for, it is refused: exit 2, as the reference.
        for (i, members) in [&["BIG.TXT"][..], &[][..]].iter().enumerate() {
            let work = Work::new(&format!("ver-sel{i}{width}"), &archive);
            let done = work.run(&["x", "-y", width], members);
            assert_eq!(code(&done), 2, "{members:?} {width}: {done:?}");
            assert!(!work.out().join("BIG.TXT").exists(), "{width}");
        }
    }
}
