//! Extraction restores a member's modification time to the PRECISION the
//! archive stored, on files and on directories.
//!
//! Before 27 Sep 2026 `x` restored whole seconds only: the dialect's
//! member view kept `MemberInfo::mtime`'s seconds and dropped its
//! nanoseconds, so all 5,000 files of the c3 corpus came out with a
//! fraction of zero where 7zz kept the stored one. Reference unrar 7.23,
//! run on macOS (APFS) on 27 Sep 2026, restores a RAR 5 TIME record's
//! nanoseconds (`f17_htime_ns.rar`: `.123456789`), its Windows-form
//! FILETIME to the 100 ns tick (`f19_htime_win.rar`: `.000000100`) and a
//! RAR 4 extended time's 100 ns fraction, and does it for directories as
//! well as files; a bare DOS time comes back in whole seconds. Its Windows
//! build does the same to NTFS's 100 ns tick, truncating a RAR 5
//! nanosecond count rather than rounding it.
//!
//! The Unix file systems this runs on keep the nanosecond; on Windows the
//! expectation is the stored time cut to NTFS's 100 ns tick ([`kept`]),
//! which is what the reference's Windows build leaves.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use rarkit::{
    FilterPolicy, HostOs, MemberSpec, Payload, Rar4Version, Timestamp, WriteFormat, WriteMethod,
    WriteOptions, Writer,
};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-subsecond-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn vector(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../specs/vectors-F/archives")
        .join(name)
}

fn at(unix_seconds: i64, nanos: u32) -> SystemTime {
    let whole = if unix_seconds >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_secs(unix_seconds.unsigned_abs())
    } else {
        SystemTime::UNIX_EPOCH - Duration::from_secs(unix_seconds.unsigned_abs())
    };
    whole + Duration::from_nanos(u64::from(nanos))
}

/// The nanoseconds a file system keeps of `nanos`: all of them on Unix,
/// whole 100 ns ticks (cut, not rounded) on Windows.
fn kept(nanos: u32) -> u32 {
    if cfg!(windows) {
        nanos / 100 * 100
    } else {
        nanos
    }
}

fn modified(path: &Path) -> SystemTime {
    std::fs::metadata(path).unwrap().modified().unwrap()
}

/// Extracts `archive` into a fresh `out` under `root` with `threads`.
///
/// Under `TZ=UTC`: a RAR 4 time is a wall clock, set on disk as LOCAL
/// time (sweep 2 item 38, `tests/rar4_times_local.rs`), and this file
/// writes its RAR 4 tree's clocks from UTC instants and asks for those
/// instants back. A RAR 5 time is an instant under any zone.
fn extract(root: &Path, archive: &Path, out: &str, threads: &str) -> PathBuf {
    let out = root.join(out);
    std::fs::create_dir_all(&out).unwrap();
    let done = Command::new(rarfast())
        .env("TZ", "UTC")
        .args(["x", "-y", "-idq", threads])
        .arg(archive)
        .arg(format!("{}/", out.display()))
        .output()
        .unwrap();
    assert!(done.status.success(), "{done:?}");
    out
}

/// A Unix-host member: a directory when `payload` is `None`.
fn member<'a>(name: &'a [u8], payload: Option<&'a [u8]>, mtime: Timestamp) -> MemberSpec<'a> {
    MemberSpec {
        name,
        is_directory: payload.is_none(),
        payload: Payload::Bytes(payload.unwrap_or(b"")),
        mtime: Some(mtime),
        attributes: if payload.is_none() { 0o40755 } else { 0o100644 },
        host_os: HostOs::Unix,
    }
}

/// The members of the tree test, directories FIRST, so every file written
/// afterwards moves its parent's time again and only a restore made once
/// the contents are in place can leave the stored one. Every fraction is a
/// whole number of 100 ns ticks, so a RAR 4 extended time holds it exactly.
const TREE: [(&str, bool, i64, u32); 7] = [
    ("tree", true, 1_000_000_000, 111_111_100),
    ("tree/a", true, 1_100_000_000, 222_222_200),
    ("tree/a/deep", true, 1_200_000_000, 333_333_300),
    ("tree/b", true, 1_300_000_001, 444_444_400),
    ("tree/a/deep/f.txt", false, 1_400_000_000, 555_555_500),
    ("tree/a/g.txt", false, 1_500_000_001, 987_654_300),
    ("tree/b/h.txt", false, 1_600_000_000, 0),
];

fn write_tree(format: WriteFormat, path: &Path) {
    let options = WriteOptions {
        format,
        method: WriteMethod::Stored,
        filters: match format {
            WriteFormat::Rar5 => FilterPolicy::Detect,
            WriteFormat::Rar4(_) => FilterPolicy::Off,
        },
        ..WriteOptions::default()
    };
    let mut writer = Writer::new(options).unwrap();
    for (name, is_dir, unix_seconds, nanos) in TREE {
        let mtime = Timestamp {
            unix_seconds,
            nanos,
        };
        let payload = (!is_dir).then_some(name.as_bytes());
        writer.add(member(name.as_bytes(), payload, mtime)).unwrap();
    }
    let mut bytes = Vec::new();
    writer.finish_into(&mut bytes).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// The two genuine reference-written vectors, each restored to the
/// fraction the reference's own `x` leaves on the file.
#[test]
fn extracted_files_keep_the_stored_subsecond_time() {
    let root = work("files");
    for (name, want) in [
        ("f17_htime_ns.rar", at(1_789_704_000, kept(123_456_789))),
        ("f19_htime_win.rar", at(1_577_934_245, 100)),
    ] {
        for threads in ["-mt1", "-mt4"] {
            let out = extract(&root, &vector(name), &format!("{name}{threads}"), threads);
            assert_eq!(
                modified(&out.join("hello.txt")),
                want,
                "{name} after x {threads}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// The directory test: each directory restored AFTER its contents,
/// to the stored fraction, over RAR 5's TIME record and RAR 4's extended
/// time, on the sequential and the concurrent path. The files are held to
/// the same precision beside them.
#[test]
fn extracted_directories_keep_the_stored_subsecond_time_after_their_contents() {
    let root = work("tree");
    for (what, format) in [
        ("rar5", WriteFormat::Rar5),
        ("rar4", WriteFormat::Rar4(Rar4Version::V29)),
    ] {
        let archive = root.join(format!("{what}.rar"));
        write_tree(format, &archive);
        for threads in ["-mt1", "-mt4"] {
            let out = extract(&root, &archive, &format!("{what}{threads}"), threads);
            for (name, _, unix_seconds, nanos) in TREE {
                assert_eq!(
                    modified(&out.join(name)),
                    at(unix_seconds, nanos),
                    "{name} from {what} after x {threads}"
                );
            }
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}
