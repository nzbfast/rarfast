//! `-ta<date>` and `-tb<date>` with a date written with separators, and
//! `-ts-` and `-tsm-`, do what reference unrar 7.23 does.
//!
//! Sweep 2 items 36 and 35, 8 Oct 2026.
//!
//! **Item 36.** Only the all digits `YYYYMMDDHHMMSS` was read as a date:
//! `-ta2023-11-14` parsed to nothing, added no filter, and every member
//! was extracted. The reference (measured on macOS arm64 the same day;
//! [`DATES`] is its own answer over the archive this test writes, under
//! `TZ=UTC`) reads six numbers, year first, each up to its width (four
//! digits, then two each) and parted by ANY run of other characters or by
//! nothing; a number left out is 1 for the month and the day and 0 for
//! the rest; a month or a day past its range carries over as the C
//! library carries it (`2023-13-45` is 14 Feb 2024). A date it cannot
//! read (`-taxyz`, `-ta`, a year of two digits, `9999-99-99`, the year
//! 3000) is NOT no filter: it is a time before every file, so `-ta` takes
//! everything and `-tb` NOTHING. Until now such a date added no filter and
//! `x -tbxyz` wrote every member where the reference writes none. `-tb`
//! is strictly before: a member at the very second is not taken, where
//! until now it was.
//!
//! **Item 35.** `-ts-` and `-tsm-` were accepted and the stored
//! modification time was still set. The reference leaves a file and a
//! directory with the time of extraction under either, and restores the
//! time under `-ts`, `-tsm`, `-tsm1`, `-tsc-` and `-tsa-`.
//!
//! Unix only, for `TZ`; the same rows on Windows are owed.
//!
//! Assumes: no thread pool to speak of (members of a few bytes; every run
//! states `-mt1`), under 16 MiB of memory.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

/// 2020-09-13 12:26:40, 2023-11-14 22:13:20 and 2024-07-03 09:46:40 UTC.
const OLD: i64 = 1_600_000_000;
const MID: i64 = 1_700_000_000;
const NEW: i64 = 1_720_000_000;

/// A switch, and whether `old.txt`, `mid.txt` and `new.txt` are listed
/// under it with `TZ=UTC`.
const DATES: &[(&str, [bool; 3])] = &[
    ("-ta2023-11-14", [false, true, true]),
    ("-ta20231114", [false, true, true]),
    ("-tb2023-11-14", [true, false, false]),
    ("-tb20231114", [true, false, false]),
    ("-ta2023-11-14,22:13:20", [false, true, true]),
    ("-ta2023-11-14,22:13:21", [false, false, true]),
    ("-tb2023-11-14,22:13:20", [true, false, false]),
    ("-tb2023-11-14,22:13:21", [true, true, false]),
    ("-ta20231114221320", [false, true, true]),
    ("-ta20231114221321", [false, false, true]),
    ("-tb20231114221320", [true, false, false]),
    ("-tb20231114221321", [true, true, false]),
    ("-ta2023-11-14_22-13-21", [false, false, true]),
    ("-ta2023/11/15", [false, false, true]),
    ("-ta2023:11:14:22:13:21", [false, false, true]),
    ("-ta2023-11-14T22:13:21", [false, false, true]),
    ("-ta2023--11--15", [false, false, true]),
    ("-ta2023", [false, true, true]),
    ("-ta2024", [false, false, true]),
    ("-ta202311", [false, true, true]),
    ("-ta2023-12", [false, false, true]),
    ("-ta2023-1-1", [false, true, true]),
    ("-ta2023-11-14-22-13-2", [false, true, true]),
    ("-ta202311142213", [false, true, true]),
    ("-ta2023111422132", [false, true, true]),
    ("-ta20231114221321999", [false, false, true]),
    ("-ta2023-13-45", [false, false, true]),
    ("-ta2023-02-30", [false, true, true]),
    ("-ta2023-11-31", [false, false, true]),
    ("-taxyz", [true, true, true]),
    ("-ta", [true, true, true]),
    ("-ta23-11-14", [true, true, true]),
    ("-ta0000", [true, true, true]),
    ("-ta9999-99-99", [true, true, true]),
    ("-tam2023-11-15", [false, false, true]),
    ("-TA2023-11-15", [false, false, true]),
    ("-tb2024-07-03 09:46:41", [true, true, true]),
    ("-ta2020-09-13+12+26+40", [true, true, true]),
    ("-ta2020-09-13;12;26;41", [false, true, true]),
    ("-ta1969-12-31", [true, true, true]),
    ("-tb1969-12-31", [false, false, false]),
    ("-ta2023-00-10", [false, true, true]),
    ("-ta2023-11-00", [false, true, true]),
    ("-tbxyz", [false, false, false]),
    ("-tb", [false, false, false]),
    ("-tb23-11-14", [false, false, false]),
    ("-tb9999-99-99", [false, false, false]),
    ("-tb3000", [false, false, false]),
    ("-ta3000", [true, true, true]),
    ("-tb2100", [true, true, true]),
    ("-ta2100", [false, false, false]),
];

struct Bench {
    dir: PathBuf,
    unrar: PathBuf,
    own: PathBuf,
    archive: String,
}

impl Bench {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rarfast-s36-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // The name picks the dialect.
        let unrar = dir.join("unrar");
        let own = dir.join("rarfast");
        copy_executable(&rarfast(), &unrar);
        copy_executable(&rarfast(), &own);
        let archive = dir.join("dated.rar");
        write_archive(&archive);
        let archive = archive.to_string_lossy().into_owned();
        Bench {
            dir,
            unrar,
            own,
            archive,
        }
    }

    fn names(&self) -> [(&'static str, &Path); 2] {
        [("unrar", &self.unrar), ("rarfast", &self.own)]
    }

    /// `TZ=UTC <exe> <args>` in a fresh directory, which is returned.
    fn run(&self, exe: &Path, args: &[&str]) -> (PathBuf, Output) {
        let room = self.dir.join("room");
        let _ = std::fs::remove_dir_all(&room);
        std::fs::create_dir_all(&room).unwrap();
        let out = output_of(
            Command::new(exe)
                .args(args)
                .env("TZ", "UTC")
                .current_dir(&room)
                .stdin(Stdio::null()),
        )
        .expect("the command runs");
        (room, out)
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A stored RAR 5 archive of three files and a directory, by the engine.
fn write_archive(path: &Path) {
    use rarkit::{HostOs, MemberSpec, Payload, Timestamp, WriteOptions, Writer};
    let mut writer = Writer::new(WriteOptions::default()).expect("options");
    let entries: [(&str, i64, bool); 4] = [
        ("old.txt", OLD, false),
        ("mid.txt", MID, false),
        ("new.txt", NEW, false),
        ("kept", OLD, true),
    ];
    for (name, unix_seconds, directory) in entries {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(if directory { b"" } else { name.as_bytes() }),
                mtime: Some(Timestamp {
                    unix_seconds,
                    nanos: 0,
                }),
                attributes: if directory { 0o040_755 } else { 0o100_644 },
                host_os: HostOs::Unix,
                is_directory: directory,
            })
            .expect("a member");
    }
    let mut bytes = Vec::new();
    writer.finish_into(&mut bytes).expect("the archive");
    std::fs::write(path, bytes).unwrap();
}

fn said(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn seconds_of(path: &Path) -> i64 {
    let modified = std::fs::metadata(path).unwrap().modified().unwrap();
    i64::try_from(modified.duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap()
}

#[test]
fn a_date_is_read_with_or_without_separators() {
    let bench = Bench::new("dates");
    for (name, exe) in bench.names() {
        for (switch, expected) in DATES {
            let (_, out) = bench.run(exe, &["lb", "-mt1", switch, &bench.archive]);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{name} {switch}: {}",
                said(&out)
            );
            let text = String::from_utf8_lossy(&out.stdout);
            let listed =
                ["old.txt", "mid.txt", "new.txt"].map(|file| text.lines().any(|line| line == file));
            assert_eq!(listed, *expected, "{name} lb {switch}");
        }
    }
}

/// The item's own scenario: the filter holds on extraction, so nothing
/// older is written.
#[test]
fn a_separated_date_filters_what_is_extracted() {
    let bench = Bench::new("extract");
    for (name, exe) in bench.names() {
        let (room, out) = bench.run(exe, &["x", "-mt1", "-o+", "-ta2023-11-14", &bench.archive]);
        assert_eq!(out.status.code(), Some(0), "{name}: {}", said(&out));
        assert!(
            !room.join("old.txt").exists(),
            "{name}: old.txt was written"
        );
        assert!(room.join("mid.txt").exists(), "{name}: {}", said(&out));
        assert!(room.join("new.txt").exists(), "{name}: {}", said(&out));
    }
}

#[test]
fn ts_minus_leaves_the_time_of_extraction() {
    let bench = Bench::new("ts");
    let recent = |path: &Path| {
        let age = SystemTime::now()
            .duration_since(std::fs::metadata(path).unwrap().modified().unwrap())
            .unwrap_or(Duration::ZERO);
        age < Duration::from_secs(600)
    };
    for (name, exe) in bench.names() {
        for switch in ["-ts-", "-tsm-", "-TSM-"] {
            let (room, out) = bench.run(exe, &["x", "-mt1", "-o+", switch, &bench.archive]);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{name} {switch}: {}",
                said(&out)
            );
            for member in ["old.txt", "mid.txt", "new.txt", "kept"] {
                assert!(
                    recent(&room.join(member)),
                    "{name} x {switch}: {member} carries {}",
                    seconds_of(&room.join(member))
                );
            }
        }
        for switch in ["-ts", "-tsm", "-tsm1", "-tsc-", "-tsa-", "-o+"] {
            let (room, out) = bench.run(exe, &["x", "-mt1", "-o+", switch, &bench.archive]);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{name} {switch}: {}",
                said(&out)
            );
            assert_eq!(seconds_of(&room.join("old.txt")), OLD, "{name} x {switch}");
            assert_eq!(seconds_of(&room.join("new.txt")), NEW, "{name} x {switch}");
            assert_eq!(seconds_of(&room.join("kept")), OLD, "{name} x {switch}");
        }
    }
}
