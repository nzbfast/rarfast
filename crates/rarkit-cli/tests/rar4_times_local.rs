//! A RAR 4 member's time is a wall clock, and extraction sets it on disk
//! as LOCAL time, as reference unrar 7.23 does and as the listing prints.
//!
//! Sweep 2 item 38, 8 Oct 2026. A RAR 1.5 to 4.x header stores a DOS date
//! and time, which carries no zone. The engine reads it as UTC and says
//! so; the listing rendered it back with no zone applied, which is the
//! stored wall clock, and extraction set that UTC reading on the file. So
//! on a machine not at UTC every file out of a RAR 4 archive was off by
//! the zone's offset from what the reference gives it and from what
//! rarfast's own `lt` shows.
//!
//! [`ROWS`] is the reference's own result (unrar 7.23, macOS arm64,
//! 8 Oct 2026, `TZ=<zone> unrar x`, then the file's time in Unix seconds)
//! over the archive this test writes: seven wall clocks under five zones.
//! Two of the zones change their offset between the archive's dates, and
//! four of the clocks sit in a change itself: one that a zone skips (the
//! reference goes FORWARD by the skipped hour) and one that it has twice
//! (the reference takes the SECOND, the winter one). That is the C
//! library's choice on macOS; what the reference does on Linux and on
//! Windows at those two instants is owed.
//!
//! Unix only: the zone is given by `TZ`, which the reference's Windows
//! build does not read; the same rows on Windows are owed.
//!
//! Assumes: no thread pool to speak of (members of a few bytes; every run
//! states `-mt1`), under 16 MiB of memory.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::UNIX_EPOCH;

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

/// The members: a name, and the wall clock its header stores, given as the
/// Unix seconds of that clock read as UTC (which is how the writer takes
/// it).
const MEMBERS: &[(&str, i64)] = &[
    // 2020-09-13 12:26:40, the legacy fixtures' own time: summer.
    ("summer.txt", 1_600_000_000),
    // 2020-01-15 08:00:00: winter.
    ("winter.txt", 1_579_075_200),
    // 2021-03-14 02:30:00: skipped in America/New_York.
    ("ny-skipped.txt", 1_615_689_000),
    // 2020-11-01 01:30:00: twice in America/New_York.
    ("ny-twice.txt", 1_604_194_200),
    // 2021-03-28 02:30:00: skipped in Europe/Berlin.
    ("cet-skipped.txt", 1_616_898_600),
    // 2020-10-25 02:30:00: twice in Europe/Berlin.
    ("cet-twice.txt", 1_603_593_000),
    // 1999-12-31 23:59:58.
    ("century.txt", 946_684_798),
];

/// A zone, and each member's time on disk in Unix seconds, in the order
/// of [`MEMBERS`].
const ROWS: &[(&str, [i64; 7])] = &[
    (
        "UTC",
        [
            1_600_000_000,
            1_579_075_200,
            1_615_689_000,
            1_604_194_200,
            1_616_898_600,
            1_603_593_000,
            946_684_798,
        ],
    ),
    (
        "America/New_York",
        [
            1_600_014_400,
            1_579_093_200,
            1_615_707_000,
            1_604_212_200,
            1_616_913_000,
            1_603_607_400,
            946_702_798,
        ],
    ),
    (
        "Europe/Berlin",
        [
            1_599_992_800,
            1_579_071_600,
            1_615_685_400,
            1_604_190_600,
            1_616_895_000,
            1_603_589_400,
            946_681_198,
        ],
    ),
    (
        "Asia/Singapore",
        [
            1_599_971_200,
            1_579_046_400,
            1_615_660_200,
            1_604_165_400,
            1_616_869_800,
            1_603_564_200,
            946_655_998,
        ],
    ),
    (
        "Australia/Sydney",
        [
            1_599_964_000,
            1_579_035_600,
            1_615_649_400,
            1_604_154_600,
            1_616_859_000,
            1_603_553_400,
            946_645_198,
        ],
    ),
];

struct Bench {
    dir: PathBuf,
    unrar: PathBuf,
    own: PathBuf,
}

impl Bench {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rarfast-s38-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // The name picks the dialect.
        let unrar = dir.join("unrar");
        let own = dir.join("rarfast");
        copy_executable(&rarfast(), &unrar);
        copy_executable(&rarfast(), &own);
        Bench { dir, unrar, own }
    }

    fn names(&self) -> [(&'static str, &Path); 2] {
        [("unrar", &self.unrar), ("rarfast", &self.own)]
    }

    /// `TZ=<zone> <exe> <args>` in a fresh directory, which is returned.
    fn run(&self, exe: &Path, zone: &str, args: &[&str]) -> (PathBuf, Output) {
        let room = self.dir.join("room");
        let _ = std::fs::remove_dir_all(&room);
        std::fs::create_dir_all(&room).unwrap();
        let out = output_of(
            Command::new(exe)
                .args(args)
                .env("TZ", zone)
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

/// The archive of [`MEMBERS`] in one of the two formats, by rarkit's own
/// writer (reference `rar` 7 writes RAR 5 only).
fn write_archive(path: &Path, format: rarkit::WriteFormat) {
    let mut writer = rarkit::Writer::new(rarkit::WriteOptions {
        format,
        method: rarkit::WriteMethod::Stored,
        filters: rarkit::FilterPolicy::Off,
        host_os: rarkit::HostOs::Unix,
        ..rarkit::WriteOptions::default()
    })
    .unwrap();
    for (name, clock) in MEMBERS {
        writer
            .add(rarkit::MemberSpec {
                name: name.as_bytes(),
                payload: rarkit::Payload::Bytes(name.as_bytes()),
                mtime: Some(rarkit::Timestamp {
                    unix_seconds: *clock,
                    nanos: 0,
                }),
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .unwrap();
    }
    let mut bytes = Vec::new();
    writer.finish_into(&mut bytes).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn seconds_of(path: &Path) -> i64 {
    let modified = std::fs::metadata(path).unwrap().modified().unwrap();
    match modified.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_secs()).unwrap(),
        Err(before) => -i64::try_from(before.duration().as_secs()).unwrap(),
    }
}

fn said(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_rar4_time_is_set_on_disk_as_local_time() {
    let bench = Bench::new("rar4");
    let archive = bench.dir.join("clocks.rar");
    write_archive(
        &archive,
        rarkit::WriteFormat::Rar4(rarkit::Rar4Version::V40),
    );
    let archive = archive.to_string_lossy().into_owned();
    for (name, exe) in bench.names() {
        for (zone, expected) in ROWS {
            let (room, out) = bench.run(exe, zone, &["x", "-mt1", "-o+", &archive]);
            assert_eq!(out.status.code(), Some(0), "{name} {zone}: {}", said(&out));
            let got: Vec<i64> = MEMBERS
                .iter()
                .map(|(member, _)| seconds_of(&room.join(member)))
                .collect();
            assert_eq!(got, expected.to_vec(), "{name} under TZ={zone}");
        }
    }
}

/// What the listing shows is the stored wall clock under every zone, and
/// it is the local reading of the time extraction sets: the two agree.
#[test]
fn the_listing_shows_the_same_clock_under_every_zone() {
    let bench = Bench::new("listing");
    let archive = bench.dir.join("clocks.rar");
    write_archive(
        &archive,
        rarkit::WriteFormat::Rar4(rarkit::Rar4Version::V40),
    );
    let archive = archive.to_string_lossy().into_owned();
    for (name, exe) in bench.names() {
        let mut first: Option<Vec<u8>> = None;
        for (zone, _) in ROWS {
            let (_, out) = bench.run(exe, zone, &["lt", "-mt1", &archive]);
            assert_eq!(out.status.code(), Some(0), "{name} {zone}: {}", said(&out));
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(
                text.contains("mtime: 2020-09-13 12:26:40,"),
                "{name} lt under TZ={zone}: {text}"
            );
            match &first {
                None => first = Some(out.stdout),
                Some(first) => assert_eq!(&out.stdout, first, "{name} lt under TZ={zone}"),
            }
        }
    }
}

/// A RAR 5 time is an instant: the same on disk under every zone. The
/// fix above must not move it.
#[test]
fn a_rar5_time_is_the_same_instant_under_every_zone() {
    let bench = Bench::new("rar5");
    let archive = bench.dir.join("instants.rar");
    write_archive(&archive, rarkit::WriteFormat::Rar5);
    let archive = archive.to_string_lossy().into_owned();
    for (name, exe) in bench.names() {
        for (zone, _) in ROWS {
            let (room, out) = bench.run(exe, zone, &["x", "-mt1", "-o+", &archive]);
            assert_eq!(out.status.code(), Some(0), "{name} {zone}: {}", said(&out));
            for (member, instant) in MEMBERS {
                assert_eq!(
                    seconds_of(&room.join(member)),
                    *instant,
                    "{name} {member} under TZ={zone}"
                );
            }
        }
    }
}

/// A time switch compares the same local reading. Reference unrar 7.23,
/// measured the same day: under `TZ=Asia/Singapore` the member stored as
/// 12:26:40 is not after 18:00 that day, and under the UTC reading it was
/// 20:26:40 there and was kept.
#[test]
fn a_time_switch_compares_a_rar4_time_as_local_time() {
    let bench = Bench::new("switch");
    let archive = bench.dir.join("clocks.rar");
    write_archive(
        &archive,
        rarkit::WriteFormat::Rar4(rarkit::Rar4Version::V40),
    );
    let archive = archive.to_string_lossy().into_owned();
    let rows = [
        ("-ta20200913180000", false),
        ("-tb20200913180000", true),
        ("-ta20200913060000", true),
        ("-tb20200913060000", false),
    ];
    for (name, exe) in bench.names() {
        for zone in ["UTC", "Asia/Singapore", "America/New_York"] {
            for (switch, kept) in rows {
                let (_, out) = bench.run(exe, zone, &["lb", "-mt1", switch, &archive]);
                assert_eq!(out.status.code(), Some(0), "{name} {zone}: {}", said(&out));
                let listed = String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .any(|line| line == "summer.txt");
                assert_eq!(listed, kept, "{name} lb {switch} under TZ={zone}");
            }
        }
    }
}
