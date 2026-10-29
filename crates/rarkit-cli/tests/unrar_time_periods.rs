//! `-tn` and `-to` take a PERIOD, back from now, and filter on it
//! (`args.rs`).
//!
//! A period did not parse as a date, so no filter was added and every
//! member was selected, silently: `x -tn7d` wrote the whole archive.
//! MEASURED against unrar 7.23 on macOS (arm64), 4 Oct 2026, over members
//! 6 years, 3 days, 2 hours and a moment old:
//!
//! - `-tn7d` lists the three younger than a week, `-to7d` the old one;
//! - the units are `d`, `h`, `m` and `s` in either case, each with its
//!   number before it, and they ADD in any order (`-tn1d2h` and `-tn2h1d`
//!   alike; `-tn1h1h1h` is three hours);
//! - a character that is no digit and no unit is stepped over and drops
//!   the number before it (`-tnx7d` is seven days, `-tn1x1h` one hour),
//!   and a number with no unit after it counts for nothing;
//! - so `-tn20250101` is a period of ZERO, not a date: it selects nothing
//!   that already exists, and `-to` with no period selects everything.
//!   Dates belong to `-ta` and `-tb`.
//!
//! Each run states `-mt1`; the archive is four small members, so no
//! memory to speak of.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use rarkit::{HostOs, MemberSpec, Payload, Timestamp, WriteOptions, Writer};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

const HOUR: i64 = 3600;
const DAY: i64 = 24 * HOUR;

/// `old.txt` (1 Jan 2020), `d3.txt` (3 days old), `mid.txt` (2 hours old)
/// and `new.txt` (a minute old), in that order.
fn archive(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-switches-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let mut writer = Writer::new(WriteOptions::default()).expect("options");
    for (name, at) in [
        ("old.txt", 1_577_836_800),
        ("d3.txt", now - 3 * DAY),
        ("mid.txt", now - 2 * HOUR),
        ("new.txt", now - 60),
    ] {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(name.as_bytes()),
                mtime: Some(Timestamp {
                    unix_seconds: at,
                    nanos: 0,
                }),
                attributes: 0o100_644,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    let path = dir.join("a.rar");
    std::fs::write(&path, out).unwrap();
    path
}

fn run(archive: &Path, command: &str, switch: &std::ffi::OsStr) -> Output {
    Command::new(rarfast())
        .args([command, "-mt1"])
        .arg(switch)
        .arg(archive)
        .output()
        .unwrap()
}

fn listed(archive: &Path, switch: &str) -> Vec<String> {
    let done = run(archive, "lb", switch.as_ref());
    assert_eq!(done.status.code(), Some(0), "{switch}: {done:?}");
    String::from_utf8_lossy(&done.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn tn_and_to_filter_on_a_period_back_from_now() {
    let archive = archive("periods");
    let young = ["d3.txt", "mid.txt", "new.txt"];
    let all = ["old.txt", "d3.txt", "mid.txt", "new.txt"];
    let none: [&str; 0] = [];
    for (switch, expected) in [
        ("-tn7d", &young[..]),
        ("-to7d", &["old.txt"][..]),
        ("-tn4d", &young),
        ("-tn2d23h", &["mid.txt", "new.txt"]),
        ("-tn3d1h", &young),
        ("-tn3h", &["mid.txt", "new.txt"]),
        ("-tn1h", &["new.txt"]),
        ("-to1h", &["old.txt", "d3.txt", "mid.txt"]),
        ("-tn1h30m", &["new.txt"]),
        ("-tn90m", &["new.txt"]),
        ("-tn1d2h", &["mid.txt", "new.txt"]),
        ("-tn2h1d", &["mid.txt", "new.txt"]),
        ("-tn1D", &["mid.txt", "new.txt"]),
        ("-tn1h1h1h", &["mid.txt", "new.txt"]),
        ("-tnx7d", &young),
        ("-tn1x1h", &["new.txt"]),
        ("-tn1d1", &["mid.txt", "new.txt"]),
        ("-tn99999999999999999999d", &all),
        ("-tn7dx", &young),
        ("-tnm7d", &young),
        // No unit, so no period: nothing is newer than now, everything
        // is older.
        ("-tn20250101", &none[..]),
        ("-tn7x", &none),
        ("-tn", &none),
        ("-to", &all),
        // A date is `-ta` and `-tb`'s, as it was.
        ("-ta20250101", &young),
        ("-tb20250101", &["old.txt"]),
    ] {
        assert_eq!(listed(&archive, switch), expected, "{switch}");
    }
    let _ = std::fs::remove_dir_all(archive.parent().unwrap());
}

/// The scenario as reported: `x -tn7d` is meant to leave the old file in
/// the archive, and wrote every member.
#[test]
fn x_under_tn_writes_only_the_members_inside_the_period() {
    let archive = archive("extract");
    let out = archive.parent().unwrap().join("o");
    std::fs::create_dir_all(&out).unwrap();
    let done = Command::new(rarfast())
        .args(["x", "-mt1", "-idq", "-tn7d"])
        .arg(&archive)
        .arg(format!("{}/", out.display()))
        .output()
        .unwrap();
    assert_eq!(done.status.code(), Some(0), "{done:?}");
    let mut found: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    found.sort();
    assert_eq!(found, ["d3.txt", "mid.txt", "new.txt"]);
    let _ = std::fs::remove_dir_all(archive.parent().unwrap());
}
