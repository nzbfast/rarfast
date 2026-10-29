//! A create switch is honoured, or refused by name: never read and dropped.
//!
//! Until 8 Oct 2026 a create read `-oh -ow -oi -ts* -tl -ag -ai -am
//! -log*` and wrote the archive it would have written without them, exit
//! 0, and it accepted spellings rar 7.23 calls `Unknown option` (`-os
//! -oc -st` and the rest of three catch-all arms).
//!
//! **Measured against rar 7.23 on 8 Oct 2026** (an Apple silicon Mac),
//! and what rarfast does with each now:
//!
//! | switch                      | the reference                              | rarfast   |
//! |-----------------------------|--------------------------------------------|-----------|
//! | `-tl`                       | archive (each volume) dated by its newest member | honoured |
//! | `-ts-`, `-tsm-`             | no mtime stored                            | honoured  |
//! | `-tsm -tsm+ -tsm4 -tsc- -tsa-` | the bytes it writes without them        | honoured  |
//! | `-ai`                       | modes `rw-rw-rw-` and `rwxrwxrwx` stored   | honoured  |
//! | `-ag`                       | `f<YYYYMMDDHHMMSS>.rar`                    | honoured  |
//! | `-ag<Y M D H S and _ - .>`  | the date in that form                      | honoured  |
//! | `-oi0`, `-oi-`              | the bytes it writes without them           | honoured  |
//! | `-ag` with `N A W E {} +`   | a number, a day of year, a week, text      | refused   |
//! | `-ts -ts+ -ts<n> -tsc -tsa` | creation and access times stored           | refused   |
//! | `-tsm<0..3>`, `-tsp`        | a coarser mtime; sources' access time kept | refused   |
//! | `-oh`, `-oh-`               | a hard link stored as a link               | refused   |
//! | `-ow`, `-ow-`               | owner and group stored                     | refused   |
//! | `-oi`, `-oi<1..4>`          | identical files stored as references       | refused   |
//! | `-am -ams -amr`             | the archive's name and time recorded       | refused   |
//! | `-log -logf=<name>`         | the names written to a file                | refused   |
//! | `-os -oc -oni -om -st -sa -sc -f+ -u1 -md` | `Unknown option`, exit 7    | the same  |
//!
//! A refusal names the switch, exits 7 (the reference's code for a
//! command line it will not run), and comes before anything is read,
//! written or deleted.
//!
//! Every run is `-mt2` over files of at most 200,000 bytes: a pool two
//! threads wide and a few MiB of memory.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// 11 Apr 2021 and 5 May 2022, as seconds.
const OLDER: u64 = 1_618_142_400;
const NEWER: u64 = 1_651_755_600;

fn dated(path: &Path, seconds: u64) {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    file.set_modified(UNIX_EPOCH + Duration::from_secs(seconds))
        .unwrap();
}

/// A directory of one test's own, made afresh under the system's
/// temporary directory, holding the tree `s`: `s/a.txt` (4 bytes, mode
/// 600, dated `OLDER`), `s/r.bin` (200,000 bytes of noise, mode 755,
/// dated `NEWER`) and `s` itself, dated a day before `OLDER`.
fn work(tag: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = std::env::temp_dir().join(format!("rarfast-silent-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("s")).unwrap();
    std::fs::write(dir.join("s/a.txt"), b"aaa\n").unwrap();
    let noise: Vec<u8> = (0..200_000_u32)
        .map(|n| (n.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    std::fs::write(dir.join("s/r.bin"), noise).unwrap();
    std::fs::set_permissions(dir.join("s/a.txt"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(dir.join("s/r.bin"), std::fs::Permissions::from_mode(0o755)).unwrap();
    dated(&dir.join("s/a.txt"), OLDER);
    dated(&dir.join("s/r.bin"), NEWER);
    dated(&dir.join("s"), OLDER - 86_400);
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(rarfast())
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|err| panic!("rarfast could not be run: {err}"))
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A create that must succeed, quietly.
fn create(dir: &Path, switches: &[&str], archive: &str) {
    let mut args = vec!["a", "-idq", "-mt2", "-m0", "-r"];
    args.extend_from_slice(switches);
    args.extend_from_slice(&[archive, "s"]);
    let out = run(dir, &args);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{switches:?}: {}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
}

/// The technical listing of an archive.
fn listing(dir: &Path, archive: &str) -> String {
    text(&run(dir, &["lt", archive]).stdout)
}

fn modified(path: &Path) -> SystemTime {
    std::fs::metadata(path).unwrap().modified().unwrap()
}

/// Nothing was written and nothing was taken.
fn untouched(dir: &Path, what: &str) {
    let left: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, ["s"], "{what} left something beside the sources");
    assert!(dir.join("s/a.txt").is_file(), "{what} took s/a.txt");
    assert!(dir.join("s/r.bin").is_file(), "{what} took s/r.bin");
}

/// Every switch a create reads and cannot act on, as typed.
const REFUSED: [&str; 27] = [
    "-oh",
    "-oh-",
    "-ow",
    "-ow-",
    "-oi",
    "-oi1",
    "-oi4:100",
    "-ts",
    "-ts+",
    "-ts1",
    "-tsc",
    "-tsa",
    "-tsc0",
    "-tsp",
    "-tsm0",
    "-tsm1",
    "-tsm3",
    "-am",
    "-ams",
    "-amr",
    "-log",
    "-logf=names.lst",
    "-agNNN",
    "-agYYYYA",
    "-agW",
    "-ag{t}YYYY",
    "-ag+YYYY",
];

/// The spellings rar 7.23 answers `Unknown option` for on a unix host.
const UNKNOWN: [&str; 14] = [
    "-os", "-os-", "-oc", "-oc-", "-oni", "-om", "-ox", "-st", "-st0", "-sa", "-sc", "-f+", "-u1",
    "-md",
];

#[test]
fn each_switch_a_create_cannot_act_on_exits_7_naming_it() {
    for command in ["a", "m"] {
        for (at, switch) in REFUSED.iter().enumerate() {
            let dir = work(&format!("refused-{command}{at}"));
            let out = run(&dir, &[command, "-mt2", "-r", switch, "f.rar", "s"]);
            let (said, warned) = (text(&out.stdout), text(&out.stderr));
            assert_eq!(
                out.status.code(),
                Some(7),
                "`{command} {switch}` was not refused; stdout: {said} stderr: {warned}"
            );
            assert!(
                warned.contains(&format!("`{switch}`")),
                "`{command} {switch}`: the refusal does not name the switch: {warned}"
            );
            untouched(&dir, &format!("{command} {switch}"));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

#[test]
fn a_switch_the_reference_does_not_know_is_an_unknown_option() {
    for command in ["a", "m"] {
        for (at, switch) in UNKNOWN.iter().enumerate() {
            let dir = work(&format!("unknown-{command}{at}"));
            let out = run(&dir, &[command, "-mt2", "-r", switch, "f.rar", "s"]);
            let said = text(&out.stdout);
            assert_eq!(out.status.code(), Some(7), "`{command} {switch}`: {said}");
            assert!(
                said.contains(&format!("ERROR: Unknown option: {}", &switch[1..])),
                "`{command} {switch}`: {said}"
            );
            untouched(&dir, &format!("{command} {switch}"));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

/// `-tl`: measured, the archive, and each volume of a set, carries the
/// time of its newest member.
#[test]
fn tl_dates_the_archive_by_its_newest_member() {
    let dir = work("tl");
    let newest = UNIX_EPOCH + Duration::from_secs(NEWER);
    create(&dir, &[], "plain.rar");
    assert_ne!(modified(&dir.join("plain.rar")), newest);
    create(&dir, &["-tl"], "one.rar");
    assert_eq!(modified(&dir.join("one.rar")), newest);
    create(&dir, &["-tl", "-v100k"], "set.rar");
    let volumes: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.to_string_lossy().contains("set.part"))
        .collect();
    assert!(volumes.len() >= 2, "{volumes:?}");
    for volume in volumes {
        assert_eq!(modified(&volume), newest, "{}", volume.display());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `-ts-` and `-tsm-` store no modification time. `-tsm` in each of its
/// spellings, and the forms a create has nothing to do for, write the
/// bytes that no switch writes; of two forms the later one stands.
#[test]
fn the_mtime_forms_of_ts_are_honoured() {
    let dir = work("ts");
    create(&dir, &[], "plain.rar");
    let plain = std::fs::read(dir.join("plain.rar")).unwrap();
    assert_eq!(listing(&dir, "plain.rar").matches("mtime:").count(), 3);
    for switch in ["-ts-", "-tsm-"] {
        let _ = std::fs::remove_file(dir.join("none.rar"));
        create(&dir, &[switch], "none.rar");
        let listed = listing(&dir, "none.rar");
        assert_eq!(listed.matches("mtime:").count(), 0, "{switch}: {listed}");
        assert_eq!(listed.matches("Name:").count(), 3, "{switch}: {listed}");
    }
    for switch in ["-tsm", "-tsm+", "-tsm4", "-tsc-", "-tsa-", "-oi0", "-oi-"] {
        let _ = std::fs::remove_file(dir.join("same.rar"));
        create(&dir, &[switch], "same.rar");
        assert!(
            std::fs::read(dir.join("same.rar")).unwrap() == plain,
            "{switch} changed the archive"
        );
    }
    // The last form on the line is the one that stands.
    create(&dir, &["-ts-", "-tsm"], "back.rar");
    assert!(std::fs::read(dir.join("back.rar")).unwrap() == plain);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `-ai`: measured, every file is stored `rw-rw-rw-` and every directory
/// `rwxrwxrwx`, whatever its mode on disk.
#[test]
fn ai_stores_the_default_modes() {
    let dir = work("ai");
    create(&dir, &[], "plain.rar");
    let plain = listing(&dir, "plain.rar");
    assert!(plain.contains("-rw-------"), "{plain}");
    assert!(plain.contains("-rwxr-xr-x"), "{plain}");
    create(&dir, &["-ai"], "ai.rar");
    let listed = listing(&dir, "ai.rar");
    assert_eq!(listed.matches("-rw-rw-rw-").count(), 2, "{listed}");
    assert_eq!(listed.matches("drwxrwxrwx").count(), 1, "{listed}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The one file beside `s`, which is the archive a run wrote.
fn written(dir: &Path) -> String {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name != "s")
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");
    names.remove(0)
}

/// `-ag` with no form: measured, `f.rar` becomes `f<YYYYMMDDHHMMSS>.rar`.
#[test]
fn ag_names_the_archive_from_the_clock() {
    let dir = work("ag");
    create(&dir, &["-ag"], "f.rar");
    let name = written(&dir);
    let stamp = name
        .strip_prefix('f')
        .and_then(|rest| rest.strip_suffix(".rar"))
        .unwrap_or_else(|| panic!("{name}"));
    assert_eq!(stamp.len(), 14, "{name}");
    assert!(stamp.bytes().all(|byte| byte.is_ascii_digit()), "{name}");
    assert!(stamp.starts_with("20"), "{name}");
    std::fs::remove_file(dir.join(&name)).unwrap();

    create(&dir, &["-agYYYY-MM-DD_"], "f.rar");
    let name = written(&dir);
    let bytes = name.as_bytes();
    assert_eq!(name.len(), "f2026-10-08_.rar".len(), "{name}");
    assert!(name.starts_with("f20") && name.ends_with("_.rar"), "{name}");
    assert_eq!((bytes[5], bytes[8]), (b'-', b'-'), "{name}");
    let _ = std::fs::remove_dir_all(&dir);
}
