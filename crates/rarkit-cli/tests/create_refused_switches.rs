//! A create switch that is parsed and not acted on is refused by name.
//!
//! Until 4 Oct 2026 the creator read a number of selection and naming
//! switches and then ignored them, so the run exited 0 having archived
//! something else: `rarfast m -sl1m small.rar *`, which should move only
//! the files under 1 MiB, archived and then DELETED every file. Each
//! of them is now refused by name before anything is selected, written
//! or deleted; honouring them is later work.
//!
//! **Measured against rar 7.23 on 4 Oct 2026** (an Apple silicon Mac),
//! over `Big.bin` (2,000,000 bytes, new), `Small.txt` (6 bytes, dated
//! 2020) and `sub/Deep.txt`; what the reference archived, where rarfast
//! archived both files under their own names every time:
//!
//! | switch          | the reference's members        |
//! |-----------------|--------------------------------|
//! | `-sl1m`         | `Small.txt`                    |
//! | `-ta20260101`   | `Big.bin`                      |
//! | `-tb20260101`   | `Small.txt`                    |
//! | `-tn1d`         | `Big.bin`                      |
//! | `-to1d`         | `Small.txt`                    |
//! | `-e+d -r sub`   | `sub` alone                    |
//! | `-apdocs`       | `docs/Small.txt`               |
//! | `-ep4sub`       | `Deep.txt` for `sub/Deep.txt`  |
//! | `-cl`           | `big.bin`, `small.txt`         |
//! | `-cu`           | `BIG.BIN`, `SMALL.TXT`         |
//! | `-si`           | one member, `stdin`            |
//! | `-sistream.txt` | one member, `stream.txt`       |
//! | `-f`, no archive| none: `WARNING: No files`, 10  |
//!
//! Two switches the same list named are NOT refused, because no run
//! could be made to differ from the reference:
//!
//! - `-u`: over a name with no archive behind it the reference adds
//!   every file, which is what rarfast does, and over an archive that
//!   exists rarfast already refuses to add at all.
//! - `-ao` on a unix host: the reference adds every file there (no
//!   Archive flag exists to select by). Off a unix host it is refused,
//!   which this file cannot run and does not pin.
//!
//! Every run here is `-mt2` over three files of at most 2,000,000
//! bytes: a pool two threads wide and a few MiB of memory.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// A directory of one test's own, made afresh under the system's
/// temporary directory, with `Big.bin`, `Small.txt` and `sub/Deep.txt` written into it.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-refused-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("Big.bin"), vec![0_u8; 2_000_000]).unwrap();
    std::fs::write(dir.join("Small.txt"), b"small\n").unwrap();
    std::fs::write(dir.join("sub/Deep.txt"), b"deep\n").unwrap();
    dir
}

/// Runs rarfast with nothing on standard input.
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

/// Every switch the creator refuses, as typed.
const REFUSED: [&str; 13] = [
    "-sl1m",
    "-ta20260101",
    "-tb20260101",
    "-tn1d",
    "-to1d",
    "-e+d",
    "-ea",
    "-apdocs",
    "-ep4sub",
    "-cl",
    "-cu",
    "-si",
    "-f",
];

/// One refusal: not exit 0, the switch named, no archive, every source
/// where it was.
fn is_refused(tag: &str, command: &str, switch: &str) {
    let dir = work(tag);
    let out = run(
        &dir,
        &[
            command,
            "-mt2",
            "-r",
            switch,
            "arc.rar",
            "Big.bin",
            "Small.txt",
            "sub",
        ],
    );
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(
        out.status.code(),
        Some(2),
        "`{command} {switch}` was not refused; stdout: {stdout} stderr: {stderr}"
    );
    assert!(
        stderr.contains(&format!("`{switch}`")),
        "`{command} {switch}`: the refusal does not name the switch: {stderr}"
    );
    assert!(
        !dir.join("arc.rar").exists(),
        "`{command} {switch}` wrote an archive"
    );
    for source in ["Big.bin", "Small.txt", "sub/Deep.txt"] {
        assert!(
            dir.join(source).is_file(),
            "`{command} {switch}` took {source}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The scenario the sweep named: the move that deleted everything.
#[test]
fn a_move_refuses_each_unhonoured_switch_and_deletes_nothing() {
    for (at, switch) in REFUSED.iter().enumerate() {
        is_refused(&format!("m{at}"), "m", switch);
    }
}

#[test]
fn an_add_refuses_each_unhonoured_switch_and_writes_nothing() {
    for (at, switch) in REFUSED.iter().enumerate() {
        is_refused(&format!("a{at}"), "a", switch);
    }
}

/// `u` goes through the same door.
#[test]
fn an_update_refuses_them_too() {
    is_refused("u-sl", "u", "-sl1m");
    is_refused("u-f", "u", "-f");
}

/// `-si<name>` with no file mask at all, which used to answer `WARNING:
/// No files` for a reason that had nothing to do with the files.
#[test]
fn si_with_a_member_name_is_turned_down_naming_the_switch() {
    let dir = work("si-name");
    let out = run(&dir, &["a", "-mt2", "-sistream.txt", "arc.rar"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("`-sistream.txt`"), "{stderr}");
    assert!(!dir.join("arc.rar").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The members of `arc.rar`, sorted.
fn members(dir: &Path) -> Vec<String> {
    let listed = run(dir, &["lb", "arc.rar"]);
    let mut names: Vec<String> = text(&listed.stdout).lines().map(str::to_owned).collect();
    names.sort();
    names
}

/// Controls: what the creator DOES honour is still honoured, and the
/// two switches that could not be told from the reference still run.
#[test]
fn honoured_switches_still_run() {
    // `-sm`, the filter the creator does apply.
    let dir = work("sm");
    let out = run(
        &dir,
        &["a", "-mt2", "-sm1m", "arc.rar", "Big.bin", "Small.txt"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(members(&dir), ["Big.bin"]);
    let _ = std::fs::remove_dir_all(&dir);

    // `-u` over no archive adds every file, as the reference does.
    let dir = work("u");
    let out = run(
        &dir,
        &["a", "-mt2", "-u", "arc.rar", "Big.bin", "Small.txt"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(members(&dir), ["Big.bin", "Small.txt"]);
    let _ = std::fs::remove_dir_all(&dir);

    // `-ao` on a unix host adds every file, as the reference does.
    if cfg!(unix) {
        let dir = work("ao");
        let out = run(
            &dir,
            &["a", "-mt2", "-ao", "arc.rar", "Big.bin", "Small.txt"],
        );
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert_eq!(members(&dir), ["Big.bin", "Small.txt"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The refusal is the CREATOR's. The same spellings on a listing are
/// the decoder's filters and keep working.
#[test]
fn a_listing_still_takes_the_same_spellings() {
    let dir = work("list");
    let out = run(&dir, &["a", "-mt2", "arc.rar", "Big.bin", "Small.txt"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let listed = run(&dir, &["lb", "-sl1000000", "arc.rar"]);
    assert_eq!(listed.status.code(), Some(0), "{}", text(&listed.stderr));
    assert_eq!(text(&listed.stdout).trim(), "Small.txt");
    let _ = std::fs::remove_dir_all(&dir);
}
