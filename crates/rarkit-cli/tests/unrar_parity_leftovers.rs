//! Four output-parity leftovers against reference unrar 7.23 (README
//! section 8), every
//! cell measured first and then matched:
//!
//! 1. An archive refused BEFORE any member: a RAR 5 `-hp` archive or
//!    volume set given a wrong password (`Incorrect password for
//!    <archive>`, then `Total errors: 1`); a RAR 1.5 to 4.x `-hp` archive,
//!    which carries no password check, whose first enciphered header
//!    fails, right password or wrong (`Checksum error in the encrypted
//!    file <archive>. Corrupt file or wrong password.`, no banner, `No
//!    files to extract`, exit 3), and the same sentence in place of
//!    `Corrupt header is found` for a LATER header of such an archive; an
//!    archive that is not there. The layout is `Out::refused`'s: apart,
//!    the closing line goes to stdout after a blank line and stderr is
//!    left unended; on one stream (`-ierr`) the message ends itself; where
//!    the stdout messages are dropped (`-idq`, `p`) stderr ends with one
//!    newline. The last rule holds after a walk too, and is the README's
//!    `-idq` item, closed here.
//! 2. `p` over a volume set prints ONE banner, the first volume's, and a
//!    member's lines in later volumes take the `t` and `x` form,
//!    `...         <name>` padded and the counter, not `------ ...
//!    <name>` headings under later banners. With it: a later volume's
//!    banner under `x` is printed by the member continuing into it, where
//!    the concurrent walk had it printed by the next member's `open`.
//! 3. (The engine's half, `rarkit/tests/fragment_mismatch.rs`: a skipped
//!    member hears nothing, SPEC-API 4.4.)
//! 4. A member refused for its window under the DEFAULT memory policy:
//!    no progress line, the reason where the line would have been, as the
//!    reference prints a member it refuses (the every-refused-member
//!    measurement), and no file.
//!
//! Items 1 and 2 are held to reference unrar's own bytes, recorded by
//! `tests/parity-leftovers/capture.py` into `cells.rs` (173 cells: `t`,
//! `x`, `p`; plain, `-idq`, `-ierr`, and for item 1 `-idd`, `-inul`;
//! rar 7.23 and rar 4.20 archives, single and volume sets, stored,
//! compressed and enciphered, both volume naming schemes). One difference
//! is kept and named in [`STANDING_DIFFERENCES`].

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

enum Stdout {
    Text(&'static [u8]),
    /// `p`'s stdout is the payload: its length and CRC32.
    Payload {
        len: usize,
        crc: u32,
    },
}

/// One run of the reference as `capture.py` recorded it: what was run and
/// what it answered.
struct Capture {
    group: &'static str,
    command: &'static str,
    switches: &'static [&'static str],
    select: &'static [&'static str],
    exit: i32,
    stdout: Stdout,
    stderr: &'static [u8],
    left: &'static [(&'static str, u64)],
}

include!("parity-leftovers/cells.rs");

/// A difference from the reference that stands for now, in every capture
/// of one group and selection: (group, selection, the bytes rarfast
/// prints, the reference's bytes there). The run's output has the first
/// exchanged for the second before it is compared.
type StandingDifference = (
    &'static str,
    &'static [&'static str],
    &'static [u8],
    &'static [u8],
);

/// The differences that stand. None does today; the table stays so that
/// the next one is written down here and not in the comparison.
const STANDING_DIFFERENCES: &[StandingDifference] = &[];

/// The counter's value is the progress code's, and differs by one or two
/// on volumes this small (a split member's header weighs more against a
/// 4 KB volume than the reference's count lets it; open there with the
/// other tiny-archive rows of README section 8), and before a damaged
/// header (`r420_dmg`: `100%` where the reference reads ` 30%`, having
/// counted to where its walk stopped). This file holds the layout, so
/// every counter reads `NNN%` on both sides.
fn masked(text: &[u8]) -> Vec<u8> {
    const MARK: &[u8] = b"\x08\x08\x08\x08";
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        let rest = &text[i..];
        if rest.starts_with(MARK)
            && rest.len() >= MARK.len() + 4
            && rest[MARK.len() + 3] == b'%'
            && rest[MARK.len()..MARK.len() + 3]
                .iter()
                .all(|b| *b == b' ' || b.is_ascii_digit())
        {
            out.extend_from_slice(MARK);
            out.extend_from_slice(b"NNN%");
            i += MARK.len() + 4;
        } else {
            out.push(text[i]);
            i += 1;
        }
    }
    out
}

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn vec(name: &str) -> PathBuf {
    root().join("specs/vectors-G/archives").join(name)
}

fn here(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/parity-leftovers")
        .join(name)
}

fn parts(stem: &str, n: usize, at: fn(&str) -> PathBuf) -> Vec<PathBuf> {
    (1..=n)
        .map(|i| at(&format!("{stem}.part{i}.rar")))
        .collect()
}

/// A group's archives, its password switch and the archive argument, as
/// `capture.py`'s `SETS` has them.
fn group(name: &str) -> (Vec<PathBuf>, Option<&'static str>, &'static str) {
    match name {
        "r5_hpw" => (
            vec!["r5_hpw.rar"].into_iter().map(vec).collect(),
            Some("-pwrong"),
            "r5_hpw.rar",
        ),
        "hv" => (parts("hv", 3, here), Some("-pwrong"), "hv.part1.rar"),
        "r4_hpw" => (vec![vec("r4_hpw.rar")], Some("-pwrong"), "r4_hpw.rar"),
        "r420_hp" => (vec![legacy_hp()], Some("-pwrong"), "r420_hp.rar"),
        // Made by `stage`.
        "r420_dmg" => (Vec::new(), Some("-pSecret"), "r420_dmg.rar"),
        "missing" => (Vec::new(), None, "nosuch.rar"),
        "two" => (parts("two", 4, here), None, "two.part1.rar"),
        "twoc" => (parts("twoc", 4, here), None, "twoc.part1.rar"),
        "twop" => (parts("twop", 4, here), Some("-psecret"), "twop.part1.rar"),
        "r5_vol" => (parts("r5_vol", 4, vec), None, "r5_vol.part1.rar"),
        "r4_vol" => (parts("r4_vol", 3, vec), None, "r4_vol.part1.rar"),
        "r4_volvn" => (
            ["r4_volvn.rar", "r4_volvn.r00", "r4_volvn.r01"]
                .into_iter()
                .map(vec)
                .collect(),
            None,
            "r4_volvn.rar",
        ),
        "r4_pwvol" => (
            parts("r4_pwvol", 3, vec),
            Some("-pSecret"),
            "r4_pwvol.part1.rar",
        ),
        other => panic!("no group {other}"),
    }
}

fn legacy_hp() -> PathBuf {
    root().join("fixtures/legacy/archives/r420_hp.rar")
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-leftovers-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Copies a group's archives into `dir` under their own names; for
/// `r420_dmg`, rar 4.20's `-hp` archive with one byte of its second
/// member's enciphered header inverted, as `capture.py`'s `DAMAGE`.
fn stage(dir: &Path, name: &str) {
    let (files, _, _) = group(name);
    for file in files {
        std::fs::copy(&file, dir.join(file.file_name().unwrap()))
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
    if name == "r420_dmg" {
        let mut bytes = std::fs::read(legacy_hp()).unwrap();
        bytes[21290] ^= 0x55;
        std::fs::write(dir.join("r420_dmg.rar"), bytes).unwrap();
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

fn files_under(top: &Path) -> Vec<(String, u64)> {
    let mut found = Vec::new();
    let mut dirs = vec![top.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                let rel = path
                    .strip_prefix(top)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                found.push((rel, std::fs::metadata(&path).unwrap().len()));
            }
        }
    }
    found.sort();
    found
}

fn shown(bytes: &[u8]) -> String {
    format!("{:?}", String::from_utf8_lossy(bytes))
}

fn replace(text: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if text[i..].starts_with(from) {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(text[i]);
            i += 1;
        }
    }
    out
}

/// Every recorded cell, rarfast against the reference's bytes; the
/// mismatches are collected and reported together.
#[test]
fn every_measured_cell_prints_what_the_reference_prints() {
    let mut wrong = Vec::new();
    for (turn, cell) in CAPTURES.iter().enumerate() {
        let dir = work(&format!("cell{turn}"));
        stage(&dir, cell.group);
        let (_, password, archive) = group(cell.group);
        let mut args: Vec<&str> = vec![cell.command];
        args.extend(password);
        args.extend(cell.switches);
        args.push(archive);
        args.extend(cell.select);
        if cell.command == "x" {
            args.push("out/");
        }
        let ran = Command::new(rarfast())
            .current_dir(&dir)
            .args(&args)
            .output()
            .unwrap();
        let mut stdout = masked(&ran.stdout);
        let mut stderr = masked(&ran.stderr);
        for &(group, select, from, to) in STANDING_DIFFERENCES {
            if group == cell.group && select == cell.select {
                stdout = replace(&stdout, from, to);
                stderr = replace(&stderr, from, to);
            }
        }
        let what = format!("{} {}", cell.group, args.join(" "));
        if ran.status.code() != Some(cell.exit) {
            wrong.push(format!(
                "{what}: exit {:?}, reference {}",
                ran.status.code(),
                cell.exit
            ));
        }
        match cell.stdout {
            Stdout::Text(want) if stdout != masked(want) => wrong.push(format!(
                "{what}: stdout {}\n    reference {}",
                shown(&stdout),
                shown(want)
            )),
            // The payload is compared whole, unmasked.
            Stdout::Payload { len, crc }
                if ran.stdout.len() != len || crc32(&ran.stdout) != crc =>
            {
                wrong.push(format!(
                    "{what}: payload of {} bytes, reference {len}",
                    ran.stdout.len()
                ))
            }
            _ => {}
        }
        if stderr != masked(cell.stderr) {
            wrong.push(format!(
                "{what}: stderr {}\n    reference {}",
                shown(&stderr),
                shown(cell.stderr)
            ));
        }
        let left = files_under(&dir.join("out"));
        let want: Vec<(String, u64)> = cell.left.iter().map(|&(p, n)| (p.to_owned(), n)).collect();
        if left != want {
            wrong.push(format!("{what}: left {left:?}, reference {want:?}"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    assert!(
        wrong.is_empty(),
        "{} of {} captures do not match the reference:\n{}",
        wrong.len(),
        CAPTURES.len(),
        wrong.join("\n")
    );
}

/// Item 4. `window.rar` is a solid pair whose window is above 4 GiB, which
/// rarkit's default policy refuses on every machine (its ceiling is half
/// of physical memory, at most 4 GiB). The reference, which has
/// no such ceiling, extracts it, so the target is its layout for a member
/// it REFUSES (an unknown method, measured 28 Sep 2026 in the
/// every-refused-member work): no progress line, the reason on stderr
/// where the line would have been, and no file. Before this, rarfast
/// opened the line with the archive's percentage and closed it failed.
#[test]
fn a_member_refused_for_its_window_prints_no_line_of_its_own() {
    // The window the engine sizes for the solid stream (4,480 MiB, over
    // rar's recorded -md=4608m for 4,400 MiB of zeros and one more
    // member), and this machine's default allowance, which is what
    // rarfast reads under with no `-mm`.
    let reason = format!(
        "Window wanted 4697620480 bytes and the policy allows {}",
        rarkit::MemoryPolicy::process_default(0).max_window
    );
    for (cmd, banner) in [
        ("t", "Testing archive"),
        ("x", "Extracting from"),
        ("p", "Extracting from"),
    ] {
        for width in ["-mt1", "-mt4"] {
            // (switch, stdout, stderr); `p`'s stdout is its payload and
            // has none here.
            let cells: [(Option<&str>, String, String); 3] = [
                (
                    None,
                    if cmd == "p" {
                        String::new()
                    } else {
                        format!("\n{banner} window.rar\n\nTotal errors: 1\n")
                    },
                    if cmd == "p" {
                        format!("\n{reason}\n")
                    } else {
                        format!("\n{reason}")
                    },
                ),
                (
                    Some("-ierr"),
                    String::new(),
                    format!("\n{banner} window.rar\n\n{reason}\nTotal errors: 1\n"),
                ),
                (Some("-idq"), String::new(), format!("\n{reason}\n")),
            ];
            for (switch, stdout, stderr) in cells {
                let dir = work(&format!("window-{cmd}{width}{switch:?}"));
                std::fs::copy(here("window.rar"), dir.join("window.rar")).unwrap();
                let mut args = vec![cmd, width];
                args.extend(switch);
                args.push("window.rar");
                if cmd == "x" {
                    args.push("out/");
                }
                let ran = Command::new(rarfast())
                    .current_dir(&dir)
                    .args(&args)
                    .output()
                    .unwrap();
                let what = args.join(" ");
                assert_eq!(ran.status.code(), Some(2), "{what}");
                assert_eq!(String::from_utf8_lossy(&ran.stdout), stdout, "{what}");
                assert_eq!(String::from_utf8_lossy(&ran.stderr), stderr, "{what}");
                assert_eq!(
                    files_under(&dir.join("out")),
                    Vec::new(),
                    "{what}: a file left"
                );
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }
}

/// Item 4's other side: a member whose DECLARED dictionary is above the
/// window ceiling but whose own window fits has its line held
/// only until it is known not to be refused, and prints exactly what it
/// prints without the ceiling. `-mm700m` allows a 350 MiB window;
/// `dict512m.rar` declares 512 MiB and its one member needs 300,000,000
/// bytes.
#[test]
fn a_held_line_is_said_when_the_member_is_not_refused() {
    let archive = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/large-dictionary/dict512m.rar");
    let dir = work("held");
    std::fs::copy(&archive, dir.join("dict512m.rar")).unwrap();
    for switch in [None, Some("-ierr")] {
        let run = |cap: Option<&str>| {
            let mut args = vec!["t", "-mt1"];
            args.extend(cap);
            args.extend(switch);
            args.push("dict512m.rar");
            Command::new(rarfast())
                .current_dir(&dir)
                .args(&args)
                .output()
                .unwrap()
        };
        let free = run(None);
        let capped = run(Some("-mm700m"));
        assert_eq!(
            capped.status.code(),
            Some(0),
            "{switch:?}: {}",
            String::from_utf8_lossy(&capped.stderr)
        );
        assert_eq!(capped.stdout, free.stdout, "{switch:?}");
        assert_eq!(capped.stderr, free.stderr, "{switch:?}");
        let said = String::from_utf8_lossy(if switch.is_some() {
            &capped.stderr
        } else {
            &capped.stdout
        })
        .into_owned();
        assert!(
            said.contains("Testing     src/zeros"),
            "{switch:?}: {said:?}"
        );
        assert!(said.ends_with("  OK \nAll OK\n"), "{switch:?}: {said:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
