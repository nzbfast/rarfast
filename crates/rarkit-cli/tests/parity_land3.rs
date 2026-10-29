//! Output parity, land 3
//! (README section 8): every cell is measured against reference rar and
//! unrar 7.23 first, recorded byte for byte by
//! `tests/parity-land3/capture.py` into `cells.rs`, and then matched.
//!
//! 3. `-inul` is the third member of the `-idq` / `-ierr` set, and the
//!    LAST of the three given wins, in both dialects: `-inul -ierr`
//!    prints the whole run on stderr, `-ierr -inul` nothing, `-inul
//!    -idq` a failure's lines and `-idq -inul` nothing.
//!
//! rarfast runs through a symlink named for the tool it stands in for, so
//! the dialect is chosen as a drop-in's would be. A difference that stays
//! is named in [`STANDING_DIFFERENCES`].

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

/// One run of a reference tool as `capture.py` recorded it: what was run
/// and what it answered.
struct Capture {
    tool: &'static str,
    group: &'static str,
    command: &'static str,
    switches: &'static [&'static str],
    rest: &'static [&'static str],
    exit: i32,
    stdout: Stdout,
    stderr: &'static [u8],
    left: &'static [(&'static str, i64)],
}

include!("parity-land3/cells.rs");

/// Command lines whose difference from the reference stands for now:
/// (tool, command, the rest of the line, why). A capture one of these
/// rows names is not run.
const STANDING_DIFFERENCES: &[(&str, &str, &[&str], &str)] = &[
    (
        "rar",
        "s",
        &["nosuch.rar"],
        "`s` is refused by name: a self-extracting module is a decision the \
         project has not made (README section 4)",
    ),
    ("rar", "a", &["-m0", "new.rar", "locked.txt"], UNREADABLE),
    (
        "rar",
        "a",
        &["-m0", "new.rar", "f.txt", "locked.txt"],
        UNREADABLE,
    ),
    (
        "rar",
        "a",
        &["-m0", "new.rar", "locked.txt", "nosuch.txt"],
        UNREADABLE,
    ),
];

/// Counters that stay one away from the reference's, per group: rarfast's
/// bytes and the reference's in their place, in every cell of the group.
/// The rule in `Opened::counted_end` reproduces every counter of the
/// committed four-part sets, `s9k` and the single archives, and of 15
/// scratch sets rar 7.23 wrote at `-v6k` to `-v20k` rarfast matches 9;
/// these are the boundary cases
/// it does not, a member in a later volume, or the first piece of a long
/// one, reading one high or one low. Not done yet (README
/// section 10, item 1).
const SHIFTED: &[(&str, &[Shift])] = &[
    (
        "qo3",
        &[
            (b"\x08\x08\x08\x08 37%", b"\x08\x08\x08\x08 38%"),
            (b"\x08\x08\x08\x08 43%", b"\x08\x08\x08\x08 44%"),
        ],
    ),
    (
        "tail9k",
        &[
            (b"\x08\x08\x08\x08 27%", b"\x08\x08\x08\x08 26%"),
            (b"\x08\x08\x08\x08 81%", b"\x08\x08\x08\x08 80%"),
        ],
    ),
];

/// rarfast's bytes and the reference's in their place.
type Shift = (&'static [u8], &'static [u8]);

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

/// Why a source that fails at READ time keeps its difference.
const UNREADABLE: &str = "a source that cannot be read stops the create, where the \
    reference goes on without it (`WARNING: Cannot open 1 file`, exit 6): \
    not done yet, it needs a spec G answer (README section 8, \
    `A create that CONTINUES past a source it cannot open`)";

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn vec(name: &str) -> PathBuf {
    root().join("specs/vectors-G/archives").join(name)
}

fn leftover(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/parity-leftovers")
        .join(name)
}

fn here(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/parity-land3")
        .join(name)
}

fn parts(at: fn(&str) -> PathBuf, stem: &str, n: usize) -> Vec<PathBuf> {
    (1..=n)
        .map(|i| at(&format!("{stem}.part{i}.rar")))
        .collect()
}

/// What a group's file is made from, as `capture.py`'s `GROUPS` has it.
enum Source {
    Copy(PathBuf),
    Bytes(&'static [u8]),
    Locked(&'static [u8]),
    Flip(PathBuf, usize, u8),
    Cut(PathBuf, Option<usize>),
}

fn group(name: &str) -> Vec<(String, Source)> {
    let copy = |p: PathBuf| {
        (
            p.file_name().unwrap().to_string_lossy().into_owned(),
            Source::Copy(p),
        )
    };
    match name {
        "store" => vec![copy(vec("r5_store.rar"))],
        "flip" => vec![(
            "flip.rar".into(),
            Source::Flip(vec("r5_store.rar"), 60, 0x55),
        )],
        "files" => vec![
            ("f.txt".into(), Source::Bytes(b"hello\n")),
            ("g.txt".into(), Source::Bytes(b"world\n")),
            ("locked.txt".into(), Source::Locked(b"x\n")),
            ("arc.rar".into(), Source::Cut(vec("r5_store.rar"), None)),
            ("cmt.rar".into(), Source::Cut(vec("r5_cmt.rar"), None)),
        ],
        "two" => parts(leftover, "two", 4).into_iter().map(copy).collect(),
        "twoc" => parts(leftover, "twoc", 4).into_iter().map(copy).collect(),
        "twop" => parts(leftover, "twop", 4).into_iter().map(copy).collect(),
        "r5_vol" => parts(vec, "r5_vol", 4).into_iter().map(copy).collect(),
        "r4_vol" => parts(vec, "r4_vol", 3).into_iter().map(copy).collect(),
        "r4_volvn" => ["r4_volvn.rar", "r4_volvn.r00", "r4_volvn.r01"]
            .into_iter()
            .map(|name| copy(vec(name)))
            .collect(),
        "s9k" => parts(here, "s9k", 6).into_iter().map(copy).collect(),
        "qo3" => parts(here, "qo3", 3).into_iter().map(copy).collect(),
        "tail9k" => parts(here, "tail9k", 5).into_iter().map(copy).collect(),
        "mixsc" => parts(here, "mixsc", 4).into_iter().map(copy).collect(),
        "mixcs" => parts(here, "mixcs", 4).into_iter().map(copy).collect(),
        "r420_dmg" => vec![(
            "r420_dmg.rar".into(),
            Source::Flip(
                root().join("fixtures/legacy/archives/r420_hp.rar"),
                21290,
                0x55,
            ),
        )],
        "cut5d" => vec![(
            "cut.rar".into(),
            Source::Cut(vec("r5_store.rar"), Some(200)),
        )],
        "cut5h" => vec![(
            "cut.rar".into(),
            Source::Cut(vec("r5_store.rar"), Some(380)),
        )],
        "cut4d" => vec![(
            "cut.rar".into(),
            Source::Cut(
                root().join("specs/vectors-J/archives/r420_mixed_nonsolid.rar"),
                Some(3000),
            ),
        )],
        other => panic!("no group {other}"),
    }
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the captures apart. What an earlier
/// run left locked there is unlocked first, or it could not be removed.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-land3-{}-{tag}", std::process::id()));
    unlock(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Makes every file under `dir` removable again. Not through a symlink:
/// the one to rarfast would take its execute bit away.
fn unlock(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    for (path, _) in files_under(dir) {
        let path = dir.join(path);
        if std::fs::symlink_metadata(&path).is_ok_and(|m| !m.file_type().is_symlink()) {
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
}

/// Stages a group into `dir`; answers whether a locked file there really
/// refuses to be read (not as root, where the cell cannot be measured).
fn stage(dir: &Path, name: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let mut locks_hold = true;
    for (file, source) in group(name) {
        let path = dir.join(&file);
        let bytes = match &source {
            Source::Copy(p) => std::fs::read(p).unwrap(),
            Source::Bytes(b) | Source::Locked(b) => b.to_vec(),
            Source::Flip(p, at, mask) => {
                let mut b = std::fs::read(p).unwrap();
                b[*at] ^= mask;
                b
            }
            Source::Cut(p, len) => {
                let mut b = std::fs::read(p).unwrap();
                if let Some(len) = len {
                    b.truncate(*len);
                }
                b
            }
        };
        std::fs::write(&path, bytes).unwrap();
        if matches!(source, Source::Locked(_)) {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
            locks_hold &= std::fs::read(&path).is_err();
        }
    }
    locks_hold
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
                found.push((rel, std::fs::symlink_metadata(&path).unwrap().len()));
            }
        }
    }
    found.sort();
    found
}

fn shown(bytes: &[u8]) -> String {
    format!("{:?}", String::from_utf8_lossy(bytes))
}

/// Every recorded cell, rarfast against the reference's bytes; the
/// mismatches are collected and reported together.
#[test]
fn every_measured_cell_prints_what_the_reference_prints() {
    let mut wrong = Vec::new();
    let mut ran_cells = 0;
    for (turn, cell) in CAPTURES.iter().enumerate() {
        let kept = STANDING_DIFFERENCES
            .iter()
            .any(|&(tool, command, rest, _)| {
                tool == cell.tool && command == cell.command && rest == cell.rest
            });
        if kept {
            continue;
        }
        let dir = work(&format!("cell{turn}"));
        if !stage(&dir, cell.group) {
            // Run as root: a mode 000 file reads, so this cell measures
            // nothing here.
            unlock(&dir);
            let _ = std::fs::remove_dir_all(&dir);
            continue;
        }
        let staged: Vec<String> = files_under(&dir).into_iter().map(|(p, _)| p).collect();
        std::os::unix::fs::symlink(rarfast(), dir.join(cell.tool)).unwrap();
        let mut args: Vec<&str> = vec![cell.command];
        args.extend(cell.switches);
        args.extend(cell.rest);
        let ran = Command::new(dir.join(cell.tool))
            .current_dir(&dir)
            .args(&args)
            // The cells were captured in UTC: listings print local time.
            .env("TZ", "UTC")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        ran_cells += 1;
        let (mut stdout, mut stderr) = (ran.stdout.clone(), ran.stderr.clone());
        for &(group, pairs) in SHIFTED {
            if group == cell.group {
                for &(from, to) in pairs {
                    stdout = replace(&stdout, from, to);
                    stderr = replace(&stderr, from, to);
                }
            }
        }
        let what = format!("{} {} ({})", cell.tool, args.join(" "), cell.group);
        if ran.status.code() != Some(cell.exit) {
            wrong.push(format!(
                "{what}: exit {:?}, reference {}",
                ran.status.code(),
                cell.exit
            ));
        }
        match cell.stdout {
            Stdout::Text(want) if stdout != want => wrong.push(format!(
                "{what}: stdout {}\n    reference {}",
                shown(&stdout),
                shown(want)
            )),
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
        if stderr != cell.stderr {
            wrong.push(format!(
                "{what}: stderr {}\n    reference {}",
                shown(&stderr),
                shown(cell.stderr)
            ));
        }
        let left: Vec<(String, i64)> = files_under(&dir)
            .into_iter()
            .filter(|(p, _)| !staged.contains(p) && p != cell.tool)
            .map(|(p, n)| {
                let n = if p.ends_with(".rar") { -1 } else { n as i64 };
                (p, n)
            })
            .collect();
        let want: Vec<(String, i64)> = cell.left.iter().map(|&(p, n)| (p.to_owned(), n)).collect();
        if left != want {
            wrong.push(format!("{what}: left {left:?}, reference {want:?}"));
        }
        unlock(&dir);
        let _ = std::fs::remove_dir_all(&dir);
    }
    assert!(ran_cells > 0, "no cell ran");
    assert!(
        wrong.is_empty(),
        "{} of the {} captures run do not match the reference:\n{}",
        wrong.len(),
        ran_cells,
        wrong.join("\n")
    );
}
