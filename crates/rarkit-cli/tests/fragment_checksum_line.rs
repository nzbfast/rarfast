//! The reference's `<name> : packed data checksum error in volume <vol>`
//! line for a LEADING fragment whose CRC32 field disagrees with its packed
//! bytes (spec F 3.5.6, the `rarfast` paragraph, answered 29 Sep 2026).
//!
//! Until 30 Sep 2026 `rarfast` failed such a member (`- checksum error`,
//! exit 3) where reference `unrar` 7.23 prints the line and passes it. The
//! field alone disagreeing is a DIAGNOSTIC: the line on stderr, `All OK`,
//! exit 0, the member extracted whole. Measured against `unrar` 7.23 on
//! 30 Sep 2026 over a `-qo-` set (rar writes a quick open record by
//! default, and `unrar` then judges that record's cached copy of the field,
//! so overwriting only the real header shows nothing there: the one
//! difference spec F pins, since rarkit judges the fragment's own header),
//! `t` and `x`, `-m0` and `-m3`, at `-mt1` and the default width, stdout
//! and stderr read apart and together under `-ierr`:
//!
//! - the line is a newline, the ARCHIVED name left justified in 20 columns
//!   (a longer name whole), ` : packed data checksum error in volume `, and
//!   the volume as the banner names it, with no newline after; it follows
//!   that volume's progress line and comes before the next volume's banner;
//! - a member whose whole checksum ALSO fails says `<name> - checksum
//!   error` after its LAST volume's line, and exits 3.
//!
//! **Fixtures.** Written by `rarfast a` from a pinned PRNG, damaged here,
//! so nothing need be on PATH.

use std::path::{Path, PathBuf};
use std::process::Command;

const MEMBER: &str = "a.bin";
const PAYLOAD: usize = 3_000_000;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-fragline-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(dir: &Path, args: &[&str]) -> Ran {
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    Ran {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn payload() -> Vec<u8> {
    let mut x = 0x9E37_79B9_u32;
    (0..PAYLOAD)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// `s.part1.rar` .. `s.partN.rar` in `dir`, one member over at least three
/// volumes, written with `method`.
fn make_set(dir: &Path, method: &str) -> Vec<String> {
    std::fs::write(dir.join(MEMBER), payload()).unwrap();
    let made = run(
        dir,
        &["a", "-ma5", method, "-v1m", "-y", "-idq", "s.rar", MEMBER],
    );
    assert_eq!(made.code, Some(0), "rarfast a: {}", made.stderr);
    std::fs::remove_file(dir.join(MEMBER)).unwrap();
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("s.part"))
        .collect();
    names.sort();
    assert!(names.len() >= 3, "the set is not split: {names:?}");
    names
}

fn vint(bytes: &[u8], at: &mut usize) -> u64 {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let b = bytes[*at];
        *at += 1;
        value |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

/// The volume's first file header: its start, its body, where its data CRC
/// field sits, and its data area.
fn file_head(volume: &[u8]) -> (usize, std::ops::Range<usize>, usize, std::ops::Range<usize>) {
    let mut at = 8;
    loop {
        let start = at;
        let mut p = at + 4;
        let size = vint(volume, &mut p) as usize;
        let body = start + 4..p + size;
        let kind = vint(volume, &mut p);
        let flags = vint(volume, &mut p);
        if flags & 1 != 0 {
            vint(volume, &mut p);
        }
        let data_size = if flags & 2 != 0 {
            vint(volume, &mut p) as usize
        } else {
            0
        };
        let data = body.end..body.end + data_size;
        if kind == 2 {
            let file_flags = vint(volume, &mut p);
            vint(volume, &mut p);
            vint(volume, &mut p);
            if file_flags & 2 != 0 {
                p += 4;
            }
            assert!(file_flags & 4 != 0, "a leading fragment carries a data CRC");
            return (start, body, p, data);
        }
        at = data.end;
    }
}

/// Overwrite the leading fragment's field in `volume` with 0xDEADBEEF and
/// re-stamp its header CRC: only the field disagrees.
fn damage_field(path: &Path) {
    let mut bytes = std::fs::read(path).unwrap();
    let (start, body, field, _) = file_head(&bytes);
    bytes[field..field + 4].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
    let crc = rarkit::checksum::crc32(&bytes[body]);
    bytes[start..start + 4].copy_from_slice(&crc.to_le_bytes());
    std::fs::write(path, bytes).unwrap();
}

/// Invert one byte in the middle of the fragment's data area.
fn damage_data(path: &Path) {
    let mut bytes = std::fs::read(path).unwrap();
    let (_, _, _, data) = file_head(&bytes);
    bytes[data.start + data.len() / 2] ^= 0xFF;
    std::fs::write(path, bytes).unwrap();
}

fn line(volume: &str) -> String {
    format!("\n{MEMBER:<20} : packed data checksum error in volume {volume}")
}

#[test]
fn the_line_is_the_reference_layout() {
    assert_eq!(
        line("s.part2.rar"),
        "\na.bin                : packed data checksum error in volume s.part2.rar"
    );
}

/// The field alone: the line for its volume, nothing else on stderr, `All
/// OK`, exit 0, at every width and for both methods; `x` writes the member
/// whole.
#[test]
fn a_field_alone_is_a_line_and_all_ok() {
    for method in ["-m0", "-m3"] {
        let dir = work(&format!("field{method}"));
        let parts = make_set(&dir, method);
        damage_field(&dir.join(&parts[1]));
        for width in [None, Some("-mt1")] {
            let mut args = vec!["t"];
            args.extend(width);
            args.push(&parts[0]);
            let ran = run(&dir, &args);
            assert_eq!(ran.code, Some(0), "{method} {width:?}: {}", ran.stderr);
            assert_eq!(ran.stderr, line(&parts[1]), "{method} {width:?}");
            assert!(
                ran.stdout.ends_with("  OK \nAll OK\n"),
                "{method} {width:?}: {}",
                ran.stdout
            );
        }
        let ran = run(&dir, &["x", "-o+", &parts[0], "out/"]);
        assert_eq!(ran.code, Some(0), "{method} x: {}", ran.stderr);
        assert_eq!(ran.stderr, line(&parts[1]), "{method} x");
        assert!(
            std::fs::read(dir.join("out").join(MEMBER)).unwrap() == payload(),
            "{method} x: the member is not whole"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Under `-ierr` the one stream shows where the line goes: after its own
/// volume's progress, before the next volume's banner.
#[test]
fn the_line_follows_its_volume_and_precedes_the_next_banner() {
    let dir = work("order");
    let parts = make_set(&dir, "-m0");
    damage_field(&dir.join(&parts[0]));
    let ran = run(&dir, &["t", "-ierr", &parts[0]]);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);
    let expected_tail = format!("{}\n\nTesting archive {}\n", line(&parts[0]), parts[1]);
    let at = ran
        .stderr
        .find(&expected_tail)
        .unwrap_or_else(|| panic!("no line then banner in {:?}", ran.stderr));
    assert!(ran.stderr[..at].ends_with('%'), "{:?}", ran.stderr);
    assert!(ran.stderr.ends_with("  OK \nAll OK\n"), "{:?}", ran.stderr);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Real damage in a later leading fragment: its volume's line too, then
/// the member's `- checksum error` after the LAST volume's line, exit 3.
#[test]
fn damage_names_its_volume_and_fails_after_the_last_volume() {
    let dir = work("damage");
    let parts = make_set(&dir, "-m0");
    damage_field(&dir.join(&parts[0]));
    damage_data(&dir.join(&parts[1]));
    let ran = run(&dir, &["t", &parts[0]]);
    assert_eq!(ran.code, Some(3), "{}", ran.stderr);
    assert!(
        ran.stdout.ends_with("\nTotal errors: 1\n"),
        "{:?}",
        ran.stdout
    );
    assert_eq!(
        ran.stderr,
        format!(
            "{}{}\n{MEMBER:<20} - checksum error",
            line(&parts[0]),
            line(&parts[1])
        )
    );
    let ran = run(&dir, &["t", "-ierr", &parts[0]]);
    let last_banner = ran
        .stderr
        .find(&format!("Testing archive {}", parts[parts.len() - 1]))
        .expect("the last volume's banner");
    let complaint = ran.stderr.find("- checksum error").expect("the complaint");
    assert!(complaint > last_banner, "{:?}", ran.stderr);
    let _ = std::fs::remove_dir_all(&dir);
}
