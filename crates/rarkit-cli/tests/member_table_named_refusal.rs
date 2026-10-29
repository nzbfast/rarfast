//! D3 at the command line: a member table that does not fit its budget is
//! refused BY NAME, and a named `-mm<size>` is that budget for `l` as it
//! already was for `t` and `x`.
//!
//! What 899cfe976 did (D3's first commit, which made the open hold the
//! member table and its names to one budget, spec F 4.2):
//!
//! - `l` read with the engine's default policy whatever `-mm` said: under
//!   `-mm16m` it listed archives whose table and names come to 55 to 87
//!   MiB, the process at 128 to 263 MiB.
//! - An open refused for its member table (`LimitExceeded { resource:
//!   MemberTable }`) was called `<archive> is not RAR archive`, exit 0
//!   under `l` and 10 under `t` and `x`, with and without `-mm`. Before
//!   that commit the same archive with no `-mm` failed later in `t` and `x`
//!   with `MemberTable wanted ... and the policy allows ...` on standard
//!   error, `Total errors: 1`, exit 2, which is the refusal kept here.
//!
//! The archives are made here: empty stored members, each name its member
//! number padded with zeros. With no `-mm` a read keeps the budget it had.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-table-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn vint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

fn block5(fields: &[u8], out: &mut Vec<u8>) {
    let mut sized = Vec::new();
    vint(fields.len() as u64, &mut sized);
    sized.extend_from_slice(fields);
    out.extend_from_slice(&crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
}

/// A RAR 4 block: its CRC16, type, flags and size, then `rest`.
fn block4(kind: u8, flags: u16, rest: &[u8], out: &mut Vec<u8>) {
    let mut body = vec![kind];
    body.extend_from_slice(&flags.to_le_bytes());
    body.extend_from_slice(&((7 + rest.len()) as u16).to_le_bytes());
    body.extend_from_slice(rest);
    out.extend_from_slice(&(crc32(&body) as u16).to_le_bytes());
    out.extend_from_slice(&body);
}

/// `count` empty stored members, each name `width` bytes, RAR 5 or RAR 4.
fn archive(rar5: bool, count: usize, width: usize) -> Vec<u8> {
    let mut out = Vec::new();
    if rar5 {
        out.extend_from_slice(b"Rar!\x1a\x07\x01\x00");
        block5(&[1, 0, 0], &mut out);
        for at in 0..count {
            let name = format!("{at:0width$}");
            let mut fields = vec![2, 0, 0, 0, 0, 0, 0];
            vint(name.len() as u64, &mut fields);
            fields.extend_from_slice(name.as_bytes());
            block5(&fields, &mut out);
        }
        block5(&[5, 0, 0], &mut out);
    } else {
        out.extend_from_slice(b"Rar!\x1a\x07\x00");
        block4(0x73, 0, &[0; 6], &mut out);
        for at in 0..count {
            let name = format!("{at:0width$}");
            let mut rest = Vec::new();
            rest.extend_from_slice(&0u32.to_le_bytes()); // packed size
            rest.extend_from_slice(&0u32.to_le_bytes()); // unpacked size
            rest.push(2); // host: Unix
            rest.extend_from_slice(&0u32.to_le_bytes()); // CRC32 of no bytes
            rest.extend_from_slice(&0x5b61_0000u32.to_le_bytes()); // DOS time
            rest.extend_from_slice(&[29, 0x30]); // version, stored
            rest.extend_from_slice(&(name.len() as u16).to_le_bytes());
            rest.extend_from_slice(&0o100_644u32.to_le_bytes());
            rest.extend_from_slice(name.as_bytes());
            block4(0x74, 0x8000, &rest, &mut out);
        }
        block4(0x7b, 0, &[], &mut out);
    }
    out
}

fn run(dir: &Path, command: &str, mm: Option<&str>) -> Output {
    let mut cmd = Command::new(rarfast());
    cmd.current_dir(dir).arg(command).arg("-p-");
    if let Some(mm) = mm {
        cmd.arg(mm);
    }
    cmd.arg("a.rar");
    if command == "x" {
        std::fs::create_dir_all(dir.join("out")).unwrap();
        cmd.arg("-y").arg("out/");
    }
    cmd.output().unwrap()
}

/// The run refused the archive for its member table, by name, exit 2: on
/// standard error the line 7e5a30b09's walk gave the same refusal,
/// `MemberTable wanted <needed> bytes and the policy allows <limit>
/// (volume 0)` with a blank line before it, and the needed figure above the
/// limit (D3b).
fn refused(ran: &Output, what: &str) {
    let stdout = String::from_utf8_lossy(&ran.stdout);
    let stderr = String::from_utf8_lossy(&ran.stderr);
    assert!(
        !stdout.contains("is not RAR archive"),
        "{what}: a member table over its budget read as no archive: {stdout}"
    );
    let figures = stderr
        .strip_prefix("\nMemberTable wanted ")
        .and_then(|rest| rest.strip_suffix(" (volume 0)\n"))
        .and_then(|rest| rest.split_once(" bytes and the policy allows "))
        .and_then(|(needed, limit)| {
            Some((needed.parse::<u64>().ok()?, limit.parse::<u64>().ok()?))
        });
    let Some((needed, limit)) = figures else {
        panic!("{what}: not the named refusal on standard error: {stderr:?}");
    };
    assert!(needed > limit, "{what}: {stderr:?}");
    assert_eq!(ran.status.code(), Some(2), "{what}: {stderr}");
}

/// Under `-mm16m` the member table's share is about 2 MiB: 20,000 members
/// with 100 byte names come to about 3.4 MB of table and names. With no
/// `-mm` the same archive lists as before.
#[test]
fn a_named_mm_bounds_the_member_table_of_l_t_and_x() {
    for rar5 in [true, false] {
        let dir = work(if rar5 { "mm5" } else { "mm4" });
        std::fs::write(dir.join("a.rar"), archive(rar5, 20_000, 100)).unwrap();
        for command in ["l", "t", "x"] {
            let ran = run(&dir, command, Some("-mm16m"));
            refused(&ran, &format!("rar5 {rar5} {command} -mm16m"));
        }
        let ran = run(&dir, "l", None);
        assert_eq!(ran.status.code(), Some(0), "rar5 {rar5} l with no -mm");
        let listed = String::from_utf8_lossy(&ran.stdout);
        assert!(
            listed.contains(&format!("{:0100}", 19_999)),
            "rar5 {rar5} l with no -mm lists every member"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// With no `-mm`: 600,000 members with 80 byte names, about 41 MiB of
/// table and 46 of names, each under the 64 MiB default and together
/// over it.
#[test]
fn a_member_table_over_its_budget_is_refused_by_name() {
    for rar5 in [true, false] {
        let dir = work(if rar5 { "over5" } else { "over4" });
        std::fs::write(dir.join("a.rar"), archive(rar5, 600_000, 80)).unwrap();
        for command in ["l", "t", "x"] {
            let ran = run(&dir, command, None);
            refused(&ran, &format!("rar5 {rar5} {command}"));
            if command == "x" {
                assert_eq!(
                    std::fs::read_dir(dir.join("out")).unwrap().count(),
                    0,
                    "a refused open writes nothing"
                );
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
