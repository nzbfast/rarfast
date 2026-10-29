//! The totals row of `l` and `v` over declared sizes whose sum does not
//! fit 64 bits.
//!
//! A header's unpacked size is the archive's word, up to 2^63 - 1 in RAR 5,
//! and the totals row summed them unchecked: a panic in an overflow-checked
//! build (`attempt to add with overflow`, list.rs:485) and a wrapped
//! unsigned number in a release one.
//!
//! MEASURED against unrar 7.23 on macOS (arm64), 4 Oct 2026, over the
//! archives built here: the reference's total wraps in 64 bits and prints
//! SIGNED. Two members of 2^63 - 1 total `-2`; three total
//! `9223372036854775805`; `v` over the three shows the same total, packed
//! `0` and `0%`.
//!
//! Each run states `-mt1`; the archives are headers only, so no memory to
//! speak of.

use std::path::PathBuf;
use std::process::Command;

#[path = "../../rarkit/tests/redirection/rewrite.rs"]
mod rewrite;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// A RAR 5 archive of stored file headers with no data area, one per
/// declared unpacked size, built from spec F 3.2.2 and 3.2.6 as
/// `redirection.rs` builds its links.
fn declared(sizes: &[u64]) -> Vec<u8> {
    fn block(body: &[u8], out: &mut Vec<u8>) {
        let mut sized = rewrite::vint(body.len() as u64);
        sized.extend_from_slice(body);
        out.extend_from_slice(&rewrite::crc32(&sized).to_le_bytes());
        out.extend_from_slice(&sized);
    }
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &mut out);
    for (at, size) in sizes.iter().enumerate() {
        let name = format!("big{at}");
        let mut body = rewrite::vint(2); // file header
        body.extend(rewrite::vint(0)); // no extra area, no data area
        body.extend(rewrite::vint(0x0004)); // CRC32 present
        body.extend(rewrite::vint(*size)); // unpacked size
        body.extend(rewrite::vint(0o100_644));
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.extend(rewrite::vint(0)); // stored
        body.extend(rewrite::vint(1)); // Unix
        body.extend(rewrite::vint(name.len() as u64));
        body.extend_from_slice(name.as_bytes());
        block(&body, &mut out);
    }
    block(&[5, 0, 0], &mut out);
    out
}

/// The totals row of `rarfast <command> -mt1` over `sizes`: the line
/// before the listing's closing blank one.
fn totals(tag: &str, command: &str, sizes: &[u64]) -> String {
    let dir = std::env::temp_dir().join(format!("rarfast-totals-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let archive = dir.join("a.rar");
    std::fs::write(&archive, declared(sizes)).unwrap();
    let done = Command::new(rarfast())
        .args([command, "-mt1"])
        .arg(&archive)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(done.status.code(), Some(0), "{tag}: {done:?}");
    let said = String::from_utf8_lossy(&done.stdout).into_owned();
    said.lines()
        .rev()
        .find(|line| !line.is_empty())
        .unwrap_or_else(|| panic!("{tag}: no totals row: {said}"))
        .to_owned()
}

const MOST: u64 = (1 << 63) - 1;

#[test]
fn the_totals_row_wraps_as_the_reference_does() {
    // The rows the reference printed, byte for byte.
    assert_eq!(
        totals("small", "l", &[5, 7]),
        "                    12                    2"
    );
    assert_eq!(
        totals("two", "l", &[MOST, MOST]),
        "                    -2                    2"
    );
    assert_eq!(
        totals("three", "l", &[MOST, MOST, MOST]),
        "            9223372036854775805                    3"
    );
    assert_eq!(
        totals("three-v", "v", &[MOST, MOST, MOST]),
        "            9223372036854775805          0   0%                              3"
    );
}
