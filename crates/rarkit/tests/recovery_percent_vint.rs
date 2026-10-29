//! Spec L 3.5.1: the `RR` service header's extra record of type 7 holds
//! the recovery percentage as a VINT, and the reference stores every value
//! from 1 to 1,000 as given. One byte holds 1 to 127 only: 300 is `AC 02`.

use std::process::Command;
use std::sync::Arc;

use rarkit::{Archive, RangeSource, ReadOptions};

fn vector(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../specs/vectors-L/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn read_vint(b: &[u8], mut i: usize) -> (u64, usize) {
    let (mut value, mut shift) = (0u64, 0);
    loop {
        let byte = b[i];
        i += 1;
        value |= u64::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return (value, i);
        }
    }
}

fn write_vint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// The recovery percentage `Archive::services` reports, if any.
fn percentage(archive: Vec<u8>) -> Option<u32> {
    let src: Arc<dyn RangeSource> = Arc::new(archive);
    let archive = Archive::open(src, &ReadOptions::default()).expect("the archive opens");
    let found: Vec<u32> = archive
        .services()
        .filter_map(|svc| svc.recovery_percent)
        .collect();
    assert!(found.len() <= 1, "{found:?}");
    found.first().copied()
}

/// `archive`, a genuine RAR 5 archive with a recovery record, with the
/// percentage in its `RR` header's type 7 record rewritten to `percent`
/// and the header's sizes and CRC32 stamped again. The record itself is
/// left as it was: only the header is under test.
fn with_percentage(archive: &[u8], percent: u64) -> Vec<u8> {
    let mut i = 8;
    loop {
        let (size, body_at) = read_vint(archive, i + 4);
        let end = body_at + size as usize;
        let (kind, at) = read_vint(archive, body_at);
        let (flags, at) = read_vint(archive, at);
        assert!(kind != 5, "no RR service header");
        let (extra, extra_end) = if flags & 1 != 0 {
            read_vint(archive, at)
        } else {
            (0, at)
        };
        let data = if flags & 2 != 0 {
            read_vint(archive, extra_end).0
        } else {
            0
        };
        let extra_start = end - extra as usize;
        // The only extra record of a genuine `RR` header: size, type 7,
        // the percentage.
        if kind == 3 && extra > 0 && archive[extra_start + 1] == 7 {
            let mut record = vec![7u8];
            record.extend(write_vint(percent));
            let mut area = write_vint(record.len() as u64);
            area.extend(record);
            let mut body = archive[body_at..at].to_vec();
            body.extend(write_vint(area.len() as u64));
            body.extend_from_slice(&archive[extra_end..extra_start]);
            body.extend(area);
            let mut header = write_vint(body.len() as u64);
            header.extend(body);
            let mut out = archive[..i].to_vec();
            out.extend_from_slice(&rarkit::checksum::crc32(&header).to_le_bytes());
            out.extend(header);
            out.extend_from_slice(&archive[end..]);
            return out;
        }
        i = end + data as usize;
    }
}

/// One thread; the archives are under 100 KiB.
#[test]
fn the_recovery_percentage_is_read_as_a_vint() {
    assert_eq!(percentage(vector("rr5_small.rar")), Some(5));
    assert_eq!(percentage(vector("rr100_small.rar")), Some(100));
    let genuine = vector("rr5_small.rar");
    assert_eq!(
        with_percentage(&genuine, 5),
        genuine,
        "the rewrite is exact"
    );
    for percent in [1u32, 127, 128, 200, 255, 256, 300, 1_000] {
        assert_eq!(
            percentage(with_percentage(&genuine, u64::from(percent))),
            Some(percent),
            "{percent} percent"
        );
    }
}

/// The same from what reference `rar` itself writes for `-rr300` and
/// `-rr1000`, where it is on PATH.
///
/// One thread; the archives are under 1 MiB.
#[test]
fn a_genuine_rr300_archive_reports_300() {
    if Command::new("rar").output().is_err() {
        eprintln!("SKIPPED: reference rar is not on PATH");
        return;
    }
    let dir = std::env::temp_dir().join(format!("rarkit-rrvint-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("data.bin");
    let data: Vec<u8> = (0..20_000u32).map(|i| (i * 31 % 251) as u8).collect();
    std::fs::write(&file, data).unwrap();
    for percent in [300u32, 1_000] {
        let path = dir.join(format!("rr{percent}.rar"));
        let out = Command::new("rar")
            .arg("a")
            .arg("-idq")
            .arg("-ep")
            .arg(format!("-rr{percent}"))
            .arg(&path)
            .arg(&file)
            .output()
            .expect("rar a");
        assert!(out.status.success(), "rar a exited {:?}", out.status.code());
        assert_eq!(
            percentage(std::fs::read(&path).unwrap()),
            Some(percent),
            "rar a -rr{percent}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// An edit that says nothing about the recovery record rebuilds it at the
/// percentage the source states, or refuses by name where the writer does
/// not make that percentage; it never rebuilds at another one. (Read as
/// one byte, 300 would have been carried as a different number.)
///
/// The vector's record is a 5 percent one whatever its header is made to
/// say, and a percentage whose record would be longer than the one
/// present is refused too (bug sweep of 8 Oct 2026, item 08;
/// `tests/edit_recovery_percent_bound.rs`): so 100 and 300 are refusals
/// here, and 5 is carried.
///
/// One thread; the archives are under 100 KiB.
#[test]
fn an_edit_carries_the_stated_percentage_or_refuses() {
    for percent in [5u32, 100, 300] {
        let bytes = with_percentage(&vector("rr5_small.rar"), u64::from(percent));
        let src: Arc<dyn RangeSource> = Arc::new(bytes);
        let archive = Archive::open(src, &ReadOptions::default()).expect("the archive opens");
        let mut out = Vec::new();
        match rarkit::edit::lock(&archive, &mut out) {
            Ok(()) => assert_eq!(percentage(out), Some(percent), "{percent} percent"),
            // Which error names it is the writer's side and not pinned.
            Err(e) => assert!(percent > 5, "{percent} percent was refused: {e}"),
        }
    }
}
