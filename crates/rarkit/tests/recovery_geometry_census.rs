//! Spec L 3.5.1, the geometry of a RAR 5 inline recovery record:
//!
//!     k = min(200, max(1, ceil(P / 1024)))
//!     m = max(1, floor(pct * k / 100))
//!     G = ceil(P / k), then + 1 if odd
//!
//! with `m` NOT capped at `k` and percentages from 1 to 1,000. The table
//! below is the census of genuine archives the section rests on
//! (`specs/vectors-L/l-evidence/census.txt`, the 49 `archive` rows and the
//! two committed files), row for row.
//!
//! Threads and memory: at most 4 workers; the largest record made here is
//! 1,000 percent of 300,007 bytes, about 3.9 MiB, under a 64 MiB limit.

use rarkit::internals::recovery::{rr5_encode, rr5_geometry, rr5_service_header};
use rarkit::memory::MemoryPolicy;
use rarkit::{
    ErrorKind, MemberSpec, Payload, Rar4Version, ReadOptions, SplitCheck, Unsupported, WriteFormat,
    WriteOptions, Writer,
};

/// `(P, pct, k, m, G, groups)` of every genuine archive in the census.
const CENSUS: &[(u64, u32, u16, u16, u64, u64)] = &[
    (1_023, 5, 1, 1, 1_024, 1),
    (1_024, 5, 1, 1, 1_024, 1),
    (1_025, 5, 2, 1, 514, 1),
    (2_048, 5, 2, 1, 1_024, 1),
    (2_049, 5, 3, 1, 684, 1),
    (40_218, 5, 40, 2, 1_006, 1),
    (100_000, 5, 98, 4, 1_022, 1),
    (203_776, 5, 199, 9, 1_024, 1),
    (203_777, 5, 200, 10, 1_020, 1),
    (204_799, 5, 200, 10, 1_024, 1),
    (204_800, 5, 200, 10, 1_024, 1),
    (204_801, 5, 200, 10, 1_026, 1),
    (300_000, 5, 200, 10, 1_500, 1),
    (1_000_001, 5, 200, 10, 5_002, 1),
    (40_218, 1, 40, 1, 1_006, 1),
    (300_000, 1, 200, 2, 1_500, 1),
    (40_218, 2, 40, 1, 1_006, 1),
    (300_000, 2, 200, 4, 1_500, 1),
    (40_218, 3, 40, 1, 1_006, 1),
    (300_000, 3, 200, 6, 1_500, 1),
    (40_218, 7, 40, 2, 1_006, 1),
    (300_000, 7, 200, 14, 1_500, 1),
    (40_218, 10, 40, 4, 1_006, 1),
    (300_000, 10, 200, 20, 1_500, 1),
    (40_218, 33, 40, 13, 1_006, 1),
    (300_000, 33, 200, 66, 1_500, 1),
    (40_218, 50, 40, 20, 1_006, 1),
    (300_000, 50, 200, 100, 1_500, 1),
    (40_218, 99, 40, 39, 1_006, 1),
    (300_000, 99, 200, 198, 1_500, 1),
    (40_218, 100, 40, 40, 1_006, 1),
    (300_000, 100, 200, 200, 1_500, 1),
    (5_000, 1, 5, 1, 1_000, 1),
    (204_799, 1, 200, 2, 1_024, 1),
    (5_000, 3, 5, 1, 1_000, 1),
    (204_799, 3, 200, 6, 1_024, 1),
    (5_000, 100, 5, 5, 1_000, 1),
    (204_799, 100, 200, 200, 1_024, 1),
    (13_107_200, 3, 200, 6, 65_536, 1),
    (13_107_201, 3, 200, 6, 65_538, 2),
    (13_107_399, 3, 200, 6, 65_538, 2),
    (14_000_162, 3, 200, 6, 70_002, 2),
    (16_000_162, 3, 200, 6, 80_002, 2),
    (26_214_401, 1, 200, 2, 131_074, 3),
    (300_000, 101, 200, 202, 1_500, 1),
    (300_000, 150, 200, 300, 1_500, 1),
    (40_218, 250, 40, 100, 1_006, 1),
    (5_000, 1_000, 5, 50, 1_000, 1),
    (1_024, 300, 1, 3, 1_024, 1),
    // The census's percentage edge rows, all over 300,007 bytes.
    (300_007, 200, 200, 400, 1_502, 1),
    (300_007, 1_000, 200, 2_000, 1_502, 1),
    // The two committed archives.
    (97, 100, 1, 1, 98, 1),
];

#[test]
fn the_geometry_is_the_census_row_for_row() {
    for &(protected, percent, k, m, shard, groups) in CENSUS {
        let got = rr5_geometry(protected, percent)
            .unwrap_or_else(|e| panic!("P = {protected} at {percent}%: {e}"));
        let header = 0x48 + 8 * u32::from(k);
        let span = groups * u64::from(header) + shard;
        assert_eq!(
            got,
            (k, m, shard, groups, header, span),
            "P = {protected} at {percent}%"
        );
    }
}

#[test]
fn a_percentage_outside_1_to_1000_has_no_geometry() {
    assert!(rr5_geometry(300_007, 0).is_err());
    assert!(rr5_geometry(300_007, 1_001).is_err());
    assert!(rr5_geometry(300_007, u32::MAX).is_err());
}

fn filler(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn options() -> ReadOptions {
    ReadOptions::default()
        .with_password(None)
        .with_memory(MemoryPolicy {
            repair_limit: 64 << 20,
            max_workers: 4,
            ..MemoryPolicy::from_limit(64 << 20)
        })
        .with_sfx_scan(0)
        .with_split_check(SplitCheck::Streaming)
        .with_tolerant_tail(false)
        .with_cancel(None)
        .with_workers(None)
        .with_sink_is_file(None)
}

/// More recovery rows than data shards, used as such: at 1,000 percent of
/// 5,000 bytes there are 5 shards and 50 rows, and with rows 0 to 44 lost
/// every one of the 5 shards is rebuilt from rows 45 to 49, none of which
/// a record capped at `k` rows would hold.
#[test]
fn rows_past_the_data_count_rebuild_every_shard() {
    let protected = filler(5_000, 0x5eed);
    let area = rr5_encode(&protected, 1_000).expect("a record at 1,000 percent");
    let span = 0x48 + 8 * 5 + 1_000;
    assert_eq!(area.len(), 50 * span, "m x span");
    for (row, record) in area.chunks(span).enumerate() {
        assert_eq!(&record[..4], b"{RB}");
        assert_eq!(u16::from_le_bytes([record[0x3a], record[0x3b]]), 5, "k");
        assert_eq!(u16::from_le_bytes([record[0x3c], record[0x3d]]), 50, "m");
        assert_eq!(
            usize::from(u16::from_le_bytes([record[0x3e], record[0x3f]])),
            row
        );
    }
    // Laid out as an archive is: the `RR` service header at `P`, then
    // the data area (spec L 3.5.5 O7: every shard is damaged below, so
    // nothing but the header says the records are this file's).
    let header = rr5_service_header(area.len() as u64, 1_000);
    let mut whole = protected.clone();
    whole.extend(&header);
    whole.extend(&area);

    let mut damaged = whole.clone();
    for shard in 0..5 {
        damaged[shard * 1_000 + 17] ^= 0x5a;
    }
    // Rows 0 to 44: break each record's seal.
    for row in 0..45 {
        damaged[5_000 + header.len() + row * span + 4] ^= 0xff;
    }
    let check = rarkit::recovery::check_inline(&damaged, &options()).expect("found");
    assert_eq!(check.groups[0].rows, 5);
    assert_eq!(check.groups[0].damaged, vec![0, 1, 2, 3, 4]);
    let mut out = Vec::new();
    rarkit::recovery::repair_inline(&damaged, &options(), &mut out).expect("repaired");
    assert_eq!(out[..5_000], whole[..5_000]);
}

fn write(format: WriteFormat, percent: u32, data: &[u8]) -> rarkit::Result<Vec<u8>> {
    let mut writer = Writer::new(WriteOptions {
        format,
        filters: match format {
            WriteFormat::Rar4(_) => rarkit::FilterPolicy::Off,
            WriteFormat::Rar5 => rarkit::FilterPolicy::default(),
        },
        recovery_percent: Some(percent),
        ..WriteOptions::default()
    })?;
    writer.add(MemberSpec {
        name: b"payload.bin",
        payload: Payload::Bytes(data),
        mtime: None,
        attributes: 0o100644,
        host_os: rarkit::HostOs::Unix,
        is_directory: false,
    })?;
    let mut out = Vec::new();
    writer.finish_into(&mut out)?;
    Ok(out)
}

fn refused(result: rarkit::Result<Vec<u8>>) -> bool {
    match result {
        Ok(_) => false,
        Err(error) => matches!(
            error.kind(),
            ErrorKind::Unsupported(Unsupported::WriteFeature(_))
        ),
    }
}

/// The writer takes every percentage the reference stores as given, 1 to
/// 1,000, and writes the record the geometry gives; the record's own
/// `m` is read back out of its first header.
#[test]
fn the_writer_takes_percentages_up_to_1000() {
    let data = filler(300_000, 0xfeed);
    for percent in [100u32, 101, 150, 250, 1_000] {
        let archive =
            write(WriteFormat::Rar5, percent, &data).unwrap_or_else(|e| panic!("{percent}%: {e}"));
        let at = archive
            .windows(4)
            .position(|w| w == b"{RB}")
            .expect("a record");
        let k = u16::from_le_bytes([archive[at + 0x3a], archive[at + 0x3b]]);
        let m = u16::from_le_bytes([archive[at + 0x3c], archive[at + 0x3d]]);
        assert_eq!(k, 200, "{percent}%");
        assert_eq!(u32::from(m), percent * 2, "{percent}%: m = pct * k / 100");

        let mut damaged = archive.clone();
        for byte in &mut damaged[2_000..2_040] {
            *byte ^= 0x77;
        }
        let mut mended = Vec::new();
        rarkit::recovery::repair_inline(&damaged, &options(), &mut mended)
            .unwrap_or_else(|e| panic!("{percent}%: repairing: {e}"));
        assert_eq!(mended, archive, "{percent}%");
    }
    assert!(refused(write(WriteFormat::Rar5, 0, &data)));
    assert!(refused(write(WriteFormat::Rar5, 1_001, &data)));
}

/// The RAR 4 family's record is another code with another rule (spec L
/// 3.7: parity sectors, at most the sectors protected); its writer keeps
/// 1 to 100.
#[test]
fn the_rar4_writer_keeps_1_to_100() {
    let data = filler(60_000, 0xbeef);
    let format = WriteFormat::Rar4(Rar4Version::V40);
    assert!(write(format, 100, &data).is_ok());
    assert!(refused(write(format, 101, &data)));
    assert!(refused(write(format, 1_000, &data)));
}
