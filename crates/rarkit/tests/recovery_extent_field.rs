//! Spec L 3.5.2, the "extent" field of a RAR 5 inline recovery record at
//! 0x1E. With `r = P - (k - 1) G` (the real bytes of the last data shard)
//! and `o = 65,536 g` (the group's offset), every genuine record holds
//! `min(r - o, 65,536)` when `r >= o` and 65,536 when `r < o`.
//!
//! And 3.5.3: a reader does not read it. The reference believes the field
//! (R9: with it set to `0x7FFFFFFF` the reference was still running after
//! 45 seconds); rarkit takes every shard's real length from `P`, `k` and
//! `G`, so whatever the field holds the repair is the same and as bounded.
//!
//! Threads and memory: at most 4 workers; the largest input is 26,214,401
//! bytes at 1 percent, a 263 KiB record, under a 64 MiB repair limit.

use rarkit::internals::recovery::{crc64_xz, rr5_encode};
use rarkit::memory::MemoryPolicy;
use rarkit::{ReadOptions, SplitCheck};

fn filler(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = vec![0u8; len];
    for chunk in out.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    out
}

/// One record of a data area: `(row, group offset, extent, length)`.
fn records(area: &[u8]) -> Vec<(u16, u64, u32, usize)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < area.len() {
        let record = &area[at..];
        assert_eq!(&record[..4], b"{RB}", "a record at {at}");
        let len = u32::from_le_bytes(record[0x0c..0x10].try_into().unwrap()) as usize;
        out.push((
            u16::from_le_bytes([record[0x3e], record[0x3f]]),
            u64::from_le_bytes(record[0x16..0x1e].try_into().unwrap()),
            u32::from_le_bytes(record[0x1e..0x22].try_into().unwrap()),
            len,
        ));
        at += len;
    }
    out
}

/// The extents of row 0, in group order.
fn row_0_extents(protected: usize, percent: u32) -> Vec<u32> {
    let area = rr5_encode(&filler(protected, protected as u64), percent).expect("a record");
    let all = records(&area);
    // Every row holds the same extents as row 0.
    let row_0: Vec<u32> = all.iter().filter(|r| r.0 == 0).map(|r| r.2).collect();
    for row in all.chunks(row_0.len()) {
        assert_eq!(row.iter().map(|r| r.2).collect::<Vec<_>>(), row_0);
    }
    row_0
}

/// The census's `extents` rows (`specs/vectors-L/l-evidence/census.txt`)
/// and the two committed archives, field for field.
#[test]
fn the_extent_is_what_every_genuine_record_holds() {
    // One group: the last shard's real bytes.
    assert_eq!(row_0_extents(40_218, 5), [984]);
    assert_eq!(row_0_extents(97, 100), [97]);
    // Two groups, the last shard reaching into the second.
    assert_eq!(row_0_extents(14_000_162, 3), [65_536, 4_228]);
    assert_eq!(row_0_extents(16_000_162, 3), [65_536, 14_228]);
    // The last group lies wholly past the last shard's real bytes: 65,536
    // there, not 0 and not the group's length of 2.
    assert_eq!(row_0_extents(13_107_201, 3), [65_139, 65_536]);
    assert_eq!(row_0_extents(13_107_399, 3), [65_337, 65_536]);
    assert_eq!(row_0_extents(26_214_401, 1), [65_536, 65_139, 65_536]);
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

/// Sets every record's extent and seals each again, as the probe's arms
/// do (3.5.3, R9).
fn with_extent(volume: &[u8], protected: usize, extent: u32) -> Vec<u8> {
    let mut out = volume.to_vec();
    let mut at = protected;
    while at < out.len() {
        let len = u32::from_le_bytes(out[at + 0x0c..at + 0x10].try_into().unwrap()) as usize;
        out[at + 0x1e..at + 0x22].copy_from_slice(&extent.to_le_bytes());
        let seal = crc64_xz(&out[at + 0x0c..at + len]);
        out[at + 0x04..at + 0x0c].copy_from_slice(&seal.to_le_bytes());
        at += len;
    }
    out
}

/// The probe's archive shape (`P = 300,007`, 5 percent, the last shard
/// 1,109 real bytes of 1,502) with the last shard and one other damaged,
/// under each value R9 tried and its worst: the output is the undamaged
/// file each time, never short and never long, and the working memory
/// reported is the same as with the true field.
#[test]
fn a_reader_does_not_trust_the_extent() {
    let protected = filler(300_007, 0x300_007);
    let mut whole = protected.clone();
    whole.extend(rr5_encode(&protected, 5).expect("a record"));
    assert_eq!(records(&whole[300_007..])[0].2, 1_109);

    let mut peaks = Vec::new();
    for extent in [
        1_109u32,
        0,
        1_108,
        1_110,
        1_502,
        65_536,
        0x7FFF_FFFF,
        u32::MAX,
    ] {
        let mut damaged = with_extent(&whole, 300_007, extent);
        for at in [199 * 1_502 + 1_000, 7 * 1_502 + 3] {
            for byte in &mut damaged[at..at + 40] {
                *byte ^= 0x77;
            }
        }
        let mut out = Vec::new();
        let report = rarkit::recovery::repair_inline(&damaged, &options(), &mut out)
            .unwrap_or_else(|e| panic!("extent {extent:#x}: {e}"));
        assert_eq!(out.len(), whole.len(), "extent {extent:#x}: length");
        assert_eq!(
            out[..300_007],
            whole[..300_007],
            "extent {extent:#x}: the protected bytes"
        );
        peaks.push(report.peak_working_memory);
    }
    assert!(
        peaks.iter().all(|peak| *peak == peaks[0]),
        "the field moved the working memory: {peaks:?}"
    );
    assert!(peaks[0] <= 64 << 20);
}
