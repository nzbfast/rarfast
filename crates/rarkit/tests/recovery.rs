//! Spec L end to end: the committed vectors (`specs/vectors-L`), the
//! damage vectors section 5 names, and differential tests against the old
//! engine through `rarkit-oracle`.
//!
//! The oracle adapters spec L section 6 names (`blake2sp`, `rr5_record`,
//! `rev_create`, `repair_inline`, `rev_repair`) now exist. This file stays
//! what it was, the vectors and the damage cases; the differentials that
//! call those adapters are in `oracle_differentials_l.rs` beside it.

use std::sync::Arc;

use rarkit::memory::MemoryPolicy;
use rarkit::{ErrorKind, RangeSource, ReadOptions, RecoveryFailure, SplitCheck};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../specs/vectors-L");

fn vector(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}/{name}")).expect("spec L vector")
}

/// A policy with room for any repair in this file. Spec F owns the
/// default budget, so every test states its own.
fn policy() -> MemoryPolicy {
    MemoryPolicy {
        working_limit: 1 << 30,
        max_window: 1 << 30,
        max_dictionary: 1 << 20,
        repair_limit: 256 << 20,
        read_ahead: 1 << 20,
        max_workers: 4,
        ..MemoryPolicy::from_limit(1 << 30)
    }
}

fn options() -> ReadOptions {
    ReadOptions::default()
        .with_password(None)
        .with_memory(policy())
        .with_sfx_scan(0)
        .with_split_check(SplitCheck::Streaming)
        .with_tolerant_tail(false)
        .with_cancel(None)
        .with_workers(None)
        .with_sink_is_file(None)
}

fn repair(volume: &[u8]) -> rarkit::Result<(Vec<u8>, rarkit::rev5::RepairReport)> {
    let mut out = Vec::new();
    let report = rarkit::recovery::repair_inline(&volume.to_vec(), &options(), &mut out)?;
    Ok((out, report))
}

/// `rr5_small.rar`: P = 40,218, k = 40, m = 2, G = 1,006, one group.
mod inline_rr5 {
    use super::*;

    const PROTECTED: usize = 40_218;
    const SHARD: usize = 1_006;

    fn damage(volume: &mut [u8], shard: usize, bytes: usize) {
        let at = shard * SHARD;
        for i in 0..bytes {
            volume[at + i] ^= 0xA5;
        }
    }

    #[test]
    fn an_undamaged_volume_comes_back_unchanged() {
        let file = vector("rr5_small.rar");
        let (out, report) = repair(&file).unwrap();
        assert_eq!(out, file);
        assert!(report.rebuilt.is_empty());
        assert!(report.failed.is_empty());
    }

    #[test]
    fn scan_finds_every_record() {
        let file = vector("rr5_small.rar");
        let chunks = rarkit::recovery::scan_inline(&file).unwrap();
        assert_eq!(chunks.len(), 2, "two rows, one group");
        assert_eq!(chunks[0].range, 40_241..40_241 + 1_398);
        assert_eq!(chunks[1].range, 41_639..41_639 + 1_398);
    }

    #[test]
    fn one_damaged_slice_is_repaired_byte_exactly() {
        let file = vector("rr5_small.rar");
        for shard in [0usize, 1, 17, 39] {
            let mut broken = file.clone();
            damage(&mut broken, shard, 200);
            assert_ne!(broken, file);
            let (out, report) = repair(&broken).unwrap();
            assert_eq!(out, file, "shard {shard}");
            assert_eq!(report.rebuilt, vec![0]);
            assert!(report.failed.is_empty());
        }
    }

    #[test]
    fn as_many_damaged_slices_as_there_are_rows() {
        let file = vector("rr5_small.rar");
        let mut broken = file.clone();
        damage(&mut broken, 3, SHARD);
        damage(&mut broken, 28, 40);
        let (out, report) = repair(&broken).unwrap();
        assert_eq!(out, file);
        assert_eq!(report.rebuilt, vec![0]);
    }

    #[test]
    fn the_last_shards_partial_slice_is_covered() {
        // Shard 39 holds P - 39 G = 984 real bytes of its 1,006.
        let file = vector("rr5_small.rar");
        let mut broken = file.clone();
        broken[PROTECTED - 1] ^= 0xFF;
        let (out, _) = repair(&broken).unwrap();
        assert_eq!(out, file);
    }

    #[test]
    fn more_damage_than_rows_is_refused() {
        let file = vector("rr5_small.rar");
        let mut broken = file.clone();
        for shard in [2usize, 9, 30] {
            damage(&mut broken, shard, 16);
        }
        let error = repair(&broken).unwrap_err();
        assert!(
            matches!(
                error.kind(),
                ErrorKind::Recovery(RecoveryFailure::TooManyMissing {
                    missing: 3,
                    available: 2
                })
            ),
            "{error}"
        );
    }

    #[test]
    fn a_corrupt_record_costs_one_row_and_no_more() {
        let file = vector("rr5_small.rar");
        let mut broken = file.clone();
        // Row 1's record, its own CRC-64 field.
        broken[41_639 + 4] ^= 0x01;
        damage(&mut broken, 11, 64);
        let (out, report) = repair(&broken).unwrap();
        assert_eq!(out[..PROTECTED], file[..PROTECTED]);
        assert_eq!(report.rebuilt, vec![0]);
        // With one row gone, two damaged slices are one too many.
        let mut worse = broken.clone();
        damage(&mut worse, 12, 64);
        let error = repair(&worse).unwrap_err();
        assert!(
            matches!(
                error.kind(),
                ErrorKind::Recovery(RecoveryFailure::TooManyMissing {
                    missing: 2,
                    available: 1
                })
            ),
            "{error}"
        );
    }

    #[test]
    fn damage_past_the_protected_prefix_is_not_the_records_to_repair() {
        // The end header, which no shard covers.
        let file = vector("rr5_small.rar");
        let mut broken = file.clone();
        let last = broken.len() - 1;
        broken[last] ^= 0xFF;
        let (out, report) = repair(&broken).unwrap();
        assert_eq!(out, broken, "copied through unchanged");
        assert!(report.rebuilt.is_empty());
    }

    #[test]
    fn a_volume_with_no_record_says_so() {
        let file = vector("rv.part1.rar");
        let error = rarkit::recovery::scan_inline(&file).unwrap_err();
        assert!(matches!(
            error.kind(),
            ErrorKind::Recovery(RecoveryFailure::NoRecord)
        ));
    }

    #[test]
    fn rr100_repairs_its_single_shard() {
        let file = vector("rr100_small.rar");
        let mut broken = file.clone();
        broken[10] ^= 0xFF;
        let (out, report) = repair(&broken).unwrap();
        assert_eq!(out, file);
        assert_eq!(report.rebuilt, vec![0]);
    }
}

/// A source that hands its bytes over in small pieces, so the engine's
/// short-read loops are exercised rather than assumed.
struct Dribble(Vec<u8>);

impl RangeSource for Dribble {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let want = buf.len().min(7);
        RangeSource::read_at(&self.0, offset, &mut buf[..want])
    }
    fn available(&self) -> u64 {
        self.0.len() as u64
    }
    fn len(&self) -> Option<u64> {
        Some(self.0.len() as u64)
    }
}

#[test]
fn a_short_reading_source_gives_the_same_repair() {
    let file = vector("rr5_small.rar");
    let mut broken = file.clone();
    broken[2_000] ^= 0xFF;
    let mut out = Vec::new();
    let source: Arc<dyn RangeSource> = Arc::new(Dribble(broken));
    rarkit::recovery::repair_inline(&source, &options(), &mut out).unwrap();
    assert_eq!(out, file);
}

/// RAR 5 `.rev` recovery volumes (spec L 3.6), against the committed
/// reference sets.
mod rev {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::sync::Mutex;

    use rarkit::rev5::{self, DataVolume, RepairSet, RevInfo, RevOptions};
    use rarkit::VolumeOut;

    /// A [`VolumeOut`] that keeps every volume in memory.
    #[derive(Default)]
    struct Collect {
        volumes: BTreeMap<u32, Arc<Mutex<Vec<u8>>>>,
    }

    struct Slot(Arc<Mutex<Vec<u8>>>);

    impl Write for Slot {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl VolumeOut for Collect {
        type W = Slot;
        fn volume(&mut self, index: u32) -> rarkit::Result<Slot> {
            let slot = self.volumes.entry(index).or_default().clone();
            Ok(Slot(slot))
        }
    }

    impl Collect {
        fn take(&self, index: u32) -> Vec<u8> {
            self.volumes[&index].lock().unwrap().clone()
        }
    }

    fn sources(names: &[&str]) -> Vec<Arc<dyn RangeSource>> {
        names
            .iter()
            .map(|n| Arc::new(vector(n)) as Arc<dyn RangeSource>)
            .collect()
    }

    const RV: [&str; 3] = ["rv.part1.rar", "rv.part2.rar", "rv.part3.rar"];
    const RVODD: [&str; 4] = [
        "rvodd.part1.rar",
        "rvodd.part2.rar",
        "rvodd.part3.rar",
        "rvodd.part4.rar",
    ];

    #[test]
    fn counts_match_the_measured_rule() {
        assert_eq!(rev5::count_for_percent(3, 67), 3);
        assert_eq!(rev5::count_for_percent(41, 10), 5);
        assert_eq!(rev5::count_for_percent(2, 1), 1);
        assert_eq!(rev5::default_count(3), 1);
        assert_eq!(rev5::default_count(20), 2);
        assert_eq!(rev5::max_count(41), 410);
        assert_eq!(rev5::max_count(1), 10);
    }

    #[test]
    fn the_reference_headers_parse() {
        let info = rev5::inspect(&vector("rv.part1.rev")).unwrap();
        assert_eq!((info.data_count, info.recovery_count, info.row), (3, 2, 0));
        assert_eq!(info.payload, 63..63 + 16_384, "hsize 47");
        assert_eq!(
            info.data_volumes,
            RV.iter()
                .map(|n| {
                    let bytes = vector(n);
                    DataVolume {
                        size: bytes.len() as u64,
                        crc32: rarkit::checksum::crc32(&bytes),
                    }
                })
                .collect::<Vec<_>>()
        );
        let second = rev5::inspect(&vector("rv.part2.rev")).unwrap();
        assert_eq!(second.row, 1, "number 4 of a three-volume set");
        assert!(info.same_set(&second));
        assert!(info.verify_payload(&vector("rv.part1.rev")).unwrap());

        let odd = rev5::inspect(&vector("rvodd.part1.rev")).unwrap();
        assert_eq!((odd.data_count, odd.row), (4, 0));
        assert_eq!(odd.payload.end - odd.payload.start, 12_290, "even payload");
        assert!(!info.same_set(&odd));
    }

    /// Every byte of the reference `.rev` files, from spec L's rules.
    #[test]
    fn create_reproduces_the_reference_volumes() {
        for (data, count, want) in [
            (&RV[..], 2u32, &["rv.part1.rev", "rv.part2.rev"][..]),
            (&RVODD[..], 1, &["rvodd.part1.rev"][..]),
        ] {
            let mut out = Collect::default();
            let report = rev5::create(
                &sources(data),
                count,
                &RevOptions { memory: policy() },
                &mut out,
            )
            .unwrap();
            assert_eq!(report.volumes, count);
            for (row, name) in want.iter().enumerate() {
                assert_eq!(out.take(row as u32), vector(name), "{name}");
            }
        }
    }

    #[test]
    fn a_missing_volume_is_rebuilt_from_either_row() {
        for rev in ["rv.part1.rev", "rv.part2.rev"] {
            let info = rev5::inspect(&vector(rev)).unwrap();
            let mut data: Vec<Option<Arc<dyn RangeSource>>> =
                sources(&RV).into_iter().map(Some).collect();
            data[1] = None;
            let set = RepairSet {
                data,
                recovery: vec![(&info, Arc::new(vector(rev)) as Arc<dyn RangeSource>)],
            };
            let rebuilt = Arc::new(Mutex::new(Vec::new()));
            let sink = rebuilt.clone();
            let report = rev5::repair(
                &set,
                &policy(),
                &mut |index| {
                    assert_eq!(index, 1);
                    Ok(Box::new(Slot(sink.clone())) as Box<dyn Write + Send>)
                },
                &mut (),
            )
            .unwrap();
            assert_eq!(report.rebuilt, vec![1], "{rev}");
            assert!(report.failed.is_empty());
            assert_eq!(*rebuilt.lock().unwrap(), vector("rv.part2.rar"), "{rev}");
        }
    }

    #[test]
    fn two_missing_volumes_need_two_rows() {
        let first = rev5::inspect(&vector("rv.part1.rev")).unwrap();
        let second = rev5::inspect(&vector("rv.part2.rev")).unwrap();
        let both: Vec<(&RevInfo, Arc<dyn RangeSource>)> = vec![
            (
                &first,
                Arc::new(vector("rv.part1.rev")) as Arc<dyn RangeSource>,
            ),
            (
                &second,
                Arc::new(vector("rv.part2.rev")) as Arc<dyn RangeSource>,
            ),
        ];
        let mut data: Vec<Option<Arc<dyn RangeSource>>> =
            sources(&RV).into_iter().map(Some).collect();
        data[0] = None;
        // The last volume is the short one, so its padding is exercised.
        data[2] = None;
        let set = RepairSet {
            data,
            recovery: both,
        };
        let out: BTreeMap<u32, Arc<Mutex<Vec<u8>>>> = BTreeMap::new();
        let out = Arc::new(Mutex::new(out));
        let sink = out.clone();
        let report = rev5::repair(
            &set,
            &policy(),
            &mut |index| {
                let slot = sink.lock().unwrap().entry(index).or_default().clone();
                Ok(Box::new(Slot(slot)) as Box<dyn Write + Send>)
            },
            &mut (),
        )
        .unwrap();
        assert_eq!(report.rebuilt, vec![0, 2]);
        let written = out.lock().unwrap();
        assert_eq!(*written[&0].lock().unwrap(), vector("rv.part1.rar"));
        assert_eq!(*written[&2].lock().unwrap(), vector("rv.part3.rar"));
    }

    #[test]
    fn two_missing_volumes_with_one_row_is_refused() {
        let info = rev5::inspect(&vector("rv.part1.rev")).unwrap();
        let mut data: Vec<Option<Arc<dyn RangeSource>>> =
            sources(&RV).into_iter().map(Some).collect();
        data[0] = None;
        data[1] = None;
        let set = RepairSet {
            data,
            recovery: vec![(
                &info,
                Arc::new(vector("rv.part1.rev")) as Arc<dyn RangeSource>,
            )],
        };
        let error = rev5::repair(&set, &policy(), &mut |_| unreachable!(), &mut ()).unwrap_err();
        assert!(
            matches!(
                error.kind(),
                ErrorKind::Recovery(RecoveryFailure::TooManyMissing {
                    missing: 2,
                    available: 1
                })
            ),
            "{error}"
        );
    }

    #[test]
    fn a_rev_from_another_set_is_a_mismatch() {
        let ours = rev5::inspect(&vector("rv.part1.rev")).unwrap();
        let theirs = rev5::inspect(&vector("rvodd.part1.rev")).unwrap();
        assert!(!ours.same_set(&theirs));
        let set = RepairSet {
            data: sources(&RV).into_iter().map(Some).collect(),
            recovery: vec![
                (
                    &ours,
                    Arc::new(vector("rv.part1.rev")) as Arc<dyn RangeSource>,
                ),
                (
                    &theirs,
                    Arc::new(vector("rvodd.part1.rev")) as Arc<dyn RangeSource>,
                ),
            ],
        };
        let error = rev5::repair(&set, &policy(), &mut |_| unreachable!(), &mut ()).unwrap_err();
        assert!(
            matches!(
                error.kind(),
                ErrorKind::Recovery(RecoveryFailure::SetMismatch)
            ),
            "{error}"
        );
    }

    #[test]
    fn a_present_but_wrong_volume_counts_as_missing() {
        let info = rev5::inspect(&vector("rv.part1.rev")).unwrap();
        let mut volumes = sources(&RV);
        let mut broken = vector("rv.part2.rar");
        broken[100] ^= 0xFF;
        volumes[1] = Arc::new(broken) as Arc<dyn RangeSource>;
        let set = RepairSet {
            data: volumes.into_iter().map(Some).collect(),
            recovery: vec![(
                &info,
                Arc::new(vector("rv.part1.rev")) as Arc<dyn RangeSource>,
            )],
        };
        let rebuilt = Arc::new(Mutex::new(Vec::new()));
        let sink = rebuilt.clone();
        let report = rev5::repair(
            &set,
            &policy(),
            &mut |_| Ok(Box::new(Slot(sink.clone())) as Box<dyn Write + Send>),
            &mut (),
        )
        .unwrap();
        assert_eq!(report.rebuilt, vec![1]);
        assert_eq!(*rebuilt.lock().unwrap(), vector("rv.part2.rar"));
    }

    /// A source that reports how many of its kind are being read at the
    /// same moment. Nothing here is timed: the count is taken on entry to
    /// every `read_at` and the peak is kept, and each read holds its place
    /// long enough for an overlap to be seen rather than raced past.
    struct Watched {
        bytes: Vec<u8>,
        live: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        peak: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl RangeSource for Watched {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            use std::sync::atomic::Ordering::SeqCst;
            let now = self.live.fetch_add(1, SeqCst) + 1;
            self.peak.fetch_max(now, SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(3));
            let got = (&self.bytes as &dyn RangeSource).read_at(offset, buf);
            self.live.fetch_sub(1, SeqCst);
            got
        }
        fn available(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn len(&self) -> Option<u64> {
            Some(self.bytes.len() as u64)
        }
    }

    /// **`rev5`'s whole-source stages hold the policy's ceiling on units
    /// in flight** (API 8.2: at most `max_workers` sources, one bounded
    /// read buffer each). Counted, not timed: the sources say how many of
    /// them were being read at once and the peak is compared against the
    /// ceiling.
    ///
    /// Both stages are covered, because both used to be unbounded in the
    /// same way: `create`'s table build handed the whole set to the pool,
    /// and `matches` read no policy at all.
    #[test]
    fn the_whole_source_stages_hold_the_policy_ceiling() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        use std::sync::Arc as StdArc;

        let count = 12usize;
        for workers in [1usize, 2, 4] {
            let policy = rarkit::MemoryPolicy {
                max_workers: workers,
                ..Default::default()
            };

            // `matches`.
            let live = StdArc::new(AtomicUsize::new(0));
            let peak = StdArc::new(AtomicUsize::new(0));
            let sources: Vec<Watched> = (0..count)
                .map(|i| Watched {
                    bytes: vec![i as u8; 4096],
                    live: live.clone(),
                    peak: peak.clone(),
                })
                .collect();
            let rows: Vec<rev5::DataVolume> = sources
                .iter()
                .map(|s| rev5::DataVolume {
                    size: s.bytes.len() as u64,
                    crc32: 0,
                })
                .collect();
            let targets: Vec<(&dyn RangeSource, &rev5::DataVolume)> = sources
                .iter()
                .zip(rows.iter())
                .map(|(s, r)| (s as &dyn RangeSource, r))
                .collect();
            let answers = rev5::matches(&targets, &policy);
            assert_eq!(answers.len(), count);
            let seen = peak.load(SeqCst);
            assert!(
                seen <= workers,
                "matches: {seen} sources read at once against a ceiling of {workers}"
            );
            // And the ceiling is REACHED, so that a stage which quietly
            // stopped running anything at once could not pass this.
            #[cfg(feature = "parallel")]
            assert!(
                seen >= workers.min(2),
                "matches: only {seen} at once with {workers} allowed and {count} to do"
            );

            // `create`'s table build, over the same sources.
            let live = StdArc::new(AtomicUsize::new(0));
            let peak = StdArc::new(AtomicUsize::new(0));
            let data: Vec<Arc<dyn RangeSource>> = (0..count)
                .map(|i| {
                    Arc::new(Watched {
                        bytes: vec![i as u8; 4096],
                        live: live.clone(),
                        peak: peak.clone(),
                    }) as Arc<dyn RangeSource>
                })
                .collect();
            let mut out: Vec<Vec<u8>> = Vec::new();
            rev5::create(&data, 1, &rev5::RevOptions { memory: policy }, &mut out).expect("create");
            let seen = peak.load(SeqCst);
            assert!(
                seen <= workers,
                "create: {seen} sources read at once against a ceiling of {workers}"
            );
            // And the ceiling is REACHED, so that a stage which quietly
            // stopped running anything at once could not pass this.
            #[cfg(feature = "parallel")]
            assert!(
                seen >= workers.min(2),
                "create: only {seen} at once with {workers} allowed and {count} to do"
            );
        }
    }

    #[test]
    fn matches_answers_size_and_crc() {
        let info = rev5::inspect(&vector("rv.part1.rev")).unwrap();
        let good = vector("rv.part1.rar");
        let mut bad = vector("rv.part2.rar");
        bad[0] ^= 1;
        let short = vector("rv.part3.rar");
        let targets = [
            (&good as &dyn RangeSource, &info.data_volumes[0]),
            (&bad as &dyn RangeSource, &info.data_volumes[1]),
            (&short as &dyn RangeSource, &info.data_volumes[0]),
        ];
        // Every ceiling gives the same answers in the same order: the
        // policy bounds how many targets are read at once and nothing
        // else (API 8.2).
        for workers in [1usize, 2, 8] {
            let policy = rarkit::MemoryPolicy {
                max_workers: workers,
                ..Default::default()
            };
            let answers: Vec<bool> = rev5::matches(&targets, &policy)
                .into_iter()
                .map(|a| a.unwrap())
                .collect();
            assert_eq!(answers, vec![true, false, false], "workers {workers}");
        }
    }

    #[test]
    fn parity_encode_is_the_code_the_files_hold() {
        let volumes: Vec<Vec<u8>> = RV.iter().map(|n| vector(n)).collect();
        let len = 16_384usize;
        let padded: Vec<Vec<u8>> = volumes
            .iter()
            .map(|v| {
                let mut p = v.clone();
                p.resize(len, 0);
                p
            })
            .collect();
        let shards: Vec<&[u8]> = padded.iter().map(|v| v.as_slice()).collect();
        let mut rows = vec![vec![0u8; len]; 2];
        let (first, rest) = rows.split_at_mut(1);
        let mut parity: Vec<&mut [u8]> = vec![&mut first[0], &mut rest[0]];
        rev5::parity::encode(&shards, &mut parity).unwrap();
        for (row, name) in ["rv.part1.rev", "rv.part2.rev"].iter().enumerate() {
            let file = vector(name);
            assert_eq!(rows[row], file[63..], "{name} payload");
        }
    }
}

/// The RAR 4 family's XOR-parity records (spec L 3.7).
///
/// No RAR 4 archive carrying one is available to this repository: the
/// genuine RAR 2.50 fixtures spec L 5 names have not been
/// copied in, and reference `rar` 7.23 no longer writes the RAR 4 format at
/// all (`-ma4` is gone). So these archives are built here from spec L
/// 3.7's own rules and read back by the scanner and the repairer, which
/// exercises every path but cannot confirm the LAYOUT against a genuine
/// file. That confirmation is still open.
mod legacy {
    use super::*;
    use rarkit::internals::recovery as l;

    const SIGNATURE: [u8; 7] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];

    fn filler(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + 3) as u8).collect()
    }

    /// A block header's own CRC16: the low 16 bits of the CRC32 of
    /// everything after it (spec L section 1).
    fn seal(head: &mut [u8]) {
        let crc = rarkit::checksum::crc32(&head[2..]) as u16;
        head[..2].copy_from_slice(&crc.to_le_bytes());
    }

    /// An archive of `payload` bytes carrying a RAR 2.x protect header.
    fn protect_archive(payload: usize, percent: u32) -> Vec<u8> {
        let mut archive = SIGNATURE.to_vec();
        archive.extend_from_slice(&filler(payload));
        let (area, sectors, parity) = l::legacy_rr_build(&archive, percent).unwrap();
        let mut head = [0u8; 26];
        head[2] = 0x78;
        head[3..5].copy_from_slice(&0x8000u16.to_le_bytes());
        head[5..7].copy_from_slice(&26u16.to_le_bytes());
        head[7..11].copy_from_slice(&(area.len() as u32).to_le_bytes());
        head[11] = 20;
        head[12..14].copy_from_slice(&(parity as u16).to_le_bytes());
        head[14..18].copy_from_slice(&(sectors as u32).to_le_bytes());
        head[18..26].copy_from_slice(b"Protect!");
        seal(&mut head);
        archive.extend_from_slice(&head);
        archive.extend_from_slice(&area);
        archive
    }

    /// The same, as a RAR 3.x `RR` subblock behind one filler block.
    fn subblock_archive(payload: usize, percent: u32) -> Vec<u8> {
        let mut archive = SIGNATURE.to_vec();
        let mut file = vec![0u8; 20];
        file[2] = 0x74;
        file[3..5].copy_from_slice(&0x8000u16.to_le_bytes());
        file[5..7].copy_from_slice(&20u16.to_le_bytes());
        file[7..11].copy_from_slice(&(payload as u32).to_le_bytes());
        seal(&mut file);
        archive.extend_from_slice(&file);
        archive.extend_from_slice(&filler(payload));
        let (area, sectors, parity) = l::legacy_rr_build(&archive, percent).unwrap();
        archive.extend_from_slice(&record_subblock(area.len(), parity, sectors));
        archive.extend_from_slice(&area);
        archive
    }

    /// A RAR 3.x subblock header (type 0x7A) named `name`, for a data area
    /// of `data` bytes: the file header's layout, with the name's length
    /// at offset 26 and the name at 32, as the genuine `r393_rr.rar`
    /// carries it.
    fn subblock(name: &[u8], data: usize) -> Vec<u8> {
        let mut head = vec![0u8; 32 + name.len()];
        head[2] = 0x7A;
        head[3..5].copy_from_slice(&0x8000u16.to_le_bytes());
        let size = head.len() as u16;
        head[5..7].copy_from_slice(&size.to_le_bytes());
        head[7..11].copy_from_slice(&(data as u32).to_le_bytes());
        head[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
        head[32..].copy_from_slice(name);
        seal(&mut head);
        head
    }

    /// The `RR` subblock's header as every genuine writer makes it (spec
    /// L 3.7): the name, then the eight bytes `Protect+`, `r`, `n` and
    /// four zero bytes, which is where a reader takes `r` and `n` from.
    fn record_subblock(data: usize, parity: u64, sectors: u64) -> Vec<u8> {
        let mut head = subblock(b"RR", data);
        head.extend_from_slice(b"Protect+");
        head.extend_from_slice(&(parity as u32).to_le_bytes());
        head.extend_from_slice(&(sectors as u32).to_le_bytes());
        head.extend_from_slice(&[0u8; 4]);
        let size = head.len() as u16;
        head[5..7].copy_from_slice(&size.to_le_bytes());
        seal(&mut head);
        head
    }

    /// A RAR 3.x archive whose comment subblock, right after the main
    /// header, has a data area of exactly the length a recovery record
    /// over the bytes before it would have (two bytes of tag for its one
    /// sector, then one parity sector), followed by a file and the real
    /// `RR` subblock.
    fn commented_archive(payload: usize, percent: u32) -> Vec<u8> {
        let mut archive = SIGNATURE.to_vec();
        let mut main = [0u8; 13];
        main[2] = 0x73;
        main[5..7].copy_from_slice(&13u16.to_le_bytes());
        seal(&mut main);
        archive.extend_from_slice(&main);
        archive.extend_from_slice(&subblock(b"CMT", 514));
        archive.extend_from_slice(&filler(514));
        let mut file = vec![0u8; 32];
        file[2] = 0x74;
        file[3..5].copy_from_slice(&0x8000u16.to_le_bytes());
        file[5..7].copy_from_slice(&32u16.to_le_bytes());
        file[7..11].copy_from_slice(&(payload as u32).to_le_bytes());
        seal(&mut file);
        archive.extend_from_slice(&file);
        archive.extend_from_slice(&filler(payload));
        let (area, sectors, parity) = l::legacy_rr_build(&archive, percent).unwrap();
        archive.extend_from_slice(&record_subblock(area.len(), parity, sectors));
        archive.extend_from_slice(&area);
        archive
    }

    /// Spec L 3.7: the record is the subblock NAMED `RR`. A comment
    /// subblock whose data length happens to be `2n + 512r` for the bytes
    /// before it is not the record, and the real one after the files is
    /// what a repair works from. Single threaded, a few KiB.
    #[test]
    fn a_comment_subblock_is_not_taken_for_the_record() {
        let archive = commented_archive(5_000, 30);
        let (header_at, _, sectors, _) = l::legacy_rr_scan(&archive).unwrap();
        assert_eq!(header_at, 7 + 13 + 35 + 514 + 32 + 5_000, "the RR subblock");
        assert_eq!(sectors, header_at.div_ceil(512));

        // Undamaged: nothing rebuilt and nothing failed.
        let mut out = Vec::new();
        let report = rarkit::recovery::repair_inline(&archive, &options(), &mut out).unwrap();
        assert_eq!(out, archive);
        assert!(
            report.failed.is_empty(),
            "an undamaged archive fails nothing"
        );
        assert!(report.rebuilt.is_empty());

        // Damaged in the file's data: the real record mends it.
        let mut broken = archive.clone();
        broken[3_000] ^= 0xFF;
        let mut out = Vec::new();
        let report = rarkit::recovery::repair_inline(&broken, &options(), &mut out).unwrap();
        assert_eq!(out, archive, "the damage is mended");
        assert_eq!(report.rebuilt, vec![0]);
        assert!(report.failed.is_empty());
    }

    fn repaired(archive: &[u8]) -> rarkit::Result<(Vec<u8>, rarkit::rev5::RepairReport)> {
        let mut out = Vec::new();
        let report = l::legacy_rr_repair(&archive.to_vec(), &policy(), &mut out)?;
        Ok((out, report))
    }

    #[test]
    fn the_record_is_found_and_its_counts_derived() {
        let archive = protect_archive(5_000, 5);
        let (header_at, data_at, sectors, parity) = l::legacy_rr_scan(&archive).unwrap();
        assert_eq!(header_at, 5_007, "the signature plus the payload");
        assert_eq!(data_at, header_at + 26);
        assert_eq!(sectors, 10, "ceil(5007 / 512)");
        assert_eq!(parity, 1, "floor(10 x 5 / 100), at least one");

        let archive = subblock_archive(5_000, 30);
        let (header_at, data_at, sectors, parity) = l::legacy_rr_scan(&archive).unwrap();
        assert_eq!(header_at, 5_027);
        assert_eq!(
            data_at,
            header_at + 54,
            "the header every genuine writer makes"
        );
        assert_eq!(sectors, 10);
        assert_eq!(parity, 3);
    }

    #[test]
    fn repair_through_the_public_entry_point() {
        // Both families reach the same place through `repair_inline`.
        for archive in [protect_archive(5_000, 50), subblock_archive(5_000, 50)] {
            let mut broken = archive.clone();
            broken[1_000] ^= 0xFF;
            let mut out = Vec::new();
            let report = rarkit::recovery::repair_inline(&broken, &options(), &mut out).unwrap();
            assert_eq!(out, archive);
            assert_eq!(report.rebuilt, vec![0]);
        }
    }

    /// Spec L 8.1: the old engine repaired only sectors wholly before the
    /// record's header, so the final PARTIAL sector was lost. It is
    /// covered like any other, and this engine repairs it.
    #[test]
    fn the_final_partial_sector_is_repaired() {
        // 5,007 protected bytes: sector 9 holds 399 of its 512.
        let archive = protect_archive(5_000, 100);
        let mut broken = archive.clone();
        broken[5_006] ^= 0xFF;
        assert_ne!(broken, archive);
        let (out, report) = repaired(&broken).unwrap();
        assert_eq!(out, archive, "the partial sector came back");
        assert_eq!(report.rebuilt, vec![0]);
    }

    #[test]
    fn one_damaged_sector_per_class_is_the_limit() {
        // 10 sectors, 5 classes: sectors 0 and 5 share class 0.
        let archive = protect_archive(5_000, 50);
        let (_, _, sectors, parity) = l::legacy_rr_scan(&archive).unwrap();
        assert_eq!((sectors, parity), (10, 5));

        let mut ok = archive.clone();
        for sector in [0u64, 1, 2, 3, 4] {
            ok[(sector * l::SECTOR) as usize + 8] ^= 0x5A;
        }
        assert_eq!(repaired(&ok).unwrap().0, archive, "one per class");

        let mut clash = archive.clone();
        clash[8] ^= 0x5A;
        clash[(5 * l::SECTOR) as usize + 8] ^= 0x5A;
        let error = repaired(&clash).unwrap_err();
        assert!(
            matches!(
                error.kind(),
                ErrorKind::Recovery(RecoveryFailure::TooManyMissing { .. })
            ),
            "{error}"
        );
    }

    /// The name check against the genuine `RR` subblocks of rar 3.9.3,
    /// 4.2.0 and 5.5.0 (`fixtures/legacy/MANIFEST.tsv`): each is found
    /// where its header sits, and mends a damaged byte. Single threaded,
    /// under a MiB.
    #[test]
    fn the_genuine_rr_subblocks_are_found_by_name() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/legacy/archives"
        );
        for (name, at, parity) in [
            ("r393_rr.rar", 68_935u64, 2u64),
            ("r420_rr.rar", 68_782, 2),
            ("r550_rr.rar", 68_754, 5),
        ] {
            let archive = std::fs::read(format!("{dir}/{name}")).expect(name);
            let found = l::legacy_rr_scan(&archive).unwrap();
            assert_eq!(found, (at, at + 54, at.div_ceil(512), parity), "{name}");
            let mut broken = archive.clone();
            broken[40_000] ^= 0xFF;
            let (out, report) = repaired(&broken).unwrap();
            assert_eq!(out, archive, "{name}");
            assert_eq!(report.rebuilt, vec![0], "{name}");
        }
    }

    /// A volume that is zeros except for a head and a tail, so a member of
    /// more than 4 GiB costs this test no memory for its data.
    struct Sparse {
        head: Vec<u8>,
        tail_at: u64,
        tail: Vec<u8>,
    }

    impl RangeSource for Sparse {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let end = self.tail_at + self.tail.len() as u64;
            let want = (end.saturating_sub(offset)).min(buf.len() as u64) as usize;
            let buf = &mut buf[..want];
            buf.fill(0);
            for (at, bytes) in [(0, &self.head), (self.tail_at, &self.tail)] {
                let from = offset.max(at);
                let to = (offset + want as u64).min(at + bytes.len() as u64);
                if from < to {
                    buf[(from - offset) as usize..(to - offset) as usize]
                        .copy_from_slice(&bytes[(from - at) as usize..(to - at) as usize]);
                }
            }
            Ok(want)
        }
        fn available(&self) -> u64 {
            self.tail_at + self.tail.len() as u64
        }
        fn len(&self) -> Option<u64> {
            Some(self.available())
        }
    }

    /// Spec F 3.3.6: flag 0x0100 on a file header says the high halves of
    /// its sizes follow, and the block walk has to step over the whole
    /// packed size or it never reaches the `RR` subblock behind a member
    /// of 4 GiB or more. The member here is 4 GiB + 1,000 bytes of zeros
    /// held by nobody; the record's tags are 17 MiB, and the scan checks
    /// every sector's tag once, single threaded: about 20 s in a debug
    /// build on an Apple M5 Max, which is the price of a real 4 GiB walk.
    #[test]
    fn the_walk_steps_over_a_member_of_more_than_four_gib() {
        const PACKED: u64 = (1 << 32) + 1_000;
        let mut head = SIGNATURE.to_vec();
        let mut file = vec![0u8; 40];
        file[2] = 0x74;
        file[3..5].copy_from_slice(&0x8100u16.to_le_bytes());
        file[5..7].copy_from_slice(&40u16.to_le_bytes());
        file[7..11].copy_from_slice(&(PACKED as u32).to_le_bytes());
        file[32..36].copy_from_slice(&((PACKED >> 32) as u32).to_le_bytes());
        seal(&mut file);
        head.extend_from_slice(&file);

        // The record over the protected bytes, by spec L 3.7's rules, with
        // one parity sector: every sector but the first and the last is
        // zeros, so they share one tag and leave the parity alone.
        let header_at = head.len() as u64 + PACKED;
        let sectors = header_at.div_ceil(512);
        let padded = |bytes: &[u8]| {
            let mut sector = [0u8; 512];
            sector[..bytes.len()].copy_from_slice(bytes);
            sector
        };
        let tag = |sector: &[u8; 512]| (!rarkit::checksum::crc32(sector) as u16).to_le_bytes();
        let first = padded(&head);
        // The last sector is partial and all zeros, as the middle ones are.
        let zero = tag(&[0u8; 512]);
        let mut area = Vec::with_capacity(2 * sectors as usize + 512);
        area.extend_from_slice(&tag(&first));
        for _ in 1..sectors {
            area.extend_from_slice(&zero);
        }
        area.extend_from_slice(&first);

        let mut tail = record_subblock(area.len(), 1, sectors);
        tail.extend_from_slice(&area);
        let volume = Sparse {
            head,
            tail_at: header_at,
            tail,
        };
        let chunks = rarkit::recovery::scan_inline(&volume).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(
            chunks[0].range,
            header_at + 54..header_at + 54 + 2 * sectors + 512
        );
    }

    #[test]
    fn an_undamaged_archive_comes_back_unchanged() {
        let archive = protect_archive(1_500, 20);
        let (out, report) = repaired(&archive).unwrap();
        assert_eq!(out, archive);
        assert!(report.rebuilt.is_empty());
    }

    #[test]
    fn scan_inline_lists_the_data_area() {
        let archive = protect_archive(2_000, 10);
        let chunks = rarkit::recovery::scan_inline(&archive).unwrap();
        assert_eq!(chunks.len(), 1);
        let (_, data_at, sectors, parity) = l::legacy_rr_scan(&archive).unwrap();
        assert_eq!(
            chunks[0].range,
            data_at..data_at + 2 * sectors + 512 * parity
        );
    }

    #[test]
    fn an_archive_with_no_record_says_so() {
        let mut archive = SIGNATURE.to_vec();
        archive.extend_from_slice(&filler(3_000));
        let error = l::legacy_rr_scan(&archive).unwrap_err();
        assert!(matches!(
            error.kind(),
            ErrorKind::Recovery(RecoveryFailure::NoRecord)
        ));
    }

    #[test]
    fn a_budget_too_small_for_the_data_area_is_refused_first() {
        let archive = protect_archive(5_000, 100);
        let mut tight = policy();
        tight.repair_limit = 64;
        let mut out = Vec::new();
        let error = l::legacy_rr_repair(&archive.to_vec(), &tight, &mut out).unwrap_err();
        assert!(
            matches!(
                error.kind(),
                ErrorKind::LimitExceeded {
                    resource: rarkit::Resource::RepairWork,
                    ..
                }
            ),
            "{error}"
        );
        assert!(out.is_empty(), "nothing written before the refusal");
    }
}

/// The checksum half's vectors (spec L 5.1 and 5.3) and the one oracle
/// adapter that exists.
mod checksums {
    use super::*;
    use rarkit::internals::recovery as l;

    fn hex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// Spec L 5.3: reference `rar` 7.23's own `-htb` digests, for the
    /// inputs committed beside them.
    #[test]
    fn blake2sp_matches_the_reference_digests() {
        for (name, want) in [
            (
                "b0.bin",
                "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f",
            ),
            (
                "b1.bin",
                "456da349adc8eaa1ee5fd8397d9c181c21a8e9173ad90f22613fd34e1d576d44",
            ),
            (
                "b64.bin",
                "e375bba69fb1c84c7f202f06e71090695f81786b7413da0cd0126e15a0f80181",
            ),
            (
                "b511.bin",
                "63a8cc6d628b88d471d4f81035b367f62b8a14dbf55bd9cca0d945dae8e226cf",
            ),
            (
                "b512.bin",
                "201135254f94f0cf5307da6ae28daf819258fd08df8249684ffbbded6c23e0e5",
            ),
            (
                "b513.bin",
                "4524c7cfa3a7cde180691ba1a3c0d4b9fc20ced214f27e65f5c76dbb0ff44c91",
            ),
            (
                "b4096.bin",
                "3f24ed36a1ecaa90c53a5e2568dfb42198cc5d852cd1fe5210f64b3d36989483",
            ),
            (
                "b4097.bin",
                "bbb0935c0ad88571fece336d8d4a3782c795821491ba9d86392236920288c8dd",
            ),
            (
                "data.bin",
                "ee89fcc4ec33fa184bd925d48f54171034cd1057372b93eef6da9fcc782df3d2",
            ),
        ] {
            let data = vector(&format!("in/{name}"));
            assert_eq!(l::blake2sp(&data), hex(want), "{name} one shot");
            // Every arrangement, and a chunking that splits both a block
            // and a group.
            for workers in [1usize, 8] {
                for step in [1usize, 7, 64, 100, 512, 4_096] {
                    let mut hasher = l::Blake2sp::with_workers(workers);
                    for chunk in data.chunks(step) {
                        hasher.update(chunk);
                    }
                    assert_eq!(hasher.finalize(), hex(want), "{name} {workers}/{step}");
                }
            }
        }
    }

    /// Spec L 5.1.
    #[test]
    fn crc_check_values() {
        assert_eq!(rarkit::checksum::crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(rarkit::checksum::crc32(b""), 0);
        assert_eq!(l::crc64_xz(b"123456789"), 0x995D_C9BB_DF19_39FA);
        assert_eq!(l::crc64_register(b""), 0);
        // Both forms over inputs made here, against the bit-at-a-time
        // division below: lengths under one table round, off a multiple of
        // eight, past the fold's floor, and past two passes of the widest
        // fold (1,024 bytes) with a tail under one block.
        let mut state = 0x6A09_E667u32;
        let made: Vec<u8> = (0..2_061)
            .map(|_| {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (state >> 16) as u8
            })
            .collect();
        for len in [3usize, 13, 64, 257, 778, 2_061] {
            let input = &made[..len];
            assert_eq!(
                l::crc64_register(input),
                crc64_by_division(0, input),
                "raw register, {len} bytes"
            );
            assert_eq!(
                l::crc64_xz(input),
                !crc64_by_division(!0, input),
                "CRC-64/XZ, {len} bytes"
            );
        }
    }

    /// Spec L 3.2 by its parameters alone: ECMA-182 in normal form
    /// dividing the message one bit at a time, highest degree first. The
    /// format's bit order (LSB first) is met by reversing each byte going
    /// in and the 64-bit remainder coming out.
    fn crc64_by_division(start: u64, data: &[u8]) -> u64 {
        let divisor = 0x42F0_E1EB_A9EA_3693u64;
        let mut remainder = start.reverse_bits();
        for &byte in data {
            remainder ^= u64::from(byte.reverse_bits()) << 56;
            for _ in 0..8 {
                let top = remainder >> 63;
                remainder = (remainder << 1) ^ (divisor & top.wrapping_neg());
            }
        }
        remainder.reverse_bits()
    }

    /// Spec L 5.2.
    #[test]
    fn the_codes_first_row() {
        assert_eq!(
            [
                l::cauchy_cell(40, 0, 0),
                l::cauchy_cell(40, 0, 1),
                l::cauchy_cell(40, 0, 2),
                l::cauchy_cell(40, 0, 3)
            ],
            [0xC607, 0x8766, 0x61E4, 0x491C]
        );
    }

    #[cfg(feature = "oracle-compare")]
    /// The one oracle adapter spec L section 6 says is already there.
    /// The rest (`blake2sp`, `rr5_record`, `rev_create`, `repair_inline`,
    /// `rev_repair`) are not there yet; until they exist the
    /// differentials above run from the committed reference files, which
    /// reference `rar` wrote rather than either engine.
    #[test]
    fn crc32_against_the_old_engine() {
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let big: Vec<u8> = (0..(3 << 20)).map(|_| next() as u8).collect();
        for len in [
            0usize,
            1,
            2,
            3,
            63,
            64,
            65,
            1_023,
            4_096,
            1 << 20,
            big.len(),
        ] {
            let data = &big[..len];
            assert_eq!(rarkit::checksum::crc32(data), rarkit_oracle::crc32(data));
            // The piece-parallel path must give the one-pass answer too.
            let pieces: Vec<&[u8]> = data.chunks(97_003.min(len.max(1))).collect();
            for workers in [1usize, 4, 16] {
                assert_eq!(
                    l::crc32_pieces(&pieces, workers),
                    rarkit_oracle::crc32(data)
                );
            }
        }
        for file in ["rr5_small.rar", "rv.part1.rev", "blake_sizes.rar"] {
            let bytes = vector(file);
            assert_eq!(
                rarkit::checksum::crc32(&bytes),
                rarkit_oracle::crc32(&bytes),
                "{file}"
            );
        }
    }
}

/// Spec L 5.4's last row: the TWO-GROUP geometry, whose archive is too
/// large to commit (16 MB). The test writes it with reference `rar` 7.23
/// when that is installed, and skips when it is not. The bytes differ per
/// run, which is the point: only the geometry and this file's rules are
/// under test.
///
/// The protected prefix `P` is READ from the reference's own bytes and
/// never assumed, because it is not a constant of the input: the RAR 5
/// file header stores the file attributes as a vint, and that field's
/// WIDTH is a property of the host, appearing twice in the prefix (the
/// file header, and the copy of it inside the quick-open `QO` service
/// header). Measured at 16,000,000 data bytes with reference `rar` 7.23:
/// a Unix mode 0o100644 = 33,188 is three bytes and `P` is 16,000,162;
/// Windows `FILE_ATTRIBUTE_ARCHIVE` = 0x20 is one byte and `P` is
/// 16,000,158; the same file with `NOT_CONTENT_INDEXED` also set, 0x2020,
/// is two bytes and `P` is 16,000,160. Spec L 3.5.1's geometry is the
/// same for all three, and 3.5.2's `extent` is the one field that moves,
/// so this test derives that one from `P` by 3.5.2's own rule.
#[test]
fn the_two_group_case_against_reference_rar() {
    use rarkit::internals::recovery as l;

    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/vectors-l");
    std::fs::create_dir_all(&dir).unwrap();
    let archive = dir.join("big_rr.rar");
    if !archive.exists() {
        let input = dir.join("big.bin");
        // 16,000,000 bytes, which puts the prefix just past 16,000,000
        // whatever the host writes in the attributes field.
        let mut x: u64 = 0x1357_9BDF_2468_ACE0;
        let filler: Vec<u8> = (0..16_000_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        std::fs::write(&input, filler).unwrap();
        let ok = std::process::Command::new("rar")
            .current_dir(&dir)
            .args(["a", "-ma5", "-m0", "-rr3", "-idq", "-y"])
            .arg("big_rr.rar")
            .arg("big.bin")
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            eprintln!("skipped: reference `rar` is not installed");
            let _ = std::fs::remove_file(&input);
            return;
        }
    }
    let file = std::fs::read(&archive).unwrap();
    let marker = file
        .windows(4)
        .position(|w| w == b"{RB}")
        .expect("a record marker");
    let protected = u64::from_le_bytes(file[marker + 0x22..marker + 0x2A].try_into().unwrap());
    // Spec L 3.5.1 gives `G = ceil(P / 200)` rounded up to even, so the
    // 5.4 row's geometry holds for every prefix in this band, and the
    // band is what the host's attribute width can move the prefix within.
    assert!(
        (16_000_001..=16_000_400).contains(&protected),
        "the prefix spec L 5.4 names, within the band its geometry holds \
         over: {protected}"
    );
    let (k, m, shard, groups, header, span) = l::rr5_geometry(protected, 3).unwrap();
    assert_eq!(
        (k, m, shard, groups, header, span),
        (200, 6, 80_002, 2, 1_672, 83_346)
    );

    let mut ours = l::rr5_encode(&file[..protected as usize], 3).unwrap();
    assert_eq!(ours.len() as u64, u64::from(m) * span);
    // Record (row 0, group 1): 16,138 bytes, group offset 65,536, and an
    // extent of spec L 3.5.2's `min(max(0, r - offset), group length)`
    // with `r = P - (k - 1) G` the last data shard's real bytes, which is
    // 14,228 at the 16,000,162 prefix the macOS `rar` writes.
    let last_shard_real = protected - u64::from(k - 1) * shard;
    let extent = last_shard_real.saturating_sub(65_536).min(14_466) as u32;
    let second = header as usize + 65_536;
    assert_eq!(
        u32::from_le_bytes(ours[second + 0x0C..second + 0x10].try_into().unwrap()),
        16_138
    );
    assert_eq!(
        u64::from_le_bytes(ours[second + 0x16..second + 0x1E].try_into().unwrap()),
        65_536
    );
    assert_eq!(
        u32::from_le_bytes(ours[second + 0x1E..second + 0x22].try_into().unwrap()),
        extent
    );

    // Every byte but the clock-derived set tag (question 3).
    let theirs = &file[marker..marker + ours.len()];
    let table_end = 0x40 + 8 * usize::from(k);
    let tag = u64::from_le_bytes(theirs[table_end..table_end + 8].try_into().unwrap());
    let mut at = 0usize;
    for row in 0..m {
        for group in 0..groups {
            let len = header as usize
                + if group == 0 {
                    65_536
                } else {
                    shard as usize - 65_536
                };
            ours[at + table_end..at + table_end + 8].copy_from_slice(&tag.to_le_bytes());
            let crc = l::crc64_xz(&ours[at + 0x0C..at + len]);
            ours[at + 4..at + 12].copy_from_slice(&crc.to_le_bytes());
            assert_eq!(
                ours[at..at + len],
                theirs[at..at + len],
                "row {row} group {group}"
            );
            at += len;
        }
    }
    assert_eq!(at, ours.len());
}

/// Spec L 3.8's memory bound, as the engine reports it: working memory
/// depends on the damage count and the stripe, never on the size of the
/// set, and a budget too small for the minimum stripe is refused before
/// any payload is read.
#[test]
fn a_repair_reports_the_working_memory_it_used() {
    use rarkit::internals::recovery as l;

    let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7 + 3) as u8).collect();
    let mut volume = data.clone();
    volume.extend_from_slice(&l::rr5_encode(&data, 20).unwrap());
    let (k, m, shard, groups, _h, _span) = l::rr5_geometry(data.len() as u64, 20).unwrap();
    assert_eq!((k, m, groups), (200, 40, 1));
    for j in [3u16, 40, 150] {
        volume[(u64::from(j) * shard) as usize] ^= 0xFF;
    }
    let (out, report) = repair(&volume).unwrap();
    assert_eq!(out, volume_repaired(&volume, &data));
    assert_eq!(report.rebuilt, vec![0]);
    // Three damaged slices of one group: `(2d + 2) w` for the stripe plus
    // the three rebuilt slices held for their checks.
    let group = shard.min(65_536);
    assert_eq!(report.peak_working_memory, (2 * 3 + 2) * group + 3 * group);
}

/// The volume as it should come back: the protected prefix intact, the
/// record untouched.
fn volume_repaired(volume: &[u8], data: &[u8]) -> Vec<u8> {
    let mut want = data.to_vec();
    want.extend_from_slice(&volume[data.len()..]);
    want
}
