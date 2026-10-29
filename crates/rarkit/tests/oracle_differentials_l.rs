//! Spec L section 6's differential plan, run against the old engine
//! through `rarkit-oracle`.
//!
//! The oracle is reached by its RUSTDOC (`cargo doc -p rarkit-oracle`) and
//! by CALLS only; no source of it was opened to write this file.
//!
//! Where the two engines disagree, rarkit is NOT bent to match. Spec L
//! decides, and where the specification leans on it, reference `rar` 7.23's
//! own bytes in `specs/vectors-L`. A difference that spec L accounts for is
//! pinned here by a test naming the section, so that a later change to
//! either side has to argue with the specification rather than with a
//! silent expectation.
// The exporter cut the cases of this file that need a crate this tree
// does not have; imports and helpers only they used are left in place.
#![allow(unused_imports, dead_code, unused_macros)]

use rarkit_testdata::Seeded;
use std::sync::Arc;

use rarkit::memory::MemoryPolicy;
use rarkit::{RangeSource, ReadOptions, RecoveryFailure, SplitCheck};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../specs/vectors-L");

fn vector(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}/{name}")).expect("spec L vector")
}

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

/// Spec L 3.3, 3.1: the checksums over random inputs with random chunking.
mod checksums {
    use super::*;
}

/// Spec L 3.5: the inline record's data area.
mod inline_record {
    use super::*;

    const FULL: [u32; 100] = {
        let mut all = [0u32; 100];
        let mut i = 0;
        while i < 100 {
            all[i] = i as u32 + 1;
            i += 1;
        }
        all
    };

    /// The geometry both engines are working to, so a disagreement above
    /// can be read against spec L 3.5.1 rather than guessed at.
    #[test]
    fn the_geometry_is_spec_l_3_5_1s() {
        let g = |p, pct| rarkit::internals::recovery::rr5_geometry(p, pct).unwrap();
        assert_eq!(g(40_218, 5), (40, 2, 1_006, 1, 392, 1_398));
        assert_eq!(g(16_000_162, 3), (200, 6, 80_002, 2, 1_672, 83_346));
        assert_eq!(g(97, 100), (1, 1, 98, 1, 80, 178));
    }
}

/// Where rarkit, the old engine and reference `rar` 7.23 part, and why the
/// specification says each is right.
mod pinned_differences {
    use super::*;

    /// The reference archives' own record bytes.
    fn reference_area(name: &str, protected: usize, pct: u32) -> (Vec<u8>, Vec<u8>) {
        let whole = vector(name);
        let at = whole
            .windows(4)
            .position(|w| w == b"{RB}")
            .expect("a record marker");
        let mine = rarkit::internals::recovery::rr5_encode(&whole[..protected], pct).unwrap();
        let real = whole[at..at + mine.len()].to_vec();
        (mine, real)
    }

    /// **Spec L question 3, and section 3.5.2's layout.**
    ///
    /// Reference `rar` 7.23 derives the 8-byte set tag at `0x40 + 8k` from
    /// a clock. Spec L question 3 replaces it with a content-derived value
    /// so that a writer is deterministic (API promise 2.6), and the record's
    /// own CRC-64 at `0x04` covers the tag, so it moves with it.
    ///
    /// So rarkit differs from `rar` in EXACTLY those two fields per record
    /// and nowhere else. This test pins that: the whole data area matches
    /// byte for byte once the tag and the CRC-64 over it are set aside, and
    /// the per-shard CRC-64 table - INCLUDING the final, partial shard's
    /// entry at `0x40 + 8(k - 1)` - matches `rar` exactly.
    #[test]
    fn rarkit_differs_from_reference_rar_in_the_set_tag_alone() {
        for (name, protected, pct, k, m, span) in [
            (
                "rr5_small.rar",
                40_218usize,
                5u32,
                40usize,
                2usize,
                1_398usize,
            ),
            ("rr100_small.rar", 97, 100, 1, 1, 178),
        ] {
            let (mine, real) = reference_area(name, protected, pct);
            assert_eq!(mine.len(), real.len(), "{name}");

            let tag = 0x40 + 8 * k;
            let last_entry = 0x40 + 8 * (k - 1);
            let mut expected: Vec<usize> = Vec::new();
            for row in 0..m {
                let base = row * span;
                expected.extend(base + 0x04..base + 0x0C);
                expected.extend(base + tag..base + tag + 8);
            }
            let differing: Vec<usize> = (0..mine.len()).filter(|&i| mine[i] != real[i]).collect();
            assert_eq!(differing, expected, "{name}: only the tag and its CRC-64");

            for row in 0..m {
                let base = row * span;
                assert_eq!(
                    mine[base + last_entry..base + last_entry + 8],
                    real[base + last_entry..base + last_entry + 8],
                    "{name} row {row}: the FINAL PARTIAL shard's CRC-64 table entry \
                     matches reference rar (spec L 3.5.2: real bytes only)"
                );
            }
        }
    }

    /// The tags `rar` wrote are the clock values spec L question 3 quotes,
    /// which is the evidence that the field is a clock and not content.
    #[test]
    fn set_tags_written_by_the_genuine_rar_program_are_the_clock_values_question_3_names() {
        let tag_of = |name: &str, protected: usize, pct: u32, k: usize| {
            let (_, real) = reference_area(name, protected, pct);
            let at = 0x40 + 8 * k;
            u64::from_le_bytes(real[at..at + 8].try_into().unwrap())
        };
        assert_eq!(
            tag_of("rr5_small.rar", 40_218, 5, 40),
            0x4d21_87dc_0e6f_a9c6
        );
        assert_eq!(tag_of("rr100_small.rar", 97, 100, 1), 0x4d21_87dc_0e6f_aa86);
    }
}

/// Spec L 3.6: `.rev` recovery volumes.
mod rev_volumes {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::sync::Mutex;

    use rarkit::rev5::{self, RepairSet, RevInfo, RevOptions};
    use rarkit::VolumeOut;

    /// A [`VolumeOut`] that keeps every volume in memory.
    #[derive(Default)]
    pub struct Collect {
        volumes: BTreeMap<u32, Arc<Mutex<Vec<u8>>>>,
    }

    pub struct Slot(pub Arc<Mutex<Vec<u8>>>);

    /// The volumes a rebuild writes, by index.
    type Rebuilt = Arc<Mutex<BTreeMap<u32, Arc<Mutex<Vec<u8>>>>>>;

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
            Ok(Slot(self.volumes.entry(index).or_default().clone()))
        }
    }

    impl Collect {
        fn take(&self, index: u32) -> Vec<u8> {
            self.volumes[&index].lock().unwrap().clone()
        }
    }

    fn sources(volumes: &[Vec<u8>]) -> Vec<Arc<dyn RangeSource>> {
        volumes
            .iter()
            .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
            .collect()
    }

    pub fn create(volumes: &[Vec<u8>], count: u32) -> Vec<Vec<u8>> {
        let mut out = Collect::default();
        let report = rev5::create(
            &sources(volumes),
            count,
            &RevOptions { memory: policy() },
            &mut out,
        )
        .expect("rarkit writes the set");
        assert_eq!(report.volumes, count);
        (0..count).map(|i| out.take(i)).collect()
    }
}

/// Spec L 3.5.5, 3.8: scan and repair from an inline record, under random
/// damage, on records written by both engines and by reference `rar`.
mod repair {
    use super::*;

    fn rarkit_repair(volume: &[u8]) -> rarkit::Result<Vec<u8>> {
        let mut out = Vec::new();
        let src: Arc<dyn RangeSource> = Arc::new(volume.to_vec());
        rarkit::recovery::repair_inline(&src, &options(), &mut out)?;
        Ok(out)
    }

    /// A volume is the protected prefix, the `RR` service header and the
    /// record area, as an archive lays them out: the header at `P` is
    /// what says the records are this file's when shard 0 is among the
    /// damaged (spec L 3.5.5 O1 and O7).
    fn volume(prefix: &[u8], area: &[u8]) -> Vec<u8> {
        let mut v = prefix.to_vec();
        v.extend_from_slice(&rarkit::internals::recovery::rr5_service_header(
            area.len() as u64,
            1,
        ));
        v.extend_from_slice(area);
        v
    }

    /// Damage `slices` distinct shards, each in a random place.
    fn damage(v: &mut [u8], rng: &mut Seeded, shard_len: usize, shards: &[usize]) {
        for &s in shards {
            let at = s * shard_len + rng.index(shard_len.min(64));
            let run = rng.index(48) + 1;
            for i in 0..run {
                if at + i < v.len() {
                    v[at + i] ^= 0xA5;
                }
            }
        }
    }
}
