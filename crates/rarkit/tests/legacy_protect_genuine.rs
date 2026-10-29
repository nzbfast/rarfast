//! Spec L 3.7 and section 8 item 1, against GENUINE RAR 2.50 protect
//! records written by RARLAB's own DOS build.
//!
//! The archives come from `fixtures/legacy` (its README, and `MANIFEST.tsv`
//! for the rows): the generator runs the six legacy RARLAB builds in
//! network-less containers from a package cache OUTSIDE this repository.
//! Reference `rar` 7.23 no longer writes the format (`-ma4` is gone), so
//! these are the only genuine RAR 2.x protect records there are.
//!
//! **The corpus is in the checkout** - committed 19 Sep 2026,
//! under `fixtures/legacy/archives/` - so nothing below is conditional.
//! Before that these tests looked for the archives and
//! reported a skip when they were missing, which is a test that passes
//! while checking nothing; now a missing archive can only mean the
//! checkout is broken, and each one fails and says which file it wanted.
//! `make fixtures-check` runs ahead of `make test` in `make ci` and
//! catches a corpus that drifted before any test reads it. Setting
//! `RARKIT_LEGACY_FIXTURES` points the lot at a directory elsewhere.

use std::path::PathBuf;
use std::sync::Arc;

use rarkit::internals::recovery as l;
use rarkit::memory::MemoryPolicy;
use rarkit::RangeSource;

/// The rows of `fixtures/legacy/MANIFEST.tsv` this file uses, with the
/// geometry spec L 3.7 gives them (measured on the genuine archives).
const ROWS: [(&str, u64, u64, u64); 3] = [
    // name, protected length = header offset, n sectors, r parity sectors
    ("d250_rr.rar", 93_625, 183, 4),
    ("d250_rr8.rar", 93_625, 183, 8),
    ("d250_vrr.rar", 29_554, 58, 2),
];

fn dir() -> Option<PathBuf> {
    if let Ok(d) = std::env::var("RARKIT_LEGACY_FIXTURES") {
        let d = PathBuf::from(d);
        if d.is_dir() {
            return Some(d);
        }
    }
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/legacy/archives");
    here.is_dir().then_some(here)
}

/// Where the archives are, or a panic naming what is not there.
///
/// The `Option` in the return type is what is left of a skip that has been
/// removed: with the corpus committed, no caller can be handed `None`, and
/// a test cannot reach its assertions without the bytes they are about.
fn archives(test: &str) -> Option<PathBuf> {
    match dir() {
        Some(d) if d.join("d250_rr.rar").exists() => Some(d),
        _ => {
            panic!(
                "{test}: no genuine RAR 2.50 protect archives at that path.\n\
                 They are committed, under fixtures/legacy/archives/ (since \
                 19 Sep 2026), so this checkout is missing something rather \
                 than waiting on anything.\n\
                 Ask `make fixtures-check` what the corpus is short of, and \
                 `git status fixtures/legacy/archives` whether it arrived at all.\n\
                 To read the archives from another directory, set \
                 RARKIT_LEGACY_FIXTURES=<dir>."
            );
        }
    }
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

fn repair(volume: &[u8]) -> rarkit::Result<(Vec<u8>, rarkit::rev5::RepairReport)> {
    let mut out = Vec::new();
    let src: Arc<dyn RangeSource> = Arc::new(volume.to_vec());
    let report = l::legacy_rr_repair(&src, &policy(), &mut out)?;
    Ok((out, report))
}

fn scan(volume: &[u8]) -> rarkit::Result<(u64, u64, u64, u64)> {
    let src: Arc<dyn RangeSource> = Arc::new(volume.to_vec());
    l::legacy_rr_scan(&src)
}

/// Spec L 3.7's tag: the low 16 bits of the bitwise NOT of the sector's
/// CRC32, recomputed here rather than taken from the engine.
fn tag(sector: &[u8]) -> u16 {
    let mut padded = [0u8; 512];
    padded[..sector.len()].copy_from_slice(sector);
    !rarkit::checksum::crc32(&padded) as u16
}

#[test]
fn the_genuine_records_are_found_with_spec_l_3_7s_geometry() {
    let Some(dir) = archives("the_genuine_records_are_found_with_spec_l_3_7s_geometry") else {
        return;
    };
    for (name, protected, n, r) in ROWS {
        let volume = std::fs::read(dir.join(name)).unwrap();
        let (header_at, data_at, got_n, got_r) = scan(&volume).unwrap_or_else(|e| {
            panic!("{name}: rarkit did not find the record: {e}");
        });
        assert_eq!(header_at, protected, "{name}: protected length");
        assert_eq!(data_at, header_at + 26, "{name}: the header is 26 bytes");
        assert_eq!(got_n, n, "{name}: n = ceil(protected / 512)");
        assert_eq!(got_r, r, "{name}: r");
        assert_eq!(n, protected.div_ceil(l::SECTOR), "{name}: n by the rule");
        // The data area is the n tags then the r parity sectors.
        assert!(
            volume.len() as u64 >= data_at + 2 * n + 512 * r,
            "{name}: the data area fits"
        );
        // The last sector is PARTIAL: this is the case section 8 item 1 is
        // about, and every row here has one.
        let tail = protected % l::SECTOR;
        assert!(
            tail != 0,
            "{name}: the final sector is partial ({tail} bytes)"
        );
    }
}

/// The tags and parity in the genuine record are what spec L 3.7 says they
/// are, recomputed from the archive's own bytes - INCLUDING the final,
/// partial sector, zero-padded. This is the evidence for section 8 item 1:
/// the record covers that sector like any other.
#[test]
fn the_genuine_tags_and_parity_cover_the_final_partial_sector() {
    let Some(dir) = archives("the_genuine_tags_and_parity_cover_the_final_partial_sector") else {
        return;
    };
    for (name, protected, n, r) in ROWS {
        let volume = std::fs::read(dir.join(name)).unwrap();
        let (_, data_at, ..) = scan(&volume).unwrap();
        let (data_at, protected, n, r) =
            (data_at as usize, protected as usize, n as usize, r as usize);
        let sector = l::SECTOR as usize;

        let sectors: Vec<Vec<u8>> = (0..n)
            .map(|s| {
                let start = s * sector;
                let end = ((s + 1) * sector).min(protected);
                let mut padded = vec![0u8; sector];
                padded[..end - start].copy_from_slice(&volume[start..end]);
                padded
            })
            .collect();

        // Every tag, the last one over a zero-padded partial sector.
        for (s, bytes) in sectors.iter().enumerate() {
            let stored = u16::from_le_bytes(
                volume[data_at + 2 * s..data_at + 2 * s + 2]
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(
                stored,
                tag(bytes),
                "{name}: tag of sector {s} of {n}{}",
                if s == n - 1 { " (the PARTIAL one)" } else { "" }
            );
        }

        // Every parity sector is the XOR of its class.
        let parity_at = data_at + 2 * n;
        for c in 0..r {
            let mut want = vec![0u8; sector];
            for s in (c..n).step_by(r) {
                for (w, b) in want.iter_mut().zip(&sectors[s]) {
                    *w ^= b;
                }
            }
            let stored = &volume[parity_at + c * sector..parity_at + (c + 1) * sector];
            assert_eq!(stored, want, "{name}: parity sector {c} of {r}");
        }
    }
}

#[test]
fn an_undamaged_genuine_archive_comes_back_unchanged() {
    let Some(dir) = archives("an_undamaged_genuine_archive_comes_back_unchanged") else {
        return;
    };
    for (name, ..) in ROWS {
        let volume = std::fs::read(dir.join(name)).unwrap();
        let (out, report) = repair(&volume).unwrap();
        assert_eq!(out, volume, "{name}");
        assert!(report.rebuilt.is_empty(), "{name}");
        assert!(report.failed.is_empty(), "{name}");
    }
}

#[test]
fn a_damaged_whole_sector_is_repaired_byte_exactly() {
    let Some(dir) = archives("a_damaged_whole_sector_is_repaired_byte_exactly") else {
        return;
    };
    for (name, _protected, n, _r) in ROWS {
        let volume = std::fs::read(dir.join(name)).unwrap();
        for s in [0u64, 1, n / 2, n - 2] {
            let mut broken = volume.clone();
            let at = (s * l::SECTOR) as usize;
            for i in 0..64 {
                broken[at + i] ^= 0xA5;
            }
            assert_ne!(broken, volume);
            let (out, report) = repair(&broken).unwrap_or_else(|e| {
                panic!("{name}: sector {s} was not repaired: {e}");
            });
            assert_eq!(out, volume, "{name}: sector {s}");
            assert_eq!(report.rebuilt, vec![0], "{name}: sector {s}");
        }
    }
}

/// **Spec L section 8 item 1.** The final sector is partial - it would run
/// into the record's own header - and the genuine records cover it. The
/// predecessor repaired only the sectors wholly before the header and
/// refused this one; rarkit repairs it.
#[test]
fn the_final_partial_sector_is_repaired() {
    let Some(dir) = archives("the_final_partial_sector_is_repaired") else {
        return;
    };
    for (name, protected, n, _r) in ROWS {
        let volume = std::fs::read(dir.join(name)).unwrap();
        let last = (n - 1) * l::SECTOR;
        let real = protected - last;
        assert!(real < l::SECTOR, "{name}: the last sector is partial");

        // The first byte of it, a byte in the middle, and its very last
        // real byte - the one that sits hard against the header.
        for offset in [0, real / 2, real - 1] {
            let mut broken = volume.clone();
            broken[(last + offset) as usize] ^= 0xFF;
            let (out, report) = repair(&broken).unwrap_or_else(|e| {
                panic!("{name}: the partial sector at +{offset} was not repaired: {e}");
            });
            assert_eq!(
                out, volume,
                "{name}: the partial sector at +{offset} of {real} real bytes"
            );
            assert_eq!(report.rebuilt, vec![0], "{name}: +{offset}");
        }

        // Only the real bytes are written back: the record's own header
        // still follows immediately, untouched.
        let mut broken = volume.clone();
        broken[(protected - 1) as usize] ^= 0xFF;
        let (out, _) = repair(&broken).unwrap();
        assert_eq!(
            out[protected as usize..],
            volume[protected as usize..],
            "{name}: nothing past the protected region is rewritten"
        );
    }
}

/// Spec L 3.7: recoverable iff no two damaged sectors share a class
/// `s mod r`.
#[test]
fn two_damaged_sectors_repair_in_different_classes_and_not_in_one() {
    let Some(dir) = archives("two_damaged_sectors_repair_in_different_classes_and_not_in_one")
    else {
        return;
    };
    for (name, _protected, _n, r) in ROWS {
        let volume = std::fs::read(dir.join(name)).unwrap();
        let hurt = |v: &mut Vec<u8>, s: u64| {
            let at = (s * l::SECTOR) as usize;
            for i in 0..32 {
                v[at + i] ^= 0x5A;
            }
        };

        // Different classes: both come back.
        let mut ok = volume.clone();
        hurt(&mut ok, 2);
        hurt(&mut ok, 3);
        let (out, report) = repair(&ok).unwrap_or_else(|e| {
            panic!("{name}: two classes should repair: {e}");
        });
        assert_eq!(out, volume, "{name}: two classes");
        // `rebuilt` is VOLUME indices (inline: 0), not a sector count, so
        // the proof that both sectors came back is `out` above.
        assert_eq!(report.rebuilt, vec![0], "{name}: two classes");

        // One class, twice: refused rather than guessed at.
        let mut clash = volume.clone();
        hurt(&mut clash, 2);
        hurt(&mut clash, 2 + r);
        let error = repair(&clash).expect_err("two sectors of one class must be refused");
        assert!(
            matches!(error.kind(), rarkit::ErrorKind::Recovery(_)),
            "{name}: {error}"
        );
    }
}

/// The multi-volume row: every volume of `d250_vrr` carries its own record
/// (spec L 3.7's protected region is per volume).
#[test]
fn every_volume_of_the_genuine_set_carries_its_own_record() {
    let Some(dir) = archives("every_volume_of_the_genuine_set_carries_its_own_record") else {
        return;
    };
    for name in [
        "d250_vrr.rar",
        "d250_vrr.r00",
        "d250_vrr.r01",
        "d250_vrr.r02",
    ] {
        let path = dir.join(name);
        assert!(
            path.is_file(),
            "{name}: the d250_vrr row of MANIFEST.tsv lists this volume, and \
             it is committed in the checkout, so a corpus without it is \
             damaged rather than incomplete"
        );
        let volume = std::fs::read(&path).unwrap();
        let (header_at, _, n, r) =
            scan(&volume).unwrap_or_else(|e| panic!("{name}: no record: {e}"));
        assert_eq!(n, header_at.div_ceil(l::SECTOR), "{name}: n");
        assert!(r >= 1, "{name}: r");

        let mut broken = volume.clone();
        broken[(header_at - 1) as usize] ^= 0xFF;
        let (out, report) = repair(&broken)
            .unwrap_or_else(|e| panic!("{name}: the partial sector was not repaired: {e}"));
        assert_eq!(out, volume, "{name}");
        assert_eq!(report.rebuilt, vec![0], "{name}");
    }
}
