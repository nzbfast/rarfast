//! A RAR 5 member decodes EVERY symbol it owns, and the surplus past its
//! declared end moves the base the next member of a solid stream counts
//! from (SPEC-H2 3.1, 3.7 and 3.8, the decision of 28 Sep 2026).
//!
//! **The defect this pins.** The old engine's fixture
//! `rar50/solid_interior_match_overrun.rar` holds three `-m3 -md=1m`
//! members. The first, `as.bin` (4,500 bytes, no checksum), ends on a
//! fresh match of 1,000 at distance 1,000 with room for 500. rarkit cut
//! that match at the member's end, so the ring held 500 bytes fewer than
//! the reference's and `bs.bin` and `cs.bin` decoded 500 bytes early:
//! checksum `Some(false)` on both, where reference `unrar t` 7.23 says OK.
//! Replaying rarkit's own decoded operations with every match written whole
//! reproduced unrar's bytes on all three members.
//!
//! **The second archive**, `rar50/solid_match_overruns_member.rar` from the
//! same corpus, ends `m1.bin`'s only block with 4 bits that are no whole
//! code, 4 bytes past its declared 37; unrar 7.23 passes it, and SPEC-H2
//! 3.1 (measured the same day) has such a cut symbol past the declared end
//! apply nothing and pass the member.
//!
//! **Where the bytes come from.** Both archives were copied out of the old
//! engine's own fixture corpus through the oracle crate's PUBLIC call,
//! `rarkit_oracle::fixture`, under a later pin of the old engine
//! (which this repository does not yet carry), without opening
//! the oracle's source; `member_end_surplus/SHA256SUMS` records
//! them, and each is checked against it here. The verdicts asserted are the
//! headers' CRC32s, which are the writer's and which reference unrar 7.23
//! passes (`unrar t`: All OK on both). The rules behind the fix are pinned
//! on hand built chains in `rar5_lz::tests::member_end_surplus`.

use std::sync::Arc;

use rarkit::{Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink};
use sha2::{Digest, Sha256};

/// One committed archive, checked against the sha256 it was copied with.
fn archive(name: &str, sha256: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/member_end_surplus/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(digest, sha256, "{name} is not the archive that was copied");
    bytes
}

fn interior_overrun() -> Vec<u8> {
    archive(
        "solid_interior_match_overrun.rar",
        "5b367d165a2993d5fdc0412beba089d9d5d043bb92e02c11a0847fd35dadb01b",
    )
}

fn cut_symbol() -> Vec<u8> {
    archive(
        "solid_match_overruns_member.rar",
        "c5705138300d80248a02bb55753ff2fdd2ae3001b7481e3b4bc0ec3866cc7d1c",
    )
}

/// Keep every member's name, size and verdict.
#[derive(Default)]
struct Verdicts {
    members: Vec<(Vec<u8>, u64, Option<bool>)>,
}

impl Sink for Verdicts {
    type Out = Vec<u8>;
    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Verify)
    }
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        _out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.members
            .push((member.name.to_vec(), outcome.bytes, outcome.checksum_ok));
        Ok(())
    }
}

/// Every read path (the decode-ahead on and off, the default width and one
/// worker) gives exactly `want`: each member's name, size and verdict.
fn every_path_gives(bytes: &[u8], want: &[(&[u8], u64, Option<bool>)]) {
    for ahead in [true, false] {
        for workers in [None, Some(1)] {
            rarkit::probe::set_ahead_off(!ahead);
            let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bytes.to_vec())];
            let mut sink = Verdicts::default();
            let report = rarkit::extract(
                sources,
                &ReadOptions::default().with_workers(workers),
                &mut sink,
                &mut (),
            );
            rarkit::probe::set_ahead_off(false);
            let path = format!("ahead {ahead}, workers {workers:?}");
            let report = report.unwrap_or_else(|err| panic!("{path}: {err:?}"));
            assert_eq!(report.checksum_failures, 0, "{path}");
            assert_eq!(sink.members.len(), want.len(), "{path}");
            for ((name, size, verdict), (want_name, want_size, want_verdict)) in
                sink.members.iter().zip(want)
            {
                assert_eq!(name.as_slice(), *want_name, "{path}");
                assert_eq!(size, want_size, "{path}");
                assert_eq!(verdict, want_verdict, "{path}");
            }
        }
    }
}

#[test]
fn the_solid_interior_overrun_archive_passes_on_every_path() {
    every_path_gives(
        &interior_overrun(),
        &[
            (b"as.bin", 4500, None),
            (b"bs.bin", 1700, Some(true)),
            (b"cs.bin", 1700, Some(true)),
        ],
    );
}

#[test]
fn a_symbol_cut_past_the_declared_end_passes_on_every_path() {
    every_path_gives(
        &cut_symbol(),
        &[
            (b"m0.bin", 5231, None),
            (b"m1.bin", 37, None),
            (b"m2.bin", 4610, None),
        ],
    );
}

/// The decoder seam, serial and parallel, gives the same members on both.
#[test]
fn the_decoder_seam_agrees_serial_and_parallel() {
    for (bytes, sizes) in [
        (interior_overrun(), [4500, 1700, 1700]),
        (cut_symbol(), [5231, 37, 4610]),
    ] {
        let serial = rarkit::internals::rar5::extract(&bytes, false).expect("serial");
        let parallel = rarkit::internals::rar5::extract(&bytes, true).expect("parallel");
        assert_eq!(serial, parallel);
        let got: Vec<usize> = serial.iter().map(|(_, body)| body.len()).collect();
        assert_eq!(got, sizes);
    }
}
