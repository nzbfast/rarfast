//! SPEC-H3 3.5, "A match that passes the declared size" (restated 8 Oct
//! 2026; SWEEP2-08OCT-52), on the two archives of
//! `specs/vectors-H/h3-match-past-size`.
//!
//! Each is a solid chain of two RAR 2.0 members. `ONE.BIN` declares 651
//! bytes and its last match ends 7 bytes past them; `TWO.BIN` declares
//! 207 and its stream holds 200. The reference writes 658 and 200 bytes.
//! rarkit's rule: `ONE.BIN` delivers its 651 declared bytes and FAILS,
//! the 7 bytes past its size are no member's output, and `TWO.BIN` starts
//! after them with its own 200 bytes.
//!
//! Until 9 Oct 2026 the 7 bytes opened `TWO.BIN`, which then delivered
//! 207, and the archive whose checksums fit that reading was reported
//! whole where the reference fails both members.
//!
//! One worker and the default width; each archive is 873 bytes and the
//! read holds the RAR 2.0 window of 1 MiB.

use std::sync::Arc;

use rarkit::{Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/vectors-H/h3-match-past-size"
);

/// (name, bytes delivered, verdict) of each member closed.
#[derive(Default)]
struct Keep(Vec<(String, Vec<u8>, Option<bool>)>);

impl Sink for Keep {
    type Out = Vec<u8>;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.0.push((
            String::from_utf8_lossy(member.name).into_owned(),
            out.unwrap_or_default(),
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

fn read(name: &str, workers: Option<usize>) -> Vec<(String, Vec<u8>, Option<bool>)> {
    let path = format!("{VECTORS}/{name}");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bytes)];
    let mut sink = Keep::default();
    // A member's failure is its own close; the walk goes on to the next.
    let _ = rarkit::extract(
        sources,
        &ReadOptions::default().with_workers(workers),
        &mut sink,
        &mut (),
    );
    sink.0
}

/// The checksum field of member `name`: offset 16 of its file header.
fn field(archive: &str, name: &[u8]) -> u32 {
    let bytes = std::fs::read(format!("{VECTORS}/{archive}")).unwrap();
    let at = bytes
        .windows(name.len())
        .position(|w| w == name)
        .expect("the member's name")
        - 32;
    u32::from_le_bytes(bytes[at + 16..at + 20].try_into().unwrap())
}

const AS_THE_REFERENCE_WRITES: &str = "crc-of-what-the-reference-writes.rar";
const CARRIED: &str = "crc-of-declared-prefix-and-carried-rest.rar";

/// Both archives read to 651 and 200 bytes, never 207, and `ONE.BIN`
/// fails in both.
#[test]
fn the_bytes_past_the_declared_size_are_no_members_output() {
    for workers in [None, Some(1)] {
        for archive in [AS_THE_REFERENCE_WRITES, CARRIED] {
            let seen = read(archive, workers);
            let shape: Vec<(&str, usize)> = seen
                .iter()
                .map(|(name, bytes, _)| (name.as_str(), bytes.len()))
                .collect();
            assert_eq!(
                shape,
                [("ONE.BIN", 651), ("TWO.BIN", 200)],
                "{archive}, workers {workers:?}"
            );
            assert_eq!(seen[0].2, Some(false), "{archive}: ONE.BIN fails");
        }
        // The archive sealed to the reference's output: `TWO.BIN`'s field
        // is the CRC32 of the reference's 200 bytes, and they are the
        // bytes delivered here, so it starts after the whole match.
        let seen = read(AS_THE_REFERENCE_WRITES, workers);
        assert_eq!(
            crc32fast::hash(&seen[1].1),
            field(AS_THE_REFERENCE_WRITES, b"TWO.BIN"),
            "workers {workers:?}: TWO.BIN's bytes are the reference's"
        );
        // The other archive: `ONE.BIN`'s field is the CRC32 of its first
        // 651 bytes, which are the bytes delivered. It fails all the same
        // (rule 3): the reference's checksum there is over 658.
        let seen = read(CARRIED, workers);
        assert_eq!(
            crc32fast::hash(&seen[0].1),
            field(CARRIED, b"ONE.BIN"),
            "workers {workers:?}: ONE.BIN delivers its declared bytes"
        );
    }
}

/// The archive whose checksums fit the old reading: the reference fails
/// both members, exit 3, and so does rarkit. It was All OK, exit 0.
#[test]
fn the_archive_sealed_to_the_carried_reading_fails_both_members() {
    for workers in [None, Some(1)] {
        let seen = read(CARRIED, workers);
        let verdicts: Vec<Option<bool>> = seen.iter().map(|m| m.2).collect();
        assert_eq!(verdicts, [Some(false), Some(false)], "workers {workers:?}");
    }
}
