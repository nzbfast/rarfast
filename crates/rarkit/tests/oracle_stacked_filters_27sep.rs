//! Two RAR 5 filter records naming the SAME span end the member early.
//!
//! FOUND on an M3 Mac, 27 Sep 2026, by `fuzz:rar5_oracle_stream` after
//! 7,083 executions, then minimised (`fuzz/findings-27sep/`). One member,
//! non-solid, no data checksum: 19 literals, a delta filter over bytes 19
//! to 230 (19 channels), a SECOND delta filter over the same span (14
//! channels), then 240 literals; it declares 259 bytes.
//!
//! - rarkit answers the member OK with 230 bytes, different from byte 19
//!   on: every decode arm and the reader alike, so the fault is in the
//!   shared filter queue. A member shorter than it declares reported as a
//!   success is against SPEC-H2 3.1 whatever the stacking means.
//! - The old engine and reference unrar 7.23 answer 259 bytes. unrar's are
//!   byte for byte those of the same stream with only the FIRST record
//!   (`single-filter-control.rar`, CRC32 `32ee0b1f`): the reference keeps
//!   the first record on a span and ignores the second.
//!
//! SPEC-H2 3.6 now says it (a record starting before the end of the last
//! record kept is dropped), and 3.1 that a member never ends short at a
//! filter boundary. Since fixed; the pin below asserts
//! both, and `rar5_overlapping_filter_records.rs` carries the other shapes.
// The exporter cut the cases of this file that need a crate this tree
// does not have; imports and helpers only they used are left in place.
#![allow(unused_imports, dead_code, unused_macros)]

use std::path::PathBuf;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink,
};

fn finding(name: &str) -> Vec<u8> {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "fuzz",
        "findings-27sep",
        name,
    ]
    .iter()
    .collect();
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[derive(Default)]
struct Keep {
    members: Vec<Vec<u8>>,
}

impl Sink for Keep {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &MemberOutcome,
    ) -> Result<()> {
        self.members.push(out.unwrap_or_default());
        Ok(())
    }
}

fn ours(archive: &[u8]) -> (Keep, Option<String>) {
    let source: Arc<dyn RangeSource> = Arc::new(archive.to_vec());
    let mut sink = Keep::default();
    let ended = extract(vec![source], &ReadOptions::default(), &mut sink, &mut ());
    (sink, ended.err().map(|e| format!("{:?}", e.kind())))
}

/// SPEC-H2 3.6 as written on 27 Sep 2026: `next` is the end
/// of the last KEPT span, and a record whose span starts before it is
/// DROPPED. This is `specs/vectors-H`'s `h5_delta_m5.rar` with eight packed
/// bytes changed by `fuzz:rar5_oracle_reframe` and no data checksum: its
/// second delta record (4 channels) now starts at 65,534, two bytes before
/// the first record's span ends at 65,536, so it is dropped. Reference
/// unrar 7.23 answers 120,000 bytes, CRC32 `d7ac410b`; rarkit before the fix
/// agreed with it to byte 65,536 and not after (`4390f75a`), and the old
/// engine departs at 65,534 (`4c8f2990`). Pinned from the fuzz find;
/// the reader here, and the serial and tape arms below it.
#[test]
fn a_filter_starting_inside_a_kept_span_is_dropped_per_h2_3_6() {
    let archive = finding("overlapping-delta-filters.rar");
    let (kept, ended) = ours(&archive);
    assert_eq!(ended, None);
    assert_eq!(kept.members.len(), 1);
    assert_eq!(kept.members[0].len(), 120_000);
    assert_eq!(crc32fast::hash(&kept.members[0]), 0xd7ac_410b);
    let members = rarkit::internals::rar5::members(&archive);
    let member = &members[0];
    for parallel in [false, true] {
        let out = rarkit::internals::rar5::decode_member(
            &member.packed,
            member.unpacked,
            member.window,
            member.algorithm,
            parallel,
        )
        .expect("the member decodes");
        assert_eq!(crc32fast::hash(&out), 0xd7ac_410b, "parallel {parallel}");
    }
}
