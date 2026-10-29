//! Spec A section 7.2: the constructed archives of `specs/vectors-A/`,
//! driven through the public `extract`.
//!
//! `a-all-sections/a_NNN.rar` are 108 archives in the RAR 1.5 container
//! (unpack version 15) that the reference decodes to `a_NNN.want`, the
//! bytes of the archive's members in order. `a47-long-match-results/`
//! holds 33 more for section 4.7. Every member's header carries the CRC32
//! of the stated bytes, so a member is right when its bytes are the stated
//! ones AND its checksum verdict is good.
//!
//! One thread, and memory of a few megabytes: every archive is read whole
//! into memory and the largest is under 2 MiB.

use std::path::PathBuf;
use std::sync::Arc;

use rarkit::{extract, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Sink};

/// The members' bytes joined in archive order, and the verdicts.
#[derive(Default)]
struct Joined {
    bytes: Vec<u8>,
    members: usize,
    bad: usize,
}

impl Sink for Joined {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        if let Some(bytes) = out {
            self.members += 1;
            self.bytes.extend_from_slice(&bytes);
            if outcome.checksum_ok != Some(true) {
                self.bad += 1;
            }
        }
        Ok(())
    }
}

fn vectors(dir: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../specs/vectors-A")
        .join(dir)
}

/// Decode every `<stem>.rar` of `dir` and compare with `<stem>.want`.
/// Answers how many archives were compared and the stems that differ.
fn sweep(dir: &str) -> (usize, Vec<String>) {
    let mut stems: Vec<String> = std::fs::read_dir(vectors(dir))
        .expect("the vectors directory is part of the checkout")
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().into_string().ok()?;
            name.strip_suffix(".rar").map(str::to_owned)
        })
        .collect();
    stems.sort();
    let mut wrong = Vec::new();
    for stem in &stems {
        let archive = std::fs::read(vectors(dir).join(format!("{stem}.rar"))).expect("archive");
        let want = std::fs::read(vectors(dir).join(format!("{stem}.want"))).expect("want");
        let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive)];
        let mut sink = Joined::default();
        let report = extract(sources, &ReadOptions::default(), &mut sink, &mut ());
        let good = report.is_ok() && sink.bad == 0 && sink.bytes == want;
        if !good {
            let first = sink
                .bytes
                .iter()
                .zip(&want)
                .position(|(a, b)| a != b)
                .unwrap_or(sink.bytes.len().min(want.len()));
            wrong.push(format!(
                "{stem}: ok={} members={} bad={} got {} bytes, want {}, first difference at {first}",
                report.is_ok(),
                sink.members,
                sink.bad,
                sink.bytes.len(),
                want.len()
            ));
        }
    }
    (stems.len(), wrong)
}

#[test]
fn spec_a_7_2_every_archive_of_all_sections_gives_its_stated_bytes() {
    let (count, wrong) = sweep("a-all-sections");
    assert_eq!(count, 108, "the specification names 108 archives");
    assert!(
        wrong.is_empty(),
        "{} differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn spec_a_4_7_every_long_match_archive_gives_its_stated_bytes() {
    let (count, wrong) = sweep("a47-long-match-results");
    assert_eq!(count, 33, "the specification names 33 archives");
    assert!(
        wrong.is_empty(),
        "{} differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Section 1.1 leaves open what a STORED member inside a solid chain does
/// to the state the chain carries; no genuine writer puts one there. This
/// decoder is never told of a stored member, so the chain carries on as
/// if it were not there, and this pins that choice.
///
/// The archive is three members made with the writer of
/// `specs/vectors-A/a_model.py` and the container of `a_containers.py`,
/// the archive's solid flag set: A.BIN is the 20 literals A to T; S.BIN
/// is ten stored bytes (its method byte set to 0x30 and its header
/// checksum taken again); B.BIN is solid, a long match of 11 bytes at
/// distance 20 and one literal. Twenty back from the start of B.BIN is
/// the A of A.BIN when the stored bytes are no part of the history, and
/// its header carries the CRC32 of that reading. Reference unrar 7.23
/// for macOS reported all three members OK on 6 Oct 2026, which is one
/// observation and not a statement of the specification.
#[test]
fn spec_a_1_1_leaves_open_a_stored_member_in_a_solid_chain_and_this_decoder_carries_on_past_it() {
    let archive: Vec<u8> = vec![
        0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00, 0x3b, 0xd0, 0x73, 0x08, 0x00, 0x0d, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x2d, 0x74, 0x00, 0x80, 0x25, 0x00, 0x17, 0x00, 0x00,
        0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0xee, 0xf9, 0x16, 0x21, 0x00, 0x00, 0x3a, 0x5b, 0x0f,
        0x33, 0x05, 0x00, 0x20, 0x00, 0x00, 0x00, 0x41, 0x2e, 0x42, 0x49, 0x4e, 0x0f, 0x2f, 0x37,
        0x3f, 0x47, 0x4f, 0x57, 0x5f, 0x60, 0x3b, 0x7b, 0xbb, 0xfc, 0x1e, 0x1f, 0x14, 0xd4, 0xd9,
        0xb9, 0xc9, 0xd9, 0xe9, 0xf0, 0xdf, 0x48, 0x74, 0x00, 0x80, 0x25, 0x00, 0x0a, 0x00, 0x00,
        0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xc6, 0xc7, 0x84, 0xa6, 0x00, 0x00, 0x3a, 0x5b, 0x0f,
        0x30, 0x05, 0x00, 0x20, 0x00, 0x00, 0x00, 0x53, 0x2e, 0x42, 0x49, 0x4e, 0x30, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xbc, 0xc5, 0x74, 0x00, 0x80, 0x25, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0xd1, 0x4f, 0x49, 0x50, 0x00, 0x00, 0x3a,
        0x5b, 0x0f, 0x33, 0x05, 0x00, 0x20, 0x00, 0x00, 0x00, 0x42, 0x2e, 0x42, 0x49, 0x4e, 0xd5,
        0xc0, 0xa2, 0xc0,
    ];
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive)];
    let mut sink = Joined::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ()).expect("the archive extracts");
    assert_eq!(sink.members, 3);
    assert_eq!(sink.bad, 0);
    assert_eq!(sink.bytes, b"ABCDEFGHIJKLMNOPQRST0123456789ABCDEFGHIJK!");
}
