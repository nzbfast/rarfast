//! Spec H3 part A against the only RAR 2.0 archives in the project that a
//! RARLAB writer produced (section 9.1, open question 1).
//!
//! `D250_M0.RAR` and `D250_M5.RAR` hold the same six members, written by
//! DOS RAR 2.50 at `-m0` and `-m5`. The stored archive is therefore the
//! answer key: every compressed member must decode to the stored member's
//! bytes exactly, and to the CRC-32 its own header declares.

mod support {
    pub mod rar20walk;
}

use rarkit::internals::rar20;
use support::rar20walk::{members, Member};

fn legacy(name: &str) -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../specs/vectors-H/legacy/");
    std::fs::read(format!("{path}{name}")).expect("legacy fixture")
}

fn stored_bytes(archive: &[Member], name: &[u8]) -> Vec<u8> {
    let member = archive
        .iter()
        .find(|m| m.name == name)
        .expect("member in the stored archive");
    assert_eq!(member.method, 0x30, "the answer key must be stored");
    member.packed.clone()
}

#[test]
fn decodes_every_compressed_member_of_the_dos_rar250_archive() {
    let stored = members(&legacy("D250_M0.RAR"));
    let compressed = members(&legacy("D250_M5.RAR"));
    let mut seen = 0;
    for member in &compressed {
        if !member.is_compressed_file() {
            continue;
        }
        assert_eq!(
            member.version, 20,
            "{:?} is not unpack version 20",
            member.name
        );
        assert!(!member.solid, "the -m5 archive is not solid");
        let capacity = rar20::dictionary_size(member.dictionary_bits);
        let out = rar20::decode_member(&member.packed, capacity, member.unpacked)
            .unwrap_or_else(|e| panic!("{:?} failed: {e}", member.name));
        assert_eq!(
            out.len() as u64,
            member.unpacked,
            "{:?} decoded to the wrong length",
            member.name
        );
        assert_eq!(
            rarkit::checksum::crc32(&out),
            member.crc,
            "{:?} decoded against its own header CRC",
            member.name
        );
        assert_eq!(
            out,
            stored_bytes(&stored, &member.name),
            "{:?} differs from the stored archive's bytes",
            member.name
        );
        seen += 1;
    }
    assert_eq!(seen, 3, "the fixture holds three compressed members");
}

// Spec H3 3.5 (TOLERATE): the window is the format maximum, not
// the declared dictionary. The pair in `fixtures/rar20-dictionary/` holds
// the same 80,000 byte input; one archive is a conformant RAR 2.50 stream,
// the other names a distance past its declared 64 KiB.

fn dictionary_fixture(name: &str) -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/rar20-dictionary/"
    );
    std::fs::read(format!("{path}{name}")).expect("dictionary fixture")
}

/// Every file `extract` delivers from one archive, by name, failing on any
/// checksum mismatch.
fn extract_all(archive: Vec<u8>) -> rarkit::Result<Vec<(String, Vec<u8>)>> {
    use rarkit::{extract, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Sink};
    use std::sync::Arc;

    #[derive(Default)]
    struct Collect(Vec<(String, Vec<u8>)>);
    impl Sink for Collect {
        type Out = Vec<u8>;
        fn open(&mut self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
            if member.is_directory {
                return Ok(Disposition::Skip);
            }
            Ok(Disposition::Write(Vec::new()))
        }
        fn close(
            &mut self,
            member: &MemberInfo<'_>,
            out: Option<Vec<u8>>,
            outcome: &MemberOutcome,
        ) -> rarkit::Result<()> {
            assert_ne!(outcome.checksum_ok, Some(false), "member failed its CRC");
            if let Some(bytes) = out {
                self.0
                    .push((String::from_utf8_lossy(member.name).into_owned(), bytes));
            }
            Ok(())
        }
    }

    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive)];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())?;
    Ok(sink.0)
}

fn assert_reads_as_the_input(archive: &str) {
    let input = dictionary_fixture("input-DICT.TXT");
    let files = extract_all(dictionary_fixture(&format!("archives/{archive}")))
        .unwrap_or_else(|e| panic!("{archive} was refused: {e}"));
    assert_eq!(files.len(), 1, "{archive} holds one file");
    assert_eq!(files[0].1, input, "{archive} decoded to different bytes");
}

#[test]
fn a_distance_past_the_declared_dictionary_is_tolerated() {
    assert_reads_as_the_input("nonconformant-64k.rar");
}

#[test]
fn the_genuine_rar250_archive_of_the_same_input_reads() {
    assert_reads_as_the_input("genuine-rar250-m3.rar");
}

#[test]
fn a_distance_past_what_the_stream_produced_is_still_refused() {
    // Tolerance is about the allocation, not about silence: with the whole
    // 1 MiB window available, a stream still may not name a byte it has not
    // produced. Damage the packed bytes one position at a time until a
    // match reaches back further than the output so far.
    let archive = dictionary_fixture("archives/genuine-rar250-m3.rar");
    let member = members(&archive)
        .into_iter()
        .find(Member::is_compressed_file)
        .expect("a compressed member");
    let mut refused = 0;
    for at in 0..member.packed.len().min(1024) {
        let mut packed = member.packed.clone();
        packed[at] ^= 0x55;
        if let Err(e) = rar20::decode_member(&packed, 1 << 20, member.unpacked) {
            if matches!(
                e.kind(),
                rarkit::ErrorKind::Corrupt(rarkit::Corruption::Rar20(
                    rarkit::Rar20Fault::DistanceOutOfRange
                ))
            ) {
                refused += 1;
            }
        }
    }
    assert!(refused > 0, "no damaged stream reached DistanceOutOfRange");
}
