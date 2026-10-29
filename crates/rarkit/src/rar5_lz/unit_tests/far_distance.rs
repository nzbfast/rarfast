//! SPEC-H2 3.5, 3.5.1 and 3.7 as amended on 11 Oct 2026: a match the
//! reader cannot honour gives ZERO bytes, says nothing, and the member's
//! checksum decides the member.
//!
//! Two kinds of test. The made archives of note 3.5.1, every one of them,
//! against what the genuine programs were measured to do with it; and a
//! hand built member for the slots only a version 1 alphabet holds, put
//! through the serial reader and through the tape, which must give one
//! answer.

use super::*;
use std::path::PathBuf;

/// The mirrored vectors: `specs/vectors-H/<set>/` as the crate carries it.
fn vectors(set: &str) -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/vectors-H")).join(set)
}

/// A manifest's rows, each split at its tabs; the heading line is dropped.
fn rows(set: &str) -> Vec<Vec<String>> {
    let text = std::fs::read_to_string(vectors(set).join("manifest.tsv")).expect("manifest.tsv");
    text.lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| line.split('\t').map(str::to_string).collect())
        .collect()
}

/// A manifest's dictionary cell, such as `128 KiB`, in bytes.
fn dictionary(cell: &str) -> u64 {
    let (count, unit) = cell.split_once(' ').expect("a count and a unit");
    let count: u64 = count.parse().expect("a count");
    count
        << match unit {
            "KiB" => 10,
            "MiB" => 20,
            "GiB" => 30,
            other => panic!("unit {other}"),
        }
}

/// A manifest's distance cell, which is hexadecimal with its `0x`.
fn distance(cell: &str) -> u64 {
    u64::from_str_radix(cell.trim_start_matches("0x"), 16).expect("a distance")
}

/// What `p` would print for an archive, every member's bytes one after
/// another, and whether every member's checksum held.
fn extracted(set: &str, file: &str) -> (Vec<u8>, bool) {
    use crate::{Disposition, MemberInfo, MemberOutcome, Sink};
    use std::sync::Arc;

    #[derive(Default)]
    struct Keep {
        bytes: Vec<u8>,
        every_checksum_held: bool,
    }
    impl Sink for Keep {
        type Out = Vec<u8>;
        fn open(&mut self, _: &MemberInfo<'_>) -> crate::Result<Disposition<Vec<u8>>> {
            Ok(Disposition::Write(Vec::new()))
        }
        fn close(
            &mut self,
            _: &MemberInfo<'_>,
            out: Option<Vec<u8>>,
            outcome: &MemberOutcome,
        ) -> crate::Result<()> {
            self.bytes.extend_from_slice(&out.unwrap_or_default());
            self.every_checksum_held &= outcome.checksum_ok == Some(true);
            Ok(())
        }
    }
    let archive = std::fs::read(vectors(set).join(file)).expect("an archive");
    let source: Arc<dyn crate::source::RangeSource> = Arc::new(archive);
    let mut sink = Keep {
        bytes: Vec::new(),
        every_checksum_held: true,
    };
    let ended = crate::extract(
        vec![source],
        &crate::ReadOptions::default(),
        &mut sink,
        &mut (),
    );
    assert!(ended.is_ok(), "{set}/{file}: nothing is said, {ended:?}");
    (sink.bytes, sink.every_checksum_held)
}

/// Note 3.5.1's first set, 85 archives: one fresh match at a far slot
/// after 300 literals, under version 0 and version 1, with the header's
/// checksum of the ZEROS reading; and three controls whose match is inside
/// the 300 bytes. The genuine programs report every member OK and write
/// exactly the bytes whose SHA-256 the manifest carries.
#[test]
fn every_far_distance_archive_reads_as_zeros_and_is_ok() {
    let rows = rows("h2-far-distance");
    assert_eq!(rows.len(), 85);
    for row in rows {
        let (arm, file, want) = (&row[0], &row[1], &row[9]);
        let (bytes, ok) = extracted("h2-far-distance", file);
        assert_eq!(&hex(&bytes), want, "{arm}: the bytes");
        assert!(ok, "{arm}: the member's checksum holds");
    }
}

/// Note 3.5.1's second set, 66 archives, in its four families.
///
/// `other`: the header's checksum is of other bytes, so the zeros are
/// written all the same and the checksum alone fails the member. `solid`:
/// "before the start" is before the start of the STREAM, and a distance
/// inside the member before copies that member's bytes. `repeat`: a
/// repeated distance match after a far match gives zeros again. `inside`:
/// the stream holds bytes at the distance, and the match gives them when
/// the distance is no more than the larger of the declared dictionary and
/// 256 KiB, and zeros when it is more; each arm is built twice, with the
/// checksum of either reading, and the one that agrees is the one that is
/// OK.
#[test]
fn every_far_distance_more_archive_reads_as_measured() {
    let rows = rows("h2-far-distance-more");
    assert_eq!(rows.len(), 66);
    let mut seen = std::collections::BTreeMap::new();
    for row in rows {
        let (arm, file, family) = (&row[0], &row[1], row[2].as_str());
        let (declared, far, checksum_of) = (dictionary(&row[3]), distance(&row[8]), &row[10]);
        let (zeros, bytes_reading) = (&row[11], &row[12]);
        // Where the manifest has a bytes reading the stream holds bytes at
        // the distance, and section 3.7 says which of the two it is.
        let honoured = bytes_reading != "-" && far <= declared.max(256 << 10);
        let (reading, want) = if honoured {
            ("bytes", bytes_reading)
        } else {
            ("zeros", zeros)
        };
        let (bytes, ok) = extracted("h2-far-distance-more", file);
        assert_eq!(&hex(&bytes), want, "{arm}: the {reading} reading");
        assert_eq!(ok, checksum_of == reading, "{arm}: the checksum's verdict");
        *seen.entry((family.to_string(), reading, ok)).or_insert(0) += 1;
    }
    // Every family, and both readings of the `inside` one with both
    // verdicts, were met: the table of 3.5.1 has zeros and bytes cells.
    let met = |family: &str, reading: &'static str, ok: bool| {
        seen.get(&(family.to_string(), reading, ok))
            .copied()
            .unwrap_or(0)
    };
    assert_eq!(met("other", "zeros", false), 5);
    assert_eq!(met("repeat", "zeros", true), 2);
    assert_eq!(
        met("solid", "zeros", true) + met("solid", "bytes", true),
        11
    );
    assert_eq!(met("solid", "bytes", true), 1);
    for (reading, ok) in [
        ("bytes", true),
        ("bytes", false),
        ("zeros", true),
        ("zeros", false),
    ] {
        assert!(met("inside", reading, ok) > 0, "inside, {reading}, {ok}");
    }
    assert_eq!(seen.values().sum::<i32>(), 66);
}

/// A version 1 member of 300 literals, one fresh match at distance slot
/// `slot` with extra bits `extra`, 100 literals, a repeated distance
/// match at the newest distance and 20 literals; and the bytes section
/// 3.5 gives it, a zero for every byte of both matches.
fn slot_member(slot: usize, extra: u32) -> (Vec<u8>, Vec<u8>) {
    use super::ladders::{fresh_match_length, length_from_slot};
    let mut block = BlockBuilder::default();
    block.distance = vec![7; 80];
    let mut want = Vec::new();
    let literals = |block: &mut BlockBuilder, want: &mut Vec<u8>, count: usize| {
        for index in 0..count {
            let byte = b'a' + ((index * 7 + want.len()) % 26) as u8;
            block.literal(byte);
            want.push(byte);
        }
    };
    literals(&mut block, &mut want, 300);
    block.fresh(20, 3, slot, extra);
    // The bonus is a fresh match's and all three of its distances are
    // passed (section 3.5).
    let fresh = fresh_match_length(length_from_slot(20, 3), usize::MAX);
    want.resize(want.len() + fresh, 0);
    literals(&mut block, &mut want, 100);
    block.repeat(0, 9, 1);
    want.resize(want.len() + length_from_slot(9, 1), 0);
    literals(&mut block, &mut want, 20);
    (block.finish(true, true), want)
}

/// THE SERIAL READER AND THE TAPE GIVE ONE ANSWER for a distance slot of
/// 66 to 79 (section 3.5, "No count of extra bits is refused"): the slot
/// is read, its match and a repeat of it give zero bytes, and the literals
/// after them are read from the right bits. Bytes and verdicts never
/// depend on the path taken or on its width.
#[test]
fn a_slot_of_66_to_79_gives_zeros_on_the_serial_path_and_on_the_tape() {
    for (slot, extra) in [
        (66usize, 0u32),
        (66, u32::MAX),
        (67, 0x1234_5678),
        (70, u32::MAX),
        (78, 0),
        (79, u32::MAX),
    ] {
        let (packed, want) = slot_member(slot, extra);
        let decode = |lz: &mut Rar5Lz| {
            let mut sink: Vec<u8> = Vec::new();
            let mut source = SliceSource::new(&packed);
            lz.member(&mut source, want.len() as u64, 1, &mut sink)
                .unwrap_or_else(|e| panic!("slot {slot}: nothing is said, {e}"));
            sink
        };
        let mut serial = Rar5Lz::new(1 << 17, &policy()).expect("window");
        serial.set_parallel(false);
        assert!(
            decode(&mut serial) == want,
            "slot {slot}: the serial reader"
        );
        #[cfg(feature = "parallel")]
        for (width, wave, overlap) in [(1, Some(1), false), (2, None, true), (8, Some(1), true)] {
            let mut tape = Rar5Lz::new(1 << 17, &policy()).expect("window");
            tape.set_parallel(true);
            tape.set_tape_width(width);
            tape.set_wave_blocks(wave);
            tape.set_overlap(overlap);
            assert!(
                decode(&mut tape) == want,
                "slot {slot}: the tape at width {width}, wave {wave:?}, overlap {overlap}"
            );
        }
    }
}

/// The same member in each of the tape's four symbol loops: none refuses
/// the slot. Each stops AT the match, with every literal before it taken
/// and no failure, so that the serial reader, which reads such a slot,
/// takes the block up from the match's first bit.
#[cfg(all(feature = "parallel", target_pointer_width = "64"))]
#[test]
fn a_slot_of_66_to_79_parks_at_the_match_in_every_tape_loop() {
    use super::tape::{self, BlockTape, Plan};
    for slot in [66usize, 67, 70, 78, 79] {
        let mut builder = BlockBuilder::default();
        builder.distance = vec![7; 80];
        for _ in 0..200 {
            builder.literal(65);
        }
        let (_, match_at) = builder.body_bits();
        builder.fresh(0, 0, slot, u32::MAX);
        for _ in 0..200 {
            builder.literal(66);
        }
        let packed = builder.finish(true, true);
        let mut plan = Plan::default();
        tape::plan(&packed, false, &mut plan).unwrap();
        let (tables, from, _) = tape::batch::tables_of(&plan, &packed, 1, 0).unwrap();
        let block = &plan.blocks[0];
        let mut tapes: [BlockTape; 4] = Default::default();
        tape::decode_block_tape(&tables, &packed, block, from, &mut tapes[0]);
        tape::decode_block_tape_checked(&tables, &packed, block, from, &mut tapes[1]);
        tape::batch::decode_block_tape_batched(&tables, &packed, block, from, &mut tapes[2]);
        tape::batch::decode_block_tape_batched_checked(
            &tables,
            &packed,
            block,
            from,
            &mut tapes[3],
        );
        let names = ["admitted", "checked", "batched", "batched checked"];
        for (name, tape) in names.iter().zip(&tapes) {
            assert!(tape.failure.is_none(), "slot {slot}, {name}: no failure");
            assert_eq!(
                tape.parked_at,
                Some(from + match_at),
                "slot {slot}, {name}: the match's first bit"
            );
            assert_eq!(tape.verbatim[..200], [65u8; 200][..], "slot {slot}, {name}");
        }
    }
}
