//! SPEC-C 8.1: every row of sections 1.3, 2.3, 3.3, 4.3, 5.3 and 6.3 as a
//! test, in both directions where the row has an `enc`, from
//! `specs/vectors-C/c8-hand-vectors/hand-vectors.tsv`; and the archives
//! beside it, in which each row was put to the reference, through the
//! public reader.
//!
//! One thread, no pool; the largest archive declares a 4 MiB dictionary
//! and each test holds under 16 MiB.

use std::sync::Arc;

use rarkit::internals::rar20::rar5_filter_encode;
use rarkit::internals::rar3::{rar3_transform, Rar3Transform};
use rarkit::internals::rar5::rar5_filter_pass;
use rarkit::{Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/vectors-C/c8-hand-vectors"
);

fn rows(name: &str) -> Vec<Vec<String>> {
    let path = format!("{VECTORS}/{name}");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    text.lines()
        .skip(1)
        .filter(|line| !line.is_empty())
        .map(|line| line.split('\t').map(str::to_string).collect())
        .collect()
}

/// Bytes written as hex, with or without spaces between them.
fn bytes(hex: &str) -> Vec<u8> {
    let digits: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    (0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).expect("hex"))
        .collect()
}

fn position(text: &str) -> u64 {
    u64::from_str_radix(text.trim_start_matches("0x"), 16).expect("a position")
}

/// One transform of the table, in one direction, over `data` at `f`.
fn pass(filter: &str, channels: u8, f: u64, data: &[u8], decode: bool) -> Vec<u8> {
    let rar5 = |kind: u8| {
        let mut out = data.to_vec();
        if decode {
            rar5_filter_pass(kind, channels, f, &mut out);
        } else {
            rar5_filter_encode(kind, channels, f, &mut out);
        }
        out
    };
    let rar3 = |which: Rar3Transform| {
        let mut out = vec![0; data.len()];
        // A RAR 3 program is handed the position modulo 2^32 (SPEC-C part
        // 0), which rows T9 and I12 are there to show.
        rar3_transform(which, decode, data, &mut out, f as u32, 0);
        out
    };
    match filter {
        "r5-delta" => rar5(0),
        "r5-call" => rar5(1),
        "r5-call-jump" => rar5(2),
        "r5-arm" => rar5(3),
        "r3-call" => rar3(Rar3Transform::X86Call),
        "r3-call-jump" => rar3(Rar3Transform::X86CallJump),
        "r3-ia64" => rar3(Rar3Transform::Itanium),
        other => panic!("a filter the table did not have before: {other}"),
    }
}

#[test]
fn every_hand_vector_row_decodes_and_encodes_as_stated() {
    let table = rows("hand-vectors.tsv");
    assert_eq!(table.len(), 53, "14 X, 5 Y, 9 T, 6 A, 14 I and 5 L rows");
    let mut both = 0;
    for row in &table {
        let (name, filter) = (&row[0], row[1].as_str());
        let f = position(&row[2]);
        let channels: u8 = row[3].parse().unwrap_or(0);
        let (stored, dec) = (bytes(&row[4]), bytes(&row[5]));
        assert_eq!(
            pass(filter, channels, f, &stored, true),
            dec,
            "{name}: decode"
        );
        let Some(enc) = row.get(6).filter(|cell| !cell.is_empty()) else {
            continue;
        };
        let enc = bytes(enc);
        assert_eq!(
            pass(filter, channels, f, &stored, false),
            enc,
            "{name}: encode"
        );
        both += 1;
    }
    assert_eq!(both, 30, "every RAR 5 row has an encode column");
}

/// SPEC-C part 5, B3, on row I14 and around it: the selector is bits 1 to
/// 4 of a bundle's first byte, so every first byte with those bits at
/// 1011 has all three slots examined, whatever bit 0 and bits 5 to 7 are,
/// and the three fields of row I1 come back as that row says.
#[test]
fn the_ia64_selector_is_bits_1_to_4_of_the_first_byte() {
    let table = rows("hand-vectors.tsv");
    let row = table.iter().find(|row| row[0] == "I1").expect("row I1");
    let (stored, dec) = (bytes(&row[4]), bytes(&row[5]));
    let f = position(&row[2]);
    for high in 0..8u8 {
        for low in 0..2u8 {
            let first = high << 5 | 0b1011 << 1 | low;
            let mut input = stored.clone();
            input[0] = first;
            let mut want = dec.clone();
            want[0] = first;
            assert_eq!(
                pass("r3-ia64", 0, f, &input, true),
                want,
                "first byte {first:#04x}"
            );
        }
    }
}

struct Keep(Vec<(Vec<u8>, Option<bool>)>);

impl Sink for Keep {
    type Out = Vec<u8>;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.0.push((out.unwrap_or_default(), outcome.checksum_ok));
        Ok(())
    }
}

/// The archives the rows were put to the reference in. Each holds its
/// span at the row's `F`, and its header carries the CRC32 of the bytes
/// the reference delivered, which are the stated reading's.
#[test]
fn every_kept_hand_vector_archive_extracts_to_the_stated_reading() {
    let mut kept = 0;
    for arm in rows("arms.tsv") {
        if arm[10] != "kept" {
            continue;
        }
        let name = &arm[0];
        let path = format!("{VECTORS}/{name}.rar");
        let archive = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive)];
        let mut sink = Keep(Vec::new());
        let options = ReadOptions::default().with_workers(Some(1));
        rarkit::extract(sources, &options, &mut sink, &mut ())
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        let stated = bytes(&arm[6]);
        let f = position(&arm[3]) as usize;
        assert!(!sink.0.is_empty(), "{name}: no member");
        for (_, ok) in &sink.0 {
            assert_eq!(*ok, Some(true), "{name}: the header's checksum");
        }
        let all: Vec<u8> = sink.0.into_iter().flat_map(|member| member.0).collect();
        assert_eq!(
            all.get(f..f + stated.len()),
            Some(&stated[..]),
            "{name}: the span at F"
        );
        kept += 1;
    }
    assert_eq!(kept, 71, "the archives kept beside the table");
}
