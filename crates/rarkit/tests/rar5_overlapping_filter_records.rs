//! RAR 5 filter records whose spans OVERLAP, or that arrive out of start
//! order, on every read path (SPEC-H2 sections 3.1 and 3.6).
//!
//! **The defect.** Two delta records naming the same span made rarkit
//! answer a 259 byte member OK with 230 bytes, on the serial arm, the tape
//! and scheduled arms and the public reader alike
//! (`oracle_stacked_filters_27sep.rs`). Two faults: the second record went
//! down the drain's hold path and waited for bytes the member never
//! produced, and the member's end checked what was PRODUCED rather than
//! what LEFT for the sink, so a member short of its declared size was
//! reported whole against section 3.1.
//!
//! **What a second record means.** Section 3.6 is silent on it; these cases
//! pin reference unrar 7.23's answer, measured black box on 27 Sep 2026 for
//! all four record types by building each stream and every subset of its
//! records and asking which subset's output the whole stream's equals. The
//! records keep the order they were READ in; a record whose span starts
//! before the end of the last record kept is ignored, and an EMPTY record
//! is kept like any other, its end being its start. So the same span, a
//! nested span either way, a partly overlapping span either way, a record
//! read while the first's span is being produced and a disjoint span that
//! starts before one read earlier all keep the earlier record alone, and
//! adjacent spans both apply. Each case below carries the subset the
//! reference kept, and is checked against the stream with only those
//! records, which every side decodes alike; where `unrar` is on the path
//! the case is checked against it directly as well.

use std::path::PathBuf;
use std::sync::Arc;

use rarkit::internals::rar5;
use rarkit::{Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink};

// ------------------------------------------------------------ the stream

/// Most significant bit first, like a block's payload (section 3.2).
#[derive(Default)]
struct Bits {
    bytes: Vec<u8>,
    count: usize,
}

impl Bits {
    fn put(&mut self, value: u32, width: u32) {
        for step in (0..width).rev() {
            if self.count.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if (value >> step) & 1 != 0 {
                self.bytes[self.count / 8] |= 1 << (7 - self.count % 8);
            }
            self.count += 1;
        }
    }
}

/// Complete tables (section 3.4): the main alphabet at eight bits for its
/// first 206 symbols and nine for the other 100, distances at six, align
/// at four, lengths at five for 20 and six for 24.
fn table_lengths() -> Vec<u8> {
    let mut lengths = vec![8u8; 206];
    lengths.extend(std::iter::repeat_n(9, 100));
    lengths.extend(std::iter::repeat_n(6, 64));
    lengths.extend(std::iter::repeat_n(4, 16));
    lengths.extend(std::iter::repeat_n(5, 20));
    lengths.extend(std::iter::repeat_n(6, 24));
    lengths
}

/// A main symbol's canonical code under [`table_lengths`].
fn main_code(symbol: u32) -> (u32, u32) {
    if symbol < 206 {
        (symbol, 8)
    } else {
        (412 + symbol - 206, 9)
    }
}

/// The counted form of section 3.6.
fn counted(bits: &mut Bits, value: u32) {
    let extra = match value {
        0..=0xff => 0,
        0x100..=0xffff => 1,
        0x1_0000..=0xff_ffff => 2,
        _ => 3,
    };
    bits.put(extra, 2);
    for index in 0..=extra {
        bits.put((value >> (8 * index)) & 0xff, 8);
    }
}

/// A record's type field and, for delta, its channel count.
#[derive(Clone, Copy, Debug)]
enum Kind {
    Delta(u32),
    E8,
    E8E9,
    Arm,
}

fn record(bits: &mut Bits, offset: u32, length: u32, kind: Kind) {
    let (symbol, width) = main_code(256);
    bits.put(symbol, width);
    counted(bits, offset);
    counted(bits, length);
    match kind {
        Kind::Delta(channels) => {
            bits.put(0, 3);
            bits.put(channels - 1, 5);
        }
        Kind::E8 => bits.put(1, 3),
        Kind::E8E9 => bits.put(2, 3),
        Kind::Arm => bits.put(3, 3),
    }
}

/// One block carrying the tables. It ends with two empty records at the
/// point it stops: the reference reads a block short when its last symbols
/// sit in its final bits, and an empty record there starts at the bytes
/// produced, so it neither applies nor moves the floor past a later span.
fn block(fill: impl FnOnce(&mut Bits), last: bool) -> Vec<u8> {
    let mut payload = Bits::default();
    for _ in 0..20 {
        payload.put(5, 4);
    }
    for length in table_lengths() {
        payload.put(u32::from(length), 5);
    }
    fill(&mut payload);
    for _ in 0..2 {
        record(&mut payload, 0, 0, Kind::Delta(1));
    }
    let final_bits = payload.count - (payload.bytes.len() - 1) * 8;
    let size = u16::try_from(payload.bytes.len()).expect("two size bytes hold it");
    let [low, high] = size.to_le_bytes();
    let mut flags = ((final_bits - 1) as u8) & 7;
    flags |= 1 << 3; // a size field of two bytes
    flags |= 0x80; // tables
    if last {
        flags |= 0x40;
    }
    let mut out = vec![flags, 0x5a ^ flags ^ low ^ high, low, high];
    out.extend_from_slice(&payload.bytes);
    out
}

/// One record as a case states it: read when `read_at` bytes have been
/// produced, naming member offsets `start..start + length`.
#[derive(Clone, Copy, Debug)]
struct Rec {
    read_at: u32,
    start: u32,
    length: u32,
    kind: Kind,
}

/// The member's packed bytes: `data` as literals with `records` read where
/// they say, in one block or cut into a block per distinct read point.
fn packed(data: &[u8], records: &[&Rec], split: bool) -> Vec<u8> {
    let mut cuts: Vec<u32> = records.iter().map(|r| r.read_at).collect();
    cuts.push(data.len() as u32);
    cuts.retain(|&cut| cut > 0);
    cuts.sort_unstable();
    cuts.dedup();
    let pieces: Vec<(u32, u32)> = if split {
        let mut at = 0;
        cuts.iter()
            .map(|&cut| {
                let piece = (at, cut);
                at = cut;
                piece
            })
            .collect()
    } else {
        vec![(0, data.len() as u32)]
    };
    let mut out = Vec::new();
    for (index, &(from, to)) in pieces.iter().enumerate() {
        let last = index + 1 == pieces.len();
        out.extend(block(
            |bits| {
                let mut at = from;
                let put = |bits: &mut Bits, from: u32, to: u32| {
                    for &byte in &data[from as usize..to as usize] {
                        let (code, width) = main_code(u32::from(byte));
                        bits.put(code, width);
                    }
                };
                for rec in records {
                    // A record read at the cut belongs to the block that
                    // begins there, and one read at the end to the last.
                    let here =
                        rec.read_at >= from && (rec.read_at < to || (last && rec.read_at == to));
                    if !here {
                        continue;
                    }
                    put(bits, at, rec.read_at);
                    at = rec.read_at;
                    record(bits, rec.start - rec.read_at, rec.length, rec.kind);
                }
                put(bits, at, to);
            },
            last,
        ));
    }
    out
}

// ------------------------------------------------------------ the container

fn vint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn header(body: &[u8]) -> Vec<u8> {
    let mut sized = Vec::new();
    vint(&mut sized, body.len() as u64);
    sized.extend_from_slice(body);
    let mut out = crc32fast::hash(&sized).to_le_bytes().to_vec();
    out.extend_from_slice(&sized);
    out
}

/// An archive of `members`, each `(packed, declared size, solid bit)`,
/// with NO data checksum: a member short of its size is then caught by
/// section 3.1 alone, which is exactly the check that was missing.
fn archive(members: &[(Vec<u8>, u64, bool)], solid: bool) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    let mut main = Vec::new();
    vint(&mut main, 1);
    vint(&mut main, 0);
    vint(&mut main, if solid { 0x04 } else { 0 });
    out.extend(header(&main));
    for (index, (packed, unpacked, member_solid)) in members.iter().enumerate() {
        let mut body = Vec::new();
        vint(&mut body, 2); // file header
        vint(&mut body, 2); // a data area follows
        vint(&mut body, packed.len() as u64);
        vint(&mut body, 0); // file flags: no data checksum
        vint(&mut body, *unpacked);
        vint(&mut body, 0); // attributes
                            // Algorithm 0, the solid bit, method 3, a 128 KiB dictionary.
        vint(&mut body, (u64::from(*member_solid) << 6) | (3 << 7));
        vint(&mut body, 0); // host os
        let name = format!("m{index}");
        vint(&mut body, name.len() as u64);
        body.extend_from_slice(name.as_bytes());
        out.extend(header(&body));
        out.extend_from_slice(packed);
    }
    let mut end = Vec::new();
    vint(&mut end, 5);
    vint(&mut end, 0);
    vint(&mut end, 0);
    out.extend(header(&end));
    out
}

/// Bytes every transform changes: x86 calls and jumps, ARM branches with
/// link, and noise between.
fn payload(length: usize, mut seed: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 8);
    while out.len() < length {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345) & 0x7fff_ffff;
        match seed % 5 {
            0 => {
                out.push(0xE8);
                out.extend_from_slice(&(seed & 0xffff).to_le_bytes());
            }
            1 => {
                out.push(0xE9);
                out.extend_from_slice(&((seed >> 3) & 0xffff).to_le_bytes());
            }
            2 => out.extend_from_slice(&[seed as u8, (seed >> 8) as u8, (seed >> 16) as u8, 0xEB]),
            _ => out.extend_from_slice(&[seed as u8, (seed >> 8) as u8]),
        }
    }
    out.truncate(length);
    out
}

// ------------------------------------------------------------ the paths

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

/// Every member's bytes, or the error kind a path stopped with.
type Answer = std::result::Result<Vec<Vec<u8>>, String>;

/// The public reader's answer.
fn reader(bytes: &[u8], options: &ReadOptions) -> Answer {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bytes.to_vec())];
    let mut sink = Keep::default();
    match rarkit::extract(sources, options, &mut sink, &mut ()) {
        Ok(_) => Ok(sink.members),
        Err(err) => Err(format!("{:?}", err.kind())),
    }
}

/// Every read path over one archive, labelled, each answering all its
/// members' bytes or the error kind it stopped with.
fn every_path(bytes: &[u8]) -> Vec<(String, Answer)> {
    let mut answers = Vec::new();
    for ahead in [true, false] {
        for workers in [None, Some(1)] {
            rarkit::probe::set_ahead_off(!ahead);
            let got = reader(bytes, &ReadOptions::default().with_workers(workers));
            rarkit::probe::set_ahead_off(false);
            answers.push((format!("reader, ahead {ahead}, workers {workers:?}"), got));
        }
    }
    let members = rar5::members(bytes);
    let chain: Vec<(&[u8], u64)> = members
        .iter()
        .map(|m| (m.packed.as_slice(), m.unpacked))
        .collect();
    let window = members[0].window;
    for window in [window, 4 << 20] {
        for parallel in [false, true] {
            for ahead in [false, true] {
                let (out, failed) =
                    rar5::decode_solid_chain_probe(&chain, window, 0, parallel, ahead);
                answers.push((
                    format!("chain, window {window}, parallel {parallel}, ahead {ahead}"),
                    failed.map_or(Ok(out), Err),
                ));
            }
        }
        if members.len() == 1 {
            for parallel in [false, true] {
                let got = rar5::decode_member(chain[0].0, chain[0].1, window, 0, parallel)
                    .map(|out| vec![out])
                    .map_err(|err| format!("{:?}", err.kind()));
                answers.push((format!("member, window {window}, parallel {parallel}"), got));
            }
            for width in [2, 4, 8] {
                for wave in [Some(1), None] {
                    for overlap in [false, true] {
                        let got = rar5::decode_member_scheduled(
                            chain[0].0, chain[0].1, window, 0, width, wave, overlap,
                        )
                        .map(|out| vec![out])
                        .map_err(|err| format!("{:?}", err.kind()));
                        answers.push((
                            format!("scheduled, window {window}, width {width}, wave {wave:?}, overlap {overlap}"),
                            got,
                        ));
                    }
                }
            }
        }
    }
    answers
}

/// Reference `unrar`'s bytes for the LAST member, or `None` when it is not
/// on the path.
fn unrar(bytes: &[u8], tag: &str) -> Option<Vec<u8>> {
    // `std::process::id` in the path: two runs of the suite on one box share
    // `temp_dir`.
    let path: PathBuf = std::env::temp_dir().join(format!(
        "rarkit-overlapping-filters-{}-{tag}.rar",
        std::process::id()
    ));
    std::fs::write(&path, bytes).ok()?;
    let listed = std::process::Command::new("unrar")
        .args(["p", "-inul"])
        .arg(&path)
        .output();
    let _ = std::fs::remove_file(&path);
    let out = listed.ok()?;
    assert!(out.status.success(), "unrar decodes {tag}");
    Some(out.stdout)
}

// ------------------------------------------------------------ the cases

/// One case: the member's size, its records in the order read, and the
/// indices of the records the reference KEPT.
struct Case {
    name: &'static str,
    size: usize,
    records: Vec<Rec>,
    kept: &'static [usize],
}

fn rec(read_at: u32, start: u32, length: u32, kind: Kind) -> Rec {
    Rec {
        read_at,
        start,
        length,
        kind,
    }
}

/// The cases, for one record type `a`, with `b` the SAME type under other
/// parameters where it has any and another type where it has none, so a
/// path that applied the wrong record reads differently.
fn cases(a: Kind, b: Kind) -> Vec<Case> {
    vec![
        Case {
            name: "the same span",
            size: 400,
            records: vec![rec(20, 20, 200, a), rec(20, 20, 200, b)],
            kept: &[0],
        },
        Case {
            name: "a second span nested inside",
            size: 400,
            records: vec![rec(20, 20, 200, a), rec(20, 60, 80, b)],
            kept: &[0],
        },
        Case {
            name: "a second span enclosing",
            size: 400,
            records: vec![rec(20, 60, 80, a), rec(20, 20, 200, b)],
            kept: &[0],
        },
        Case {
            name: "partly overlapping, the second later",
            size: 400,
            records: vec![rec(20, 20, 200, a), rec(20, 120, 200, b)],
            kept: &[0],
        },
        Case {
            name: "partly overlapping, the second earlier",
            size: 400,
            records: vec![rec(20, 120, 200, a), rec(20, 20, 200, b)],
            kept: &[0],
        },
        Case {
            name: "a second record read mid-span",
            size: 400,
            records: vec![rec(20, 20, 200, a), rec(100, 100, 60, b)],
            kept: &[0],
        },
        Case {
            name: "a second record read mid-span, running past it",
            size: 400,
            records: vec![rec(20, 20, 200, a), rec(100, 150, 200, b)],
            kept: &[0],
        },
        Case {
            name: "adjacent spans",
            size: 400,
            records: vec![rec(20, 20, 100, a), rec(20, 120, 100, b)],
            kept: &[0, 1],
        },
        Case {
            name: "disjoint spans, in order with a gap",
            size: 400,
            records: vec![rec(20, 20, 50, a), rec(20, 150, 50, b)],
            kept: &[0, 1],
        },
        Case {
            name: "disjoint spans, the second starting earlier",
            size: 400,
            records: vec![rec(20, 200, 100, a), rec(20, 20, 100, b)],
            kept: &[0],
        },
        Case {
            name: "three, the third overlapping both kept",
            size: 500,
            records: vec![
                rec(20, 20, 100, a),
                rec(20, 200, 100, b),
                rec(20, 100, 120, a),
            ],
            kept: &[0, 1],
        },
        Case {
            name: "three, the third overlapping only the ignored second",
            size: 500,
            records: vec![
                rec(20, 20, 100, a),
                rec(20, 60, 100, b),
                rec(20, 150, 100, a),
            ],
            kept: &[0, 2],
        },
        Case {
            name: "an empty record ahead of a later span",
            size: 400,
            records: vec![rec(20, 300, 0, a), rec(20, 20, 100, b)],
            kept: &[0],
        },
        Case {
            name: "an empty record, then a span at its start",
            size: 400,
            records: vec![rec(20, 300, 0, a), rec(20, 300, 100, b)],
            kept: &[0, 1],
        },
        Case {
            name: "an empty record inside a kept span",
            size: 400,
            records: vec![rec(20, 20, 330, a), rec(20, 300, 0, b), rec(20, 320, 60, b)],
            kept: &[0],
        },
        // The arms of `specs/vectors-H/h2-stacked-filter-probe.py` the
        // shapes above do not already take.
        Case {
            name: "the same span, the second read later",
            size: 400,
            records: vec![rec(0, 19, 211, a), rec(10, 19, 211, b)],
            kept: &[0],
        },
        Case {
            name: "overlapping by one byte",
            size: 400,
            records: vec![rec(20, 20, 100, a), rec(20, 119, 100, b)],
            kept: &[0],
        },
        Case {
            name: "three on one span",
            size: 400,
            records: vec![
                rec(20, 20, 200, a),
                rec(20, 20, 200, b),
                rec(20, 20, 200, a),
            ],
            kept: &[0],
        },
        Case {
            name: "a second record read after the first span ends",
            size: 400,
            records: vec![rec(0, 19, 100, a), rec(150, 150, 50, b)],
            kept: &[0, 1],
        },
        Case {
            name: "an empty record at a later span's start",
            size: 400,
            records: vec![rec(20, 20, 0, a), rec(20, 20, 50, b)],
            kept: &[0, 1],
        },
        Case {
            name: "a dropped record running past the member's end",
            size: 400,
            records: vec![rec(20, 20, 100, a), rec(20, 50, 400, b)],
            kept: &[0],
        },
    ]
}

fn kinds() -> [(&'static str, Kind, Kind); 4] {
    [
        ("delta", Kind::Delta(3), Kind::Delta(5)),
        ("x86 call", Kind::E8, Kind::Arm),
        ("x86 call and jump", Kind::E8E9, Kind::Delta(4)),
        ("ARM", Kind::Arm, Kind::E8E9),
    ]
}

/// A lead member for the solid chain: literals only, so the case member's
/// records are measured from its OWN start (section 3.6).
fn lead() -> (Vec<u8>, u64, bool) {
    let data = payload(300, 11);
    (packed(&data, &[], false), 300, false)
}

fn check_case(kind: &str, case: &Case, split: bool) {
    let data = payload(case.size, 7);
    let all: Vec<&Rec> = case.records.iter().collect();
    let kept: Vec<&Rec> = case.kept.iter().map(|&i| &case.records[i]).collect();
    let label = format!(
        "{kind}: {}{}",
        case.name,
        if split { ", a block per record" } else { "" }
    );
    let size = case.size as u64;

    for solid in [false, true] {
        let members = |records: &[&Rec]| {
            let member = (packed(&data, records, split), size, solid);
            if solid {
                vec![lead(), member]
            } else {
                vec![member]
            }
        };
        let theirs = archive(&members(&all), solid);
        let control = archive(&members(&kept), solid);

        // The control: records in order and apart, which every side reads
        // alike. Its bytes are what the reference's answer means.
        let want = rar5::decode_solid_chain_probe(
            &rar5::members(&control)
                .iter()
                .map(|m| (m.packed.as_slice(), m.unpacked))
                .collect::<Vec<_>>(),
            1 << 17,
            0,
            false,
            false,
        );
        assert_eq!(want.1, None, "{label}: the control decodes");
        let want = want.0;
        assert_eq!(
            want.last().map(Vec::len),
            Some(case.size),
            "{label}: the control is whole"
        );
        #[cfg(feature = "oracle-compare")]
        {
            let old = rarkit_oracle::extract(&[&control], None)
                .expect("the old engine reads the control");
            assert!(
                old.last().is_some_and(|m| m.data == *want.last().unwrap()),
                "{label}: the old engine agrees on the control"
            );
        }

        for (path, got) in every_path(&theirs) {
            match got {
                Ok(got) => assert!(
                    got == want,
                    "{label}, solid {solid}: {path}: not the reference's bytes"
                ),
                Err(kind) => panic!("{label}, solid {solid}: {path}: failed {kind}"),
            }
        }
        if !solid {
            let tag = format!(
                "{}-{}-{}",
                kind.replace(' ', "_"),
                case.name.replace([' ', ','], "_"),
                split
            );
            if let Some(reference) = unrar(&theirs, &tag) {
                assert!(
                    reference == *want.last().unwrap(),
                    "{label}: unrar 7.23 disagrees"
                );
            } else {
                eprintln!("    unrar is not on the path; {label} checked against the control only");
            }
        }
    }
}

#[test]
fn a_record_starting_before_the_last_kept_record_ends_is_ignored() {
    for (kind, a, b) in kinds() {
        for case in cases(a, b) {
            check_case(kind, &case, false);
        }
    }
}

/// The same cases with every record at the head of a block of its own, so
/// the second record reaches the queue from a later block: the tape arms
/// decode those blocks on other lanes and resolve the record at apply.
#[test]
fn the_same_holds_when_the_records_sit_in_different_blocks() {
    for (kind, a, b) in kinds() {
        for case in cases(a, b) {
            check_case(kind, &case, true);
        }
    }
}

/// Without the reference: a record that would have ended the member short
/// never answers OK. The 27 Sep finding's own shape, two delta records on
/// one span, fails no path and is whole on every one.
#[test]
fn no_path_answers_a_short_member_ok() {
    let data = payload(259, 3);
    let records = [
        rec(19, 19, 211, Kind::Delta(19)),
        rec(19, 19, 211, Kind::Delta(14)),
    ];
    let all: Vec<&Rec> = records.iter().collect();
    let bytes = archive(&[(packed(&data, &all, false), 259, false)], false);
    for (path, got) in every_path(&bytes) {
        if let Ok(members) = got {
            assert_eq!(members[0].len(), 259, "{path}: SPEC-H2 3.1");
        }
    }
}

/// A KEPT record whose span leaves the member is still `FilterRange`
/// (section 3.6). The reference writes the bytes before the span and
/// stops, and passes the short member when the header's CRC32 matches
/// them; section 3.1 forbids rarkit that, so this difference is pinned.
#[test]
fn a_kept_span_past_the_members_end_is_filter_range() {
    let data = payload(259, 3);
    let records = [rec(19, 19, 300, Kind::Delta(3))];
    let all: Vec<&Rec> = records.iter().collect();
    let bytes = archive(&[(packed(&data, &all, false), 259, false)], false);
    for (path, got) in every_path(&bytes) {
        match got {
            Ok(_) => panic!("{path}: answered OK"),
            Err(kind) => assert!(kind.contains("FilterRange"), "{path}: failed {kind}"),
        }
    }
}
