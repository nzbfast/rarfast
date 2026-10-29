//! RAR 5 filter records LONGER than 0x3ffff bytes, and records that start
//! behind the end of the last one kept, on members long enough to reach
//! one window past them (SPEC-H2 3.6, "Long records" and "Where the
//! reference parts from the order rule", 28 Sep 2026).
//!
//! **The defect.** Until 28 Sep rarkit refused any record longer than
//! 0x3ffff when it was READ, as `FilterRange`, and so failed members that
//! reference unrar 7.23 extracts correctly: at a 4 MiB dictionary a delta
//! span of 0x3fffff bytes runs in full there. With `D` the declared
//! dictionary and `W = max(D, 256 KiB)`, section 3.6 now reads, in order:
//!
//! 1. a record longer than 0x400000 is ignored as though never read, and
//!    does not move the order rule's floor;
//! 2. the order rule drops a record starting before the last kept span's
//!    end, whatever its length;
//! 3. a KEPT span of `W` bytes or more is `FilterRange`;
//! 4. a KEPT span shorter than `W` runs over the whole of it.
//!
//! Rules 1 and 4 MATCH the reference. Rule 3 fails loudly where
//! the reference stops its output silently at the span's start, and rule 2
//! keeps rarkit's order rule where the reference runs a record behind the
//! floor one window later, at `start + W`, on a member long enough to reach
//! it. Both are pinned below as differences: rarkit's answer is asserted on
//! every read path, and where `unrar` is on the path its answer is asserted
//! too, as the reading section 3.6 measured, so a change in either side
//! shows. The recipes are `specs/vectors-H/h2-far-record-probe.py`'s.
//!
//! Every member here is hand built: genuine rar 7.23 writes spans of at
//! most 0x10000, ascending and disjoint (section 3.6's census).

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
    Delta(u8),
    E8,
    E8E9,
    Arm,
}

impl Kind {
    fn field(self) -> (u8, u8) {
        match self {
            Kind::Delta(channels) => (0, channels),
            Kind::E8 => (1, 0),
            Kind::E8E9 => (2, 0),
            Kind::Arm => (3, 0),
        }
    }
}

fn record(bits: &mut Bits, offset: u32, length: u32, kind: Kind) {
    let (symbol, width) = main_code(256);
    bits.put(symbol, width);
    counted(bits, offset);
    counted(bits, length);
    let (field, channels) = kind.field();
    bits.put(u32::from(field), 3);
    if field == 0 {
        bits.put(u32::from(channels) - 1, 5);
    }
}

/// One record as a case states it: read after `read_at` literals, naming
/// member offsets `start..start + length`. `start` is a `u64` and the
/// length a `u32` so a case can state what the counted fields hold.
#[derive(Clone, Copy, Debug)]
struct Rec {
    read_at: u32,
    start: u64,
    length: u32,
    kind: Kind,
}

fn rec(read_at: u32, start: u64, length: u32, kind: Kind) -> Rec {
    Rec {
        read_at,
        start,
        length,
        kind,
    }
}

/// The member's packed bytes: `data` as literals with `records` read where
/// they say, in ONE block whose size takes three bytes (section 3.2), so a
/// member of four megabytes needs no block boundary. It ends with two empty
/// records: the reference reads a block short when its last symbols sit in
/// its final bits, and an empty record at the member's end moves nothing.
fn packed(data: &[u8], records: &[Rec]) -> Vec<u8> {
    let mut payload = Bits::default();
    for _ in 0..20 {
        payload.put(5, 4);
    }
    for length in table_lengths() {
        payload.put(u32::from(length), 5);
    }
    let mut at = 0usize;
    let mut put = |bits: &mut Bits, to: usize| {
        for &byte in &data[at..to] {
            let (code, width) = main_code(u32::from(byte));
            bits.put(code, width);
        }
        at = to;
    };
    for r in records {
        put(&mut payload, r.read_at as usize);
        let offset = u32::try_from(r.start - u64::from(r.read_at)).expect("a counted offset");
        record(&mut payload, offset, r.length, r.kind);
    }
    put(&mut payload, data.len());
    for _ in 0..2 {
        record(&mut payload, 0, 0, Kind::Delta(1));
    }
    let final_bits = payload.count - (payload.bytes.len() - 1) * 8;
    let size = payload.bytes.len() as u32;
    assert!(size < 1 << 24, "three size bytes hold it");
    let [low, mid, high, _] = size.to_le_bytes();
    let mut flags = ((final_bits - 1) as u8) & 7;
    flags |= 2 << 3; // a size field of three bytes
    flags |= 0x80; // tables
    flags |= 0x40; // the last block
    let mut out = vec![flags, 0x5a ^ flags ^ low ^ mid ^ high, low, mid, high];
    out.extend_from_slice(&payload.bytes);
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

/// A one member archive, method 3, dictionary `128 KiB << dictlog`, with NO
/// data checksum, so a member short of its size is caught by section 3.1
/// alone and `unrar p` prints whatever the reference wrote.
fn archive(packed: &[u8], unpacked: u64, dictlog: u64) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    let mut main = Vec::new();
    vint(&mut main, 1);
    vint(&mut main, 0);
    vint(&mut main, 0);
    out.extend(header(&main));
    let mut body = Vec::new();
    vint(&mut body, 2); // file header
    vint(&mut body, 2); // a data area follows
    vint(&mut body, packed.len() as u64);
    vint(&mut body, 0); // file flags: no data checksum
    vint(&mut body, unpacked);
    vint(&mut body, 0); // attributes
    vint(&mut body, (3 << 7) | (dictlog << 10)); // algorithm 0, method 3
    vint(&mut body, 0); // host os
    vint(&mut body, 1);
    body.push(b'm');
    out.extend(header(&body));
    out.extend_from_slice(packed);
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

/// `raw` with each of `records` run over its span, in the order given: the
/// decoder's own transforms through the `internals` seam, so what this
/// checks is WHICH spans run and over which bytes, not the transforms.
fn applied(raw: &[u8], records: &[(u64, u32, Kind)]) -> Vec<u8> {
    let mut out = raw.to_vec();
    for &(start, length, kind) in records {
        let (field, channels) = kind.field();
        let span = &mut out[start as usize..start as usize + length as usize];
        rar5::rar5_filter_pass(field, channels, start, span);
    }
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

/// The member's bytes, or the error kind a path stopped with.
type Answer = std::result::Result<Vec<u8>, String>;

/// The public reader's answer.
fn reader(bytes: &[u8], options: &ReadOptions) -> Answer {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bytes.to_vec())];
    let mut sink = Keep::default();
    match rarkit::extract(sources, options, &mut sink, &mut ()) {
        Ok(_) => Ok(sink.members.pop().unwrap_or_default()),
        Err(err) => Err(format!("{:?}", err.kind())),
    }
}

/// Every read path over a one member archive, labelled: the public reader
/// with and without decode ahead and a worker, the serial and tape arms,
/// the solid chain probe and the scheduled arms. The window is the one the
/// header declares on every path, because `W` is measured from it.
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
    let (packed, unpacked, window) = (&members[0].packed, members[0].unpacked, members[0].window);
    for parallel in [false, true] {
        let got = rar5::decode_member(packed, unpacked, window, 0, parallel)
            .map_err(|err| format!("{:?}", err.kind()));
        answers.push((format!("member, parallel {parallel}"), got));
        for ahead in [false, true] {
            let (mut out, failed) = rar5::decode_solid_chain_probe(
                &[(packed.as_slice(), unpacked)],
                window,
                0,
                parallel,
                ahead,
            );
            answers.push((
                format!("chain, parallel {parallel}, ahead {ahead}"),
                failed.map_or(Ok(out.pop().unwrap_or_default()), Err),
            ));
        }
    }
    for width in [2, 8] {
        for wave in [Some(1), None] {
            for overlap in [false, true] {
                let got = rar5::decode_member_scheduled(
                    packed, unpacked, window, 0, width, wave, overlap,
                )
                .map_err(|err| format!("{:?}", err.kind()));
                answers.push((
                    format!("scheduled, width {width}, wave {wave:?}, overlap {overlap}"),
                    got,
                ));
            }
        }
    }
    answers
}

/// Reference `unrar`'s bytes for the member, or `None` when it is not on
/// the path.
fn unrar(bytes: &[u8], tag: &str) -> Option<Vec<u8>> {
    // `std::process::id` in the path: two runs of the suite on one box share
    // `temp_dir`.
    let path: PathBuf = std::env::temp_dir().join(format!(
        "rarkit-long-filters-{}-{tag}.rar",
        std::process::id()
    ));
    std::fs::write(&path, bytes).ok()?;
    let printed = std::process::Command::new("unrar")
        .args(["p", "-inul"])
        .arg(&path)
        .output();
    let _ = std::fs::remove_file(&path);
    Some(printed.ok()?.stdout)
}

/// A member of `literals` literals with `records`, at dictionary
/// `128 KiB << dictlog`: its raw bytes and its archive.
fn build(literals: usize, records: &[Rec], dictlog: u64) -> (Vec<u8>, Vec<u8>) {
    let raw = payload(literals, 7);
    let bytes = archive(&packed(&raw, records), literals as u64, dictlog);
    (raw, bytes)
}

/// Every path answers `want`.
fn every_path_is(label: &str, bytes: &[u8], want: &[u8]) {
    for (path, got) in every_path(bytes) {
        match got {
            Ok(got) => assert!(
                got == want,
                "{label}: {path}: not the bytes section 3.6 names ({} against {})",
                got.len(),
                want.len()
            ),
            Err(kind) => panic!("{label}: {path}: failed {kind}"),
        }
    }
}

fn tag(label: &str) -> String {
    label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// `W` for dictionary `128 KiB << dictlog`.
fn window_bound(dictlog: u64) -> u64 {
    (128u64 << 10 << dictlog).max(256 << 10)
}

// ------------------------------------------------------------ rule 4

/// A KEPT span shorter than `W` runs over the whole of it, above 0x3ffff
/// too: the spans `h2-far-record-probe.py`'s default arms and `--bisect`
/// step 1 run, at `D` of 128 KiB (the 0x3ffff controls), 512 KiB, 4 MiB and
/// 8 MiB, for each record type. Every path gives the transformed member,
/// and so does the reference.
#[test]
fn a_kept_span_shorter_than_w_runs_in_full() {
    let cases: &[(&str, u64, u32, Kind)] = &[
        (
            "control: delta 0x3ffff at 128 KiB",
            0,
            0x3_ffff,
            Kind::Delta(3),
        ),
        ("control: x86 0x3ffff at 128 KiB", 0, 0x3_ffff, Kind::E8),
        ("ARM 0x7ffff at 512 KiB", 2, 0x7_ffff, Kind::Arm),
        ("delta 0x40000 at 4 MiB", 5, 0x4_0000, Kind::Delta(3)),
        ("x86 0x40000 at 4 MiB", 5, 0x4_0000, Kind::E8),
        ("delta 0x50000 at 4 MiB", 5, 0x5_0000, Kind::Delta(3)),
        ("delta 0x3fffff at 4 MiB", 5, 0x3f_ffff, Kind::Delta(3)),
        (
            "x86 call and jump 0x3fffff at 4 MiB",
            5,
            0x3f_ffff,
            Kind::E8E9,
        ),
        ("delta 0x400000 at 8 MiB", 6, 0x40_0000, Kind::Delta(4)),
    ];
    for &(label, dictlog, length, kind) in cases {
        assert!(
            u64::from(length) < window_bound(dictlog),
            "{label}: shorter than W"
        );
        let literals = 19 + length as usize + 0x100;
        let (raw, bytes) = build(literals, &[rec(19, 19, length, kind)], dictlog);
        let want = applied(&raw, &[(19, length, kind)]);
        assert!(want != raw, "{label}: the transform changes the span");
        every_path_is(label, &bytes, &want);
        if let Some(reference) = unrar(&bytes, &tag(label)) {
            assert!(reference == want, "{label}: unrar 7.23 disagrees");
        }
    }
}

/// A span starting further ahead of the bytes produced than the window is
/// not refused: one 0x50000 bytes ahead at `D` = 128 KiB runs, and a long
/// kept span leaves the order rule's floor at its end, so a short record
/// after it runs and one inside it is dropped (the probe's "far" and
/// "long, then short" arms; its "far" arms with a record BEHIND the far
/// one are differences, pinned with the others below).
/// A case: its label, `dictlog`, the member's literals, its records, and
/// the indices of the records that run.
type Case = (&'static str, u64, usize, Vec<Rec>, Vec<usize>);

#[test]
fn a_far_start_and_a_long_span_keep_the_order_rule() {
    let cases: Vec<Case> = vec![
        (
            "one record 0x50000 ahead at 128 KiB",
            0,
            0x60000,
            vec![rec(19, 0x5_0013, 100, Kind::Delta(3))],
            vec![0],
        ),
        (
            "far control: the second after the first",
            0,
            0x60000,
            vec![
                rec(19, 0x5_0013, 100, Kind::Delta(3)),
                rec(19, 0x5_0113, 100, Kind::Delta(5)),
            ],
            vec![0, 1],
        ),
        (
            "long, then short after it, at 4 MiB",
            5,
            0x60000,
            vec![
                rec(19, 19, 0x4_0000, Kind::Delta(3)),
                rec(19, 0x4_0023, 100, Kind::Delta(5)),
            ],
            vec![0, 1],
        ),
        (
            "long, then short inside it, at 4 MiB",
            5,
            0x60000,
            vec![
                rec(19, 19, 0x4_0000, Kind::Delta(3)),
                rec(19, 119, 100, Kind::Delta(5)),
            ],
            vec![0],
        ),
    ];
    for (label, dictlog, literals, records, kept) in &cases {
        let (raw, bytes) = build(*literals, records, *dictlog);
        let kept: Vec<_> = kept
            .iter()
            .map(|&i| (records[i].start, records[i].length, records[i].kind))
            .collect();
        let want = applied(&raw, &kept);
        every_path_is(label, &bytes, &want);
        if let Some(reference) = unrar(&bytes, &tag(label)) {
            assert!(reference == want, "{label}: unrar 7.23 disagrees");
        }
    }
}

// ------------------------------------------------------------ rule 1

/// A record longer than 0x400000 is ignored as though never read, at any
/// dictionary, and does not move the floor: a record after it on an
/// EARLIER span still runs (`--bisect` step 2's cap and the probe's
/// "capped" and "0xffffffff" arms). 0x400000 itself is read: kept and
/// shorter than `W` at 8 MiB it runs (rule 4's case above), and at 128 KiB
/// it is a kept span past the member's end, `FilterRange`.
#[test]
fn a_record_longer_than_4_mib_is_never_read() {
    for dictlog in [0, 5, 6] {
        let cases: Vec<(String, usize, Vec<Rec>, Vec<usize>)> = vec![
            (
                format!("capped 0x400001, then [50,150), at dictlog {dictlog}"),
                259,
                vec![
                    rec(19, 19, 0x40_0001, Kind::Delta(3)),
                    rec(19, 50, 100, Kind::Delta(5)),
                ],
                vec![1],
            ),
            (
                format!("capped 0x400001, then [19,119), at dictlog {dictlog}"),
                259,
                vec![
                    rec(19, 19, 0x40_0001, Kind::Delta(3)),
                    rec(19, 19, 100, Kind::Delta(5)),
                ],
                vec![1],
            ),
            (
                format!("0xffffffff alone, at dictlog {dictlog}"),
                0x6_0000,
                vec![rec(19, 19, u32::MAX, Kind::Delta(3))],
                vec![],
            ),
            (
                format!("0xffffffff, then [19,119), at dictlog {dictlog}"),
                259,
                vec![rec(19, 19, u32::MAX, Kind::E8), rec(19, 19, 100, Kind::E8)],
                vec![1],
            ),
        ];
        for (label, literals, records, kept) in &cases {
            let (raw, bytes) = build(*literals, records, dictlog);
            let kept: Vec<_> = kept
                .iter()
                .map(|&i| (records[i].start, records[i].length, records[i].kind))
                .collect();
            let want = applied(&raw, &kept);
            every_path_is(label, &bytes, &want);
            if let Some(reference) = unrar(&bytes, &tag(label)) {
                assert!(reference == want, "{label}: unrar 7.23 disagrees");
            }
        }
    }
}

// ------------------------------------------------------------ rule 3

/// A KEPT span of `W` bytes or more is `FilterRange` on every path, though
/// it lies inside the member. PINNED DIFFERENCE (section 3.6 rule 3): the
/// reference writes the bytes before the span and stops, silently, as for
/// a kept span past the member's end; section 3.1 forbids rarkit a short
/// member, so it fails loudly.
#[test]
fn a_kept_span_of_w_or_more_is_filter_range() {
    let cases: &[(&str, u64, u32)] = &[
        ("0x40000 at 128 KiB", 0, 0x4_0000),
        ("0x40000 at 256 KiB", 1, 0x4_0000),
        ("0x80000 at 512 KiB", 2, 0x8_0000),
        ("0x400000 at 4 MiB", 5, 0x40_0000),
    ];
    for &(label, dictlog, length) in cases {
        assert!(
            u64::from(length) >= window_bound(dictlog),
            "{label}: at least W"
        );
        let literals = 19 + length as usize + 0x100;
        let (_raw, bytes) = build(literals, &[rec(19, 19, length, Kind::Delta(3))], dictlog);
        for (path, got) in every_path(&bytes) {
            match got {
                Ok(got) => panic!("{label}: {path}: answered OK with {} bytes", got.len()),
                Err(kind) => assert!(
                    kind.contains("FilterRange"),
                    "{label}: {path}: failed {kind}"
                ),
            }
        }
        if let Some(reference) = unrar(&bytes, &tag(label)) {
            assert_eq!(
                reference.len(),
                19,
                "{label}: the reference stops at the span's start"
            );
        }
    }
}

// ------------------------------------------------------------ rule 2

/// One pinned difference behind the floor: the records, the member, what
/// rarkit keeps (in place) and what the reference was measured to do.
struct Behind {
    name: &'static str,
    dictlog: u64,
    literals: usize,
    records: Vec<Rec>,
    /// The records rarkit runs, in place.
    kept: Vec<usize>,
    reference: Reading,
}

/// What reference unrar 7.23 writes, per section 3.6's measurement.
enum Reading {
    /// Records run in place (`false`) or at `start + W` (`true`).
    Runs(Vec<(usize, bool)>),
    /// A prefix of rarkit's bytes, stopping at this member offset.
    StopsAt(u64),
}

fn behind_cases() -> Vec<Behind> {
    let w0 = window_bound(0);
    let d = Kind::Delta;
    vec![
        Behind {
            name: "[119,169) then [19,275)",
            dictlog: 0,
            literals: 19 + 0x6_0000,
            records: vec![rec(19, 119, 50, d(3)), rec(19, 19, 0x100, d(5))],
            kept: vec![0],
            reference: Reading::Runs(vec![(0, false), (1, true)]),
        },
        Behind {
            name: "two deltas on [19,230), the fuzz finding",
            dictlog: 0,
            literals: 19 + 0x6_0000,
            records: vec![rec(19, 19, 211, d(19)), rec(19, 19, 211, d(14))],
            kept: vec![0],
            reference: Reading::Runs(vec![(0, false), (1, true)]),
        },
        Behind {
            name: "x86 then delta on [19,230)",
            dictlog: 0,
            literals: 19 + 0x6_0000,
            records: vec![rec(19, 19, 211, Kind::E8), rec(19, 19, 211, d(4))],
            kept: vec![0],
            reference: Reading::Runs(vec![(0, false), (1, true)]),
        },
        Behind {
            name: "[119,169) then [19,275) at 512 KiB",
            dictlog: 2,
            literals: 19 + 0xA_0000,
            records: vec![rec(19, 119, 50, d(3)), rec(19, 19, 0x100, d(5))],
            kept: vec![0],
            reference: Reading::Runs(vec![(0, false), (1, true)]),
        },
        Behind {
            name: "[119,169) then [19,275) at 4 MiB",
            dictlog: 5,
            literals: 19 + 0x40_0100,
            records: vec![rec(19, 119, 50, d(3)), rec(19, 19, 0x100, d(5))],
            kept: vec![0],
            reference: Reading::Runs(vec![(0, false), (1, true)]),
        },
        Behind {
            name: "[19,119) [69,169) [179,229)",
            dictlog: 0,
            literals: 19 + 0x6_0000,
            records: vec![
                rec(19, 19, 100, d(3)),
                rec(19, 69, 100, d(5)),
                rec(19, 179, 50, d(7)),
            ],
            kept: vec![0, 2],
            reference: Reading::Runs(vec![(0, false), (1, true), (2, false)]),
        },
        Behind {
            name: "an empty record at 100, then [19,69): no difference",
            dictlog: 0,
            literals: 19 + 0x6_0000,
            records: vec![rec(19, 100, 0, d(3)), rec(19, 19, 50, d(5))],
            kept: vec![],
            reference: Reading::Runs(vec![]),
        },
        Behind {
            name: "[19,119) [69,169) [W+100,W+150)",
            dictlog: 0,
            literals: 19 + 0x6_0000,
            records: vec![
                rec(19, 19, 100, d(3)),
                rec(19, 69, 100, d(5)),
                rec(19, w0 + 100, 50, d(7)),
            ],
            kept: vec![0, 2],
            reference: Reading::Runs(vec![(0, false), (1, true)]),
        },
        Behind {
            name: "[119,169) then [19,+0x3ffff), the member ending inside the shift",
            dictlog: 0,
            literals: 19 + 0x6_0000,
            records: vec![rec(19, 119, 50, d(3)), rec(19, 19, 0x3_ffff, d(5))],
            kept: vec![0],
            reference: Reading::StopsAt(19 + w0),
        },
        Behind {
            name: "[119,169) then [19,+0x40000), the member ending inside the shift",
            dictlog: 0,
            literals: 19 + 0x6_0000,
            records: vec![rec(19, 119, 50, d(3)), rec(19, 19, 0x4_0000, d(5))],
            kept: vec![0],
            reference: Reading::StopsAt(19 + w0),
        },
        Behind {
            name: "[119,169) then [19,275) in a member ending before 19 + W: no difference",
            dictlog: 0,
            literals: 19 + 0x4_0000,
            records: vec![rec(19, 119, 50, d(3)), rec(19, 19, 0x100, d(5))],
            kept: vec![0],
            reference: Reading::Runs(vec![(0, false)]),
        },
        // `--bisect` step 3: once the record that set the floor started
        // `W - 0x1017` or more ahead, the record behind it runs IN PLACE;
        // a byte less and it is dropped. The member ends before `19 + W`
        // either way.
        Behind {
            name: "a first record W - 0x1018 ahead, then [19,119): no difference",
            dictlog: 0,
            literals: 19 + (w0 - 0x1018) as usize + 100 + 0x200,
            records: vec![rec(19, 19 + w0 - 0x1018, 100, d(3)), rec(19, 19, 100, d(5))],
            kept: vec![0],
            reference: Reading::Runs(vec![(0, false)]),
        },
        Behind {
            name: "a first record W - 0x1017 ahead, then [19,119)",
            dictlog: 0,
            literals: 19 + (w0 - 0x1017) as usize + 100 + 0x200,
            records: vec![rec(19, 19 + w0 - 0x1017, 100, d(3)), rec(19, 19, 100, d(5))],
            kept: vec![0],
            reference: Reading::Runs(vec![(0, false), (1, false)]),
        },
        Behind {
            name: "a first record W - 0x1017 ahead at 4 MiB, then [19,119)",
            dictlog: 5,
            literals: 19 + (window_bound(5) - 0x1017) as usize + 100 + 0x200,
            records: vec![
                rec(19, 19 + window_bound(5) - 0x1017, 100, d(3)),
                rec(19, 19, 100, d(5)),
            ],
            kept: vec![0],
            reference: Reading::Runs(vec![(0, false), (1, false)]),
        },
        // The probe's "far" arms: a first record 0x50000 ahead is past
        // `W - 0x1017`, so the reference runs the record behind it in place.
        Behind {
            name: "far: a first record 0x50000 ahead, then [19,119)",
            dictlog: 0,
            literals: 0x6_0000,
            records: vec![rec(19, 0x5_0013, 100, d(3)), rec(19, 19, 100, d(5))],
            kept: vec![0],
            reference: Reading::Runs(vec![(0, false), (1, false)]),
        },
        Behind {
            name: "far: a first record 0x50000 ahead, then one 0x10000 ahead",
            dictlog: 0,
            literals: 0x6_0000,
            records: vec![rec(19, 0x5_0013, 100, d(3)), rec(19, 0x1_0013, 100, d(5))],
            kept: vec![0],
            reference: Reading::Runs(vec![(0, false), (1, false)]),
        },
    ]
}

/// A record starting before the last kept span's end is DROPPED on members
/// of any length (the order rule is kept), and each case is pinned
/// against what the reference does instead: it runs such a record one
/// window later, at `start + W`, without moving the floor; a member ending
/// inside that shifted span stops there, silently; and the corners section
/// 3.6 lists fit no rule (`h2-far-record-probe.py --shift` and `--bisect`
/// step 3). The fuzz targets' oracle comparisons count this class as known.
#[test]
fn a_record_behind_the_floor_is_dropped_where_the_reference_shifts_it() {
    for case in behind_cases() {
        let label = case.name;
        let w = window_bound(case.dictlog);
        let (raw, bytes) = build(case.literals, &case.records, case.dictlog);
        let span = |i: usize| {
            (
                case.records[i].start,
                case.records[i].length,
                case.records[i].kind,
            )
        };
        let kept: Vec<_> = case.kept.iter().map(|&i| span(i)).collect();
        let want = applied(&raw, &kept);
        every_path_is(label, &bytes, &want);

        let Some(reference) = unrar(&bytes, &tag(label)) else {
            eprintln!("    unrar is not on the path; {label} checked on rarkit's side only");
            continue;
        };
        match &case.reference {
            Reading::Runs(runs) => {
                let theirs: Vec<_> = runs
                    .iter()
                    .map(|&(i, shifted)| {
                        let (start, length, kind) = span(i);
                        (if shifted { start + w } else { start }, length, kind)
                    })
                    .collect();
                assert!(
                    reference == applied(&raw, &theirs),
                    "{label}: unrar 7.23 no longer reads as section 3.6 measured"
                );
                let differs = runs
                    .iter()
                    .any(|&(i, shifted)| shifted || !case.kept.contains(&i));
                assert_eq!(reference != want, differs, "{label}: the pinned difference");
            }
            Reading::StopsAt(at) => {
                assert_eq!(
                    reference.len() as u64,
                    *at,
                    "{label}: where the reference stops"
                );
                assert!(
                    want.starts_with(&reference),
                    "{label}: a prefix of rarkit's bytes"
                );
            }
        }
    }
}

// ------------------------------------------------------------ the old engine

#[cfg(feature = "oracle-compare")]
/// The one class the oracle fuzz targets must not report as a finding
/// (`fuzz/fuzz_targets/oracle_support.rs`, `long_records`), pinned here so
/// the seam they ask and the old engine's answer are both held: the old
/// engine FAILS a record longer than 0x400000 ("filter range exceeds
/// output") where the reference and rarkit ignore it, and RUNS a kept span
/// of `W` or more where rarkit fails it and the reference stops silently.
/// Both sides of each are checked, so a change in either shows.
#[test]
fn the_old_engine_parts_from_section_3_6_on_long_records_and_the_seam_names_it() {
    let ignored = build(
        259,
        &[
            rec(19, 19, 0x40_0001, Kind::Delta(3)),
            rec(19, 50, 100, Kind::Delta(5)),
        ],
        0,
    )
    .1;
    assert_eq!(rar5::long_filter_records(&ignored), [1, 0]);
    assert!(reader(&ignored, &ReadOptions::default()).is_ok());
    assert!(rarkit_oracle::extract(&[&ignored], None).is_err());

    let at_w = build(0x4_0200, &[rec(19, 19, 0x4_0000, Kind::Delta(3))], 0).1;
    assert_eq!(rar5::long_filter_records(&at_w), [0, 1]);
    assert!(reader(&at_w, &ReadOptions::default()).is_err());
    assert!(rarkit_oracle::extract(&[&at_w], None).is_ok());

    // And a record the rule runs is neither: the seam answers zero.
    let runs = build(0x4_0200, &[rec(19, 19, 0x4_0000, Kind::Delta(3))], 5).1;
    assert_eq!(rar5::long_filter_records(&runs), [0, 0]);
}
