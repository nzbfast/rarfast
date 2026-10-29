//! A kept RAR 5 filter record whose span starts at or past its member's
//! declared size, the member that declares ZERO bytes included, on every
//! read path (SPEC-H2 3.1, "a kept filter record whose span is not wholly
//! inside the member's declared output", as restated on 8 Oct 2026).
//!
//! The rule, by what the stream does with the span and by whether the
//! member carries a checksum:
//!
//! - the stream COMPLETES the span and the member carries NO checksum: the
//!   member PASSES and its output is its declared bytes, none past them;
//! - the stream completes the span and the member carries a checksum:
//!   `FilterRange`;
//! - the stream does NOT complete the span: the record is dropped at the
//!   member's end and fails nothing, with a checksum or without;
//! - in every case the decode goes on and the member after it is whole.
//!
//! **What this file said before 8 Oct 2026, and why it moved.** It pinned
//! `FilterRange` for the first case too, under the sentence "the
//! reference fails the same member". Measured, the reference fails it
//! only through a checksum: with none it passes (a genuine `-m5 -s`
//! archive with one member's size set to 0 and its checksum flag cleared,
//! and the archive `fuzz:rar5_oracle_stream` framed at its 71st
//! execution, both `All OK`), and rarkit failed a member the reference
//! opens.
//!
//! **A span that STRADDLES the declared size** (it starts inside the
//! declared output and ends past it) is the same section's: completed, in
//! a member with no checksum, the member passes, the transform is run
//! over the WHOLE span and the output's part of it is delivered (rule 2);
//! under a checksum it is `FilterRange` (rule 3); and one the stream does
//! not complete is `FilterRange` whatever the member carries, because it
//! would leave the member short (rule 4's last sentence, and 3.6). The
//! last tests below hold the three.
//!
//! The stream is a solid chain of three members built by hand from
//! SPEC-H2 3.2 to 3.6: A, ten literals; B, the member under test; and C,
//! ten literals leaning on nothing of B's.
//!
//! The paths: the sequential reader with the chain's decode-ahead allowed
//! and refused, at the default width and at 1 and 2 workers, and
//! `extract_parallel` at 1 and 2. Memory: one 128 KiB dictionary and
//! archives of under 400 bytes each.

use std::sync::{Arc, Mutex};

use rarkit::{
    extract_parallel, Disposition, MemberInfo, MemberOutcome, ParallelSink, RangeSource,
    ReadOptions, Result, Sink,
};

/// Most significant bit first, like a block's payload (SPEC-H2 3.2).
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

/// A main symbol's code under the tables [`block`] sends: eight bits for
/// the first 206 symbols and nine for the other 100.
fn main_code(symbol: u32) -> (u32, u32) {
    if symbol < 206 {
        (symbol, 8)
    } else {
        (412 + symbol - 206, 9)
    }
}

fn literals(bits: &mut Bits, text: &[u8]) {
    for &byte in text {
        let (code, width) = main_code(u32::from(byte));
        bits.put(code, width);
    }
}

/// A delta record of one channel: symbol 256, the offset and the length
/// in the counted form of 3.6 (each under 256 here), type 0.
fn delta_record(bits: &mut Bits, offset: u32, length: u32) {
    delta_record_of(bits, offset, length, 1);
}

/// The same record with `channels` channels, 1 to 32.
fn delta_record_of(bits: &mut Bits, offset: u32, length: u32, channels: u32) {
    let (code, width) = main_code(256);
    bits.put(code, width);
    for value in [offset, length] {
        bits.put(0, 2);
        bits.put(value, 8);
    }
    bits.put(0, 3);
    bits.put(channels - 1, 5);
}

/// One block that is its member's last and carries complete tables: every
/// code length code at four bits, then the main alphabet at eight and
/// nine, distances at six, align at four, lengths at five and six.
fn block(fill: impl FnOnce(&mut Bits)) -> Vec<u8> {
    let mut payload = Bits::default();
    for _ in 0..20 {
        payload.put(5, 4);
    }
    let mut lengths = vec![8u32; 206];
    lengths.extend(std::iter::repeat_n(9, 100));
    lengths.extend(std::iter::repeat_n(6, 64));
    lengths.extend(std::iter::repeat_n(4, 16));
    lengths.extend(std::iter::repeat_n(5, 20));
    lengths.extend(std::iter::repeat_n(6, 24));
    for length in lengths {
        payload.put(length, 5);
    }
    fill(&mut payload);
    let final_bits = payload.count - (payload.bytes.len() - 1) * 8;
    let size = u16::try_from(payload.bytes.len()).expect("two size bytes hold it");
    let [low, high] = size.to_le_bytes();
    // The bits of the last byte, a size field of two bytes, tables, last.
    let flags = (((final_bits - 1) as u8) & 7) | 1 << 3 | 0x80 | 0x40;
    let mut out = vec![flags, 0x5a ^ flags ^ low ^ high, low, high];
    out.extend_from_slice(&payload.bytes);
    out
}

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
    let mut out = rarkit::checksum::crc32(&sized).to_le_bytes().to_vec();
    out.extend_from_slice(&sized);
    out
}

/// A solid archive of `members`, each its packed bytes, its declared size
/// and the CRC32 field its header carries, if it carries one.
fn archive(members: &[(Vec<u8>, u64, Option<u32>)]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    let mut main = Vec::new();
    vint(&mut main, 1);
    vint(&mut main, 0);
    vint(&mut main, 0x04);
    out.extend(header(&main));
    for (index, (packed, unpacked, crc)) in members.iter().enumerate() {
        let mut body = Vec::new();
        vint(&mut body, 2); // a file header
        vint(&mut body, 2); // a data area follows
        vint(&mut body, packed.len() as u64);
        // File flags: 0x04 says a CRC32 of the data follows the attributes.
        vint(&mut body, if crc.is_some() { 4 } else { 0 });
        vint(&mut body, *unpacked);
        vint(&mut body, 0); // attributes
        if let Some(crc) = crc {
            body.extend_from_slice(&crc.to_le_bytes());
        }
        // Algorithm 0, the solid bit on every member but the first,
        // method 3, a 128 KiB dictionary.
        vint(&mut body, (u64::from(index > 0) << 6) | (3 << 7));
        vint(&mut body, 0); // host
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

/// What B's block holds after its first literals.
#[derive(Clone, Copy, Debug)]
enum Middle {
    /// Ten literals and no record.
    Plain,
    /// Five literals, a delta record of 4 bytes at offset 0, five more:
    /// the span is `[5, 9)` and the stream COMPLETES it.
    Completed,
    /// Five literals, a delta record of 8 bytes at offset 0, two more:
    /// the span is `[5, 13)` and the stream ends at 7, inside it.
    Unfinished,
    /// Two literals, a delta record of 4 bytes at offset 0, eight more:
    /// the span is `[2, 6)`, completed.
    Early,
    /// Two literals, a delta record of TWO channels and 6 bytes at offset
    /// 0, eight more: the span is `[2, 8)`, completed, and every other
    /// byte of its output comes from the second half of its input, so a
    /// transform run over less than the whole span gives other bytes.
    Wide,
    /// Two literals, a delta record of two channels and 12 bytes at
    /// offset 0, eight more: the span is `[2, 14)` and the stream ends at
    /// 10, inside it.
    WideUnfinished,
}

/// The CRC32 of the first `declared` bytes B's literals spell: what a
/// member's field holds when it is computed from the declared output.
fn declared_crc(middle: Middle, declared: u64) -> u32 {
    let text: &[u8] = match middle {
        Middle::Unfinished => b"abcdefg",
        _ => b"abcdefghij",
    };
    rarkit::checksum::crc32(&text[..declared as usize])
}

/// The chain, its middle member declaring `declared` bytes and carrying
/// the CRC32 of its declared output when `checked`.
fn chain(middle: Middle, declared: u64, checked: bool) -> Vec<u8> {
    let crc = checked.then(|| declared_crc(middle, declared));
    archive(&[
        (block(|bits| literals(bits, b"first ten.")), 10, None),
        (
            block(|bits| match middle {
                Middle::Plain => literals(bits, b"abcdefghij"),
                Middle::Completed => {
                    literals(bits, b"abcde");
                    delta_record(bits, 0, 4);
                    literals(bits, b"fghij");
                }
                Middle::Unfinished => {
                    literals(bits, b"abcde");
                    delta_record(bits, 0, 8);
                    literals(bits, b"fg");
                }
                Middle::Early => {
                    literals(bits, b"ab");
                    delta_record(bits, 0, 4);
                    literals(bits, b"cdefghij");
                }
                Middle::Wide => {
                    literals(bits, b"ab");
                    delta_record_of(bits, 0, 6, 2);
                    literals(bits, b"cdefghij");
                }
                Middle::WideUnfinished => {
                    literals(bits, b"ab");
                    delta_record_of(bits, 0, 12, 2);
                    literals(bits, b"cdefghij");
                }
            }),
            declared,
            crc,
        ),
        (block(|bits| literals(bits, b"third ten.")), 10, None),
    ])
}

/// What each member closed with: its bytes and its verdict.
type Closed = Vec<(Vec<u8>, Option<bool>)>;

#[derive(Default)]
struct Keep {
    members: Mutex<Closed>,
}

impl Keep {
    fn closed(&self, out: Option<Vec<u8>>, outcome: &MemberOutcome) {
        self.members
            .lock()
            .expect("lock")
            .push((out.unwrap_or_default(), outcome.checksum_ok));
    }
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
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.closed(out, outcome);
        Ok(())
    }
}

impl ParallelSink for Keep {
    type Out = Vec<u8>;

    fn open(&self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.closed(out, outcome);
        Ok(())
    }
}

/// Every member's close, and the error kind the read ended with.
type Read = (Closed, Option<String>);

/// Every read path over one archive, labelled.
fn every_path(bytes: &[u8]) -> Vec<(String, Read)> {
    let source = || -> Vec<Arc<dyn RangeSource>> { vec![Arc::new(bytes.to_vec())] };
    let kind = |end: Result<rarkit::ExtractReport>| end.err().map(|e| format!("{:?}", e.kind()));
    let mut reads = Vec::new();
    for ahead in [true, false] {
        for workers in [None, Some(1), Some(2)] {
            let options = ReadOptions::default().with_workers(workers);
            let mut sink = Keep::default();
            rarkit::probe::set_ahead_off(!ahead);
            let end = rarkit::extract(source(), &options, &mut sink, &mut ());
            rarkit::probe::set_ahead_off(false);
            reads.push((
                format!("sequential, ahead {ahead}, workers {workers:?}"),
                (sink.members.into_inner().expect("lock"), kind(end)),
            ));
        }
    }
    for width in [1, 2] {
        let sink = Keep::default();
        let end = extract_parallel(source(), &ReadOptions::default(), &sink, width);
        reads.push((
            format!("parallel, {width} wide"),
            (sink.members.into_inner().expect("lock"), kind(end)),
        ));
    }
    reads
}

const REFUSED: &str = "Corrupt(Rar5(FilterRange))";

fn whole(text: &[u8]) -> (Vec<u8>, Option<bool>) {
    (text.to_vec(), None)
}

/// B passes on every path: its declared bytes and no more, the verdict
/// `want` (`None` with no checksum field, `Some(true)` with one), and the
/// members either side of it whole.
fn passes(middle: Middle, declared: u64, checked: bool) {
    let text = b"abcdefghij";
    let paths = every_path(&chain(middle, declared, checked));
    assert_eq!(paths.len(), 8);
    for (path, (closed, end)) in paths {
        let case = format!("{middle:?}, declares {declared}, checked {checked}, {path}");
        assert_eq!(end, None, "{case}");
        assert_eq!(closed[0], whole(b"first ten."), "{case}");
        assert_eq!(closed[1].0, &text[..declared as usize], "{case}");
        assert_eq!(closed[1].1, checked.then_some(true), "{case}");
        assert_eq!(closed[2], whole(b"third ten."), "{case}");
    }
}

/// B fails `FilterRange` on every path, closed failed with nothing past
/// its declared bytes, and the members either side of it are whole.
fn refused(middle: Middle, declared: u64, checked: bool) {
    for (path, (closed, end)) in every_path(&chain(middle, declared, checked)) {
        let case = format!("{middle:?}, declares {declared}, checked {checked}, {path}");
        assert_eq!(end.as_deref(), Some(REFUSED), "{case}");
        assert_eq!(closed[0], whole(b"first ten."), "{case}");
        assert_eq!(closed[1].1, Some(false), "{case}");
        assert!(closed[1].0.len() as u64 <= declared, "{case}");
        assert_eq!(closed[2], whole(b"third ten."), "{case}");
    }
}

#[test]
fn the_controls_with_no_record_pass() {
    for declared in [0, 3, 10] {
        for checked in [false, true] {
            passes(Middle::Plain, declared, checked);
        }
    }
}

/// Rule 2: the stream completes a span at or past the declared size and
/// the member carries no checksum. It passes, as the reference passes it,
/// and nothing past its declared size is delivered (rule 1).
#[test]
fn a_completed_span_past_the_declared_size_passes_with_no_checksum() {
    for declared in [0, 3, 5] {
        passes(Middle::Completed, declared, false);
    }
}

/// Rule 3: the same span in a member that carries a checksum is
/// `FilterRange`, the field being that of the declared output.
#[test]
fn a_completed_span_past_the_declared_size_is_refused_under_a_checksum() {
    for declared in [0, 3, 5] {
        refused(Middle::Completed, declared, true);
    }
}

/// Rule 4: a span starting at or past the declared size that the stream
/// never completes is dropped at the member's end, with a checksum or
/// without.
#[test]
fn an_unfinished_span_past_the_declared_size_is_dropped() {
    for declared in [0, 3, 5] {
        for checked in [false, true] {
            passes(Middle::Unfinished, declared, checked);
        }
    }
}

/// A span wholly inside the declared output is applied as it always was,
/// which the rule does not touch: only that the member passes is asked
/// here, its bytes being the transform's.
#[test]
fn a_span_inside_the_declared_output_is_still_applied() {
    for (path, (closed, end)) in every_path(&chain(Middle::Early, 10, false)) {
        assert_eq!(end, None, "{path}");
        assert_eq!(closed[1].0.len(), 10, "{path}");
        assert_eq!(&closed[1].0[..2], b"ab", "{path}");
        assert_ne!(closed[1].0, b"abcdefghij", "{path}");
        assert_eq!(closed[2], whole(b"third ten."), "{path}");
    }
}

/// B's whole output with its span applied: the chain read with B
/// declaring all ten of its bytes, which every path agrees on.
fn applied(middle: Middle) -> Vec<u8> {
    let mut whole: Option<Vec<u8>> = None;
    for (path, (closed, end)) in every_path(&chain(middle, 10, false)) {
        assert_eq!(end, None, "{middle:?}, {path}");
        assert_eq!(closed[1].0.len(), 10, "{middle:?}, {path}");
        let agreed = whole.get_or_insert_with(|| closed[1].0.clone());
        assert_eq!(&closed[1].0, agreed, "{middle:?}, {path}");
    }
    whole.expect("eight paths")
}

/// Rule 2's straddling half: a span that starts inside the declared
/// output and ends past it, completed, in a member with no checksum. The
/// member passes on every path and its bytes are the first `declared` of
/// its whole output, the transform having run over the WHOLE span: with
/// two channels the bytes delivered from the span are not what a
/// transform over the declared part alone would give.
#[test]
fn a_straddling_span_the_stream_completes_passes_with_no_checksum() {
    for middle in [Middle::Early, Middle::Wide] {
        let full = applied(middle);
        assert_eq!(&full[..2], b"ab", "{middle:?}");
        assert_ne!(full, b"abcdefghij", "{middle:?}");
        let last = if matches!(middle, Middle::Wide) { 7 } else { 5 };
        for declared in 3..=last {
            for (path, (closed, end)) in every_path(&chain(middle, declared, false)) {
                let case = format!("{middle:?}, declares {declared}, {path}");
                assert_eq!(end, None, "{case}");
                assert_eq!(closed[0], whole(b"first ten."), "{case}");
                assert_eq!(closed[1].0, &full[..declared as usize], "{case}");
                assert_eq!(closed[1].1, None, "{case}");
                assert_eq!(closed[2], whole(b"third ten."), "{case}");
            }
        }
    }
    // The two channel span's delivered part does lean on input past the
    // declared size: its second byte is the second channel's first.
    let full = applied(Middle::Wide);
    assert_ne!(full[3], b"abcdefghij"[3]);
}

/// Rule 3 for the same span: under a checksum it is `FilterRange`.
#[test]
fn a_straddling_span_is_refused_under_a_checksum() {
    for middle in [Middle::Early, Middle::Wide] {
        refused(middle, 3, true);
    }
}

/// A straddling span the stream does NOT complete leaves the member
/// short at a filter boundary, which is `FilterRange` with a checksum
/// and without one (rule 4's last sentence; "a member never ends short").
#[test]
fn a_straddling_span_the_stream_does_not_complete_is_refused() {
    for checked in [false, true] {
        refused(Middle::WideUnfinished, 5, checked);
    }
}

/// A member that ends short is judged by its checksum (spec F 4.2), and
/// that must not reach a member whose bytes a filter span held back: B
/// declares 13 bytes, its span is `[5, 13)`, its stream ends validly at 7
/// and its header carries the CRC32 of the five bytes before the span,
/// which are all a reader delivers. The reference passes such a member
/// (SPEC-H2 3.6); rarkit refuses it on every path, `FilterRange`, with a
/// checksum and without one, and the members either side are whole.
#[test]
fn a_span_the_stream_leaves_open_is_refused_whatever_the_checksum_says() {
    let packed = || {
        block(|bits| {
            literals(bits, b"abcde");
            delta_record(bits, 0, 8);
            literals(bits, b"fg");
        })
    };
    for crc in [Some(rarkit::checksum::crc32(b"abcde")), None] {
        let bytes = archive(&[
            (block(|bits| literals(bits, b"first ten.")), 10, None),
            (packed(), 13, crc),
            (block(|bits| literals(bits, b"third ten.")), 10, None),
        ]);
        let paths = every_path(&bytes);
        assert_eq!(paths.len(), 8);
        for (path, (closed, end)) in paths {
            let case = format!("checksum {crc:?}, {path}");
            assert_eq!(end.as_deref(), Some(REFUSED), "{case}");
            assert_eq!(closed[0], whole(b"first ten."), "{case}");
            assert_eq!(closed[1].1, Some(false), "{case}");
            assert_eq!(closed[1].0, b"abcde", "{case}");
            assert_eq!(closed[2], whole(b"third ten."), "{case}");
        }
    }
}
