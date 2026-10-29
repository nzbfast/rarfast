//! Spec H1 entry points for this repository's tests, benches and fuzz
//! targets, behind the `bench-internals` feature. Not part of the API; no
//! shipped build enables it.

use std::ops::Range;

use crate::memory::MemoryPolicy;
use crate::rar3_lz::bits::Bits;
use crate::rar3_lz::{MemberSpan, Rar3Lz, Rar3Stream, StreamOut};
use crate::Result;

pub use crate::error::Rar3Fault;

/// One member of a stream: where its packed data sits in the bytes handed
/// in, and the size its header declares.
#[derive(Debug, Clone)]
pub struct MemberIn {
    /// The member's packed span.
    pub packed: Range<usize>,
    /// The size the member's header declares.
    pub unpacked: u64,
}

/// What one member decoded to.
#[derive(Debug, Default, Clone)]
pub struct MemberOut {
    /// The member's bytes, or empty when the caller asked for none.
    pub data: Vec<u8>,
    /// How many bytes it produced.
    pub bytes: u64,
    /// CRC32 of those bytes.
    pub crc32: u32,
}

/// A sink that keeps the bytes, or only their length and CRC32.
struct Sink {
    keep: bool,
    out: MemberOut,
    hasher: crc32fast::Hasher,
}

impl StreamOut for Sink {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.out.bytes += bytes.len() as u64;
        self.hasher.update(bytes);
        if self.keep {
            self.out.data.extend_from_slice(bytes);
        }
        Ok(())
    }
}

/// A policy with room for any RAR 3 stream.
pub fn wide_policy() -> MemoryPolicy {
    MemoryPolicy {
        max_window: 1 << 22,
        max_dictionary: 1 << 22,
        max_workers: 1,
        ..MemoryPolicy::from_limit(1 << 30)
    }
}

/// A decoder kept across streams, as a driver keeps one: the window, the
/// tables, spec J's staging areas and spec I's arena are allocated once
/// and re-used, so nothing is allocated per member or per archive.
pub struct Runner {
    stream: Option<Rar3Stream>,
}

impl Default for Runner {
    fn default() -> Runner {
        Runner::new()
    }
}

impl Runner {
    /// A runner with no stream yet.
    pub fn new() -> Runner {
        Runner { stream: None }
    }

    /// The programs the last decoded stream's filter slots named, as
    /// stable strings so this seam does not export an internal enum.
    ///
    /// Empty when nothing has been decoded, and empty when the member
    /// framed no filter record; the two are told apart by `run`'s own
    /// record count, not here.
    #[cfg(feature = "bench-internals")]
    pub fn filter_census(&self) -> Vec<(&'static str, u32)> {
        use crate::rar3_filters::StandardProgram as P;
        let Some(stream) = self.stream.as_ref() else {
            return Vec::new();
        };
        stream
            .filter_census()
            .into_iter()
            .map(|(program, len)| {
                let name = match program {
                    P::X86Call => "x86-call",
                    P::X86CallJump => "x86-call-jump",
                    P::Itanium => "itanium",
                    P::Delta => "delta",
                    P::Rgb => "rgb",
                    P::Audio => "audio",
                };
                (name, len)
            })
            .collect()
    }

    /// Decode one stream, re-using what the last one held.
    pub fn run(
        &mut self,
        packed: &[u8],
        members: &[MemberIn],
        dictionary: u32,
        keep: bool,
    ) -> Result<(Vec<MemberOut>, u64)> {
        match &mut self.stream {
            Some(stream) => stream.begin_stream(dictionary),
            slot => *slot = Some(Rar3Stream::new(dictionary, &wide_policy())?),
        }
        let stream = self.stream.as_mut().expect("a stream");
        let (out, records, failed) = drive(stream, packed, members, keep);
        match failed {
            Some(error) => Err(error),
            None => Ok((out, records)),
        }
    }
}

/// Decode one stream: a solid chain, or one non solid member.
///
/// `packed` is the members' packed data, in order, as spec F concatenates
/// it; `members` says where each member's span is and how much it
/// declares. With `keep` false the bytes are counted and hashed but not
/// held, which is what the benches measure.
pub fn decode_stream(
    packed: &[u8],
    members: &[MemberIn],
    dictionary: u32,
    keep: bool,
) -> Result<(Vec<MemberOut>, u64)> {
    let (done, records, failed) = decode_stream_partial(packed, members, dictionary, keep);
    match failed {
        Some(error) => Err(error),
        None => Ok((done, records)),
    }
}

/// [`decode_stream`], and how many MAIN SYMBOLS the stream decoded.
///
/// SPEC-H1 7.5 asks for the per symbol cost split from the per output
/// byte cost before any target is claimed, and the two cannot be told
/// apart from outside: a literal run and a long match produce the same
/// bytes for wildly different symbol counts. the gate bench reads
/// this to print symbols per member and nanoseconds per symbol beside
/// every RAR 3 leg's nanoseconds per byte. The third value is how many
/// of those symbols were LITERALS, which is what lets the two costs be
/// solved for rather than bounded.
pub fn decode_stream_symbols(
    packed: &[u8],
    members: &[MemberIn],
    dictionary: u32,
    keep: bool,
) -> Result<(Vec<MemberOut>, u64, u64)> {
    let mut stream = Rar3Stream::new(dictionary, &wide_policy())?;
    let (done, _, failed) = drive(&mut stream, packed, members, keep);
    match failed {
        Some(error) => Err(error),
        None => Ok((done, stream.symbols(), stream.literals())),
    }
}

/// [`decode_stream`], keeping what decoded before a member failed, so a
/// test can say which member of a chain broke.
pub fn decode_stream_partial(
    packed: &[u8],
    members: &[MemberIn],
    dictionary: u32,
    keep: bool,
) -> (Vec<MemberOut>, u64, Option<crate::Error>) {
    let mut stream = match Rar3Stream::new(dictionary, &wide_policy()) {
        Ok(stream) => stream,
        Err(error) => return (Vec::new(), 0, Some(error)),
    };
    drive(&mut stream, packed, members, keep)
}

fn drive(
    stream: &mut Rar3Stream,
    packed: &[u8],
    members: &[MemberIn],
    keep: bool,
) -> (Vec<MemberOut>, u64, Option<crate::Error>) {
    let mut input = Bits::new(packed);
    let mut out = Vec::with_capacity(members.len());
    for member in members {
        let mut sink = Sink {
            keep,
            out: MemberOut::default(),
            hasher: crc32fast::Hasher::new(),
        };
        let outcome = stream.member(
            &mut input,
            &MemberSpan {
                packed: member.packed.clone(),
                unpacked: member.unpacked,
            },
            &mut sink,
        );
        let mut done = sink.out;
        done.crc32 = sink.hasher.finalize();
        out.push(done);
        if let Err(error) = outcome {
            return (out, stream.records(), Some(error));
        }
    }
    (out, stream.records(), None)
}

/// Working memory one whole stream holds: this package's window and
/// tables, spec J's two staging areas and spec I's arena.
pub fn held_bytes(dictionary: u32) -> Result<u64> {
    Ok(Rar3Stream::new(dictionary, &wide_policy())?.held_bytes())
}

/// What THIS package holds: the window, the five tables and the stored
/// code lengths (SPEC-H1 4.2 and 5.6).
pub fn codec_bytes(dictionary: u32) -> Result<u64> {
    Ok(Rar3Stream::new(dictionary, &wide_policy())?.codec_bytes())
}

/// The fuzz target of SPEC-H1 6.3: one non solid member of a fixed
/// declared size in a fixed 64 KiB dictionary.
pub fn fuzz_member(data: &[u8]) {
    let members = [MemberIn {
        packed: 0..data.len(),
        unpacked: 1 << 16,
    }];
    let _ = decode_stream(data, &members, 1 << 16, false);
}

/// The fuzz target of SPEC-H1 6.3: block headers and their code length
/// tables only, which reaches the table machinery without paying for
/// symbol decode.
pub fn fuzz_tables(data: &[u8]) {
    let mut lz = Rar3Lz::new();
    let mut input = Bits::new(data);
    // Header after header until one of them fails, so a body that holds
    // several tables is worth as much to the fuzzer as its first.
    for _ in 0..8 {
        match lz.begin_block(&mut input) {
            Ok(Some(_)) | Err(_) => break,
            Ok(None) => {}
        }
    }
}

/// The fuzz target of SPEC-H1 6.3: four members of one solid chain, cut by
/// a length prefix, which reaches the carry over rules of 3.7 and 3.8.
pub fn fuzz_solid_chain(data: &[u8]) {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let cut = usize::from(first).min(rest.len());
    let mut members = Vec::with_capacity(4);
    let mut at = 0usize;
    for index in 0..4 {
        let end = if index == 3 {
            rest.len()
        } else {
            (at + cut).min(rest.len())
        };
        members.push(MemberIn {
            packed: at..end,
            unpacked: 1 << 14,
        });
        at = end;
    }
    let _ = decode_stream(rest, &members, 1 << 16, false);
}

/// The smallest dictionary SPEC-H1 3.6 declares, `65,536 << 0`, which is
/// what the window edge target uses so a member laps it for a fifth of a
/// megabyte rather than for tens.
pub const EDGE_WINDOW: usize = 1 << 16;

/// How far the window edge target's member runs: three laps of
/// [`EDGE_WINDOW`], GUARANTEED, whatever length of seed libFuzzer hands
/// it.
///
/// This is the number the first version of the target got wrong, and the
/// way it got it wrong is the one this whole target is about. It built a
/// base of one lap and then appended one match pair per three seed
/// bytes, so the laps were a function of the SEED LENGTH: a ten minute
/// run never grew its inputs past 25 bytes, because an exec that encodes
/// and decodes a fifth of a megabyte costs about 24 ms, and 25 bytes buys
/// about 660 bytes of pairs. The member lapped 1.06 times and only those
/// 660 bytes sat where `Window::copy`'s `SpillWatch` can bite at all.
/// That is the short-lap finding arriving in a target WRITTEN FOR it,
/// which is worth recording rather than quietly correcting.
///
/// So the pairs now CYCLE over the seed until the member is three laps
/// long. Coverage still comes from the seed - it chooses every lead
/// length, every gap and every distance - but the lap count does not.
const EDGE_TARGET: usize = 3 * EDGE_WINDOW;

/// Append `length` bytes from `distance` back, the byte at a time way, so
/// the input holds a repeat the encoder can only express at that
/// distance.
fn edge_repeat(out: &mut Vec<u8>, distance: usize, length: usize) {
    for _ in 0..length {
        let byte = out[out.len() - distance];
        out.push(byte);
    }
}

/// The window edge target's input: a base that laps the dictionary, then
/// LEAD then EDGE match pairs to the full three laps.
///
/// A short lead match is the copy that could round its length up; the gap
/// of literals moves the write point on; the edge match, at a distance
/// within 64 of the dictionary itself, is what READS the slots the lead
/// may have scribbled. SPEC-H1 3.6 admits a distance up to `ring.len()`,
/// so an `edge` of zero is legal and names the slot the write point is
/// about to overwrite.
pub fn window_edge_input(data: &[u8]) -> Vec<u8> {
    let mut noise =
        crate::bench_bytes::ByteRun::new(u32::from_le_bytes([data[1], data[2], data[3], data[4]]));
    let mut input: Vec<u8> = (0..EDGE_WINDOW + 4096).map(|_| noise.byte()).collect();
    let steps = &data[5..];
    if steps.len() < 3 {
        // No pairs to be had from this seed. The base still laps, so the
        // member is a plain one; the length is held to three laps so
        // every seed costs the fuzzer the same.
        while input.len() < EDGE_TARGET {
            input.push(noise.byte());
        }
        return input;
    }
    let mut at = 0usize;
    while input.len() < EDGE_TARGET {
        let step = &steps[at..at + 3];
        at += 3;
        if at + 3 > steps.len() {
            at = 0;
        }
        let lead = usize::from(step[0] % 64) + 1;
        let gap = usize::from(step[1] % 24);
        let edge = usize::from(step[2] % 65);
        edge_repeat(&mut input, 1024, lead);
        for _ in 0..gap {
            input.push(noise.byte());
        }
        edge_repeat(&mut input, EDGE_WINDOW - edge, 70);
    }
    input
}

/// The window edge fuzz body for the RAR 3 window (window 1 of
/// `WINDOW-INVARIANTS.md`).
///
/// The three targets of SPEC-H1 6.3 cannot see the window edge class:
/// `fuzz_member` declares `1 << 16` bytes into a `1 << 16` dictionary, so
/// it reaches the end of its FIRST lap and no further, and below one lap
/// every slot ahead of the write point holds a byte the stream never
/// produced. This one laps three times and carries lead then edge pairs
/// throughout, and the round trip through this crate's own RAR 2.9
/// encoder is checked byte for byte.
pub fn fuzz_window_edge(data: &[u8]) {
    if data.len() < 8 {
        return;
    }
    // Spec G's levels 4 and 5 run the optimal parse, far too slow to fuzz
    // a fifth of a megabyte with; the distances this target is about are
    // the match finder's, and levels 0 to 3 reach them.
    let level = data[0] % 4;
    let input = window_edge_input(data);
    let packed = crate::encode::rar29::Rar29Encoder::new(
        crate::encode::rar29::EncodeOptions::for_level(level, EDGE_WINDOW as u32),
    )
    .encode(&input);
    let members = [MemberIn {
        packed: 0..packed.len(),
        unpacked: input.len() as u64,
    }];
    let (out, _) = decode_stream(&packed, &members, EDGE_WINDOW as u32, true)
        .expect("spec H1's decoder reads what this crate's RAR 2.9 encoder wrote");
    assert!(
        out[0].data == input,
        "level {level}: the round trip changed the bytes at {:?}",
        out[0].data.iter().zip(&input).position(|(a, b)| a != b)
    );
}

/// What one literal burst stream holds, for the test that proves this
/// target is not vacuous.
///
/// The three figures are the ones a seed can silently lose: the number of
/// TABLE READS (a stream with one reaches no boundary), the literals
/// decoded, and the members the stream is cut into.
pub fn literal_burst_shape(data: &[u8]) -> Option<(u32, u64, usize)> {
    let burst = crate::rar3_lz::burst::literal_burst(data)?;
    Some((burst.blocks, burst.literals, burst.members.len()))
}

/// A fourth fuzz target for SPEC-H1 6.3: long literal runs at the TABLE
/// BOUNDARIES, left open on 19 Sep 2026.
///
/// `crate::rar3_lz::burst` says why the three targets the specification
/// names cannot reach this shape. The assertion here is a byte
/// comparison and not "no panic": the builder knows every literal it
/// wrote, so a decoder that carries the stored code lengths wrongly
/// across a keep bit, or that loses a byte where a block ends, fails
/// here with the member and the offset rather than passing quietly.
pub fn fuzz_literal_burst(data: &[u8]) {
    let Some(burst) = crate::rar3_lz::burst::literal_burst(data) else {
        return;
    };
    let members: Vec<MemberIn> = burst
        .members
        .iter()
        .map(|(packed, unpacked)| MemberIn {
            packed: packed.clone(),
            unpacked: *unpacked,
        })
        .collect();
    let (out, _) = decode_stream(
        &burst.packed,
        &members,
        crate::rar3_lz::burst::BURST_WINDOW,
        true,
    )
    .expect("spec H1's decoder reads the literal bursts this crate wrote");
    assert_eq!(
        out.len(),
        burst.expected.len(),
        "the decoder answered {} members for {} spans",
        out.len(),
        burst.expected.len()
    );
    for (at, (got, want)) in out.iter().zip(&burst.expected).enumerate() {
        assert!(
            &got.data == want,
            "member {at} of {} blocks differs at {:?}",
            burst.blocks,
            got.data.iter().zip(want).position(|(a, b)| a != b)
        );
    }
}

/// The literal loop of SPEC-H1 7.3 item 5 with one STAGE removed at a
/// time, for the subtractive ladder bench.
///
/// Why a subtraction rather than a profile: two earlier attempts
/// reasoned from a sampled profile's self time
/// over this loop and both regressed. A stage whose removal moves the
/// wall is on the critical path; a stage whose removal moves nothing is
/// overlapped, and no lever aimed at it can pay.
pub struct LiteralLadder(crate::rar3_lz::ladder::Ladder);

/// Build `symbols` literals of one shape, with the table that decodes
/// them.
///
/// `incomp` (widths 7 to 9) and `code` (5 to 9) are the two alphabets
/// the pair-loop-gate work MEASURED off the real corpora, and they are
/// the ones a form should be judged on. `random` (flat eight),
/// `nearflat` (eight and nine) and `text` (four to twelve) are
/// CONSTRUCTIONS, kept because the subtractive ladder's standing rows
/// are on them. `None` names none of the five.
pub fn literal_ladder(shape: &str, symbols: usize) -> Option<LiteralLadder> {
    use crate::rar3_lz::ladder::{Ladder, Shape};
    let shape = match shape {
        "random" => Shape::Random,
        "text" => Shape::Text,
        "nearflat" => Shape::NearFlat,
        "incomp" => Shape::Incomp,
        "code" => Shape::Code,
        _ => return None,
    };
    Some(LiteralLadder(Ladder::build(shape, symbols)))
}

/// Every stage name, in ladder order.
pub fn ladder_stages() -> Vec<&'static str> {
    crate::rar3_lz::ladder::Stage::ALL
        .iter()
        .map(|stage| stage.name())
        .collect()
}

impl LiteralLadder {
    /// Symbols every stage walks.
    pub fn symbols(&self) -> usize {
        self.0.symbols()
    }

    /// Run one stage over the whole stream. The answer is the symbols it
    /// walked and a value derived from everything it did, which the
    /// caller must keep so that no part of the loop is dead code.
    /// `None` names no stage.
    pub fn run(&self, stage: &str) -> Option<(usize, u64)> {
        let stage = crate::rar3_lz::ladder::Stage::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.name() == stage)?;
        Some(self.0.run(stage))
    }

    /// The last `want` bytes the full loop produces, and the last `want`
    /// bytes it MUST produce. Equal is the correctness check every
    /// figure in the ladder is worth nothing without.
    pub fn full_against_expected(&self, want: usize) -> (Vec<u8>, Vec<u8>) {
        self.stage_against_expected("full", want)
            .unwrap_or_default()
    }

    /// The same for any stage that DECODES, which is every stage that is
    /// a candidate LOOP rather than a subtraction. `None` names no such
    /// stage: the subtractive stages do not decode and must not, so the
    /// comparison is refused for them rather than failed.
    pub fn stage_against_expected(&self, stage: &str, want: usize) -> Option<(Vec<u8>, Vec<u8>)> {
        let stage = crate::rar3_lz::ladder::Stage::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.name() == stage)?;
        if !stage.decodes() {
            return None;
        }
        let expected = self.0.expected();
        let from = expected.len().saturating_sub(want);
        #[allow(clippy::indexing_slicing)] // `from <= len`
        Some((self.0.decode_tail(stage, want), expected[from..].to_vec()))
    }

    /// Every stage that DECODES, which is what
    /// [`LiteralLadder::stage_against_expected`] answers for.
    pub fn decoding_stages(&self) -> Vec<&'static str> {
        crate::rar3_lz::ladder::Stage::ALL
            .iter()
            .filter(|stage| stage.decodes())
            .map(|stage| stage.name())
            .collect()
    }

    /// The share of each pair table's entries that answer a pair: the
    /// fourteen bit one this package may hold, and the sixteen bit one
    /// it may not. A property of the ALPHABET, not of the box.
    pub fn pair_cover(&self) -> (f64, f64) {
        self.0.pair_cover()
    }

    /// The width the speculative stages guess, the share of this
    /// stream's literals that have it, and the share that have it or the
    /// width above it: the hit rates of the two speculative stages.
    pub fn mode_cover(&self) -> (u8, f64, f64) {
        self.0.mode_cover()
    }

    /// The width that WOULD have been the best guess on this stream, and
    /// its share: the headroom in the STATISTIC rather than in the form.
    pub fn best_mode(&self) -> (u8, f64) {
        self.0.best_mode()
    }
}
