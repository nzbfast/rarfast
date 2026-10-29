//! Tests of package J from `specs/vectors-J` (SPEC-J section 5) and the
//! properties of section 6.2.

use super::record::Parsed;
use super::*;
use crate::carry::h_ours::codec::address_filters::{self, Direction};
use crate::error::{ErrorKind, Unsupported};
use crate::memory::MemoryPolicy;

const HAND: &str = include_str!("../../vectors-J/hand.tsv");
const PROGRAMS: &str = include_str!("../../vectors-J/programs.tsv");
const DERIVED: &str = include_str!("../../vectors-J/records-derived.tsv");
const GENUINE: &str = include_str!("../../vectors-J/genuine-records.tsv");
#[cfg(all(feature = "repo-tests", feature = "oracle-compare"))]
const INPUTS: &str = include_str!("../../vectors-J/inputs.sha256");
#[cfg(all(feature = "repo-tests", feature = "oracle-compare"))]
const ARCHIVES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/vectors-J/archives"
);

fn policy() -> MemoryPolicy {
    MemoryPolicy {
        max_window: 1 << 22,
        max_dictionary: 1 << 22,
        max_workers: 1,
        ..MemoryPolicy::from_limit(1 << 30)
    }
}

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

/// Record bytes from a slice; running out is `Truncated`, as a decoder's
/// source reports the end of the member's packed data.
struct Bytes<'a>(&'a [u8]);
impl RecordBytes for Bytes<'_> {
    fn next_byte(&mut self) -> crate::Result<u8> {
        let (&b, rest) = self
            .0
            .split_first()
            .ok_or_else(|| crate::Error::new(ErrorKind::Truncated))?;
        self.0 = rest;
        Ok(b)
    }
}

const WIDE: MemberBounds = MemberBounds {
    start: 0,
    end: u64::MAX / 4,
};

/// The error's kind as text (`ErrorKind` holds an `io::Error`, so it has
/// no `PartialEq`).
fn kind(r: crate::Result<impl std::fmt::Debug>) -> String {
    format!("{:?}", r.expect_err("expected an error").kind())
}

fn text(k: ErrorKind) -> String {
    format!("{k:?}")
}

const RECORD: &str = "Corrupt(FilterRecord)";
const PARAMS: &str = "Corrupt(FilterParameters)";

// ---------------------------------------------------------------------------
// Transforms: hand.tsv and properties
// ---------------------------------------------------------------------------

type Tx = fn(&[u8], &mut [u8], u32, u32);
fn tx(name: &str, decode: bool) -> Tx {
    match (name, decode) {
        ("delta", true) => |s, o, a, _| delta_decode(s, o, a),
        ("delta", false) => |s, o, a, _| delta_encode(s, o, a),
        ("rgb", true) => |s, o, a, b| rgb_decode(s, o, a, b),
        ("rgb", false) => |s, o, a, b| rgb_encode(s, o, a, b),
        ("audio", true) => |s, o, a, _| audio_decode(s, o, a),
        ("audio", false) => |s, o, a, _| audio_encode(s, o, a),
        _ => unreachable!(),
    }
}

fn run(name: &str, decode: bool, input: &[u8], a: u32, b: u32) -> Vec<u8> {
    let mut out = vec![0u8; input.len()];
    tx(name, decode)(input, &mut out, a, b);
    out
}

#[test]
fn hand_vectors() {
    let mut rows = 0;
    for line in HAND.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split('\t').collect();
        let (id, name) = (f[0], f[1]);
        let params: Vec<u32> = f[2]
            .trim_matches(|c| c == '(' || c == ')')
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().parse().unwrap())
            .collect();
        let field = |key: &str| hex(f.iter().find_map(|x| x.strip_prefix(key)).unwrap());
        let (input, dec, enc) = (field("in="), field("dec="), field("enc="));
        // hand.tsv states RGB's first parameter as the row width `W`.
        let (a, b) = (params[0], params.get(1).copied().unwrap_or(0));
        assert_eq!(run(name, true, &input, a, b), dec, "{id} decode");
        assert_eq!(run(name, false, &input, a, b), enc, "{id} encode");
        rows += 1;
    }
    assert_eq!(rows, 11);
}

fn assert_inverse(name: &str, x: &[u8], a: u32, b: u32) {
    let e = run(name, false, x, a, b);
    assert_eq!(
        run(name, true, &e, a, b),
        x,
        "{name} dec(enc) n={} a={a} b={b}",
        x.len()
    );
    let d = run(name, true, x, a, b);
    assert_eq!(
        run(name, false, &d, a, b),
        x,
        "{name} enc(dec) n={} a={a} b={b}",
        x.len()
    );
}

/// The whole-pixel row width takes `rgb_encode`'s contiguous path and
/// every other width takes the generic one. They are the same transform,
/// so running the generic shape at a whole-pixel width must agree byte
/// for byte with the path that width actually selects.
#[test]
fn rgb_encode_contiguous_path_matches_the_generic_one() {
    let mut rng = rarkit_testdata::Seeded::new(0x5eed_0003);
    for n in 0..=200usize {
        let x = rng.bytes(n);
        for w in (3..=99u32).step_by(3) {
            for r in 0..=5u32 {
                let mut fast = vec![0u8; n];
                super::transforms::rgb_encode(&x, &mut fast, w, r);
                let mut slow = vec![0u8; n];
                super::transforms::rgb_encode_generic_for_tests(&x, &mut slow, w, r);
                assert_eq!(fast, slow, "n={n} w={w} r={r}");
            }
        }
    }
}

#[test]
fn inverse_every_small_block() {
    let mut rng = rarkit_testdata::Seeded::new(0x5eed_0001);
    for n in 0..=130 {
        let x = rng.bytes(n);
        for ch in 1..=40 {
            assert_inverse("delta", &x, ch, 0);
            assert_inverse("audio", &x, ch, 0);
        }
        for w in (3..=135).step_by(3) {
            for r in 0..=5 {
                assert_inverse("rgb", &x, w, r);
            }
        }
    }
}

#[test]
fn inverse_random_blocks() {
    let mut rng = rarkit_testdata::Seeded::new(0x5eed_0002);
    for case in 0..20_000 {
        let n = rng.below(4097) as usize;
        let mut x = rng.bytes(n);
        if case % 2 == 0 {
            // Smooth data, where the predictors actually predict.
            let mut v = 0u8;
            for b in &mut x {
                v = v.wrapping_add((rng.below(5) as u8).wrapping_sub(2));
                *b = v;
            }
        }
        match case % 3 {
            0 => {
                let ch = match rng.below(8) {
                    0 => u32::MAX - rng.below(3) as u32,
                    _ => 1 + rng.below(40) as u32,
                };
                assert_inverse("delta", &x, ch, 0);
            }
            1 => assert_inverse("audio", &x, 1 + rng.below(40) as u32, 0),
            _ => {
                let w = match rng.below(8) {
                    0 => 3 * (n as u32 / 3 + 1 + rng.below(100) as u32),
                    _ => 3 * (1 + rng.below(300) as u32),
                };
                assert_inverse("rgb", &x, w, rng.below(6) as u32);
            }
        }
    }
    for n in [65_535, 65_536, 65_537, 245_760] {
        let x = rng.bytes(n);
        assert_inverse("delta", &x, 3, 0);
        assert_inverse("audio", &x, 4, 0);
        assert_inverse("rgb", &x, 771, 2);
    }
}

#[test]
fn transforms_out_of_domain_terminate() {
    let mut rng = rarkit_testdata::Seeded::new(9);
    let x = rng.bytes(300);
    for a in [0, 1, 2, 4, 5, 7, 299, 300, 301, u32::MAX] {
        for b in [0, 1, 299, 300, u32::MAX] {
            for name in ["delta", "rgb", "audio"] {
                run(name, true, &x, a, b);
                run(name, false, &x, a, b);
            }
        }
    }
    // Mismatched lengths touch only the common prefix.
    let mut out = [7u8; 4];
    delta_decode(&x[..2], &mut out, 3);
    assert_eq!(out[2..], [7, 7]);
    rgb_decode(&x[..2], &mut out, 3, 0);
    audio_decode(&x[..2], &mut out, 3);
    assert_eq!(out[2..], [7, 7]);
}

// ---------------------------------------------------------------------------
// Programs and the fingerprint table
// ---------------------------------------------------------------------------

/// Section 3.4's table, both ways round, against the specification's own
/// record of what genuine archives carry. The crate holds no program
/// bytes: what it holds is each program's LENGTH and CRC32,
/// and this test reads `programs.tsv`'s hex to prove those two numbers
/// really are the length and the CRC32 of the bytes observed.
#[test]
fn fingerprint_table_matches_programs_tsv() {
    let all = [
        StandardProgram::X86Call,
        StandardProgram::X86CallJump,
        StandardProgram::Itanium,
        StandardProgram::Delta,
        StandardProgram::Rgb,
        StandardProgram::Audio,
    ];
    for p in all {
        let (len, crc) = p.fingerprint();
        assert_eq!(identify(len, crc), Some(p));
        // A stand-in of the same fingerprint identifies as the same
        // program: the table looks at nothing else (section 3.4).
        let bytes = stand_in_program(p);
        assert_eq!(bytes.len() as u32, len);
        assert_eq!(
            identify(bytes.len() as u32, crc32fast::hash(&bytes)),
            Some(p)
        );
    }
    let mut rows = 0;
    for line in PROGRAMS.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        let bytes = hex(&f[2]
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(" "));
        let (len, crc) = (
            f[0].parse::<u32>().unwrap(),
            u32::from_str_radix(f[1], 16).unwrap(),
        );
        assert_eq!(bytes.len() as u32, len, "{line}");
        assert_eq!(crc32fast::hash(&bytes), crc, "{line}");
        let p = identify(len, crc).expect("every row of programs.tsv is standard");
        assert_eq!(p.fingerprint(), (len, crc));
        rows += 1;
    }
    assert_eq!(rows, 6);
    assert_eq!(identify(29, 0x1a06_eecf), None);
    assert_eq!(identify(53, 0x0e06_077d), None);
}

/// Section 3.7.3 as it is stated, steps 1 to 6 in their order, for one
/// channel: the three lagged differences, the three weights and the seven
/// sums each one indexed thing, steps 5 and 6 once over an index `i` of 1
/// to 3 (rule A1). The shipped transform folds the weights onto plain
/// differences and forms the sums at a revision; this does neither, so
/// the two agree only if both are the section's arithmetic.
#[derive(Clone, Default)]
struct AudioAsStated {
    t: usize,
    last_byte: i32,
    last_difference: i32,
    lagged: [i32; 3],
    weights: [i32; 3],
    sums: [i32; 7],
}

impl AudioAsStated {
    /// Steps 1 to 5 for the filtered byte `e`: the original byte.
    fn through_step_5(&mut self, e: u8) -> u8 {
        // Step 1, right-hand sides as they were before it.
        self.lagged = [
            self.last_difference,
            self.last_difference - self.lagged[0],
            self.lagged[1],
        ];
        // Step 2, the floor of the exact quotient.
        let numerator = 8 * self.last_byte
            + (0..3)
                .map(|i| self.weights[i] * self.lagged[i])
                .sum::<i32>();
        let q = numerator.div_euclid(8);
        // Step 3.
        let x = (q - i32::from(e)).rem_euclid(256);
        // Step 4.
        self.last_difference = i32::from((x - self.last_byte) as u8 as i8);
        self.last_byte = x;
        // Step 5.
        let v = 8 * i32::from(e as i8);
        self.sums[0] += v.abs();
        for i in 1..=3 {
            self.sums[2 * i - 1] += (v - self.lagged[i - 1]).abs();
            self.sums[2 * i] += (v + self.lagged[i - 1]).abs();
        }
        x as u8
    }

    /// Step 6, and on to the next byte.
    fn step_6(&mut self) {
        if self.t.is_multiple_of(32) {
            let mut j = 0;
            for candidate in 1..7 {
                if self.sums[candidate] < self.sums[j] {
                    j = candidate;
                }
            }
            self.sums = [0; 7];
            if j != 0 {
                let i = j.div_ceil(2);
                if j % 2 == 1 && self.weights[i - 1] >= -16 {
                    self.weights[i - 1] -= 1;
                } else if j.is_multiple_of(2) && self.weights[i - 1] < 16 {
                    self.weights[i - 1] += 1;
                }
            }
        }
        self.t += 1;
    }

    fn channel(filtered: &[u8]) -> Vec<u8> {
        let mut state = AudioAsStated::default();
        filtered
            .iter()
            .map(|&e| {
                let x = state.through_step_5(e);
                state.step_6();
                x
            })
            .collect()
    }
}

/// Section 3.7.3 and its rule A1: the shipped audio transform gives the
/// bytes of the recurrence as stated, channel by channel, for the channel
/// counts and lengths of the section's evidence, on random filtered bytes
/// and on bytes of small magnitude (where ties among the sums happen);
/// and encode gives the filtered bytes back.
#[test]
fn audio_is_the_recurrence_as_section_3_7_3_states_it() {
    let mut source = rarkit_testdata::Seeded::new(0x6175_6469);
    let mut next = move || source.next_u32();
    let mut cases = 0;
    for channels in [1usize, 2, 3, 4, 5, 7, 31, 32, 33, 128] {
        for n in [0usize, 1, 2, 31, 32, 33, 64, 65, 129, 700, 2_000, 9_001] {
            for small in [false, true] {
                let filtered: Vec<u8> = (0..n)
                    .map(|_| {
                        let r = next();
                        if small {
                            // -2 to 2, as bytes.
                            ((r >> 9) % 5) as u8 ^ if r & 1 == 0 { 0 } else { 0xff }
                        } else {
                            (r >> 11) as u8
                        }
                    })
                    .collect();
                // The filtered block is one channel after another.
                let mut want = vec![0u8; n];
                let mut at = 0;
                for c in 0..channels.min(n) {
                    let len = (n - c).div_ceil(channels);
                    let plane = AudioAsStated::channel(&filtered[at..at + len]);
                    for (t, &byte) in plane.iter().enumerate() {
                        want[c + t * channels] = byte;
                    }
                    at += len;
                }
                assert_eq!(at, n);
                let mut got = vec![0u8; n];
                audio_decode(&filtered, &mut got, channels as u32);
                assert_eq!(got, want, "decode N={channels} n={n} small={small}");
                let mut back = vec![0u8; n];
                audio_encode(&want, &mut back, channels as u32);
                assert_eq!(back, filtered, "encode N={channels} n={n} small={small}");
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 240);
}

/// Section 3.7.3: a channel whose filtered bytes keep one sum the
/// smallest walks that sum's weight to its bound and holds it there, -17
/// for an odd sum and 16 for an even one. One channel for each of the six
/// sums that move a weight, each filtered byte chosen, of all 256, to
/// leave its sum furthest below the other six; the stated recurrence is
/// asked to have reached the bound, and the shipped transform to give its
/// bytes.
#[test]
fn audio_weights_walked_to_their_bounds_give_the_stated_bytes() {
    for target in 1..=6usize {
        let mut state = AudioAsStated::default();
        let mut filtered = Vec::new();
        let mut want = Vec::new();
        for _ in 0..1_500 {
            let lead = |e: u8| {
                let mut tried = state.clone();
                tried.through_step_5(e);
                let others = (0..7).filter(|&j| j != target).map(|j| tried.sums[j]);
                tried.sums[target] - others.min().unwrap()
            };
            // On a tie a byte other than zero, so the channel leaves rest.
            let e = (0..=255u8).min_by_key(|&e| (lead(e), e == 0)).unwrap();
            want.push(state.through_step_5(e));
            state.step_6();
            filtered.push(e);
        }
        let bound = if target % 2 == 1 { -17 } else { 16 };
        assert_eq!(state.weights[(target - 1) / 2], bound, "sum {target}");
        assert_eq!(want, AudioAsStated::channel(&filtered));
        let mut got = vec![0u8; filtered.len()];
        audio_decode(&filtered, &mut got, 1);
        assert_eq!(got, want, "sum {target}");
        let mut back = vec![0u8; filtered.len()];
        audio_encode(&want, &mut back, 1);
        assert_eq!(back, filtered, "sum {target}");
    }
}

/// Section 3.4, rule T1: the six rows stand in ascending order of `k`,
/// 29, 53, 57, 120, 149, 216. Ascending and strict, so no two rows share
/// a `k` and no definition can match two; and the answer `identify` gives
/// is by the pair alone, since a row's `k` with another row's CRC32, or
/// its CRC32 with another row's `k`, names nothing.
#[test]
fn the_six_rows_stand_in_ascending_order_of_their_length() {
    let lengths: Vec<u32> = super::ROWS.iter().map(|row| row.bytes).collect();
    assert_eq!(lengths, [29, 53, 57, 120, 149, 216]);
    assert!(lengths.windows(2).all(|pair| pair[0] < pair[1]));
    for row in &super::ROWS {
        assert_eq!(identify(row.bytes, row.crc32), Some(row.program));
        assert_eq!(row.program.fingerprint(), (row.bytes, row.crc32));
        for other in &super::ROWS {
            if other.bytes != row.bytes {
                assert_eq!(identify(row.bytes, other.crc32), None);
                assert_eq!(identify(other.bytes, row.crc32), None);
            }
        }
        assert_eq!(identify(row.bytes + 1, row.crc32), None);
        assert_eq!(identify(row.bytes - 1, row.crc32), None);
        assert_eq!(identify(row.bytes, row.crc32.wrapping_add(1)), None);
    }
}

/// A stand-in is solved, not searched: every fingerprint of the table, and
/// a few lengths around them, come out with exactly the length and CRC32
/// asked for, and two stand-ins of one fingerprint are the same bytes.
#[test]
fn stand_ins_hit_their_fingerprint() {
    for (len, crc) in [
        (4u32, 0u32),
        (29, 0x0e06_077d),
        (29, 0x1a06_eecf),
        (216, 0xbc85_e701),
    ] {
        let p = stand_in(len, crc);
        assert_eq!((p.len() as u32, crc32fast::hash(&p)), (len, crc));
        assert_eq!(p, stand_in(len, crc));
    }
    for len in 4..64u32 {
        let p = stand_in(len, 0xdead_beef);
        assert_eq!((p.len() as u32, crc32fast::hash(&p)), (len, 0xdead_beef));
    }
}

// ---------------------------------------------------------------------------
// The write seam (spec G 3.14.7, closed: no filter record is written)
// ---------------------------------------------------------------------------

/// A RAR 4 write that asks for filters is REFUSED, with spec G 3.14.9's
/// error kind and from `Writer::new`, before any output. It is not
/// resolved to `FilterPolicy::Off` behind the caller's back, which is the
/// other half of what 3.14.7 allowed: a caller who asked for filtered
/// output and silently got unfiltered output has no way to find out.
///
/// RAR 5 is untouched (its filters are spec H3's), and so is a RAR 4
/// request that asks for no filters; both are checked through the rule
/// itself, because `Writer::new` beyond this point is spec G's and is
/// still `unimplemented!()`.
#[test]
fn a_rar4_filter_request_is_refused() {
    use crate::write::{FilterPolicy, Rar4Version, WriteFormat, WriteMethod, WriteOptions};

    for version in [Rar4Version::V29, Rar4Version::V30, Rar4Version::V40] {
        let options = WriteOptions {
            format: WriteFormat::Rar4(version),
            method: WriteMethod::Compressed {
                level: 5,
                dictionary: None,
            },
            filters: FilterPolicy::Detect,
            ..WriteOptions::default()
        };
        let e = match crate::Writer::new(options) {
            Err(e) => e,
            Ok(_) => panic!("{version:?}: a RAR 4 filter request must be refused"),
        };
        assert!(
            matches!(
                e.kind(),
                ErrorKind::Unsupported(Unsupported::WriteFeature(_))
            ),
            "{version:?}: {:?}",
            e.kind()
        );
        assert!(
            format!("{e}").contains("FilterPolicy::Off"),
            "the refusal names the one word that fixes it: {e}"
        );
    }

    // Every other combination passes the rule.
    for format in [
        WriteFormat::Rar5,
        WriteFormat::Rar4(Rar4Version::V29),
        WriteFormat::Rar4(Rar4Version::V40),
    ] {
        refuse_written_filters(format, FilterPolicy::Off).unwrap();
    }
    refuse_written_filters(WriteFormat::Rar5, FilterPolicy::Detect).unwrap();
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

fn write(
    w: &mut RecordBuilder,
    p: StandardProgram,
    start: u64,
    len: u32,
    pos: u64,
    params: Params,
) -> Vec<u8> {
    let mut out = Vec::new();
    w.record(p, start, len, pos, params, &mut out).unwrap();
    out
}

fn parse(s: &mut FilterState, bytes: &[u8], pos: u64) -> crate::Result<Parsed> {
    let mut src = Bytes(bytes);
    let r = s.parse(&mut src, pos, WIDE);
    if r.is_ok() {
        assert!(src.0.is_empty(), "record left {} bytes unread", src.0.len());
    }
    r
}

fn new_state() -> FilterState {
    FilterState::new(&policy()).unwrap()
}

/// Run every due filter over zeros.
fn drain_due(s: &mut FilterState, pos: u64) {
    let zeros = vec![0u8; STAGE_SPAN as usize];
    while let Some(end) = s.due_at() {
        if end > pos {
            break;
        }
        let len = (end - s.hold_from().unwrap()) as usize;
        let out = s
            .run_due(pos, SpanBytes::Window(&zeros[..len], &[]))
            .unwrap();
        assert_eq!(out.unwrap().bytes.len(), len);
    }
}

#[test]
fn derived_records_v1_to_v4() {
    let rows: Vec<Vec<u8>> = DERIVED
        .lines()
        .skip(1)
        .map(|l| hex(l.split('\t').nth(2).unwrap()))
        .collect();
    let rgb = Params::Rgb {
        width: 768,
        red_at: 2,
    };
    // V1: the rar 3.93 RGB reuse, after a definition of slot 0 for 32,768.
    let (mut w, mut s) = (RecordBuilder::new(), new_state());
    let def = write(&mut w, StandardProgram::Rgb, 0, 32_768, 0, rgb);
    parse(&mut s, &def, 0).unwrap();
    drain_due(&mut s, 32_768);
    assert_eq!(
        write(&mut w, StandardProgram::Rgb, 32_768, 32_768, 32_768, rgb),
        rows[0]
    );
    let p = parse(&mut s, &rows[0], 32_768).unwrap();
    assert_eq!(
        (p.slot, p.defined, p.start, p.len, p.regs[0], p.regs[1]),
        (0, false, 32_768, 32_768, 771, 2)
    );

    // V2: select slot 1 (delta), start P + 258 + 65278, length 65536.
    let (mut w, mut s) = (RecordBuilder::new(), new_state());
    for (p, params) in [
        (StandardProgram::X86Call, Params::None),
        (StandardProgram::Delta, Params::Channels(3)),
    ] {
        let b = write(&mut w, p, 0, 0, 0, params);
        parse(&mut s, &b, 0).unwrap();
    }
    let b = write(&mut w, StandardProgram::X86Call, 0, 0, 0, Params::None);
    parse(&mut s, &b, 0).unwrap();
    drain_due(&mut s, 0);
    let v2 = write(
        &mut w,
        StandardProgram::Delta,
        65_536,
        65_536,
        0,
        Params::Channels(3),
    );
    assert_eq!(v2, rows[1]);
    let p = parse(&mut s, &rows[1], 0).unwrap();
    assert_eq!(
        (p.slot, p.defined, p.start, p.len, p.regs[0]),
        (1, false, 65_536, 65_536, 3)
    );

    // V3: reuse the last slot (x86), start = P, length inherited.
    let (mut w, mut s) = (RecordBuilder::new(), new_state());
    let b = write(&mut w, StandardProgram::X86Call, 0, 32_768, 0, Params::None);
    parse(&mut s, &b, 0).unwrap();
    drain_due(&mut s, 32_768);
    assert_eq!(
        write(
            &mut w,
            StandardProgram::X86Call,
            32_768,
            32_768,
            32_768,
            Params::None
        ),
        rows[2]
    );
    let p = parse(&mut s, &rows[2], 32_768).unwrap();
    assert_eq!((p.slot, p.start, p.len, p.body_len), (0, 32_768, 32_768, 1));

    // V4: select slot 0 after slot 1, start P + 5, length 12000.
    let (mut w, mut s) = (RecordBuilder::new(), new_state());
    for p in [StandardProgram::X86Call, StandardProgram::Itanium] {
        let b = write(&mut w, p, 0, 0, 0, Params::None);
        parse(&mut s, &b, 0).unwrap();
    }
    drain_due(&mut s, 0);
    assert_eq!(
        write(&mut w, StandardProgram::X86Call, 5, 12_000, 0, Params::None),
        rows[3]
    );
    let p = parse(&mut s, &rows[3], 0).unwrap();
    assert_eq!((p.slot, p.start, p.len), (0, 5, 12_000));
}

/// One line of `genuine-records.tsv` (SPEC-J 5.1): a record as the
/// census read it out of a genuine archive.
struct GenuineRecord<'a> {
    archive: &'a str,
    member: &'a str,
    stream: &'a str,
    /// The stream position the record was read at.
    at: u64,
    /// Where the member begins in its stream.
    member_start: u64,
    flags: u8,
    slot: u32,
    defines: bool,
    start: u64,
    len: u32,
    /// The registers the record sends, by number.
    registers: Vec<(usize, u32)>,
    body_len: u32,
    /// The program of the record's slot: a definition names it by its
    /// length and CRC32 (3.4), and a later record of the stream means
    /// the program its slot was last defined with.
    kind: StandardProgram,
}

impl GenuineRecord<'_> {
    fn sent(&self, number: usize) -> u32 {
        self.registers
            .iter()
            .find(|(n, _)| *n == number)
            .map(|(_, value)| *value)
            .unwrap_or_else(|| panic!("{} sends no R{number}", self.archive))
    }

    /// The parameters the record states, from the registers it sends
    /// (3.9): none for the address programs, `R0` channels for delta and
    /// audio, `R0 - 3` and `R1` for RGB.
    fn params(&self) -> Params {
        match self.kind {
            StandardProgram::X86Call | StandardProgram::X86CallJump | StandardProgram::Itanium => {
                Params::None
            }
            StandardProgram::Delta | StandardProgram::Audio => Params::Channels(self.sent(0)),
            StandardProgram::Rgb => Params::Rgb {
                width: self.sent(0) - 3,
                red_at: self.sent(1),
            },
        }
    }
}

/// Every line of the table under its header, in the table's order.
fn genuine_records() -> Vec<GenuineRecord<'static>> {
    let mut stream_of = ("", "");
    let mut in_slot: Vec<Option<StandardProgram>> = Vec::new();
    GENUINE
        .lines()
        .skip(1)
        .map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            assert_eq!(f.len(), 13, "{line}");
            if (f[0], f[2]) != stream_of {
                stream_of = (f[0], f[2]);
                in_slot.clear();
            }
            let registers = f[10]
                .split_whitespace()
                .filter(|word| *word != "-")
                .map(|word| {
                    let (name, value) = word.split_once('=').unwrap();
                    let number = name.strip_prefix('R').unwrap().parse().unwrap();
                    (number, value.parse().unwrap())
                })
                .collect();
            let slot: u32 = f[6].parse().unwrap();
            let defines = f[7] == "yes";
            if in_slot.len() <= slot as usize {
                in_slot.resize(slot as usize + 1, None);
            }
            if defines {
                let (len, crc) = f[12].split_once(':').unwrap();
                let crc = u32::from_str_radix(crc, 16).unwrap();
                in_slot[slot as usize] = identify(len.parse().unwrap(), crc);
            }
            GenuineRecord {
                archive: f[0],
                member: f[1],
                stream: f[2],
                at: f[3].parse().unwrap(),
                member_start: f[4].parse().unwrap(),
                flags: u8::from_str_radix(f[5], 16).unwrap(),
                slot,
                defines,
                start: f[8].parse().unwrap(),
                len: f[9].parse().unwrap(),
                registers,
                body_len: f[11].parse().unwrap(),
                kind: in_slot[slot as usize].unwrap_or_else(|| panic!("no program: {line}")),
            }
        })
        .collect()
}

/// SPEC-J 6.1, record equality: for every stream of every archive in
/// `genuine-records.tsv`, each record built again by section 3.9's
/// rules from the fields the table states is read back by the parser
/// with exactly those fields: first byte, slot, whether it defines,
/// span, registers and body length. One thread, a few KiB.
#[test]
fn every_genuine_record_reads_back_with_the_fields_the_table_states() {
    let rows = genuine_records();
    assert_eq!(rows.len(), 126);
    let mut wrong = Vec::new();
    let mut at = 0;
    while at < rows.len() {
        let (archive, stream) = (rows[at].archive, rows[at].stream);
        let (mut builder, mut state) = (RecordBuilder::new(), new_state());
        while at < rows.len() && (rows[at].archive, rows[at].stream) == (archive, stream) {
            let row = &rows[at];
            at += 1;
            let what = format!("{archive} stream {stream} at {}", row.at);
            let bytes = write(
                &mut builder,
                row.kind,
                row.start,
                row.len,
                row.at,
                row.params(),
            );
            drain_due(&mut state, row.at);
            let read =
                parse(&mut state, &bytes, row.at).unwrap_or_else(|e| panic!("{what}: {e:?}"));
            let sent: Vec<u32> = row.registers.iter().map(|&(n, _)| read.regs[n]).collect();
            let stated: Vec<u32> = row.registers.iter().map(|&(_, v)| v).collect();
            let got = (
                read.flags,
                read.slot,
                read.defined,
                read.start,
                read.len,
                sent,
                read.body_len,
            );
            let want = (
                row.flags,
                row.slot,
                row.defines,
                row.start,
                row.len,
                stated,
                row.body_len,
            );
            if got != want {
                wrong.push(format!("{what}: read {got:x?}, the table {want:x?}"));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} records:\n{}",
        wrong.len(),
        rows.len(),
        wrong.join("\n")
    );
}

/// A body built field by field, for records no genuine writer emits.
fn raw(flags: u8, build: impl FnOnce(&mut BodyBits)) -> Vec<u8> {
    let mut b = BodyBits::default();
    build(&mut b);
    let mut out = Vec::new();
    b.emit(flags, &mut out).unwrap();
    out
}

fn program_bits(b: &mut BodyBits, program: &[u8]) {
    b.vint(program.len() as u32).unwrap();
    for &x in program {
        b.put(x as u32, 8).unwrap();
    }
}

#[test]
fn u1_u2_unknown_programs_are_refused() {
    let mut changed = stand_in_program(StandardProgram::Delta);
    *changed.last_mut().unwrap() ^= 1;
    let zeros = vec![0u8; 300];
    for (program, crc) in [
        (&changed[..], crc32fast::hash(&changed)),
        (&zeros[..], 0xb534_8fd2),
    ] {
        let mut s = new_state();
        let rec = raw(0xb0, |b| {
            b.vint(0).unwrap();
            b.vint(0).unwrap();
            b.vint(10).unwrap();
            b.put(1, 7).unwrap();
            b.vint(3).unwrap();
            program_bits(b, program);
        });
        let k = kind(parse(&mut s, &rec, 100));
        assert_eq!(
            k,
            text(ErrorKind::Unsupported(Unsupported::FilterProgram {
                len: program.len() as u32,
                crc32: crc
            }))
        );
        // Nothing queued: no byte at or after P is held for a filter.
        assert_eq!((s.hold_from(), s.queued()), (None, 0));
    }
}

/// The one non-standard program the fork's census found in the wild
/// (section 5.4, U11): 29 bytes, CRC32 `0x1a06eecf`, carried by the
/// fixture `rar15_40/rarvm/generic_delta_padding_mutation.rar`. That
/// fingerprint is published in spec J, and a fingerprint is all the reader
/// looks at, so the stand-in below stands in for it exactly as a stand-in
/// stands in for a standard program: this crate holds no copy of U11's
/// bytes any more than it holds a copy of the delta program's.
fn u11_program() -> Vec<u8> {
    let p = stand_in(29, 0x1a06_eecf);
    assert_eq!((p.len(), crc32fast::hash(&p)), (29, 0x1a06_eecf));
    p
}

/// U11: the census's one real-world non-standard program is refused by
/// its fingerprint, with the length and CRC32 the row names, and nothing
/// of its span is delivered. The old engine runs such a program through
/// an interpreter (section 6.1 lists this archive as the one exception to
/// O-archive) and reference `unrar` 7.23 writes wrong bytes and exits 3;
/// rarkit refuses (section 8 item 1).
///
/// NOT DONE YET: the ARCHIVE half of U11, reading that fixture through
/// `rarkit_oracle::fixture` end to end, waits on spec H's RAR 3 LZ
/// decoder, because the record lives inside the member's compressed
/// stream. The half below is the fingerprint, which is what decides the
/// refusal; the archive adds only the path from the stream to it.
#[test]
fn u11_census_program_is_refused_by_its_fingerprint() {
    let program = u11_program();
    // Not one of the six: the table says so before anything runs it.
    assert_eq!(identify(29, 0x1a06_eecf), None);
    let mut s = new_state();
    let rec = raw(0xb0, |b| {
        b.vint(0).unwrap();
        b.vint(0).unwrap();
        b.vint(10).unwrap();
        b.put(1, 7).unwrap();
        b.vint(3).unwrap();
        program_bits(b, &program);
    });
    assert_eq!(
        kind(parse(&mut s, &rec, 100)),
        text(ErrorKind::Unsupported(Unsupported::FilterProgram {
            len: 29,
            crc32: 0x1a06_eecf
        }))
    );
    assert_eq!((s.hold_from(), s.queued()), (None, 0));
    // The length alone is not what refuses it: the standard delta program
    // is 29 bytes too, and a 29-byte string with ITS CRC32 is accepted.
    let delta = stand_in_program(StandardProgram::Delta);
    assert_eq!(delta.len(), program.len());
    assert_eq!(
        identify(29, crc32fast::hash(&delta)),
        Some(StandardProgram::Delta)
    );
}

/// The other side of U11: the fixture is in the old engine's corpus and
/// the old engine extracts it, which is what makes it section 6.1's
/// listed exception to O-archive rather than a disagreement.
#[cfg(all(feature = "repo-tests", feature = "oracle-compare"))]
#[test]
fn u11_fixture_is_in_the_corpus_and_the_oracle_runs_it() {
    const NAME: &str = "rar15_40/rarvm/generic_delta_padding_mutation.rar";
    let names = rarkit_oracle::fixture_names().expect("the corpus");
    assert!(
        names.iter().any(|n| n == NAME),
        "{NAME} is not in the corpus"
    );
    let archive = rarkit_oracle::fixture(NAME).expect("fixture bytes");
    let members = rarkit_oracle::extract(&[&archive], None).expect("the old engine runs it");
    assert!(!members.is_empty());
}

/// A stream with slots `programs` defined, each by a record whose span
/// has run: zero-length spans at 0, but for RGB, whose row must fit its
/// span (section 3.5) and so takes the three bytes after the others.
fn with_slots(programs: &[StandardProgram]) -> (RecordBuilder, FilterState) {
    let (mut w, mut s) = (RecordBuilder::new(), new_state());
    let mut at = 0u64;
    for &p in programs {
        let (params, len) = match p {
            StandardProgram::Delta | StandardProgram::Audio => (Params::Channels(1), 0),
            StandardProgram::Rgb => (
                Params::Rgb {
                    width: 3,
                    red_at: 0,
                },
                3,
            ),
            _ => (Params::None, 0),
        };
        let b = write(&mut w, p, at, len, 0, params);
        parse(&mut s, &b, 0).unwrap();
        at += u64::from(len);
    }
    drain_due(&mut s, at);
    (w, s)
}

#[test]
fn u3_to_u7_and_u9_corrupt_records() {
    use StandardProgram::*;
    // U3: selector 5 with 2 slots defined.
    let (_, mut s) = with_slots(&[X86Call, Delta]);
    let r = raw(0x80, |b| {
        b.vint(5).unwrap();
        b.vint(0).unwrap();
    });
    assert_eq!(kind(parse(&mut s, &r, 0)), RECORD);

    // U4: the longest span, by program (sections 3.5 and 4), each where
    // the reference stops running the program: the three address programs
    // at 262,143 bytes, and delta, RGB and audio at 131,072.
    for (program, most, r0) in [
        (X86Call, 262_143u32, 1),
        (X86CallJump, 262_143, 1),
        (Itanium, 262_143, 1),
        // A channel count, and for RGB a row of three bytes.
        (Audio, 131_072, 1),
        (Delta, 131_072, 1),
        (Rgb, 131_072, 6),
    ] {
        assert_eq!(longest_span(program), most, "{program:?}");
        for (len, ok) in [(most, true), (most + 1, false)] {
            let (_, mut s) = with_slots(&[program]);
            let r = raw(0x30, |b| {
                b.vint(3).unwrap();
                b.vint(len).unwrap();
                b.put(1, 7).unwrap();
                b.vint(r0).unwrap();
            });
            let outcome = parse(&mut s, &r, 0);
            assert_eq!(outcome.is_ok(), ok, "{program:?}, {len} bytes");
            if !ok {
                assert_eq!(kind(outcome), RECORD, "{program:?}, {len} bytes");
            }
        }
    }

    // U5: a span ending one byte past the member.
    let (_, mut s) = with_slots(&[X86Call]);
    let r = raw(0x20, |b| {
        b.vint(10).unwrap();
        b.vint(91).unwrap();
    });
    // It is judged when the member ends, where the bytes its packed data
    // produces are known to end (SPEC-J 3.8): the record is read, and the
    // span the member began and could not complete fails it there.
    let member = MemberBounds { start: 0, end: 100 };
    s.read_record(&mut Bytes(&r), 0, member).unwrap();
    assert_eq!(kind(s.end_member(100)), RECORD);
    let r = raw(0x20, |b| {
        b.vint(10).unwrap();
        b.vint(90).unwrap();
    });
    s.read_record(&mut Bytes(&r), 0, member).unwrap();
    let zeros = [0u8; 90];
    assert!(s
        .run_due(100, SpanBytes::Window(&zeros, &[]))
        .unwrap()
        .is_some());
    s.end_member(100).unwrap();

    // U6: the second span starting inside the first; adjacent is fine.
    let (_, mut s) = with_slots(&[X86Call]);
    let span = |start: u32| {
        raw(0x20, |b| {
            b.vint(start).unwrap();
            b.vint(100).unwrap();
        })
    };
    parse(&mut s, &span(0), 0).unwrap();
    assert_eq!(kind(parse(&mut s, &span(99), 0)), RECORD);
    let (_, mut s) = with_slots(&[X86Call]);
    parse(&mut s, &span(0), 0).unwrap();
    parse(&mut s, &span(100), 0).unwrap();

    // U7: parameters, over a span of 600 bytes, on both sides of every
    // edge of section 3.5. `Some` is the parameter the filter is queued
    // with; `None` is `Corrupt`, parameters: outside what the reference
    // runs the program for, no transform is run.
    for (program, r0, r1, runs) in [
        (Delta, 0, 0, None),
        (Delta, 1, 0, Some(1)),
        (Delta, 1_024, 0, Some(1_024)),
        (Delta, 1_025, 0, None),
        (Delta, 65_536, 0, None),
        (Delta, u32::MAX, 0, None),
        (Audio, 0, 0, None),
        (Audio, 1, 0, Some(1)),
        (Audio, 128, 0, Some(128)),
        (Audio, 129, 0, None),
        (Audio, u32::MAX, 0, None),
        // RGB: the row is `R0 - 3` bytes, a positive multiple of three;
        // the red position is 0 to 2. A row longer than the span runs
        // (the test after this one says why), up to the widest row that
        // was put to a genuine reader.
        (Rgb, 0, 0, None),
        (Rgb, 2, 0, None),
        (Rgb, 3, 0, None),
        (Rgb, 5, 0, None),
        (Rgb, 6, 0, Some(3)),
        (Rgb, 7, 0, None),
        (Rgb, 603, 0, Some(600)),
        (Rgb, 603, 2, Some(600)),
        (Rgb, 603, 3, None),
        (Rgb, 603, u32::MAX, None),
        (Rgb, 604, 0, None),
        (Rgb, 606, 0, Some(603)),
        (Rgb, 3_145_731, 0, Some(3_145_728)),
        (Rgb, 3_145_734, 0, None),
        (Rgb, u32::MAX - 1, 0, None),
        (Rgb, u32::MAX, 0, None),
    ] {
        let (_, mut s) = with_slots(&[program]);
        let r = raw(0x30, |b| {
            b.vint(3).unwrap();
            b.vint(600).unwrap();
            b.put(3, 7).unwrap();
            b.vint(r0).unwrap();
            b.vint(r1).unwrap();
        });
        let outcome = parse(&mut s, &r, 0);
        let what = format!("{program:?} R0={r0} R1={r1}");
        match runs {
            Some(_) => assert_eq!(outcome.map(|p| p.len).ok(), Some(600), "{what}"),
            None => assert_eq!(kind(outcome), PARAMS, "{what}"),
        }
        assert_eq!(s.queued(), usize::from(runs.is_some()), "{what}");
    }
    // A register that is not sent reads as zero: delta, audio and RGB
    // without their first are refused, and RGB without its second runs.
    for (program, mask, runs) in [
        (Delta, 0, false),
        (Audio, 0, false),
        (Rgb, 0, false),
        (Rgb, 1, true),
        (Delta, 2, false),
    ] {
        let (_, mut s) = with_slots(&[program]);
        let r = raw(0x30, |b| {
            b.vint(3).unwrap();
            b.vint(600).unwrap();
            b.put(mask, 7).unwrap();
            b.vint(6).unwrap();
        });
        let outcome = parse(&mut s, &r, 0);
        match runs {
            true => assert!(outcome.is_ok(), "{program:?} mask {mask}"),
            false => assert_eq!(kind(outcome), PARAMS, "{program:?} mask {mask}"),
        }
    }
    // Register 4 is the span's length when it is sent: equal to it, the
    // record is as if it were not sent; any other value is refused, on
    // every program.
    for program in [X86Call, X86CallJump, Itanium, Delta, Rgb, Audio] {
        for (r4, ok) in [(600, true), (599, false), (601, false), (0, false)] {
            let (_, mut s) = with_slots(&[program]);
            let r = raw(0x30, |b| {
                b.vint(3).unwrap();
                b.vint(600).unwrap();
                b.put(1 | 1 << 4, 7).unwrap();
                b.vint(6).unwrap();
                b.vint(r4).unwrap();
            });
            let outcome = parse(&mut s, &r, 0);
            match ok {
                true => assert!(outcome.is_ok(), "{program:?} R4={r4}"),
                false => assert_eq!(kind(outcome), PARAMS, "{program:?} R4={r4}"),
            }
        }
    }
    // Any other register a program does not read changes nothing.
    for program in [X86Call, X86CallJump, Itanium, Delta, Rgb, Audio] {
        let (_, mut s) = with_slots(&[program]);
        let r = raw(0x30, |b| {
            b.vint(3).unwrap();
            b.vint(600).unwrap();
            b.put(0b110_1111, 7).unwrap();
            for value in [6, 1, 77, 78, 80, 81] {
                b.vint(value).unwrap();
            }
        });
        parse(&mut s, &r, 0).unwrap_or_else(|e| panic!("{program:?}: {e:?}"));
    }

    // U9: a body cut one bit short of its last register. Start (6 bits),
    // length (18), mask (7) and R0 in its 32-bit form (34) are 65 bits.
    let (_, mut s) = with_slots(&[Delta]);
    let mut b = BodyBits::default();
    b.vint(0).unwrap();
    b.put(2, 2).unwrap();
    b.put(300, 16).unwrap();
    b.put(1, 7).unwrap();
    b.put(3, 2).unwrap();
    b.put(3, 32).unwrap();
    let body = &b.body()[..8];
    let rec: Vec<u8> = [0x36, 1].iter().chain(body).copied().collect();
    assert_eq!(kind(parse(&mut s, &rec, 0)), RECORD);
    // The same with its last byte is accepted.
    let (_, mut s) = with_slots(&[Delta]);
    let rec: Vec<u8> = [0x36, 2].iter().chain(b.body()).copied().collect();
    parse(&mut s, &rec, 0).unwrap();
}

/// SPEC-J 3.5, "An RGB row wider than its span": genuine rar 4.20 and
/// 5.50, packing a true colour file that is 1 or 2 bytes longer than a
/// multiple of 65,536, end the member with an RGB record over those last
/// bytes with `R0 = 6`, a row of three. The record is run, and its result
/// is section 3.7.2's; reference unrar 7.23 leaves the span as it is and
/// fails its own writer's member, and rarkit does not follow it there.
///
/// One thread, no pool; under 2 MiB.
#[test]
fn an_rgb_row_wider_than_its_span_runs_as_a_genuine_rar_4_20_record() {
    let (_, mut s) = with_slots(&[StandardProgram::Rgb]);
    // The genuine record's fields: one byte, a row of three, red at 0.
    let r = raw(0x30, |b| {
        b.vint(3).unwrap();
        b.vint(1).unwrap();
        b.put(3, 7).unwrap();
        b.vint(6).unwrap();
        b.vint(0).unwrap();
    });
    let p = parse(&mut s, &r, 0).unwrap();
    assert_eq!((p.start, p.len), (3, 1));
    let data = [0x61u8];
    let out = s
        .run_due(4, SpanBytes::Window(&data, &[]))
        .unwrap()
        .unwrap();
    let mut want = [0u8; 1];
    rgb_decode(&data, &mut want, 3, 0);
    assert_eq!(out.bytes, want);
}

#[test]
fn u8_delta_at_its_most_channels_runs_and_past_them_does_not() {
    // Section 3.5: the reference runs the delta program for 1 to 1,024
    // channels. At 1,024 over a span of ten bytes every byte is its own
    // channel; at 1,025 and at 2^32 - 1 the record is refused, where the
    // reference would deliver the span unchanged.
    let record = |channels: u32| {
        raw(0x30, |b| {
            b.vint(0).unwrap();
            b.vint(10).unwrap();
            b.put(1, 7).unwrap();
            b.vint(channels).unwrap();
        })
    };
    for channels in [1_025, u32::MAX] {
        let (_, mut s) = with_slots(&[StandardProgram::Delta]);
        assert_eq!(kind(parse(&mut s, &record(channels), 0)), PARAMS);
        assert_eq!(s.queued(), 0, "nothing waits to be run");
    }
    let (_, mut s) = with_slots(&[StandardProgram::Delta]);
    parse(&mut s, &record(1_024), 0).unwrap();
    let data: Vec<u8> = (1..=10).collect();
    let out = s
        .run_due(10, SpanBytes::Window(&data, &[]))
        .unwrap()
        .unwrap();
    assert_eq!(
        out.bytes,
        data.iter()
            .map(|b| 0u8.wrapping_sub(*b))
            .collect::<Vec<_>>()
    );
}

#[test]
fn u10_queue_and_slot_bounds() {
    // Section 4: 8,193 filters wait together and the next is refused.
    assert_eq!((WAITING_AT_MOST, SLOTS_AT_MOST), (8_193, 8_193));
    let (_, mut s) = with_slots(&[StandardProgram::X86Call]);
    for i in 0..WAITING_AT_MOST as u32 {
        let r = raw(0x20, |b| {
            b.vint(i).unwrap();
            b.vint(1).unwrap();
        });
        parse(&mut s, &r, 0).unwrap();
    }
    let r = raw(0x00, |b| b.vint(WAITING_AT_MOST as u32).unwrap());
    assert_eq!(kind(parse(&mut s, &r, 0)), RECORD);

    // A stream defines 8,193 slots and the 8,194th definition is refused.
    let (mut w, mut s) = with_slots(&[StandardProgram::X86Call]);
    let _ = &mut w;
    let define = |n: u32| {
        raw(0x80, |b| {
            b.vint(n + 1).unwrap();
            b.vint(0).unwrap();
            program_bits(b, &stand_in_program(StandardProgram::X86Call));
        })
    };
    for n in 1..SLOTS_AT_MOST as u32 {
        parse(&mut s, &define(n), 0).unwrap();
    }
    assert_eq!(
        kind(parse(&mut s, &define(SLOTS_AT_MOST as u32), 0)),
        RECORD
    );
}

/// Section 4, "Memory": the limits fix the worst case, stated here in
/// bytes. Two staging areas of the longest admitted span, the slots and
/// the waiting filters at their limits; all three are sized from the
/// constants and never from archive bytes. Single threaded.
#[test]
fn the_worst_case_memory_is_these_bytes() {
    assert_eq!(FilterState::STAGING_BYTES, 524_286);
    assert_eq!(FilterState::SLOT_BYTES, 8);
    assert_eq!(FilterState::WAITING_BYTES, 24);
    let most = FilterState::STAGING_BYTES
        + (SLOTS_AT_MOST * FilterState::SLOT_BYTES) as u64
        + (WAITING_AT_MOST * FilterState::WAITING_BYTES) as u64;
    assert_eq!(most, 786_462);
}

#[test]
fn reset_global_data_and_truncation() {
    use StandardProgram::*;
    // A reset while a filter is queued.
    let (_, mut s) = with_slots(&[X86Call]);
    parse(
        &mut s,
        &raw(0x20, |b| {
            b.vint(0).unwrap();
            b.vint(5).unwrap();
        }),
        0,
    )
    .unwrap();
    let reset = raw(0x80, |b| {
        b.vint(0).unwrap();
        b.vint(0).unwrap();
        program_bits(b, &stand_in_program(Delta));
    });
    assert_eq!(kind(parse(&mut s, &reset, 0)), RECORD);

    // Bit 3 of the flags and whatever follows the last field are nothing
    // (section 3.3 item 6): a "global data" length with its bytes, and one
    // that runs far past the body's end, are the same record as without.
    let (_, mut s) = with_slots(&[X86Call]);
    let r = raw(0x28, |b| {
        b.vint(1).unwrap();
        b.vint(4).unwrap();
        b.vint(3).unwrap();
        for x in [1, 2, 3] {
            b.put(x, 8).unwrap();
        }
    });
    let p = parse(&mut s, &r, 0).unwrap();
    assert_eq!((p.start, p.len), (1, 4));
    let r = raw(0x28, |b| {
        b.vint(0).unwrap();
        b.vint(1).unwrap();
        b.vint(200).unwrap();
    });
    let p = parse(&mut s, &r, 10).unwrap();
    assert_eq!((p.start, p.len), (10, 1));

    // A program of length 0, and one longer than the body.
    let (_, mut s) = with_slots(&[]);
    let r = raw(0x80, |b| {
        b.vint(0).unwrap();
        b.vint(0).unwrap();
        b.vint(0).unwrap();
    });
    assert_eq!(kind(parse(&mut s, &r, 0)), RECORD);
    let r = raw(0x80, |b| {
        b.vint(0).unwrap();
        b.vint(0).unwrap();
        b.vint(200).unwrap();
    });
    assert_eq!(kind(parse(&mut s, &r, 0)), RECORD);

    // The source running out mid-record passes its error through.
    let (_, mut s) = with_slots(&[]);
    let r = raw(0x80, |b| {
        b.vint(0).unwrap();
        b.vint(0).unwrap();
        program_bits(b, &stand_in_program(Delta));
    });
    assert_eq!(kind(parse(&mut s, &r[..r.len() - 1], 0)), "Truncated");

    // The negative vint form is read (then refused as a span far away).
    let (_, mut s) = with_slots(&[X86Call]);
    let r = raw(0x00, |b| {
        b.put(1, 2).unwrap();
        b.put(3, 8).unwrap();
        b.put(4, 4).unwrap();
    });
    let member = MemberBounds {
        start: 0,
        end: 1 << 40,
    };
    let p = s.parse(&mut Bytes(&r), 0, member).unwrap();
    assert_eq!(p.start, 0xFFFF_FF34);
}

#[test]
fn finish_member_and_solid_offsets() {
    // A filter whose span began before the member's end and still waits
    // there fails the member, and is dropped with it (SPEC-J 3.8).
    let (_, mut s) = with_slots(&[StandardProgram::X86Call]);
    s.end_member(0).unwrap();
    parse(
        &mut s,
        &raw(0x20, |b| {
            b.vint(0).unwrap();
            b.vint(5).unwrap();
        }),
        0,
    )
    .unwrap();
    assert_eq!(kind(s.end_member(5)), RECORD);
    assert_eq!(s.queued(), 0, "nothing waits after a member's end");
    s.end_member(5).unwrap();

    // One whose span starts at or past the member's end is dropped there
    // and fails nothing (SPEC-J 3.8, section 4).
    let (_, mut s) = with_slots(&[StandardProgram::X86Call]);
    parse(
        &mut s,
        &raw(0x20, |b| {
            b.vint(5).unwrap();
            b.vint(5).unwrap();
        }),
        0,
    )
    .unwrap();
    assert_eq!(s.queued(), 1);
    s.end_member(5).unwrap();
    assert_eq!(s.queued(), 0);
    assert_eq!(s.hold_from(), None);

    // F_off is member-relative: an x86 span in a member starting at 1000.
    let mut data = vec![0x90u8; 64];
    data[10] = 0xE8;
    data[11..15].copy_from_slice(&0x0000_2000u32.to_le_bytes());
    let (_, mut s) = with_slots(&[StandardProgram::X86Call]);
    let r = raw(0x20, |b| {
        b.vint(0).unwrap();
        b.vint(64).unwrap();
    });
    s.read_record(
        &mut Bytes(&r),
        1200,
        MemberBounds {
            start: 1000,
            end: 5000,
        },
    )
    .unwrap();
    let got = s
        .run_due(1264, SpanBytes::Window(&data, &[]))
        .unwrap()
        .unwrap();
    assert_eq!(got.start, 1200);
    let mut want = data.clone();
    address_filters::x86_pass::<false, false, false>(&mut want, 200);
    assert_eq!(got.bytes, want);
}

#[test]
fn run_due_window_split_and_staged_agree() {
    use StandardProgram::*;
    let mut rng = rarkit_testdata::Seeded::new(77);
    for (program, params, regs) in [
        (Delta, Params::Channels(3), [3, 0]),
        (Audio, Params::Channels(4), [4, 0]),
        (
            Rgb,
            Params::Rgb {
                width: 768,
                red_at: 1,
            },
            [771, 1],
        ),
        (X86CallJump, Params::None, [0, 0]),
        (Itanium, Params::None, [0, 0]),
    ] {
        let data = rng.bytes(65_536);
        let mut outs = Vec::new();
        for mode in 0..3 {
            let (mut w, mut s) = with_slots(&[program]);
            let rec = write(&mut w, program, 70_000, 65_536, 70_000, params);
            s.read_record(
                &mut Bytes(&rec),
                70_000,
                MemberBounds {
                    start: 60_000,
                    end: 200_000,
                },
            )
            .unwrap();
            assert_eq!(s.hold_from(), Some(70_000));
            assert!(s
                .run_due(135_535, SpanBytes::Window(&data, &[]))
                .unwrap()
                .is_none());
            let window = match mode {
                0 => SpanBytes::Window(&data, &[]),
                1 => SpanBytes::Window(&data[..1000], &data[1000..]),
                _ => {
                    s.staging_in().unwrap().copy_from_slice(&data);
                    SpanBytes::Staged
                }
            };
            outs.push(s.run_due(135_536, window).unwrap().unwrap().bytes.to_vec());
            assert_eq!(s.hold_from(), None);
        }
        assert_eq!(outs[0], outs[1]);
        assert_eq!(outs[0], outs[2]);
        let mut want = vec![0u8; data.len()];
        match program {
            Delta | Audio | Rgb => tx(
                match program {
                    Delta => "delta",
                    Audio => "audio",
                    _ => "rgb",
                },
                true,
            )(
                &data,
                &mut want,
                if program == Rgb { regs[0] - 3 } else { regs[0] },
                regs[1],
            ),
            X86CallJump => {
                want.copy_from_slice(&data);
                address_filters::x86_pass::<false, true, false>(&mut want, 10_000);
            }
            _ => {
                want.copy_from_slice(&data);
                address_filters::ia64(&mut want, 10_000, Direction::Decode);
            }
        }
        assert_eq!(outs[0], want, "{program:?}");
    }
}

#[test]
fn staging_is_bounded_by_policy() {
    let mut p = policy();
    p.working_limit = FilterState::STAGING_BYTES - 1;
    assert!(matches!(
        FilterState::new(&p).unwrap_err().kind(),
        ErrorKind::LimitExceeded { .. }
    ));
}

// ---------------------------------------------------------------------------
// No allocation per span
// ---------------------------------------------------------------------------

/// The crate's ONE counting global allocator: a binary may install only
/// one, so spec F's own allocation test (`read::tests`) and spec H1's
/// reuse this.
pub(crate) mod counting {
    #![allow(unsafe_code)]
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local!(pub static ALLOCS: Cell<u64> = const { Cell::new(0) });
    thread_local!(static LIVE: Cell<i64> = const { Cell::new(0) });
    thread_local!(static PEAK: Cell<i64> = const { Cell::new(0) });
    thread_local!(static BASE: Cell<i64> = const { Cell::new(0) });

    /// Add `delta` to this thread's live bytes and raise its high-water
    /// mark. Bytes are what spec L 7 gates on; the call count above
    /// cannot see a buffer that grows without being reallocated.
    fn moved(delta: i64) {
        let _ = LIVE.try_with(|live| {
            let now = live.get() + delta;
            live.set(now);
            let _ = PEAK.try_with(|peak| {
                if now > peak.get() {
                    peak.set(now);
                }
            });
        });
    }

    pub struct Counting;
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
            moved(layout.size() as i64);
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            moved(-(layout.size() as i64));
            unsafe { System.dealloc(ptr, layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
            // A reallocation holds both blocks at once, which is how a
            // growing `Vec` reaches three times the bytes it keeps.
            moved(size as i64);
            let out = unsafe { System.realloc(ptr, layout, size) };
            moved(-(layout.size() as i64));
            out
        }
    }

    #[global_allocator]
    static GLOBAL: Counting = Counting;

    pub fn count() -> u64 {
        ALLOCS.with(|c| c.get())
    }

    /// Reset this thread's high-water mark to its live bytes, so the next
    /// [`peak_bytes`] reads only what happened since.
    pub fn reset_peak() {
        LIVE.with(|live| {
            PEAK.with(|peak| peak.set(live.get()));
            BASE.with(|base| base.set(live.get()));
        });
    }

    /// The most bytes this thread has had live since [`reset_peak`], over
    /// what it already held then: the peak a measured call ADDED.
    pub fn peak_bytes() -> u64 {
        PEAK.with(|peak| BASE.with(|base| (peak.get() - base.get()).max(0) as u64))
    }
}

#[test]
fn no_allocation_per_record_or_span() {
    use StandardProgram::*;
    let mut rng = rarkit_testdata::Seeded::new(5);
    let data = rng.bytes(65_536);
    let (mut w, mut s) = with_slots(&[Delta, Rgb, Audio, X86Call, Itanium]);
    let programs = [
        (Delta, Params::Channels(3)),
        (
            Rgb,
            Params::Rgb {
                width: 768,
                red_at: 2,
            },
        ),
        (Audio, Params::Channels(4)),
        (X86Call, Params::None),
        (Itanium, Params::None),
    ];
    let records: Vec<Vec<u8>> = (0..50u64)
        .map(|i| {
            let (p, params) = programs[i as usize % 5];
            write(&mut w, p, i * 65_536, 65_536, i * 65_536, params)
        })
        .collect();
    let before = counting::count();
    for (i, rec) in records.iter().enumerate() {
        let pos = i as u64 * 65_536;
        s.read_record(&mut Bytes(rec), pos, WIDE).unwrap();
        let split = if i % 2 == 0 { 65_536 } else { 777 };
        let out = s
            .run_due(
                pos + 65_536,
                SpanBytes::Window(&data[..split], &data[split..]),
            )
            .unwrap()
            .unwrap();
        assert_eq!(out.bytes.len(), 65_536);
    }
    assert_eq!(counting::count() - before, 0);
}

// ---------------------------------------------------------------------------
// The genuine archives, through the oracle
// ---------------------------------------------------------------------------

#[cfg(all(feature = "repo-tests", feature = "oracle-compare"))]
fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// O-archive and the vectors agree: the oracle extracts every archive of
/// section 5.1 to the seeded inputs. Then every genuine delta, RGB and
/// audio span of a solid or single-member archive, cut from the oracle's
/// output with its record's parameters, passes both directions.
#[cfg(all(feature = "repo-tests", feature = "oracle-compare"))]
#[test]
fn the_oracle_extracts_the_genuine_archives_and_their_spans_invert() {
    let inputs: std::collections::HashMap<&str, &str> = INPUTS
        .lines()
        .map(|line| {
            let mut words = line.split_whitespace();
            let sum = words.next().unwrap();
            (words.nth(1).unwrap(), sum)
        })
        .collect();
    let rows = genuine_records();
    let mut names: Vec<String> = std::fs::read_dir(ARCHIVES)
        .expect("the archives of section 5.1")
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".rar"))
        .collect();
    names.sort();
    assert_eq!(names.len(), 15);
    let mut spans = 0;
    for name in &names {
        let bytes = std::fs::read(format!("{ARCHIVES}/{name}")).unwrap();
        let members = rarkit_oracle::extract(&[&bytes], None)
            .unwrap_or_else(|e| panic!("{name}: the oracle: {e}"));
        for member in members.iter().filter(|member| !member.is_directory) {
            let called = std::str::from_utf8(&member.name).unwrap();
            assert_eq!(
                sha256_hex(&member.data),
                inputs[called],
                "{name}: {called} is not its input"
            );
        }
        let listed = format!("specs/vectors-J/archives/{name}");
        for row in rows.iter().filter(|row| row.archive == listed) {
            // A span is stated in its stream; the member's start in the
            // stream places it in the member's own bytes.
            let (transform, a, b) = match row.kind {
                StandardProgram::Delta => ("delta", row.sent(0), 0),
                StandardProgram::Audio => ("audio", row.sent(0), 0),
                StandardProgram::Rgb => ("rgb", row.sent(0) - 3, row.sent(1)),
                _ => continue,
            };
            let member = members
                .iter()
                .find(|member| member.name == row.member.as_bytes())
                .unwrap_or_else(|| panic!("{name}: no member {}", row.member));
            let from = (row.start - row.member_start) as usize;
            let span = member
                .data
                .get(from..from + row.len as usize)
                .unwrap_or_else(|| panic!("{name}: {} at {}: past the member", row.member, row.at));
            assert_inverse(transform, span, a, b);
            spans += 1;
        }
    }
    assert!(spans > 0, "no span was cut");
}

/// Delta decode written again, from section 3.7.1's words alone: the
/// filtered block is planar, plane `c` holds the bytes of channel `c` in
/// order, and original byte `i` is channel `i mod N`'s next running sum.
///
/// It is deliberately the slow, obvious spelling and it is not any of the
/// three paths it checks, so a mistake shared between them cannot hide.
fn delta_decode_from_the_words(src: &[u8], channels: usize) -> Vec<u8> {
    let n = src.len();
    if channels == 0 {
        return vec![0; n];
    }
    let mut planes: Vec<Vec<u8>> = Vec::with_capacity(channels);
    let mut at = 0;
    for c in 0..channels {
        let len = if c >= n {
            0
        } else {
            (n - c).div_ceil(channels)
        };
        planes.push(src[at.min(n)..(at + len).min(n)].to_vec());
        at += len;
    }
    let mut acc = vec![0u8; channels];
    let mut out = vec![0u8; n];
    let mut taken = vec![0usize; channels];
    for (i, o) in out.iter_mut().enumerate() {
        let c = i % channels;
        let byte = planes[c].get(taken[c]).copied().unwrap_or(0);
        taken[c] += 1;
        acc[c] = acc[c].wrapping_sub(byte);
        *o = acc[c];
    }
    out
}

/// Every channel count this package dispatches on, against the words.
///
/// The widths that matter here are the ones the arm list used to MISS:
/// before this change 2, 3, 4, 6 and 8 took the one pass row form and every
/// other count fell to the plane at a time form, including the 16 that
/// the `rar3_vm_1m` member of the bench asks for on all 32 of
/// its spans.
#[test]
fn delta_decode_answers_every_channel_count() {
    let mut source = rarkit_testdata::Seeded::new(0x6465_6c74);
    let mut next = || source.next_byte();
    // Lengths either side of a vector block (16 rows of 16 bytes = 256),
    // so the kernel's block loop, the rows it cannot reach and the last
    // partial row are all exercised.
    for n in [
        0, 1, 2, 15, 16, 17, 31, 255, 256, 257, 271, 4095, 4096, 32_768,
    ] {
        let src: Vec<u8> = (0..n).map(|_| next()).collect();
        for channels in 1..=40u32 {
            let want = delta_decode_from_the_words(&src, channels as usize);
            let mut got = vec![0u8; n];
            crate::rar3_filters::delta_decode(&src, &mut got, channels);
            assert!(
                got == want,
                "delta_decode: {n} bytes over {channels} channels differ at {:?}",
                got.iter().zip(&want).position(|(a, b)| a != b)
            );
        }
    }
}

/// The three paths agree with each other as well as with the words, which
/// is what lets `delta_decode` choose between them on speed alone.
#[test]
fn delta_paths_agree_on_every_width() {
    use crate::rar3_filters::transforms::{delta_planes_for_tests, delta_rows_for_tests};
    let mut source = rarkit_testdata::Seeded::new(0x726f_7773);
    let mut next = || source.next_byte();
    for n in [1, 16, 17, 255, 256, 257, 1000, 32_768] {
        let src: Vec<u8> = (0..n).map(|_| next()).collect();
        for channels in 2..=32u32 {
            let mut dispatched = vec![0u8; n];
            let mut rows = vec![0u8; n];
            let mut planes = vec![0u8; n];
            crate::rar3_filters::delta_decode(&src, &mut dispatched, channels);
            delta_rows_for_tests(&src, &mut rows, channels);
            delta_planes_for_tests(&src, &mut planes, channels);
            assert!(
                dispatched == rows,
                "{n} bytes, {channels} channels: what was dispatched differs from \
                 the scalar row form at {:?}",
                dispatched.iter().zip(&rows).position(|(a, b)| a != b)
            );
            assert!(
                rows == planes,
                "{n} bytes, {channels} channels: the row form differs from the \
                 plane at a time form at {:?}",
                rows.iter().zip(&planes).position(|(a, b)| a != b)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The record target's pinned seeds
// ---------------------------------------------------------------------------

/// The seeds of the fuzz target `rar3_filter_record`, one for each
/// archive of `specs/vectors-J/archives` that `genuine-records.tsv` has
/// records for, named by the archive's file name less `.rar`.
///
/// A seed is what the target reads: two bytes, the member's length in
/// units of 97 bytes, low byte first; then for each record one STEP byte,
/// which moves the position on by 97 times its value, and the record.
/// The target's positions are multiples of 97, which a genuine record's
/// position mostly is not, so a record keeps what the genuine writer
/// chose and is placed where the target can reach: its program, its
/// registers and its span's length are the table's, and it stands at
/// the first step at or past the end of the span before it. Its span
/// begins as far from it as the table's does; where one step byte (255
/// steps at most) cannot carry the record past the span before, the
/// span begins where that one ends and its offset is the longer for it.
/// An archive's streams follow one another in one seed, built by section
/// 3.9's rules through this package's builder.
fn record_seeds() -> Vec<(String, Vec<u8>)> {
    const STEP: u64 = 97;
    let rows = genuine_records();
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    let mut at = 0;
    while at < rows.len() {
        let archive = rows[at].archive;
        let mut builder = RecordBuilder::new();
        let (mut body, mut pos, mut reach) = (Vec::new(), 0u64, 0u64);
        while at < rows.len() && rows[at].archive == archive {
            let row = &rows[at];
            at += 1;
            let step = reach.saturating_sub(pos).div_ceil(STEP).min(255);
            pos += step * STEP;
            // No span begins inside the one before it.
            let start = (pos + (row.start - row.at)).max(reach);
            body.push(step as u8);
            body.extend(write(
                &mut builder,
                row.kind,
                start,
                row.len,
                pos,
                row.params(),
            ));
            reach = start + u64::from(row.len);
        }
        let Some(name) = archive
            .strip_prefix("specs/vectors-J/archives/")
            .and_then(|file| file.strip_suffix(".rar"))
        else {
            continue;
        };
        let units = reach.div_ceil(STEP).min(u64::from(u16::MAX)) as u16;
        let mut seed = units.to_le_bytes().to_vec();
        seed.extend(body);
        seeds.push((name.to_owned(), seed));
    }
    seeds
}

/// Every seed is a record stream the parser reads to its end, at the
/// positions its step bytes give. One thread, a few KiB.
#[test]
fn the_record_seeds_read_from_end_to_end() {
    let seeds = record_seeds();
    assert_eq!(seeds.len(), 14);
    for (name, seed) in &seeds {
        let mut state = new_state();
        let (mut src, mut pos) = (Bytes(&seed[2..]), 0u64);
        while let Some((&step, rest)) = src.0.split_first() {
            src.0 = rest;
            pos += u64::from(step) * 97;
            drain_due(&mut state, pos);
            state
                .parse(&mut src, pos, WIDE)
                .unwrap_or_else(|e| panic!("{name} at {pos}: {e:?}"));
        }
    }
}

/// Writes [`record_seeds`] under `fuzz/seeds/rar3_filter_record`, a file
/// a seed. Run by hand when the table changes:
/// `cargo test -p rarkit --features repo-tests
/// rar3_filters::tests::write_the_record_seeds -- --ignored`.
#[cfg(feature = "repo-tests")]
#[test]
#[ignore = "writes into fuzz/seeds; run by hand"]
fn write_the_record_seeds() {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/seeds/rar3_filter_record"
    );
    std::fs::create_dir_all(dir).unwrap();
    for (name, seed) in record_seeds() {
        std::fs::write(format!("{dir}/{name}"), seed).unwrap();
    }
}
