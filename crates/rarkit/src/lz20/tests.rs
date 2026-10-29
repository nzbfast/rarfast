//! Tests for the RAR 2.0 codec: spec H3 section 9.1's hand vectors, spec D
//! part 1's model vectors and spec D part 2's trailing switch matrix.

use super::audio::Model;
use super::bits::SliceBits;
use super::table::{self, Table};
use super::window::Window;
use super::*;
use crate::checksum::crc32;

// ---------------------------------------------------------------- helpers

/// One symbol's canonical code and its width.
type Code = (u32, u8);
/// The three LZ alphabets' codes, in the order a block reads them.
type LzCodes = (Vec<Code>, Vec<Code>, Vec<Code>);

/// A most significant bit first writer, which is how RAR lays its fields
/// down.
#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    bits: usize,
}

impl BitWriter {
    fn push(&mut self, value: u32, count: u8) {
        for index in (0..count).rev() {
            let bit = (value >> index) & 1;
            if self.bits.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if bit == 1 {
                let last = self.bytes.len() - 1;
                self.bytes[last] |= 1 << (7 - (self.bits % 8));
            }
            self.bits += 1;
        }
    }

    fn push_code(&mut self, code: Code) {
        self.push(code.0, code.1);
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    /// Bits written so far, which at a member's check point is what spec D
    /// section 2.2's `R` is measured from.
    fn bits(&self) -> usize {
        self.bits
    }

    /// Finish, then cut or pad the packed bytes so that a check at
    /// `check_bits` sees exactly `r` whole bytes left.
    fn finish_with_r(self, check_bits: usize, r: usize) -> Vec<u8> {
        let mut bytes = self.finish();
        bytes.resize(check_bits / 8 + r, 0xff);
        bytes
    }
}

/// Canonical codes for `lengths`, as spec D section 3.2.2 describes them:
/// symbols sorted by length then symbol number, codes consecutive, shorter
/// lengths first, the first code all zeros.
fn canonical(lengths: &[u8]) -> Vec<Code> {
    let mut codes = vec![(0u32, 0u8); lengths.len()];
    let mut code = 0u32;
    for length in 1..=table::MAX_CODE_LEN as u8 {
        for (symbol, &symbol_length) in lengths.iter().enumerate() {
            if symbol_length == length {
                codes[symbol] = (code, length);
                code += 1;
            }
        }
        code <<= 1;
    }
    codes
}

/// The level alphabet every hand vector below writes its code lengths
/// through: all nineteen symbols at five bits, which is an incomplete code
/// whose hole no vector reaches.
const LEVEL_WIDTH: u8 = 5;

/// Write a block's code lengths: the nineteen four bit level fields, then
/// one level symbol per position. The stored array is zero (the keep bit is
/// clear in every vector here), so the value emitted for a position is the
/// length wanted there.
fn write_lengths(out: &mut BitWriter, lengths: &[u8]) {
    for _ in 0..19 {
        out.push(u32::from(LEVEL_WIDTH), 4);
    }
    let level = canonical(&[LEVEL_WIDTH; 19]);
    for &length in lengths {
        assert!(length < 16);
        out.push_code(level[length as usize]);
    }
}

/// The three LZ alphabets' code lengths, laid out as an LZ block reads
/// them: main, then distance, then length.
struct LzTables {
    main: [u8; MAIN_SYMBOLS],
    distance: [u8; DISTANCE_SLOTS],
    length: [u8; LENGTH_SLOTS],
}

impl LzTables {
    /// Tables in which every symbol named in `main` gets a code, and every
    /// distance and length slot does: a vector names the main symbols it
    /// means, and never has to work out which ladder slot a distance falls
    /// in before it can write the table.
    fn over(main: &[u16]) -> LzTables {
        let slots: Vec<u16> = (0..DISTANCE_SLOTS as u16).collect();
        let lengths: Vec<u16> = (0..LENGTH_SLOTS as u16).collect();
        LzTables {
            main: flat(main),
            distance: flat(&slots),
            length: flat(&lengths),
        }
    }

    fn codes(&self) -> LzCodes {
        (
            canonical(&self.main),
            canonical(&self.distance),
            canonical(&self.length),
        )
    }

    fn write(&self, out: &mut BitWriter) {
        let mut lengths = Vec::new();
        lengths.extend_from_slice(&self.main);
        lengths.extend_from_slice(&self.distance);
        lengths.extend_from_slice(&self.length);
        write_lengths(out, &lengths);
    }
}

/// A flat code over `used`: every named symbol at the same width, which is
/// complete when the count is a power of two and incomplete otherwise.
fn flat<const N: usize>(used: &[u16]) -> [u8; N] {
    let mut lengths = [0u8; N];
    if used.is_empty() {
        return lengths;
    }
    let width = (usize::BITS - (used.len() - 1).leading_zeros()).max(1) as u8;
    for &symbol in used {
        lengths[symbol as usize] = width;
    }
    lengths
}

/// Write an LZ block header with the keep bit clear.
fn lz_header(out: &mut BitWriter) {
    out.push(0, 1);
    out.push(0, 1);
}

/// Write a multimedia block header with the keep bit clear.
fn mm_header(out: &mut BitWriter, channels: usize) {
    out.push(1, 1);
    out.push(0, 1);
    out.push(channels as u32 - 1, 2);
}

/// The distance slot and extra bits that name `distance` exactly.
fn distance_fields(distance: u32) -> (usize, u32, u8) {
    for slot in (0..DISTANCE_SLOTS).rev() {
        let base = DISTANCE_BASE[slot] + 1;
        if distance >= base {
            let extra = distance - base;
            assert!(
                u64::from(extra) < 1u64 << DISTANCE_EXTRA[slot],
                "distance {distance} does not fit slot {slot}"
            );
            return (slot, extra, DISTANCE_EXTRA[slot]);
        }
    }
    panic!("distance {distance} is below the ladder");
}

/// Decode one member's worth of a stream, driving the decoder the way spec
/// F's extract path will: begin a block when none is in force, run, drain.
fn decode(packed: &[u8], capacity: u32, wanted: u64) -> Result<Vec<u8>> {
    let mut decoder = Rar20Lz::new();
    let mut window = Window::new(capacity);
    let mut input = SliceBits::new(packed);
    let out = run_member(&mut decoder, &mut input, &mut window, wanted)?;
    Ok(out)
}

/// Produce `wanted` bytes of one member through an existing decoder, so a
/// solid chain can run two members through one object.
fn run_member(
    decoder: &mut Rar20Lz,
    input: &mut SliceBits<'_>,
    window: &mut Window,
    wanted: u64,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while (out.len() as u64) < wanted {
        if !decoder.codes_stand() {
            decoder.begin_block(input)?;
        }
        let room = (wanted - out.len() as u64).min(window.room() as u64);
        let step = decoder.run(input, window, room)?;
        let (first, second) = window.pending();
        out.extend_from_slice(first);
        out.extend_from_slice(second);
        let taken = window.held_bytes();
        window.take(taken);
        if step == Lz20Step::BlockEnded && (out.len() as u64) < wanted {
            continue;
        }
    }
    Ok(out)
}

// ------------------------------------------------- spec D part 1 vectors

/// Run `residuals` through a fresh model over `channels`, then check the
/// encode direction reproduces them from the bytes.
fn model_round_trip(channels: usize, residuals: &[u8]) -> Vec<u8> {
    let mut model = Model::fresh();
    let mut out = Vec::with_capacity(residuals.len());
    for (index, &residual) in residuals.iter().enumerate() {
        out.push(model.residual_to_byte(index % channels, residual));
    }
    let mut back = Model::fresh();
    let again: Vec<u8> = out
        .iter()
        .enumerate()
        .map(|(index, &byte)| back.byte_to_residual(index % channels, byte))
        .collect();
    assert_eq!(again, residuals, "the encode direction must invert exactly");
    out
}

#[test]
fn audio_vector_v1_is_a_unit_ramp() {
    let out = model_round_trip(1, &[0xff; 40]);
    let expected: Vec<u8> = (1..=40).collect();
    assert_eq!(out, expected);
}

#[test]
fn audio_vector_v2_turns_at_the_first_adaptation() {
    let residuals: Vec<u8> = [0xfe, 0x02].iter().cycle().take(40).copied().collect();
    let out = model_round_trip(1, &residuals);
    let mut expected = vec![];
    for _ in 0..16 {
        expected.extend_from_slice(&[0x02, 0x00]);
    }
    expected.extend_from_slice(&[0x02, 0xff, 0x01, 0xfe, 0x00, 0xfd, 0xff, 0xfc]);
    assert_eq!(out, expected);
}

#[test]
fn audio_vector_v3_matches_the_specified_bytes() {
    let residuals: Vec<u8> = (0..40u32).map(|i| ((37 * i + 11) % 256) as u8).collect();
    let out = model_round_trip(1, &residuals);
    let expected = [
        0xf5, 0xc5, 0x70, 0xf6, 0x57, 0x93, 0xaa, 0x9c, 0x69, 0x11, 0x94, 0xf2, 0x2b, 0x3f, 0x2e,
        0xf8, 0x9d, 0x1d, 0x78, 0xae, 0xbf, 0xab, 0x72, 0x14, 0x91, 0xe9, 0x1c, 0x2a, 0x13, 0xd7,
        0x76, 0xf0, 0x60, 0x8e, 0x90, 0x70, 0x2c, 0xc3, 0x35, 0xa2,
    ];
    assert_eq!(out, expected);
}

#[test]
fn audio_vector_v4_runs_two_channels() {
    let residuals: Vec<u8> = [0xff, 0x01].iter().cycle().take(68).copied().collect();
    let out = model_round_trip(2, &residuals);
    let expected = [
        0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x05, 0xfb, 0x06, 0xfa, 0x07, 0xf9, 0x08,
        0xf8, 0x09, 0xf7, 0x0a, 0xf6, 0x0b, 0xf5, 0x0c, 0xf4, 0x0d, 0xf3, 0x0e, 0xf2, 0x0f, 0xf1,
        0x10, 0xf0, 0x11, 0xef, 0x12, 0xee, 0x13, 0xed, 0x14, 0xec, 0x15, 0xeb, 0x16, 0xea, 0x17,
        0xe9, 0x18, 0xe8, 0x19, 0xe7, 0x1a, 0xe6, 0x1b, 0xe5, 0x1c, 0xe4, 0x1d, 0xe3, 0x1e, 0xe2,
        0x1f, 0xe1, 0x20, 0xe0, 0x21, 0xde, 0x22, 0xdc,
    ];
    assert_eq!(out, expected);
}

#[test]
fn audio_vector_tie_resolves_to_the_lowest_index() {
    let residuals: Vec<u8> = [0x01, 0x00].iter().cycle().take(64).copied().collect();
    let out = model_round_trip(1, &residuals);
    let mut expected = Vec::new();
    for step in 0..32u32 {
        let value = (0xffu32.wrapping_sub(step)) as u8;
        expected.push(value);
        expected.push(value);
    }
    assert_eq!(out, expected);
}

#[test]
fn audio_vector_c1_holds_the_weight_floor_at_minus_seventeen() {
    let residuals: Vec<u8> = [0xc0, 0xfc, 0x80]
        .iter()
        .cycle()
        .take(2048)
        .copied()
        .collect();
    let out = model_round_trip(1, &residuals);
    assert_eq!(crc32(&out), 0x5552_116b);
    assert_eq!(&out[..8], &[0x40, 0x44, 0xc4, 0x04, 0x08, 0x88, 0xc8, 0xcc]);
    assert_eq!(
        &out[out.len() - 8..],
        &[0xe4, 0x24, 0x17, 0x69, 0xca, 0x7d, 0x4a, 0xbd]
    );
}

#[test]
fn audio_vector_c2_holds_the_weight_ceiling_at_sixteen() {
    let residuals: Vec<u8> = [0x7f, 0x7f, 0x40]
        .iter()
        .cycle()
        .take(2048)
        .copied()
        .collect();
    let out = model_round_trip(1, &residuals);
    assert_eq!(crc32(&out), 0x63e1_072d);
    assert_eq!(&out[..8], &[0x81, 0x02, 0xc2, 0x43, 0xc4, 0x84, 0x05, 0x86]);
    assert_eq!(
        &out[out.len() - 8..],
        &[0xdb, 0xa0, 0x10, 0x71, 0x60, 0xf6, 0x2b, 0x2f]
    );
}

#[test]
fn audio_vector_v7_runs_four_channels() {
    let mut x: u64 = 12345;
    let residuals: Vec<u8> = (0..8192)
        .map(|_| {
            x = (1103515245u64.wrapping_mul(x).wrapping_add(12345)) % (1u64 << 31);
            ((x / 65536) % 256) as u8
        })
        .collect();
    assert_eq!(crc32(&residuals), 0x43f5_2e59);
    assert_eq!(
        &residuals[..8],
        &[0xdc, 0x04, 0x65, 0xaa, 0x1f, 0xad, 0x1d, 0x5a]
    );
    let out = model_round_trip(4, &residuals);
    assert_eq!(crc32(&out), 0x78f8_40af);
    assert_eq!(&out[..8], &[0x24, 0xfc, 0x9b, 0x56, 0x05, 0x4f, 0x7e, 0xfc]);
}

/// THE NARROW LANE'S BOUND, driven at the worst case the format allows.
///
/// Spec D 1.4.2's headroom argument is the whole reason `Acc` may be a
/// `u16` on x86-64, and this is the vector that holds the two lane widths
/// to each other. `sx(r)` is `r` read as a signed byte, so residuals kept
/// to the four values around its extremes drive `e = 8 * sx(r)` to within
/// eight of its own extremes on EVERY sample, which is the case the
/// bound is computed for; four channels and 40,000 samples give each
/// channel 312 adaptation windows at that level.
///
/// The CRC below was computed on the WIDE form, on aarch64. A narrow
/// target that disagrees by one byte fails here, which is what makes the
/// `cfg(target_arch)` gate in `lz20::audio` a checked claim rather than
/// an argument. The round trip inside `model_round_trip` checks the
/// encode direction on the same stream.
#[test]
fn audio_the_narrow_lane_bound_holds_at_its_worst_case() {
    let mut x: u64 = 987_654_321;
    let hot: Vec<u8> = (0..40_000)
        .map(|_| {
            x = (1103515245u64.wrapping_mul(x).wrapping_add(12345)) % (1u64 << 31);
            // 0x7e, 0x7f, 0x80, 0x81: sx is 126, 127, -128, -127, so
            // |e| is at least 1016 of its 1024 maximum on every sample.
            [0x7e, 0x7f, 0x80, 0x81][((x >> 16) % 4) as usize]
        })
        .collect();
    assert_eq!(crc32(&hot), 0x3155_c76d);
    let out = model_round_trip(4, &hot);
    assert_eq!(crc32(&out), 0x2f09_765f);
}

// ------------------------------------------------ spec H3 hand vectors

/// A test side model of what the symbols MEAN, used to say what a stream
/// must decode to without asking the decoder. Distances and lengths here
/// are the effective ones, after the length bonus the vector is pinning.
enum Op {
    Literal(u8),
    Copy { distance: u32, length: u32 },
}

fn apply(ops: &[Op]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for op in ops {
        match *op {
            Op::Literal(byte) => out.push(byte),
            Op::Copy { distance, length } => {
                for _ in 0..length {
                    let byte = out[out.len() - distance as usize];
                    out.push(byte);
                }
            }
        }
    }
    out
}

/// Write a run of `count` zero code lengths with the long zero run symbol,
/// which carries 11 + 7 bits, and the short one, which carries 3 + 3.
fn write_zero_run(out: &mut BitWriter, level: &[Code], mut count: usize) {
    while count > 0 {
        if count >= 11 {
            let take = count.min(11 + 127);
            out.push_code(level[18]);
            out.push((take - 11) as u32, 7);
            count -= take;
        } else if count >= 3 {
            let take = count.min(3 + 7);
            out.push_code(level[17]);
            out.push((take - 3) as u32, 3);
            count -= take;
        } else {
            out.push_code(level[0]);
            count -= 1;
        }
    }
}

#[test]
fn v20_level_reads_two_bits_after_the_repeat_symbol() {
    // The three differences from RAR 2.9, all silent if got wrong: the
    // alphabet is 19 and not 20, symbol 16 carries 2 bits and not 3, and
    // 17 and 18 are short and long ZERO runs rather than repeats.
    let mut out = BitWriter::default();
    lz_header(&mut out);
    for _ in 0..19 {
        out.push(u32::from(LEVEL_WIDTH), 4);
    }
    let level = canonical(&[LEVEL_WIDTH; 19]);
    // Main symbols 65 to 68 and 269 at three bits: an incomplete code,
    // which a strict table builds and only refuses in its hole.
    write_zero_run(&mut out, &level, 65);
    out.push_code(level[3]);
    // The repeat symbol, with the 2 bit count RAR 2.0 uses: three more
    // positions take the length just written, so 66, 67 and 68 are 3.
    out.push_code(level[16]);
    out.push(0, 2);
    // A short zero run, whose count is 3 bits.
    write_zero_run(&mut out, &level, 3);
    write_zero_run(&mut out, &level, 197);
    out.push_code(level[3]);
    write_zero_run(&mut out, &level, LZ_LENGTHS - 270);

    let mut main = [0u8; MAIN_SYMBOLS];
    for symbol in [65usize, 66, 67, 68, 269] {
        main[symbol] = 3;
    }
    let codes = canonical(&main);
    out.push_code(codes[65]);
    out.push_code(codes[68]);
    out.push_code(codes[66]);
    out.push_code(codes[269]);

    let packed = out.finish();
    let decoded = decode(&packed, 65_536, 3).expect("the level table reads back");
    assert_eq!(decoded, b"ADB");
}

/// Build a member that fills the window with one literal and a run of
/// maximum length matches, so a far distance is reachable, then runs
/// `tail` symbols. Returns the packed bytes and the filler's length.
fn far_window(tail: impl FnOnce(&mut BitWriter, &LzCodes)) -> (Vec<u8>, usize) {
    // Main: literal 65, a fresh match at length slot 27 for the filler and
    // at slot 0 for the vector itself, the repeated distance arm k = 0,
    // and the block end.
    let tables = LzTables::over(&[65, 257, 269, 270, 297]);
    let mut out = BitWriter::default();
    lz_header(&mut out);
    tables.write(&mut out);
    let codes = tables.codes();
    out.push_code(codes.0[65]);
    // Each match copies the longest run the ladder can name, at distance
    // one, so the window fills with the same byte.
    const FILLERS: usize = 1017;
    for _ in 0..FILLERS {
        out.push_code(codes.0[297]);
        out.push(31, LENGTH_EXTRA[LENGTH_SLOTS - 1]);
        let (slot, extra, width) = distance_fields(1);
        out.push_code(codes.1[slot]);
        out.push(extra, width);
    }
    tail(&mut out, &codes);
    out.push_code(codes.0[269]);
    (out.finish(), 1 + FILLERS * 258)
}

#[test]
fn v20_bonus_is_asymmetric_between_the_fresh_and_repeated_arms() {
    // Spec H3 section 3.3: the fresh arm has two distance thresholds and
    // the repeated arm three, which is the opposite way round from RAR 5.
    // The expected gains are the specification's own, written out rather
    // than taken from the decoder's rule.
    let cases = [
        (0x100u32, 0u32, 0u32),
        (0x101, 0, 1),
        (0x1fff, 0, 1),
        (0x2000, 1, 2),
        (0x3ffff, 1, 2),
        (0x40000, 2, 3),
    ];
    for (distance, fresh_gain, repeat_gain) in cases {
        let (packed, filler) = far_window(|out, codes| {
            // A fresh match at the shortest slot: length 3 before the
            // bonus. It also pushes the distance, so the repeated arm
            // below names the same one.
            out.push_code(codes.0[270]);
            out.push(0, LENGTH_EXTRA[0]);
            let (slot, extra, width) = distance_fields(distance);
            out.push_code(codes.1[slot]);
            out.push(extra, width);
            // The repeated distance arm, k = 0: length 2 before the bonus.
            out.push_code(codes.0[257]);
            out.push_code(codes.2[0]);
            out.push(0, LENGTH_EXTRA[0]);
        });
        let fresh_length = 3 + fresh_gain;
        let repeat_length = 2 + repeat_gain;
        let expected = apply(&[
            Op::Literal(65),
            Op::Copy {
                distance: 1,
                length: (filler - 1) as u32,
            },
            Op::Copy {
                distance,
                length: fresh_length,
            },
            Op::Copy {
                distance,
                length: repeat_length,
            },
        ]);
        let wanted = expected.len() as u64;
        let decoded = decode(&packed, 1 << 20, wanted).expect("the bonus vector decodes");
        assert_eq!(
            decoded.len() as u64,
            wanted,
            "distance {distance:#x}: fresh {fresh_length}, repeated {repeat_length}"
        );
        assert_eq!(decoded, expected, "distance {distance:#x}");
    }
}

#[test]
fn v20_push_records_the_distance_symbol_256_repeats() {
    // Main symbol 256 repeats the last match AND pushes its distance,
    // which RAR 2.9's symbol 258 does not. Without the push the repeated
    // distance named below would still be zero, which is refused.
    let tables = LzTables::over(&[65, 66, 256, 259, 270, 269]);
    let mut out = BitWriter::default();
    lz_header(&mut out);
    tables.write(&mut out);
    let codes = tables.codes();
    for _ in 0..8 {
        out.push_code(codes.0[65]);
    }
    for _ in 0..8 {
        out.push_code(codes.0[66]);
    }
    // A fresh match at distance 16, length 3: repeated distances become
    // [16, 0, 0, 0].
    let far = 16u32;
    out.push_code(codes.0[270]);
    out.push(0, LENGTH_EXTRA[0]);
    let (slot, extra, width) = distance_fields(far);
    out.push_code(codes.1[slot]);
    out.push(extra, width);
    // A fresh match at distance 1, length 3: [1, 16, 0, 0].
    let near = 1u32;
    out.push_code(codes.0[270]);
    out.push(0, LENGTH_EXTRA[0]);
    let (slot, extra, width) = distance_fields(near);
    out.push_code(codes.1[slot]);
    out.push(extra, width);
    // Symbol 256: repeat that match, pushing again, so [1, 1, 16, 0].
    out.push_code(codes.0[256]);
    // Repeated distance k = 2, which is 16 only because 256 pushed.
    out.push_code(codes.0[259]);
    out.push_code(codes.2[0]);
    out.push(0, LENGTH_EXTRA[0]);
    out.push_code(codes.0[269]);

    let packed = out.finish();
    let mut ops = vec![];
    for _ in 0..8 {
        ops.push(Op::Literal(65));
    }
    for _ in 0..8 {
        ops.push(Op::Literal(66));
    }
    ops.push(Op::Copy {
        distance: far,
        length: 3,
    });
    ops.push(Op::Copy {
        distance: near,
        length: 3,
    });
    ops.push(Op::Copy {
        distance: near,
        length: 3,
    });
    // Distance 16 is under 0x101, so the repeated arm gains nothing.
    ops.push(Op::Copy {
        distance: far,
        length: 2,
    });
    let expected = apply(&ops);
    let decoded = decode(&packed, 65_536, expected.len() as u64).expect("the push vector decodes");
    assert_eq!(decoded, expected);
}

#[test]
fn v20_strict_refuses_an_oversubscribed_table_at_build() {
    let mut table = Table::new(8);
    // Four one bit codes: a Kraft sum of two.
    let err = table.build(&[1, 1, 1, 1, 0, 0, 0, 0]).unwrap_err();
    assert!(matches!(
        err.kind(),
        ErrorKind::Corrupt(Corruption::Rar20(Rar20Fault::Oversubscribed))
    ));
}

/// The first 15 bits of a two byte input, as a table reads them.
fn fifteen(value: u16) -> [u8; 2] {
    (value << 1).to_be_bytes()
}

#[test]
fn spec_h3_3_2_t2_a_value_no_codeword_owns_takes_15_bits_and_gives_symbol_0_or_the_first_ranked() {
    let mut table = Table::new(8);
    // One symbol, number 2, of two bits: it owns the first 8,192 of the
    // 32,768 values, so T is 8,192, m is 1 and n is 8.
    table.build(&[0, 0, 2, 0, 0, 0, 0, 0]).expect("builds");
    let owned = fifteen(8191);
    let mut input = SliceBits::new(&owned);
    assert_eq!(table.decode(&mut input).expect("the codeword"), 2);
    assert_eq!(input.available(), 14);
    // k = m + (v - T): 1 at the first unowned value and 7 six on, both
    // under n, so symbol 0; 8 at the next and at the last value of all,
    // so the first ranked symbol.
    for (value, symbol) in [(8192, 0), (8198, 0), (8199, 2), (32767, 2)] {
        let packed = fifteen(value);
        let mut input = SliceBits::new(&packed);
        assert_eq!(table.decode(&mut input).expect("T2"), symbol, "{value}");
        assert_eq!(input.available(), 1, "15 bits are consumed at {value}");
    }
    // Fewer than 15 bits left: a symbol that begins inside the input is
    // read whole, the bits past the end as zeros (section 3.5). Eight one
    // bits and seven zeros are the value 32,640, past the seven values
    // that give symbol 0, so the first ranked symbol; all 15 bits are
    // consumed, seven of them from past the end.
    let mut input = SliceBits::new(&[0xff]);
    assert_eq!(table.decode(&mut input).expect("read whole"), 2);
    assert_eq!(input.available(), 0);
    assert!(input.past_end());
}

#[test]
fn spec_h3_3_2_t2_an_all_zero_table_gives_symbol_0_for_every_15_bits() {
    let mut table = Table::new(8);
    table.build(&[0; 8]).expect("an all zero list builds");
    assert!(!table.is_used());
    for value in [0, 7, 8, 0x5a5a >> 1, 32767] {
        let packed = fifteen(value);
        let mut input = SliceBits::new(&packed);
        assert_eq!(table.decode(&mut input).expect("T2"), 0, "{value}");
        assert_eq!(input.available(), 1);
    }
}

#[test]
fn spec_h3_3_2_leaves_open_t2_on_the_level_table_and_this_decoder_refuses_there() {
    // The read the code length alphabet's own table is given: a value no
    // codeword owns, and every value of an all zero list, is refused.
    let mut table = Table::new(19);
    let mut lengths = [0u8; 19];
    lengths[3] = 2;
    table.build(&lengths).expect("builds");
    let owned = fifteen(8191);
    let mut input = SliceBits::new(&owned);
    assert_eq!(table.decode_owned(&mut input).expect("the codeword"), 3);
    for (lengths, value) in [(lengths, 8192), (lengths, 32767), ([0u8; 19], 0)] {
        table.build(&lengths).expect("builds");
        let packed = fifteen(value);
        let mut input = SliceBits::new(&packed);
        let err = table.decode_owned(&mut input).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                ErrorKind::Corrupt(Corruption::Rar20(Rar20Fault::InvalidCode))
            ),
            "{value}"
        );
    }
}

/// One multimedia channel's code lengths: every named symbol at the same
/// width, the terminator among them.
fn audio_lengths(used: &[u16]) -> [u8; AUDIO_SYMBOLS] {
    flat(used)
}

/// Write a multimedia block's header and the code lengths of its
/// `channels` alphabets, laid out one after another.
fn mm_block(out: &mut BitWriter, alphabets: &[[u8; AUDIO_SYMBOLS]]) -> Vec<Vec<Code>> {
    mm_header(out, alphabets.len());
    let mut lengths = Vec::new();
    for alphabet in alphabets {
        lengths.extend_from_slice(alphabet);
    }
    write_lengths(out, &lengths);
    alphabets.iter().map(|a| canonical(a)).collect()
}

#[test]
fn v20_chan_resumes_the_channel_an_earlier_block_stopped_on() {
    // Spec H3 section 3.1: an LZ header leaves the current channel index
    // alone, which is observable when a later multimedia block resumes on
    // it. Spec D part 2's vector S5 pins exactly this.
    let first = audio_lengths(&[5, 256]);
    let second = audio_lengths(&[7, 256]);
    let mut out = BitWriter::default();

    // A multimedia block over two channels: one residual on channel 0,
    // which leaves the index on channel 1, then the terminator from
    // channel 1's own alphabet.
    let codes = mm_block(&mut out, &[first, second]);
    out.push_code(codes[0][5]);
    out.push_code(codes[1][256]);

    // An LZ block of one literal. It touches neither the channel index nor
    // the predictor.
    let tables = LzTables::over(&[90, 269]);
    lz_header(&mut out);
    tables.write(&mut out);
    let lz = tables.codes();
    out.push_code(lz.0[90]);
    out.push_code(lz.0[269]);

    // A second multimedia block over two channels. Its first symbol is
    // read from channel 1's alphabet, where these bits mean residual 7; on
    // channel 0 they would mean residual 5 and a different output byte.
    let codes = mm_block(&mut out, &[first, second]);
    out.push_code(codes[1][7]);
    out.push_code(codes[0][256]);

    let packed = out.finish();
    let decoded = decode(&packed, 65_536, 3).expect("the channel vector decodes");

    let mut model = Model::fresh();
    let expected = vec![
        model.residual_to_byte(0, 5),
        90,
        model.residual_to_byte(1, 7),
    ];
    assert_eq!(decoded, expected);
}

#[test]
fn a_multimedia_block_writes_the_window_a_later_match_reaches_into() {
    // Section 3.4: there are no matches in a multimedia block, but the
    // window is still written, so a later LZ block can match into bytes
    // the predictor produced.
    let alphabet = audio_lengths(&[9, 256]);
    let mut out = BitWriter::default();
    let codes = mm_block(&mut out, &[alphabet]);
    for _ in 0..4 {
        out.push_code(codes[0][9]);
    }
    out.push_code(codes[0][256]);

    let tables = LzTables::over(&[270, 269]);
    lz_header(&mut out);
    tables.write(&mut out);
    let lz = tables.codes();
    // A fresh match of length 3 at distance 4 reaches back into the four
    // bytes the predictor produced.
    out.push_code(lz.0[270]);
    out.push(0, LENGTH_EXTRA[0]);
    let (slot, extra, width) = distance_fields(4);
    out.push_code(lz.1[slot]);
    out.push(extra, width);
    out.push_code(lz.0[269]);

    let packed = out.finish();
    let decoded = decode(&packed, 65_536, 7).expect("the window vector decodes");

    let mut model = Model::fresh();
    let mut expected: Vec<u8> = (0..4).map(|_| model.residual_to_byte(0, 9)).collect();
    for index in 0..3 {
        expected.push(expected[index]);
    }
    assert_eq!(decoded, expected);
}

#[test]
fn a_multimedia_block_wraps_the_ring_and_produces_the_same_bytes() {
    // Section 3.4's bytes go into the window through a CONTIGUOUS RUN at
    // the write point, and the ring's end cuts that run short. This pins
    // the cut, which needs the write point OFF ZERO when the multimedia
    // block starts: an LZ block emits two literals into a four byte
    // window first, so the run of six that follows is served as two of
    // two, two and two, wrapping twice.
    //
    // A run that ignored the ring's end here would ask for a slice past
    // it, and one that ignored the room asked for would overwrite a byte
    // the caller has not drained.
    let tables = LzTables::over(&[65, 66, 269]);
    let mut out = BitWriter::default();
    lz_header(&mut out);
    tables.write(&mut out);
    let lz = tables.codes();
    out.push_code(lz.0[65]);
    out.push_code(lz.0[66]);
    out.push_code(lz.0[269]);

    let alphabet = audio_lengths(&[11, 256]);
    let codes = mm_block(&mut out, &[alphabet]);
    for _ in 0..6 {
        out.push_code(codes[0][11]);
    }
    out.push_code(codes[0][256]);

    let packed = out.finish();
    let decoded = decode(&packed, 4, 8).expect("the wrapping vector decodes");

    let mut model = Model::fresh();
    let mut expected = vec![b'A', b'B'];
    expected.extend((0..6).map(|_| model.residual_to_byte(0, 11)));
    assert_eq!(decoded, expected);
}

// ------------------------------- spec D part 2, the trailing table switch

/// Two members through one decoder, which is what a solid chain gives the
/// RAR 2.0 codec: the bit stream restarts per member, the decoder's state
/// does not.
struct Chain {
    decoder: Rar20Lz,
    window: Window,
}

impl Chain {
    fn new() -> Chain {
        Chain {
            decoder: Rar20Lz::new(),
            window: Window::new(65_536),
        }
    }

    fn member(&mut self, packed: &[u8], wanted: u64) -> Result<Vec<u8>> {
        let mut input = SliceBits::new(packed);
        let out = run_member(&mut self.decoder, &mut input, &mut self.window, wanted)?;
        self.decoder.finish_member(&mut input)?;
        Ok(out)
    }
}

/// Member one of every vector below: an LZ block over two literals, then
/// `count` of the first of them. Returns the packed bytes, cut so that the
/// check sees `r` whole bytes, and the codes, so a caller can write a
/// terminator and a trailing table first.
fn member_one(
    count: usize,
    r: Option<usize>,
    trailer: impl FnOnce(&mut BitWriter, &LzCodes),
) -> Vec<u8> {
    let tables = LzTables::over(&[65, 66, 269]);
    let mut out = BitWriter::default();
    lz_header(&mut out);
    tables.write(&mut out);
    let codes = tables.codes();
    for _ in 0..count {
        out.push_code(codes.0[65]);
    }
    let check = out.bits();
    trailer(&mut out, &codes);
    match r {
        Some(r) => out.finish_with_r(check, r),
        None => out.finish(),
    }
}

#[test]
fn s1_takes_a_trailing_table_switch_into_a_multimedia_block() {
    // The packed data of one member may end with a block terminator
    // followed by the tables of the NEXT member's first block, and they
    // must be picked up here because the next member's data starts with
    // coded symbols, not tables.
    let alphabet = audio_lengths(&[0, 256]);
    let mut audio = Vec::new();
    let first = member_one(4, None, |out, codes| {
        out.push_code(codes.0[269]);
        audio = mm_block(out, &[alphabet]);
    });

    let mut second = BitWriter::default();
    for _ in 0..3 {
        second.push_code(audio[0][0]);
    }
    let second = second.finish();

    let mut chain = Chain::new();
    assert_eq!(chain.member(&first, 4).expect("member one"), b"AAAA");
    // A fresh model turns residual 0 into byte 0, so the switch is visible
    // as three zero bytes where an LZ reading would give something else.
    assert_eq!(chain.member(&second, 3).expect("member two"), [0, 0, 0]);
}

/// Three codes for `B` under member one's tables: what member two is when
/// it carries on in the old block.
fn three_bs() -> Vec<u8> {
    let codes = LzTables::over(&[65, 66, 269]).codes();
    let mut second = BitWriter::default();
    for _ in 0..3 {
        second.push_code(codes.0[66]);
    }
    second.finish()
}

#[test]
fn s2_a_trailing_read_that_runs_out_does_not_fail_its_member() {
    // R = 5 is at the threshold, so the read is begun (SPEC-D 2.2, O4):
    // the one bits after the terminator name a multimedia block and its
    // tables do not read. Member one is complete before the read and is
    // whole (O5); member two is refused (rule 3), where S3 decodes it.
    let first = member_one(4, Some(5), |out, codes| {
        out.push_code(codes.0[269]);
        // Ones from the bit after the terminator on, not from the next
        // whole byte: the cut below leaves five bytes of them.
        for _ in 0..6 {
            out.push(0xff, 8);
        }
    });
    let mut chain = Chain::new();
    assert_eq!(chain.member(&first, 4).expect("member one"), b"AAAA");
    assert!(chain.member(&three_bs(), 3).is_err());
}

/// SPEC-D 2.2 rule 3 and vector S9: a tail read that does not complete
/// leaves the member carrying it whole, and no later member of that solid
/// chain is decoded: each is refused with the fault the read met. This is
/// stricter than the reference, which goes on under the state O7 records;
/// that state is not reproduced. Two tails at every R from 5 to 16: a
/// switch to other LZ tables that the packed data ends inside
/// (`Truncated`), and zero bits, which run out or give an empty code
/// length alphabet (`InvalidCode`) by how many there are.
#[test]
fn s9_a_tail_read_that_does_not_complete_refuses_every_later_member() {
    for r in 5..=16 {
        let cut_switch = member_one(4, Some(r), |out, codes| {
            out.push_code(codes.0[269]);
            lz_header(out);
            LzTables::over(&[66, 67, 269]).write(out);
        });
        let zeros = member_one(4, Some(r), |out, codes| {
            out.push_code(codes.0[269]);
            for _ in 0..20 {
                out.push(0, 8);
            }
        });
        for (name, first, cut) in [("a cut switch", cut_switch, true), ("zeros", zeros, false)] {
            let mut chain = Chain::new();
            assert_eq!(chain.member(&first, 4).expect("member one"), b"AAAA");
            // Member two, and member three after it: what would have
            // carried on in the old block, and what opens with tables of
            // its own.
            let mut own = BitWriter::default();
            lz_header(&mut own);
            let tables = LzTables::over(&[67, 68, 269]);
            tables.write(&mut own);
            own.push_code(tables.codes().0[68]);
            for later in [three_bs(), own.finish()] {
                let err = chain.member(&later, 1).expect_err("a later member");
                let ran_out = matches!(err.kind(), ErrorKind::Truncated);
                let no_code = matches!(
                    err.kind(),
                    ErrorKind::Corrupt(Corruption::Rar20(Rar20Fault::InvalidCode))
                );
                // The switch is always cut inside its lengths. The zeros
                // run out inside the header's nineteen four bit fields
                // while too few bytes are left, and past that give an
                // empty code length alphabet, as at the longest tail here.
                let as_the_read_failed = if cut {
                    ran_out
                } else if r == 16 {
                    no_code
                } else {
                    ran_out || no_code
                };
                assert!(as_the_read_failed, "{name}, R = {r}: {err:?}");
            }
        }
    }
}

#[test]
fn s3_skips_the_trailing_read_below_the_threshold() {
    // R = 4 is below it, so nothing is read at all and the decoder stays
    // inside the block it was in. Member two carries on with the same
    // tables, in the same block.
    let first = member_one(4, Some(4), |out, codes| {
        out.push_code(codes.0[269]);
    });
    let mut chain = Chain::new();
    assert_eq!(chain.member(&first, 4).expect("member one"), b"AAAA");

    let tables = LzTables::over(&[65, 66, 269]);
    let codes = tables.codes();
    let mut second = BitWriter::default();
    for _ in 0..3 {
        second.push_code(codes.0[66]);
    }
    let second = second.finish();
    assert_eq!(chain.member(&second, 3).expect("member two"), b"BBB");
}

#[test]
fn s4_ignores_a_trailing_symbol_that_is_not_the_terminator() {
    // R is over the threshold and the next code is a literal: it is read,
    // it changes nothing, and member two continues in the old block.
    let first = member_one(4, Some(9), |out, codes| {
        out.push_code(codes.0[66]);
    });
    let mut chain = Chain::new();
    assert_eq!(chain.member(&first, 4).expect("member one"), b"AAAA");

    let tables = LzTables::over(&[65, 66, 269]);
    let codes = tables.codes();
    let mut second = BitWriter::default();
    for _ in 0..3 {
        second.push_code(codes.0[66]);
    }
    let second = second.finish();
    assert_eq!(chain.member(&second, 3).expect("member two"), b"BBB");
}

#[test]
fn s6_reads_nothing_when_the_active_table_has_no_symbols() {
    // A multimedia block over two channels whose second alphabet is all
    // zero. One residual on channel 0 leaves the index on channel 1, so
    // the active table at the check has no symbols and nothing is read.
    let used = audio_lengths(&[3, 256]);
    let empty = [0u8; AUDIO_SYMBOLS];
    let mut out = BitWriter::default();
    let codes = mm_block(&mut out, &[used, empty]);
    out.push_code(codes[0][3]);
    let check = out.bits();
    let packed = out.finish_with_r(check, 40);

    let mut chain = Chain::new();
    let decoded = chain.member(&packed, 1).expect("the member succeeds");
    let mut model = Model::fresh();
    assert_eq!(decoded, [model.residual_to_byte(0, 3)]);
}

#[test]
fn s7_a_trailing_field_that_is_no_codeword_takes_nothing() {
    // SPEC-D 2.2, O6: an incomplete main table, R over the threshold and
    // the next bits in its unused space. Member one is whole and member
    // two carries on in the old block under the old tables.
    let mut main = [0u8; MAIN_SYMBOLS];
    // One two bit code: three quarters of the space is unused, and the
    // field below lands in it.
    main[65] = 2;
    let tables = LzTables {
        main,
        distance: flat(&(0..DISTANCE_SLOTS as u16).collect::<Vec<_>>()),
        length: flat(&(0..LENGTH_SLOTS as u16).collect::<Vec<_>>()),
    };
    let mut out = BitWriter::default();
    lz_header(&mut out);
    tables.write(&mut out);
    let codes = tables.codes();
    for _ in 0..4 {
        out.push_code(codes.0[65]);
    }
    let check = out.bits();
    // All ones: the only code the table holds is two zero bits.
    out.push(0b11, 2);
    let packed = out.finish_with_r(check, 9);

    let mut chain = Chain::new();
    assert_eq!(chain.member(&packed, 4).expect("member one"), b"AAAA");
    let mut second = BitWriter::default();
    for _ in 0..3 {
        second.push_code(codes.0[65]);
    }
    assert_eq!(
        chain.member(&second.finish(), 3).expect("member two"),
        b"AAA"
    );
}

#[test]
fn repeated_distances_are_pushed() {
    // The erratum on `Rar20Lz::push_distance`: the repeated distance arm
    // PUSHES, where RAR 2.9 rotates. The two readings first differ when a
    // repeated distance deeper than k = 1 is named after an earlier
    // repeated distance match, which is why six of the ten RAR 2.0 corpus
    // members decode under either one.
    let tables = LzTables::over(&[65, 258, 259, 269, 270]);
    let mut out = BitWriter::default();
    lz_header(&mut out);
    tables.write(&mut out);
    let codes = tables.codes();
    // Thirty-two distinct literals, so a copy at one distance is never the
    // same bytes as a copy at another.
    for _ in 0..32 {
        out.push_code(codes.0[65]);
    }
    let mut ops: Vec<Op> = (0..32).map(|_| Op::Literal(65)).collect();

    // Three fresh matches: the history becomes [4, 8, 16, 0].
    for distance in [16u32, 8, 4] {
        out.push_code(codes.0[270]);
        out.push(0, LENGTH_EXTRA[0]);
        let (slot, extra, width) = distance_fields(distance);
        out.push_code(codes.1[slot]);
        out.push(extra, width);
        ops.push(Op::Copy {
            distance,
            length: 3,
        });
    }
    // Repeated distance k = 1, which is 8. Pushing leaves [8, 4, 8, 16];
    // rotating would leave [8, 4, 16, 0].
    out.push_code(codes.0[258]);
    out.push_code(codes.2[0]);
    out.push(0, LENGTH_EXTRA[0]);
    ops.push(Op::Copy {
        distance: 8,
        length: 2,
    });
    // Repeated distance k = 2. Under the push it is 8 again; under the
    // rotation it would be 16, and the bytes differ.
    out.push_code(codes.0[259]);
    out.push_code(codes.2[0]);
    out.push(0, LENGTH_EXTRA[0]);
    ops.push(Op::Copy {
        distance: 8,
        length: 2,
    });
    out.push_code(codes.0[269]);

    let packed = out.finish();
    let expected = apply(&ops);
    let decoded = decode(&packed, 65_536, expected.len() as u64).expect("the push vector decodes");
    assert_eq!(decoded, expected);
}

/// Spec F section 4.2: "declared unpacked size ... never used to size a
/// buffer; it is a limit on output, checked as output is produced."
///
/// The size comes from an UNTRUSTED RAR 2.0 member header. Sizing the
/// output buffer by it let a header of a few bytes ask for the whole
/// declared size at once on a 64-bit target; on a 32-bit one a declared
/// size at or over 4 GiB truncated in the narrowing cast and reserved some
/// small unrelated figure instead. Driven here either side of 4 GiB, which
/// is the only way a 64-bit host can run the 32-bit case.
#[test]
fn a_declared_size_never_sizes_the_output_buffer() {
    let cap = OUTPUT_RESERVE_MAX as usize;
    assert_eq!(reserve_for(0), 0);
    assert_eq!(reserve_for(1024), 1024);
    assert_eq!(reserve_for(OUTPUT_RESERVE_MAX), cap);
    assert_eq!(reserve_for(OUTPUT_RESERVE_MAX + 1), cap);

    // Either side of what a 32-bit `usize` holds, and far past it. Every
    // one reserves the same bounded figure, so the narrowing is exact on
    // any pointer width and no header can ask for an allocation.
    for declared in [
        u64::from(u32::MAX) - 1,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        1u64 << 32,
        1u64 << 40,
        u64::MAX,
    ] {
        assert_eq!(reserve_for(declared), cap, "declared {declared}");
        // What the cast alone answered: `1 << 32` reserved NOTHING.
        assert!(reserve_for(declared) as u64 <= OUTPUT_RESERVE_MAX);
    }
    assert_eq!((1u64 << 32) as u32, 0, "the truncation this replaces");
}

/// The exhausted-input rule reaches RAR 2.0, and this is its limiting case.
///
/// SPEC-A 6.1 states that a step which BEGINS with the packed input already
/// exhausted ends the member rather than being carried to the declared
/// size by zero bits, and it says in terms "It reaches RAR 2.0 too", with
/// SPEC-H3 3.5 carrying the cross-reference. The member is then short of
/// what it declared, and that is `Ok`: the shortfall is reported as a
/// member CHECKSUM failure (`MemberOutcome::checksum_ok == Some(false)`,
/// SPEC-F 2.5), never as a codec error.
///
/// An empty packed input is the limiting case, because the member's very
/// first step begins exhausted, so no step is taken at all and the member
/// produces nothing whatever it declared. Package A pins the same case at
/// `rar1x::tests::spec_a_4_11_the_member_ends_short_at_the_first_step_with_no_packed_bit_left`;
/// package D had no pin until the seeded fuzz reproducer
/// `rar20_member-crash-fa04531393192953630e9f8fa603c0460d6653e1` (input
/// `2d 2d 4d`, so an empty packed slice against a declared 19,757) reached
/// `fuzz_targets/rar20_member.rs`'s old "delivered whole" assertion and
/// showed the gap.
#[test]
fn an_empty_input_ends_a_rar20_member_at_once() {
    for declared in [1u64, 2, 100, 5_000, 19_757] {
        let out = Rar20Chain::new(65_536)
            .decode_next(&[], declared)
            .unwrap_or_else(|e| panic!("declared {declared}: {e}"));
        assert!(
            out.is_empty(),
            "declared {declared}: {} bytes from no packed input at all",
            out.len()
        );
    }
}

/// The upper bound `fuzz_targets/rar20_member.rs` asserts, as a unit test.
///
/// SPEC-A section 6 promises that no byte of an over-running match is
/// delivered, and the RAR 2.0 driver keeps to it by clamping every step to
/// the room the declared size leaves, carrying a match's excess in
/// `OwedCopy` rather than writing it. So a member never delivers MORE
/// than it declared, whatever its packed bytes say, and that bound is also
/// the memory bound of section 6's panics paragraph.
#[test]
fn a_member_never_delivers_more_than_it_declared() {
    // Packed bytes that decode to 300 literals, asked for a spread of
    // declared sizes both under and at that figure.
    let packed = member_one(300, None, |_, _| {});
    for declared in [0u64, 1, 2, 17, 300] {
        let out = Rar20Chain::new(65_536)
            .decode_next(&packed, declared)
            .unwrap_or_else(|e| panic!("declared {declared}: {e}"));
        assert!(
            out.len() as u64 <= declared,
            "declared {declared}: delivered {} bytes",
            out.len()
        );
    }
}

/// THE REACH COUNTER IS WIRED: a stream that carries a multimedia block
/// is counted, and one that does not is not.
///
/// `examples/h3_audio_reach.rs` reads this counter to say whether a fuzz
/// corpus ever lands a sample in the predictor, and a counter that is
/// silently never incremented would report "never reached" for every
/// corpus, which is the answer it was written to test for. So the
/// instrument is checked before it is believed.
///
/// It runs serially because the counter is process wide: one test owns it.
#[cfg(feature = "audio-lane-ref")]
#[test]
fn the_multimedia_reach_counter_counts_multimedia_samples() {
    use crate::lz20::lane_ref;

    let alphabet = audio_lengths(&[7, 256]);
    let mut out = BitWriter::default();
    let codes = mm_block(&mut out, &[alphabet]);
    for _ in 0..40 {
        out.push_code(codes[0][7]);
    }
    out.push_code(codes[0][256]);
    let packed = out.finish();

    lane_ref::reset_samples();
    let decoded = decode(&packed, 65_536, 40).expect("the multimedia vector decodes");
    assert_eq!(decoded.len(), 40);
    assert_eq!(
        lane_ref::samples(),
        40,
        "a multimedia block of 40 samples was not counted"
    );

    // An LZ block of one literal, which touches the predictor nowhere.
    let tables = LzTables::over(&[90, 269]);
    let mut out = BitWriter::default();
    lz_header(&mut out);
    tables.write(&mut out);
    let lz = tables.codes();
    out.push_code(lz.0[90]);
    out.push_code(lz.0[269]);
    let packed = out.finish();

    lane_ref::reset_samples();
    let _ = decode(&packed, 65_536, 1);
    assert_eq!(
        lane_ref::samples(),
        0,
        "a stream with no multimedia block counted a sample"
    );
}

/// Section 3.2's T2 makes the decoder accept streams it refused before:
/// tables that are incomplete or all zero. Arbitrary bytes are mostly
/// such streams. Whatever they decode to, a member never gives more than
/// its declared size, and its memory is the stream's fixed window and
/// tables and the declared size's worth of output, here 64 KiB at most.
/// One thread.
#[test]
fn spec_h3_3_2_t2_arbitrary_streams_stay_inside_the_declared_size() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut decoded = 0u32;
    for round in 0..3000u32 {
        let size = (next() % 600) as usize;
        let mut packed: Vec<u8> = (0..size).map(|_| (next() >> 24) as u8).collect();
        // Most rounds thin the bits out, which is what leaves tables
        // incomplete instead of oversubscribed.
        if round % 4 != 0 {
            for byte in packed.iter_mut() {
                *byte &= (next() >> 16) as u8 & (next() >> 40) as u8;
            }
        }
        let declared = next() % 65_536;
        if let Ok(out) = Rar20Chain::new(64 << 10).decode_next(&packed, declared) {
            assert!(out.len() as u64 <= declared, "round {round}");
            decoded += 1;
        }
    }
    assert!(
        decoded > 0,
        "no stream decoded, so the bound was never asked"
    );
}

/// SPEC-H3 3.5, "A match that passes the declared size" (restated 8 Oct
/// 2026; SWEEP2-08OCT-52).
///
/// Member one is eight literals and a match of 258 bytes at distance 8,
/// and declares 259 bytes: the match ends 7 bytes past its size. The
/// match enters the stream WHOLE, those 7 bytes are no member's output,
/// and the member fails. Member two continues the chain with a literal, a
/// match of 3 at distance 10 and a literal: it starts AFTER the 7 bytes,
/// so its match copies stream positions 257 to 259.
///
/// The two readings this refuses: the 7 bytes open member two's output
/// (the rule until 9 Oct 2026, which passed an archive the reference
/// fails), and the match is cut at the size, where member two's match
/// would copy positions 250 to 252.
#[test]
fn spec_h3_3_5_a_match_past_the_declared_size_enters_the_stream_whole() {
    const PATTERN: [u16; 8] = [65, 66, 66, 65, 65, 65, 66, 65];
    let tables = LzTables::over(&[65, 66, 269, 270, 297]);
    let codes = tables.codes();
    let mut one = BitWriter::default();
    lz_header(&mut one);
    tables.write(&mut one);
    for literal in PATTERN {
        one.push_code(codes.0[literal as usize]);
    }
    one.push_code(codes.0[297]);
    one.push(31, LENGTH_EXTRA[LENGTH_SLOTS - 1]);
    let (slot, extra, width) = distance_fields(8);
    one.push_code(codes.1[slot]);
    one.push(extra, width);
    let one = one.finish();

    let mut two = BitWriter::default();
    two.push_code(codes.0[66]);
    two.push_code(codes.0[270]);
    two.push(0, LENGTH_EXTRA[0]);
    let (slot, extra, width) = distance_fields(10);
    two.push_code(codes.1[slot]);
    two.push(extra, width);
    two.push_code(codes.0[65]);
    let two = two.finish();

    // The whole stream as the reference has it: the pattern for 266
    // bytes, then member two's five.
    let at = |index: usize| PATTERN[index % 8] as u8;
    let want_two = [66, at(257), at(258), at(259), 65];
    assert_ne!(
        [at(257), at(258), at(259)],
        [at(250), at(251), at(252)],
        "the vector tells the two readings of the stream apart"
    );

    // Declared at the match's own end, nothing passes the size.
    let mut whole = Rar20Chain::new(65_536);
    let all = whole
        .decode_next(&one, 266)
        .expect("the match ends at the size");
    assert_eq!(all, (0..266).map(at).collect::<Vec<u8>>());
    assert_eq!(whole.decode_next(&two, 5).expect("member two"), want_two);

    // Declared 7 bytes short of it: the member fails, and the chain goes
    // on from the same stream.
    let mut chain = Rar20Chain::new(65_536);
    let failed = chain
        .decode_next(&one, 259)
        .expect_err("a match past the size");
    assert!(
        matches!(failed.kind(), ErrorKind::Corrupt(Corruption::Stream)),
        "{failed:?}"
    );
    assert_eq!(
        chain.decode_next(&two, 5).expect("member two"),
        want_two,
        "member two starts after the whole match, with none of its bytes"
    );
}
