//! Unit tests of the RAR 1.x decoder, each named by the section of spec A
//! it holds. One thread; the largest test holds the decoder's own 64 KiB
//! and a few megabytes of packed input.

use super::codes::{literal_code, Narrow, Wide, LENA, LENB, RK, SHORT};
use super::ranks::Ranks;
use super::{Past, Rar1x, RING, UNSET};
#[cfg(debug_assertions)]
use super::{Watch, FIRST, WATCHED};
use crate::error::{Corruption, Error, ErrorKind, Result};
use crate::rar5_lz::output::LzSink;
use crate::rar5_lz::{PackedSource, SliceSource};

/// Decode `packed` as one member that is not solid.
fn decode(packed: &[u8], target: u64) -> (Result<()>, Vec<u8>) {
    let mut out = Vec::new();
    let ran = Rar1x::new().member(&mut SliceSource::new(packed), target, false, &mut out);
    (ran, out)
}

fn is_stream_fault(ran: &Result<()>) -> bool {
    matches!(
        ran.as_ref().map_err(Error::kind),
        Err(ErrorKind::Corrupt(Corruption::Stream))
    )
}

/// A sink that counts and keeps nothing.
struct Count(u64);

impl LzSink for Count {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.0 += bytes.len() as u64;
        Ok(())
    }
}

/// The value and length a 12 bit lookup gives for a codeword written as
/// text, the rest of the window filled with `fill` bits.
fn wide(code: &Wide, word: &str, fill: bool) -> (u32, usize) {
    let mut window = usize::from_str_radix(word, 2).expect("binary") << (12 - word.len());
    if fill {
        window |= (1 << (12 - word.len())) - 1;
    }
    let entry = code[window];
    (u32::from(entry >> 4), usize::from(entry & 15))
}

#[test]
fn spec_a_4_2_check_vectors_of_every_code() {
    let checks: [(&Wide, &str); 7] = [
        (&LENA, "00>0 01>1 100>2 1010>3 11000>5 110100>7 1110000>11 11101010>16 111011100>20 1111000000>24 111100100000>32 111111111111>255"),
        (&LENB, "000>0 100>4 1010>5 11000>7 110100>9 1110000>13 11101010>18 111011100>22 1111000000>26 11110010000>34 111100100100>36 111111111111>255"),
        (&RK[0], "0000>0 0111>7 10000>8 110000>16 1110000>24 1111000>32 111100100000>33 111111111111>256"),
        (&RK[1], "00000>0 001000>4 101111>43 1100000>44 11100000>60 111100000>76 11110010000>80 11110111110>126 111101111110>127 111111111111>256"),
        (&RK[2], "00000>0 000100>2 0010010>7 10000000>53 110000000>117 111110011>232 1111101000>233 1111111111>256"),
        (&RK[3], "000000>0 0000100>2 00100100>16 111011100>218 111111100>250 1111111010>251 1111111111>256"),
        (&RK[4], "00000000>0 11111110>254 111111110>255 111111111>256"),
    ];
    for (number, (code, list)) in checks.iter().enumerate() {
        for check in list.split(' ') {
            let (word, value) = check.split_once('>').expect("word>value");
            let value: u32 = value.parse().expect("a value");
            for fill in [false, true] {
                assert_eq!(
                    wide(code, word, fill),
                    (value, word.len()),
                    "code {number}, {word}"
                );
            }
        }
    }
}

#[test]
fn spec_a_4_2_every_code_is_complete_and_gives_each_value_once() {
    let codes: [(&Wide, u32); 7] = [
        (&LENA, 256),
        (&LENB, 256),
        (&RK[0], 257),
        (&RK[1], 257),
        (&RK[2], 257),
        (&RK[3], 257),
        (&RK[4], 257),
    ];
    for (number, (code, values)) in codes.iter().enumerate() {
        let mut windows = vec![0usize; *values as usize];
        for entry in code.iter() {
            let (value, bits) = (usize::from(entry >> 4), u32::from(entry & 15));
            assert!(
                (1..=12).contains(&bits),
                "code {number}: a window no codeword owns"
            );
            windows[value] += 1;
            assert_eq!(
                windows[value].min(1 << (12 - bits)),
                windows[value],
                "code {number}: value {value} owns more than one codeword"
            );
        }
        for (value, count) in windows.iter().enumerate() {
            assert!(count.is_power_of_two(), "code {number}: value {value}");
        }
    }
}

#[test]
fn spec_a_4_3_every_codeword_of_the_four_columns() {
    let table: [[&str; 4]; 15] = [
        ["0", "0", "00", "00"],
        ["101", "1010", "010", "010"],
        ["1101", "1101", "011", "011"],
        ["1110", "1110", "101", "1010"],
        ["11110", "11110", "1101", "1101"],
        ["111110", "111110", "1110", "1110"],
        ["1111110", "1111110", "11110", "11110"],
        ["11111110", "11111110", "111110", "111110"],
        ["11111111", "11111111", "111111", "111111"],
        ["1100", "1100", "1100", "1100"],
        ["1000", "1000", "1000", "1000"],
        ["10010", "10010", "10010", "10010"],
        ["100110", "100110", "100110", "100110"],
        ["100111", "100111", "100111", "100111"],
        ["", "1011", "", "1011"],
    ];
    let columns: [&Narrow; 4] = [&SHORT[0][0], &SHORT[0][1], &SHORT[1][0], &SHORT[1][1]];
    for (index, row) in table.iter().enumerate() {
        for (word, column) in row.iter().zip(columns) {
            if word.is_empty() {
                continue;
            }
            let first = usize::from_str_radix(word, 2).expect("binary") << (8 - word.len());
            let span = 1usize << (8 - word.len());
            for entry in &column[first..first + span] {
                assert_eq!(
                    (usize::from(entry >> 4), usize::from(entry & 15)),
                    (index, word.len()),
                    "index {index}, {word}"
                );
            }
        }
    }
    // With the variant off, 1011 is index 1 of the first table and index 3
    // of the second.
    assert_eq!(SHORT[0][0][0b1011_0000] >> 4, 1);
    assert_eq!(SHORT[1][0][0b1011_0000] >> 4, 3);
}

#[test]
fn spec_a_4_5_the_literal_code_at_each_boundary_of_the_average() {
    let rows = [
        (0, 0),
        (3583, 0),
        (3584, 1),
        (13823, 1),
        (13824, 2),
        (24063, 2),
        (24064, 3),
        (30207, 3),
        (30208, 4),
        (65280, 4),
    ];
    for (mean, code) in rows {
        assert!(std::ptr::eq(literal_code(mean), &RK[code]), "{mean}");
    }
}

/// Section 4.1 read word for word: a scan for the lowest slot of a weight.
struct PlainRanks {
    slots: Vec<(u8, u8)>,
    ceiling: u8,
}

impl PlainRanks {
    fn take(&mut self, slot: usize) -> u8 {
        let (symbol, mut weight) = self.slots[slot];
        if weight == self.ceiling {
            for (place, entry) in self.slots.iter_mut().enumerate() {
                entry.1 = 7 - (place / 32) as u8;
            }
            weight = self.slots[slot].1;
        }
        let lowest = self
            .slots
            .iter()
            .position(|entry| entry.1 == weight)
            .expect("the slot itself has this weight");
        self.slots[slot] = self.slots[lowest];
        self.slots[lowest] = (symbol, weight + 1);
        symbol
    }
}

/// Many uses of one table against the plain reading.
fn promotions<const CEILING: u16>(mut quick: Ranks<CEILING>, seed: u64) {
    let mut dice = rarkit_testdata::Seeded::new(seed);
    let mut plain = PlainRanks {
        slots: quick.slots(),
        ceiling: CEILING as u8,
    };
    for turn in 0..200_000u32 {
        // Mostly a few slots, so weights climb to the ceiling and a
        // re-weight comes round many times; now and then any slot.
        let roll = dice.next_u64();
        let slot = match roll & 7 {
            0 => (roll >> 8) as u8,
            1 | 2 => ((roll >> 8) % 40) as u8,
            _ => ((roll >> 8) % 3) as u8,
        };
        assert_eq!(
            quick.take(slot),
            plain.take(usize::from(slot)),
            "ceiling {CEILING}, turn {turn}"
        );
        if turn % 997 == 0 {
            assert_eq!(quick.slots(), plain.slots, "ceiling {CEILING}, turn {turn}");
        }
    }
    assert_eq!(quick.slots(), plain.slots);
}

#[test]
fn spec_a_4_1_a_promotion_is_the_stated_exchange_through_every_ceiling() {
    promotions(Ranks::<161>::flat(|slot| slot), 0x05ee_da41);
    promotions(
        Ranks::<255>::flat(|slot| 0u8.wrapping_sub(slot)),
        0x05ee_da42,
    );
    promotions(Ranks::<255>::graded(|slot| slot), 0x05ee_da43);
}

// The first step of a member that is not solid, by hand. The flag byte is
// code value 0 of the fourth rank code, 00000: slot 0 of the flag table
// holds byte 0, eight zero flag bits. Two of them make a short-family
// step; index 0 is the bit 0; the near rank is 00000 again, entry 0,
// distance 1 and length 2. Eleven zero bits in all, and the two bytes are
// zeros because nothing lies one place back.

#[test]
fn spec_a_4_8_a_copy_from_before_the_start_gives_zeros() {
    let (ran, out) = decode(&[0, 0], 2);
    assert!(ran.is_ok());
    assert_eq!(out, [0, 0]);
}

#[test]
fn spec_a_4_8_a_match_past_the_declared_size_fails_and_delivers_none_of_it() {
    let (ran, out) = decode(&[0, 0], 1);
    assert!(is_stream_fault(&ran), "{ran:?}");
    assert!(out.is_empty());
    // The same after bytes that do fit: 22 zero bits are two such
    // matches, and the second would make four bytes of three.
    let (ran, out) = decode(&[0, 0, 0], 3);
    assert!(is_stream_fault(&ran), "{ran:?}");
    assert_eq!(out, [0, 0]);
}

#[test]
fn spec_a_4_4_a_member_of_size_zero_reads_nothing_and_gives_nothing() {
    /// A source that fails the moment it is asked for anything.
    struct Untouchable;
    impl PackedSource for Untouchable {
        fn fill(&mut self, _want: usize) -> Result<()> {
            Err(Error::new(ErrorKind::Truncated))
        }
        fn available(&self) -> &[u8] {
            &[]
        }
        fn advance(&mut self, _n: usize) {}
        fn exhausted(&self) -> bool {
            false
        }
    }
    let mut out = Vec::new();
    let mut lz = Rar1x::new();
    assert!(lz.member(&mut Untouchable, 0, false, &mut out).is_ok());
    assert!(lz.member(&mut Untouchable, 0, true, &mut out).is_ok());
    assert!(out.is_empty());
    // And for a member that owes bytes, the source's failure is the
    // member's.
    let ran = lz.member(&mut Untouchable, 1, false, &mut out);
    assert!(matches!(
        ran.as_ref().map_err(Error::kind),
        Err(ErrorKind::Truncated)
    ));
}

#[test]
fn spec_a_4_11_the_member_ends_short_at_the_first_step_with_no_packed_bit_left() {
    // No packed byte: no step, no byte, and no failure.
    let (ran, out) = decode(&[], 5);
    assert!(ran.is_ok());
    assert!(out.is_empty());
    // Two bytes hold one whole step and five more bits. The second step
    // begins with packed bits left, so it is taken; the third does not.
    let (ran, out) = decode(&[0, 0], 100);
    assert!(ran.is_ok());
    assert_eq!(out, [0, 0, 0, 0]);
}

#[test]
fn spec_a_4_11_leaves_open_what_lies_past_a_members_end_and_this_decoder_reads_zeros() {
    // One byte: the step's flag byte and index are in it, and the last
    // two bits begin its near rank. Read as zeros past the end, the rank
    // is 0 and the step gives two bytes.
    let (ran, out) = decode(&[0], 100);
    assert!(ran.is_ok());
    assert_eq!(out, [0, 0]);
    // The same step with ones in the bits the packed byte does hold:
    // 00000 0 11, then zeros, is rank code 1100000, value 44, distance 45.
    let (ran, out) = decode(&[0b0000_0011], 100);
    assert!(ran.is_ok());
    assert_eq!(out, [0, 0]);
}

#[test]
fn spec_a_4_8_leaves_open_copies_before_the_start_past_70_mb_and_this_decoder_gives_zeros() {
    let mut history = Past::new();
    let mut past = history.pen();
    let mut sink = Count(0);
    for count in 0..71_000_000u32 {
        past.push((count % 251) as u8 | 1, &mut sink).expect("push");
    }
    let before = past.at as usize;
    for distance in [0, UNSET, 65_536, 70_000_000] {
        past.copy(distance, 5, &mut sink).expect("copy");
    }
    past.copy(65_535, 1, &mut sink).expect("copy");
    past.settle(&mut sink).expect("settle");
    assert_eq!(sink.0, 71_000_021);
    let tail: Vec<u8> = (0..21).map(|k| past.ring[(before + k) % RING]).collect();
    assert_eq!(tail[..20], [0u8; 20]);
    // Distance 65,535 is a byte that exists, and none of those written
    // here is zero.
    assert_ne!(tail[20], 0);
}

#[test]
fn spec_a_6_a_distance_over_the_output_so_far_gives_zeros_for_the_whole_copy() {
    // Three bytes are out and the copy is five long at distance 5: the
    // distance names no byte when the copy begins, so all five are
    // zeros, the fourth and fifth too, although by then five places back
    // is a byte of the output. Ten of the constructed archives of
    // `specs/vectors-A` tell this from a byte by byte reading
    // (`tests/spec_a_vectors.rs`).
    let mut history = Past::new();
    let mut past = history.pen();
    let mut out = Vec::new();
    for byte in [7, 8, 9] {
        past.push(byte, &mut out).expect("push");
    }
    past.copy(5, 5, &mut out).expect("copy");
    // Distance 8 names the first byte now, and the copy overlaps itself.
    past.copy(8, 10, &mut out).expect("copy");
    past.settle(&mut out).expect("settle");
    assert_eq!(out, [7, 8, 9, 0, 0, 0, 0, 0, 7, 8, 9, 0, 0, 0, 0, 0, 7, 8]);
}

/// Section 4.8 read word for word over a plain vector: no ring. A
/// distance over 65,535 is one no rule gives; the decoder holds it for a
/// distance never set, which is how it keeps that one.
fn plain_copy(all: &mut Vec<u8>, distance: usize, length: usize) {
    let exists = distance >= 1 && distance <= all.len().min(65_535);
    for _ in 0..length {
        let byte = if exists { all[all.len() - distance] } else { 0 };
        all.push(byte);
    }
}

#[test]
fn spec_a_4_8_copies_of_every_shape_agree_with_the_plain_reading_round_the_ring() {
    // Literals and copies at near, overlapping, far and impossible
    // distances, for five laps of the ring, in members cut at arbitrary
    // places, against a vector that keeps everything.
    let mut dice = rarkit_testdata::Seeded::new(0x00c0_ffee);
    let mut history = Past::new();
    let mut all: Vec<u8> = Vec::new();
    let mut got: Vec<u8> = Vec::new();
    while all.len() < 5 * RING {
        let mut pen = history.pen();
        for _ in 0..(dice.next_u64() % 5000) {
            let roll = dice.next_u64();
            let length = match roll >> 8 & 3 {
                0 => roll >> 12 & 7,
                1 => roll >> 12 & 31,
                _ => (roll >> 12) % 267,
            } as usize;
            let distance = match roll & 7 {
                0 => {
                    let byte = (roll >> 40) as u8;
                    pen.push(byte, &mut got).expect("push");
                    all.push(byte);
                    continue;
                }
                1 => roll >> 20 & 7,
                2 => roll >> 20 & 15,
                3 => roll >> 20 & 0xff,
                4 => 65_535 - (roll >> 20 & 15),
                5 => 65_536 + (roll >> 20 & 3),
                _ => roll >> 20 & 0xffff,
            } as usize;
            pen.copy(distance as u32, length as u32, &mut got)
                .expect("copy");
            plain_copy(&mut all, distance, length);
        }
        pen.settle(&mut got).expect("settle");
        (history.at, history.lapped) = (pen.at, pen.lapped);
        assert!(got == all, "after {} bytes", all.len());
    }
}

/// Every short overlapping and near copy, the ones the wide copy's two
/// fixed blocks serve with no loop: distances 1 to 16 (under, at and over
/// one block) and lengths 3 to 40 (inside the two blocks, at their edge,
/// and on into the loop), each at the ring's middle and near its end,
/// against 4.8 read a byte at a time. One thread, one ring of 128 KiB.
#[test]
fn spec_a_4_8_short_and_overlapping_copies_give_the_bytes_of_the_plain_reading() {
    for start in [1_000, RING - 300] {
        for distance in 1..=16usize {
            for length in 3..=40usize {
                let mut history = Past::new();
                let mut got: Vec<u8> = Vec::new();
                let mut all: Vec<u8> = Vec::new();
                let mut pen = history.pen();
                // A run of distinct bytes up to `start`, then the copy,
                // then a byte after it so a write past its end would
                // show once later copies read there.
                for k in 0..start {
                    let byte = (k % 251 + 1) as u8;
                    pen.push(byte, &mut got).expect("push");
                    all.push(byte);
                }
                pen.copy(distance as u32, length as u32, &mut got)
                    .expect("copy");
                plain_copy(&mut all, distance, length);
                pen.copy(length as u32 + 1, length as u32 + 1, &mut got)
                    .expect("copy");
                plain_copy(&mut all, length + 1, length + 1);
                pen.settle(&mut got).expect("settle");
                (history.at, history.lapped) = (pen.at, pen.lapped);
                assert!(
                    got == all,
                    "distance {distance}, length {length}, from {start}"
                );
            }
        }
    }
}

#[test]
fn spec_a_3_2_a_member_that_is_not_solid_sees_nothing_of_the_one_before() {
    let mut dice = rarkit_testdata::Seeded::new(0x000a_11ce);
    let noise = dice.bytes(4096);
    let mut lz = Rar1x::new();
    let mut first = Vec::new();
    // A size no 4,096 packed bytes reach, so no match can pass it.
    lz.member(&mut SliceSource::new(&noise), 1 << 30, false, &mut first)
        .expect("a member that ends short is not a failure");
    assert!(!first.is_empty());
    let mut again = Vec::new();
    let ran = lz.member(&mut SliceSource::new(&[0, 0]), 2, false, &mut again);
    assert!(ran.is_ok());
    assert_eq!(again, [0, 0]);
}

#[test]
fn spec_a_6_arbitrary_bytes_never_give_more_than_the_declared_size() {
    let mut dice = rarkit_testdata::Seeded::new(0x00dd_ba11);
    for round in 0..400u32 {
        let packed = {
            let size = (dice.next_u64() % 3000) as usize;
            let mut bytes = dice.bytes(size);
            // Some rounds lean to zeros or to ones, which reach the
            // match steps and run mode far more often than noise does.
            match round % 4 {
                1 => bytes
                    .iter_mut()
                    .for_each(|b| *b &= (dice.next_u64() >> 9) as u8),
                2 => bytes
                    .iter_mut()
                    .for_each(|b| *b |= (dice.next_u64() >> 9) as u8),
                _ => {}
            }
            bytes
        };
        let mut lz = Rar1x::new();
        for member in 0..3 {
            let target = dice.next_u64() % 70_000;
            let mut out = Vec::new();
            let cut = (dice.next_u64() as usize) % (packed.len() + 1);
            let ran = lz.member(
                &mut SliceSource::new(&packed[cut..]),
                target,
                member > 0,
                &mut out,
            );
            assert!(out.len() as u64 <= target, "round {round}");
            match ran {
                Ok(()) => {}
                Err(fault) => {
                    assert!(is_stream_fault(&Err(fault)), "round {round}");
                    break;
                }
            }
        }
    }
}

#[test]
fn spec_a_4_11_the_work_is_bounded_by_the_packed_bytes_whatever_the_declared_size() {
    // Every step gives at most 266 bytes and uses at least one bit, so a
    // member of N packed bytes gives no more than 8 N steps of 266.
    let mut dice = rarkit_testdata::Seeded::new(0xb0b);
    for packed in [vec![0u8; 20_000], vec![0xff; 20_000], dice.bytes(20_000)] {
        let mut sink = Count(0);
        let ran = Rar1x::new().member(
            &mut SliceSource::new(&packed),
            4_294_967_280,
            false,
            &mut sink,
        );
        assert!(ran.is_ok());
        assert!(sink.0 <= 266 * 8 * 20_000, "{}", sink.0);
    }
}

#[test]
fn spec_a_2_a_source_that_hands_bytes_over_in_pieces_reads_the_same() {
    /// The same bytes, never more than `piece` available at once.
    struct Pieces<'a> {
        rest: &'a [u8],
        shown: usize,
        piece: usize,
    }
    impl PackedSource for Pieces<'_> {
        fn fill(&mut self, _want: usize) -> Result<()> {
            self.shown = self.piece.min(self.rest.len());
            Ok(())
        }
        fn available(&self) -> &[u8] {
            &self.rest[..self.shown]
        }
        fn advance(&mut self, n: usize) {
            self.rest = &self.rest[n..];
            self.shown -= n;
        }
        fn exhausted(&self) -> bool {
            self.rest.is_empty()
        }
    }
    let mut dice = rarkit_testdata::Seeded::new(0x0091_ece5);
    let packed = dice.bytes(6000);
    let (ran, whole) = decode(&packed, 50_000);
    assert!(ran.is_ok() || is_stream_fault(&ran));
    for piece in [1, 2, 3, 5, 7, 4096] {
        let mut source = Pieces {
            rest: &packed,
            shown: 0,
            piece,
        };
        let mut out = Vec::new();
        let again = Rar1x::new().member(&mut source, 50_000, false, &mut out);
        assert_eq!(again.is_ok(), ran.is_ok(), "piece {piece}");
        assert!(out == whole, "piece {piece}");
    }
}

/// A ring with every slot distinct from its neighbours, so a write past
/// a copy always shows as a change.
#[cfg(debug_assertions)]
fn marked_ring() -> Box<[u8; RING]> {
    let ring: Vec<u8> = (0..RING).map(|slot| (slot % 251 + 1) as u8).collect();
    ring.into_boxed_slice().try_into().expect("RING bytes")
}

/// Whether the guard lets through a change to the slot `spilled` past a
/// copy's end, when the copy may touch `allowed`.
#[cfg(debug_assertions)]
fn let_through(end: usize, spilled: usize, allowed: usize) -> bool {
    let mut ring = marked_ring();
    let watch = Watch::take(&ring, end);
    ring[(end + spilled) % RING] ^= 0xff;
    std::panic::catch_unwind(|| watch.held(&ring, allowed, "test")).is_ok()
}

/// The guard on the ring's copies is seen to pass AND to fail, on the
/// very question the copies put to it. One thread, one ring of 128 KiB
/// at a time.
#[cfg(debug_assertions)]
#[test]
fn spec_a_4_8_the_wide_copy_may_touch_its_last_block_and_nothing_past_it() {
    // In the ring's middle, and where the watch goes round its end.
    for end in [1_009, RING - 3] {
        // Every slot the wide copy is allowed passes; every watched slot
        // past them is a copy wider than its first run, or a block too
        // many.
        for spilled in 0..WATCHED {
            assert_eq!(
                let_through(end, spilled, FIRST),
                spilled < FIRST,
                "the wide copy, slot {spilled} past {end}"
            );
            // The byte at a time copy is allowed nothing at all.
            assert!(!let_through(end, spilled, 0), "the byte copy, {spilled}");
        }
    }
}
