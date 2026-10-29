//! Section 5.4: the hand vectors.

use super::*;

/// The tests' own slot helper against the reader's ladder: for a
/// distance from each part of the ladder, the slot and extra bits the
/// helper gives are ones the reader turns back into that distance.
#[test]
fn the_slot_helper_is_the_ladder_run_backwards() {
    use super::ladders::distance_named;
    for distance in [
        1usize,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        255,
        256,
        257,
        4096,
        1 << 20,
        0x3fff_ffff,
    ] {
        let (slot, extra) = distance_slot(distance);
        assert_eq!(
            distance_named(slot, extra),
            distance,
            "slot {slot} with extra bits {extra}"
        );
    }
}

/// V5-HOLE: a block whose main table is incomplete and whose symbols
/// never reach the hole decodes; a lookahead that lands in the hole gives
/// `InvalidCode`.
#[test]
fn v5_hole_an_incomplete_table_decodes_until_a_lookahead_lands_in_it() {
    // 306 symbols at nine bits leaves 206 of the 512 lookaheads unused.
    let mut good = BlockBuilder::default();
    good.literals(b"hole");
    assert_eq!(
        run(&[good.finish(true, true)], 4, 1 << 17).unwrap(),
        b"hole"
    );

    let mut bad = BlockBuilder::default();
    bad.literals(b"hol");
    // A nine bit code above the last symbol falls in the unused space.
    bad.raw(400, 9);
    assert_fault(
        run(&[bad.finish(true, true)], 4, 1 << 17),
        Rar5Fault::InvalidCode,
    );
}

/// V5-OVER: code lengths claiming more code space than exists give
/// `Oversubscribed` at table build, before any symbol is read.
#[test]
fn v5_over_an_oversubscribed_table_is_refused_at_build() {
    let mut over = BlockBuilder::default();
    // 306 symbols at eight bits want 306 of the 256 codes an eight bit
    // length has.
    over.main = vec![8; super::tables::MAIN_SYMBOLS];
    over.literals(b"never read");
    assert_fault(
        run(&[over.finish(true, true)], 4, 1 << 17),
        Rar5Fault::Oversubscribed,
    );
}

/// V5-BITS: a block whose last byte has 3 valid bits, followed by another
/// block, where reading the last byte's remaining 5 bits would decode a
/// spurious symbol. The decoder must stop at the bit count.
#[test]
fn v5_bits_decoding_stops_at_the_blocks_bit_count() {
    // Eight literals at three bits each, so nine of them are 27 bits: the
    // last byte carries three valid bits and five that are not the
    // block's, and five bits is room for another three bit code.
    let alphabet: Vec<usize> = (b'a'..=b'h').map(usize::from).collect();
    let mut first = BlockBuilder::default().with_main(&alphabet, 3);
    first.literals(b"abcdefgha");
    let mut block = first.finish(true, false);
    // `f` is symbol 5, whose canonical three bit code is 101.
    *block.last_mut().unwrap() |= 0b1_0100;
    let mut second = BlockBuilder::default().with_main(&alphabet, 3);
    second.literals(b"b");
    let out = run(&[block, second.finish(true, true)], 10, 1 << 17).unwrap();
    assert_eq!(
        out, b"abcdefghab",
        "the five spare bits are not the block's"
    );
}

/// V5-ALIGN (section 5.4): a fresh match on a distance slot with `b = 6`
/// reads two plain bits and one alignment symbol, always. (a) a skewed
/// complete table, (b) sixteen lengths of 4, whose bits equal six plain
/// bits, (c) all zero lengths, `EmptyTable` at the match, and a block of
/// only `b < 4` slots with all zero lengths still decodes.
#[test]
fn v5_align_the_alignment_alphabet_supplies_the_low_four_bits() {
    use super::ladders::DISTANCE_SLOT_BITS;
    let distance = 200usize;
    let (slot, extra) = distance_slot(distance);
    assert_eq!(DISTANCE_SLOT_BITS[slot], 6, "slot {slot} has b = 6");
    assert_ne!(extra & 0xf, 0, "the low four bits are not zero");

    let filler: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
    let expected = {
        let mut want = filler.clone();
        for _ in 0..2 {
            let byte = want[want.len() - distance];
            want.push(byte);
        }
        want
    };
    let total = expected.len() as u64;

    // (a) lengths 1, 2, ... 14, 15, 15: complete and skewed.
    let mut skewed: Vec<u8> = (1..=15).collect();
    skewed.push(15);
    let mut a = BlockBuilder::default().with_align_lengths(&skewed);
    a.literals(&filler);
    a.fresh(0, 0, slot, extra);
    let got = run(&[a.finish(true, true)], total, 1 << 17).unwrap();
    assert_eq!(got, expected, "two bits plus a skewed alignment symbol");

    // (b) sixteen 4s: the same bytes, and the same bits as six plain bits.
    let mut b = BlockBuilder::default().with_align_lengths(&[4; 16]);
    b.literals(&filler);
    b.fresh(0, 0, slot, extra);
    let got = run(&[b.finish(true, true)], total, 1 << 17).unwrap();
    assert_eq!(got, expected, "sixteen lengths of 4");
    let mut plain = BlockBuilder::default().with_align_lengths(&[0; 16]);
    plain.literals(&filler);
    plain.fresh(0, 0, slot, extra);
    assert_eq!(
        b.body_bits(),
        plain.body_bits(),
        "four bit codes are plain bits"
    );

    // (c) all zero: the plain bits follow the slot and the decoder refuses.
    assert_fault(
        run(&[plain.finish(true, true)], total, 1 << 17),
        Rar5Fault::EmptyTable,
    );

    // The fourth block: all zero, but no slot needs the alphabet.
    let mut near = BlockBuilder::default().with_align_lengths(&[0; 16]);
    near.literals(&filler);
    near.fresh(0, 0, distance_slot(5).0, distance_slot(5).1);
    let mut want = filler.clone();
    for _ in 0..2 {
        let byte = want[want.len() - 5];
        want.push(byte);
    }
    let got = run(&[near.finish(true, true)], want.len() as u64, 1 << 17).unwrap();
    assert_eq!(got, want, "b < 4 needs no alignment alphabet");
}

/// V5-REP0: symbol 258 as the first symbol of a stream gives
/// `UninitialisedRepeat`.
#[test]
fn v5_rep0_a_repeat_of_an_unset_distance_is_refused() {
    let mut block = BlockBuilder::default();
    block.repeat(0, 0, 0);
    assert_fault(
        run(&[block.finish(true, true)], 8, 1 << 17),
        Rar5Fault::UninitialisedRepeat,
    );
    for k in 1..4 {
        let mut block = BlockBuilder::default();
        block.repeat(k, 0, 0);
        assert_fault(
            run(&[block.finish(true, true)], 8, 1 << 17),
            Rar5Fault::UninitialisedRepeat,
        );
    }
}

/// V5-ROT: repeated distances `[a, b, c, d]`, then symbol 260 (`k = 2`).
/// Expect `c` and the order `[c, a, b, d]`.
#[test]
fn v5_rot_the_chosen_distance_moves_to_the_front() {
    let mut state = MatchState {
        repeats: [11, 22, 33, 44],
        ..MatchState::default()
    };
    assert_eq!(state.rotate(2, 7).unwrap(), 33);
    assert_eq!(state.repeats, [33, 11, 22, 44]);
    assert_eq!(state.last_length, 7);

    // The ones after the chosen slot do not move; the ones before it do.
    let mut state = MatchState {
        repeats: [11, 22, 33, 44],
        ..MatchState::default()
    };
    assert_eq!(state.rotate(0, 1).unwrap(), 11);
    assert_eq!(state.repeats, [11, 22, 33, 44]);
    let mut state = MatchState {
        repeats: [11, 22, 33, 44],
        ..MatchState::default()
    };
    assert_eq!(state.rotate(3, 1).unwrap(), 44);
    assert_eq!(state.repeats, [44, 11, 22, 33]);

    // A fresh match pushes the four along.
    let mut state = MatchState {
        repeats: [11, 22, 33, 44],
        ..MatchState::default()
    };
    state.fresh(99, 5);
    assert_eq!(state.repeats, [99, 11, 22, 33]);
}

/// `MatchState::rotate` against the rule written out the long way (take
/// slot `k` out, put it in front), for every `k` and every state whose
/// slots are drawn from zero and three distances, so every slot is zero
/// or set in every combination. A zero chosen slot is the uninitialised
/// repeat fault and leaves the state as it was; any other gives the
/// chosen distance, the moved slots and the new length.
/// The apply walks call
/// `rotate_outlined`, a select per slot out of line that answers 0 for the
/// fault, and this holds it and `rotate` to the rule and to each other.
#[cfg(feature = "parallel")]
#[test]
fn rotate_and_rotate_outlined_match_the_rule_for_every_index_and_zero_pattern() {
    let values = [0usize, 7, 1 << 20, usize::MAX >> 1];
    let mut checked = 0;
    for a in values {
        for b in values {
            for c in values {
                for d in values {
                    for k in 0..4 {
                        let before = [a, b, c, d];
                        let mut state = MatchState {
                            repeats: before,
                            last_length: 3,
                        };
                        let got = state.rotate(k, 9);
                        let mut outlined = MatchState {
                            repeats: before,
                            last_length: 3,
                        };
                        let got_outlined = outlined.rotate_outlined(k, 9);
                        if before[k] == 0 {
                            assert!(got.is_err(), "{before:?} k {k}");
                            assert_eq!(state.repeats, before);
                            assert_eq!(state.last_length, 3);
                            assert_eq!(got_outlined, 0, "{before:?} k {k}");
                            assert_eq!(outlined.repeats, before);
                            assert_eq!(outlined.last_length, 3);
                        } else {
                            let mut want = before.to_vec();
                            let chosen = want.remove(k);
                            want.insert(0, chosen);
                            assert_eq!(got.unwrap(), before[k]);
                            assert_eq!(state.repeats.to_vec(), want, "{before:?} k {k}");
                            assert_eq!(state.last_length, 9);
                            assert_eq!(got_outlined, before[k]);
                            assert_eq!(outlined, state, "{before:?} k {k}");
                        }
                        checked += 1;
                    }
                }
            }
        }
    }
    assert_eq!(checked, 4 * 4 * 4 * 4 * 4);
}

/// The same rotation, seen through the bytes a member produces.
#[test]
fn a_rotated_repeat_copies_from_the_distance_it_names() {
    let filler: Vec<u8> = (0..600u32).map(|i| (i * 13 + i / 5) as u8).collect();
    let distances = [17usize, 130, 260, 520];
    let mut block = BlockBuilder::default();
    block.literals(&filler);
    for &distance in &distances {
        let (slot, extra) = distance_slot(distance);
        block.fresh(0, 0, slot, extra);
    }
    // The four are now [520, 260, 130, 17]; `k = 2` names 130.
    block.repeat(2, 0, 0);

    let mut want = filler.clone();
    for &distance in &distances {
        for _ in 0..super::ladders::fresh_match_length(2, distance) {
            let byte = want[want.len() - distance];
            want.push(byte);
        }
    }
    // A repeated distance match gets no bonus (section 3.5).
    for _ in 0..2 {
        let byte = want[want.len() - 130];
        want.push(byte);
    }
    let out = run(&[block.finish(true, true)], want.len() as u64, 1 << 17).unwrap();
    assert_eq!(out, want);
}

/// V5-BONUS: fresh matches at distances `0x100`, `0x101`, `0x2000`,
/// `0x2001`, `0x40000` and `0x40001` with one length slot. Expect bonuses
/// 0, 1, 1, 2, 2, 3.
#[test]
fn v5_bonus_three_thresholds_and_the_first_is_strictly_above_0x100() {
    let distances = [0x100usize, 0x101, 0x2000, 0x2001, 0x40000, 0x40001];
    let bonuses = [0usize, 1, 1, 2, 2, 3];
    let filler: Vec<u8> = (0..0x40010u32).map(|i| (i * 31 + i / 7) as u8).collect();

    let mut block = BlockBuilder::default();
    block.literals(&filler);
    for &distance in &distances {
        let (slot, extra) = distance_slot(distance);
        // Length slot 0 names a length of two before the bonus.
        block.fresh(0, 0, slot, extra);
    }
    let mut want = filler.clone();
    for (&distance, &bonus) in distances.iter().zip(&bonuses) {
        for _ in 0..(2 + bonus) {
            let byte = want[want.len() - distance];
            want.push(byte);
        }
    }
    let out = run(&[block.finish(true, true)], want.len() as u64, 1 << 20).unwrap();
    assert_eq!(out.len(), want.len(), "the bonus decides the total length");
    assert_eq!(out, want);
}

/// Section 3.5: a repeated distance match and a last length repeat get NO
/// bonus, where a fresh match at the same distance takes three.
#[test]
fn a_repeat_gets_no_bonus() {
    let distance = 0x40001usize;
    let filler: Vec<u8> = (0..0x40010u32).map(|i| (i * 17) as u8).collect();
    let (slot, extra) = distance_slot(distance);

    let mut block = BlockBuilder::default();
    block.literals(&filler);
    block.fresh(0, 0, slot, extra); // length slot 0 is two, plus three of bonus
    block.repeat(0, 0, 0); // two bytes, no bonus, and the last length is two
    block.repeat_last(); // two bytes again
    let total = (filler.len() + 5 + 2 + 2) as u64;
    let out = run(&[block.finish(true, true)], total, 1 << 20).unwrap();

    let mut want = filler.clone();
    for count in [5usize, 2, 2] {
        for _ in 0..count {
            let byte = want[want.len() - distance];
            want.push(byte);
        }
    }
    assert_eq!(out, want);
}

/// V5-NOTABLE: a first block with the table bit clear gives `EmptyTable` on
/// its first symbol, not a panic.
#[test]
fn v5_notable_a_first_block_with_no_tables_is_refused() {
    let mut block = BlockBuilder::default();
    block.literals(b"x");
    assert_fault(
        run(&[block.finish(false, true)], 1, 1 << 17),
        Rar5Fault::EmptyTable,
    );
}

/// Section 3.2: a later block with the table bit clear uses the tables the
/// block before it left behind.
#[test]
fn a_later_block_reuses_the_tables_before_it() {
    let mut first = BlockBuilder::default();
    first.literals(b"one");
    let mut second = BlockBuilder::default();
    second.literals(b"two");
    let out = run(
        &[first.finish(true, false), second.finish(false, true)],
        6,
        1 << 17,
    )
    .unwrap();
    assert_eq!(out, b"onetwo");
}

/// A main alphabet of four letters at two bits: a table set no default
/// block builds, so bytes decoded under the wrong set cannot come out
/// right by accident.
fn four_letter_block() -> BlockBuilder {
    BlockBuilder::default().with_main(&b"aipr".map(usize::from), 2)
}

/// One solid chain of hand built members, each `(packed, unpacked)`,
/// answering every member's outcome and bytes.
fn chain(members: &[(Vec<u8>, u64)]) -> Vec<(crate::Result<()>, Vec<u8>)> {
    let mut lz = Rar5Lz::new(1 << 17, &policy()).expect("window");
    members
        .iter()
        .map(|(packed, unpacked)| {
            let mut sink: Vec<u8> = Vec::new();
            let mut source = SliceSource::new(packed);
            let outcome = lz.member(&mut source, *unpacked, 0, &mut sink);
            (outcome, sink)
        })
        .collect()
}

/// Section 3.2 across a ZERO BYTE member: a member that declares no bytes
/// but carries a block with a table set leaves THAT set in force, and the
/// member after it, whose first block has the table bit clear, decodes
/// under it. Reference `rar` 7.23 at `-m3 -s` gives every fifteenth member
/// of a solid stream such a block even when the member is empty; before
/// 27 Sep 2026
/// the zero byte member's block was never read, and the member after it
/// decoded under the older set (239 of 4,878 members of a Python tree
/// failed their checksum where reference `unrar` passed them).
#[test]
fn zero_byte_member_tables_carry_to_the_next_member() {
    let mut first = BlockBuilder::default();
    first.literals(b"hello");
    let empty = four_letter_block();
    let mut next = four_letter_block();
    next.literals(b"pair");
    let out = chain(&[
        (first.finish(true, true), 5),
        (empty.finish(true, true), 0),
        (next.finish(false, true), 4),
    ]);
    for (outcome, _) in &out {
        assert!(outcome.is_ok(), "{outcome:?}");
    }
    let bytes: Vec<&[u8]> = out.iter().map(|(_, bytes)| bytes.as_slice()).collect();
    assert_eq!(bytes, [&b"hello"[..], b"", b"pair"]);
}

/// A zero byte member with NO packed bytes changes nothing: the set before
/// it stays in force for the member after it.
#[test]
fn a_zero_byte_member_with_no_blocks_keeps_the_set_in_force() {
    let mut first = BlockBuilder::default();
    first.literals(b"one");
    let mut next = BlockBuilder::default();
    next.literals(b"two");
    let out = chain(&[
        (first.finish(true, true), 3),
        (Vec::new(), 0),
        (next.finish(false, true), 3),
    ]);
    assert!(out.iter().all(|(outcome, _)| outcome.is_ok()));
    assert_eq!(out[2].1, b"two");
}

/// A zero byte member whose block does not read cannot fail: it owes no
/// bytes. It DROPS the set in force instead, so the member after it that
/// leans on a carried set is `EmptyTable` rather than bytes decoded under
/// a set its writer did not mean.
#[test]
fn a_damaged_zero_byte_member_drops_the_set_in_force() {
    let mut first = BlockBuilder::default();
    first.literals(b"hello");
    let mut damaged = four_letter_block().finish(true, true);
    // The header check byte (section 3.2).
    damaged[1] ^= 0xff;
    let mut next = four_letter_block();
    next.literals(b"pair");
    let mut out = chain(&[
        (first.finish(true, true), 5),
        (damaged, 0),
        (next.finish(false, true), 4),
    ]);
    assert!(out[0].0.is_ok());
    assert!(out[1].0.is_ok(), "{:?}", out[1].0);
    assert_fault(out.remove(2).0, Rar5Fault::EmptyTable);
}

/// Section 3.5, "No count of extra bits is refused": a distance slot of 66
/// to 79, which only a version 1 member's alphabet holds, is READ, its
/// count of extra bits less four as plain bits and then one alignment
/// symbol, and its match goes to the window like any other. Until 11 Oct
/// 2026 such a slot was `DistanceSlot` before a bit of it was taken.
///
/// Each arm is one literal and one fresh match at the slot, in a block
/// that ends on the match's last bit. With every bit there the match is
/// taken, as zero bytes, and the member is whole. With the last bit
/// missing the block ends inside the match and the member fails, so a
/// reader that took one bit fewer than the slot has would be caught by
/// the second arm and one that took more by the first.
#[test]
fn a_distance_slot_past_thirty_one_extra_bits_is_read_and_gives_zeros() {
    use super::tables::{ALIGN_SYMBOLS, LENGTH_SYMBOLS, MAIN_SYMBOLS};
    use super::vectors::{frame, BitWriter, ALIGN_WIDTH, LENGTH_WIDTH, MAIN_WIDTH};
    // A version 1 member: 80 distance symbols of 7 bits each, and an
    // alignment code of sixteen equal lengths.
    let member = |slot: u32, plain: u32, bits_after_slot: u32| {
        let mut payload = BitWriter::default();
        for _ in 0..super::tables::LEVEL_SYMBOLS {
            payload.put(5, 4);
        }
        let lengths: Vec<u8> = std::iter::repeat_n(MAIN_WIDTH, MAIN_SYMBOLS)
            .chain(std::iter::repeat_n(7, 80))
            .chain(std::iter::repeat_n(ALIGN_WIDTH, ALIGN_SYMBOLS))
            .chain(std::iter::repeat_n(LENGTH_WIDTH, LENGTH_SYMBOLS))
            .collect();
        for length in lengths {
            payload.put(u32::from(length), 5);
        }
        payload.put(u32::from(b'z'), u32::from(MAIN_WIDTH));
        payload.put(262, u32::from(MAIN_WIDTH));
        payload.put(slot, 7);
        // The plain bits, all ones, and then the alignment code's symbol
        // 0, which is all zeros (the vectors' alignment code is five bits
        // wide and its sixteen symbols are the codes 0 to 15). A bit at a
        // time, so that an arm may stop one short.
        for bit in 0..bits_after_slot {
            payload.put(u32::from(bit < plain), 1);
        }
        let packed = frame(&payload, true, true);
        let mut lz = Lz::new(1 << 17, &policy()).unwrap();
        let mut sink: Vec<u8> = Vec::new();
        let mut source = SliceSource::new(&packed);
        // One literal and a fresh match of length slot 0, which with the
        // three bytes a far distance adds is five zeros.
        lz.member(&mut source, 6, 1, &mut sink).map(|()| {
            assert_eq!(sink, b"z\0\0\0\0\0", "slot {slot}");
        })
    };
    for (slot, count) in [(66u32, 32u32), (67, 32), (70, 34), (78, 38), (79, 38)] {
        let plain = count - 4;
        let whole = plain + u32::from(ALIGN_WIDTH);
        member(slot, plain, whole).expect("the slot is read and nothing is said");
        member(slot, plain, whole - 1).expect_err("the block ends inside the match");
    }
}

/// A version 1 member DECODES (section 3.3): its tables are 446
/// lengths, 80 of them distance, and the symbols after them read exactly
/// as version 0's. The same block with 430 lengths is the version 0 case,
/// and reading one as the other is out of step by 16 lengths, so each is
/// also run at the other version to show the version is what decides it.
#[test]
fn a_version_one_member_reads_446_lengths_and_decodes() {
    let body = |block: &mut BlockBuilder| {
        block.literals(b"abcdefgh");
        let (slot, extra) = distance_slot(4);
        block.fresh(1, 0, slot, extra); // length slot 1 is three
        block.literals(b"!");
    };
    let want = b"abcdefghefg!".to_vec();

    let mut v1 = BlockBuilder::default();
    v1.distance = vec![7; 80];
    body(&mut v1);
    let v1 = v1.finish(true, true);
    let mut v0 = BlockBuilder::default();
    body(&mut v0);
    let v0 = v0.finish(true, true);

    let decode = |packed: &[u8], algorithm: u8| {
        let mut lz = Lz::new(1 << 17, &policy()).unwrap();
        let mut sink: Vec<u8> = Vec::new();
        let mut source = SliceSource::new(packed);
        lz.member(&mut source, want.len() as u64, algorithm, &mut sink)
            .map(|()| sink)
    };
    assert_eq!(decode(&v1, 1).unwrap(), want);
    assert_eq!(decode(&v0, 0).unwrap(), want);
    assert!(decode(&v1, 0).map_or(true, |out| out != want));
    assert!(decode(&v0, 1).map_or(true, |out| out != want));
}

/// Section 3.7 as amended on 11 Oct 2026: a match at a distance greater than the
/// bytes the stream has produced gives a zero for each of its bytes and is
/// no fault; a distance above the declared dictionary copies the bytes at
/// the distance as long as it is no more than 256 KiB, and gives zeros
/// above that though the stream holds bytes there.
#[test]
fn a_distance_past_the_stream_or_the_window_gives_zeros_and_is_no_fault() {
    let mut block = BlockBuilder::default();
    block.literals(b"window");
    // Length slot 3 is five bytes, and 23 back from the seventh byte of a
    // stream is before its start for every one of them.
    let (slot, extra) = distance_slot(23);
    block.fresh(3, 0, slot, extra);
    let out = run(&[block.finish(true, true)], 11, 1 << 17).expect("no fault");
    assert_eq!(out, b"window\0\0\0\0\0");

    // Past the declared window of 128 KiB with the bytes present: the
    // larger of it and 256 KiB is what a match is honoured to.
    let filler: Vec<u8> = (0..400_000u32).map(|i| (i % 251) as u8).collect();
    for (far, honoured) in [
        (131_073usize, true),
        (150_000, true),
        (262_144, true),
        (262_145, false),
        (300_000, false),
    ] {
        let mut block = BlockBuilder::default();
        block.literals(&filler);
        let (slot, extra) = distance_slot(far);
        block.fresh(0, 0, slot, extra);
        // Length slot 0 is 2, and a distance past 0x40000 adds all three
        // of a fresh match's bytes, one past 0x2000 two of them.
        let length = if far > 0x4_0000 { 5 } else { 4 };
        let out = run(
            &[block.finish(true, true)],
            (filler.len() + length) as u64,
            1 << 17,
        )
        .expect("no fault");
        let from = filler.len() - far;
        let want: Vec<u8> = if honoured {
            filler[from..from + length].to_vec()
        } else {
            vec![0; length]
        };
        assert_eq!(out.len(), filler.len() + length, "distance {far}");
        assert!(
            out[..filler.len()] == filler[..],
            "distance {far}: the literals"
        );
        assert_eq!(out[filler.len()..], want[..], "distance {far}");
    }
}

/// Section 3.6: a record whose type field is 4 or above is `FilterType`,
/// and a span that leaves the member is `FilterRange`.
#[test]
fn a_filter_records_type_and_span_are_bounded() {
    let mut block = BlockBuilder::default();
    block.filter(0, 4, 4, 0);
    block.literals(b"abcd");
    assert_fault(
        run(&[block.finish(true, true)], 4, 1 << 17),
        Rar5Fault::FilterType,
    );

    let mut block = BlockBuilder::default();
    block.filter(0, 64, 1, 0);
    block.literals(b"abcd");
    assert_fault(
        run(&[block.finish(true, true)], 4, 1 << 17),
        Rar5Fault::FilterRange,
    );
}

/// Section 3.6: a record whose length is zero names an empty span and is a
/// no operation, not an error.
#[test]
fn an_empty_filter_span_is_a_no_operation() {
    let mut block = BlockBuilder::default();
    block.filter(0, 0, 1, 0);
    block.literals(b"abcd");
    assert_eq!(
        run(&[block.finish(true, true)], 4, 1 << 17).unwrap(),
        b"abcd"
    );
}

/// Section 3.3: a repeat of the previous code length that arrives first is
/// `RepeatAtStart`, and a code length alphabet symbol above 19 cannot be
/// reached from a 20 symbol alphabet.
#[test]
fn v5_repeat_at_start_is_refused() {
    use super::vectors::{frame, BitWriter};
    let mut payload = BitWriter::default();
    for _ in 0..super::tables::LEVEL_SYMBOLS {
        payload.put(5, 4);
    }
    // Symbol 16: repeat the previous length, with nothing written yet.
    payload.put(16, 5);
    payload.put(0, 3);
    let packed = frame(&payload, true, true);
    let mut lz = Lz::new(1 << 17, &policy()).unwrap();
    let mut sink: Vec<u8> = Vec::new();
    let mut source = SliceSource::new(&packed);
    assert_fault(
        lz.member(&mut source, 8, 0, &mut sink),
        Rar5Fault::RepeatAtStart,
    );
}
