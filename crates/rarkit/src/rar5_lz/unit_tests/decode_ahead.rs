//! The SOLID CHAIN's decode-ahead (section 3.8, `rar5_lz::ahead`).

use super::*;

/// Decode every LZ member of one archive with the chain's decode-ahead
/// fed, which is what spec F's read path does from its own header walk.
///
/// The members AFTER the one about to be decoded are offered first, so the
/// lanes decode them while this thread applies it. That order is the whole
/// of the lever and it is what this helper exists to reproduce.
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
fn decode_archive_ahead(data: &[u8], depth: usize) -> Vec<(String, Vec<u8>)> {
    let all = members(data);
    let mut out = Vec::new();
    let mut decoder: Option<Rar5Lz> = None;
    // The first member not yet offered: a member is offered ONCE, and a
    // member the stage refused for now is offered again at the next turn
    // rather than skipped (the seam's `offer_from` says why).
    let mut offered = 0usize;
    for (index, member) in all.iter().enumerate() {
        if member.directory || member.method == 0 {
            continue;
        }
        if !member.solid || decoder.is_none() {
            decoder = Some(Rar5Lz::new(member.window, &policy()).expect("window"));
        }
        let lz = decoder.as_mut().expect("a decoder for this member");
        let mut at = offered.max(index + 1);
        while at < all.len() && at <= index + depth {
            let next = &all[at];
            if next.directory || next.method == 0 || !next.solid {
                break;
            }
            if !lz.offer_ahead(&next.packed, next.unpacked, next.algorithm) {
                break;
            }
            at += 1;
        }
        offered = at;
        let mut sink: Vec<u8> = Vec::new();
        let mut source = SliceSource::new(&member.packed);
        lz.member(&mut source, member.unpacked, member.algorithm, &mut sink)
            .expect("the vector archives decode");
        out.push((member.name.clone(), sink));
    }
    out
}

/// Section 3.8's consequence 2, across a MEMBER boundary: a chain decoded
/// ahead of the apply stage is byte identical to the serial one, at every
/// depth, and the lever genuinely ran.
///
/// The claim counter is the only witness that it ran at all. That is the
/// point of the stage - the bytes are identical either way - and a test
/// that checked the bytes alone would pass just as well with the whole of
/// `ahead` deleted.
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_solid_chain_decoded_ahead_gives_the_serial_bytes() {
    for stem in ["h5_solid", "h5_solid_mixed"] {
        let data = archive(stem);
        let serial = decode_archive(&data, false);
        assert!(
            serial.len() > 1,
            "{stem} is not a chain, so it tests nothing here"
        );
        for depth in [1usize, 2, 3, 8, 64] {
            let _counting = counting();
            let ahead = decode_archive_ahead(&data, depth);
            assert_eq!(ahead, serial, "{stem} differed at depth {depth}");
            assert!(
                crate::probe::ahead_claims() > 0,
                "{stem} at depth {depth} never reached the decode-ahead, so \
                 this comparison proves nothing"
            );
        }
    }
}

/// THE TAPE PATH'S ARM of `V5-SOLIDFILT` (section 3.6), which
/// the measurements left open for whoever changed the extent of a
/// plan: a filter record's span is member relative, and the reading that
/// makes it stream relative "differs only in a solid chain and would
/// silently corrupt filtered members after the first".
///
/// `v5_solidfilt_a_filter_after_a_solid_member_is_member_relative` pins
/// that on the SERIAL path. This is the same vector with the chain's
/// decode-ahead running, which is the arm that did not exist when that
/// test was written: the filtered member is now decoded on another thread
/// while the member in front of it is applied.
///
/// It passes for a reason worth stating rather than discovering: the raw
/// record is what the tape carries, and `Record::resolve` is called from
/// `tape::apply` against `Window::produced()`, which `begin_member()` has
/// reset. Nothing the lanes do can reach either.
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn v5_solidfilt_holds_with_the_chain_decoded_ahead() {
    let data = archive("h5_solid_mixed");
    let serial = decode_archive(&data, false);
    let _counting = counting();
    let ahead = decode_archive_ahead(&data, 64);
    assert!(crate::probe::ahead_claims() > 0);
    // The member decoded ALONE is the reference the serial arm's own
    // V5-SOLIDFILT test uses, and it is what a stream relative base would
    // break. Every member of the chain is compared against the serial
    // arm, which that test has already tied to the standalone decode.
    assert_eq!(ahead, serial);
}

/// The eligibility rule of `ahead`, shown to BITE: a member whose first
/// block does not carry its own table set is not offered WHEN NO RUN IS
/// OPEN, because its symbols depend on a group an earlier member opened
/// and the stage holds nothing of that member.
///
/// Removing the `has_tables` test in `Ahead::eligible` is what this
/// catches. It is checked by construction rather than by a decode,
/// because a member of that shape is what reference `rar` writes only
/// sometimes and a test may not depend on which. The case where a run IS
/// open, and such a member joins it, is the carry's own tests below.
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
#[test]
fn a_member_that_opens_no_table_group_is_never_decoded_ahead() {
    use super::ahead::Ahead;
    let data = archive("h5_solid");
    let all = members(&data);
    let member = all
        .iter()
        .find(|m| !m.directory && m.method != 0)
        .expect("a compressed member");
    let stage = Ahead::new(u64::MAX, 4);
    assert!(
        stage.eligible(&member.packed, member.unpacked),
        "a member whose first block carries tables must be offerable"
    );
    // The same bytes with the table bit of the first block CLEARED, and
    // the header's own check kept intact so the refusal under test is the
    // only one that can fire. Section 3.2's check is the flags byte
    // exclusive-or'd with the check byte and then with every size byte, so
    // clearing a flag bit and flipping the same bit of the check byte
    // leaves the accumulator where it was.
    let mut cleared = member.packed.clone();
    let first = super::block::block_in_hand(&cleared).expect("a first block");
    assert!(
        first.carries_tables(),
        "the fixture's first block carries tables"
    );
    cleared[0] &= !super::block::FLAG_TABLES;
    cleared[1] ^= super::block::FLAG_TABLES;
    let without = super::block::block_in_hand(&cleared)
        .expect("the header's own check must still pass, or this tests nothing");
    assert!(
        !without.carries_tables(),
        "the mutation did not clear the table bit"
    );
    assert!(
        !stage.eligible(&cleared, member.unpacked),
        "a member whose first block opens no table group was offered"
    );
}

/// Section 4.2, and a stated budget is hard: what the stage holds is bounded by the
/// caller's STATED budget, and a budget too small for one member turns
/// the lever off rather than growing past it.
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
#[test]
fn the_decode_ahead_holds_no_more_than_the_stated_budget() {
    use super::ahead::Ahead;
    let data = archive("h5_solid");
    let all = members(&data);
    let offerable: Vec<_> = all
        .iter()
        .filter(|m| !m.directory && m.method != 0 && m.solid)
        .collect();
    assert!(!offerable.is_empty(), "the fixture has no solid member");
    let one = offerable[0].packed.len() as u64 + offerable[0].unpacked;

    // A budget under one member's charge takes nothing at all.
    let mut tight = Ahead::new(one - 1, 4);
    for member in &offerable {
        assert!(
            !tight.offer(&member.packed, member.unpacked, member.algorithm),
            "a stated budget too small for one member was exceeded"
        );
    }
    assert_eq!(tight.in_flight(), 0);
    assert_eq!(tight.charged(), 0);

    // A budget for exactly one holds exactly one, and says it is full.
    let mut narrow = Ahead::new(one, 4);
    let mut taken = 0usize;
    for member in &offerable {
        if narrow.offer(&member.packed, member.unpacked, member.algorithm) {
            taken += 1;
        }
    }
    assert!(taken <= 1, "a stated budget for one member took {taken}");
    assert!(narrow.charged() <= one);
    if taken == 1 {
        assert!(narrow.full(), "a full stage must tell its feeder to stop");
    }
    narrow.clear();
    assert_eq!(narrow.charged(), 0);
}

/// Every candidate scan priced against the split body writes exactly what
/// the shipped pass writes.
///
/// The candidates change ONE thing each about phase one and nothing about
/// phase two: the trigger window's size, two independent word loads a step
/// instead of one, and a sixteen byte NEON compare. None of them ships
/// unless the subtraction says it wins, but a candidate that is not
/// byte-equivalent is not a candidate at all, and a probe that times three
/// arms without this test behind it is timing three different transforms.
///
/// Held to `x86_pass_equivalence_cases`, the same shapes the shipped body
/// is held to, so a candidate cannot pass on an easier set. Both record
/// types, both directions and both offset rules, over seven `F` values.
///
/// Shown to FAIL, by making each change and running it: dropping the
/// `position < resume` test in the wide arm, and taking the NEON arm's
/// lane index from the bit rather than from the nibble.
#[test]
#[cfg(feature = "bench-internals")]
fn the_split_candidates_agree_with_the_shipped_pass() {
    use crate::carry::h_ours::codec::address_filters as af;

    let cases = x86_pass_equivalence_cases();
    for (index, case) in cases.iter().enumerate() {
        for offset in [0u32, 1, 5, 0x00FF_FFFF, 0x0100_0000, 0x8000_0000, u32::MAX] {
            macro_rules! for_both_late {
                ($batch:literal) => {{
                    let mut want = case.clone();
                    let mut got = case.clone();
                    af::x86_pass::<false, true, true>(&mut want, offset);
                    af::x86_pass_split_late::<false, true, true, $batch>(&mut got, offset);
                    assert_eq!(
                        want, got,
                        "late skip BATCH {}: case {index}, decode, call+jump, rar5, f {offset}",
                        $batch
                    );

                    let mut want = case.clone();
                    let mut got = case.clone();
                    af::x86_pass::<true, false, false>(&mut want, offset);
                    af::x86_pass_split_late::<true, false, false, $batch>(&mut got, offset);
                    assert_eq!(
                        want, got,
                        "late skip BATCH {}: case {index}, encode, call, rar3, f {offset}",
                        $batch
                    );
                }};
            }

            macro_rules! agrees {
                ($name:literal, $candidate:ident) => {{
                    // decode, call and jump, the RAR 5 offset rule: the
                    // shape `rar5_code_32m_m3_serial` actually carries.
                    let mut want = case.clone();
                    let mut got = case.clone();
                    af::x86_pass::<false, true, true>(&mut want, offset);
                    af::$candidate::<false, true, true>(&mut got, offset);
                    assert_eq!(
                        want, got,
                        "{}: case {index}, decode, call+jump, rar5, f {offset}",
                        $name
                    );

                    // encode, calls alone, the RAR 3 offset rule: the other
                    // corner of the eight instantiations.
                    let mut want = case.clone();
                    let mut got = case.clone();
                    af::x86_pass::<true, false, false>(&mut want, offset);
                    af::$candidate::<true, false, false>(&mut got, offset);
                    assert_eq!(
                        want, got,
                        "{}: case {index}, encode, call, rar3, f {offset}",
                        $name
                    );
                }};
            }

            // The window size, at a quarter and four times the shipped 256.
            let mut want = case.clone();
            let mut got = case.clone();
            af::x86_pass::<false, true, true>(&mut want, offset);
            af::x86_pass_split_batch::<false, true, true, 64>(&mut got, offset);
            assert_eq!(want, got, "BATCH 64: case {index}, decode, f {offset}");

            let mut got = case.clone();
            af::x86_pass_split_batch::<false, true, true, 1024>(&mut got, offset);
            assert_eq!(want, got, "BATCH 1024: case {index}, decode, f {offset}");

            let mut want = case.clone();
            let mut got = case.clone();
            af::x86_pass::<true, false, false>(&mut want, offset);
            af::x86_pass_split_batch::<true, false, false, 64>(&mut got, offset);
            assert_eq!(
                want, got,
                "BATCH 64: case {index}, encode, rar3, f {offset}"
            );

            agrees!("two words a step", x86_pass_split_wide);
            // The late arm at the SHIPPED window and at the smallest one
            // the scan permits. The small window is the case that matters:
            // this arm's whole correctness argument is that its cursor
            // carries ACROSS windows, and at 256 a 20,000 byte case has
            // about eight boundaries while at 8 it has hundreds, so the
            // mutation "reset the cursor per window" has somewhere to show.
            for_both_late!(256);
            for_both_late!(8);
            #[cfg(target_arch = "aarch64")]
            agrees!("NEON sixteen bytes", x86_pass_split_neon);
            // The SHIPPABLE NEON arm, which differs from the prototype
            // above in one way only: it carries the sparse memchr path.
            // The barren cases in this set are what hold that path, and
            // they are why the prototype's figure is not a licence to ship
            // the prototype.
            #[cfg(target_arch = "aarch64")]
            agrees!("NEON sixteen bytes, shippable", x86_pass_neon16);
        }
    }
}
