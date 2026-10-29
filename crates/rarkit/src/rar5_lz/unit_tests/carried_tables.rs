//! THE CARRIED TABLE GROUP across a member boundary (section 3.2, 3.8;
//! `rar5_lz::ahead`'s runs).

use super::*;

// ---------------------------------------------------------------------------
// THE CARRIED TABLE GROUP across a member boundary (section 3.2, 3.8;
// `rar5_lz::ahead`'s runs).
// ---------------------------------------------------------------------------

/// One hand-built member of a chain: its blocks and its declared size.
#[cfg(feature = "parallel")]
type HandMember = (Vec<u8>, u64);

/// Decode a hand-built solid chain with EVERY member offered to the
/// decode-ahead before the first is decoded, answering each member's bytes
/// or its error. The offers are made up front because the stage is what
/// is under test here, not an offering layer.
#[cfg(feature = "parallel")]
fn decode_hand_chain_ahead(chain: &[HandMember]) -> Vec<Result<Vec<u8>, String>> {
    let mut lz = Lz::new(1 << 17, &policy()).expect("window");
    // ONE LANE, so every run of the chain goes to the same lane and a set
    // carried out of one run is what the lane holds when the next run's
    // head arrives, which is what the stale-carry case corrupts. The lane
    // is opened by name under a width of two: at a width of ONE the stage
    // opens no lane at all (SPEC-API 8.4.2; the test below
    // this helper's holds that), and a stage opened at one lane grows
    // only after eight waits, which no chain here is long enough to make.
    lz.set_tape_width(2);
    lz.set_ahead_lanes(1);
    for (packed, unpacked) in chain {
        // Refusals are not errors: a member the stage does not take
        // decodes on the path it always did, and the test reads the claim
        // counter to know which happened.
        let _ = lz.offer_ahead(packed, *unpacked, 0);
    }
    decode_hand_chain_with(&mut lz, chain)
}

/// AT A WIDTH OF ONE THE CHAIN'S DECODE-AHEAD OPENS NO LANE (SPEC-API
/// 8.4.2: "At a width of one (`-mt1`) NO decode lane runs
/// beside the caller: the one decode lane is the caller's own thread,
/// which decodes, applies and writes"). Every offer is refused, nothing is
/// claimed, and the chain decodes to the serial arm's bytes on the calling
/// thread; at a width of two the same chain is taken whole.
///
/// FAILS on the build before 2 Oct 2026, which opened the stage's lane
/// beside the caller at a width of one and claimed all three members.
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_width_of_one_opens_no_decode_ahead_lane() {
    let chain = vec![
        one_bit_member(b"ab", b"abba", true),
        one_bit_member(b"ab", b"baab", false),
        one_bit_member(b"ab", b"aaab", false),
    ];
    let serial = decode_hand_chain_serial(&chain);
    let _counting = counting();
    let mut lz = Lz::new(1 << 17, &policy()).expect("window");
    lz.set_tape_width(1);
    for (packed, unpacked) in &chain {
        assert!(
            !lz.offer_ahead(packed, *unpacked, 0),
            "a member was taken by the decode-ahead at a width of one"
        );
    }
    assert!(
        lz.ahead_full(),
        "a walk in front of a width of one is told to stop"
    );
    assert_eq!(decode_hand_chain_with(&mut lz, &chain), serial);
    assert_eq!(
        crate::probe::ahead_claims(),
        0,
        "a member was decoded on a lane beside the caller at a width of one"
    );
    // The same decoder at a width of two takes the chain: the rule is the
    // width's and nothing else's.
    let ahead = decode_hand_chain_ahead(&chain);
    assert_eq!(ahead, serial);
    assert_eq!(crate::probe::ahead_claims(), 3);
}

/// The same chain decoded SERIALLY, member after member, on a fresh
/// decoder that was offered nothing.
#[cfg(feature = "parallel")]
fn decode_hand_chain_serial(chain: &[HandMember]) -> Vec<Result<Vec<u8>, String>> {
    let mut lz = Lz::new(1 << 17, &policy()).expect("window");
    lz.set_parallel(false);
    decode_hand_chain_with(&mut lz, chain)
}

#[cfg(feature = "parallel")]
fn decode_hand_chain_with(lz: &mut Lz, chain: &[HandMember]) -> Vec<Result<Vec<u8>, String>> {
    chain
        .iter()
        .map(|(packed, unpacked)| {
            let mut sink: Vec<u8> = Vec::new();
            let mut source = SliceSource::new(packed);
            lz.member(&mut source, *unpacked, 0, &mut sink)
                .map(|()| sink)
                .map_err(|e| format!("{:?}", e.kind()))
        })
        .collect()
}

/// A member of one block under a main alphabet of just `symbols`, every
/// code one bit wide, holding `text`. `tables` says whether the block
/// carries the set or uses the one in force.
#[cfg(feature = "parallel")]
fn one_bit_member(symbols: &[u8], text: &[u8], tables: bool) -> HandMember {
    let alphabet: Vec<usize> = symbols.iter().map(|&b| usize::from(b)).collect();
    let mut block = BlockBuilder::default().with_main(&alphabet, 1);
    block.literals(text);
    (block.finish(tables, true), text.len() as u64)
}

/// A run of members sharing ONE table set is decoded ahead as a run: the
/// head opens the set, the members behind it use it, and every one of
/// them is claimed.
///
/// Before the carry existed the two members behind the head were refused
/// by construction (`a_member_that_opens_no_table_group_is_never_decoded_ahead`
/// above pins the rule that still refuses them when no run is open).
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_run_of_members_sharing_one_table_set_is_decoded_ahead() {
    let chain = vec![
        one_bit_member(b"ab", b"abba", true),
        one_bit_member(b"ab", b"baab", false),
        one_bit_member(b"ab", b"aaab", false),
    ];
    let serial = decode_hand_chain_serial(&chain);
    assert_eq!(
        serial,
        vec![
            Ok(b"abba".to_vec()),
            Ok(b"baab".to_vec()),
            Ok(b"aaab".to_vec())
        ]
    );
    let _counting = counting();
    let ahead = decode_hand_chain_ahead(&chain);
    assert_eq!(ahead, serial);
    assert_eq!(
        crate::probe::ahead_claims(),
        3,
        "the run's members were not all decoded ahead"
    );
}

/// THE STALE CARRY, and the equivalence above is shown to have teeth: with
/// the lane made to keep the previous run's set across a run head, the
/// member behind the head decodes under the wrong set and the bytes are
/// wrong. The knob is process wide, so the counter lock covers it.
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_stale_carried_set_is_a_wrong_byte_and_the_comparison_sees_it() {
    // Two runs. The second run's alphabet names different bytes with the
    // same one-bit codes, so a member of it decoded under the first run's
    // set comes out as the other letters, byte for byte the same length.
    let chain = vec![
        one_bit_member(b"ab", b"abab", true),
        one_bit_member(b"ab", b"bbaa", false),
        one_bit_member(b"cd", b"cdcd", true),
        one_bit_member(b"cd", b"ddcc", false),
    ];
    let serial = decode_hand_chain_serial(&chain);
    assert!(serial.iter().all(Result::is_ok));
    let _counting = counting();
    crate::probe::set_ahead_carry_stale(true);
    let corrupted = decode_hand_chain_ahead(&chain);
    crate::probe::set_ahead_carry_stale(false);
    assert_eq!(
        crate::probe::ahead_claims(),
        4,
        "the corruption did not reach a claimed member, so it tested nothing"
    );
    assert_ne!(
        corrupted, serial,
        "a stale carried set produced the serial bytes, so the carry is \
         not what the equivalence rests on"
    );
    assert_eq!(
        corrupted[3],
        Ok(b"bbaa".to_vec()),
        "the member behind the second head decoded under the first run's set"
    );
    // And the same chain without the corruption is the serial bytes, with
    // every member claimed.
    crate::probe::reset_ahead_claims();
    let ahead = decode_hand_chain_ahead(&chain);
    assert_eq!(ahead, serial);
    assert_eq!(crate::probe::ahead_claims(), 4);
}

/// A member that reaches its declared size BEFORE its last table-carrying
/// block still DECODES that block (SPEC-H2 3.1, amended 28 Sep
/// 2026), so the later set is the one in force for the member behind it,
/// in the serial arm and on the decode-ahead alike, and nothing is
/// poisoned: the lane carried the set the apply stage finished under.
///
/// Before that change the serial arm stopped at the declared size, left the
/// earlier set in force, and the decode-ahead's check in `Ahead::give`
/// poisoned the run so the member behind decoded serially as `aba`. The
/// check stays (`rar5_lz::ahead`'s header says why), and this chain is
/// what shows it no longer fires where the arms agree.
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_member_that_ends_before_its_last_table_set_still_carries_it() {
    // The first member: block one carries the `ab` set and produces the
    // whole declared size; block two carries a `cd` set and one surplus
    // symbol, both decoded past the declared end.
    let mut first = BlockBuilder::default().with_main(&[97, 98], 1);
    first.literals(b"aaa");
    let mut second = BlockBuilder::default().with_main(&[99, 100], 1);
    second.literals(b"c");
    let mut packed = first.finish(true, false);
    packed.extend_from_slice(&second.finish(true, true));
    let ends_early: HandMember = (packed, 3);
    // The member behind it: the bits `010`, which are `aba` under the
    // `ab` set and `cdc` under the `cd` one.
    let behind = one_bit_member(b"ab", b"aba", false);
    let chain = vec![ends_early, behind];

    let serial = decode_hand_chain_serial(&chain);
    assert_eq!(serial, vec![Ok(b"aaa".to_vec()), Ok(b"cdc".to_vec())]);

    let _counting = counting();
    let ahead = decode_hand_chain_ahead(&chain);
    assert_eq!(
        ahead, serial,
        "the decode-ahead disagrees with the serial arm"
    );
    assert_eq!(
        crate::probe::ahead_claims(),
        2,
        "both members are claimed: the lane's carried set is the one the \
         apply stage finished under, so nothing is poisoned"
    );
}

/// A member the offering layer steps over between two offered ones does
/// not cost the front of the queue: the claim for it fails on content and
/// the front WAITS for the member it was decoded for.
///
/// Every member here declares the same size, which is the shape that lost
/// 158 to 199 of 200 claims before (22 Sep 2026): the
/// stepped-over member matched the front's size key, failed on content,
/// and the front was discarded as never reached.
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_stepped_over_member_does_not_cost_the_queues_front() {
    let head = one_bit_member(b"ab", b"abba", true);
    let stepped_over = one_bit_member(b"ab", b"bbbb", true);
    let after = one_bit_member(b"ab", b"aabb", true);
    let chain = vec![head.clone(), stepped_over.clone(), after.clone()];
    let serial = decode_hand_chain_serial(&chain);

    let _counting = counting();
    let mut lz = Lz::new(1 << 17, &policy()).expect("window");
    // Offer the first and the third, never the second.
    assert!(lz.offer_ahead(&head.0, head.1, 0));
    assert!(lz.offer_ahead(&after.0, after.1, 0));
    let ahead = decode_hand_chain_with(&mut lz, &chain);
    assert_eq!(ahead, serial);
    assert_eq!(
        crate::probe::ahead_claims(),
        2,
        "the third member's work was discarded when the second was claimed \
         against it"
    );
}

/// Offer each head member and claim it at once, so the claim meets a lane
/// that has not finished: the apply stage WAITS on every one. Returns how
/// many offers were claimed. Every member used opens its own table group,
/// so each offer is a run's head and no run carries anything.
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
fn drive_a_stalling_chain(stage: &mut super::ahead::Ahead, rounds: usize) -> usize {
    let data = archive("h5_solid");
    let heads: Vec<_> = members(&data)
        .into_iter()
        .filter(|m| !m.directory && m.method != 0)
        .filter(|m| super::block::block_in_hand(&m.packed).is_ok_and(|b| b.carries_tables()))
        .collect();
    assert!(
        !heads.is_empty(),
        "the fixture has no member opening a group"
    );
    let mut claimed = 0usize;
    for _ in 0..rounds {
        for m in &heads {
            if !stage.offer(&m.packed, m.unpacked, m.algorithm) {
                continue;
            }
            if let Some(work) = stage.claim(&m.packed, m.unpacked, m.algorithm) {
                claimed += 1;
                drop(work);
            }
        }
    }
    claimed
}

/// A STATED width opens every lane at once and never grows, however often
/// the apply stage waits: the dial is the caller's (SPEC-API 8.4.2).
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
#[test]
fn a_stated_width_opens_all_its_lanes_and_never_grows() {
    // Through `set_width`, which is how `Rar5Lz::set_tape_width` states a
    // width, and from a stage built wider, so the width is the setter's.
    let mut stage = super::ahead::Ahead::new(u64::MAX, 8);
    stage.set_width(3);
    let claimed = drive_a_stalling_chain(&mut stage, 200);
    assert!(
        claimed > 0,
        "the stage never took a member, so this tests nothing"
    );
    assert_eq!(
        stage.lanes_open(),
        3,
        "a stated width of three grew or shrank"
    );
}

/// The DEFAULT stage starts narrow and GROWS, one lane at a time, while
/// the apply stage keeps waiting on it, up to its ceiling and not past it
/// (`read::lanes::ahead_lanes`, `GROW_AFTER_STALLS`).
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
#[test]
fn a_default_stage_grows_to_its_ceiling_while_the_apply_waits() {
    let mut stage = super::ahead::Ahead::new(u64::MAX, 1);
    stage.set_lanes(1, 4);
    let mut rounds = 0usize;
    while stage.lanes_open() < 4 && rounds < 2_000 {
        drive_a_stalling_chain(&mut stage, 5);
        rounds += 5;
    }
    assert_eq!(
        stage.lanes_open(),
        4,
        "a stage waited on for {rounds} rounds did not grow to its ceiling"
    );
    drive_a_stalling_chain(&mut stage, 50);
    assert_eq!(stage.lanes_open(), 4, "the stage grew past its ceiling");
}
