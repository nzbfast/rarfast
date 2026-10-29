//! The paired chain search: each position gets the single search's list.

use super::*;

// ---- the paired chain search ------------------------------------------

/// Bytes of every shape a chain walk meets: text whose far copies start
/// on common words, bytes with nothing to find, a run of one byte (matches
/// that end at the limit), and plain few_words text.
fn every_walk(seed: u64) -> Vec<u8> {
    let mut input = far_sentences(40 << 10, seed);
    input.extend_from_slice(&nothing_to_find(4 << 10, seed));
    input.extend_from_slice(&[b'a'; 1500]);
    input.extend_from_slice(&few_words(12 << 10, seed ^ 5));
    input
}

#[test]
fn the_paired_search_gives_each_position_the_single_searchs_list() {
    // `chain::Links::search_pair` is two of `search`'s walks taken in
    // turn. At every position of a member, paired with the next position,
    // with one farther on and with one past the block's end, at the depths
    // and stops the ladder uses and at a reach the walks run out of, each
    // list is `search`'s own for that position: the same candidates in the
    // same order, the same count.
    use super::chain::{Chains, Found, FOUND_MAX, KEY_SHORT};
    use super::lz::Format;
    let input = every_walk(11);
    let lists = |found: &[Found; FOUND_MAX], kept: usize| -> Vec<(u32, u32)> {
        found[..kept]
            .iter()
            .map(|f| (f.distance, f.length))
            .collect()
    };
    let longests = [
        rar5::wire_for_tests().longest(),
        rar29::wire_for_tests().longest(),
    ];
    let mut compared = 0usize;
    for (reach, end) in [(1usize << 20, input.len()), (3000, input.len() - 777)] {
        let mut chains = Chains::new(reach, input.len(), usize::MAX, KEY_SHORT);
        let (heads, links) = (&mut chains.heads, &chains.links);
        links.insert(heads, &input, 0..input.len());
        for (round, (depth, enough)) in [(1u32, 32usize), (12, 64), (32, 256), (64, 256)]
            .into_iter()
            .enumerate()
        {
            let longest = longests[round % 2];
            let limit = |at: usize| end.saturating_sub(at).min(longest);
            let single = |at: usize| {
                let mut found = [Found::default(); FOUND_MAX];
                let kept = links.search(&input, at, limit(at), depth, enough, &mut found);
                lists(&found, kept)
            };
            let mut gap = 2usize;
            for at in 0..end {
                gap = 2 + (gap * 37 + at) % 300;
                for also in [at + 1, at + gap, end - 1, end + 2] {
                    let mut found = [[Found::default(); FOUND_MAX]; 2];
                    let kept = links.search_pair(
                        &input,
                        [at, also],
                        [limit(at), limit(also)],
                        depth,
                        enough,
                        &mut found,
                    );
                    let what = format!("{at} with {also}, {depth} links, reach {reach}");
                    assert_eq!(lists(&found[0], kept[0]), single(at), "{what}");
                    if also < input.len() {
                        assert_eq!(lists(&found[1], kept[1]), single(also), "{what}");
                    } else {
                        assert_eq!(kept[1], 0, "{what}");
                    }
                    compared += kept[0] + kept[1];
                }
            }
        }
    }
    assert!(compared > 1_000_000, "{compared} candidates compared");
}

#[test]
fn the_paired_search_under_a_far_link_budget_is_the_single_searchs() {
    // Under a FAR-LINK BUDGET (`Links::set_far_budget`) a walk follows at
    // most the budget's count of candidates farther than 2 MiB back, and
    // the paired search ends each of its walks as the single search does:
    // the same list for every position, whichever position it is asked
    // with, at budgets of none, one, two and more than a walk can spend,
    // and with no budget. The member repeats a stretch of every kind of
    // walk past 2 MiB, so the positions of its second copy have near
    // candidates in the copy and far ones in the first.
    use super::chain::{Chains, Found, FAR_FROM, FOUND_MAX, KEY_SHORT};
    use super::lz::Format;
    let piece = every_walk(13);
    let mut input = piece.clone();
    input.extend_from_slice(&few_words(FAR_FROM + (64 << 10), 14));
    let again = input.len();
    input.extend_from_slice(&piece);
    let lists = |found: &[Found; FOUND_MAX], kept: usize| -> Vec<(u32, u32)> {
        found[..kept]
            .iter()
            .map(|f| (f.distance, f.length))
            .collect()
    };
    let longest = rar5::wire_for_tests().longest();
    let end = input.len();
    let limit = |at: usize| end.saturating_sub(at).min(longest);
    let mut chains = Chains::new(4 << 20, input.len(), usize::MAX, KEY_SHORT);
    chains
        .links
        .insert(&mut chains.heads, &input, 0..input.len());
    let mut far_kept = [0usize; 5];
    for (which, budget) in [Some(0), Some(1), Some(2), Some(u32::MAX), None]
        .into_iter()
        .enumerate()
    {
        chains.links.set_far_budget(budget);
        let links = &chains.links;
        for (depth, enough) in [(12u32, 64usize), (32, 256), (80, 256)] {
            let single = |at: usize| {
                let mut found = [Found::default(); FOUND_MAX];
                let kept = links.search(&input, at, limit(at), depth, enough, &mut found);
                lists(&found, kept)
            };
            let mut gap = 2usize;
            for at in (again..end).step_by(3) {
                gap = 2 + (gap * 37 + at) % 300;
                let alone = single(at);
                far_kept[which] += alone
                    .iter()
                    .filter(|(distance, _)| *distance as usize > FAR_FROM)
                    .count();
                for also in [at + 1, at + gap, end + 2] {
                    let mut found = [[Found::default(); FOUND_MAX]; 2];
                    let kept = links.search_pair(
                        &input,
                        [at, also],
                        [limit(at), limit(also)],
                        depth,
                        enough,
                        &mut found,
                    );
                    let what = format!("{at} with {also}, {depth} links, budget {budget:?}");
                    assert_eq!(lists(&found[0], kept[0]), alone, "{what}");
                    if also < input.len() {
                        assert_eq!(lists(&found[1], kept[1]), single(also), "{what}");
                    } else {
                        assert_eq!(kept[1], 0, "{what}");
                    }
                }
            }
        }
    }
    // The budget is what the lists turn on: none far with a budget of
    // none, some with one link, and no fewer as it grows.
    assert_eq!(far_kept[0], 0, "a budget of none kept a far candidate");
    assert!(far_kept[1] > 100, "{far_kept:?}");
    assert!(
        far_kept[1] <= far_kept[2] && far_kept[2] <= far_kept[3],
        "{far_kept:?}"
    );
    assert_eq!(
        far_kept[3], far_kept[4],
        "an unspendable budget is no budget"
    );
}

#[test]
fn the_lazy_parse_sends_the_same_tokens_whichever_positions_it_asks_at_together() {
    // The pairing is time and never a byte (`lz::Asked`): a block parsed
    // asking one position a search, and a position with the next from the
    // span's start, from early in it and from the middle of the block,
    // sends the same tokens, in both formats, with the backward extension and without, at every
    // chain effort of the ladder, from a block's start and from history.
    use super::chain::{Chains, Pairing, KEY_SHORT};
    use super::lz::{lazy_parse, Block, Format, PriceModel, Source, BACK_LIMIT};
    fn check<F: Format>(format: &F, input: &[u8], dictionary: usize) {
        let mut chains = Chains::new(dictionary, input.len(), usize::MAX, KEY_SHORT);
        let (heads, links) = (&mut chains.heads, &chains.links);
        links.insert(heads, input, 0..input.len());
        let third = input.len() / 3;
        let mut matches = 0usize;
        for (start, end) in [
            (0, third),
            (third, 2 * third + 1),
            (2 * third + 1, input.len()),
        ] {
            let block = Block {
                span: input,
                start,
                end,
                dictionary,
            };
            for (depth, enough) in [(1u32, 32usize), (3, 32), (12, 64), (32, 256), (64, 256)] {
                for back in [0, BACK_LIMIT] {
                    let parse = |pair: Pairing| {
                        let source = Source::Chains {
                            chains: links,
                            depth,
                            enough,
                            pair,
                        };
                        let mut tokens = Vec::new();
                        let mut model = PriceModel::new(format);
                        lazy_parse(format, block, source, &mut model, &mut tokens, back);
                        tokens
                            .iter()
                            .map(|t| (t.arm, t.length, t.distance))
                            .collect::<Vec<_>>()
                    };
                    let single = parse(Pairing::Single);
                    let covered: usize = single.iter().map(|t| t.1 as usize).sum();
                    assert_eq!(covered, end - start);
                    matches += single.iter().filter(|t| t.0 != Arm::Literal).count();
                    for from in [0, 1000, start + (end - start) / 2] {
                        assert!(
                            parse(Pairing::From(from)) == single,
                            "from {from}: block {start}..{end}, {depth} links, back {back}"
                        );
                    }
                }
            }
        }
        assert!(matches > 10_000, "{matches} matches");
    }
    let input = every_walk(23);
    check(&rar5::wire_for_tests(), &input, 1 << 20);
    check(&rar29::wire_for_tests(), &input, 1 << 20);
    check(&rar5::wire_for_tests(), &input, 3000);
}

#[test]
fn every_chain_level_writes_the_same_member_whichever_positions_it_asks_at_together() {
    // The encoder end to end: levels 2, 3 and 4, level 1 in its priced
    // form, and a short lone member at every level (level 5's is the one
    // chain effort the tree level runs), in both formats, on one thread and on the
    // pool, write the bytes the single search writes, and they decode.
    // Under the shipped pairing the long member is parsed in pairs past its
    // first bytes and the short one never (`Pairing::From`), and the
    // count of pairs over a span of each member's own length shows it;
    // paired from its first byte, the lone one is too. Both lengths are odd
    // ones no other test encodes.
    use super::chain::{Pairing, PAIRING, PROBE_PAIRS, PROBE_SPAN};
    use super::drive::Plan;
    let mut long = every_walk(31).repeat(32);
    long.truncate(long.len() - 13);
    let lone = &long[..(12 << 10) + 13];
    let window = 2u32 << 20;
    for level in 1u8..=5 {
        for (input, what) in [(&long[..], "long"), (lone, "lone")] {
            if level == 5 && what == "long" {
                // The tree's level: only its lone members walk the chains.
                continue;
            }
            let plan = |pair: Pairing| {
                let plan = Plan::for_level(level);
                let plan = if level == 1 {
                    plan.priced_level1()
                } else {
                    plan
                };
                Plan { pair, ..plan }
            };
            for workers in [1, usize::MAX] {
                let five = |pair: Pairing| {
                    let mut options = rar5::EncodeOptions::for_level(level, window);
                    options.plan = plan(pair);
                    options.workers = workers;
                    rar5::Rar5Encoder::new(options).encode(input)
                };
                let three = |pair: Pairing| {
                    let mut options = rar29::EncodeOptions::for_level(level, window);
                    options.plan = plan(pair);
                    options.workers = workers;
                    rar29::Rar29Encoder::new(options).encode(input)
                };
                let (single5, single3) = (five(Pairing::Single), three(Pairing::Single));
                PROBE_SPAN.store(input.len(), Ordering::Relaxed);
                let before = PROBE_PAIRS.load(Ordering::Relaxed);
                let label = format!("level {level}, {what}, {workers} workers");
                assert!(five(PAIRING) == single5, "RAR 5, {label}");
                assert!(three(PAIRING) == single3, "RAR 2.9, {label}");
                let pairs = PROBE_PAIRS.load(Ordering::Relaxed) - before;
                if what == "long" {
                    assert!(pairs > 1000, "{label}: {pairs} pairs");
                } else {
                    assert_eq!(pairs, 0, "{label}");
                }
                let before = PROBE_PAIRS.load(Ordering::Relaxed);
                assert!(five(Pairing::From(0)) == single5, "RAR 5 from 0, {label}");
                assert!(
                    three(Pairing::From(0)) == single3,
                    "RAR 2.9 from 0, {label}"
                );
                let pairs = PROBE_PAIRS.load(Ordering::Relaxed) - before;
                assert!(pairs > 1000, "{label}, from 0: {pairs} pairs");
                if workers == 1 {
                    assert!(
                        rar5_decode(&single5, input.len(), u64::from(window)) == input,
                        "level {level}, {what}"
                    );
                }
            }
        }
    }
}

// ---- the floor scan's literals a stride at a time ------------------------------------

#[test]
fn the_floor_scan_takes_the_tokens_it_took_a_position_a_turn() {
    // `lz::floor_scan` sends every literal up to the next position it asks
    // the finder at in one go; `lz::floor_scan_a_position_a_turn` is the
    // scan as it was, one position a turn. Over bytes with copies near and
    // far, runs that go on at the last distance, and bytes with nothing to
    // find, for blocks that start on and off the stride and at strides and
    // least matches either side of the shipped ones, the two take the same
    // tokens in both formats.
    use super::chain::{Chains, Pairing, KEY_SHORT};
    use super::lz::{floor_scan, floor_scan_a_position_a_turn, Block, Source};
    let mut input = every_walk(23);
    let copy = input[1000..9000].to_vec();
    input.extend_from_slice(&copy);
    input.extend_from_slice(&nothing_to_find(9 << 10, 29));
    input.extend_from_slice(&copy[..3000]);
    let mut chains = Chains::new(1 << 20, input.len(), usize::MAX, KEY_SHORT);
    let (heads, links) = (&mut chains.heads, &chains.links);
    links.insert(heads, &input, 0..input.len());
    let source = Source::Chains {
        chains: links,
        depth: 1,
        enough: 32,
        pair: Pairing::Single,
    };
    let rar5 = rar5::wire_for_tests();
    let rar29 = rar29::wire_for_tests();
    let fields = |tokens: &[Token]| -> Vec<(Arm, u16, u32)> {
        tokens
            .iter()
            .map(|t| (t.arm, t.length, t.distance))
            .collect()
    };
    let mut matched = 0usize;
    for (start, end) in [
        (0, input.len()),
        (5, 40_000),
        (1001, input.len() - 3),
        (16, 17),
    ] {
        let block = Block {
            span: &input,
            start,
            end,
            dictionary: 1 << 20,
        };
        for (stride, least) in [(16, 32), (1, 6), (3, 8), (32, 64), (16, 4)] {
            let (mut bulk, mut single) = (Vec::new(), Vec::new());
            floor_scan(&rar5, block, source, &mut bulk, stride, least, 1);
            floor_scan_a_position_a_turn(&rar5, block, source, &mut single, stride, least);
            assert!(
                fields(&bulk) == fields(&single),
                "RAR 5, {start}..{end}, stride {stride}, least {least}"
            );
            matched += bulk.iter().filter(|t| t.arm != Arm::Literal).count();
            let (mut bulk, mut single) = (Vec::new(), Vec::new());
            floor_scan(&rar29, block, source, &mut bulk, stride, least, 1);
            floor_scan_a_position_a_turn(&rar29, block, source, &mut single, stride, least);
            assert!(
                fields(&bulk) == fields(&single),
                "RAR 2.9, {start}..{end}, stride {stride}, least {least}"
            );
        }
    }
    assert!(matched > 100, "{matched} matches: the scan must take some");
}

// ---- the thin scan's pairs -------------------------------------------------------------

#[test]
fn the_thin_scan_takes_the_tokens_the_floor_scan_takes_at_a_stride_of_one() {
    // `lz::thin_scan` asks the chains two positions at a time and keeps the
    // second answer for the next position; `lz::floor_scan` at a stride of
    // one asks each position alone. Over bytes with copies near and far,
    // runs that go on at the last distance, thin noise and noise with
    // nothing to find, for blocks that start anywhere and end one byte on,
    // at least matches and depths either side of the shipped ones, the two
    // take the same tokens in both formats. One thread, under 8 MiB.
    use super::chain::{Chains, Pairing, KEY_SHORT};
    use super::lz::{floor_scan, thin_scan, Block, Source};
    let mut input = every_walk(31);
    let copy = input[2000..12000].to_vec();
    input.extend_from_slice(&nothing_to_find(9 << 10, 37));
    input.extend_from_slice(&copy);
    let mut noise = nothing_to_find(40 << 10, 43);
    let mut pick = rarkit_testdata::Seeded::new(47);
    let mut at = 64;
    while at + 9 <= noise.len() {
        let back = pick.between(9, 60);
        noise.copy_within(at - back..at - back + 9, at);
        at += pick.between(20, 90);
    }
    input.extend_from_slice(&noise);
    input.extend_from_slice(&copy[..3000]);
    let mut chains = Chains::new(1 << 20, input.len(), usize::MAX, KEY_SHORT);
    let (heads, links) = (&mut chains.heads, &chains.links);
    links.insert(heads, &input, 0..input.len());
    let rar5 = rar5::wire_for_tests();
    let rar29 = rar29::wire_for_tests();
    let fields = |tokens: &[Token]| -> Vec<(Arm, u16, u32)> {
        tokens
            .iter()
            .map(|t| (t.arm, t.length, t.distance))
            .collect()
    };
    let mut matched = 0usize;
    for (start, end) in [
        (0, input.len()),
        (7, 50_000),
        (1001, input.len() - 1),
        (input.len() - 6, input.len()),
        (16, 17),
    ] {
        let block = Block {
            span: &input,
            start,
            end,
            dictionary: 1 << 20,
        };
        for depth in [1u32, 2, 4, 9] {
            let source = Source::Chains {
                chains: links,
                depth,
                enough: 32,
                pair: Pairing::Single,
            };
            for least in [4usize, 5, 6, 32] {
                let (mut paired, mut alone) = (Vec::new(), Vec::new());
                thin_scan(&rar5, block, source, &mut paired, least);
                floor_scan(&rar5, block, source, &mut alone, 1, least, 1);
                assert!(
                    fields(&paired) == fields(&alone),
                    "RAR 5, {start}..{end}, depth {depth}, least {least}"
                );
                matched += paired.iter().filter(|t| t.arm != Arm::Literal).count();
                let (mut paired, mut alone) = (Vec::new(), Vec::new());
                thin_scan(&rar29, block, source, &mut paired, least);
                floor_scan(&rar29, block, source, &mut alone, 1, least, 1);
                assert!(
                    fields(&paired) == fields(&alone),
                    "RAR 2.9, {start}..{end}, depth {depth}, least {least}"
                );
            }
        }
    }
    assert!(matched > 1000, "{matched} matches: the scan must take some");
}
