//! The level ladder, and the sample under it: what each level parses
//! with, and the whole run and the held wave beside the windowed encode.

use super::*;

#[test]
fn the_sample_separates_bytes_worth_searching_from_bytes_that_are_not() {
    // `encode::sample`'s whole job, and the only thing the shipped
    // threshold rests on: the two populations must not overlap. The
    // margin here is the one the histogram
    // measured over six real corpora, where every block of every
    // compressible one read above 215 per thousand and every block of the
    // incompressible one read 0.
    use super::sample::{worth_searching, yield_per_mille};
    let rich = few_words(super::drive::PARSE_BLOCK_BYTES, 7);
    let poor = nothing_to_find(super::drive::PARSE_BLOCK_BYTES, 11);
    let (rich_yield, poor_yield) = (yield_per_mille(&rich), yield_per_mille(&poor));
    assert!(
        rich_yield > 200,
        "text should read richly; it read {rich_yield} per thousand"
    );
    assert!(
        poor_yield < 10,
        "bytes with nothing in them should read near zero; they read {poor_yield}"
    );
    assert!(worth_searching(&rich), "text is worth searching");
    assert!(!worth_searching(&poor), "noise is not worth searching");
}

#[test]
fn a_block_too_short_to_sample_is_always_searched() {
    // The sample is not taken below a floor, because a short block has no
    // wall in it worth saving and is a bad sample of itself. It must fail
    // SAFE, which is to say towards searching.
    use super::sample::worth_searching;
    for len in [0usize, 1, 100, 4_000, 16 << 10] {
        assert!(
            worth_searching(&nothing_to_find(len, 3)),
            "a {len} byte block must be searched, not dropped to the floor"
        );
    }
}

#[test]
fn the_shipped_ladder_is_monotone_and_has_no_redundant_rung() {
    // The levels are the product, so two things have to hold
    // of the shipped mapping and are cheap to check here rather than only
    // in a bench: a higher level never compresses WORSE, and no two
    // levels are the same plan under two names. The measured frontier
    // map is what says each rung also EARNS its
    // place; this is the part a test can keep true.
    use super::drive::Plan;
    let mut input = few_words(700_000, 5);
    input.extend_from_slice(&nothing_to_find(200_000, 6));
    input.extend_from_slice(&few_words(400_000, 7));
    let sizes: Vec<usize> = (1u8..=5)
        .map(|level| rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, 1 << 20)))
        .map(|mut encoder| encoder.encode(&input).len())
        .collect();
    assert!(
        sizes.windows(2).all(|pair| pair[0] >= pair[1]),
        "a higher level must not compress worse: {sizes:?}"
    );
    let plans: Vec<String> = (1u8..=5)
        .map(|level| format!("{:?}", Plan::for_level(level)))
        .collect();
    for (a, first) in plans.iter().enumerate() {
        for (b, second) in plans.iter().enumerate().skip(a + 1) {
            assert_ne!(
                first,
                second,
                "levels {} and {} are the same plan, so one of them offers the user nothing",
                a + 1,
                b + 1
            );
        }
    }
}

#[test]
fn the_floor_scan_is_the_chain_levels_and_never_read_from_the_parse() {
    // Spec G 3.8.3: levels 1 to 3 scan an empty
    // block, and so does level 4 since its default plan went to the chains
    // (1 Oct 2026, exactly as level 3 does); level 5, and level 4 under
    // its tree or optimal option, do not, and the option clears it. The
    // field is set per LEVEL: a level 3 whose parse is lazy (the default
    // ladder) or optimal scans alike, so neither parse can switch
    // the scan.
    use super::drive::{Parse, Plan};
    let four = Plan::for_level(4);
    assert!(!four.tree_level4().scans_floor, "level 4's tree option");
    assert!(
        !four.optimal_tree(4).scans_floor,
        "level 4's optimal option"
    );
    for level in 1u8..=5 {
        let plan = Plan::for_level(level);
        assert_eq!(plan.scans_floor, level <= 4, "level {level}");
        assert!(
            !plan.lazy_floor().scans_floor,
            "level {level} with the option"
        );
    }
    let three = Plan::for_level(3);
    for parse in [Parse::Lazy, Parse::Optimal] {
        let plan = Plan { parse, ..three };
        assert!(plan.scans_floor, "level 3 under a {parse:?} parse");
        assert!(!plan.lazy_floor().scans_floor, "{parse:?} with the option");
    }
}

#[test]
fn the_floor_is_cheaper_than_every_level_it_stands_under() {
    // What `Plan::floor` promises: it is a plan no level is already at or
    // under, so dropping to it is always a saving, and it keeps the
    // level's FINDER, because a finder's index has to take every position
    // whether a block's parse looks at it or not.
    use super::drive::{Parse, Plan};
    for level in 2u8..=5 {
        let plan = Plan::for_level(level);
        let floor = plan.floor_for_test();
        assert_eq!(
            format!("{:?}", floor.finder),
            format!("{:?}", plan.finder),
            "level {level}'s floor must keep its finder"
        );
        assert_eq!(floor.parse, Parse::Lazy, "the floor is the lazy parse");
        assert!(
            floor.depth <= plan.depth,
            "level {level}'s floor must not look deeper than the level does"
        );
        assert!(
            !plan.at_floor_for_test(),
            "level {level} must have something under it, or it pays for a sample that saves nothing"
        );
    }
    // Level 1 too: it looks decoyed links deep where the floor looks one,
    // and the sample was measured to be worth 2.00x its CPU on bytes with
    // nothing in them. The guard exists for the plans BELOW the ladder,
    // which a sweep reaches and a caller does not.
    assert!(
        !Plan::for_level(1).at_floor_for_test(),
        "level 1 has the floor under it too, and the sample is worth taking there"
    );
    assert!(
        Plan::for_level(1).floor_for_test().at_floor_for_test(),
        "the floor itself must be at the floor, or a floored block samples again for nothing"
    );
}

#[test]
fn a_lone_member_is_parsed_at_its_levels_lone_effort_and_nothing_else_is() {
    // `drive::Lone`: at level 3 a whole member of at most one parse block
    // (262,144 bytes, SPEC-H3 8.1), from no history, is
    // the lazy parse 64 links deep; one byte longer, or any member that
    // continues a carried run, is level 3's own plan, which is that same
    // parse by default and the optimal parse under the
    // option (`Plan::optimal_level3`). The spelled plans carry no lone
    // effort, so they are the two parses on their own.
    use super::drive::Plan;
    let lone = Plan::for_level(3).lone.expect("level 3 has a lone effort");
    assert_eq!(lone.bytes, 262_144);
    assert_eq!(lone.bytes, super::drive::PARSE_BLOCK_BYTES);
    for level in [1u8, 2] {
        assert!(
            Plan::for_level(level).lone.is_none(),
            "levels 1 and 2 are the lazy parse already"
        );
    }
    assert!(
        lone.depth > Plan::for_level(2).depth,
        "a lone member at level 3 must still be searched harder than level 2 searches"
    );
    let dictionary = 128 << 10;
    // The option: the level 3 whose long members are the
    // optimal parse, which is what separates a lone member from the rest.
    let level3 = || {
        let mut options = rar5::EncodeOptions::for_level(3, dictionary);
        options.plan = options.plan.optimal_level3();
        rar5::Rar5Encoder::new(options)
    };
    let spelled = |plan: &str| {
        rar5::Rar5Encoder::new(rar5::EncodeOptions::spelled(plan, dictionary).expect("a plan"))
    };
    let (lazy, optimal) = ("lazy:chain:64:256", "optimal:chain:8:64");
    let short = few_words(lone.bytes, 9);
    let long = few_words(lone.bytes + 1, 9);
    assert_eq!(level3().encode(&short), spelled(lazy).encode(&short));
    assert_ne!(
        spelled(lazy).encode(&short),
        spelled(optimal).encode(&short)
    );
    assert_eq!(level3().encode(&long), spelled(optimal).encode(&long));
    // The windowed shape: one chunk from no history is as lone as one
    // region is.
    let chunk = |mut encoder: rar5::Rar5Encoder, parts: &[&[u8]]| {
        parts
            .iter()
            .map(|part| {
                let mut out = Vec::new();
                encoder.encode_chunk(part, true, &mut out);
                out
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(chunk(level3(), &[&short]), chunk(spelled(lazy), &[&short]));
    // A chunk that continues a carried run is never lone, however short.
    let first = few_words(4_000, 3);
    assert_eq!(
        chunk(level3(), &[&first, &short])[1],
        chunk(spelled(optimal), &[&first, &short])[1]
    );
}

#[test]
fn level_3_is_the_lazy_parse_32_links_deep_and_the_options_are_64_links_and_the_optimal_parse() {
    // Level 3's own plan is the lazy parse over the chains,
    // stopped at a 256 byte match; with the backward extension it follows
    // `drive::LEVEL3_LINKS` (32) links, not the 64 first set, which
    // `Plan::deep_level3` (`WriteOptions::level3_deep`) keeps;
    // `Plan::optimal_level3` (`WriteOptions::level3_optimal`) restores the
    // optimal parse 8 links deep, and overrides the other. Lone members
    // keep their 64 links. RAR 5 and the RAR 2.9 method share the
    // ladder.
    use super::drive::{Lone, Plan};
    let dictionary = 1 << 20;
    let plan = Plan::for_level(3);
    assert_eq!(plan.lone, Some(Lone::LAZY));
    assert_eq!(plan.optimal_level3().lone, Some(Lone::LAZY));
    let long = few_words(700_000, 23);
    assert_eq!(plan.depth, super::drive::LEVEL3_LINKS);
    assert_eq!(plan.deep_level3().lone, Some(Lone::LAZY));
    let level3 = |optimal: bool| {
        let mut options = rar5::EncodeOptions::for_level(3, dictionary);
        if optimal {
            options.plan = options.plan.optimal_level3();
        }
        rar5::Rar5Encoder::new(options)
    };
    let deep = || {
        let mut options = rar5::EncodeOptions::for_level(3, dictionary);
        options.plan = options.plan.deep_level3();
        rar5::Rar5Encoder::new(options)
    };
    // A spelled plan is the raw plan; `back` gives it the extension.
    let spelled_back = |text: &str, back: usize| {
        let mut options = rar5::EncodeOptions::spelled(text, dictionary).expect("a plan");
        options.plan.back = back;
        rar5::Rar5Encoder::new(options)
    };
    let spelled = |text: &str| spelled_back(text, 0);
    let limit = super::lz::BACK_LIMIT;
    assert_eq!(
        level3(false).encode(&long),
        spelled_back("lazy:chain:32:256", limit).encode(&long)
    );
    assert_eq!(
        deep().encode(&long),
        spelled_back("lazy:chain:64:256", limit).encode(&long)
    );
    assert_eq!(
        level3(true).encode(&long),
        spelled("optimal:chain:8:64").encode(&long)
    );
    let r29 = |text: Option<&str>| {
        let options = match text {
            Some(text) => {
                let mut options = rar29::EncodeOptions::spelled(text, dictionary).expect("a plan");
                options.plan.back = limit;
                options
            }
            None => rar29::EncodeOptions::for_level(3, dictionary),
        };
        rar29::Rar29Encoder::new(options)
    };
    assert_eq!(
        r29(None).encode(&long),
        r29(Some("lazy:chain:32:256")).encode(&long)
    );
    // Still a rung: level 2 looks less deep, level 4 walks the tree.
    assert!(plan.depth > Plan::for_level(2).depth);
}

#[test]
fn level_1_is_the_fast_parse_over_six_byte_chains_and_the_option_is_the_lazy_parse() {
    // Level 1's own plan is the fast parse over chains keyed
    // on six bytes; `Plan::priced_level1` (`WriteOptions::level1_priced`)
    // restores the lazy parse three links deep over four byte chains, the
    // level 1 of before. The key follows the LEVEL's plan: the floor is a
    // lazy plan, so an engine built at level 1's floor, which is what
    // packs the store rule's samples (spec G 3.8.3), keeps four byte
    // chains. RAR 5 and the RAR 2.9 method share the ladder.
    use super::chain::{KEY_SHORT, KEY_WIDE};
    use super::drive::{Finder, Parse, Plan};
    let plan = Plan::for_level(1);
    assert_eq!(plan.parse, Parse::Fast);
    assert_eq!(plan.finder, Finder::Chain);
    assert_eq!(plan.chain_key(), KEY_WIDE);
    assert_eq!(plan.lone, None);
    assert!(plan.scans_floor);
    assert_eq!(plan.floor_for_test().parse, Parse::Lazy);
    assert_eq!(plan.floor_for_test().chain_key(), KEY_SHORT);
    let priced = plan.priced_level1();
    assert_eq!((priced.parse, priced.finder), (Parse::Lazy, Finder::Chain));
    assert_eq!((priced.depth, priced.enough, priced.back), (3, 32, 0));
    assert_eq!(priced.chain_key(), KEY_SHORT);
    assert_eq!(priced.lone, None);
    assert!(priced.scans_floor);
    assert!(!priced.at_floor_for_test());
    assert_eq!(priced.extend_low().back, super::lz::BACK_LIMIT);
    for level in 2u8..=5 {
        assert_eq!(
            Plan::for_level(level).chain_key(),
            KEY_SHORT,
            "level {level}"
        );
    }
    // The tree has no six byte key, so no plan pairs the parse with it.
    assert!(Plan::spelled("fast:tree:1:32").is_none());

    let dictionary = 1 << 20;
    let mut long = few_words(500_000, 31);
    long.extend_from_slice(&nothing_to_find(300_000, 32));
    long.extend_from_slice(&few_words(200_003, 33));
    let level1 = |priced: bool| {
        let mut options = rar5::EncodeOptions::for_level(1, dictionary);
        if priced {
            options.plan = options.plan.priced_level1();
        }
        rar5::Rar5Encoder::new(options)
    };
    let spelled = |text: &str| {
        rar5::Rar5Encoder::new(rar5::EncodeOptions::spelled(text, dictionary).expect("a plan"))
    };
    let fast = level1(false).encode(&long);
    assert_eq!(fast, spelled("fast:chain:1:32").encode(&long));
    assert_eq!(
        level1(true).encode(&long),
        spelled("lazy:chain:3:32").encode(&long)
    );
    assert!(fast != level1(true).encode(&long));
    assert_eq!(rar5_decode(&fast, long.len(), u64::from(dictionary)), long);
    let r29 = |text: Option<&str>| {
        let options = match text {
            Some(text) => rar29::EncodeOptions::spelled(text, dictionary).expect("a plan"),
            None => rar29::EncodeOptions::for_level(1, dictionary),
        };
        rar29::Rar29Encoder::new(options)
    };
    assert_eq!(
        r29(None).encode(&long),
        r29(Some("fast:chain:1:32")).encode(&long)
    );
    let mut options = rar29::EncodeOptions::for_level(1, dictionary);
    options.plan = options.plan.priced_level1();
    assert_eq!(
        rar29::Rar29Encoder::new(options).encode(&long),
        r29(Some("lazy:chain:3:32")).encode(&long)
    );
}

#[test]
fn both_formats_name_every_fresh_match_the_fast_parse_takes() {
    // The fast parse takes a fresh match of `lz::FAST_LEAST` bytes or more
    // and asks the format only for the distance's bonus. Both length
    // ladders must name that length at every distance, the farthest
    // included, or a token would go out that the wire cannot write.
    use super::lz::{Format, PriceModel, FAST_LEAST, UNPRICED};
    fn check<F: Format>(format: &F, farthest: u32) {
        let prices = PriceModel::new(format).prices;
        let mut distance = 1u32;
        while distance <= farthest {
            for back in [distance, distance + distance / 2, (distance - 1).max(1)] {
                let bonus = format.bonus(back);
                assert!(FAST_LEAST as u32 >= 2 + bonus, "distance {back}");
                for length in [FAST_LEAST as u32, format.longest() as u32] {
                    assert!(
                        format.fresh_length_price(&prices, length - bonus) < UNPRICED,
                        "distance {back}, length {length}"
                    );
                }
            }
            if distance > farthest / 2 {
                break;
            }
            distance *= 2;
        }
    }
    check(&rar5::wire_for_tests(), 1 << 31);
    check(&rar29::wire_for_tests(), 4 << 20);
}

#[test]
fn the_blind_cut_tiles_the_tokens_and_leaves_the_last_block_its_tokens() {
    use crate::carry::c_lz::codec::rar50::ENTROPY_BLOCK_MIN_TOKENS;
    let mut ranges = Vec::new();
    // Nothing, and a parse block of a few long matches: one block.
    cut::cut_blind(&[], &mut ranges);
    assert_eq!(ranges, vec![0..0]);
    let long: Vec<Token> = (0..64)
        .map(|_| Token {
            arm: Arm::Fresh,
            length: 4096,
            distance: 4096,
        })
        .collect();
    cut::cut_blind(&long, &mut ranges);
    assert_eq!(ranges, vec![0..long.len()]);
    // A parse block of literals and matches: a block ends with the token
    // that takes it to the cut's bytes, and the last keeps more than the
    // least a table set is worth.
    let mut tokens: Vec<Token> = Vec::new();
    let mut x = 7u32;
    let mut bytes = 0usize;
    while bytes < 256 << 10 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let token = if (x >> 16).is_multiple_of(3) {
            Token {
                arm: Arm::Fresh,
                length: 6 + ((x >> 20) % 40) as u16,
                distance: 1 + (x >> 12) % 100_000,
            }
        } else {
            Token::literal((x >> 16) as u8)
        };
        bytes += token.length as usize;
        tokens.push(token);
    }
    cut::cut_blind(&tokens, &mut ranges);
    assert_eq!(ranges.first().map(|r| r.start), Some(0));
    assert_eq!(ranges.last().map(|r| r.end), Some(tokens.len()));
    assert!(ranges.windows(2).all(|pair| pair[0].end == pair[1].start));
    assert_eq!(ranges.len(), 4, "{ranges:?}");
    for range in &ranges[..ranges.len() - 1] {
        let held: usize = tokens[range.clone()]
            .iter()
            .map(|t| t.length as usize)
            .sum();
        let short = held - tokens[range.end - 1].length as usize;
        assert!(held >= cut::BLIND_CUT_BYTES && short < cut::BLIND_CUT_BYTES);
    }
    assert!(ranges.last().unwrap().len() > ENTROPY_BLOCK_MIN_TOKENS);
}

#[test]
fn the_six_byte_pass_ends_the_chains_of_the_positions_it_cannot_key() {
    // A position with four or five bytes after it has no six byte key, so
    // the pass links it to nothing; but a search asks at it (it can start
    // a four byte match), and reads its slot first. The slot is the cyclic
    // buffer's, and an earlier member's pass wrote it: left alone, the
    // short member's last positions would follow the long member's links.
    use super::chain::{Chains, KEY_WIDE};
    let long: Vec<u8> = b"abcdefgh".iter().copied().cycle().take(4096).collect();
    let short = &long[..1000];
    let mut chains = Chains::new(1 << 20, long.len(), usize::MAX, KEY_WIDE);
    let (heads, links) = (&mut chains.heads, &chains.links);
    links.insert(heads, &long, 0..long.len());
    for at in [994, 995, 996] {
        assert!(links.nearest(at).is_some(), "the long member links {at}");
    }
    // The next member over the same chains, from empty heads, as a run
    // that starts fresh has them.
    chains.forget(&long);
    assert!(chains.heads.iter().all(|&head| head == 0));
    let (heads, links) = (&mut chains.heads, &chains.links);
    links.insert(heads, short, 0..short.len());
    assert_eq!(links.nearest(994), Some(986), "six bytes after it: keyed");
    for at in [995, 996] {
        assert_eq!(
            links.nearest(at),
            None,
            "position {at} has no key and must end its chain"
        );
    }
    // The pass built across the pool leaves the same links.
    #[cfg(feature = "parallel")]
    {
        use super::chain::{Build, Piece};
        chains.forget(short);
        let (heads, links) = (&mut chains.heads, &chains.links);
        links.insert(heads, &long, 0..long.len());
        chains.forget(&long);
        let (heads, links) = (&mut chains.heads, &chains.links);
        let pieces = [
            Piece {
                cut: short.len(),
                range: 0..600,
                parses: 0..0,
                stride: 1,
            },
            Piece {
                cut: short.len(),
                range: 600..short.len(),
                parses: 0..0,
                stride: 1,
            },
        ];
        Build::default().run(heads, links, short, &pieces, 2, &|_| {});
        assert_eq!(links.nearest(994), Some(986));
        assert_eq!((links.nearest(995), links.nearest(996)), (None, None));
    }
}

#[test]
fn an_engine_that_parsed_a_longer_member_writes_the_next_as_a_fresh_one_does() {
    // An engine keeps its chains between members and empties only their
    // heads. Members of every length around a parse block's end, each
    // after a longer one, at the six byte key and at the four byte one.
    for level in [1u8, 2] {
        let new = || rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, 1 << 20));
        let mut kept = new();
        let first = few_words(900_000, 41);
        let expected = new().encode(&first);
        assert_eq!(kept.encode(&first), expected, "level {level}");
        for len in (262_138..262_152).chain(70_000..70_009).chain(1..12) {
            let member = &first[first.len() - len..];
            let packed = kept.encode(member);
            assert!(
                packed == new().encode(member),
                "level {level}: a member of {len} bytes"
            );
            assert_eq!(rar5_decode(&packed, len, 1 << 20), member, "{len}");
        }
    }
}

#[test]
fn levels_4_and_5_parse_a_lone_member_lazily_and_the_option_off_optimally() {
    // SPEC-H3 8.1: at levels 4 and 5 a whole
    // non-solid member of at most one parse block, from no history, takes
    // level 3's lone LAZY parse by default, over the
    // chains, and builds no tree; one byte longer is not lone, and under
    // a megabyte it has no class reading, so it takes the chains at both
    // levels (level 4's at 64 links, its own plan; level 5's at 80 links,
    // its other effort; each with the backward extension). The
    // user's option off gives such a member level 3's OPTIMAL
    // chain parse instead (the earlier default), at levels 4 and 5 only.
    // RAR 5 and the RAR 2.9 method share the ladder.
    use super::drive::{Lone, Plan};
    let dictionary = 1 << 20;
    let short = few_words(262_144, 21);
    let long = few_words(262_145, 21);
    for (level, own) in [(4u8, "lazy:chain:64:256"), (5, "lazy:chain:80:256")] {
        let plan = Plan::for_level(level);
        assert_eq!(plan.lone, Some(Lone::LAZY));
        assert_eq!(
            plan.optimal_small_members(level).lone,
            Some(Lone::OPTIMAL_CHAIN)
        );
        assert_eq!(
            plan.tree_level4().optimal_small_members(level).lone,
            Some(Lone::OPTIMAL_CHAIN),
            "the option reaches the level whichever finder its plan walks"
        );
        let level_n = || rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, dictionary));
        let spelled = |text: &str| {
            rar5::Rar5Encoder::new(rar5::EncodeOptions::spelled(text, dictionary).expect("a plan"))
        };
        let own_plan = || {
            let mut options = rar5::EncodeOptions::spelled(own, dictionary).expect("a plan");
            if own.contains("tree") {
                options.plan.candidates = 1;
                options.plan.full_reach = true;
            }
            options.plan.back = super::lz::BACK_LIMIT;
            rar5::Rar5Encoder::new(options)
        };
        let mut lone = level_n();
        assert_eq!(
            lone.encode(&short),
            spelled("lazy:chain:64:256").encode(&short),
            "level {level}: a lone member is level 3's lone lazy parse"
        );
        assert_eq!(
            lone.structure_bytes(),
            lone.member_structure_bytes(short.len(), false),
            "level {level}: a lone member builds the chains and no tree"
        );
        assert_eq!(
            level_n().encode(&long),
            own_plan().encode(&long),
            "level {level}: one byte past a block is the chains, not lone"
        );
        let optimal = || {
            let mut options = rar5::EncodeOptions::for_level(level, dictionary);
            options.plan = options.plan.optimal_small_members(level);
            rar5::Rar5Encoder::new(options)
        };
        assert_eq!(
            optimal().encode(&short),
            spelled("optimal:chain:8:64").encode(&short),
            "level {level}: the option off parses a lone member optimally"
        );
        assert_eq!(optimal().encode(&long), own_plan().encode(&long));
        // The RAR 2.9 method, which shares the ladder.
        let r29 = |text: Option<&str>| {
            let options = match text {
                Some(text) => rar29::EncodeOptions::spelled(text, dictionary).expect("a plan"),
                None => rar29::EncodeOptions::for_level(level, dictionary),
            };
            rar29::Rar29Encoder::new(options)
        };
        assert_eq!(
            r29(None).encode(&short),
            r29(Some("lazy:chain:64:256")).encode(&short)
        );
    }
    // The option is no change at levels 1 to 3: level 3's lone is lazy
    // either way, and levels 1 and 2 have none.
    for level in 1..=3 {
        assert_eq!(
            Plan::for_level(level).optimal_small_members(level).lone,
            Plan::for_level(level).lone
        );
    }
}

#[test]
fn level_4_takes_the_chains_level_5_the_lazy_tree_and_the_options_the_plans_before() {
    // SPEC-H3 8.1, acceptance tests 1 and 10 at the encoder. A member that
    // is not lone is encoded
    // - at level 4 by `lazy:chain:64:256` with the backward extension: level
    //   3's plan at twice its depth, field for field the plan
    //   `level3_deep` gives level 3, so it holds no tree;
    // - at level 4 under `Plan::tree_level4` (`WriteOptions::level4_tree`)
    //   by `lazy:tree:12:0`, and at level 5 under `Plan::tree_level5`
    //   (`WriteOptions::level5_tree`) by `lazy:tree:16:0`, one hint slot
    //   each, the full reach, with the backward extension;
    // - at level 5 by default, these members being under a megabyte, by
    //   `lazy:chain:80:256` with the extension (level 5 by class);
    // - under `Plan::optimal_tree` (`level4_optimal`, `level5_optimal`) by
    //   `optimal:tree:8:0` and `optimal:tree:32:0` at four slots, the
    //   narrow ring and NO extension, whether `tree_level4` is on or not.
    // The member with a block of noise in it is sent to the floor there:
    // over the tree that reads the level's own hints, over level 4's chains
    // it is level 3's floor scan. RAR 5 and the RAR 2.9 method share the
    // ladder; levels 1 to 3 are not touched.
    use super::drive::{Finder, Parse, Plan};
    use super::lz::BACK_LIMIT;
    use crate::carry::h_ours::codec::rar50::tree::TREE_CANDIDATE_SLOTS;
    let dictionary = 1 << 20;
    let long = few_words(262_145, 23);
    let mut mixed = few_words(262_144, 24);
    mixed.extend_from_slice(&nothing_to_find(262_144, 25));
    mixed.extend_from_slice(&few_words(300_000, 26));

    let four = Plan::for_level(4);
    assert_eq!(
        (four.parse, four.finder, four.depth, four.enough),
        (Parse::Lazy, Finder::Chain, 64, 256)
    );
    assert_eq!(four.back, BACK_LIMIT, "level 4 extends backward");
    assert!(!four.full_reach, "level 4 walks no tree");
    assert_eq!(
        format!("{four:?}"),
        format!("{:?}", Plan::for_level(3).deep_level3()),
        "level 4 is level 3's plan at 64 links"
    );
    assert!(four.other.is_none(), "level 4 has one effort");
    assert_eq!(
        format!("{:?}", four.optimal_tree(4)),
        format!("{:?}", four.tree_level4().optimal_tree(4)),
        "the optimal option overrides the tree option"
    );
    for level in [1u8, 2, 3, 5] {
        let plan = Plan::for_level(level);
        assert_eq!(
            Plan::for_level(4).lone,
            Plan::for_level(4).tree_level4().lone,
            "the tree option leaves level 4's lone effort"
        );
        // `tree_level4` is applied by the writer at level 4 only; nothing
        // here applies it elsewhere, and the plans of the other levels
        // are not the chains at 64 links.
        assert_ne!(format!("{plan:?}"), format!("{four:?}"), "level {level}");
    }

    let r5_plan = |level: u8, plan: Plan| {
        let mut options = rar5::EncodeOptions::for_level(level, dictionary);
        options.plan = plan;
        rar5::Rar5Encoder::new(options)
    };
    // A spelled plan is the raw plan: the slots, the reach and the
    // extension are set here as the level sets them.
    let dress = |text: &str, mut plan: Plan, slots: usize| {
        let lazy = text.starts_with("lazy");
        if text.contains("tree") {
            plan.candidates = slots;
            plan.full_reach = lazy;
        }
        plan.back = if lazy { BACK_LIMIT } else { 0 };
        plan
    };
    let r5_spelled = |text: &str, slots: usize| {
        let mut options = rar5::EncodeOptions::spelled(text, dictionary).expect("a plan");
        options.plan = dress(text, options.plan, slots);
        rar5::Rar5Encoder::new(options)
    };
    let r29_plan = |level: u8, plan: Plan| {
        let mut options = rar29::EncodeOptions::for_level(level, dictionary);
        options.plan = plan;
        rar29::Rar29Encoder::new(options)
    };
    let r29_spelled = |text: &str, slots: usize| {
        let mut options = rar29::EncodeOptions::spelled(text, dictionary).expect("a plan");
        options.plan = dress(text, options.plan, slots);
        rar29::Rar29Encoder::new(options)
    };

    // Level 4's default: the chains.
    for (name, input) in [("long", &long), ("mixed", &mixed)] {
        let chains = r5_plan(4, four).encode(input);
        assert_eq!(
            chains,
            r5_spelled("lazy:chain:64:256", 0).encode(input),
            "level 4, {name}: the chains at 64 links, extended"
        );
        assert_eq!(
            chains,
            r5_plan(3, Plan::for_level(3).deep_level3()).encode(input),
            "level 4, {name}: what level 3 writes under its deep option"
        );
        assert!(
            chains != r5_plan(4, four.tree_level4()).encode(input),
            "level 4, {name}: and not the tree's bytes"
        );
        assert_eq!(
            r29_plan(4, four).encode(input),
            r29_spelled("lazy:chain:64:256", 0).encode(input),
            "level 4, {name}: the RAR 2.9 method"
        );
    }
    let mut chains = r5_plan(4, four);
    let mut level3 = r5_plan(3, Plan::for_level(3));
    chains.encode(&long);
    level3.encode(&long);
    assert_eq!(
        chains.structure_bytes(),
        level3.structure_bytes(),
        "a level 4 member that is not lone holds level 3's chains and no tree"
    );
    let mut tree = r5_plan(4, four.tree_level4());
    tree.encode(&long);
    assert!(
        tree.structure_bytes() != chains.structure_bytes(),
        "the tree option holds the tree"
    );

    // The lazy tree plans: level 4's under its option, level 5's own.
    for (level, plan, lazy, optimal) in [
        (
            4u8,
            four.tree_level4(),
            "lazy:tree:12:0",
            "optimal:tree:8:0",
        ),
        (
            5,
            Plan::for_level(5).tree_level5(),
            "lazy:tree:16:0",
            "optimal:tree:32:0",
        ),
    ] {
        assert_eq!((plan.parse, plan.finder), (Parse::Lazy, Finder::Tree));
        assert_eq!(plan.candidates, 1, "level {level} keeps one hint slot");
        assert_eq!(plan.back, BACK_LIMIT, "level {level} extends backward");
        let floor = plan.floor_for_test();
        assert_eq!(floor.finder, Finder::Tree, "level {level}'s floor");
        assert_eq!(floor.candidates, plan.candidates, "level {level}'s floor");
        assert_eq!(floor.back, 0, "level {level}'s floor takes no extension");
        assert!(
            !plan.scans_floor,
            "level {level}'s tree keeps the lazy floor"
        );
        let kept = Plan::for_level(level).optimal_tree(level);
        assert_eq!((kept.parse, kept.finder), (Parse::Optimal, Finder::Tree));
        assert_eq!(kept.candidates, TREE_CANDIDATE_SLOTS);
        assert_eq!(kept.back, 0, "the option's plan takes no extension");
        assert_eq!(kept.lone, plan.lone, "the option leaves the lone effort");
        assert!(
            plan.full_reach,
            "level {level} reaches the whole dictionary"
        );
        assert!(!kept.full_reach, "the option keeps the narrow ring");
        assert!(!kept.scans_floor, "the option keeps the lazy floor");
        for (name, input) in [("long", &long), ("mixed", &mixed)] {
            assert_eq!(
                r5_plan(level, plan).encode(input),
                r5_spelled(lazy, 1).encode(input),
                "level {level}, {name}: the lazy tree plan at one slot, extended"
            );
            let mut bare = plan;
            bare.back = 0;
            assert!(
                r5_plan(level, bare).encode(input) != r5_spelled(lazy, 1).encode(input),
                "level {level}, {name}: and not the plan without the extension"
            );
            assert_eq!(
                r5_plan(level, kept).encode(input),
                r5_spelled(optimal, TREE_CANDIDATE_SLOTS).encode(input),
                "level {level}, {name}: the option's optimal tree plan"
            );
            assert_eq!(
                r29_plan(level, plan).encode(input),
                r29_spelled(lazy, 1).encode(input),
                "level {level}, {name}: the RAR 2.9 method"
            );
        }
    }
    for level in 1u8..=3 {
        let plan = Plan::for_level(level);
        assert!(!plan.full_reach, "level {level} walks no tree");
        assert!(plan.other.is_none(), "level {level} has one effort");
        assert_eq!(
            format!("{:?}", plan.optimal_tree(level)),
            format!("{plan:?}"),
            "level {level}"
        );
    }

    // Level 5's default on a member under a megabyte: the chains at 80
    // links with the extension, level 4's plan one step deeper.
    let five = Plan::for_level(5);
    let deeper = five.other().expect("level 5 has another effort");
    assert_eq!(
        (deeper.parse, deeper.finder, deeper.depth, deeper.enough),
        (Parse::Lazy, Finder::Chain, 80, 256)
    );
    assert_eq!(
        format!("{deeper:?}"),
        format!(
            "{:?}",
            Plan {
                depth: 80,
                other: None,
                ..four
            }
        ),
        "level 5's other effort is level 4's chains at twice the links"
    );
    for (name, input) in [("long", &long), ("mixed", &mixed)] {
        let chains = r5_plan(5, five).encode(input);
        assert_eq!(
            chains,
            r5_spelled("lazy:chain:80:256", 0).encode(input),
            "level 5, {name}: the chains at 80 links, extended"
        );
        assert!(
            chains != r5_plan(5, five.tree_level5()).encode(input),
            "level 5, {name}: and not the tree's bytes"
        );
        assert_eq!(
            r29_plan(5, five).encode(input),
            r29_spelled("lazy:chain:80:256", 0).encode(input),
            "level 5, {name}: the RAR 2.9 method"
        );
    }
    for plan in [five.tree_level5(), five.optimal_tree(5), four.tree_level4()] {
        assert!(plan.other.is_none(), "an option keeps the level one effort");
    }
}

#[test]
fn a_solid_run_keeps_two_hint_slots_at_level_4s_tree_and_nothing_else_moves() {
    // SPEC-H3 8.1 acceptance test 7: a member of a solid set at level 4 is
    // `lazy:chain:64:256` with the backward extension (no hint slot at
    // all); with the tree option on it is the lazy parse over the tree at
    // depth 12 with TWO hint slots and the extension; at level 5 it is
    // `lazy:chain:72:256` with the extension (level 4's chains a step
    // deeper) UNLESS THE RUN'S FIRST MEMBER is a megabyte or more and
    // reads at or over the level's cut-off, when the whole run is the
    // lazy parse at depth 16 with ONE slot and the extension, which is
    // also what level 5's tree option gives every run. A run has one
    // plan, its first member's. The optimal plan the options keep has its
    // four slots and no extension.
    use super::drive::{Finder, Parse, Plan};
    use super::lz::BACK_LIMIT;
    use crate::carry::h_ours::codec::rar50::tree::TREE_CANDIDATE_SLOTS;
    let four = Plan::for_level(4);
    let solid4 = four.solid_run(4);
    assert!(solid4.wide_ring);
    assert_eq!(
        (solid4.parse, solid4.finder, solid4.depth, solid4.candidates),
        (Parse::Lazy, Finder::Chain, 64, four.candidates),
        "solid level 4 walks the chains"
    );
    let tree4 = four.tree_level4();
    assert_eq!(
        tree4.candidates, 1,
        "non-solid level 4's tree keeps one slot"
    );
    let five = Plan::for_level(5).tree_level5();
    assert_eq!(five.candidates, 1, "non-solid level 5 keeps one slot");
    let solid5 = Plan::for_level(5).solid_run(5);
    assert!(solid5.wide_ring);
    assert_eq!(
        (solid5.parse, solid5.finder, solid5.depth, solid5.enough),
        (Parse::Lazy, Finder::Chain, 72, 256),
        "solid level 5 walks the chains at 72 links"
    );
    assert_eq!(solid5.back, BACK_LIMIT, "solid level 5 extends backward");
    for plan in [solid4, five.solid_run(5), tree4.solid_run(4)] {
        assert!(plan.other.is_none(), "a solid run has one plan");
    }
    // Level 5's run: the chains, and the tree where its first member says
    // so. The tree it takes is the option's solid plan exactly.
    let head = super::class::HEAD_BYTES;
    let far_first = far_linked(head + 300_000);
    let near_first = few_words(head + 300_000, 3);
    assert!(solid5.reads_head(head as u64) && !solid5.reads_head(head as u64 - 1));
    assert_eq!(
        format!(
            "{:?}",
            solid5.for_member(&far_first, far_first.len() as u64)
        ),
        format!("{:?}", five.solid_run(5)),
        "a far first member: the run is the option's tree"
    );
    for (name, first) in [
        ("a near first member", &near_first[..]),
        ("a first member under a megabyte", &far_first[..head - 1]),
    ] {
        let took = solid5.for_member(first, first.len() as u64);
        assert_eq!(
            (took.parse, took.finder, took.depth, took.enough),
            (Parse::Lazy, Finder::Chain, 72, 256),
            "{name}: the run keeps the chains"
        );
        assert!(took.wide_ring && took.other.is_none(), "{name}");
    }
    for (level, plan, depth, slots) in [(4u8, tree4, 12, 2), (5, five, 16, 1)] {
        let solid = plan.solid_run(level);
        assert!(solid.wide_ring);
        assert_eq!(
            (solid.parse, solid.finder, solid.depth),
            (Parse::Lazy, Finder::Tree, depth)
        );
        assert_eq!(solid.candidates, slots, "solid level {level}'s hint slots");
        assert_eq!(
            solid.back, BACK_LIMIT,
            "solid level {level} extends backward"
        );
        let kept = plan.optimal_tree(level).solid_run(level);
        assert_eq!(
            kept.candidates, TREE_CANDIDATE_SLOTS,
            "level {level}: the option's optimal plan keeps its four"
        );
        assert_eq!(kept.back, 0, "level {level}: and takes no extension");
    }
    for level in 1u8..=3 {
        let plan = Plan::for_level(level);
        assert_eq!(plan.solid_run(level).candidates, plan.candidates);
    }
    // The bytes: a solid run of three members, each staged whole, against
    // the same run under the spelled plan.
    let dictionary = 1u32 << 20;
    let members = [
        few_words(300_000, 41),
        few_words(90_000, 42),
        few_words(400_000, 43),
    ];
    let run = |options: rar5::EncodeOptions| {
        let mut encoder = rar5::Rar5Encoder::new(options);
        encoder.reset_history();
        let mut packed = Vec::new();
        for member in &members {
            encoder.stage(member, true);
            packed.extend(encoder.flush().iter().cloned());
        }
        packed
    };
    let shipped = |level: u8, plan: Plan| {
        let mut options = rar5::EncodeOptions::for_level(level, dictionary);
        options.plan = plan.solid_run(level);
        options
    };
    let spelled = |text: &str, slots: usize, back: usize| {
        let mut options = rar5::EncodeOptions::spelled(text, dictionary).expect("a plan");
        if text.contains("tree") {
            options.plan.candidates = slots;
        }
        options.plan.wide_ring = true;
        options.plan.back = back;
        options
    };
    let chains = run(shipped(4, four));
    assert!(
        chains == run(spelled("lazy:chain:64:256", 0, BACK_LIMIT)),
        "solid level 4 is the chains at 64 links with the extension"
    );
    assert!(chains != run(spelled("lazy:chain:64:256", 0, 0)));
    assert!(
        chains == run(shipped(3, Plan::for_level(3).deep_level3())),
        "and what solid level 3 writes under its deep option"
    );
    let deeper = run(shipped(5, Plan::for_level(5)));
    assert!(
        deeper == run(spelled("lazy:chain:72:256", 0, BACK_LIMIT)),
        "solid level 5 is the chains at 72 links with the extension"
    );
    assert!(deeper != chains, "and not level 4's 64");
    for (level, plan, text, slots, other) in [
        (4u8, tree4, "lazy:tree:12:0", 2, 1),
        (5, five, "lazy:tree:16:0", 1, 2),
    ] {
        let solid = run(shipped(level, plan));
        assert!(
            solid == run(spelled(text, slots, BACK_LIMIT)),
            "solid level {level}'s tree is {slots} slots with the extension"
        );
        assert!(
            solid != run(spelled(text, other, BACK_LIMIT)),
            "and not {other}"
        );
        assert!(
            solid != run(spelled(text, slots, 0)),
            "and not without the extension"
        );
    }
    // A run by its FIRST MEMBER, started as a writer starts it: a far
    // first member makes the whole run the one-slot tree, the members
    // after it included; a near one leaves it on the chains; and the
    // tree option's run is the tree whatever starts it.
    let dictionary = 4u32 << 20;
    let started = |options: rar5::EncodeOptions, first: &[u8]| {
        let mut encoder = rar5::Rar5Encoder::new(options);
        encoder.start_member(first, first.len() as u64);
        let mut packed = Vec::new();
        for member in [first, &members[1][..], &members[2][..]] {
            encoder.stage(member, true);
            packed.extend(encoder.flush().iter().cloned());
        }
        packed
    };
    let shipped5 = |plan: Plan| {
        let mut options = rar5::EncodeOptions::for_level(5, dictionary);
        options.plan = plan.solid_run(5);
        options
    };
    let spelled = |text: &str| {
        let mut options = rar5::EncodeOptions::spelled(text, dictionary).expect("a plan");
        if text.contains("tree") {
            options.plan.candidates = 1;
            options.plan.full_reach = true;
        }
        options.plan.wide_ring = true;
        options.plan.back = BACK_LIMIT;
        options
    };
    let far_run = started(shipped5(Plan::for_level(5)), &far_first);
    assert!(
        far_run == started(spelled("lazy:tree:16:0"), &far_first),
        "a run whose first member reads far is the one-slot tree"
    );
    assert!(
        far_run == started(shipped5(five), &far_first),
        "which is what the tree option writes"
    );
    assert!(far_run != started(spelled("lazy:chain:72:256"), &far_first));
    let near_run = started(shipped5(Plan::for_level(5)), &near_first);
    assert!(
        near_run == started(spelled("lazy:chain:72:256"), &near_first),
        "a run whose first member reads near is the chains at 72 links"
    );
    assert!(near_run != started(shipped5(five), &near_first));
}

#[test]
fn levels_4_and_5_reach_the_whole_dictionary_on_a_member_that_is_not_solid() {
    // The non-solid wide ring: a repeat that sits farther back
    // than the dictionary less the walk's skew bound, and within the
    // dictionary, is found at levels 4 and 5 as level 3's chains find it;
    // with the option's narrow ring it is not. Noise, so that only the
    // repeat compresses: 300,000 bytes, 600,000 others, then the first
    // 300,000 again, 900,000 bytes back at a 1 MiB dictionary.
    let dictionary = 1 << 20;
    // (The helper's seed is an offset into one sequence: seeds far apart.)
    let first = nothing_to_find(300_000, 31);
    let mut input = first.clone();
    input.extend_from_slice(&nothing_to_find(600_000, 1 << 40));
    input.extend_from_slice(&first);
    let at = |level: u8, optimal: bool| {
        let mut options = rar5::EncodeOptions::for_level(level, dictionary);
        if optimal {
            options.plan = options.plan.optimal_tree(level);
        }
        rar5::Rar5Encoder::new(options).encode(&input).len()
    };
    // Found, the repeat costs a few hundred bytes; missed, 300,000.
    let chains = at(3, false);
    assert!(chains < 910_000, "level 3 finds the repeat: {chains}");
    for level in [4u8, 5] {
        let wide = at(level, false);
        let narrow = at(level, true);
        assert!(wide < 910_000, "level {level} finds the repeat: {wide}");
        assert!(
            narrow > 1_190_000,
            "level {level}'s option keeps the narrow ring: {narrow}"
        );
    }
    // SPEC-H3 section 4's acceptance tests 2 and 4: a member at or under the
    // reach (the dictionary less 256 KiB), and any member at a dictionary
    // above 4 MiB, write exactly the narrow ring's bytes.
    let narrow_ring = |level: u8, dictionary: u32, input: &[u8]| {
        let mut options = rar5::EncodeOptions::for_level(level, dictionary);
        options.plan.full_reach = false;
        rar5::Rar5Encoder::new(options).encode(input)
    };
    let short = few_words((1 << 20) - (256 << 10), 33);
    let long = few_words((8 << 20) + 1, 34);
    for level in [4u8, 5] {
        let default = |dictionary: u32, input: &[u8]| {
            rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, dictionary)).encode(input)
        };
        assert!(
            default(1 << 20, &short) == narrow_ring(level, 1 << 20, &short),
            "level {level}: a member at the reach keeps the narrow ring"
        );
        assert!(
            default(8 << 20, &long) == narrow_ring(level, 8 << 20, &long),
            "level {level}: an 8 MiB dictionary is unchanged"
        );
    }
}

#[test]
fn a_lone_block_from_the_samples_floor_up_is_sampled_and_noise_takes_the_floor() {
    // SPEC-H3 8.1: a lone member of 32 KiB or more is
    // sampled first (SPEC-G 3.8.3) and, where nothing is worth searching,
    // parsed at the floor; under 32 KiB it is never sampled, and text of
    // any lone length keeps the lone effort.
    use super::drive::Plan;
    let lone = Plan::for_level(3).lone.expect("level 3 has a lone effort");
    let dictionary = 128 << 10;
    let level3 = || rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(3, dictionary));
    let spelled = |plan: &str| {
        rar5::Rar5Encoder::new(rar5::EncodeOptions::spelled(plan, dictionary).expect("a plan"))
    };
    let (lazy, floor) = ("lazy:chain:64:256", "lazy:chain:1:32");
    // Noise the sample reads as having nothing in it, but where a deep
    // search still finds more than the floor's one link: a random run,
    // five copies of it each with the bytes of one residue mod 5 changed,
    // and the run again. Any four byte word leaves one residue uncovered,
    // so at every position of the last copy the nearest candidate is the
    // decoy that matches for a few bytes, and only a search deeper than
    // the floor's one link reaches the whole run: the two efforts write
    // different bytes, and the test can tell them apart.
    let base = nothing_to_find(16 << 10, 11);
    let mut decoyed = base.clone();
    for residue in 0..5 {
        let mut decoy = base.clone();
        for byte in decoy.iter_mut().skip(residue).step_by(5) {
            *byte ^= 0x5A;
        }
        decoyed.extend_from_slice(&decoy);
    }
    decoyed.extend_from_slice(&base);
    assert_eq!(
        level3().encode(&decoyed),
        spelled(floor).encode(&decoyed),
        "a lone member of noise from the sample's floor up takes the floor"
    );
    for len in [32 << 10, 100_000, lone.bytes] {
        let noise = nothing_to_find(len, 11);
        assert_eq!(
            level3().encode(&noise),
            spelled(floor).encode(&noise),
            "a lone {len} byte member of noise takes the floor"
        );
        let text = few_words(len, 12);
        assert_eq!(
            level3().encode(&text),
            spelled(lazy).encode(&text),
            "a lone {len} byte member of text keeps the lone effort"
        );
    }
    // Under the floor nothing is sampled: noise keeps the lone effort.
    let short = nothing_to_find((32 << 10) - 1, 13);
    assert_eq!(level3().encode(&short), spelled(lazy).encode(&short));
}

#[test]
fn a_whole_run_is_the_windowed_encodes_bytes_and_its_finder_is_what_was_charged() {
    // `drive::Engine::encode_whole_run`: one member in one chunk from no
    // history, the worker team's reader member. Its bytes are the
    // windowed encode's, whatever the chains are sized from; and what
    // `one_block_structure_bytes` charges before anything is built is at
    // least what the finder then holds, and exactly it for a member of a
    // whole parse block.
    use super::drive::PARSE_BLOCK_BYTES;
    for level in 1u8..=5 {
        for dictionary in [128u32 << 10, 2 << 20, 4 << 20] {
            let new = || rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, dictionary));
            for len in [4_000, PARSE_BLOCK_BYTES] {
                let data = few_words(len, u64::from(level) + u64::from(dictionary) + len as u64);
                let mut whole = new();
                let mut packed = Vec::new();
                whole.encode_whole_run(&data, &mut packed, &[]);
                let mut windowed = new();
                windowed.reset_history();
                let mut expected = Vec::new();
                windowed.encode_chunk(&data, true, &mut expected);
                assert_eq!(packed, expected, "level {level}, {dictionary} B, {len} B");

                let charged = whole.one_block_structure_bytes(true);
                assert!(whole.structure_bytes() <= charged);
                assert!(windowed.structure_bytes() >= whole.structure_bytes());
                let mut region = new();
                let mut out = Vec::new();
                region.encode_region(&data, 0, true, &mut out);
                assert!(region.structure_bytes() <= region.one_block_structure_bytes(false));
                if len == PARSE_BLOCK_BYTES {
                    assert_eq!(whole.structure_bytes(), charged);
                    assert_eq!(
                        region.structure_bytes(),
                        region.one_block_structure_bytes(false)
                    );
                }
                // The same encoder again, as a crew is: the bytes do not
                // follow the member before.
                let mut again = Vec::new();
                whole.encode_whole_run(&data, &mut again, &[]);
                assert_eq!(again, expected);
            }
        }
    }
    // The point of the whole run: at a 2 MiB dictionary the windowed
    // encode's chains hold 64 MiB of links for a member of a few KiB.
    let data = few_words(4_000, 1);
    let mut whole = rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(1, 2 << 20));
    let mut windowed = rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(1, 2 << 20));
    whole.encode_whole_run(&data, &mut Vec::new(), &[]);
    windowed.encode_chunk(&data, true, &mut Vec::new());
    assert!(windowed.structure_bytes() >= 64 << 20);
    assert!(whole.structure_bytes() <= 8 << 20);
}

#[test]
fn a_filtered_whole_run_is_the_filtered_windowed_encodes_bytes() {
    // The worker team's reader member under `FilterPolicy::Detect`: the
    // whole run stages its one chunk with the plan at base 0, as the
    // windowed encode's first and only window does.
    use super::filter::{FilterKind, FilterSpan};
    for level in [1u8, 3, 5] {
        let new = || rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, 2 << 20));
        let data = few_words(100_000, u64::from(level) + 40);
        let plan = [FilterSpan {
            start: 4_096,
            len: 60_000,
            kind: FilterKind::Delta(4),
        }];
        let mut packed = Vec::new();
        new().encode_whole_run(&data, &mut packed, &plan);
        let mut expected = Vec::new();
        new().encode_chunk_filtered(&data, true, &mut expected, &plan, 0);
        assert_eq!(packed, expected, "level {level}");
        let mut plain = Vec::new();
        new().encode_whole_run(&data, &mut plain, &[]);
        assert_ne!(packed, plain, "level {level}: the plan was not applied");
    }
}

#[test]
fn a_rar29_whole_run_is_the_windowed_encodes_bytes() {
    for level in [1u8, 3, 5] {
        let new = || rar29::Rar29Encoder::new(rar29::EncodeOptions::for_level(level, 4 << 20));
        let data = few_words(100_000, u64::from(level));
        let mut packed = Vec::new();
        new().encode_whole_run(&data, &mut packed);
        let mut expected = Vec::new();
        new().encode_chunk(&data, true, &mut expected);
        assert_eq!(packed, expected, "level {level}");
    }
}

#[test]
fn a_held_wave_holds_the_finder_smaller_and_moves_no_byte_at_the_shipped_dictionary() {
    // `drive::Engine::hold_wave`: a caller's budget holds a windowed
    // member to fewer blocks in flight. The chains' cyclic buffer and the
    // tree's hints shrink to that wave, which cannot move a byte; the
    // chains' HEADS shrink with a dictionary under 2 MiB, which can
    // (`Chains::head_bits`), so below it only the tree's bytes are pinned
    // here and the chains' round trip is `tests/streamed_packed_member.rs`'s
    // budgeted row. A 256 KiB dictionary and 512 KiB chunks make the held
    // chains wrap (1 Mi links for a history of up to 1.25 MiB) where the
    // unheld ones never do, and the history slides twice.
    use super::drive::PARSE_BLOCK_BYTES;
    let dictionary = 256u32 << 10;
    let data = few_words(3 << 19, 7);
    for level in [1u8, 3, 5] {
        let new = || rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, dictionary));
        let windowed = |encoder: &mut rar5::Rar5Encoder| {
            let mut out = Vec::new();
            encoder.reset_history();
            let chunks: Vec<&[u8]> = data.chunks(1 << 19).collect();
            for (index, chunk) in chunks.iter().enumerate() {
                encoder.encode_chunk(chunk, index + 1 == chunks.len(), &mut out);
            }
            out
        };
        let mut free = new();
        let expected = windowed(&mut free);
        for wave in [1, PARSE_BLOCK_BYTES, 2 * PARSE_BLOCK_BYTES, 1 << 19] {
            let mut held = new();
            held.hold_wave(wave);
            let packed = windowed(&mut held);
            if level == 5 {
                // Two blocks a chunk: the hints are two blocks either way.
                assert_eq!(packed, expected, "level {level}, wave {wave}");
                assert!(held.structure_bytes() <= free.structure_bytes());
            } else {
                assert!(held.structure_bytes() < free.structure_bytes());
            }
            // What the writer charges for it is at least what it holds.
            let charged = held.member_held_bytes(data.len(), Some(1 << 19));
            assert!(held.structure_bytes() + held.held_bytes() <= charged);
        }
    }
    // The wave each sizing allows, at the shipped 2 MiB dictionary over a
    // span that wraps: unheld, the floor's 16 Mi links keep one position
    // in hand; held to one window, 4 Mi links carry exactly the reach and
    // one window, eight blocks in one wave (`Chains::wave_bytes`).
    {
        use super::chain::{Chains, KEY_SHORT, KEY_WIDE};
        let span = 32 << 20;
        // The key moves no size.
        assert_eq!(
            Chains::new(2 << 20, span, usize::MAX, KEY_WIDE).wave_bytes(span),
            (16 << 20) - (2 << 20) - 1
        );
        assert_eq!(
            Chains::new(2 << 20, span, usize::MAX, KEY_SHORT).wave_bytes(span),
            (16 << 20) - (2 << 20) - 1
        );
        for wave in [PARSE_BLOCK_BYTES, 2 << 20] {
            let held = Chains::new(2 << 20, span, wave, KEY_SHORT);
            assert_eq!(held.wave_bytes(span), 2 << 20, "wave {wave}");
        }
    }
    // The point of it, at the shipped 2 MiB dictionary and window. Level
    // 1: the floor's 16 Mi links against the 4 Mi a 2 MiB wave needs.
    // Level 5: a 2 MiB chunk is eight blocks, whose hints (32 MiB) a wave
    // of one block holds to one walk group of four, and the groups are
    // cut where they were.
    let data = few_words(4 << 20, 9);
    for (level, wave, unheld, kept) in [
        (
            1u8,
            2 << 20,
            4 * ((1 << 20) + (16 << 20)),
            4 * ((1 << 20) + (4 << 20)),
        ),
        (5, PARSE_BLOCK_BYTES, 0, 0),
    ] {
        let new = || rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, 2 << 20));
        let (mut free, mut held) = (new(), new());
        held.hold_wave(wave);
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for (index, chunk) in data.chunks(2 << 20).enumerate() {
            free.encode_chunk(chunk, index == 1, &mut a);
            held.encode_chunk(chunk, index == 1, &mut b);
        }
        assert_eq!(a, b, "level {level}");
        if level == 1 {
            assert_eq!(free.structure_bytes(), unheld);
            assert_eq!(held.structure_bytes(), kept);
        } else {
            // Four blocks of hints, four bytes a slot, at the level's
            // slots a position (one by design).
            let stride = super::drive::Plan::for_level(level).candidates;
            let hints = 4 * PARSE_BLOCK_BYTES * 4 * stride;
            assert_eq!(
                free.structure_bytes() - held.structure_bytes(),
                hints as u64
            );
        }
        let charged = held.member_held_bytes(data.len(), Some(2 << 20));
        assert!(held.structure_bytes() + held.held_bytes() <= charged);
    }
}

#[test]
fn held_parses_and_a_planned_flush_move_no_byte_and_the_parses_are_charged() {
    // `drive::Engine::hold_parses`: under a caller's budget the tree's
    // blocks are parsed a few at a time, in lanes, rather than one task a
    // block. `drive::Engine::plan_flush`: the hints are built once, for
    // the widest flush the run planned, rather than grown member by
    // member. Neither can move a byte, and what the parses hold
    // (`flight_bytes`) is never more than the writer charges for them
    // (`flight_term`), held or not. Two 2 MiB windows of one member, at
    // the shipped dictionary, after a member of one block, so an unplanned
    // engine grows its hints between the two.
    let small = few_words(200 << 10, 12);
    let data = few_words(4 << 20, 11);
    for level in [4u8, 5] {
        let new = || rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, 2 << 20));
        let run = |encoder: &mut rar5::Rar5Encoder| {
            let mut out = Vec::new();
            encoder.reset_history();
            encoder.encode_chunk(&small, true, &mut out);
            encoder.reset_history();
            for (index, chunk) in data.chunks(2 << 20).enumerate() {
                encoder.encode_chunk(chunk, index == 1, &mut out);
            }
            out
        };
        let mut free = new();
        let expected = run(&mut free);
        assert!(
            free.flight_bytes() <= free.flight_term(2 << 20),
            "level {level}"
        );
        let mut planned = new();
        planned.plan_flush(2 << 20);
        assert_eq!(run(&mut planned), expected, "level {level}, planned");
        assert_eq!(planned.structure_bytes(), free.structure_bytes());
        for parses in [1, 2, 3] {
            let mut held = new();
            held.hold_parses(parses);
            assert_eq!(run(&mut held), expected, "level {level}, {parses} parses");
            assert!(held.flight_bytes() <= held.flight_term(2 << 20));
            assert!(held.flight_term(2 << 20) <= free.flight_term(2 << 20));
            let mut both = new();
            both.hold_wave(super::drive::PARSE_BLOCK_BYTES);
            both.hold_parses(parses);
            assert_eq!(
                run(&mut both),
                expected,
                "level {level}, held, {parses} parses"
            );
            assert!(both.flight_bytes() <= both.flight_term(2 << 20));
        }
    }
}

#[test]
fn the_thin_scan_is_level_3s_alone_and_its_options_clear_it() {
    // `Plan::scans_thin` is set at level 3 only, never by the RAR 2.9
    // writer, and the options that keep
    // level 3's earlier bytes (the lazy floor, the deep and the optimal
    // level 3) clear it.
    use super::drive::Plan;
    for level in 1u8..=5 {
        assert_eq!(
            Plan::for_level(level).scans_thin,
            level == 3,
            "level {level}"
        );
    }
    let three = Plan::for_level(3);
    assert!(!three.lazy_floor().scans_thin, "the lazy floor");
    assert!(!three.deep_level3().scans_thin, "the deep level 3");
    assert!(!three.optimal_level3().scans_thin, "the optimal level 3");
    assert!(
        !rar29::EncodeOptions::for_level(3, 1 << 20).plan.scans_thin,
        "RAR 2.9's level 3"
    );
}

/// Noise with a 12 byte copy from up to 1,000 bytes back every 48 bytes:
/// worth searching, but thin (`sample::thin`).
fn thin_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut out = nothing_to_find(len, seed);
    let mut pick = rarkit_testdata::Seeded::new(seed ^ 0x7468_696e);
    let mut at = 4096;
    while at + 12 <= len {
        let back = pick.between(12, 1000);
        out.copy_within(at - back..at - back + 12, at);
        at += 48;
    }
    out
}

#[test]
fn a_thin_block_takes_the_thin_scan_at_level_3_and_round_trips() {
    // Four parse blocks of thin bytes at level 3 (one thread, a 1 MiB
    // dictionary, about 10 MiB of memory): the sample reads them thin,
    // level 3 parses them by the thin scan, so the stream differs from
    // the one level 3's lazy parse writes with the option that clears
    // it, and rarkit's own decoder gives the bytes back.
    use super::sample::{thin, yield_per_mille, THIN_UNDER_PER_MILLE};
    let block = super::drive::PARSE_BLOCK_BYTES;
    let input = thin_bytes(4 * block, 41);
    for piece in input.chunks(block) {
        let reading = yield_per_mille(piece);
        assert!(
            thin(reading, THIN_UNDER_PER_MILLE),
            "the bytes should read thin; a block read {reading} per thousand"
        );
    }
    let dictionary = 1 << 20;
    let three = |lazy: bool| {
        let mut options = rar5::EncodeOptions::for_level(3, dictionary);
        if lazy {
            options.plan = options.plan.lazy_floor();
        }
        rar5::Rar5Encoder::new(options).encode(&input)
    };
    let (scanned, lazy) = (three(false), three(true));
    assert!(scanned != lazy, "a thin block must take the thin scan");
    assert_eq!(
        rar5_decode(&scanned, input.len(), u64::from(dictionary)),
        input
    );
    assert_eq!(
        rar5_decode(&lazy, input.len(), u64::from(dictionary)),
        input
    );
}

#[cfg(feature = "parallel")]
#[test]
fn the_built_pass_links_an_empty_block_at_its_stride_as_the_one_thread_pass_does() {
    // The empty stride (`chain::EMPTY_STRIDE`) is a property of the links,
    // so the pass built across the pool must leave the links one thread
    // leaves, at every position: a piece of empty blocks links every
    // stride-th position from its start and ends the others' chains, and
    // none of those ended chains may be read as a first. Two builders on
    // the global pool (any width runs it); about 8 MiB of chains.
    use super::chain::{Build, Chains, Piece, EMPTY_STRIDE, KEY_SHORT, PIECE_MOST};
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let mut span: Vec<u8> = (0..300_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    // Something to find: an earlier stretch again, from inside an empty
    // piece into the dense one and on into the second empty piece.
    span.copy_within(1_000..41_000, 180_000);
    // Odd lengths, so a stride does not line up with the next piece.
    let ranges = [0..100_001, 100_001..200_003, 200_003..span.len()];
    let strides = [EMPTY_STRIDE, 1, EMPTY_STRIDE];
    let link = |chains: &mut Chains| {
        let (heads, links) = (&mut chains.heads, &chains.links);
        for (range, &stride) in ranges.iter().zip(&strides) {
            if stride == 1 {
                links.insert(heads, &span, range.clone());
            } else {
                links.insert_sparse(heads, &span, range.clone(), stride);
            }
        }
    };
    let mut alone = Chains::new(1 << 20, span.len(), usize::MAX, KEY_SHORT);
    link(&mut alone);
    let mut pieces = Vec::new();
    for (range, &stride) in ranges.iter().zip(&strides) {
        let mut at = range.start;
        while at < range.end {
            // A piece of an empty block starts on its block's stride.
            let end = (at + PIECE_MOST / stride * stride).min(range.end);
            pieces.push(Piece {
                cut: span.len(),
                range: at..end,
                parses: 0..0,
                stride,
            });
            at = end;
        }
    }
    let mut built = Chains::new(1 << 20, span.len(), usize::MAX, KEY_SHORT);
    {
        let (heads, links) = (&mut built.heads, &built.links);
        Build::default().run(heads, links, &span, &pieces, 2, &|_| {});
    }
    for at in 0..span.len() - 3 {
        assert_eq!(
            alone.links.nearest(at),
            built.links.nearest(at),
            "position {at}"
        );
    }
    assert_eq!(alone.heads, built.heads);
    // A position the empty stride does not take has no chain: 200,005 is
    // off the grid, and its window's ask is at offset 0.
    assert!(!super::chain::empty_takes(200_005, EMPTY_STRIDE));
    assert_eq!(alone.links.nearest(200_005), None);
}

/// The class a writer reads from ONE member's head before a named
/// ceiling's refusal (`Engine::member_finder`, FROM-STUDIO 841) is the class
/// the encode then takes for it (`Engine::start_member`), on a member the
/// chains take and on one the tree takes, at level 5 and a 32 MiB window:
/// so the finder the refusal charges is the finder the run builds.
#[cfg(feature = "parallel")]
#[test]
fn the_class_read_before_the_refusal_is_the_class_the_encode_takes() {
    use super::drive::Finder;
    let mut state = 0x5eed_0034_7e47_0001_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    // Lines of twelve words of 24, the chains' class.
    let words = ["the", "quick", "brown", "fox", "jumps", "over", "a", "lazy"];
    let mut lines = String::new();
    while lines.len() < 2 << 20 {
        let line: Vec<&str> = (0..12)
            .map(|_| words[(next() % words.len() as u64) as usize])
            .collect();
        lines.push_str(&line.join(" "));
        lines.push('\n');
    }
    // Lines of ten made-up words of 20,000, of two to four syllables of a
    // consonant and a vowel, the tree's (as `tests/named_single_member_class.rs`).
    let consonants = ["b", "c", "d", "f", "g", "l", "m", "n", "p", "r", "s", "t"];
    let vowels = ["a", "e", "i", "o", "u", "an", "er", "in"];
    let vocab: Vec<String> = (0..20_000)
        .map(|_| {
            (0..2 + next() % 3)
                .map(|_| {
                    let pick = (next() % (consonants.len() * vowels.len()) as u64) as usize;
                    [consonants[pick / vowels.len()], vowels[pick % vowels.len()]].concat()
                })
                .collect()
        })
        .collect();
    let mut prose = String::new();
    while prose.len() < 2 << 20 {
        let line: Vec<&str> = (0..10)
            .map(|_| vocab[(next() % vocab.len() as u64) as usize].as_str())
            .collect();
        prose.push_str(&line.join(" "));
        prose.push_str(".\n");
    }
    let size = 34_u64 << 20;
    let mut taken = Vec::new();
    for head in [lines.as_bytes(), prose.as_bytes()] {
        let mut encoder = rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(5, 32 << 20));
        let read = encoder.member_finder(head, size);
        encoder.start_member(head, size);
        assert_eq!(
            read,
            encoder.member_effort().finder,
            "the class read before the refusal is the one the encode takes"
        );
        taken.push(read);
    }
    assert_eq!(
        taken,
        [Finder::Chain, Finder::Tree],
        "one member of each class"
    );
}
