//! The code builder, the bit writer, the ladders in the encoding direction,
//! the repeated distance model, the low distance run form and the block
//! boundary search.

use super::*;

/// Build a code for `frequency`, then read every used symbol back through
/// the crate's own strict table, which is the class RAR 5 and RAR 2.0 both
/// use.
fn round_trip(frequency: &[u32]) -> Vec<u8> {
    let mut lengths = vec![0u8; frequency.len()];
    code_lengths(frequency, &mut lengths);
    assert!(
        lengths.iter().all(|&l| l <= MAX_CODE_LEN),
        "no code may be deeper than 15"
    );
    assert!(is_complete(&lengths), "the code must be complete");

    let mut codes = vec![Default::default(); frequency.len()];
    canonical(&lengths, &mut codes);

    let mut table = Table::new(frequency.len());
    table.build(&lengths).expect("a complete code builds");

    let mut out = BitWriter::new();
    let used: Vec<usize> = (0..frequency.len()).filter(|&s| frequency[s] > 0).collect();
    for &symbol in &used {
        out.push_code(codes[symbol]);
    }
    let (bytes, _) = out.finish();
    let bytes = bytes.to_vec();
    let mut input = SliceBits::new(&bytes);
    for &symbol in &used {
        assert_eq!(
            table.decode(&mut input).expect("decodes") as usize,
            symbol,
            "symbol {symbol} did not read back"
        );
    }
    lengths
}

/// Section 6.3 item 1, the case that arises by itself: a block that uses
/// one symbol of an alphabet sends it at length 1, with length 1 on one
/// other symbol it never sends, so the table fills the code space
/// (`round_trip` asks that of every table). Whichever symbol is used,
/// the first of the alphabet included.
#[test]
fn one_used_symbol_is_sent_with_one_unsent_symbol_beside_it() {
    for only in [0usize, 1, 17, 43] {
        let mut frequency = vec![0u32; 44];
        frequency[only] = 12;
        let lengths = round_trip(&frequency);
        assert_eq!(lengths[only], 1, "symbol {only}");
        let coded: Vec<usize> = (0..44).filter(|&s| lengths[s] != 0).collect();
        assert_eq!(coded.len(), 2, "symbol {only}: {coded:?}");
        assert!(coded.iter().all(|&s| lengths[s] == 1), "symbol {only}");
    }
}

#[test]
fn two_used_symbols_are_one_bit_each() {
    let mut frequency = vec![0u32; 44];
    frequency[3] = 7;
    frequency[40] = 9;
    let lengths = round_trip(&frequency);
    assert_eq!((lengths[3], lengths[40]), (1, 1));
}

#[test]
fn a_flat_frequency_gives_a_flat_code() {
    let frequency = vec![1u32; 64];
    let lengths = round_trip(&frequency);
    assert!(lengths.iter().all(|&l| l == 6));
}

#[test]
fn a_deep_frequency_is_capped_at_fifteen_and_stays_complete() {
    // Fibonacci frequencies are the worst case for code depth: the plain
    // Huffman code for 40 of them is 39 bits deep. Section 6.3 item 2
    // requires the OPTIMAL code of depth 15 here, not a flat fallback.
    let mut frequency = vec![0u32; 306];
    let (mut a, mut b) = (1u32, 1u32);
    for slot in frequency.iter_mut().take(40) {
        *slot = a;
        (a, b) = (b, a.saturating_add(b));
    }
    let lengths = round_trip(&frequency);
    assert_eq!(*lengths.iter().max().expect("a length"), MAX_CODE_LEN);
    // A flat code over 40 symbols would be 6 bits each, so the most
    // frequent symbol would cost 6 bits. The optimal depth limited code
    // must do better than that on the head of the distribution.
    assert!(
        lengths[39] < 6,
        "the commonest symbol should be cheaper than a flat code, got {}",
        lengths[39]
    );
}

#[test]
fn the_reused_package_merge_gives_the_reference_lengths_table_for_table() {
    // The per thread lists and the early stop at a repeated level must
    // move no length: every table below goes through both builders. The
    // shapes are the ones that decide ties and depth: few symbols, many
    // equal weights, weights spread over many orders of magnitude, deep
    // Fibonacci runs, and each format's alphabet sizes.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let check = |frequency: &[u32]| {
        let mut ours = vec![0u8; frequency.len()];
        let mut theirs = vec![0u8; frequency.len()];
        code_lengths(frequency, &mut ours);
        code_lengths_reference(frequency, &mut theirs);
        assert_eq!(ours, theirs, "frequencies {frequency:?}");
    };
    for size in [2usize, 3, 16, 20, 28, 44, 64, 80, 299, 306] {
        for round in 0..400 {
            let used = 1 + (next() as usize % size);
            let spread = round % 5;
            let mut frequency = vec![0u32; size];
            for _ in 0..used {
                let symbol = next() as usize % size;
                frequency[symbol] = match spread {
                    0 => 1 + (next() % 4) as u32,
                    1 => 1 + (next() % 1000) as u32,
                    2 => 1u32 << (next() % 24),
                    3 => (next() >> 40) as u32 + 1,
                    _ => 7,
                };
            }
            check(&frequency);
        }
    }
    let mut fibonacci = vec![0u32; 306];
    let (mut a, mut b) = (1u32, 1u32);
    for slot in fibonacci.iter_mut().take(44) {
        *slot = a;
        (a, b) = (b, a.saturating_add(b));
    }
    check(&fibonacci);
    fibonacci.reverse();
    check(&fibonacci);
    check(&[u32::MAX; 306]);
    check(&[0; 306]);
}

#[test]
fn the_code_is_no_worse_than_a_flat_one() {
    // The property that matters for ratio: the depth limited code's cost
    // never exceeds the flat code's on the same frequencies.
    let mut x: u32 = 12345;
    let mut frequency = vec![0u32; 306];
    for slot in frequency.iter_mut() {
        x = x.wrapping_mul(1103515245).wrapping_add(12345);
        *slot = (x >> 20) % 97;
    }
    let lengths = round_trip(&frequency);
    let used = frequency.iter().filter(|&&f| f > 0).count() as u32;
    let flat = (u32::BITS - (used - 1).leading_zeros()) as u64;
    let ours: u64 = frequency
        .iter()
        .zip(&lengths)
        .map(|(&f, &l)| u64::from(f) * u64::from(l))
        .sum();
    let flat_cost: u64 = frequency.iter().map(|&f| u64::from(f) * flat).sum();
    assert!(ours <= flat_cost, "{ours} bits against a flat {flat_cost}");
}

#[test]
fn the_bit_writer_is_the_readers_mirror() {
    let mut out = BitWriter::new();
    out.push(0b1, 1);
    out.push(0b0110, 4);
    out.push(0x5a5a, 16);
    out.push(0, 3);
    let (bytes, valid) = out.finish();
    let bytes = bytes.to_vec();
    assert_eq!(valid, 8);
    let mut input = SliceBits::new(&bytes);
    assert_eq!(input.read(1).expect("a bit"), 0b1);
    assert_eq!(input.read(4).expect("four"), 0b0110);
    assert_eq!(input.read(16).expect("sixteen"), 0x5a5a);
    assert_eq!(input.read(3).expect("decoyed"), 0);
}

// ---- the ladders, in the encoding direction ---------------------------------

/// Every row of `specs/vectors-H/ladders.tsv` for `generation`, as
/// `(alphabet, slot, extra bits, first, last)`.
fn ladder_rows(generation: &str) -> Vec<(String, usize, u8, u64, u64)> {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../specs/vectors-H/ladders.tsv");
    let text = std::fs::read_to_string(path).expect("ladders.tsv");
    text.lines()
        .skip(1)
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .filter(|cell| cell.len() >= 7 && cell[0] == generation)
        .map(|cell| {
            (
                cell[1].to_string(),
                cell[2].parse().unwrap(),
                cell[3].parse().unwrap(),
                cell[5].parse().unwrap(),
                cell[6].parse().unwrap(),
            )
        })
        .collect()
}

#[cfg(feature = "repo-tests")]
#[test]
fn the_rar5_ladders_encode_what_the_committed_table_decodes() {
    // Section 6.4: the ladder is walked in the encoding direction at the
    // same width the decoding direction uses. Both ends of every slot.
    let mut rows = 0;
    for (alphabet, slot, extra, first, last) in ladder_rows("rar5") {
        let ends = [(first, 0u64), (last, (1u64 << extra) - 1)];
        for (value, offset) in ends {
            let Ok(value) = u32::try_from(value) else {
                continue; // past what a u32 dictionary can name
            };
            let got = match alphabet.as_str() {
                "length" => rar5::length_fields(value),
                "distance" => rar5::distance_fields(value),
                other => panic!("an alphabet this test does not know: {other}"),
            };
            assert_eq!(got, (slot, offset as u32, extra), "{alphabet} {value}");
        }
        rows += 1;
    }
    assert_eq!(rows, 108, "every RAR 5 row of ladders.tsv");
}

#[cfg(feature = "repo-tests")]
#[test]
fn the_rar3_ladders_encode_what_the_committed_table_decodes() {
    let mut rows = 0;
    for (alphabet, slot, extra, first, last) in ladder_rows("rar3") {
        for (value, offset) in [(first as u32, 0u32), (last as u32, (1u32 << extra) - 1)] {
            let got = match alphabet.as_str() {
                // The fresh arm's base is 3 and the repeated arm's is 2.
                "length" => rar29::length_fields(value - 3),
                "repeat_length" => rar29::length_fields(value - 2),
                "distance" => rar29::distance_fields(value),
                "short_distance" => rar29::short_fields(value),
                other => panic!("an alphabet this test does not know: {other}"),
            };
            assert_eq!(got, (slot, offset, extra), "{alphabet} {value}");
        }
        rows += 1;
    }
    assert_eq!(rows, 124, "every RAR 3 row of ladders.tsv");
}

// ---- the repeated distance model ----------------------------------------------

#[test]
fn the_repeat_model_pushes_rotates_and_leaves_alone() {
    let start = Repeats::default();
    let pushed = start
        .after(Arm::Fresh, 10, 5)
        .after(Arm::Fresh, 20, 6)
        .after(Arm::Short, 30, 2)
        .after(Arm::Fresh, 40, 7);
    assert_eq!(pushed.distance, [40, 30, 20, 10]);
    assert_eq!(pushed.last_length, 7);
    // H1 section 3.5's own example: with `k = 2`, `[a, b, c, d]` becomes
    // `[c, a, b, d]`.
    let rotated = pushed.after(Arm::Repeat(2), 20, 9);
    assert_eq!(rotated.distance, [20, 40, 30, 10]);
    assert_eq!(rotated.last_length, 9);
    // The last match again, and a literal, change nothing.
    let same = rotated.after(Arm::Last, 20, 9).after(Arm::Literal, 65, 1);
    assert_eq!(same.distance, rotated.distance);
    assert_eq!(same.last_length, rotated.last_length);
    assert_eq!(rotated.slot_of(30), Some(2));
    assert_eq!(start.slot_of(0), None, "an empty slot holds no distance");
}

#[test]
fn the_low_distance_run_is_written_only_where_every_follower_agrees() {
    // Distances whose low four bits (of distance - 1) are all 5, far
    // enough for the low distance alphabet.
    let agreeing: Vec<Token> = (0..20).map(|i| far(0x1000 + 16 * i + 6)).collect();
    let mut forms = Vec::new();
    rar29::low_forms(&agreeing, &mut forms);
    // The first sets the remembered part; the run serves sixteen; the
    // decoyed left over are a run of their own, which the next table read
    // cuts short on the decoder's side too.
    assert_eq!(forms[0], 5);
    assert_eq!(forms[1], 16);
    assert!(forms[2..17].iter().all(|&form| form == rar29::LOW_IN_RUN));
    assert_eq!(forms[17], 16);
    assert!(forms[18..].iter().all(|&form| form == rar29::LOW_IN_RUN));

    // One dissenter inside the sixteen forbids the run over it.
    let mut broken = agreeing.clone();
    broken[9] = far(0x1000 + 16 * 9 + 7);
    rar29::low_forms(&broken, &mut forms);
    assert!(forms[..9].iter().all(|&form| form == 5));
    assert_eq!(forms[9], 6);

    // A near match has no low part at all.
    rar29::low_forms(&[far(9)], &mut forms);
    assert!(forms.is_empty());
}

// ---- the block boundary search ----------------------------------------------------

#[test]
fn the_cut_covers_every_token_once_and_finds_a_change_of_statistics() {
    // Text then noise: two populations of literals that no one table set
    // prices well. The cut must tile the stream and put a boundary near
    // the change.
    let mut tokens: Vec<Token> = Vec::new();
    let mut x = 1u32;
    for i in 0..400_000u32 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let byte = if i < 200_000 {
            b"etaoin shrdlu"[(x >> 16) as usize % 13]
        } else {
            (x >> 16) as u8
        };
        tokens.push(Token::literal(byte));
    }
    let wire = rar5::wire_for_tests();
    let mut ranges = Vec::new();
    cut::cut(&wire, &tokens, &mut ranges);
    assert_eq!(ranges.first().map(|r| r.start), Some(0));
    assert_eq!(ranges.last().map(|r| r.end), Some(tokens.len()));
    assert!(ranges.windows(2).all(|pair| pair[0].end == pair[1].start));
    assert!(ranges.iter().all(|range| !range.is_empty()));
    let nearest = ranges
        .iter()
        .map(|range| range.end.abs_diff(200_000))
        .min()
        .unwrap();
    assert!(
        nearest <= 4096,
        "no boundary within a fine grid step of the change: {ranges:?}"
    );
    let mut again = Vec::new();
    cut::cut(&wire, &tokens, &mut again);
    assert_eq!(again, ranges, "the cut is deterministic");
}

// ---- the counts the cut hands the emitter ----------------------------------------

/// Literals, fresh matches, repeats and last-match tokens over every byte
/// value, seeded: a stream whose counts reach every alphabet.
fn mixed_tokens(len: usize, seed: u32) -> Vec<Token> {
    let mut x = seed;
    let mut tokens = Vec::with_capacity(len);
    while tokens.len() < len {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let token = match (x >> 24) % 16 {
            0 => Token {
                arm: Arm::Fresh,
                length: 8 + (x >> 8) as u16 % 32,
                distance: 1 + (x >> 4) % 0x1000,
            },
            1 => Token {
                arm: Arm::Repeat(((x >> 12) % 4) as u8),
                length: 4 + (x >> 8) as u16 % 16,
                distance: 1 + (x >> 4) % 0x1000,
            },
            2 => Token {
                arm: Arm::Last,
                length: 4,
                distance: 1,
            },
            _ => Token::literal((x >> 16) as u8),
        };
        tokens.push(token);
    }
    tokens
}

#[test]
fn every_format_visits_a_literal_as_its_byte_alone() {
    // `lz::Format::visit`'s rule, which `cut::Running::new` counts
    // literals by without asking the format: one symbol, the byte, and no
    // plain bit, in both formats.
    fn check(format: &impl lz::Format, name: &str) {
        for byte in 0..=255u8 {
            let mut symbols = Vec::new();
            let plain = format.visit(Token::literal(byte), &mut |symbol| symbols.push(symbol));
            assert_eq!(symbols, [usize::from(byte)], "{name}, byte {byte}");
            assert_eq!(plain, 0, "{name}, byte {byte}");
        }
    }
    check(&rar5::wire_for_tests(), "RAR 5");
    check(&rar29::wire_for_tests(), "RAR 2.9");
}

#[test]
fn the_cuts_counts_are_each_blocks_own_symbol_counts() {
    // `cut::cut_counting` hands the emitter a table of counts a block,
    // which the emitter then takes in place of counting the tokens itself:
    // each table must be what visiting that block's tokens counts, and the
    // cuts must be `cut::cut`'s. A stream too short to cut gets no table.
    fn check(format: &impl lz::Format, tokens: &[Token], name: &str) {
        let symbols = format.symbols();
        let (mut cuts, mut counts) = (Vec::new(), Vec::new());
        cut::cut_counting(format, tokens, &mut cuts, &mut counts);
        let mut plain_cuts = Vec::new();
        cut::cut(format, tokens, &mut plain_cuts);
        assert_eq!(cuts, plain_cuts, "{name}");
        assert_eq!(counts.len(), cuts.len() * symbols, "{name}");
        for (index, range) in cuts.iter().enumerate() {
            let mut own = vec![0u32; symbols];
            for &token in &tokens[range.clone()] {
                format.visit(token, &mut |symbol| own[symbol] += 1);
            }
            assert_eq!(
                &counts[index * symbols..][..symbols],
                &own[..],
                "{name}, block {index}"
            );
        }
    }
    let rar5 = rar5::wire_for_tests();
    let rar29 = rar29::wire_for_tests();
    for (len, seed) in [(400_000, 7), (90_000, 11), (5_000, 13)] {
        let tokens = mixed_tokens(len, seed);
        check(&rar5, &tokens, &format!("RAR 5, {len} tokens"));
        check(&rar29, &tokens, &format!("RAR 2.9, {len} tokens"));
    }
    let (mut cuts, mut counts) = (Vec::new(), vec![1u32; 4]);
    cut::cut_counting(&rar5, &mixed_tokens(500, 3), &mut cuts, &mut counts);
    assert!(
        matches!(cuts.as_slice(), [only] if *only == (0..500)),
        "one cut, the whole stream: {cuts:?}"
    );
    assert!(
        counts.is_empty(),
        "a stream too short to cut is counted by the emitter"
    );
}

#[test]
fn the_log2_table_is_the_squaring_routines_own() {
    // `log2_sixteenths` reads a table under 4,096 and squares above it:
    // every value the table answers, and the values around its edge, give
    // the routine's own answer.
    use crate::carry::c_lz::codec::rar50::{log2_sixteenths, log2_sixteenths_squared};
    for value in (1u64..8192).chain([1 << 20, (1 << 32) + 5, u64::MAX]) {
        assert_eq!(
            log2_sixteenths(value),
            log2_sixteenths_squared(value),
            "value {value}"
        );
    }
}
