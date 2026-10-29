//! The packed bound and the packed block ceiling.

use super::*;

#[test]
fn the_packed_bound_holds_for_bytes_no_level_compresses() {
    // `drive::packed_most`, which the writer's `Run::packed_bound` is:
    // what a member it has not encoded yet can pack to, and what a held
    // member's buffer is reserved to under a caller's ceiling. At the old
    // 64 bytes a block this failed at every level (about 2,270 bytes over
    // 4 MiB, against 1,024 allowed), and 20 MiB of SHA-256 output at -m5
    // outgrew a buffer reserved to it. RAR 5 a member at a time and a
    // window at a time, and RAR 4.
    use super::drive::packed_most;
    for (len, seed) in [(4 << 20, 5u64), (300 << 10, 6), (1000, 7)] {
        let data = incompressible(len, seed);
        let bound = packed_most(data.len());
        for level in 1u8..=5 {
            let new5 = || rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, 2 << 20));
            let mut region = Vec::new();
            new5().encode_region(&data, 0, true, &mut region);
            assert!(
                region.len() <= bound,
                "RAR 5 -m{level} {len}: {} > {bound}",
                region.len()
            );
            let mut five = new5();
            let mut windowed = Vec::new();
            let chunks: Vec<&[u8]> = data.chunks(2 << 20).collect();
            for (index, chunk) in chunks.iter().enumerate() {
                five.encode_chunk(chunk, index + 1 == chunks.len(), &mut windowed);
            }
            assert!(windowed.len() <= bound, "RAR 5 -m{level} {len} windowed");
            let mut old = Vec::new();
            rar29::Rar29Encoder::new(rar29::EncodeOptions::for_level(level, 2 << 20))
                .encode_region(&data, 0, true, &mut old);
            assert!(
                old.len() <= bound,
                "RAR 4 -m{level} {len}: {} > {bound}",
                old.len()
            );
        }
    }
}

// ---- the packed block ceiling ------------------------------------------------------

/// Every block of a RAR 5 packed stream, as `(bytes, is_last)`, header
/// included.
fn rar5_block_sizes(packed: &[u8]) -> Vec<(usize, bool)> {
    let mut at = 0;
    let mut out = Vec::new();
    while at < packed.len() {
        let block = crate::rar5_lz::block::block_in_hand(&packed[at..]).expect("a block");
        out.push((block.past(), block.ends_member()));
        at += block.past();
        if block.ends_member() {
            break;
        }
    }
    assert_eq!(at, packed.len(), "the blocks tile the stream");
    out
}

#[test]
fn every_block_packs_under_the_ceiling_that_keeps_unrar_parallel() {
    // Reference unrar decodes a member on one thread from its first block
    // over about 128 KiB packed to its end. Incompressible bytes are the
    // case that used to make one block of a whole 256 KiB parse block, so
    // they sit between text here, at every level.
    let mut mixed = few_words(300_000, 11);
    mixed.extend_from_slice(&nothing_to_find(700_000, 12));
    mixed.extend_from_slice(&few_words(300_000, 13));
    // And the other end: a highly repetitive input, whose blocks are long
    // in bytes and short in packed size.
    let repetitive: Vec<u8> = (0..1_200_000u32)
        .map(|i| b"abcab"[(i % 5) as usize])
        .collect();
    let most = rar5::BLOCK_BYTES_MOST_FOR_TESTS;
    assert_eq!(most, 122_880, "SPEC-H3 6.2");
    for (name, input) in [("mixed", &mixed), ("repetitive", &repetitive)] {
        for level in 1u8..=5 {
            let mut encoder =
                rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, 2 << 20));
            let packed = encoder.encode(input);
            let blocks = rar5_block_sizes(&packed);
            let largest = blocks.iter().map(|&(bytes, _)| bytes).max().unwrap();
            assert!(
                largest <= most,
                "{name} level {level}: a block of {largest} bytes is over the ceiling of {most}"
            );
            assert_eq!(
                &rar5_decode(&packed, input.len(), 2 << 20),
                input,
                "{name} level {level}"
            );
        }
    }
}

#[test]
fn a_block_that_packs_over_the_ceiling_is_split_and_still_decodes() {
    // The cut prices blocks under the ceiling, so the split in `emit` is
    // reached only when its estimate misses. Hand `emit` one range of
    // incompressible literals far larger than a small ceiling and read
    // back what it wrote.
    use super::drive::Emit;
    let bytes = nothing_to_find(40_000, 21);
    let tokens: Vec<Token> = bytes.iter().map(|&byte| Token::literal(byte)).collect();
    let most = 4096;
    let wire = rar5::wire_with_ceiling_for_tests(most);
    let mut packed = Vec::new();
    let whole = 0..tokens.len();
    wire.emit(
        &tokens,
        std::slice::from_ref(&whole),
        true,
        &[],
        &mut packed,
    );
    let blocks = rar5_block_sizes(&packed);
    assert!(
        blocks.len() >= 10,
        "40,000 noise bytes need at least ten 4 KiB blocks: {blocks:?}"
    );
    assert!(blocks.iter().all(|&(size, _)| size <= most), "{blocks:?}");
    let lasts: Vec<bool> = blocks.iter().map(|&(_, last)| last).collect();
    assert_eq!(lasts.iter().filter(|&&last| last).count(), 1);
    assert!(lasts[lasts.len() - 1], "only the final block is the last");
    assert_eq!(rar5_decode(&packed, bytes.len(), 128 << 10), bytes);
}
