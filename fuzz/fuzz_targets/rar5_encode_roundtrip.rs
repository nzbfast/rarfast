//! Spec H3 section 9.3: arbitrary bytes through the RAR 5 encoder.
//!
//! The specification asks this target to encode arbitrary input and
//! DECODE IT BACK, asserting equality, through spec H2's decoder. It also
//! asserts that no input panics, that the encoder is deterministic, and
//! that the block chain it produces is walkable, which is the property H2
//! section 3.1 says the whole performance story rests on.
//!
//! It has a SOLID mode as well (spec H3 section 4): the input is cut into
//! members that one encoder writes as a set, carrying the output history
//! and the match finder's index over it, and the set is read back through
//! one decoder stream. Every block chain in the set is walked, and a
//! shrunken history slack makes the engine SLIDE its history mid set,
//! which is the one place the index is built again.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar20;

const DICTIONARY: u32 = 128 * 1024;

/// Walk a member's chain by its headers alone, as a decoder does: every
/// block must be located without decoding a symbol, the checksums must
/// hold, and the last block must be the last one.
fn walk(packed: &[u8]) {
    let mut at = 0usize;
    let mut seen_last = false;
    while at < packed.len() {
        assert!(!seen_last, "a block follows the last one");
        assert!(at + 2 <= packed.len(), "a header is cut short");
        let flags = packed[at];
        let checksum = packed[at + 1];
        let width = usize::from((flags >> 3) & 3) + 1;
        assert!(width <= 3, "a four byte block size");
        assert!(at + 2 + width <= packed.len(), "a size is cut short");
        let size_bytes = &packed[at + 2..at + 2 + width];
        let mixed = size_bytes.iter().fold(flags ^ checksum, |acc, &b| acc ^ b);
        assert_eq!(mixed, 0x5a, "the block header checksum");
        let mut size = 0usize;
        for (index, &byte) in size_bytes.iter().enumerate() {
            size |= usize::from(byte) << (8 * index);
        }
        at += 2 + width + size;
        assert!(at <= packed.len(), "a payload runs past the member");
        seen_last = flags & 0x40 != 0;
    }
    assert!(seen_last, "the chain has no last block");
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let level = data[0] % 6;
    // Zero cuts is the non solid member this target has always driven;
    // anything else is a solid set of that many members.
    let cuts = usize::from(data[1] & 7);
    let input = &data[2..];

    if cuts == 0 {
        let packed = rar20::rar5_encode(input, level, DICTIONARY);
        assert_eq!(
            rar20::rar5_encode(input, level, DICTIONARY),
            packed,
            "the encoder is not deterministic"
        );
        walk(&packed);
        let back =
            rarkit::internals::rar5::decode_member(&packed, input.len() as u64, 128 * 1024, 0, false)
                .expect("spec H2's decoder reads what this encoder wrote");
        assert!(back == input, "the round trip changed the bytes");
        return;
    }

    let each = input.len().div_ceil(cuts).max(1);
    let members: Vec<&[u8]> = input.chunks(each).collect();
    if members.is_empty() {
        return;
    }
    // A slack of a few kilobytes forces the engine to slide its history
    // inside the set, where the shipped one is megabytes and never would.
    let slack = 1024 + usize::from(data[1]) * 64;
    let packed = rar20::rar5_encode_solid_slid(&members, slack, level, DICTIONARY);
    assert_eq!(
        rar20::rar5_encode_solid_slid(&members, slack, level, DICTIONARY),
        packed,
        "the solid encoder is not deterministic"
    );
    // The BATCHED entry stages several members and parses them as one
    // wave, so the parse stays wide across the member boundaries. It is
    // a width change and may not move a byte, whatever the set is cut
    // into and however often the history slides under it.
    assert_eq!(
        rar20::rar5_encode_solid_batched(&members, Some(slack), level, DICTIONARY),
        packed,
        "batching the solid set moved the bytes"
    );
    for member in &packed {
        walk(member);
    }
    let chain: Vec<(&[u8], u64)> = packed
        .iter()
        .zip(&members)
        .map(|(p, m)| (p.as_slice(), m.len() as u64))
        .collect();
    let back = rarkit::internals::rar5::decode_solid_chain(&chain, u64::from(DICTIONARY), 0, false)
        .expect("spec H2's decoder reads the solid set this encoder wrote");
    assert!(
        back.iter().map(Vec::as_slice).eq(members.iter().copied()),
        "the solid round trip changed the bytes"
    );
});
