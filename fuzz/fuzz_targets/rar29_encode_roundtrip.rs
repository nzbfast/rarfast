//! Spec H3 section 9.3: arbitrary bytes through the RAR 2.9 encoder.
//!
//! Encode arbitrary input and DECODE IT BACK through spec H1's decoder,
//! asserting equality; and that no input panics, that the encoder is
//! deterministic, and that its output is not empty for a non empty
//! member, so a silently dropped block cannot pass.
//!
//! It has a SOLID mode as well (spec H3 section 4): the input is cut into
//! members that one encoder writes as a set, carrying the output history
//! and the match finder's index over it, and the set is read back as one
//! stream the way spec F concatenates a solid chain. A shrunken history
//! slack makes the engine SLIDE its history mid set.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar20;
use rarkit::internals::rar3_lz::{decode_stream, MemberIn};

const DICTIONARY: u32 = 1 << 20;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let level = data[0] % 6;
    let cuts = usize::from(data[1] & 7);
    let input = &data[2..];

    if cuts == 0 {
        let packed = rar20::rar29_encode(input, level, DICTIONARY);
        assert_eq!(
            rar20::rar29_encode(input, level, DICTIONARY),
            packed,
            "the encoder is not deterministic"
        );
        assert!(!packed.is_empty(), "a member with no packed bytes at all");
        let members = [MemberIn {
            packed: 0..packed.len(),
            unpacked: input.len() as u64,
        }];
        let (out, _) = decode_stream(&packed, &members, DICTIONARY, true)
            .expect("spec H1's decoder reads what this encoder wrote");
        assert!(out[0].data == input, "the round trip changed the bytes");
        return;
    }

    let each = input.len().div_ceil(cuts).max(1);
    let members: Vec<&[u8]> = input.chunks(each).collect();
    if members.is_empty() {
        return;
    }
    let slack = 1024 + usize::from(data[1]) * 64;
    let packed = rar20::rar29_encode_solid_slid(&members, slack, level, DICTIONARY);
    assert_eq!(
        rar20::rar29_encode_solid_slid(&members, slack, level, DICTIONARY),
        packed,
        "the solid encoder is not deterministic"
    );
    // The BATCHED entry stages several members and parses them as one
    // wave, so the parse stays wide across the member boundaries. It is
    // a width change and may not move a byte, whatever the set is cut
    // into and however often the history slides under it.
    assert_eq!(
        rar20::rar29_encode_solid_batched(&members, Some(slack), level, DICTIONARY),
        packed,
        "batching the solid set moved the bytes"
    );
    let mut stream = Vec::new();
    let spans: Vec<MemberIn> = packed
        .iter()
        .zip(&members)
        .map(|(p, m)| {
            let at = stream.len();
            stream.extend_from_slice(p);
            MemberIn {
                packed: at..stream.len(),
                unpacked: m.len() as u64,
            }
        })
        .collect();
    let (out, _) = decode_stream(&stream, &spans, DICTIONARY, true)
        .expect("spec H1's decoder reads the solid set this encoder wrote");
    for (n, member) in members.iter().enumerate() {
        assert!(
            out[n].data == *member,
            "the solid round trip changed member {n}"
        );
    }
});
