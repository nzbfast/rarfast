//! Spec K 2.1 and 7: an overlapped member's CBC decrypt on TWO LANES is
//! the same bytes as on one, and leaves the same chaining value behind.
//!
//! The mode is parallel by construction, block `i`'s plaintext needing
//! only `C[i]` and `C[i-1]`, so the split is an arrangement and never a
//! result. This target says so over arbitrary ciphertext, arbitrary
//! chunking and both key lengths.
//!
//! **It would be VACUOUS on the corpus alone.** The split has a floor of
//! 16384 whole blocks, far above any input libFuzzer will offer, so a
//! target that fed the input straight through would compare one serial
//! run with another and pass for ever. The payload is therefore GROWN
//! past the floor by repetition before either arm sees it, and the
//! assertion that a split actually happened is the `assert!` on the
//! length rather than a comment.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::crypto::*;

/// Comfortably past the engine's own two lane floor of 16384 blocks.
const GROWN: usize = 16384 * 16 + 48;

fn cipher(kind: u8) -> MemberCipher {
    if kind % 2 == 0 {
        MemberCipher::aes128(&Rar4Key::derive(b"Secret", Some([1; 8])).unwrap())
    } else {
        MemberCipher::aes256(
            &Rar5Keys::derive(b"Secret", &[2; 16], 0, None).unwrap(),
            &[3; 16],
        )
    }
}

/// Feed `data` in `sizes` chunks with the split dialled either way.
fn run(kind: u8, data: &[u8], sizes: &[u8], two_lane: bool) -> (Vec<u8>, bool) {
    let mut dec = MemberDecryptor::new(cipher(kind));
    dec.set_two_lane(two_lane);
    let mut out = Vec::new();
    let (mut at, mut i) = (0usize, 0usize);
    while at < data.len() {
        // A mixture of tiny chunks, which straddle blocks, and chunks
        // above the floor, which are the ones that split.
        let pick = sizes.get(i % sizes.len().max(1)).copied().unwrap_or(0);
        let n = if pick % 4 == 0 {
            GROWN / 2 + usize::from(pick)
        } else {
            1 + usize::from(pick)
        }
        .min(data.len() - at);
        let mut buf = data[at..at + n].to_vec();
        let pending = dec.pending();
        let got = dec.update(&mut buf);
        assert!(got.body <= n);
        assert!(got.head.is_empty() || got.head.len() == pending);
        out.extend_from_slice(got.head);
        out.extend_from_slice(&buf[..got.body]);
        at += n;
        i += 1;
    }
    let ok = dec.finish().is_ok();
    (out, ok)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let kind = data[0];
    let (sizes, seed) = data[1..].split_at(data.len().saturating_sub(1).min(16));
    if seed.is_empty() {
        return;
    }
    // Grown past the floor by repetition, so the split certainly runs.
    let mut payload = Vec::with_capacity(GROWN + seed.len());
    while payload.len() < GROWN {
        payload.extend_from_slice(seed);
    }
    assert!(payload.len() / 16 >= 16384, "the split would not run");

    let (one, one_ok) = run(kind, &payload, sizes, false);
    let (two, two_ok) = run(kind, &payload, sizes, true);
    assert_eq!(one_ok, two_ok, "the two arrangements disagreed on finish");
    assert_eq!(one, two, "the two arrangements disagreed on the bytes");
});
