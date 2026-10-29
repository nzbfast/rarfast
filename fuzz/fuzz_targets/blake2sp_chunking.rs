#![no_main]
//! Spec L 6: `blake2sp_chunking`, arbitrary input and cut points against
//! the one-shot digest.
//!
//! The first byte chooses the worker allowance, so both arrangements of
//! spec L 3.3.3 are driven; the rest is read as a run of cut points and
//! then as the input. Every chunking of the same bytes must give the
//! digest of 3.3.1, which the one-shot path answers.

use libfuzzer_sys::fuzz_target;
use rarkit::internals::recovery::{blake2sp, Blake2sp};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // Byte 0: the worker allowance, 1 to 8.
    let workers = (data[0] % 8) as usize + 1;
    let rest = &data[1..];
    // Byte 1, when there is one: how many of the following bytes are cut
    // points rather than input.
    let (cuts, input) = match rest.split_first() {
        Some((count, body)) => {
            let take = (*count as usize).min(body.len());
            body.split_at(take)
        }
        None => (&rest[..0], rest),
    };

    let want = blake2sp(input);
    let mut hasher = Blake2sp::with_workers(workers);
    let mut at = 0;
    for cut in cuts {
        // A cut point is a step of 0 to 255 bytes, so the empty update
        // and the block-, group- and buffer-straddling ones all occur.
        let step = (*cut as usize).min(input.len() - at);
        hasher.update(&input[at..at + step]);
        at += step;
    }
    hasher.update(&input[at..]);
    assert_eq!(hasher.finalize(), want, "workers {workers} cuts {cuts:?}");
});
