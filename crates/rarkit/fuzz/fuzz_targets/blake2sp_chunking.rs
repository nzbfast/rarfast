//! SPEC-L section 6: arbitrary input and arbitrary cut points against the
//! one-shot digest. 3.3.2 promises the digest is identical for every
//! chunking, and 3.3.3 promises the same of every arrangement, so both are
//! held to the one-shot answer here.
#![no_main]
use libfuzzer_sys::fuzz_target;

use rarkit::internals::recovery as l;

fuzz_target!(|data: &[u8]| {
    // The first byte picks the worker allowance, the next few are cut
    // points into what is left.
    let Some((&workers, rest)) = data.split_first() else {
        return;
    };
    let (cuts, input) = rest.split_at(rest.len().min(8));
    let want = l::blake2sp(input);

    let mut hasher = l::Blake2sp::with_workers(usize::from(workers % 9));
    let mut at = 0usize;
    for &cut in cuts {
        let step = (usize::from(cut) * 64).min(input.len() - at);
        hasher.update(&input[at..at + step]);
        at += step;
    }
    hasher.update(&input[at..]);
    assert_eq!(hasher.finalize(), want, "chunking changed the digest");
});
