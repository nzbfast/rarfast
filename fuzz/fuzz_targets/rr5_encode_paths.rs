#![no_main]
//! Spec L 3.5.4: the streaming encoder and the whole-slice team must write
//! the SAME record.
//!
//! The encode has two implementations now, chosen by whether the caller
//! holds every protected byte and by section 7's per-worker gate, and two
//! implementations of one deterministic function is exactly the shape a
//! differential target is for.
//!
//! **Why the protected length is SYNTHESISED and not just the input.** The
//! team's gate is 1 MiB of protected bytes per worker, and libFuzzer's
//! default input cap is 4 KiB: a target that encoded the raw input would
//! run the streaming path on BOTH sides for ever and compare it with
//! itself. The first campaign did exactly that - 5.3 million runs, no
//! finding, and not one of them past the gate. So a knob byte chooses a
//! length up to 4 MiB and the input's bytes are tiled to fill it, which
//! costs the fuzzer nothing and puts roughly a third of the runs on the
//! wide path, at real geometries: the last data shard falling short of
//! `G`, an odd length that `Coefficient::fold` would truncate to a whole
//! symbol, the 64 KiB group boundary, and the `k = 200` ceiling.
//!
//! Tiling makes the bytes repetitive, which matters to a compressor and
//! not at all here: what is compared is two implementations of one linear
//! function over those bytes, and the coefficients do not care.
//!
//! Width 1 is the streaming path by construction - the gate cannot give a
//! team of one any work - so the comparison is always serial against wide.

use libfuzzer_sys::fuzz_target;
use rarkit::internals::recovery::rr5_encode_workers;

/// The most protected bytes one run will build.
const MAX_PROTECTED: usize = 4 << 20;

fuzz_target!(|data: &[u8]| {
    // Three bytes of knobs, then the pattern the protected bytes are tiled
    // from.
    let [percent, workers, size, pattern @ ..] = data else {
        return;
    };
    if pattern.is_empty() {
        return;
    }
    let percent = u32::from(*percent % 100) + 1;
    let workers = usize::from(*workers % 33) + 2;
    // Quadratic in the knob so the small lengths - where the geometry's
    // corners are - stay dense while the top of the range still clears the
    // gate by several workers.
    let len = (1 + usize::from(*size) * usize::from(*size) * 64).min(MAX_PROTECTED);

    let mut protected = Vec::with_capacity(len);
    while protected.len() < len {
        let take = pattern.len().min(len - protected.len());
        protected.extend_from_slice(&pattern[..take]);
    }

    let serial = rr5_encode_workers(&protected, percent, 1);
    let wide = rr5_encode_workers(&protected, percent, workers);
    match (serial, wide) {
        (Ok(serial), Ok(wide)) => assert_eq!(
            serial, wide,
            "{len} protected bytes at {percent}% came out differently on \
             {workers} workers than on the streaming path"
        ),
        (Err(_), Err(_)) => {}
        (a, b) => panic!(
            "{len} protected bytes at {percent}%: the two paths disagreed \
             on whether a record exists at all: {} against {}",
            a.is_ok(),
            b.is_ok()
        ),
    }
});
