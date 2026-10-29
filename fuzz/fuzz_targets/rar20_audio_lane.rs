//! Spec D 1.4.2: the RAR 2.0 multimedia predictor's NARROW LANE, against a
//! wide reference of the same section, over the same residuals.
//!
//! `lz20::audio` narrows its multiplier to `i16` and its accumulator to
//! `u16` under `#[cfg(target_arch = "x86_64")]`, and keeps `i32` and
//! `u32` on every other target. Spec D 1.4.2 proves that exact:
//! `|e| <= 1024` and `|v_j| <= 255`, so a term is at most 1,279 and at
//! most 32 land before the channel adapts, so 40,928 is the most any
//! accumulator holds and a `u16` carries it with 24,607 to spare.
//!
//! That proof had never been MEASURED on the arm it licenses. Every fuzz
//! campaign in this repository before 22 Sep 2026 ran on an aarch64 box,
//! where the narrow arm does not compile, and no target reached the
//! predictor except through a RAR 2.0 block header whose multimedia bit
//! and whose 256-per-channel code length table a coverage guided fuzzer
//! must first build. This target has no grammar in front of it: the input
//! IS the residual stream, so every execution enters the model.
//!
//! Two properties, and the second is not implied by the first:
//!
//! 1. the shipped model and the reference agree BYTE FOR BYTE. On x86-64
//!    that is the narrow lane against a wide one, which is the whole
//!    point; on aarch64 it is the wide lane against a differently shaped
//!    wide one, which is worth running and is what lets a vector found
//!    here be pinned as a regression on both architectures.
//! 2. no accumulator passes spec D 1.4.2's bound. Read on the REFERENCE,
//!    which cannot wrap, so the bound is reported rather than lost.
//!
//! THE PAYLOAD IS GROWN BY REPETITION, and that is not decoration: a
//! channel's accumulators are cleared every 32 samples, so a short input
//! never reaches one adaptation window and the property under test never
//! engages. The target asserts the engagement it arranged.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar20;

/// Samples the payload is grown to, so every channel crosses many
/// adaptation windows: 4,096 samples is 1,024 per channel at the widest
/// rotation, which is 32 windows.
const FLOOR: usize = 4_096;
/// The ceiling on that growth, so an execution stays cheap enough for the
/// campaign to run millions of them.
const CEILING: usize = 16_384;
/// Samples a channel takes before it adapts (spec D 1.2.2 step 7).
const WINDOW: usize = 32;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    // 1 to 4, which is what a multimedia block header's two bit field
    // plus one can name.
    let channels = usize::from(data[0] & 3) + 1;
    let seed = &data[1..];

    // Grow by repetition to the floor, then stop: the shape of the input
    // is the fuzzer's to choose and the LENGTH is this target's, so a
    // short interesting seed still crosses the windows that matter.
    let mut residuals = Vec::with_capacity(FLOOR.max(seed.len()).min(CEILING));
    while residuals.len() < FLOOR && residuals.len() + seed.len() <= CEILING {
        residuals.extend_from_slice(seed);
    }
    if residuals.is_empty() {
        residuals.extend_from_slice(&seed[..seed.len().min(CEILING)]);
    }

    // The engagement this target arranged, asserted rather than assumed:
    // every channel must reach at least one adaptation window, or the
    // bound below is a property of nothing.
    assert!(
        residuals.len() >= channels * WINDOW,
        "the payload never reached an adaptation window: {} samples over \
         {channels} channels",
        residuals.len()
    );

    let (want, peak) = rar20::audio_reference(channels, &residuals);
    let got = rar20::audio_shipped(channels, &residuals);
    assert_eq!(
        got.len(),
        want.len(),
        "the shipped model dropped samples at {channels} channels"
    );
    if got != want {
        let at = got
            .iter()
            .zip(&want)
            .position(|(a, b)| a != b)
            .unwrap_or_default();
        panic!(
            "the {} lane disagrees with spec D at sample {at} of {}, \
             {channels} channels: shipped {:#04x}, reference {:#04x}",
            if rar20::AUDIO_NARROW_LANE {
                "narrow"
            } else {
                "wide"
            },
            got.len(),
            got[at],
            want[at]
        );
    }
    assert!(
        peak <= rar20::AUDIO_ACCUMULATOR_BOUND,
        "spec D 1.4.2's bound is exceeded, so the narrow lane's u16 is not \
         exact: {peak} against {}, {channels} channels",
        rar20::AUDIO_ACCUMULATOR_BOUND
    );
});
