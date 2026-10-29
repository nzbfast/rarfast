//! Spec I section 6: one PPM block from arbitrary bytes. A START header is
//! built from the first two bytes (order code, memory byte clamped to 1 to
//! 4 MiB so a run stays fast) and the rest is the block's body.
//!
//! Asserts: no panic, bounded time, and working memory never above
//! `S + 84 KiB` (spec I 4.2).
//!
//! Seeding, which spec I section 6 asks for: one corpus file per PPM member
//! of `specs/vectors-I/archives/*.rar`, holding the two bytes this target
//! reads as its header (an order code and a memory byte), then that
//! member's packed data from its fourth byte on, where the block header
//! ends and the range decoder's four priming bytes begin. `fuzz/corpus/` is
//! not committed (see `fuzz/.gitignore`).
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::ppmd::fuzz_ppm_block;

fuzz_target!(|data: &[u8]| {
    let run = fuzz_ppm_block(data, 1 << 20);
    assert!(run.produced <= 1 << 20);
    if run.model_size > 0 {
        assert!(
            run.held <= run.model_size + 84 * 1024,
            "held {} for a {} byte model",
            run.held,
            run.model_size
        );
    }
});
