//! Spec I section 6: a solid run of members around fuzzed packed data,
//! each driven through the block header, the token loop and the member-end
//! check, and each driven WHETHER OR NOT the one before it faulted.
//!
//! Carrying on past a fault is what spec F's `extract` does with a solid
//! archive, and it is the only shape that reaches a decoder left
//! half-narrowed by its own error return: the divide-by-zero of 20 Sep
//! 2026 lived there, and a single-member target ran past it for weeks.
//! Spec F's whole container has no target yet; this is the member path.
//!
//! Seeding, which spec I section 6 asks for: one corpus file per PPM member
//! of `specs/vectors-I/archives/*.rar`, holding the three bytes this target
//! reads as its header (a declared-size byte, a memory byte and the byte
//! that cuts the second member), then that member's packed data from its
//! fourth byte on, where the block header ends and the range decoder's four
//! priming bytes begin. `fuzz/corpus/` is not committed (see
//! `fuzz/.gitignore`).
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::ppmd::fuzz_ppm_member;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_ppm_member(data);
});
