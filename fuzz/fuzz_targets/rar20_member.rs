//! Spec H3 section 9.3: arbitrary bytes as one RAR 2.0 member's packed
//! data. No panic, no unbounded loop, and bounded working memory: the
//! window is the declared dictionary and nothing else is sized by the
//! input.
//!
//! A success delivers NO MORE than the declared length, and may deliver
//! less. The specification (SPEC-A 4.11, and 6.1, which says in terms "It reaches
//! RAR 2.0 too" with the cross-reference carried by SPEC-H3 3.5) ends a
//! member at the step that BEGINS with the packed input already
//! exhausted, short of the declared size, and that outcome is `Ok` and
//! not an error: the shortfall is the caller's member CHECKSUM to report,
//! as `MemberOutcome::checksum_ok == Some(false)` (SPEC-F 2.5). SPEC-A
//! 6.1 adds that the exact byte count of a short member "is not
//! specified", so no byte count is asserted here. An empty packed input
//! is the limiting case: the member's first step begins exhausted, so it
//! produces nothing whatever it declared.
//!
//! The UPPER bound is still asserted, because SPEC-A section 6 promises
//! it where the length is concerned: no byte of an over-running match is
//! delivered, and the RAR 2.0 driver clamps every step to the room the
//! declared size leaves. That bound is also the memory bound section 6's
//! panics paragraph names, so it is the property worth fuzzing.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar20;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    // The dictionary selector and the declared unpacked size come from the
    // first bytes, so one input shape covers every window size and both
    // sides of the member's end.
    let capacity = rar20::dictionary_size(data[0] & 7);
    let unpacked = u64::from(u16::from_le_bytes([data[1], data[2]]));
    if let Ok(out) = rar20::decode_member(&data[3..], capacity, unpacked) {
        assert!(
            out.len() as u64 <= unpacked,
            "a member never delivers more than its declared size: {} against {unpacked}",
            out.len()
        );
    }
});
