//! SPEC-H2 section 3.6 against the ring: the drain must never let the
//! ring lap a byte that has not left it, on a filtered member, at any
//! ring a dictionary can give.
//!
//! Found in the md128k work on 23 Sep 2026 under the shipped walk: a
//! filter span served in the middle of a drain batch left the rest of the
//! batch in the ring, the next drain was due a whole batch after the
//! bytes PRODUCED, and the tape walk writes a whole drain batch between
//! two due tests. On a ring of two batches (every dictionary up to 2 MiB)
//! a release build then emitted lapped bytes. `rar5_filter_offload` could
//! not see it: it compares the handed drain with the synchronous one, and
//! both carried the defect.
//!
//! So the input is a SCRIPT for one member three rings long by
//! construction, on a rung of the dictionary ladder from a stated 128 KiB
//! budget to 4 MiB, with runs of a batch and a byte either side, runs to
//! the next batch edge, spans on and around that edge and matches that
//! overshoot it, driven at the tape walk's cadence and compared with the
//! same member in a ring that cannot lap.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar5;

fuzz_target!(|data: &[u8]| {
    let _ = rar5::drain_lap_agrees(data);
});
