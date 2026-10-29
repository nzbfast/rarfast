//! SPEC-H1 sections 3.6 and 3.9: match distances at the EDGE of the RAR 3
//! window.
//!
//! The three plain H1 targets beside this one decode into a 64 KiB
//! dictionary from a few kilobytes of fuzz input, so none of them laps
//! the ring and none can see the window edge class: an earlier finding
//! showed that below one lap the slot ahead of the write point holds a
//! byte the stream never produced, so a copy that overruns is writing on
//! dead memory and the write side guard has nothing to catch. That is
//! also why `rar5_member` and `rar5_solid_chain` never found the defect
//! `rar5_window_edge` was written for, and this target is that one's
//! model applied to window 1 of `WINDOW-INVARIANTS.md`.
//!
//! So the input is BUILT rather than hoped for: the dictionary is the
//! smallest RAR 3 declares, the member laps it about three times, and the
//! fuzz bytes choose the lead lengths, the gaps and how far inside the
//! window's edge each distance lands. This crate's own RAR 2.9 encoder
//! writes the member, spec H1's decoder reads it back, and the bytes must
//! come back byte for byte - with `--debug-assertions`, under
//! `Window::copy`'s `SpillWatch` on every match.
//!
//! THE LAP IS NOT A FUNCTION OF THE SEED. The first version of this
//! target built one lap of base and appended one pair per three seed
//! bytes, so a ten minute run that never grew its inputs past 25 bytes
//! lapped 1.06 times: that same finding arriving inside a target
//! written for it. The construction now cycles the seed's pairs
//! until the member is three laps long, and
//! `crates/rarkit/tests/window_edge_targets.rs` checks that at the seed
//! lengths libFuzzer really reaches.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar3_lz;

fuzz_target!(|data: &[u8]| {
    rar3_lz::fuzz_window_edge(data);
});
