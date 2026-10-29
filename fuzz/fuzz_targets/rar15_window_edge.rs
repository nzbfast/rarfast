//! Spec A: a RAR 1.x member long enough to go round the decoder's history
//! ring several times.
//!
//! There is no RAR 1.5 encoder in this crate, so this target cannot write
//! copies at the ring's end on purpose and read them back. What it forces
//! instead is the precondition: the seed is tiled into enough packed
//! bytes that the member laps the ring, so copies whose source or
//! destination meets the ring's end are reached at all.
//! `crates/rarkit/tests/window_edge_targets.rs` is the proof that the lap
//! really happens. The decoder indexes its ring by checked arithmetic
//! only, so the verdict is a panic or a member that delivers more than it
//! declared.
//!
//! The same seed is then put through spec A 7.4's body: a declared size,
//! solid flags and up to four members cut from the bytes as they stand.
//! `rar1x_member` drives that body on one member at a time, from genuine
//! seeds.
//!
//! This header is adapted from the file's earlier text, which served the
//! decoder before this one.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar15;

fuzz_target!(|data: &[u8]| {
    rar15::fuzz_window_edge(data);
    rar15::fuzz_decode(data);
});
