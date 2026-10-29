//! SPEC-H1 6.3, the fourth target: long literal runs at the TABLE
//! BOUNDARIES of one RAR 2.9 stream, round tripped against the bytes the
//! builder wrote. An open item from 19 Sep 2026.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rarkit::internals::rar3_lz::fuzz_literal_burst(data);
});
