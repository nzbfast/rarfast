//! SPEC-H1 6.3: four members of one solid chain, cut by a length prefix,
//! which covers the carry over rules of sections 3.7 and 3.8.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rarkit::internals::rar3_lz::fuzz_solid_chain(data);
});
