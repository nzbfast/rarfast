//! SPEC-H1 6.3: one block header and its code length tables, which
//! reaches the code length machinery without paying for symbol decode.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rarkit::internals::rar3_lz::fuzz_tables(data);
});
