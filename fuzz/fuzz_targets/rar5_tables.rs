//! SPEC-H2 section 6.3: bytes in, read one block's tables.
//!
//! The first byte picks the algorithm version, so both the 430 length and
//! the 446 length reads of section 3.3 are covered.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar5;

fuzz_target!(|data: &[u8]| {
    let Some((&algorithm, rest)) = data.split_first() else {
        return;
    };
    let _ = rar5::read_block_tables(rest, algorithm & 1);
});
