//! Spec H3 section 9.3: arbitrary bytes as a RAR 2.0 block header and its
//! code length tables, which is the table read on its own.
//!
//! A RAR 2.0 table is STRICT: an oversubscribed length list is refused
//! when the table is built and a lookahead in an incomplete table's unused
//! space is refused at decode. Neither may panic, and a table that builds
//! must decode every lookahead to a symbol inside its alphabet or refuse.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar20;

fuzz_target!(|data: &[u8]| {
    // A tiny declared size, so the run stops just past the tables and the
    // target spends its time where the tables are read.
    let _ = rar20::decode_member(data, 65_536, 64);
});
