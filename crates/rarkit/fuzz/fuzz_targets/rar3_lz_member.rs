//! SPEC-H1 6.3: one non solid RAR 2.9 member, a fixed declared size and a
//! fixed 64 KiB dictionary. No panic, bounded memory, bounded time.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rarkit::internals::rar3_lz::fuzz_member(data);
});
