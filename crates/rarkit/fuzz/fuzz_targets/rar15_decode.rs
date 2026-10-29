//! SPEC-A 7.4: `(target up to 1 MiB, solid-flag bitmap, one to four packed
//! chunks)` decoded by the RAR 1.5 decoder. No panic, and on `Ok` the
//! output is no larger than the target.
//!
//! SPEC-A 4.11 and 6.1 are what make a SHORT member `Ok`
//! rather than an error, and the body's own doc comment carries the
//! reasoning and the sections.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rarkit::internals::rar15::fuzz_decode(data);
});
