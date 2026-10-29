//! SPEC-H2 section 3.6 on the tape path: the RAR 5 filter transforms
//! handed off the drain's thread (`rar5_lz::filters::Offload`) must give
//! the sink the bytes, and the order, the synchronous drain gives it.
//!
//! The member target reaches the offload almost never: its members are
//! 256 KiB, so they take the serial decode. So the input here is not an
//! archive but a SCRIPT for one member driven straight through the drain,
//! 6 MiB long, which laps every ring it picks by construction: 1 and 2 MiB,
//! under four drain batches, which take the short ring form and copy out
//! everything a drain accounts for, and 4 and 8 MiB, which may leave a
//! range in the ring until the next drain. Seeded literal runs and
//! matches, filter records of every kind at points the script chooses,
//! optionally an overlapping pair, and the decode optionally on the only
//! thread of its pool, where no batch is ever started by the pool and the
//! drain must run each one itself.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar5;

fuzz_target!(|data: &[u8]| {
    let _ = rar5::filter_offload_agrees(data);
});
