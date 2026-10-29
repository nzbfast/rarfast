//! SPEC-H2 section 6.3: bytes in, walk the block chain with `block_in_hand`
//! only. Cheap, and it is the target that covers section 3.2 densely.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar5;

fuzz_target!(|data: &[u8]| {
    // No symbol is decoded and nothing is allocated by the walk; what is
    // under test is that every header shape either locates a block or is
    // refused, and that the chain always advances.
    let _ = rar5::walk_block_chain(data);
});
