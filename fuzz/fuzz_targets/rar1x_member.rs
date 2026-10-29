//! Spec A section 7.4, held to ONE member: arbitrary bytes as the packed
//! data of a single RAR 1.x member, with the declared size and the solid
//! flag taken from the input's first four bytes.
//!
//! The input is the shape `rar15::fuzz_decode` reads (three bytes of
//! little endian declared size, reduced into 0 to 1 MiB, then a flags
//! byte, then the packed bytes), with the flags byte cut down to its
//! lowest bit: the member count that byte also carries is forced to one,
//! so every packed byte belongs to the same member and none is spent on
//! a second. What is left of the byte says whether the member is decoded
//! as a solid continuation of a decoder that has seen nothing, which is
//! the one solid shape a single member can have.
//!
//! That is what lets a GENUINE member be a seed as it stands: its
//! declared size, a zero byte and its packed bytes, cut from the RAR
//! 1.40 archives of `fixtures/legacy` (`fuzz/seeds/rar1x_member`, held to
//! those archives by `crates/rarkit/tests/rar1x_member_seeds.rs`). The
//! other tree's `rar15_decode` starts from one pinned input and splits
//! what it is given into up to four chunks.
//!
//! The verdict is section 6's: no panic, and a member never delivers
//! more than its declared size. A member that delivers FEWER is one
//! whose packed bytes ran out (4.11), which is `Ok` and for the caller's
//! member checksum to report. The largest declared size is 1 MiB against
//! a 64 KiB history, so the working memory is that history and the
//! output, whatever the input says.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar15;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let mut one = data.to_vec();
    one[3] &= 1;
    rar15::fuzz_decode(&one);
});
