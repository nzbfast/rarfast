//! SPEC-H2 section 6.3: bytes in, split into members, one solid stream.
//!
//! The window, the four repeated distances, the last match length and the
//! table set all carry across a member boundary; the filter base does NOT
//! and that is what this target walks over.
//!
//! **The chain is decoded THREE ways and the three must agree**, on the
//! bytes and on where they stopped. Section 3.8's property is what makes
//! the second and third lawful, and this is where it is held to:
//!
//! 1. the serial path, which is the reference;
//! 2. the tape path, which splits each member's decode from its apply;
//! 3. the tape path with the CHAIN'S DECODE-AHEAD running, where the
//!    members in front of the one being applied are Huffman decoded on
//!    other threads before the apply stage reaches them.
//!
//! The third arm is what puts a whole chain of DEFERRED failures ahead of
//! the member that genuinely stops, across a member boundary rather than
//! inside one, which is section 3.8's consequence 1 at the boundary the
//! lever added.
//!
//! ## Why this target names its own lane width
//!
//! The third arm is the only place in the roster that opens the chain's
//! decode-ahead stage, and the stage opens one lane per thread the
//! process's pool reports. On a 32-core box that is about thirty-one
//! threads created and joined for EVERY execution, for a chain that holds
//! at most six members and about sixty-four kilobytes in total, so the
//! width is spent on nothing the property needs.
//!
//! It is not free. Under the address sanitizer, which is how a campaign
//! builds, each thread the process has ever created costs about 116 bytes
//! that are never given back, and at eight hundred executions a second
//! this target's resident set climbed 3.6 KB an execution and crossed
//! libFuzzer's 2048 MB limit partway through a 600 s sweep on 22 Sep
//! 2026, on two trees at once, taking the target's whole result
//! with it. The engine is not what grows: the same executions with the
//! same thread churn and no sanitizer hold flat at 33 MB, and an arm
//! that opens no lane holds flat under the sanitizer too.
//!
//! So the width is named here, at two, the same number
//! `fuzz/fuzz_targets/rar5_member.rs` names for its scheduled arms. Two
//! lanes still interleave, which is the whole of what the third arm
//! tests; what is given up is width this input size could never use.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar5;

const WINDOW: u64 = 1 << 20;

/// The lanes the decode-ahead stage opens, and through it the workers the
/// tape path may spread over. See the width note at the head of the file.
const LANES: usize = 2;

/// Hold the process's pool to [`LANES`] threads, once, before the first
/// decode.
///
/// The stage reads its width from `rayon::current_num_threads()`, so
/// building the global pool explicitly is what names it; an environment
/// variable would not survive a campaign, which sets none. A second call
/// is refused by rayon rather than being an error here: the pool is
/// already the width this asked for, or a host built one first, and
/// either way the decode below is correct and only wider.
fn hold_the_pool() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(LANES)
            .build_global();
    });
}

fuzz_target!(|data: &[u8]| {
    hold_the_pool();
    let Some((&count, rest)) = data.split_first() else {
        return;
    };
    let members = usize::from(count % 6) + 1;
    if rest.len() < members {
        return;
    }
    let each = rest.len() / members;
    let mut chain: Vec<(&[u8], u64)> = Vec::with_capacity(members);
    for index in 0..members {
        let start = index * each;
        let end = if index + 1 == members {
            rest.len()
        } else {
            start + each
        };
        chain.push((&rest[start..end], (each as u64 + 1) * 4));
    }
    let serial = rar5::decode_solid_chain_probe(&chain, WINDOW, 0, false, false);
    for (parallel, ahead) in [(true, false), (true, true)] {
        let got = rar5::decode_solid_chain_probe(&chain, WINDOW, 0, parallel, ahead);
        assert_eq!(
            serial.1, got.1,
            "parallel {parallel}, decode-ahead {ahead}: the chain's outcome moved"
        );
        assert!(
            serial.0 == got.0,
            "parallel {parallel}, decode-ahead {ahead}: {} members against {}",
            got.0.len(),
            serial.0.len()
        );
    }
});
