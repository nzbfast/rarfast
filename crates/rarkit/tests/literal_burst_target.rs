//! THE NON-VACUOUSNESS PROOF FOR THE LITERAL BURST TARGET.
//!
//! `crates/rarkit/fuzz/fuzz_targets/rar3_lz_literal_burst.rs` exists to
//! reach SPEC-H1's TABLE BOUNDARIES: the point where a block of literals
//! ends, the stored code lengths are carried or cleared, and the next
//! block's 404 lengths are read as deltas on them (3.3, 3.7). A target
//! that built ONE block would reach no boundary at all, and one whose
//! block count depended on the seed LENGTH would stop reaching them the
//! moment libFuzzer settled on short inputs - which is exactly what
//! `rar3_lz_window_edge` was found doing on 19 Sep 2026 and what
//! `tests/window_edge_targets.rs` was written for.
//!
//! So the properties are checked at THE SEED LENGTHS THAT OCCUR rather
//! than hoped for: every seed builds at least two table reads, a long
//! literal run, and streams that are cut into more than one member.
#![cfg(feature = "bench-internals")]

use rarkit::internals::rar3_lz;

fn seed(bytes: usize, state: u32) -> Vec<u8> {
    rarkit_testdata::scramble(u64::from(state), bytes)
}

/// The seed lengths libFuzzer really hands a target: it starts at a
/// handful of bytes and only grows what buys coverage, so five and eight
/// are the cases that matter and 4,096 is the comfortable one.
const LENGTHS: [usize; 7] = [5, 6, 8, 16, 25, 64, 4096];

#[test]
fn every_seed_builds_at_least_two_table_reads_and_a_long_burst() {
    let mut multi_member = 0usize;
    let mut widest = 0u64;
    for bytes in LENGTHS {
        for state in 1..=16u32 {
            let data = seed(bytes, state);
            let (blocks, literals, members) = rar3_lz::literal_burst_shape(&data)
                .unwrap_or_else(|| panic!("{bytes} bytes, state {state}: no stream at all"));
            assert!(
                blocks >= 2,
                "{bytes} bytes, state {state}: {blocks} table read(s), which reaches no boundary"
            );
            assert!(
                literals >= 1024,
                "{bytes} bytes, state {state}: {literals} literals is not a burst"
            );
            assert!(members >= 1, "{bytes} bytes, state {state}: no member");
            multi_member += usize::from(members > 1);
            widest = widest.max(literals);
        }
    }
    // The member cutting arms of SPEC-H1 3.7 are reached by the seeds as
    // well, not only in principle.
    assert!(
        multi_member >= 16,
        "only {multi_member} of {} seeds cut the stream into more than one member",
        LENGTHS.len() * 16
    );
    assert!(
        widest >= 1 << 16,
        "the widest burst was only {widest} bytes"
    );
}

/// The target's own assertion, over the same seeds: every stream it
/// builds decodes to exactly the literals it wrote.
#[test]
fn the_literal_burst_target_round_trips() {
    for bytes in LENGTHS {
        for state in 1..=16u32 {
            rar3_lz::fuzz_literal_burst(&seed(bytes, state));
        }
    }
    // The shapes a fuzzer reaches by mutation rather than by noise: all
    // zeros, all ones, and the shortest input that builds anything.
    for data in [vec![0u8; 5], vec![0xFF; 5], vec![0u8; 64], vec![0xFF; 4096]] {
        rar3_lz::fuzz_literal_burst(&data);
    }
    for short in 0..5usize {
        rar3_lz::fuzz_literal_burst(&vec![0x5A; short]);
    }
}
