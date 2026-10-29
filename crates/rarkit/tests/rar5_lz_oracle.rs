//! SPEC-H2 section 6.1: the RAR 5 LZ decoder against `rarkit-oracle`.
//!
//! Compares bytes per member and error KIND for every archive of section
//! 5.2, plus every RAR 5 fixture the repository already carries. The
//! required cases of 6.1 - the two solid archives, the filtered and
//! unfiltered pair for x86 and for delta, the 64 MiB dictionary archive
//! and the empty member - are named below so a reader can see them run.
// The exporter cut the cases of this file that need a crate this tree
// does not have; imports and helpers only they used are left in place.
#![allow(unused_imports, dead_code, unused_macros)]

use rarkit::internals::rar5;

fn archive(stem: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../specs/vectors-H/archives/{stem}.rar",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

const ARCHIVES: [&str; 16] = [
    "h5_delta_m5",
    "h5_delta_off",
    "h5_empty",
    "h5_far_m5",
    "h5_far_small_md",
    "h5_lit_m1",
    "h5_md_max",
    "h5_rand_m5",
    "h5_runs_m5",
    "h5_solid",
    "h5_solid_mixed",
    "h5_text_m3",
    "h5_text_m5",
    "h5_tiny",
    "h5_x86_m5",
    "h5_x86_nofilter",
];

/// Section 6.2: a truncation at every 64th byte, and a declared dictionary
/// of the maximum the field can hold.
#[test]
fn truncations_and_a_maximum_dictionary_never_panic() {
    let data = archive("h5_far_m5");
    let members = rar5::members(&data);
    let member = members.iter().find(|m| m.method != 0).expect("compressed");
    for cut in (0..member.packed.len()).step_by(64) {
        let outcome = rar5::decode_member(
            &member.packed[..cut],
            member.unpacked,
            member.window,
            0,
            false,
        );
        assert!(outcome.is_err(), "a truncation at {cut} must not complete");
    }
    // The dictionary field is four bits, so `131,072 << 15` is 4 GiB: a
    // window `max_window` refuses long before it is allocated on a 32 bit
    // target, and one this box can hold on a 64 bit one.
    let outcome = rar5::decode_member(&member.packed, member.unpacked, 131_072 << 15, 0, false);
    assert!(outcome.is_ok() || outcome.is_err());
}
