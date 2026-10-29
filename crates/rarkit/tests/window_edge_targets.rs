//! THE NON-VACUOUSNESS PROOF FOR THE TWO WINDOW EDGE FUZZ TARGETS.
//!
//! A fuzz target that never LAPS its ring is
//! structurally incapable of seeing the window edge class, because below
//! one lap every slot ahead of the write point holds a byte the stream
//! never produced and a copy that overruns is writing on dead memory.
//! `rar5_member` and `rar5_solid_chain` fixed UNPACKED at 1 << 18 against
//! a WINDOW of 1 << 20 and so never lapped, which is why neither of them
//! found the defect and why `rar5_window_edge` had to be written.
//!
//! A window edge target is therefore only worth its ten minutes if its
//! members really do lap. That is a property of the target's input
//! construction, not of the fuzzer, so it is checked here rather than
//! hoped for: exactly the same reasoning as `window_guard.rs`'s rule that
//! a guard seen only to pass is not evidence.
#![cfg(feature = "bench-internals")]

use rarkit::internals::{rar15, rar20, rar3_lz};

fn seed(bytes: usize, state: u32) -> Vec<u8> {
    rarkit_testdata::scramble(u64::from(state), bytes)
}

/// Spec A's target laps its history ring, from seeds the size libFuzzer
/// really hands a target.
///
/// This is the test that justifies TILING the seed. Used as it stands, a
/// 4 KiB seed is about 3,600 RAR 1.5 literals and stops far short of one
/// lap; tiled it goes round, and it is only past the first lap that a
/// copy can name a place on the far side of the ring's end.
///
/// THE SEED LENGTHS ARE THE ONES THAT OCCUR, not comfortable ones. A ten
/// minute run of this target never grew its inputs past EIGHT BYTES - the
/// `lim:` column stayed at 8 for all 8,613 execs, because one exec
/// decodes three laps under the guard - so a test that only tried 4 KiB
/// seeds would be checking a case the fuzzer never reaches. The tiling is
/// what makes an 8 byte seed lap at all, and this is what holds it to
/// that. The sibling `the_rar3_window_edge_target_laps_its_dictionary`
/// exists because the RAR 3 target FAILED exactly this check.
#[test]
fn the_rar15_window_edge_target_laps_its_ring() {
    for bytes in [1usize, 2, 8, 9, 16, 25, 64, 512, 4096] {
        let mut lapped = 0usize;
        let mut best = 0usize;
        for state in 1..=8u32 {
            let (produced, window) = rar15::window_edge_reach(&seed(bytes, state));
            best = best.max(produced);
            if produced > window {
                lapped += 1;
            }
        }
        assert!(
            lapped > 0,
            "no seed of 8 at {bytes} bytes lapped the ring: the \
             furthest got {best} bytes, so at this seed length the target \
             cannot see the window edge class at all"
        );
        eprintln!("rar15_window_edge: {bytes} byte seeds, {lapped} of 8 lapped, furthest {best}");
    }
}

/// Spec H1's target laps its dictionary three times AT THE SEED LENGTHS
/// LIBFUZZER REALLY REACHES, which is the thing the first version of it
/// got wrong.
///
/// An exec that encodes and decodes a fifth of a megabyte costs about
/// 24 ms, so a ten minute run never grew its inputs past 25 bytes: the
/// `lim:` column of `rar3_lz_window_edge`'s log went 8, then 25, and
/// stopped. The first construction appended one match pair per three
/// seed bytes on top of one lap of base, so at 25 bytes it lapped 1.06
/// times and only about 660 bytes of the member sat where
/// `Window::copy`'s `SpillWatch` can bite at all. This is the test that
/// would have caught it, and it checks the seed lengths that actually
/// occur rather than a comfortable one.
#[test]
fn the_rar3_window_edge_target_laps_its_dictionary() {
    let window = rar3_lz::EDGE_WINDOW;
    for bytes in [8usize, 9, 16, 25, 64, 512, 4096] {
        for state in 1..=4u32 {
            let input = rar3_lz::window_edge_input(&seed(bytes, state));
            assert!(
                input.len() >= 3 * window,
                "a seed of {bytes} bytes built a member of {} bytes, which is \
                 {:.2} laps of the {window} byte dictionary: below three laps \
                 this target is most of the way back to being blind to the \
                 class it exists for",
                input.len(),
                input.len() as f64 / window as f64
            );
        }
    }
}

/// And the round trip itself, at the shortest seed the target accepts.
///
/// Three laps of encode and decode is the expensive half of one fuzz
/// exec, so this runs it once rather than over a sweep: what the sweep
/// above is for is the LENGTH, and what this is for is that the bytes
/// come back.
#[test]
fn the_rar3_window_edge_target_round_trips() {
    let window = rar3_lz::EDGE_WINDOW;
    let input = rar3_lz::window_edge_input(&seed(8, 0x9E37_79B9));
    let packed = rar20::rar29_encode(&input, 1, window as u32);
    let members = [rar3_lz::MemberIn {
        packed: 0..packed.len(),
        unpacked: input.len() as u64,
    }];
    let (out, _) = rar3_lz::decode_stream(&packed, &members, window as u32, true)
        .expect("spec H1's decoder reads what this encoder wrote");
    assert_eq!(out[0].data, input, "the round trip changed the bytes");
}
