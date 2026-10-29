//! THE CANARY FOR THE WIDTH ARGUMENT OF `internals::rar5::extract_scheduled`.
//!
//! `internals_seam_width.rs` beside this file guards the seam's DEFAULT:
//! that a decoder built by the seam and given no width at all still
//! spreads, because `Rar5Lz::new` defaults to the engine's own pool width
//! rather than to a floor of one. This file guards the other half, the
//! seam's explicit ARGUMENT, and they are separate defects with separate
//! histories.
//!
//! On 21 Sep 2026 that argument was INERT. `extract_scheduled` put its
//! `max_workers` into a `MemoryPolicy` and handed that to the decoder, and
//! `Rar5Lz::new` has not read a worker count out of a memory policy since
//! an earlier revision - a memory budget is not a thread count (API 8.4.2). So the
//! `rar5_text_64m_m3_w4` and `rar5_code_32m_m3_w4` gate rows in
//! the gate bench, whose comment calls them "what a four core host
//! gets from rarkit", ran at the pool's width like every other leg: on a
//! 32 core box, a 32 wide run wearing a four wide name. A later revision made
//! both seams call `set_tape_width`; this file is what stops the argument
//! going inert a second time.
//!
//! **WHY THIS FILE AND NOT THE ONE IN `rar5_lz/tests.rs`.**
//! `the_named_width_is_the_width_that_runs` already crosses two widths,
//! but it goes through `decode_member_probe_scheduled`. That function
//! builds its own decoder, and so do `extract_scheduled`,
//! `extract_counting_scheduled` and `decode_member_scheduled`: four
//! entry points, four chances to drop the width, and only one of the four
//! is the one the GATE ROWS come through. This asserts it where the
//! benches enter.
//!
//! **WHAT `probe::peak_lanes` COUNTS.** A high-water mark of
//! `LaneGuard::enter`, which lives inside `scope.spawn`, so it counts lane
//! THREADS ALIVE. It reads zero both when the tape path is skipped and
//! when it is entered down a single lane, because the spreading branch is
//! `overlap && lanes > 1`. So it does not distinguish those two and is not
//! read here as if it did: what it says exactly is whether the decode was
//! SPREAD, which is the property a dead width argument destroys.
//!
//! **THE TWO READINGS ARE TAKEN THE TWO ROBUST WAYS ROUND**, because that
//! mark is process wide and one run of it is not deterministic. The
//! CEILING at a narrow width is asserted on EVERY INDIVIDUAL RUN, since a
//! run that exceeded it is a real breach whatever the others did. The
//! FLOOR at a wide width is asserted on the MAXIMUM over the runs, since
//! one unlucky run whose lanes never overlapped in time is not a breach.

#![cfg(all(
    feature = "parallel",
    feature = "test-support",
    feature = "bench-internals"
))]

use rarkit::{probe, MemberSpec, Payload, WriteMethod, WriteOptions, Writer};

/// Material an `-m3` archive can hold: about half of it compresses and
/// half does not, so the block chain keeps growing and there are blocks
/// enough to spread over lanes. A single repeated byte gives a chain of
/// one block, which takes no lane whatever the width. Copied in shape
/// from `internals_seam_width.rs`, for the reason it exists there.
fn body(bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 128);
    let mut seed = 0x2026_0921_u64;
    while out.len() < bytes {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.extend_from_slice(format!("{:016x} ", seed >> 24).as_bytes());
        out.extend_from_slice(b"the quick brown fox jumps over the lazy dog ");
        for _ in 0..8 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            out.extend_from_slice(&seed.to_le_bytes());
        }
    }
    out.truncate(bytes);
    out
}

fn archive(body: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"big.dat",
            payload: Payload::Bytes(body),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

/// Two widths through `extract_scheduled` must give two different lane
/// counts and ONE set of bytes.
///
/// ONE test in this file, because `probe::peak_lanes` is process wide and
/// cargo runs a binary's tests on several threads at once. Cargo gives
/// each integration test file its own binary, so this counter is not the
/// one `internals_seam_width.rs` is reading.
///
/// The member is 24 MiB because the tape path has a size floor of 16 MiB
/// of output below which a member takes no lane at all, whatever the
/// width: a smaller fixture would pass this with the argument dead.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn the_width_argument_of_extract_scheduled_reaches_the_tape() {
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    // THE MACHINE THIS STATES: widths of one and of eight BY NAME, and a
    // named width meets the machine's lanes as a stated one does, the
    // hardware threads less one for the apply stage; so the spread at
    // eight needs three hardware threads. Memory is the seam's own policy
    // and a 24 MiB member. The engine is asked what this machine gives
    // (`probe::tape_host_lanes`): "two cores or more" was the test here
    // until 6 Oct 2026, and a hosted Windows runner of two hardware
    // threads gives one lane, on which a width of eight is a width of one.
    let host = probe::tape_host_lanes(true);

    let bytes = archive(&body(24 << 20));
    let mut narrow_bytes: Option<Vec<(Vec<u8>, Vec<u8>)>> = None;
    let mut wide_seen = Vec::new();

    for run in 0..3 {
        for width in [1usize, 8usize] {
            probe::reset_peak_lanes();
            let got = rarkit::internals::rar5::extract_scheduled(&bytes, width, None, true)
                .unwrap_or_else(|e| panic!("run {run} at width {width}: {e}"));
            let lanes = probe::peak_lanes();

            if width == 1 {
                // Asserted on EVERY run: a breach of the ceiling is real
                // whatever the other runs read.
                assert!(
                    lanes <= 1,
                    "run {run}: a width of one spread over {lanes} lanes. The width \
                     argument of `extract_scheduled` is not reaching `set_tape_width`, \
                     so every `_w<n>` bench leg is running at the pool's width under a \
                     name that promises {width}. See this file's header."
                );
            } else {
                wide_seen.push(lanes);
            }

            // Scheduling may not change a byte (SPEC-H2 section 3.8,
            // consequence 2), so the two widths and the three runs are
            // all one answer.
            match &narrow_bytes {
                None => narrow_bytes = Some(got),
                Some(want) => assert!(
                    *want == got,
                    "run {run} at width {width}: the bytes moved with the schedule"
                ),
            }
        }
    }

    let spread = wide_seen.iter().copied().max().expect("three runs");
    if host < 2 {
        // Not a silent pass: the ceiling at a width of one and the bytes
        // at both widths were held above on every run; and here a width
        // of eight must have decoded on the calling thread alone.
        assert_eq!(
            spread, 0,
            "this machine gives a stated width {host} lane(s), under the two a spread \
             needs, and yet a width of eight had {wide_seen:?} lane threads alive"
        );
        eprintln!(
            "the spread at a width of eight is NOT READ: this machine ({cores} hardware \
             threads) gives a stated width {host} lane(s) and a spread needs two (three \
             hardware threads); both widths decoded on the calling thread alone, to one answer"
        );
        return;
    }
    assert!(
        spread >= 2,
        "a width of eight never spread at all ({wide_seen:?}), so the ceiling asserted \
         at a width of one above holds vacuously and this canary proves nothing. Either \
         the tape path is not being entered or this box has fewer lanes than it has \
         cores ({cores})."
    );
}
