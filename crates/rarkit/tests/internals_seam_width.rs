//! THE CANARY FOR THE INTERNALS SEAM'S TAPE WIDTH.
//!
//! Spec F's read path resolves a member's tape width through
//! `read::extract`'s `Decoders` helper, which calls
//! `Rar5Lz::set_tape_width` once per member. The `internals_h2` seam
//! (`internals::rar5::extract`, `extract_counting`, `decode_member*`)
//! builds a decoder DIRECTLY and calls no such thing, because it is
//! scaffolding for benches, fuzz targets and differential tests rather
//! than a read path.
//!
//! On 20 Sep 2026 that difference cost the whole H2 group its threads.
//! API 8.4's dial took the tape width off `MemoryPolicy::max_workers`,
//! and `Rar5Lz::new` was left constructing the field as `1` on a comment
//! claiming `set_tape_width` replaced it "before the first member reaches
//! it on any read path". It does, on spec F's path. It does not on this
//! one, so every H2 bench leg and every H2 test decoded at tape width ONE:
//! right in its bytes, serial in its threads, and silent, because nothing
//! asserted a lane count outside the read path. `rar5_serial_vs_parallel`
//! is rarkit's parallel arm against its own serial arm in ONE binary, so
//! it reads the defect directly, and it fell from 2.151x to 0.806x.
//!
//! **WHAT THE DEFECT ACTUALLY DID, corrected.** A first account of this
//! said a width of one never entered the tape path. That is wrong, and
//! the H2 work caught it. `wants_tape` asks `tape::workers(unpacked,
//! max_workers) > 0`, and `tape::workers` answers `min(host, policy_max)`,
//! which at a width of one is ONE and not zero: the member takes the tape
//! path. What it does not take is the OVERLAP, because the spreading
//! branch is `if self.overlap && lanes > 1`. So the decode ran the tape
//! machinery down a single lane with a wave one block deep and spawned no
//! lane thread at all. That is why work inside `decode_block_tape` could
//! still move the timing while the concurrency was gone.
//!
//! The fix is that `Rar5Lz::new` now defaults the width to the ENGINE'S
//! OWN (`read::pool_width`, which is what 8.4.3 resolves `workers: None`
//! to), rather than to a floor of one. A seam that forgets to set a width
//! therefore gets the documented default instead of no threads at all.
//!
//! **WHAT THIS COUNTS, precisely.** `probe::peak_lanes` is a high-water
//! mark of `LaneGuard::enter`, which lives INSIDE `scope.spawn`, so it
//! counts lane THREADS ALIVE and nothing else. It reads zero both when
//! the tape path is skipped and when it is entered down one lane, so it
//! does not distinguish those two and must not be read as if it did. What
//! it does say, exactly, is whether the decode was SPREAD, which is the
//! same condition the engine itself branches on (`lanes > 1`) and is the
//! property this defect destroyed.
//!
//! **This file is the canary.** It asserts the property rather than the
//! wall clock: a wall ratio in `make ci` would fail on a loaded laptop for
//! reasons that have nothing to do with the defect, while a LANE COUNT of
//! one is the defect itself and is deterministic. The bench ratio is
//! measured on a quiet machine,
//! which is where a timing claim belongs.

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
/// from `read_width.rs`, for the same reason it exists there.
fn body(bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 128);
    let mut seed = 0x2026_0920_u64;
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

/// The seam's parallel arm must take MORE THAN ONE tape lane, and must
/// give the same bytes as its serial arm.
///
/// ONE test in this file, because `probe::peak_lanes` is process-wide and
/// cargo runs a binary's tests on several threads at once.
///
/// The member is 24 MiB because the tape path has a size floor of 16 MiB
/// of output below which a member takes no lane at all, whatever the
/// width: a smaller fixture would pass this test with the defect present.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn the_internals_seam_decodes_on_more_than_one_lane() {
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    // THE MACHINE THIS STATES: the seam decodes at the engine's DEFAULT
    // width, whose lanes are the PHYSICAL cores less one for the apply
    // stage, so a spread (two lanes) needs three physical cores; memory is
    // the seam's own policy and a 24 MiB member. The engine is asked what
    // this machine gives (`probe::tape_host_lanes`), not the thread count:
    // "two cores or more" was the test here until 6 Oct 2026, and a hosted
    // Windows runner of two hardware threads, which gives no lane at all,
    // read "0 tape lane(s) on a 2 core box".
    let host = probe::tape_host_lanes(false);

    let bytes = archive(&body(24 << 20));

    probe::reset_peak_lanes();
    let parallel = rarkit::internals::rar5::extract(&bytes, true).expect("parallel extract");
    let lanes = probe::peak_lanes();

    let serial = rarkit::internals::rar5::extract(&bytes, false).expect("serial extract");

    assert_eq!(
        parallel, serial,
        "the two arms must agree byte for byte (promise 2.6)"
    );
    if host < 2 {
        // Not a silent pass: the bytes above are held on every machine,
        // and here the member must have decoded on the calling thread
        // alone, which is what no lane alive means.
        assert_eq!(
            lanes, 0,
            "this machine gives the default width {host} lane(s), under the two a \
             spread needs, and yet {lanes} lane threads were alive"
        );
        eprintln!(
            "the spread is NOT READ: this machine ({cores} hardware threads) gives the \
             default width {host} lane(s) and a spread needs two (three physical cores); \
             the member decoded on the calling thread alone and its bytes are the serial arm's"
        );
        return;
    }
    assert!(
        lanes > 1,
        "the internals seam decoded on {lanes} tape lane(s) on a {cores} core box. \
         This counts lane THREADS ALIVE, so zero and one both mean the decode was \
         never SPREAD: the seam is building a decoder whose width nobody set and \
         whose default is not the engine's. See this file's header, and \
         `Rar5Lz::new`'s `max_workers`. With the 20 Sep 2026 defect reinstated this \
         reads ZERO, because a width of one takes the tape path down a single lane \
         and the spreading branch (`overlap && lanes > 1`) never runs."
    );
}
