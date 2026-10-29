//! Members below the offload floor have a member team of their
//! own, at most eight workers, and never above the decode width.
//!
//! In a test binary of its own, with ONE test in it, because the counter it
//! reads (`rarkit::probe::peak_members`) is process-wide.

#![cfg(all(feature = "parallel", feature = "test-support"))]

use std::path::PathBuf;
use std::sync::Arc;

use rarkit::{
    extract_parallel, Disposition, MemberInfo, MemberOutcome, ParallelSink, RangeSource,
    ReadOptions, Result,
};

struct Sink;

impl ParallelSink for Sink {
    type Out = Vec<u8>;
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(&self, _: &MemberInfo<'_>, _: Option<Vec<u8>>, _: &MemberOutcome) -> Result<()> {
        Ok(())
    }
}

#[test]
fn the_member_team_caps_the_members_below_the_floor_decoding_at_once() {
    // Every fixture here holds members above the 16 KiB floor, which the
    // team does not hold and the counter does count; a floor above the
    // fixture's largest member (90,000 bytes) puts every member below it.
    rarkit::probe::set_offload_floor(Some(128 << 10));
    let bytes = std::fs::read(PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/legacy/archives/r550_m3.rar"
    )))
    .expect("the fixture");
    // On x86-64 the DEFAULT team is at most half the box's hardware
    // threads (the finer x86 form); a team set by name is not.
    let room = if cfg!(target_arch = "x86_64") {
        std::thread::available_parallelism().map_or(1, |n| (n.get() / 2).max(1))
    } else {
        usize::MAX
    };
    let default = |workers: usize| workers.min(8).min(room);
    // (team, workers, the most that may decode at once)
    for (team, workers, most) in [
        (Some(2), 8usize, 2usize),
        (Some(1), 8, 1),
        (Some(8), 3, 3),
        (None, 16, default(16)),
        (None, 8, default(8)),
        (None, 3, default(3)),
        (None, 32, default(32)),
        (None, 1, 1),
        (Some(8), 8, 8),
        (Some(0), 3, 3),
    ] {
        for batch in [(1usize, 256u64 << 10), (2, 256 << 10)] {
            rarkit::probe::set_small_team(team);
            rarkit::probe::set_small_batch(Some(batch));
            rarkit::probe::reset_peak_members();
            extract_parallel(
                vec![Arc::new(bytes.clone()) as Arc<dyn RangeSource>],
                &ReadOptions::default().with_workers(Some(workers)),
                &Sink,
                workers,
            )
            .expect("parallel");
            let peak = rarkit::probe::peak_members();
            assert!(
                peak >= 1,
                "team {team:?} x{workers}: nothing was dispatched"
            );
            assert!(
                peak <= most,
                "team {team:?} x{workers} batch {batch:?}: {peak} members below the \
                 floor decoded at once, above {most}"
            );
        }
    }
    rarkit::probe::set_small_team(None);
    rarkit::probe::set_small_batch(None);
    rarkit::probe::set_offload_floor(None);
}
