//! The tape pipeline's instruments: the lane grants, the planned chunks,
//! the walk stalls and the split of the pipeline's time.

#[allow(unused_imports)]
use super::*;

// ---------------------------------------------------------------------------
// The bimodality instrument
// ---------------------------------------------------------------------------

/// The widest grant these histograms have a bucket for. A grant above it
/// is counted in the last bucket, which no shape here reaches: the tape
/// path's own ceiling is `MT_MAX_WORKERS`, 8.
pub(super) const GRANT_BUCKETS: usize = 33;

/// How many tape chunks ran at each lane count, and how many members
/// were decoding when each grant was taken.
///
/// **What these exist to separate**, and it is one question asked two
/// ways. `read::lanes::LaneBudget::take` gives a member the FAIR SHARE of
/// the read width, `ceiling / live`, where `live` is the members decoding
/// at that instant - the walk's own member included, since
/// `read::extract::decode` takes a slot whichever thread it is on. A
/// large member sharing an archive with small ones therefore re-takes its
/// width once per chunk against a `live` that the small members move, and
/// the two of these say whether a slow decode is a decode that was handed
/// narrow grants and, if so, what it was sharing with.
///
/// PROCESS-wide, for the same reason [`peak_lanes`] is: the grants are
/// taken on whichever thread holds the member.
pub(super) static GRANT_LANES: [std::sync::atomic::AtomicU64; GRANT_BUCKETS] =
    [const { std::sync::atomic::AtomicU64::new(0) }; GRANT_BUCKETS];

pub(super) static GRANT_LIVE: [std::sync::atomic::AtomicU64; GRANT_BUCKETS] =
    [const { std::sync::atomic::AtomicU64::new(0) }; GRANT_BUCKETS];

/// Count one lane grant: `lanes` granted with `live` members decoding.
#[cfg(feature = "parallel")]
pub(crate) fn note_lane_grant(lanes: usize, live: usize) {
    use std::sync::atomic::Ordering;
    GRANT_LANES[lanes.min(GRANT_BUCKETS - 1)].fetch_add(1, Ordering::Relaxed);
    GRANT_LIVE[live.min(GRANT_BUCKETS - 1)].fetch_add(1, Ordering::Relaxed);
}

/// Grants by the lanes they granted, bucket `n` being `n` lanes.
pub fn lane_grants() -> Vec<u64> {
    GRANT_LANES
        .iter()
        .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
        .collect()
}

/// Grants by the members decoding when they were taken.
pub fn lane_grant_live() -> Vec<u64> {
    GRANT_LIVE
        .iter()
        .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
        .collect()
}

/// Forget both grant histograms.
pub fn reset_lane_grants() {
    for c in GRANT_LANES.iter().chain(GRANT_LIVE.iter()) {
        c.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Chunks the RAR 5 tape decode planned, and the blocks those plans held.
///
/// The second question the instrument asks: whether a narrow grant makes
/// the decode do the SAME work more times. `Rar5Lz::member_planned` plans
/// a chunk and then consumes a wave of it, so a wave narrower than the
/// chunk leaves blocks to be planned again by the next call. Chunks
/// against blocks says whether that is happening and by how much, which
/// a wall cannot.
pub(super) static PLANNED_CHUNKS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(super) static PLANNED_BLOCKS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Count one planned chunk holding `blocks` blocks.
#[cfg(all(feature = "parallel", feature = "h2-probes"))]
pub(crate) fn note_planned(blocks: usize) {
    use std::sync::atomic::Ordering;
    PLANNED_CHUNKS.fetch_add(1, Ordering::Relaxed);
    PLANNED_BLOCKS.fetch_add(blocks as u64, Ordering::Relaxed);
}

/// Chunks planned, and the blocks in those plans, since [`reset_planned`].
pub fn planned() -> (u64, u64) {
    use std::sync::atomic::Ordering;
    (
        PLANNED_CHUNKS.load(Ordering::Relaxed),
        PLANNED_BLOCKS.load(Ordering::Relaxed),
    )
}

/// Forget the plan counters.
pub fn reset_planned() {
    use std::sync::atomic::Ordering;
    PLANNED_CHUNKS.store(0, Ordering::Relaxed);
    PLANNED_BLOCKS.store(0, Ordering::Relaxed);
}

/// Nanoseconds the walking thread spent waiting for a worker's answer,
/// and how many times it waited.
///
/// The third question: head-of-line blocking. `read::concurrent`'s flight
/// queue retires from the FRONT because `close` is archive order, so a
/// walk that has run out of free workers waits for the OLDEST member in
/// flight however long that member is and however many of the others
/// have already answered. On an archive whose first member is much the
/// largest that is a stall with a shape, and this measures it rather than
/// inferring it from a wall.
pub(super) static WALK_STALL_NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(super) static WALK_STALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Count one wait of `nanos` for a worker's answer.
#[cfg(feature = "parallel")]
pub(crate) fn note_walk_stall(nanos: u64) {
    use std::sync::atomic::Ordering;
    WALK_STALL_NS.fetch_add(nanos, Ordering::Relaxed);
    WALK_STALLS.fetch_add(1, Ordering::Relaxed);
}

/// Waits for a worker's answer, and their total nanoseconds.
pub fn walk_stalls() -> (u64, u64) {
    use std::sync::atomic::Ordering;
    (
        WALK_STALLS.load(Ordering::Relaxed),
        WALK_STALL_NS.load(Ordering::Relaxed),
    )
}

/// Forget the stall counters.
pub fn reset_walk_stalls() {
    use std::sync::atomic::Ordering;
    WALK_STALLS.store(0, Ordering::Relaxed);
    WALK_STALL_NS.store(0, Ordering::Relaxed);
}

/// Where the RAR 5 tape pipeline's time goes, in nanoseconds, split
/// between the one apply stage and the decode lanes that feed it.
///
/// The fourth question, and the one the incompressible member asks.
/// The parallel arm was measured APPLY bound at a real
/// width, but that came from a SAMPLE of one thread, which gives a
/// share of that thread's samples and not a share of the member's wall. A
/// share is not a wall. These counters are the wall form of the same
/// question: how long the apply stage sat in `recv` with no tape to
/// apply, how long a lane sat in `send` with nowhere to put one, and how
/// long the lanes spent decoding. A pipeline whose apply stage never
/// blocks and whose lanes block constantly is apply bound; the reverse is
/// decode bound; and the figures say which without a profiler and on
/// every box.
///
/// PROCESS-wide and `Relaxed`, for [`peak_lanes`]'s reason: the lanes are
/// other threads by construction. A reader therefore owns the process for
/// the length of its measurement. Two clock reads per block per stage,
/// against a block that is hundreds of microseconds of work.
pub(super) static APPLY_WAIT_NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(super) static APPLY_WAITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(super) static LANE_WAIT_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(super) static LANE_WAITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(super) static LANE_DECODE_NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(super) static APPLY_BUSY_NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Count one wait of `nanos` by the apply stage for the next tape.
#[cfg(all(feature = "parallel", feature = "h2-probes"))]
pub(crate) fn note_apply_wait(nanos: u64) {
    use std::sync::atomic::Ordering;
    APPLY_WAIT_NS.fetch_add(nanos, Ordering::Relaxed);
    APPLY_WAITS.fetch_add(1, Ordering::Relaxed);
}

/// Count `nanos` of the apply stage actually applying a tape.
#[cfg(all(feature = "parallel", feature = "h2-probes"))]
pub(crate) fn note_apply_busy(nanos: u64) {
    use std::sync::atomic::Ordering;
    APPLY_BUSY_NS.fetch_add(nanos, Ordering::Relaxed);
}

/// Count one wait of `nanos` by a decode lane handing its tape over.
#[cfg(all(feature = "parallel", feature = "h2-probes"))]
pub(crate) fn note_lane_wait(nanos: u64) {
    use std::sync::atomic::Ordering;
    LANE_WAIT_NS.fetch_add(nanos, Ordering::Relaxed);
    LANE_WAITS.fetch_add(1, Ordering::Relaxed);
}

/// Count `nanos` of a decode lane decoding one block.
#[cfg(all(feature = "parallel", feature = "h2-probes"))]
pub(crate) fn note_lane_decode(nanos: u64) {
    use std::sync::atomic::Ordering;
    LANE_DECODE_NS.fetch_add(nanos, Ordering::Relaxed);
}

/// The pipeline's split: apply waits, apply wait ns, apply busy ns, lane
/// waits, lane wait ns, lane decode ns.
pub fn pipeline_split() -> (u64, u64, u64, u64, u64, u64) {
    use std::sync::atomic::Ordering;
    (
        APPLY_WAITS.load(Ordering::Relaxed),
        APPLY_WAIT_NS.load(Ordering::Relaxed),
        APPLY_BUSY_NS.load(Ordering::Relaxed),
        LANE_WAITS.load(Ordering::Relaxed),
        LANE_WAIT_NS.load(Ordering::Relaxed),
        LANE_DECODE_NS.load(Ordering::Relaxed),
    )
}

/// Forget the pipeline split counters.
pub fn reset_pipeline_split() {
    use std::sync::atomic::Ordering;
    for counter in [
        &APPLY_WAITS,
        &APPLY_WAIT_NS,
        &APPLY_BUSY_NS,
        &LANE_WAITS,
        &LANE_WAIT_NS,
        &LANE_DECODE_NS,
    ] {
        counter.store(0, Ordering::Relaxed);
    }
}
