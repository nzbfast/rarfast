//! Counters this repository's own tests read (feature `test-support`).
//!
//! They exist so a test can assert a NEGATIVE that no output shows: that a
//! member a sink skipped was never decoded, and that the packed bytes of a
//! chain nobody wants were never read. Spec F 3.6 and 3.7.1 require it and
//! nothing in an extraction's output can tell the two apart - a skipped
//! member and a decoded-then-discarded one deliver the same bytes to the
//! same sink, and differ only in the work done.
//!
//! Nothing here is API: without the feature the module does not exist and
//! the counters are not incremented, so a shipped build carries neither the
//! counters nor the calls.
//!
//! The RAR 5 decode path's own probes (the lane and worker guards, the
//! pipeline clocks, the pool hand-off, chunk plan and decode-ahead counts)
//! are written only under the further feature `h2-probes`, because
//! `test-support` reaches the gate binary `two_arm` and those calls sit on
//! every block of the measured arm. Their readers below stay under
//! `test-support` alone and read zero without `h2-probes`: a test or lab
//! that asserts on them turns `h2-probes` on itself.

// A knob feature alone compiles this module for its one dial's setter and
// reader; the counters below are then written by nothing, since every
// write site sits behind `test-support`.
#![cfg_attr(not(feature = "test-support"), allow(dead_code))]

use std::cell::Cell;

// The probe's parts, one module a seam.
mod counters;
#[cfg(feature = "parallel")]
pub use counters::tape_host_lanes;
#[cfg(feature = "parallel")]
#[allow(unused_imports)]
pub(crate) use counters::MemberGuard;
#[cfg(feature = "h2-probes")]
#[allow(unused_imports)]
pub(crate) use counters::WorkerGuard;
pub use counters::{
    chunk_blocks, chunk_blocks_total, chunk_groups, chunk_plans_dropped, chunks_planned,
    decoded_members, header_clones, least_chunk_blocks, peak_chunk_blocks, peak_lanes,
    peak_members, peak_workers, pool_handoffs, reset, reset_chunk_plans, reset_header_clones,
    reset_peak_lanes, reset_peak_members, reset_peak_workers, reset_pool_handoffs,
};
#[cfg(all(feature = "parallel", feature = "h2-probes"))]
#[allow(unused_imports)]
pub(crate) use counters::{note_chunk_plan, note_pool_handoff, LaneGuard};
#[allow(unused_imports)]
pub(crate) use counters::{note_decoded, note_header_clone};
mod breadth;
#[allow(unused_imports)]
pub(crate) use breadth::x86_arm;
#[cfg(feature = "parallel")]
#[allow(unused_imports)]
pub(crate) use breadth::{
    breadth_arm, narrow_after, note_batch, offload_floor, outputs_over_breadth, queue_own,
    settle_spin, small_batch, small_team, task_spin, wait_any,
};
pub use breadth::{
    peak_batch, physical_cores, reset_peak_batch, set_breadth_arm, set_narrow_after,
    set_offload_floor, set_outputs_over_breadth, set_queue_own, set_settle_spin, set_small_batch,
    set_small_team, set_task_spin, set_wait_any, set_x86_arm, BREADTH_ARM_BREADTH_FIRST,
    BREADTH_ARM_DIVIDED, BREADTH_ARM_HANDBACK, BREADTH_ARM_IN_TURN, BREADTH_ARM_LATE_NARROW,
    BREADTH_ARM_NARROW, BREADTH_ARM_SHRINKING, BREADTH_ARM_SPILL, BREADTH_ARM_WHOLE,
    NARROW_AFTER_DEFAULT, X86_ARM_ADAPTIVE, X86_ARM_SPLIT, X86_ARM_WALKING,
};
mod solid;
#[cfg(feature = "parallel")]
pub use solid::wide_floor;
#[cfg(feature = "parallel")]
#[allow(unused_imports)]
pub(crate) use solid::{
    note_seq_ahead, note_seq_ahead_held, note_solid_ahead, note_solid_pool,
    note_solid_stored_range, seq_ahead, seq_ahead_bytes, seq_ahead_hold, seq_small, solid_ahead,
    solid_queue_depth, solid_stored_in_order, solid_stored_piece, solid_stored_wide,
};
#[cfg(all(feature = "parallel", feature = "test-support"))]
pub use solid::{open_ahead, open_ahead_refusals, seq_ahead_live};
pub use solid::{
    peak_seq_ahead_bytes, peak_seq_ahead_held, peak_seq_ahead_members, reset_seq_ahead_peak,
    reset_solid_ahead_seen, reset_solid_stored_ranges, seq_ahead_taken, set_seq_ahead,
    set_seq_ahead_bytes, set_seq_ahead_hold, set_seq_ahead_hold_packed, set_seq_small,
    set_solid_ahead, set_solid_queue_depth, set_solid_stored_in_order, set_solid_stored_piece,
    set_solid_stored_wide, solid_ahead_seen, solid_pool_seen, solid_stored_ranges,
};
#[cfg(all(feature = "parallel", feature = "test-support"))]
pub(crate) use solid::{seq_ahead_hold_packed, watch_seq_ahead_gate};
mod seam;
#[cfg(feature = "k-two-lane-probe")]
pub use seam::set_two_lane_cipher;
#[cfg(all(feature = "k-two-lane-probe", feature = "parallel"))]
#[allow(unused_imports)]
pub(crate) use seam::two_lane_cipher;
#[cfg(feature = "parallel")]
#[allow(unused_imports)]
pub(crate) use seam::{
    cipher_overlap, cipher_overlap_chunk, lent_whole_slab, note_cipher_overlap, seam_coalesce,
    seam_floor, SeamGuard,
};
pub use seam::{
    cipher_overlaps, peak_seam, reset_cipher_overlaps, reset_peak_seam, seam_now,
    set_cipher_overlap, set_cipher_overlap_chunk, set_lent_whole_slab, set_seam_coalesce,
    set_seam_floor,
};
mod pipeline;
pub use pipeline::{
    lane_grant_live, lane_grants, pipeline_split, planned, reset_lane_grants, reset_pipeline_split,
    reset_planned, reset_walk_stalls, walk_stalls,
};
#[cfg(all(feature = "parallel", feature = "h2-probes"))]
#[allow(unused_imports)]
pub(crate) use pipeline::{
    note_apply_busy, note_apply_wait, note_lane_decode, note_lane_wait, note_planned,
};
#[cfg(feature = "parallel")]
#[allow(unused_imports)]
pub(crate) use pipeline::{note_lane_grant, note_walk_stall};
mod apply;
#[cfg(all(feature = "parallel", feature = "h2-apply-arms"))]
#[allow(unused_imports)]
pub(crate) use apply::{
    far_distance, far_every, far_floor, far_prefetch, far_prefetch_mode, literal_ladder,
};
pub use apply::{
    far_prefetch_modes, set_far_floor, set_far_prefetch, set_far_prefetch_mode, set_literal_ladder,
};
mod ahead;
#[cfg(feature = "parallel")]
#[allow(unused_imports)]
pub(crate) use ahead::ahead_carry_stale;
pub use ahead::{
    ahead_allocs, ahead_claims, ahead_peak_lanes, ahead_stalls, begin_ahead_claim_scope,
    end_ahead_claim_scope, reset_ahead_claims, set_ahead_carry_stale, set_ahead_growth,
    set_ahead_off, set_ahead_small,
};
#[allow(unused_imports)]
pub(crate) use ahead::{ahead_grow_after, ahead_grow_start, ahead_off, ahead_small};
#[cfg(all(feature = "parallel", feature = "h2-probes"))]
#[allow(unused_imports)]
pub(crate) use ahead::{note_ahead_alloc, note_ahead_claim, note_ahead_lanes, note_ahead_stall};
mod arms;
#[cfg(all(feature = "parallel", feature = "h2-apply-arms"))]
#[allow(unused_imports)]
pub(crate) use arms::apply_arm;
#[cfg(all(
    feature = "parallel",
    any(feature = "h2-apply-arms", feature = "h2-far-list-knob")
))]
#[allow(unused_imports)]
pub(crate) use arms::far_list;
#[cfg(any(feature = "h2-apply-arms", feature = "h2-far-list-knob"))]
pub use arms::set_far_list;
#[cfg(feature = "h2-apply-arms")]
pub use arms::{apply_arms, set_apply_arm};
mod wide;
#[cfg(feature = "test-support")]
pub use wide::{allow_spawns, spawns_refused};
pub use wide::{
    crc_shared, crossed_ahead, fragments_abreast_runs, job_spans, reset_crc_shared,
    reset_fragments_abreast_runs, reset_scratch_give_backs, reset_split_jobs_taken,
    reset_stored_cuts, reset_wide_block_joins, reset_wide_verifies, scratch_give_backs,
    set_fragments_abreast, set_fragments_abreast_joined, set_job_wide, set_job_wide_write,
    set_job_wide_written, set_solid_tape, set_split_jobs, set_split_jobs_all, set_stored_cut,
    set_stored_cut_cipher, set_stored_cut_when, split_jobs_taken, stored_cuts, wide_block_joins,
    wide_verifies,
};
#[cfg(feature = "parallel")]
#[allow(unused_imports)]
pub(crate) use wide::{
    fragments_abreast, job_wide, job_wide_write, job_wide_written, note_crossed_ahead,
    note_fragments_abreast, note_job_span, note_split_job, note_stored_cut, note_wide_block_join,
    note_wide_verify, solid_tape, split_jobs, split_jobs_all, stored_cut, stored_cut_cipher,
    stored_cut_when,
};
#[allow(unused_imports)]
pub(crate) use wide::{note_crc_shared, note_scratch_give_back};
mod b2sp;
#[cfg(feature = "parallel")]
#[allow(unused_imports)]
pub(crate) use b2sp::{
    b2sp_cut, b2sp_cut_walk, b2sp_wide, note_b2sp_cut, note_b2sp_wide, note_wide_held,
    note_wide_readers, wide_breadth, wide_cores, wide_running,
};
pub use b2sp::{
    b2sp_cuts, b2sp_wides, reset_b2sp_cuts, set_b2sp_cut, set_b2sp_cut_walk, set_b2sp_team,
    set_b2sp_wide, set_wide_breadth, set_wide_cores, set_wide_running, take_b2sp_allowance,
    take_wide_held,
};
#[allow(unused_imports)]
pub(crate) use b2sp::{b2sp_team, note_b2sp_allowance};

/// The walker count the ENCODER'S tree walk last settled on.
///
/// PROCESS-wide and a LAST rather than a peak, in the shape of
/// `checksum::blake2sp`'s allowance counter and for the same reason: what
/// a test of `WriteOptions::workers` needs to know is the figure the
/// encoder computed, `min(workers, the engine's own ceiling, the pool's
/// width)`, and not how many threads then happened to be awake inside it.
/// A ceiling is never a demand (API 8.2), so a test that counted live
/// walkers would be asserting on the rayon pool's scheduling and would
/// flake.
///
/// It exists so that `tests/encoder_width.rs` can show it is not vacuous.
/// That test asserts a NEGATIVE, that the archive's bytes never move with
/// the width, and such a test passes just as happily when the width never
/// reached the encoder at all - which is exactly what happened to
/// `thread_width.rs`'s write leg when the encoder moved off
/// `MemoryPolicy::max_workers`. Reading this counter turns "the bytes did
/// not move" into "the bytes did not move AND the width did".
static WALKERS_LAST: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Record the width one tree walk is about to run at.
pub(crate) fn note_walkers(walkers: usize) {
    WALKERS_LAST.store(walkers, std::sync::atomic::Ordering::Relaxed);
}

/// The width the last tree walk ran at, or 0 if none has run since
/// [`forget_walkers`].
///
/// Zero also means the walk was never reached: a member small enough to
/// be one parse block, or a plan with no tree, takes no walk at all.
pub fn last_walkers() -> usize {
    WALKERS_LAST.load(std::sync::atomic::Ordering::Relaxed)
}

/// Forget the last tree walk's width.
pub fn forget_walkers() {
    WALKERS_LAST.store(0, std::sync::atomic::Ordering::Relaxed);
}

/// THE APPLY WALK'S MEASURING KNOBS STILL REACH A LANE THAT ASKS FOR
/// THEM. The literal ladder, the far prefetch depth and its pass mode
/// moved from `test-support` to `h2-apply-arms` so that the gate binary,
/// which turns `test-support` on, compiles the walk that ships; these
/// hold that a build WITH the feature still reads every dial it sets, one
/// test per knob, and that each unset dial is the shipped value. The walk
/// reads each reader under the same `cfg` (`tape::apply_walk`), and the
/// byte-exact differentials in `rar5_lz::tests` run both settings of each.
#[cfg(all(test, feature = "parallel", feature = "h2-apply-arms"))]
mod apply_knob_tests {
    use super::*;

    #[test]
    fn the_literal_ladder_dial_reaches_its_reader() {
        assert!(!literal_ladder(), "unset is the shipped fixed-width store");
        set_literal_ladder(Some(true));
        assert!(literal_ladder());
        set_literal_ladder(Some(false));
        assert!(!literal_ladder());
        set_literal_ladder(None);
        assert!(!literal_ladder());
    }

    #[test]
    fn the_far_prefetch_depth_dial_reaches_its_reader() {
        for depth in [0, 1, 17, 64, 256] {
            set_far_prefetch(Some(depth));
            assert_eq!(far_prefetch(), depth);
        }
        set_far_prefetch(None);
        // Unset defers to the environment, then to the shipped depth.
        if std::env::var_os("RARKIT_FAR_PREFETCH").is_none() {
            assert_eq!(
                far_prefetch(),
                crate::rar5_lz::output::Window::FAR_PREFETCH_DEPTH
            );
        }
    }

    #[test]
    fn the_far_prefetch_mode_dial_reaches_its_reader() {
        assert_eq!(far_prefetch_mode(), far_prefetch_modes::ALL);
        for mode in [
            far_prefetch_modes::DRY,
            far_prefetch_modes::UNGATED,
            far_prefetch_modes::ALL,
        ] {
            set_far_prefetch_mode(mode);
            assert_eq!(far_prefetch_mode(), mode);
        }
    }
}

#[cfg(test)]
mod tests {
    //! The knobs whose UNSET value is a claim about what ships.

    /// An unset x86 arm dispatches the body that SHIPS.
    ///
    /// The three arms compute the same bytes, so no output can tell them
    /// apart and an equivalence test cannot catch this: the only
    /// observable is the value the dispatch reads. Nothing else in the
    /// library sets this knob, so reading it here is not a race with
    /// another unit test; a harness that sets it does so in its own
    /// process.
    #[test]
    fn unset_x86_arm_is_the_shipped_adaptive() {
        assert_eq!(
            super::x86_arm(),
            super::X86_ARM_ADAPTIVE,
            "an unset arm must dispatch the shipped body; arm 0 is walking, not a sentinel"
        );
    }
}

// ---------------------------------------------------------------------------
// The wait census
// ---------------------------------------------------------------------------

/// WHAT EVERY THREAD OF A READ IS DOING OR WAITING ON, as gauges a sampler
/// reads (feature `wait-census`, never shipped and not part of
/// `test-support`: its sites sit on every tape unit).
///
/// A thread census from outside (`/proc`, `sample`) says how many threads
/// run and how many are parked, and not which wait each parked thread is
/// in. Each site here is one place a read's thread waits or works; a
/// thread inside it holds the site's gauge up by one, and the site's
/// entries and nanoseconds are summed. `examples/breadth_lanes.rs` polls
/// the gauges while an extraction runs and prints their means, so a row
/// reads "of the members in flight, this many were applying, this many
/// waited on a lane, this many waited to be admitted".
#[cfg(feature = "wait-census")]
pub mod census {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
    use std::time::Instant;

    /// The walk, waiting on the front member's answer because the outputs
    /// open at once are at their bound.
    pub const WALK_OUTPUTS: usize = 0;
    /// The walk, waiting on the front member because the next member's
    /// window does not fit the working limit beside those in flight.
    pub const WALK_MEMORY: usize = 1;
    /// The walk, closing what is in flight (a member it decodes itself,
    /// a skipped one, the archive's end, a pipe's worker).
    pub const WALK_END: usize = 2;
    /// The walk, waiting for any worker to answer (the breadth is full).
    pub const WALK_WORKER: usize = 3;
    /// The walk, waiting for the small-member team.
    pub const WALK_TEAM: usize = 4;
    /// A started pool worker with no task.
    pub const WORKER_IDLE: usize = 5;
    /// A member waiting to be admitted by the lane budget.
    pub const ADMIT_WAIT: usize = 6;
    /// Members admitted (holding the budget's member slot).
    pub const MEMBERS: usize = 7;
    /// RAR 5 members on the streamed tape path (16 MiB and up), admitted.
    pub const BIG_MEMBERS: usize = 8;
    /// A streamed member's own thread filling its packed chunk.
    pub const FILL: usize = 9;
    /// A streamed member's own thread locating the chunk's blocks.
    pub const PLAN: usize = 10;
    /// A streamed member's own thread starting its chunk's lanes.
    pub const SPAWN: usize = 11;
    /// The apply stage waiting for a lane's unit.
    pub const APPLY_WAIT: usize = 12;
    /// The apply stage applying a unit.
    pub const APPLY_BUSY: usize = 13;
    /// A streamed member's own thread joining its chunk's lanes.
    pub const JOIN: usize = 14;
    /// A lane decoding a unit.
    pub const LANE_DECODE: usize = 15;
    /// A lane waiting to hand a unit over (the apply is behind).
    pub const LANE_SEND: usize = 16;
    /// A streamed member's chunk decoded on its own thread, no lanes.
    pub const ONE_THREAD: usize = 17;
    /// Lanes alive (threads), summed over members.
    pub const LANES: usize = 18;
    /// A whole member's decode on a pool worker, admission wait included.
    pub const DECODE: usize = 19;
    /// The walk, closing everything in flight before it closes a member
    /// it decoded ITSELF (`Pool::close`).
    pub const WALK_OWN_CLOSE: usize = 20;
    /// The walk, closing everything in flight before it counts a member
    /// the sink SKIPPED, a directory entry among them (`Pool::skipped`).
    pub const WALK_SKIPPED: usize = 21;
    /// How many sites there are.
    pub const SITES: usize = 22;

    /// The sites' names, in order.
    pub const NAMES: [&str; SITES] = [
        "walk_outputs",
        "walk_memory",
        "walk_end",
        "walk_worker",
        "walk_team",
        "worker_idle",
        "admit_wait",
        "members",
        "big_members",
        "fill",
        "plan",
        "spawn",
        "apply_wait",
        "apply_busy",
        "join",
        "lane_decode",
        "lane_send",
        "one_thread",
        "lanes",
        "decode",
        "walk_own_close",
        "walk_skipped",
    ];

    static NOW: [AtomicI64; SITES] = [const { AtomicI64::new(0) }; SITES];
    static ENTERS: [AtomicU64; SITES] = [const { AtomicU64::new(0) }; SITES];
    static NANOS: [AtomicU64; SITES] = [const { AtomicU64::new(0) }; SITES];

    thread_local! {
        /// Why the walk is about to settle the front member, set by the
        /// caller of `Pool::settle_front` and read inside it.
        static WHY: Cell<usize> = const { Cell::new(WALK_END) };
    }

    /// A thread inside a site, for as long as this lives.
    pub struct At {
        site: usize,
        from: Instant,
        by: i64,
    }

    /// Enter `site`.
    pub fn at(site: usize) -> At {
        by(site, 1)
    }

    /// Enter `site`, holding its gauge up by `n` (the lanes of a chunk).
    pub fn by(site: usize, n: usize) -> At {
        let by = n as i64;
        NOW[site].fetch_add(by, Ordering::Relaxed);
        ENTERS[site].fetch_add(1, Ordering::Relaxed);
        At {
            site,
            from: Instant::now(),
            by,
        }
    }

    impl Drop for At {
        fn drop(&mut self) {
            NOW[self.site].fetch_sub(self.by, Ordering::Relaxed);
            NANOS[self.site].fetch_add(self.from.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
    }

    /// Say why this thread's next settle of the front member is made.
    pub fn because(site: usize) {
        WHY.with(|w| w.set(site));
    }

    /// Enter the site [`because`] last named on this thread. The reason
    /// stands until [`because`] names another: `Pool::settle` closes the
    /// whole flight under one.
    pub fn at_settle() -> At {
        at(WHY.with(|w| w.get()))
    }

    /// Every gauge, now.
    pub fn now() -> [i64; SITES] {
        std::array::from_fn(|i| NOW[i].load(Ordering::Relaxed))
    }

    /// Every site's entries and nanoseconds since [`reset`].
    pub fn totals() -> [(u64, u64); SITES] {
        std::array::from_fn(|i| {
            (
                ENTERS[i].load(Ordering::Relaxed),
                NANOS[i].load(Ordering::Relaxed),
            )
        })
    }

    /// Forget the entries and the nanoseconds; the gauges are live.
    pub fn reset() {
        for i in 0..SITES {
            ENTERS[i].store(0, Ordering::Relaxed);
            NANOS[i].store(0, Ordering::Relaxed);
        }
    }
}
