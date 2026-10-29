//! Carried from the predecessor's `recovery/rar5.rs` at an earlier revision: items ours from birth
//! per the provenance census (and clean-room outputs, clean by provenance).

use std::borrow::Cow;
/// Ceiling on a striped plan's `damaged * data_count` encoder cells (u16s),
/// i.e. 64 MB of matrix at 32M cells. The striped path holds only the
/// selected rows, so `data_count` alone costs nothing grid-shaped any more -
/// a 100 GB release split into 15 MB volumes is ~6,800 data volumes and must
/// plan - but a crafted header can still pair a wide slot count with a huge
/// damage list, and rows * columns is what that declaration actually
/// allocates. Any real repair is tens of damaged volumes against tens of
/// thousands of slots at most, orders of magnitude under this line.
pub(crate) const MAX_STRIPE_PLAN_CELLS: usize = 32 * 1024 * 1024;
/// Source-window bytes below which the striped repair folds a window into a
/// rebuilt row on the calling thread, for a host of `threads` threads.
///
/// This fold dispatches once per (source, damaged row) per stripe, so its
/// team is woken and parked once per SOURCE - a 17-volume set is 17
/// dispatches a stripe - and it pays per WINDOW, never per repair. Measured
/// 15 Sep 2026, serial build against parallel, cold process and warm pool.
/// On an M1 Ultra (20 threads) a 1 MiB window was 2.0-2.6x the serial time,
/// 4 MiB (a one-volume repair of 4 MiB volumes, rarfast `rc`'s case)
/// 1.14-1.23x, 8 MiB 1.02-1.10x, 12 MiB 0.91-0.94x and 64 MiB 0.55-0.66x;
/// on an M3 Ultra (32 threads) every one of those was worse - 16 MiB still
/// 1.30-1.34x, 24 MiB 1.14-1.15x, 32 MiB 0.96x, 64 MiB 0.72-0.81x - and a
/// 16 MiB window cost 12% END TO END in `rarfast rc`, which is the defect
/// this gate's first form shipped. Coarser tasks (1 and 4 MiB) only brought
/// small windows back to even, never ahead. So: 2 MiB of window a thread,
/// which wins on both (20 threads 0.64-0.69x, 32 threads 0.72-0.81x),
/// floored at the 12 MiB the 20-thread box measured.
///
/// `rarfast rc` cannot reach this: `REV_REBUILD_BUDGET` is 64 MiB and a
/// one-volume repair divides it three ways, so its stripe caps near 21 MiB
/// and the fold stays serial on any host of 11 threads or more - which is
/// what every end-to-end measurement of `rc` says it should do. The host's
/// `repair_cap()` reaches 512 MiB, so a daemon-side repair still gets the
/// team. Measured in the host's bench of 14 Sep 2026, section 14 (local
/// change, 15 Sep 2026; see VENDORING.md).
#[cfg(feature = "parallel")]
pub(crate) fn striped_team_min_window_for(threads: usize) -> usize {
    const FLOOR: usize = 12 << 20;
    const PER_THREAD: usize = 2 << 20;
    FLOOR.max(threads.saturating_mul(PER_THREAD))
}
/// Probe-only override of the striped fold's gate, in BYTES, read once from
/// `RARKIT_STRIPED_FOLD_MIN_WINDOW`.
///
/// Behind a NON-DEFAULT feature and absent from every shipped build: the
/// gate below cannot be answered from outside the crate, because the gate is
/// precisely what stops the team starting, so a measurement of "would the
/// team win at a window the gate refuses?" has to be able to move it. `0`
/// forces the team ON at every window and a value past any window forces it
/// OFF, so ONE binary serves both arms of an A/B at the SAME memory budget -
/// which the budget-driven arm pair of
/// the repair scan threading note of 16 Sep 2026, section 7.4, could
/// not do, and its section 7.8 lists as a limit. Unset leaves the shipped
/// rule untouched.
///
/// Cached, because this is read inside the fold's own inner loop and a
/// `getenv` there would be the thing being measured.
///
/// Dead under `--all-features`, where `ratio-lab` swaps in a different
/// caller; live in every shipped and gated build.
#[cfg(all(feature = "parallel", feature = "fold-team-probe"))]
#[allow(dead_code)]
pub(crate) fn striped_team_min_window_probe() -> Option<usize> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    // `usize::MAX` is "not looked up yet"; `usize::MAX - 1` is "looked up,
    // unset". A window can never reach either, so no real threshold collides.
    const UNREAD: usize = usize::MAX;
    const ABSENT: usize = usize::MAX - 1;
    static CACHED: AtomicUsize = AtomicUsize::new(UNREAD);

    let cached = CACHED.load(Ordering::Relaxed);
    if cached == ABSENT {
        return None;
    }
    if cached != UNREAD {
        return Some(cached);
    }
    let read = std::env::var("RARKIT_STRIPED_FOLD_MIN_WINDOW")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok());
    CACHED.store(read.unwrap_or(ABSENT), Ordering::Relaxed);
    read
}
/// Probe-only: the fold's task length, so a bench can bound the team's WIDTH
/// rather than only its existence.
///
/// `RARKIT_STRIPED_FOLD_TEAM_WIDTH=N` cuts the window into at most `N` pieces
/// instead of fixed `RECOVER_FOLD_CHUNK` ones, which caps the concurrency at
/// `N` with no second pool and no change to the process's shared rayon pool -
/// the implementation route
/// the repair fold gate note of 16 Sep 2026 (small volumes), section 8,
/// recommends costing. Its section 6 measured the same axis through
/// `RAYON_NUM_THREADS`, which narrows the WHOLE pool and so is a proxy; this
/// is the thing itself, and section 9 lists the difference as a limit.
///
/// Even, because a chunk start off a 2-byte symbol boundary would corrupt the
/// fold - the same constraint `RECOVER_FOLD_CHUNK` satisfies by being 64 KiB.
///
/// Dead under `--all-features`, where `ratio-lab` swaps in a different
/// caller; live in every shipped and gated build.
#[cfg(all(feature = "parallel", feature = "fold-team-probe"))]
#[allow(dead_code)]
pub(crate) fn striped_fold_chunk_len(window: usize) -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    const UNREAD: usize = usize::MAX;
    const ABSENT: usize = usize::MAX - 1;
    static CACHED: AtomicUsize = AtomicUsize::new(UNREAD);

    let mut width = CACHED.load(Ordering::Relaxed);
    if width == UNREAD {
        width = std::env::var("RARKIT_STRIPED_FOLD_TEAM_WIDTH")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&w| w > 0)
            .unwrap_or(ABSENT);
        CACHED.store(width, Ordering::Relaxed);
    }
    if width == ABSENT {
        return RECOVER_FOLD_CHUNK;
    }
    // Ceiling division, so `width` pieces cover the window, then rounded UP to
    // an even length. Never below 2, and never past the window itself.
    let per = window.div_ceil(width).max(2);
    let per = per.next_multiple_of(2);
    per.min(window.max(2))
}
/// One chunk of a table-driven fold; even so chunk starts stay on symbol
/// boundaries. 64 KiB keeps the destination L2-resident while sources stream.
// Live with the `parallel` feature only, which the default build has.
#[allow(dead_code)]
pub(crate) const RECOVER_FOLD_CHUNK: usize = 64 * 1024;
/// Smallest stripe worth running: below this the per-stripe seek and
/// matrix-solve overhead dominates, and a budget that cannot afford even
/// this much is better reported than crawled through.
///
/// Deliberately low. The working set scales with the DAMAGE count, so a
/// badly damaged set (100 missing shards out of 200) divides the budget a
/// hundred ways; a higher floor here would refuse repairs that are perfectly
/// affordable, just fine-grained. 8 KiB still amortizes the per-stripe solve
/// and keeps each pass over the set sequential enough for the page cache.
pub const MIN_STRIPE_LEN: usize = 8 * 1024;
