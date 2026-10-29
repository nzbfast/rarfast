//! The apply walk's knobs: the literal ladder and the far prefetch, its
//! distance, floor and modes.

use super::*;

thread_local! {
    /// Which arm of the apply loop's LITERAL path runs: the fixed-width
    /// store out of the ring's spill margin, or the carried inline
    /// ladder that branches on the run's length.
    ///
    /// A MEASUREMENT KNOB, for the reason [`SEAM_COALESCE`] states at
    /// length and this work needs twice over. Code LAYOUT alone was
    /// measured moving an untouched leg by 7
    /// percent, and by 16 in a later measurement, and the difference
    /// this knob is pricing is of that order, so two shas cannot settle
    /// it: the before and after has to be ONE BINARY against itself. Both
    /// arms write the same bytes and stop at the same operation - the
    /// spill slots the wide arm touches are unnameable, which is what
    /// `the_room_ahead_of_the_apply_point_is_the_spill_margin_and_no_more`
    /// holds - so this is a speed dial and not a behaviour switch, and
    /// the differential tests are run against both settings.
    ///
    /// Default `None`, which is the arm that SHIPS: the fixed-width
    /// store. Without `h2-apply-arms` the constant is folded in and the
    /// ladder arm is not reachable at all.
    pub(super) static LITERAL_LADDER: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Run this thread's next RAR 5 extractions with the apply stage's
/// literal path on the carried inline LADDER rather than the fixed-width
/// store, or with the shipping arm when `None` or `Some(false)`.
///
/// A MEASURING ARM, so it reaches the walk only with the `h2-apply-arms`
/// feature. `test-support` alone compiles this setter and nothing that
/// reads it: `two_arm` turns `test-support` on through the crate's dev
/// dependency on itself, and the gate binary must compile the apply loop
/// that ships. Without the feature this is a store
/// nobody reads.
pub fn set_literal_ladder(on: Option<bool>) {
    let _ = LITERAL_LADDER.try_with(|c| c.set(on));
}

/// Whether this thread asked for the ladder arm.
#[cfg(all(feature = "parallel", feature = "h2-apply-arms"))]
pub(crate) fn literal_ladder() -> bool {
    LITERAL_LADDER.try_with(Cell::get).unwrap_or(None) == Some(true)
}

thread_local! {
    /// THE FAR-COPY PREFETCH DEPTH this thread's next RAR 5 extractions
    /// run the tape walk at: how many operations ahead of the apply point
    /// a fresh match's source is hinted, zero for none.
    ///
    /// A MEASUREMENT KNOB for the reason [`LITERAL_LADDER`] gives: the
    /// lever is priced ONE BINARY against itself, and every setting
    /// writes the same bytes, since a hint changes no state. `None` defers
    /// to `RARKIT_FAR_PREFETCH`, then to the shipped depth.
    pub(super) static FAR_PREFETCH: Cell<Option<usize>> = const { Cell::new(None) };
}

/// Run this thread's next RAR 5 extractions with the tape walk's far-copy
/// prefetch at `depth` operations ahead (`Some(0)` is off), or defer to
/// the environment and then the shipped depth with `None`.
///
/// A MEASURING ARM, so it reaches the walk only with the `h2-apply-arms`
/// feature. `test-support` alone compiles this setter and nothing that
/// reads it: `two_arm` turns `test-support` on through the crate's dev
/// dependency on itself, and the gate binary must compile the apply loop
/// that ships. Without the feature this is a store
/// nobody reads.
pub fn set_far_prefetch(depth: Option<usize>) {
    let _ = FAR_PREFETCH.try_with(|c| c.set(depth));
}

/// The far-copy prefetch's DISTANCE, a measuring dial: `RARKIT_FAR_DISTANCE`
/// in KiB, read ONCE a process (said once on stderr), else the shipped
/// `Window::FAR_GATE_DISTANCE`. What the lane lists, the gate samples and
/// the walk hints as far, all three at once.
#[cfg(all(feature = "parallel", feature = "h2-apply-arms"))]
pub(crate) fn far_distance() -> usize {
    static FROM_ENV: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *FROM_ENV.get_or_init(|| {
        match std::env::var("RARKIT_FAR_DISTANCE")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
        {
            Some(kib) => {
                eprintln!("rarkit far distance: {kib} KiB");
                kib << 10
            }
            None => crate::rar5_lz::output::Window::FAR_GATE_DISTANCE,
        }
    })
}

thread_local! {
    /// THE FAR PREFETCH'S DICTIONARY FLOOR this thread's next RAR 5
    /// extractions use, `None` deferring to `RARKIT_FAR_FLOOR_KIB` and then
    /// the shipped floor. A test that holds the two hint walks against each
    /// other on small rings sets it to zero, so the floor does not turn the
    /// machinery under test off.
    pub(super) static FAR_FLOOR: Cell<Option<usize>> = const { Cell::new(None) };
}

/// Run this thread's next RAR 5 extractions with the far prefetch's
/// dictionary floor at `floor` bytes, or defer with `None`. A measuring
/// arm: it reaches the walk only with the `h2-apply-arms` feature.
pub fn set_far_floor(floor: Option<usize>) {
    let _ = FAR_FLOOR.try_with(|c| c.set(floor));
}

/// The far prefetch's dictionary floor, a measuring dial: this thread's
/// own ([`set_far_floor`]), else `RARKIT_FAR_FLOOR_KIB` read ONCE a
/// process (said once on stderr), else the shipped
/// `Window::FAR_DICTIONARY_FLOOR`.
#[cfg(all(feature = "parallel", feature = "h2-apply-arms"))]
pub(crate) fn far_floor() -> usize {
    if let Some(floor) = FAR_FLOOR.try_with(Cell::get).unwrap_or(None) {
        return floor;
    }
    static FROM_ENV: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *FROM_ENV.get_or_init(|| {
        match std::env::var("RARKIT_FAR_FLOOR_KIB")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
        {
            Some(kib) => {
                eprintln!("rarkit far floor: {kib} KiB");
                kib << 10
            }
            None => crate::rar5_lz::output::Window::FAR_DICTIONARY_FLOOR,
        }
    })
}

/// The far gate's ratio, a measuring dial: `RARKIT_FAR_EVERY` read ONCE a
/// process, else the shipped `Window::FAR_GATE_EVERY`.
#[cfg(all(feature = "parallel", feature = "h2-apply-arms"))]
pub(crate) fn far_every() -> usize {
    static FROM_ENV: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *FROM_ENV.get_or_init(|| {
        match std::env::var("RARKIT_FAR_EVERY")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
        {
            Some(every) => {
                eprintln!("rarkit far every: {every}");
                every
            }
            None => crate::rar5_lz::output::Window::FAR_GATE_EVERY,
        }
    })
}

/// The far-copy prefetch depth for this thread's tape walk: the thread's
/// own dial, else `RARKIT_FAR_PREFETCH` read ONCE a process (said once on
/// stderr when set, so a timed run can show the knob reached the binary),
/// else the shipped [`crate::rar5_lz::output::Window::FAR_PREFETCH_DEPTH`].
/// Read once per tape, never per operation.
///
/// `RARKIT_FAR_PREFETCH` is read HERE, so a binary built without
/// `h2-apply-arms` never reads it and never prints the line that says it
/// did: a timed run's knob cell on the far prefetch needs `two_arm` built
/// with that feature, and a run that checks for the line refuses a
/// binary without it.
#[cfg(all(feature = "parallel", feature = "h2-apply-arms"))]
pub(crate) fn far_prefetch() -> usize {
    if let Some(depth) = FAR_PREFETCH.try_with(Cell::get).unwrap_or(None) {
        return depth;
    }
    static FROM_ENV: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    FROM_ENV
        .get_or_init(|| {
            let v = std::env::var("RARKIT_FAR_PREFETCH").ok()?;
            let depth = v.trim().parse::<usize>().unwrap_or(0);
            eprintln!("rarkit far prefetch: depth {depth}");
            Some(depth)
        })
        .unwrap_or(crate::rar5_lz::output::Window::FAR_PREFETCH_DEPTH)
}

/// What the far-copy prefetch pass does with each fresh match, for the
/// lab's SUBTRACTION of the pass from the hint. Every mode writes the
/// same bytes: a hint changes no state.
pub mod far_prefetch_modes {
    /// Hint every operation of a tape the gate admits
    /// (`Window::FAR_GATE_SAMPLE`): what the lever is.
    pub const ALL: u8 = 0;
    /// Compute every address and hint none, on every tape: the pass
    /// alone, ungated.
    pub const DRY: u8 = 1;
    /// Hint every operation of every tape, the gate removed.
    pub const UNGATED: u8 = 2;
}

thread_local! {
    /// This thread's [`far_prefetch_modes`] setting.
    pub(super) static FAR_PREFETCH_MODE: Cell<u8> = const { Cell::new(far_prefetch_modes::ALL) };
}

/// Run this thread's next RAR 5 extractions with the far-copy prefetch
/// pass in `mode` ([`far_prefetch_modes`]).
///
/// A MEASURING ARM, so it reaches the walk only with the `h2-apply-arms`
/// feature. `test-support` alone compiles this setter and nothing that
/// reads it: `two_arm` turns `test-support` on through the crate's dev
/// dependency on itself, and the gate binary must compile the apply loop
/// that ships. Without the feature this is a store
/// nobody reads.
pub fn set_far_prefetch_mode(mode: u8) {
    let _ = FAR_PREFETCH_MODE.try_with(|c| c.set(mode));
}

/// This thread's far-copy prefetch pass mode.
#[cfg(all(feature = "parallel", feature = "h2-apply-arms"))]
pub(crate) fn far_prefetch_mode() -> u8 {
    FAR_PREFETCH_MODE
        .try_with(Cell::get)
        .unwrap_or(far_prefetch_modes::ALL)
}
