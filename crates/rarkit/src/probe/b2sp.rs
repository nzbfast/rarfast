//! The big-to-small-pieces team's dials and counts, and the wide breadth,
//! cores, running and reader dials.

#[allow(unused_imports)]
use super::*;

/// Which figure a BLAKE2sp hasher's worker allowance is taken from
/// (`read::extract::TeamRule`): 0 is the shipped answer
/// (`RARKIT_B2SP_TEAM`, or its default), 1 the policy's, 2 the larger of
/// that and an unstated read width, 3 the read width alone; one word for
/// the process.
pub(super) static B2SP_TEAM: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Force it for the process: 1 policy, 2 larger, 3 width, 0 the default.
pub fn set_b2sp_team(mode: u8) {
    B2SP_TEAM.store(mode, std::sync::atomic::Ordering::SeqCst);
}

/// The forced rule, `None` for none.
pub(crate) fn b2sp_team() -> Option<crate::read::extract::TeamRule> {
    use crate::read::extract::TeamRule;
    match B2SP_TEAM.load(std::sync::atomic::Ordering::SeqCst) {
        1 => Some(TeamRule::Policy),
        2 => Some(TeamRule::Larger),
        3 => Some(TeamRule::Width),
        _ => None,
    }
}

/// The worker allowance the last BLAKE2sp hasher armed in this process was
/// given, 0 before any: nothing in any output says which allowance a
/// hasher holds, so a test of the rule reads it here.
pub(super) static B2SP_ALLOWANCE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Record one hasher's allowance.
pub(crate) fn note_b2sp_allowance(workers: usize) {
    B2SP_ALLOWANCE.store(workers, std::sync::atomic::Ordering::SeqCst);
}

/// The allowance last recorded, and forget it.
pub fn take_b2sp_allowance() -> usize {
    B2SP_ALLOWANCE.swap(0, std::sync::atomic::Ordering::SeqCst)
}

/// Whether a clear stored BLAKE2sp member a pool worker writes is cut
/// (`read::handed::b2sp_cut`): 0 is the shipped answer (`RARKIT_B2SP_CUT`,
/// or its default), 1 never, 2 the hasher on a lane behind the reader, 3
/// the hasher on the reader. One word for the process: a pool worker reads
/// it on its own thread.
pub(super) static B2SP_CUT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// How many ranges such a worker has cut, in the whole process.
pub(super) static B2SP_CUTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Cut such members (`Some(true)`), leave them as before (`Some(false)`),
/// or do as the environment says (`None`); `lane` names where the hasher
/// runs where the cut is forced on.
pub fn set_b2sp_cut(on: Option<bool>, lane: bool) {
    let word = match (on, lane) {
        (None, _) => 0,
        (Some(false), _) => 1,
        (Some(true), true) => 2,
        (Some(true), false) => 3,
    };
    B2SP_CUT.store(word, std::sync::atomic::Ordering::SeqCst);
}

/// The forced answer, `None` for none.
#[cfg(feature = "parallel")]
pub(crate) fn b2sp_cut() -> Option<Option<crate::read::handed::HashDial>> {
    use crate::read::handed::HashDial;
    match B2SP_CUT.load(std::sync::atomic::Ordering::SeqCst) {
        1 => Some(None),
        2 => Some(Some(HashDial {
            lane: true,
            piece: None,
        })),
        3 => Some(Some(HashDial {
            lane: false,
            piece: None,
        })),
        _ => None,
    }
}

/// Whether THE WALK cuts its own clear stored BLAKE2sp member
/// (`read::handed::b2sp_cut_walk`, `RARKIT_B2SP_CUT_WALK`): 0 is the
/// shipped answer, 1 on, 2 off; one word for the process.
pub(super) static B2SP_CUT_WALK: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Force it for the process (`Some`), or do as the environment says.
pub fn set_b2sp_cut_walk(on: Option<bool>) {
    let word = match on {
        None => 0,
        Some(true) => 1,
        Some(false) => 2,
    };
    B2SP_CUT_WALK.store(word, std::sync::atomic::Ordering::SeqCst);
}

/// The forced answer, `None` for none.
#[cfg(feature = "parallel")]
pub(crate) fn b2sp_cut_walk() -> Option<bool> {
    match B2SP_CUT_WALK.load(std::sync::atomic::Ordering::SeqCst) {
        1 => Some(true),
        2 => Some(false),
        _ => None,
    }
}

/// Count one such range.
#[cfg(feature = "parallel")]
pub(crate) fn note_b2sp_cut() {
    B2SP_CUTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// How many such ranges since the last reset: what makes a test of the
/// cut non-vacuous.
pub fn b2sp_cuts() -> u64 {
    B2SP_CUTS.load(std::sync::atomic::Ordering::SeqCst)
}

pub fn reset_b2sp_cuts() {
    B2SP_CUTS.store(0, std::sync::atomic::Ordering::SeqCst);
}

/// Whether a clear stored member checked by BLAKE2sp is read wide
/// (`RARKIT_B2SP_WIDE`): 0 is the shipped answer, 1 on, 2 off; one word
/// for the process.
pub(super) static B2SP_WIDE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Force it for the process (`Some`), or do as the environment says.
pub fn set_b2sp_wide(on: Option<bool>) {
    let word = match on {
        None => 0,
        Some(true) => 1,
        Some(false) => 2,
    };
    B2SP_WIDE.store(word, std::sync::atomic::Ordering::SeqCst);
}

/// The forced answer, `None` for none.
#[cfg(feature = "parallel")]
pub(crate) fn b2sp_wide() -> Option<bool> {
    match B2SP_WIDE.load(std::sync::atomic::Ordering::SeqCst) {
        1 => Some(true),
        2 => Some(false),
        _ => None,
    }
}

/// Ranges of BLAKE2sp members read wide and fed to their hasher in order,
/// in the whole process, so a test of the two arrangements proves the
/// wide one ran.
pub(super) static B2SP_WIDES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Count one such range.
#[cfg(feature = "parallel")]
pub(crate) fn note_b2sp_wide() {
    B2SP_WIDES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// How many such ranges so far.
pub fn b2sp_wides() -> u64 {
    B2SP_WIDES.load(std::sync::atomic::Ordering::Relaxed)
}

/// The wide read's breadth rule forced for the process
/// (`RARKIT_WIDE_BREADTH`): 0 is as the environment says, 1 the width as
/// given, 2 the physical cores, 3 the fast cores.
pub(super) static WIDE_BREADTH: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Force it for the process (`Some("width")`, `Some("cores")`,
/// `Some("fast")`), or do as the environment says (`None`, and any other
/// word).
pub fn set_wide_breadth(rule: Option<&str>) {
    let word = match rule {
        Some("width") => 1,
        Some("cores") => 2,
        Some("fast") => 3,
        _ => 0,
    };
    WIDE_BREADTH.store(word, std::sync::atomic::Ordering::SeqCst);
}

/// The forced rule's word, 0 for none.
#[cfg(feature = "parallel")]
pub(crate) fn wide_breadth() -> u8 {
    WIDE_BREADTH.load(std::sync::atomic::Ordering::SeqCst)
}

/// The machine a test states to the breadth rule: its physical cores (0
/// is the machine's own) and its fast cores (0 is none named).
pub(super) static WIDE_PHYSICAL: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub(super) static WIDE_FAST: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// State the machine to the breadth rule (`Some((physical, fast))`), or
/// let it read the machine's own (`None`).
pub fn set_wide_cores(cores: Option<(usize, Option<usize>)>) {
    let (physical, fast) = cores.map_or((0, 0), |(p, f)| (p, f.unwrap_or(0)));
    WIDE_PHYSICAL.store(physical, std::sync::atomic::Ordering::SeqCst);
    WIDE_FAST.store(fast, std::sync::atomic::Ordering::SeqCst);
}

/// The machine stated, `None` for none.
#[cfg(feature = "parallel")]
pub(crate) fn wide_cores() -> Option<(usize, Option<usize>)> {
    match WIDE_PHYSICAL.load(std::sync::atomic::Ordering::SeqCst) {
        0 => None,
        physical => {
            let fast = WIDE_FAST.load(std::sync::atomic::Ordering::SeqCst);
            Some((physical, (fast != 0).then_some(fast)))
        }
    }
}

/// What every sampled piece of a held wide read says of its reader,
/// whatever the clocks say: 0 reads the clocks, 1 that it ran throughout, 2
/// that it waited on the source throughout. One word for the process.
pub(super) static WIDE_RUNNING: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Force it for the process (`Some`), or read the clocks (`None`).
pub fn set_wide_running(running: Option<bool>) {
    let word = match running {
        None => 0,
        Some(true) => 1,
        Some(false) => 2,
    };
    WIDE_RUNNING.store(word, std::sync::atomic::Ordering::SeqCst);
}

/// The forced answer, `None` for none.
#[cfg(feature = "parallel")]
pub(crate) fn wide_running() -> Option<bool> {
    match WIDE_RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
        1 => Some(true),
        2 => Some(false),
        _ => None,
    }
}

/// The most readers any range kept at work WHILE its hold was on, and the
/// decisions that put a hold on, in the whole process, since the last
/// [`take_wide_held`]: what a test of the breadth rule reads, since no
/// output byte shows how many readers worked at once.
pub(super) static WIDE_READERS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub(super) static WIDE_HELD: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Record the readers at work under a hold.
#[cfg(feature = "parallel")]
pub(crate) fn note_wide_readers(at_work: usize) {
    WIDE_READERS.fetch_max(at_work, std::sync::atomic::Ordering::SeqCst);
}

/// Count one decision that put a hold on.
#[cfg(feature = "parallel")]
pub(crate) fn note_wide_held() {
    WIDE_HELD.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// The decisions that put a hold on and the most readers at work under
/// one, and forget both.
pub fn take_wide_held() -> (u64, usize) {
    (
        WIDE_HELD.swap(0, std::sync::atomic::Ordering::SeqCst),
        WIDE_READERS.swap(0, std::sync::atomic::Ordering::SeqCst),
    )
}
