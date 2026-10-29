//! The seam's guard and dials: its floor, the coalesce rule, the lent slab,
//! and the cipher overlap and its chunk.

use super::*;

/// The most SEAM units alive at once, anywhere in the process.
///
/// The seam of spec F 3.7.7 puts one member's read, decrypt, decode and
/// checksum on a scoped thread while the walking thread writes. SPEC-API
/// 8.5 prices that at ONE unit of the read side's thread ceiling per
/// member in flight, in the same accounting as a decode lane, so it is
/// counted the way [`peak_lanes`] counts a lane rather than inferred from
/// how many members a caller asked for: a member below the seam's floor,
/// or one a policy has no room for a ring for, is run in sequence and
/// adds no unit at all.
///
/// PROCESS-wide, for the same reason [`peak_workers`] is.
pub(super) static SEAM_NOW: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub(super) static SEAM_PEAK: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// A seam's source unit is alive for as long as this lives.
#[cfg(feature = "parallel")]
pub(crate) struct SeamGuard;

#[cfg(feature = "parallel")]
impl SeamGuard {
    pub(crate) fn enter() -> SeamGuard {
        use std::sync::atomic::Ordering;
        let now = SEAM_NOW.fetch_add(1, Ordering::Relaxed) + 1;
        SEAM_PEAK.fetch_max(now, Ordering::Relaxed);
        SeamGuard
    }
}

#[cfg(feature = "parallel")]
impl Drop for SeamGuard {
    fn drop(&mut self) {
        SEAM_NOW.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The most seam source units alive at once since [`reset_peak_seam`].
pub fn peak_seam() -> usize {
    SEAM_PEAK.load(std::sync::atomic::Ordering::Relaxed)
}

/// Seam source units alive right now.
pub fn seam_now() -> usize {
    SEAM_NOW.load(std::sync::atomic::Ordering::Relaxed)
}

/// Forget the seam high-water mark.
pub fn reset_peak_seam() {
    SEAM_PEAK.store(
        SEAM_NOW.load(std::sync::atomic::Ordering::Relaxed),
        std::sync::atomic::Ordering::Relaxed,
    );
}

thread_local! {
    /// The seam floor this thread's next extraction should use, in place
    /// of `read::seam::SEAM_FLOOR`.
    ///
    /// Per THREAD for the same reason `OFFLOAD_FLOOR` is: it is read on
    /// the WALKING thread, which is the thread that called `extract`, so
    /// a thread-local reaches exactly the run that set it.
    ///
    /// `Some(0)` forces the seam on for every written member, which is
    /// what a test that wants the overlapped path over a small fixture
    /// asks for; `Some(u64::MAX)` turns it off, which is how the same
    /// fixture's bytes are taken on the sequential path for comparison.
    /// SPEC-API 8.5 does not promise whether any given member is
    /// overlapped, so neither answer is an API fact.
    pub(super) static SEAM_FLOOR: Cell<Option<u64>> = const { Cell::new(None) };
}

/// Run this thread's next extractions with `bytes` as the seam floor, or
/// with the engine's own figure when `None`.
pub fn set_seam_floor(bytes: Option<u64>) {
    let _ = SEAM_FLOOR.try_with(|c| c.set(bytes));
}

/// The seam floor this thread asked for, if it asked for one.
#[cfg(feature = "parallel")]
pub(crate) fn seam_floor() -> Option<u64> {
    SEAM_FLOOR.try_with(Cell::get).unwrap_or(None)
}

thread_local! {
    /// Whether the seam's deliver unit COALESCES a ring buffer's writes
    /// into one, in place of replaying the source unit's own write
    /// boundaries.
    ///
    /// A MEASUREMENT KNOB AND NOTHING ELSE, and the only one in this file
    /// that turns on a behaviour the engine has rejected rather than a
    /// constant it has not yet fixed. Coalescing is what the seam did
    /// until it was found offering a refusing writer a whole ring where
    /// the sequential path offered one chunk, which is spec F 3.7.6's
    /// promise loosened by the size of the ring
    /// (`tests/parallel.rs::a_refused_write_stops_a_piped_member_s_decode`,
    /// 1,049,096 against 131,592). It exists because the question "how
    /// much of the seam's measured win was the bigger writes" cannot be
    /// answered by building two shas: code LAYOUT alone was
    /// measured moving an untouched leg about 7
    /// percent, so a before and after must be ONE BINARY against itself.
    ///
    /// Default `None`, which is boundary-preserving. Nothing but a bench
    /// or a test ever sets it, and `test-support` is what reads it.
    pub(super) static SEAM_COALESCE: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Run this thread's next extractions with the seam's deliver unit
/// coalescing each ring buffer into one write, or not, or with the
/// engine's own answer when `None`.
///
/// See [`SEAM_COALESCE`]: `Some(true)` restores a shape that LOOSENS spec
/// F 3.7.6's refusal bound, and is for pricing that shape against the one
/// that ships. It is not an API fact and no caller can reach it.
pub fn set_seam_coalesce(on: Option<bool>) {
    let _ = SEAM_COALESCE.try_with(|c| c.set(on));
}

/// Whether this thread asked for the coalescing deliver unit.
#[cfg(feature = "parallel")]
pub(crate) fn seam_coalesce() -> bool {
    SEAM_COALESCE.try_with(Cell::get).unwrap_or(None) == Some(true)
}

thread_local! {
    /// Whether a stored member on the seam's LENT path asks the ring for
    /// the WHOLE of the slab it is lent at each read, in place of the
    /// engine's own answer (`extract::lent::whole_slab`, which says yes
    /// from 1 GiB). A measurement knob for the big-media extract work.
    pub(super) static LENT_WHOLE_SLAB: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Run this thread's next extractions with the lent path asking for whole
/// slabs (`Some(true)`), for its ordinary request (`Some(false)`), or with
/// the engine's own answer (`None`).
pub fn set_lent_whole_slab(on: Option<bool>) {
    let _ = LENT_WHOLE_SLAB.try_with(|c| c.set(on));
}

/// This thread's answer, else the process's `RARKIT_LENT_WHOLE_SLAB` (`1`
/// or `0`, read once, for a count from the command line), else `None`.
#[cfg(feature = "parallel")]
pub(crate) fn lent_whole_slab() -> Option<bool> {
    if let Some(v) = LENT_WHOLE_SLAB.try_with(Cell::get).unwrap_or(None) {
        return Some(v);
    }
    static ENV: std::sync::OnceLock<Option<bool>> = std::sync::OnceLock::new();
    *ENV.get_or_init(
        || match std::env::var("RARKIT_LENT_WHOLE_SLAB").ok().as_deref() {
            Some("1") => Some(true),
            Some("0") => Some(false),
            _ => None,
        },
    )
}

thread_local! {
    /// Whether this thread's next extractions run an encrypted stored
    /// member's cipher and hasher OVERLAPPED, in place of the engine's
    /// own answer.
    ///
    /// The acceptance leg SPEC-F 3.7.7 names,
    /// `f/extract-one-stored-encrypted-overlap`, is the overlap ON
    /// against OFF on one member, and it cannot be two shas
    /// for this reason: code LAYOUT alone moves an untouched
    /// leg about 7 percent, so a before and after has to be ONE BINARY
    /// against itself. `Some(false)` is the serial pipeline this overlap
    /// replaced, kept reachable for exactly that comparison;
    /// `Some(true)` forces the overlap on for a member the engine's own
    /// floor would run in sequence.
    ///
    /// **The bytes and the verdict are identical either way**, which is
    /// what `tests/encrypted_overlap.rs` pins: this is a knob over the
    /// ARRANGEMENT of the work and never over its result.
    pub(super) static CIPHER_OVERLAP: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Run this thread's next extractions with the cipher and the hasher
/// overlapped, or in sequence, or with the engine's own answer when
/// `None`. See [`CIPHER_OVERLAP`].
pub fn set_cipher_overlap(on: Option<bool>) {
    let _ = CIPHER_OVERLAP.try_with(|c| c.set(on));
}

/// What this thread asked of the cipher-hasher overlap, if it asked.
#[cfg(feature = "parallel")]
pub(crate) fn cipher_overlap() -> Option<bool> {
    CIPHER_OVERLAP.try_with(Cell::get).unwrap_or(None)
}

thread_local! {
    /// Members whose cipher and hasher actually ran OVERLAPPED on this
    /// thread since the last [`reset_cipher_overlaps`].
    ///
    /// Per THREAD for the same reason [`DECODED`] is, and it is the same
    /// count for the same reason: `read::extract::copy` chooses the
    /// arrangement on the thread that is decoding the member.
    ///
    /// **This exists so an acceptance test cannot pass VACUOUSLY.**
    /// `overlap_plan`'s four conditions are all satisfiable by accident
    /// in a small fixture, and a test that compares an overlapped
    /// extraction with a sequential one proves nothing at all if neither
    /// arm overlapped. `tests/encrypted_overlap.rs` reads this and
    /// asserts the count before it compares any bytes.
    pub(super) static CIPHER_OVERLAPS: Cell<u64> = const { Cell::new(0) };
}

/// Count one member whose cipher and hasher ran overlapped.
#[cfg(feature = "parallel")]
pub(crate) fn note_cipher_overlap() {
    let _ = CIPHER_OVERLAPS.try_with(|c| c.set(c.get() + 1));
}

/// How many members this thread has overlapped since the last reset.
pub fn cipher_overlaps() -> u64 {
    CIPHER_OVERLAPS.try_with(Cell::get).unwrap_or(0)
}

/// Start counting overlapped members again from zero on this thread.
pub fn reset_cipher_overlaps() {
    let _ = CIPHER_OVERLAPS.try_with(|c| c.set(0));
}

thread_local! {
    /// The chunk each of the overlap's two buffers holds, in place of
    /// `read::extract::overlap_plan`'s own answer.
    ///
    /// **A MEASUREMENT DIAL THAT CAN BREACH A MEMORY PROMISE, and it is
    /// here for one question.** The plan HALVES `read_ahead` before
    /// taking it twice, so two overlapped buffers cost what the serial
    /// path's one costs; the consequence is that the hasher is fed half
    /// the batch it was fed before, and the hasher's own
    /// dispatch census says a feed of half the size is about twice the
    /// dispatches and about twice the width-one staged remainder. So
    /// the overlap buys a stage and pays for a chunking, and the two
    /// have to be told apart before either is believed. Setting this
    /// above the plan's answer runs the overlap OUTSIDE
    /// `MemoryPolicy::read_ahead` and is for that comparison only:
    /// nothing but a bench sets it and no caller can reach it.
    pub(super) static CIPHER_OVERLAP_CHUNK: Cell<Option<usize>> = const { Cell::new(None) };
}

/// Run this thread's overlapped members with `bytes` per buffer, or with
/// the engine's own answer when `None`. See [`CIPHER_OVERLAP_CHUNK`].
pub fn set_cipher_overlap_chunk(bytes: Option<usize>) {
    let _ = CIPHER_OVERLAP_CHUNK.try_with(|c| c.set(bytes));
}

/// The overlap chunk this thread asked for, if it asked for one.
#[cfg(feature = "parallel")]
pub(crate) fn cipher_overlap_chunk() -> Option<usize> {
    CIPHER_OVERLAP_CHUNK.try_with(Cell::get).unwrap_or(None)
}

thread_local! {
    /// Whether an overlapped member's CBC decrypt takes a SECOND LANE,
    /// in place of the engine's own answer.
    ///
    /// Behind the `k-two-lane-probe` feature and nothing else. It is
    /// deliberately NOT part of `bench-internals` or `test-support`,
    /// both of which the gate bench turns on for every leg: a knob
    /// those carried would be compiled into every gate binary, where
    /// the gate must compile the code that ships.
    ///
    /// **Why a knob rather than two shas.** The prize this change is
    /// priced for is 5 to 8 percent of two legs
    /// (22 Sep), and a measurement
    /// of 20 Sep puts code LAYOUT alone at about 7 percent on a leg
    /// nothing touched. A before and after taken as two binaries cannot
    /// tell this change from its own layout, so the comparison has to be
    /// ONE BINARY against itself, which is the same argument
    /// [`CIPHER_OVERLAP`] is here for.
    ///
    /// **The bytes and the verdict are identical either way.** This
    /// moves the ARRANGEMENT of the decrypt and never its result; the
    /// mode is parallel by construction and each lane runs the same
    /// arithmetic from the same chaining value.
    pub(super) static TWO_LANE_CIPHER: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Run this thread's overlapped members with the CBC decrypt split
/// across two lanes, or on one, or with the engine's own answer when
/// `None`. See [`TWO_LANE_CIPHER`].
#[cfg(feature = "k-two-lane-probe")]
pub fn set_two_lane_cipher(on: Option<bool>) {
    let _ = TWO_LANE_CIPHER.try_with(|c| c.set(on));
}

/// What this thread asked of the two lane cipher, if it asked.
#[cfg(all(feature = "k-two-lane-probe", feature = "parallel"))]
pub(crate) fn two_lane_cipher() -> Option<bool> {
    TWO_LANE_CIPHER.try_with(Cell::get).unwrap_or(None)
}
