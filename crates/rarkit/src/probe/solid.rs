//! The sequential and solid read's dials and counts: the read ahead, the
//! queue depth, the wide stored pieces and the pool's peaks.

use super::*;

thread_local! {
    /// Whether the SEQUENTIAL entry point decodes ahead, and its byte
    /// ceiling, when a TEST asks rather than the process's environment
    /// (`read::sequential`, `RARKIT_SEQ_AHEAD` and
    /// `RARKIT_SEQ_AHEAD_BYTES`). Per thread, read on the walking thread.
    pub(super) static SEQ_AHEAD: Cell<Option<bool>> = const { Cell::new(None) };
    pub(super) static SEQ_AHEAD_BYTES: Cell<Option<u64>> = const { Cell::new(None) };
    /// The window the look-ahead's workers are held at
    /// (`RARKIT_SEQ_AHEAD_HOLD_MIB`). Per thread, read on the walking thread.
    pub(super) static SEQ_AHEAD_HOLD: Cell<Option<u64>> = const { Cell::new(None) };
    /// Whether the gate holds the worker of a member that packs well too
    /// (`RARKIT_SEQ_AHEAD_HOLD_PACKED`). Per thread, read on the walking
    /// thread.
    pub(super) static SEQ_AHEAD_HOLD_PACKED: Cell<Option<bool>> = const { Cell::new(None) };
    /// The most members and the most declared bytes the look-ahead held
    /// at once, and how many members it ever took, on this thread.
    pub(super) static SEQ_AHEAD_PEAK: Cell<(usize, u64, u64)> = const { Cell::new((0, 0, 0)) };
    /// The most chunk bytes the look-ahead held decoded and not yet
    /// delivered, over the extractions this thread walked.
    pub(super) static SEQ_AHEAD_HELD: Cell<u64> = const { Cell::new(0) };
}

thread_local! {
    /// Whether the sequential look-ahead takes a compressed member under
    /// the offload floor onto its workers (`read::sequential`,
    /// `RARKIT_SEQ_SMALL`), when a TEST asks. Per thread, read on the
    /// walking thread.
    pub(super) static SEQ_SMALL: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Run this thread's next sequential extractions with the look-ahead
/// taking small members onto its workers or not, or as the process's
/// environment says when `None`.
pub fn set_seq_small(on: Option<bool>) {
    let _ = SEQ_SMALL.try_with(|c| c.set(on));
}

#[cfg(feature = "parallel")]
pub(crate) fn seq_small() -> Option<bool> {
    SEQ_SMALL.try_with(Cell::get).unwrap_or(None)
}

/// Run this thread's next sequential extractions with decode-ahead on or
/// off, or as the process's environment says when `None`.
pub fn set_seq_ahead(on: Option<bool>) {
    let _ = SEQ_AHEAD.try_with(|c| c.set(on));
}

/// The look-ahead's byte ceiling for this thread's next sequential
/// extractions, in BYTES, `Some(0)` for none of its own, `None` for the
/// process's setting.
pub fn set_seq_ahead_bytes(bytes: Option<u64>) {
    let _ = SEQ_AHEAD_BYTES.try_with(|c| c.set(bytes));
}

/// The window the look-ahead's workers are held at for this thread's next
/// sequential extractions, in BYTES, `Some(0)` for none, `None` for the
/// process's setting.
pub fn set_seq_ahead_hold(bytes: Option<u64>) {
    let _ = SEQ_AHEAD_HOLD.try_with(|c| c.set(bytes));
}

/// Hold the worker of EVERY member at the look-ahead's gate
/// (`Some(true)`), only of a member that barely packs (`Some(false)`), or
/// as the process's setting says (`None`), for this thread's next
/// sequential extractions.
pub fn set_seq_ahead_hold_packed(all: Option<bool>) {
    let _ = SEQ_AHEAD_HOLD_PACKED.try_with(|c| c.set(all));
}

#[cfg(all(feature = "parallel", feature = "test-support"))]
pub(crate) fn seq_ahead_hold_packed() -> Option<bool> {
    SEQ_AHEAD_HOLD_PACKED.try_with(Cell::get).unwrap_or(None)
}

#[cfg(feature = "parallel")]
pub(crate) fn seq_ahead_hold() -> Option<u64> {
    SEQ_AHEAD_HOLD.try_with(Cell::get).unwrap_or(None)
}

#[cfg(feature = "parallel")]
pub(crate) fn seq_ahead() -> Option<bool> {
    SEQ_AHEAD.try_with(Cell::get).unwrap_or(None)
}

#[cfg(feature = "parallel")]
pub(crate) fn seq_ahead_bytes() -> Option<u64> {
    SEQ_AHEAD_BYTES.try_with(Cell::get).unwrap_or(None)
}

/// The look-ahead now holds `members` members declaring `bytes` bytes.
#[cfg(feature = "parallel")]
pub(crate) fn note_seq_ahead(members: usize, bytes: u64) {
    let _ = SEQ_AHEAD_PEAK.try_with(|c| {
        let (m, b, n) = c.get();
        c.set((m.max(members), b.max(bytes), n + 1));
    });
}

/// An extraction this thread walked held at most `bytes` chunk bytes
/// decoded and not yet delivered.
#[cfg(feature = "parallel")]
pub(crate) fn note_seq_ahead_held(bytes: u64) {
    let _ = SEQ_AHEAD_HELD.try_with(|c| c.set(c.get().max(bytes)));
}

/// The most chunk bytes the look-ahead held decoded and not yet delivered
/// on this thread since the last reset.
pub fn peak_seq_ahead_held() -> u64 {
    SEQ_AHEAD_HELD.try_with(Cell::get).unwrap_or(0)
}

#[cfg(all(feature = "parallel", feature = "test-support"))]
thread_local! {
    /// The gate of the look-ahead this thread is walking under, while it
    /// is: what a test's own writer, which runs on this thread, reads the
    /// look-ahead's holdings from as they stand.
    static SEQ_AHEAD_GATE: std::cell::RefCell<Option<std::sync::Arc<crate::read::sequential::Gate>>> =
        const { std::cell::RefCell::new(None) };
}

/// This thread walks under `gate` from here, or under none.
#[cfg(all(feature = "parallel", feature = "test-support"))]
pub(crate) fn watch_seq_ahead_gate(gate: Option<std::sync::Arc<crate::read::sequential::Gate>>) {
    let _ = SEQ_AHEAD_GATE.try_with(|c| *c.borrow_mut() = gate);
}

/// What the look-ahead this thread is walking under holds NOW: the chunk
/// bytes decoded and not yet delivered, and the workers waiting at its
/// gate. Zeros where the thread walks under none.
#[cfg(all(feature = "parallel", feature = "test-support"))]
pub fn seq_ahead_live() -> (u64, usize) {
    SEQ_AHEAD_GATE
        .try_with(|c| c.borrow().as_ref().map(|g| g.live()))
        .ok()
        .flatten()
        .unwrap_or((0, 0))
}

/// The most members the look-ahead held at once on this thread since the
/// last reset.
pub fn peak_seq_ahead_members() -> usize {
    SEQ_AHEAD_PEAK.try_with(|c| c.get().0).unwrap_or(0)
}

/// The most declared bytes the look-ahead held at once on this thread
/// since the last reset.
pub fn peak_seq_ahead_bytes() -> u64 {
    SEQ_AHEAD_PEAK.try_with(|c| c.get().1).unwrap_or(0)
}

/// How many members the look-ahead took on this thread since the last
/// reset: what makes a test of its bound non-vacuous.
pub fn seq_ahead_taken() -> u64 {
    SEQ_AHEAD_PEAK.try_with(|c| c.get().2).unwrap_or(0)
}

thread_local! {
    /// Whether a SOLID archive's walk goes to a worker
    /// (`read::sequential`, `RARKIT_SOLID_AHEAD`), when a TEST asks, and
    /// how many solid extractions took that path and the most bytes their
    /// budget held.
    pub(super) static SOLID_AHEAD: Cell<Option<bool>> = const { Cell::new(None) };
    pub(super) static SOLID_AHEAD_SEEN: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
    /// The depth of the solid path's queue between its walk and the
    /// caller's thread, when a TEST shrinks it.
    pub(super) static SOLID_QUEUE_DEPTH: Cell<Option<usize>> = const { Cell::new(None) };
}

/// Give this thread's next solid extractions a queue of `depth` items
/// between the walk and the caller's thread, or the engine's own when
/// `None`. A small depth lets a test reach, on a member of a few MiB, the
/// geometry a member of about 1 GiB reaches at the engine's depth: more
/// progress notes inside one member than the queue holds.
pub fn set_solid_queue_depth(depth: Option<usize>) {
    let _ = SOLID_QUEUE_DEPTH.try_with(|c| c.set(depth.map(|d| d.max(1))));
}

#[cfg(feature = "parallel")]
pub(crate) fn solid_queue_depth() -> Option<usize> {
    SOLID_QUEUE_DEPTH.try_with(Cell::get).unwrap_or(None)
}

thread_local! {
    /// Whether the solid path hands a stored member's ranges to the
    /// caller's thread (`read::handed`, `RARKIT_SOLID_STORED_WIDE`), when a
    /// TEST asks; the piece it cuts them at, when a test names one; and
    /// how many ranges this thread has delivered.
    pub(super) static SOLID_STORED_WIDE: Cell<Option<bool>> = const { Cell::new(None) };
    pub(super) static SOLID_STORED_PIECE: Cell<Option<u64>> = const { Cell::new(None) };
    pub(super) static SOLID_STORED_IN_ORDER: Cell<Option<bool>> = const { Cell::new(None) };
    pub(super) static SOLID_STORED_RANGES: Cell<u64> = const { Cell::new(0) };
}

/// Hand this thread's next solid extractions' stored ranges to the
/// caller's thread, or queue every byte as before, or do as the
/// environment says when `None`.
pub fn set_solid_stored_wide(on: Option<bool>) {
    let _ = SOLID_STORED_WIDE.try_with(|c| c.set(on));
}

/// The smallest range of a stored member the wide read takes
/// (`read::wide::FLOOR`), for a caller's test that holds a figure of its
/// own to it: rarkit-cli advises an archive file as read in order by its
/// length against this floor, and its test fails if the two differ.
#[cfg(feature = "parallel")]
pub fn wide_floor() -> u64 {
    crate::read::wide::FLOOR
}

/// The bound on volumes forwarded ahead of the pool's workers
/// (`read::forwarded`): the most fragments ever forwarded and unread at once in
/// this process, how many times a walk waited at the bound, and the bound
/// as it stands now.
#[cfg(all(feature = "parallel", feature = "test-support"))]
pub fn open_ahead() -> (usize, u64, usize) {
    use std::sync::atomic::Ordering;
    (
        crate::read::forwarded::probe::PEAK.load(Ordering::Relaxed),
        crate::read::forwarded::probe::WAITS.load(Ordering::Relaxed),
        crate::read::forwarded::limit(),
    )
}

/// How many times a read abreast (`read::across`) was held at the bound on
/// volumes open ahead and joined pieces of its own before it opened
/// another, in this process.
#[cfg(all(feature = "parallel", feature = "test-support"))]
pub fn open_ahead_refusals() -> u64 {
    crate::read::forwarded::probe::REFUSALS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Cut a handed range into pieces of `bytes`, where a test forces the
/// hand-over on ([`set_solid_stored_wide`]); half the read-ahead when
/// `None`.
pub fn set_solid_stored_piece(bytes: Option<u64>) {
    let _ = SOLID_STORED_PIECE.try_with(|c| c.set(bytes));
}

/// Read a handed range with ONE reader in order (`Some(true)`), with the
/// window's pieces at once (`Some(false)`), or as the system's default
/// says (`None`), where a test forces the hand-over on.
pub fn set_solid_stored_in_order(in_order: Option<bool>) {
    let _ = SOLID_STORED_IN_ORDER.try_with(|c| c.set(in_order));
}

#[cfg(feature = "parallel")]
pub(crate) fn solid_stored_in_order() -> Option<bool> {
    SOLID_STORED_IN_ORDER.try_with(Cell::get).unwrap_or(None)
}

#[cfg(feature = "parallel")]
pub(crate) fn solid_stored_wide() -> Option<bool> {
    SOLID_STORED_WIDE.try_with(Cell::get).unwrap_or(None)
}

#[cfg(feature = "parallel")]
pub(crate) fn solid_stored_piece() -> Option<u64> {
    SOLID_STORED_PIECE.try_with(Cell::get).unwrap_or(None)
}

/// One range reached the caller's thread, which is this one.
#[cfg(feature = "parallel")]
pub(crate) fn note_solid_stored_range() {
    let _ = SOLID_STORED_RANGES.try_with(|c| c.set(c.get() + 1));
}

/// How many stored ranges this thread has delivered for a solid walk
/// since the last reset: what makes a test of the hand-over non-vacuous.
pub fn solid_stored_ranges() -> u64 {
    SOLID_STORED_RANGES.try_with(Cell::get).unwrap_or(0)
}

pub fn reset_solid_stored_ranges() {
    let _ = SOLID_STORED_RANGES.try_with(|c| c.set(0));
}

/// Run this thread's next solid extractions with the walk on a worker, or
/// not, or as the environment says when `None`.
pub fn set_solid_ahead(on: Option<bool>) {
    let _ = SOLID_AHEAD.try_with(|c| c.set(on));
}

#[cfg(feature = "parallel")]
pub(crate) fn solid_ahead() -> Option<bool> {
    SOLID_AHEAD.try_with(Cell::get).unwrap_or(None)
}

/// One solid extraction took the worker path, its budget holding at most
/// `peak` bytes.
#[cfg(feature = "parallel")]
pub(crate) fn note_solid_ahead(peak: u64) {
    let _ = SOLID_AHEAD_SEEN.try_with(|c| {
        let (n, p) = c.get();
        c.set((n + 1, p.max(peak)));
    });
}

/// How many solid extractions on this thread took the worker path, and the
/// most bytes their budget ever held, since the last reset.
pub fn solid_ahead_seen() -> (u64, u64) {
    SOLID_AHEAD_SEEN.try_with(Cell::get).unwrap_or((0, 0))
}

pub fn reset_solid_ahead_seen() {
    let _ = SOLID_AHEAD_SEEN.try_with(|c| c.set((0, 0)));
    let _ = SOLID_POOL_SEEN.try_with(|c| c.set((0, 0)));
}

thread_local! {
    /// The solid path's buffer pool: the most capacity it held alive at
    /// once, and the capacity still handed out when the extraction ended.
    pub(super) static SOLID_POOL_SEEN: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
}

/// One solid extraction's buffer pool held at most `peak` bytes of
/// capacity alive, and `out` bytes were still handed out at its end.
#[cfg(feature = "parallel")]
pub(crate) fn note_solid_pool(peak: u64, out: u64) {
    let _ = SOLID_POOL_SEEN.try_with(|c| {
        let (p, o) = c.get();
        c.set((p.max(peak), o.max(out)));
    });
}

/// The most capacity the solid path's pool held alive in the extractions on
/// this thread since the last [`reset_solid_ahead_seen`], and the most any
/// of them left handed out at its end (zero when every buffer came back).
pub fn solid_pool_seen() -> (u64, u64) {
    SOLID_POOL_SEEN.try_with(Cell::get).unwrap_or((0, 0))
}

pub fn reset_seq_ahead_peak() {
    let _ = SEQ_AHEAD_PEAK.try_with(|c| c.set((0, 0, 0)));
    let _ = SEQ_AHEAD_HELD.try_with(|c| c.set(0));
}
