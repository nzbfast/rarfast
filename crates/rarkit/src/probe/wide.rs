//! The wide read's dials and counts: the solid tape, the shared CRC, the
//! wide verify and joins, the job and stored cuts, the split jobs, the
//! fragments abreast, the spawn allowance and the scratch give-backs.

use super::*;

thread_local! {
    /// Whether a decoder built on this thread sends a solid chain's
    /// continuing members down the tape path from the lever's floor
    /// (`rar5_lz`, `RARKIT_SOLID_TAPE`), when a TEST asks; `None` defers to
    /// the environment.
    pub(super) static SOLID_TAPE: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Build this thread's next decoders with the solid tape lever on, or
/// off, or as the environment says when `None`.
pub fn set_solid_tape(on: Option<bool>) {
    let _ = SOLID_TAPE.try_with(|c| c.set(on));
}

#[cfg(feature = "parallel")]
pub(crate) fn solid_tape() -> Option<bool> {
    SOLID_TAPE.try_with(Cell::get).unwrap_or(None)
}

/// Bytes a split stored member's checksum took by APPENDING the CRC its
/// fragment check computed, rather than hashing them again: on the serial
/// `copy` path and on the seam's lent path (`read/extract/lent.rs`).
/// Process-wide, because the lent path runs on the seam's source thread;
/// a test reading them runs alone in its own binary.
pub(super) static CRC_SHARED_COPY: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(super) static CRC_SHARED_LENT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Count `n` bytes shared on the serial copy path (`lent` false) or the
/// lent path (`lent` true).
pub(crate) fn note_crc_shared(lent: bool, n: usize) {
    let counter = if lent {
        &CRC_SHARED_LENT
    } else {
        &CRC_SHARED_COPY
    };
    counter.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
}

/// The two counts, copy path then lent path, since the last reset.
pub fn crc_shared() -> (u64, u64) {
    (
        CRC_SHARED_COPY.load(std::sync::atomic::Ordering::Relaxed),
        CRC_SHARED_LENT.load(std::sync::atomic::Ordering::Relaxed),
    )
}

/// Zero both counts.
pub fn reset_crc_shared() {
    CRC_SHARED_COPY.store(0, std::sync::atomic::Ordering::Relaxed);
    CRC_SHARED_LENT.store(0, std::sync::atomic::Ordering::Relaxed);
}

thread_local! {
    /// Fragment ranges the wide verify (`read::wide`) read and hashed on
    /// this thread since the last [`reset_wide_verifies`].
    ///
    /// Per THREAD because the walking thread is the one that chooses the
    /// arrangement, as with [`CIPHER_OVERLAPS`], and for the same reason:
    /// a test comparing the wide verify with the ordinary loop proves
    /// nothing if neither ran wide. `tests/stored_volume_verify_wide.rs`
    /// asserts it first.
    pub(super) static WIDE_VERIFIES: Cell<u64> = const { Cell::new(0) };
}

/// Count one range read by the wide verify.
#[cfg(feature = "parallel")]
pub(crate) fn note_wide_verify() {
    let _ = WIDE_VERIFIES.try_with(|c| c.set(c.get() + 1));
}

/// How many ranges this thread has read wide since the last reset.
pub fn wide_verifies() -> u64 {
    WIDE_VERIFIES.try_with(Cell::get).unwrap_or(0)
}

/// Start counting wide ranges again from zero on this thread.
pub fn reset_wide_verifies() {
    let _ = WIDE_VERIFIES.try_with(|c| c.set(0));
}

thread_local! {
    /// Short reads an ENCRYPTED stored member's wide read made on this
    /// thread to finish a cipher block a fragment left part way, since the
    /// last [`reset_wide_block_joins`] (SPEC-K 3.7.4 says a
    /// fragment need not be whole blocks). Per thread for the reason
    /// [`WIDE_VERIFIES`] is: `tests/encrypted_stored_wide.rs` asserts its
    /// volume sets really cross a block inside a fragment boundary.
    pub(super) static WIDE_BLOCK_JOINS: Cell<u64> = const { Cell::new(0) };
}

/// Count one block finished across a fragment boundary.
#[cfg(feature = "parallel")]
pub(crate) fn note_wide_block_join() {
    let _ = WIDE_BLOCK_JOINS.try_with(|c| c.set(c.get() + 1));
}

/// How many blocks this thread has finished across a fragment boundary
/// since the last reset.
pub fn wide_block_joins() -> u64 {
    WIDE_BLOCK_JOINS.try_with(Cell::get).unwrap_or(0)
}

/// Start counting those again from zero on this thread.
pub fn reset_wide_block_joins() {
    let _ = WIDE_BLOCK_JOINS.try_with(|c| c.set(0));
}

/// The fewest lanes at which a pool worker reads an encrypted stored
/// member wide (`concurrent::job_wide`), plus one: 0 is the shipped answer
/// (`RARKIT_JOB_WIDE`, or its default), 1 is never, and `n + 1` is `n`
/// lanes. ONE word for the process and not one a thread, because the
/// WORKER asks, on a thread the test never sees; a test that sets it holds
/// a lock of its own around the read.
pub(super) static JOB_WIDE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Force the fewest lanes a pool worker's wide read is taken at, for the
/// process: `Some(0)` for never, `Some(1)` for always, or `None` for the
/// default.
pub fn set_job_wide(lanes: Option<usize>) {
    let word = lanes.map_or(0, |n| n.saturating_add(1));
    JOB_WIDE.store(word, std::sync::atomic::Ordering::SeqCst);
}

/// The forced answer, if any.
#[cfg(feature = "parallel")]
pub(crate) fn job_wide() -> Option<usize> {
    JOB_WIDE
        .load(std::sync::atomic::Ordering::SeqCst)
        .checked_sub(1)
}

/// Whether a stored member written to a file by the thread that reads it
/// is cut into aligned pieces there (`read::handed::stored_cut`), and how:
/// 0 is the shipped answer (`RARKIT_STORED_CUT`, or its default), 1 is
/// never, 2 the default dial, 3 one reader in order, 4 the window's pieces
/// at once. One word for the process, as [`set_job_wide`]'s is: a pool
/// worker reads it on its own thread.
pub(super) static STORED_CUT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// How many ranges such a writer has cut, in the whole process.
pub(super) static STORED_CUTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Cut such members (`Some(true)`), leave them as before (`Some(false)`),
/// or do as the environment says (`None`); `in_order` names the reader
/// where the cut is forced on.
pub fn set_stored_cut(on: Option<bool>, in_order: Option<bool>) {
    let word = match (on, in_order) {
        (None, _) => 0,
        (Some(false), _) => 1,
        (Some(true), None) => 2,
        (Some(true), Some(true)) => 3,
        (Some(true), Some(false)) => 4,
    };
    STORED_CUT.store(word, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(feature = "parallel")]
pub(crate) fn stored_cut() -> Option<Option<crate::read::handed::Dial>> {
    use crate::read::handed::Dial;
    match STORED_CUT.load(std::sync::atomic::Ordering::SeqCst) {
        1 => Some(None),
        2 => Some(Some(Dial::default())),
        3 => Some(Some(Dial {
            piece: None,
            in_order: Some(true),
        })),
        4 => Some(Some(Dial {
            piece: None,
            in_order: Some(false),
        })),
        _ => None,
    }
}

/// Whether an AES-CBC member is cut where the cut is on
/// (`read::handed::stored_cut_cipher`): 0 is the shipped answer
/// (`RARKIT_STORED_CUT_CIPHER`, or its default), 1 off, 2 on.
pub(super) static STORED_CUT_CIPHER: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);

pub fn set_stored_cut_cipher(on: Option<bool>) {
    let word = match on {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    };
    STORED_CUT_CIPHER.store(word, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(feature = "parallel")]
pub(crate) fn stored_cut_cipher() -> Option<bool> {
    match STORED_CUT_CIPHER.load(std::sync::atomic::Ordering::SeqCst) {
        1 => Some(false),
        2 => Some(true),
        _ => None,
    }
}

/// When a pool worker cuts its member (`concurrent::stored_cut_when`): 0
/// is the shipped answer (`RARKIT_STORED_CUT_WHEN`, or its default), 1
/// whenever the lanes allow, 2 only while no other member is decoded.
pub(super) static STORED_CUT_WHEN: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);

pub fn set_stored_cut_when(mode: u8) {
    STORED_CUT_WHEN.store(mode, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(feature = "parallel")]
pub(crate) fn stored_cut_when() -> u8 {
    STORED_CUT_WHEN.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(feature = "parallel")]
pub(crate) fn note_stored_cut() {
    STORED_CUTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// How many stored ranges a writer's own thread has cut since the last
/// reset, in the whole process: what makes a test of the cut non-vacuous.
pub fn stored_cuts() -> u64 {
    STORED_CUTS.load(std::sync::atomic::Ordering::SeqCst)
}

pub fn reset_stored_cuts() {
    STORED_CUTS.store(0, std::sync::atomic::Ordering::SeqCst);
}

/// Whether a pool worker reads a clear stored member it WRITES wide
/// (`concurrent::job_wide_write`): 0 is the shipped answer
/// (`RARKIT_JOB_WIDE_WRITE`, or its default), 1 off, 2 on; one word for
/// the process, as [`set_job_wide`]'s is.
pub(super) static JOB_WIDE_WRITE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Force it on or off for the process, or `None` for the default.
pub fn set_job_wide_write(on: Option<bool>) {
    let word = match on {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    };
    JOB_WIDE_WRITE.store(word, std::sync::atomic::Ordering::SeqCst);
}

/// The forced answer, if any.
#[cfg(feature = "parallel")]
pub(crate) fn job_wide_write() -> Option<bool> {
    match JOB_WIDE_WRITE.load(std::sync::atomic::Ordering::SeqCst) {
        1 => Some(false),
        2 => Some(true),
        _ => None,
    }
}

/// When a pool worker reads a stored member it WRITES wide
/// (`concurrent::Written`): 0 is the shipped answer
/// (`RARKIT_JOB_WIDE_WRITTEN`, or its default), 1 always, 2 only beside
/// another member, 3 never; one word for the process, as
/// [`set_job_wide`]'s is.
pub(super) static JOB_WIDE_WRITTEN: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);

/// Force it for the process: 1 always, 2 beside, 3 never, 0 the default.
pub fn set_job_wide_written(mode: u8) {
    JOB_WIDE_WRITTEN.store(mode, std::sync::atomic::Ordering::SeqCst);
}

/// The forced mode, 0 for none.
#[cfg(feature = "parallel")]
pub(crate) fn job_wide_written() -> u8 {
    JOB_WIDE_WRITTEN.load(std::sync::atomic::Ordering::SeqCst)
}

/// Ranges a pool worker's reader has offered the wide read, in the whole
/// process (the worker's thread is not the test's), so a test comparing
/// the two arrangements proves the wide one ran.
pub(super) static JOB_SPANS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Count one such offer.
#[cfg(feature = "parallel")]
pub(crate) fn note_job_span() {
    JOB_SPANS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// How many the process has made.
pub fn job_spans() -> u64 {
    JOB_SPANS.load(std::sync::atomic::Ordering::Relaxed)
}

thread_local! {
    /// Whether the concurrent pool takes a split stored member as a job
    /// over its fragments (`extract::Split`), on this thread: `None` is the
    /// shipped answer (yes). Per thread because the walking thread asks.
    pub(super) static SPLIT_JOBS: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Force split jobs on or off for this thread, or `None` for the default.
pub fn set_split_jobs(on: Option<bool>) {
    let _ = SPLIT_JOBS.try_with(|c| c.set(on));
}

/// The forced answer, if any.
#[cfg(feature = "parallel")]
pub(crate) fn split_jobs() -> Option<bool> {
    SPLIT_JOBS.try_with(Cell::get).ok().flatten()
}

thread_local! {
    /// Whether EVERY split member is a split job (`Some(true)`, the knob's
    /// `all`) or only a stored clear one (`Some(false)`, its `stored`), on
    /// this thread (`extract::split_job_kind`): `None` is the shipped
    /// answer (`RARKIT_SPLIT_JOBS`, or its default). The walk and the
    /// pool's `open` both ask it on the walking thread.
    pub(super) static SPLIT_JOBS_ALL: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Force compressed and encrypted split jobs on or off for this thread, or
/// `None` for the default.
pub fn set_split_jobs_all(on: Option<bool>) {
    let _ = SPLIT_JOBS_ALL.try_with(|c| c.set(on));
}

/// The forced answer, if any.
#[cfg(feature = "parallel")]
pub(crate) fn split_jobs_all() -> Option<bool> {
    SPLIT_JOBS_ALL.try_with(Cell::get).ok().flatten()
}

thread_local! {
    /// Whether a stored member's fragments under the wide read's floor are
    /// read abreast (`read::across`), on this thread: `None` is the shipped
    /// answer (`RARKIT_FRAGMENTS_ABREAST`, or its default). Per thread
    /// because the member's own thread asks.
    pub(super) static FRAGMENTS_ABREAST: Cell<Option<u8>> = const { Cell::new(None) };
    /// Runs of fragments this thread has read abreast since the last
    /// [`reset_fragments_abreast_runs`], so a test comparing the
    /// arrangement with the read in order proves it ran.
    pub(super) static FRAGMENTS_ABREAST_RUNS: Cell<u64> = const { Cell::new(0) };
}

/// Force the fragments abreast on or off for this thread, or `None` for
/// the default: on is the form that crosses to the next volume ahead of
/// the join.
pub fn set_fragments_abreast(on: Option<bool>) {
    let _ = FRAGMENTS_ABREAST.try_with(|c| c.set(on.map(u8::from)));
}

/// Force the form that joins every piece it holds before it crosses to
/// the next volume, on this thread.
pub fn set_fragments_abreast_joined() {
    let _ = FRAGMENTS_ABREAST.try_with(|c| c.set(Some(2)));
}

/// The forced answer, if any: 0 off, 1 ahead of the join, 2 joined first.
#[cfg(feature = "parallel")]
pub(crate) fn fragments_abreast() -> Option<u8> {
    FRAGMENTS_ABREAST.try_with(Cell::get).ok().flatten()
}

thread_local! {
    /// Volumes this thread's reads abreast asked for AHEAD of their join
    /// since the last [`reset_fragments_abreast_runs`].
    pub(super) static CROSSED_AHEAD: Cell<u64> = const { Cell::new(0) };
}

/// Count one volume asked for ahead of the join.
#[cfg(feature = "parallel")]
pub(crate) fn note_crossed_ahead() {
    let _ = CROSSED_AHEAD.try_with(|c| c.set(c.get() + 1));
}

/// How many volumes this thread's reads abreast asked for ahead of their
/// join since the reset.
pub fn crossed_ahead() -> u64 {
    CROSSED_AHEAD.try_with(Cell::get).unwrap_or(0)
}

/// Count one run of fragments read abreast.
#[cfg(feature = "parallel")]
pub(crate) fn note_fragments_abreast() {
    let _ = FRAGMENTS_ABREAST_RUNS.try_with(|c| c.set(c.get() + 1));
}

/// How many runs of fragments this thread has read abreast since the reset.
pub fn fragments_abreast_runs() -> u64 {
    FRAGMENTS_ABREAST_RUNS.try_with(Cell::get).unwrap_or(0)
}

/// Start counting runs read abreast again from zero on this thread.
pub fn reset_fragments_abreast_runs() {
    let _ = CROSSED_AHEAD.try_with(|c| c.set(0));
    let _ = FRAGMENTS_ABREAST_RUNS.try_with(|c| c.set(0));
}

thread_local! {
    /// Split members this thread's walk dispatched over their
    /// fragment lists since the last [`reset_split_jobs_taken`], so a test
    /// comparing the arrangement with the walk's own read proves it ran.
    pub(super) static SPLIT_JOBS_TAKEN: Cell<u64> = const { Cell::new(0) };
}

/// Count one split member dispatched.
#[cfg(feature = "parallel")]
pub(crate) fn note_split_job() {
    let _ = SPLIT_JOBS_TAKEN.try_with(|c| c.set(c.get() + 1));
}

/// How many split members this thread has dispatched since the reset.
pub fn split_jobs_taken() -> u64 {
    SPLIT_JOBS_TAKEN.try_with(Cell::get).unwrap_or(0)
}

/// Start counting split jobs again from zero on this thread.
pub fn reset_split_jobs_taken() {
    let _ = SPLIT_JOBS_TAKEN.try_with(|c| c.set(0));
}

/// Allow the operations this thread runs `n` more scoped thread starts in
/// all, counted across every thread they start, and refuse the rest as a
/// host out of threads would; `None` lifts it (`crate::threads`). What a
/// refused start does is the read path's own answer to one: run narrower,
/// or run the work on the thread that asked.
#[cfg(feature = "test-support")]
pub fn allow_spawns(n: Option<usize>) {
    crate::threads::allowance::set(n);
}

/// How many thread starts the allowance [`allow_spawns`] set on this
/// thread has refused, across every thread it reached.
#[cfg(feature = "test-support")]
pub fn spawns_refused() -> usize {
    crate::threads::allowance::refused()
}

/// How many times a member's decode ended by giving its scratch back
/// (`read::extract::decode`'s tail), anywhere in the process: a member
/// continuing a solid chain keeps it for the next instead. PROCESS-wide,
/// because a pool or look-ahead worker gives back on its own thread; a
/// test reading it runs alone in its binary.
pub(super) static SCRATCH_GIVE_BACKS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Count one scratch give-back at a member's end.
pub(crate) fn note_scratch_give_back() {
    SCRATCH_GIVE_BACKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// The scratch give-backs since [`reset_scratch_give_backs`].
pub fn scratch_give_backs() -> u64 {
    SCRATCH_GIVE_BACKS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Start counting scratch give-backs again from zero.
pub fn reset_scratch_give_backs() {
    SCRATCH_GIVE_BACKS.store(0, std::sync::atomic::Ordering::Relaxed);
}
