//! The concurrent read's dials: the breadth and x86 arms, the offload
//! floor, the spins, the queue and wait rules, the small batch and team.

use super::*;

/// Which way the concurrent driver divides `max_workers` between the
/// members it decodes at once and the tape lanes inside each of them.
///
/// A MEASURING knob, not a tuning one, and it exists because API 8.3
/// names breadth-first a STARTING DEFAULT "to be confirmed or overturned
/// by measurement per shape, not a rule". The arms it selects are the
/// four API 8.3 asks to be crossed; the engine ships whichever one
/// measured lowest wall inside the ceiling, and this stays so the table
/// of those measurements can be rebuilt rather than believed.
///
/// PROCESS-wide, for the same reason [`peak_workers`] is: the width is
/// read on the walking thread but spent on other threads entirely, and a
/// measuring run owns the process anyway.
/// UNSET is the arrangement that SHIPS, so a build with `test-support`
/// on behaves as a build without it until a harness says otherwise, and
/// the ceiling test in `tests/breadth_width.rs` pins the real default
/// rather than one it selected for itself.
// BREADTH_ARM_SPILL since the zero-lane floor: the unset value has to be
// whatever SHIPS, or a build with `test-support` on behaves differently
// from a build without it and the ceiling test in `tests/breadth_width.rs`
// pins an arrangement it selected for itself.
pub(super) static BREADTH_ARM: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(BREADTH_ARM_SPILL);

/// Arm 0: each member at the operation's whole `max_workers`.
pub const BREADTH_ARM_WHOLE: u8 = 0;

/// Arm 1: breadth first, each member at an inner width of one.
pub const BREADTH_ARM_BREADTH_FIRST: u8 = 1;

/// Arm 2: the ceiling divided by the pool's own width. What ships.
pub const BREADTH_ARM_DIVIDED: u8 = 2;

/// Arm 3: the ceiling divided by the members actually in flight.
///
/// **Measured, and it does NOT conform**: a member keeps the width it was
/// granted, so a grant made while the pool was quiet is still outstanding
/// when the pool fills. It is kept because it bounds from above what a
/// member handing lanes BACK to its neighbours could win, which is the
/// only sound way to get what this arm reaches for. See `inner_width`.
pub const BREADTH_ARM_HANDBACK: u8 = 3;

/// Arm 4: a shared RESERVATION, re-taken at every chunk boundary.
///
/// What dividing by the members in flight reaches for, made sound: a
/// member takes its fair share of what is free and gives it back when
/// its chunk's scope joins, so a grant made while the pool was quiet
/// lasts one chunk. See `read::lanes`.
pub const BREADTH_ARM_SHRINKING: u8 = 4;

/// Arm 5: the reservation with the REMAINDER of the fair share spent.
///
/// Arm 4 floors the share, so a ceiling of six over four members offers
/// every member one lane and two units to nobody, and one lane is no tape
/// decode at all (`read::lanes::MIN_USEFUL_LANES`). This hands the
/// remainder out a unit at a time, keeping the breadth and spending the
/// ceiling exactly.
pub const BREADTH_ARM_SPILL: u8 = 5;

/// Arm 6: the BREADTH narrowed until every member has a useful width.
///
/// The other of the two arrangements SPEC-API 8.3 leaves to measurement:
/// fewer members in flight, each with a width worth having, rather than
/// more members that each decode on their own thread alone. See
/// `read::lanes::useful_breadth`.
pub const BREADTH_ARM_NARROW: u8 = 6;

/// Arm 7: one member at a time, at the whole width.
///
/// Narrowing taken to its end, and the upper bound on what spending the
/// ceiling entirely on WIDTH can buy. 8.3's "breadth first" prior says
/// this should lose; the prior is a starting default and this is what
/// measures it.
pub const BREADTH_ARM_IN_TURN: u8 = 7;

/// Arm 8: the breadth narrowed LATE, once the walk has offered more
/// than [`narrow_after`] members.
///
/// The arm that exists because arms 5 and 6 each win half the table and
/// the engine cannot tell the halves apart when it sizes the pool.
/// Narrowing was measured at up to 1.279x on an
/// eight member shape and at 0.929x on a four member one, and the
/// member count is not known until the walk has run. This narrows only
/// after the walk has proved there are members enough to fill a
/// narrowed breadth, which is a thing the pool CAN see, one member at a
/// time, as it dispatches them.
///
/// A family rather than a rule: [`set_narrow_after`] is the threshold,
/// zero reproduces [`BREADTH_ARM_NARROW`] and `usize::MAX`
/// [`BREADTH_ARM_SPILL`], so the two arms this has to beat are the two
/// ends of its own sweep and the sweep picks the threshold.
pub const BREADTH_ARM_LATE_NARROW: u8 = 8;

/// How many members the walk must have offered before arm 8 narrows.
///
/// PROCESS-wide, for the same reason `BREADTH_ARM` is. A harness
/// sweeping the family sets it per process, which is how it is meant to
/// be reached; the constant below is only what an unset arm 8 would do
/// and is NOT a measured figure, because arm 8 does not ship.
pub(super) static NARROW_AFTER: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(NARROW_AFTER_DEFAULT);

/// The threshold arm 8 uses when a harness sets none.
///
/// **Not a measured figure and not a default that ships.** Arm 8 is
/// only reachable from a `test-support` build, and what ships narrows
/// at no threshold at all (`read::concurrent`'s `narrow_after`). This
/// exists so that a harness which selects the arm and forgets the
/// threshold gets a defined arrangement rather than an accidental one,
/// and so the tests have something to put the knob back to.
pub const NARROW_AFTER_DEFAULT: usize = 4;

/// Measure arm 8 with this threshold.
pub fn set_narrow_after(members: usize) {
    NARROW_AFTER.store(members, std::sync::atomic::Ordering::Relaxed);
}

/// The threshold in force, for the pool to read as it dispatches.
#[cfg(feature = "parallel")]
pub(crate) fn narrow_after() -> usize {
    NARROW_AFTER.load(std::sync::atomic::Ordering::Relaxed)
}

/// Which x86 address pass the filter apply paths run.
///
/// UNSET is [`X86_ARM_ADAPTIVE`], which is what SHIPS, so a build with
/// `test-support` on behaves as a build without it until a harness says
/// otherwise.
///
/// It exists because the two passes differ by 17 percent over real filter
/// blocks and by 1.51x the other way over the suite's own generated ones
/// (22 Sep 2026), and a difference that size has
/// to be measured against a control that is not a second BUILD. Code
/// layout alone moves an untouched leg by about 7 percent, so two binaries
/// differing anywhere cannot settle a difference smaller than that however
/// tight their intervals; an arm switch inside ONE binary has no layout
/// difference at all.
///
/// **The unset value is [`X86_ARM_ADAPTIVE`] because arm 0 is not a
/// sentinel.** This initialised to [`X86_ARM_WALKING`] until 22 Sep 2026,
/// which made the paragraph above false: `x86_apply` MATCHES arm 0 and
/// returns the walking body, so a `test-support` build with no harness
/// behind it ran walking rather than what ships. `Cargo.toml` makes
/// rarkit its own dev dependency with `test-support` on, so that was
/// every integration test of a RAR 5 type 1 or type 2 filter, and the
/// shipped adaptive body had no default coverage at all.
/// **The unset value is [`X86_ARM_ADAPTIVE`] because arm 0 is not a
/// sentinel.** It initialised to [`X86_ARM_WALKING`] until 22 Sep 2026,
/// which made the paragraph above false: `x86_apply` MATCHES arm 0 and
/// returns the walking body, so a `test-support` build with no harness
/// behind it ran walking rather than what ships. `Cargo.toml` makes
/// rarkit its own dev dependency with `test-support`, so that was every
/// integration test of a RAR 5 type 1 or type 2 filter, and the shipped
/// adaptive had no default coverage at all.
///
/// **It was HELD at walking for one landing and is restored here.**
/// Correcting it turned `tests/solid_chain_head_refusal.rs` red, the
/// lookahead asking the source for 1,352,623 bytes more than the walk on
/// a 3,000 member chain, bisected to this one line and to the adaptive
/// arm alone. The cause was a timing dependence in the decode-ahead
/// cursor rather than a wrong lever, and the table-carry landing removes
/// it. Both halves were measured on 22 Sep 2026.
pub(super) static X86_ARM: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(X86_ARM_ADAPTIVE);

/// Ask for the next trigger, convert it, resume five bytes on. Ships.
pub const X86_ARM_WALKING: u8 = 0;

/// Scan a window of triggers, then convert them. Shipped 21 to 22 Sep
/// 2026; see `carry::h_ours::codec::address_filters::x86_pass`.
pub const X86_ARM_SPLIT: u8 = 1;

/// Choose per block, on the density the split's own first scan measures.
/// Ships from 22 Sep 2026; see
/// `carry::h_ours::codec::address_filters::x86_pass_adaptive`.
pub const X86_ARM_ADAPTIVE: u8 = 2;

/// Measure the filter apply paths with this x86 pass.
pub fn set_x86_arm(arm: u8) {
    X86_ARM.store(arm, std::sync::atomic::Ordering::Relaxed);
}

/// The pass in force, for the apply paths to read per block.
pub(crate) fn x86_arm() -> u8 {
    X86_ARM.load(std::sync::atomic::Ordering::Relaxed)
}

/// Measure the concurrent driver with this division of the ceiling.
pub fn set_breadth_arm(arm: u8) {
    BREADTH_ARM.store(arm, std::sync::atomic::Ordering::Relaxed);
}

/// The division in force, for the driver to read at dispatch.
#[cfg(feature = "parallel")]
pub(crate) fn breadth_arm() -> u8 {
    BREADTH_ARM.load(std::sync::atomic::Ordering::Relaxed)
}

thread_local! {
    /// The offload floor this thread's next extraction should use, in
    /// place of `read::extract::OFFLOAD_FLOOR`.
    ///
    /// Per THREAD for the same reason `DECODED` is: a test binary runs its
    /// tests concurrently in one process, and the floor is read on the
    /// WALKING thread - which is the thread that called `extract_parallel`
    /// - so a thread-local reaches exactly the run that set it and no
    /// other test's.
    ///
    /// It exists because the production floor is chosen so that a member
    /// too small to pay for a worker is not given one, and every fixture
    /// in this repository is far below it. A test that wants the
    /// concurrent path driven over small members sets the floor to zero;
    /// a test that wants the floor ITSELF asserted leaves it alone and
    /// reads [`decoded_members`], which counts only what the walking
    /// thread decoded.
    pub(super) static OFFLOAD_FLOOR: Cell<Option<u64>> = const { Cell::new(None) };
}

/// Run this thread's next extractions with `bytes` as the offload floor,
/// or with the engine's own figure when `None`.
pub fn set_offload_floor(bytes: Option<u64>) {
    let _ = OFFLOAD_FLOOR.try_with(|c| c.set(bytes));
}

/// The floor this thread asked for, if it asked for one.
#[cfg(feature = "parallel")]
pub(crate) fn offload_floor() -> Option<u64> {
    OFFLOAD_FLOOR.try_with(Cell::get).unwrap_or(None)
}

thread_local! {
    /// How long the concurrent driver should wait for a worker WITHOUT
    /// parking, in microseconds, in place of `read::concurrent::
    /// SETTLE_SPIN_US`.
    ///
    /// Per thread for the reason [`OFFLOAD_FLOOR`] is: it is read on the
    /// WALKING thread, which is the thread that called `extract_parallel`.
    ///
    /// It exists so the figure that ships is the one a table picked. The
    /// spin buys WALL with CPU that would otherwise be idle, which is what
    /// SPEC-API 8.3 asks for and is also the way a figure like
    /// this goes wrong, so the gate bench sweeps it.
    pub(super) static SETTLE_SPIN: Cell<Option<u64>> = const { Cell::new(None) };
}

/// Run this thread's next extractions with `micros` as the no-park wait,
/// or with the engine's own figure when `None`.
pub fn set_settle_spin(micros: Option<u64>) {
    let _ = SETTLE_SPIN.try_with(|c| c.set(micros));
}

/// The wait this thread asked for, if it asked for one.
#[cfg(feature = "parallel")]
pub(crate) fn settle_spin() -> Option<u64> {
    SETTLE_SPIN.try_with(Cell::get).unwrap_or(None)
}

thread_local! {
    /// The no-park wait a WORKER is to sweep its task channel for, when a
    /// bench asks for one rather than the engine's own figure.
    ///
    /// Per thread like [`SETTLE_SPIN`], and for the same reason: it is
    /// read on the WALKING thread, which is where `extract_parallel` was
    /// called and where the pool spawns its workers. The figure is read
    /// once per worker, at the spawn, and travels into that worker rather
    /// than being looked up on it: a thread-local set by the caller is not
    /// visible on a thread the caller starts, and an atomic read on the
    /// dispatch path would be a cost this is trying to remove.
    pub(super) static TASK_SPIN: Cell<Option<u64>> = const { Cell::new(None) };
}

/// Spawn this thread's next pool's workers with `micros` as the no-park
/// wait on their task channel, or with the engine's own figure when
/// `None`.
pub fn set_task_spin(micros: Option<u64>) {
    let _ = TASK_SPIN.try_with(|c| c.set(micros));
}

/// The worker wait this thread asked for, if it asked for one.
#[cfg(feature = "parallel")]
pub(crate) fn task_spin() -> Option<u64> {
    TASK_SPIN.try_with(Cell::get).unwrap_or(None)
}

thread_local! {
    /// The outputs a pool may hold open, as a multiple of its breadth,
    /// when a TEST asks for one rather than the process's own setting.
    ///
    /// The shipped knob is the environment variable the pool reads once
    /// per process (`read::concurrent::outputs_over_breadth`); a test
    /// cannot use it, because every test in a binary shares one process.
    /// Per thread, read on the walking thread, like [`SETTLE_SPIN`].
    pub(super) static OUTPUTS_OVER_BREADTH: Cell<Option<usize>> = const { Cell::new(None) };
}

/// Run this thread's next extractions with at most `factor` times the
/// breadth of outputs open, or with the process's own setting when
/// `None`. Two is the default; one is the tighter pool.
pub fn set_outputs_over_breadth(factor: Option<usize>) {
    let _ = OUTPUTS_OVER_BREADTH.try_with(|c| c.set(factor));
}

/// The factor this thread asked for, if it asked for one.
#[cfg(feature = "parallel")]
pub(crate) fn outputs_over_breadth() -> Option<usize> {
    OUTPUTS_OVER_BREADTH.try_with(Cell::get).unwrap_or(None)
}

thread_local! {
    /// Whether the concurrent pool queues a member the walk handled for
    /// its turn to close (`read::concurrent::QUEUE_OWN_ENV`), when a TEST
    /// asks rather than the process's environment. Per thread, read on
    /// the walking thread, like [`OUTPUTS_OVER_BREADTH`].
    pub(super) static QUEUE_OWN: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Run this thread's next extractions with the walk's own members queued
/// for their turn to close (`Some(true)`), with the flight closed first
/// at each of them (`Some(false)`), or as the process's environment says
/// (`None`).
pub fn set_queue_own(on: Option<bool>) {
    let _ = QUEUE_OWN.try_with(|c| c.set(on));
}

/// The queueing this thread asked for, if it asked.
#[cfg(feature = "parallel")]
pub(crate) fn queue_own() -> Option<bool> {
    QUEUE_OWN.try_with(Cell::get).unwrap_or(None)
}

thread_local! {
    /// Whether the concurrent pool's wait for a worker ends at whichever
    /// answers first (`read::concurrent::WAIT_ANY_ENV`), when a TEST asks.
    /// Per thread, read on the walking thread.
    pub(super) static WAIT_ANY: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Run this thread's next extractions with the walk's wait for a worker
/// ended by any worker's answer (`Some(true)`), parked on the oldest
/// member (`Some(false)`), or as the process's environment says (`None`).
pub fn set_wait_any(on: Option<bool>) {
    let _ = WAIT_ANY.try_with(|c| c.set(on));
}

/// The wait this thread asked for, if it asked.
#[cfg(feature = "parallel")]
pub(crate) fn wait_any() -> Option<bool> {
    WAIT_ANY.try_with(Cell::get).unwrap_or(None)
}

thread_local! {
    /// The concurrent driver's small member batches, when a TEST asks
    /// rather than the process's `RARKIT_SMALL_BATCH`: `(members, cap in
    /// bytes)`, members 0 is off. Per thread for the reason
    /// [`OUTPUTS_OVER_BREADTH`] is.
    pub(super) static SMALL_BATCH: Cell<Option<(usize, u64)>> = const { Cell::new(None) };
}

/// Run this thread's next extractions with small compressed members handed
/// to workers `members` at a time and at most `cap` declared bytes a
/// batch, `Some((0, 0))` for none, or the process's setting when `None`.
pub fn set_small_batch(batch: Option<(usize, u64)>) {
    let _ = SMALL_BATCH.try_with(|c| c.set(batch));
}

/// The batch this thread asked for, if it asked for one.
#[cfg(feature = "parallel")]
pub(crate) fn small_batch() -> Option<(usize, u64)> {
    SMALL_BATCH.try_with(Cell::get).unwrap_or(None)
}

thread_local! {
    /// The member team's width cap when a TEST asks, in place of
    /// `RARKIT_SMALL_TEAM`; `Some(0)` is uncapped.
    pub(super) static SMALL_TEAM: Cell<Option<usize>> = const { Cell::new(None) };
}

/// Run this thread's next extractions with at most `team` workers holding
/// members below the offload floor (`Some(0)` uncapped), or the process's
/// setting when `None`.
pub fn set_small_team(team: Option<usize>) {
    let _ = SMALL_TEAM.try_with(|c| c.set(team));
}

/// The team width this thread asked for, if it asked for one.
#[cfg(feature = "parallel")]
pub(crate) fn small_team() -> Option<usize> {
    SMALL_TEAM.try_with(Cell::get).unwrap_or(None)
}

/// The most members and declared bytes any one small member batch has
/// held since [`reset_peak_batch`]. PROCESS-wide, as [`peak_members`] is.
pub(super) static BATCH_MEMBERS_PEAK: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub(super) static BATCH_BYTES_PEAK: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(super) static BATCHES_SENT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// A batch of `members` members declaring `bytes` bytes was sent.
#[cfg(feature = "parallel")]
pub(crate) fn note_batch(members: usize, bytes: u64) {
    use std::sync::atomic::Ordering;
    BATCH_MEMBERS_PEAK.fetch_max(members, Ordering::Relaxed);
    BATCH_BYTES_PEAK.fetch_max(bytes, Ordering::Relaxed);
    BATCHES_SENT.fetch_add(1, Ordering::Relaxed);
}

/// `(most members, most declared bytes, batches sent)` since
/// [`reset_peak_batch`].
pub fn peak_batch() -> (usize, u64, usize) {
    use std::sync::atomic::Ordering;
    (
        BATCH_MEMBERS_PEAK.load(Ordering::Relaxed),
        BATCH_BYTES_PEAK.load(Ordering::Relaxed),
        BATCHES_SENT.load(Ordering::Relaxed),
    )
}

/// Forget the batch high-water marks.
pub fn reset_peak_batch() {
    use std::sync::atomic::Ordering;
    BATCH_MEMBERS_PEAK.store(0, Ordering::Relaxed);
    BATCH_BYTES_PEAK.store(0, Ordering::Relaxed);
    BATCHES_SENT.store(0, Ordering::Relaxed);
}

/// The physical cores this process may run on, as the engine counts them
/// (`cores::physical`: SMT siblings once, never above the hardware
/// threads, at least one). For a test whose expectation is a DEFAULT the
/// engine sizes from this count, so the test can say which machine it is
/// on instead of assuming one: the small batches' default is off below
/// two cores, and a hosted runner of two hardware threads may be one core.
pub fn physical_cores() -> usize {
    crate::cores::physical()
}
