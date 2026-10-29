//! The pool's dials: each default, the environment name a bench build
//! reads it by, and the rule it feeds.

use super::*;

/// Whether the shared reservation is the arrangement in force.
///
/// The reservation (`read::lanes`) is what ships; the division at
/// dispatch is kept reachable so the breadth driver script can price the
/// two against each other in one binary, which is how 8.3's "confirmed or
/// overturned by measurement per shape" is answered rather than asserted.
#[cfg(feature = "breadth-knob")]
pub(crate) fn shrinking() -> bool {
    matches!(
        crate::probe::breadth_arm(),
        crate::probe::BREADTH_ARM_SHRINKING
            | crate::probe::BREADTH_ARM_SPILL
            | crate::probe::BREADTH_ARM_NARROW
            | crate::probe::BREADTH_ARM_IN_TURN
            | crate::probe::BREADTH_ARM_LATE_NARROW
    )
}

#[cfg(not(feature = "breadth-knob"))]
pub(crate) fn shrinking() -> bool {
    true
}

/// Whether the REMAINDER of the fair share is spendable (`read::lanes`).
///
/// The arrangement that ships, since the zero-lane floor: a floored
/// share at a ceiling of six over four members offers each member one
/// lane and two units to nobody, and one lane is no tape decode at all.
#[cfg(feature = "breadth-knob")]
pub(crate) fn spilling() -> bool {
    !matches!(
        crate::probe::breadth_arm(),
        crate::probe::BREADTH_ARM_SHRINKING
    )
}

// TRUE, and the reason is a COUNT rather than a wall. SPEC-API 8.3 makes
// every default a measured one and wall decides it, so this
// line needs figures; what decides it is that the floored share leaves
// the ceiling UNSPENT, which is not a timing question. Measured on four
// 24 MiB members at a width of six: the floored share puts zero lanes in
// the air and hands two of the six units to nobody, and spending them is
// a provable no-op wherever the share divides exactly (see
// `read::lanes`'s `spilling_is_a_no_op_when_the_ceiling_divides`). The
// wall figures were measured beside it.
#[cfg(not(feature = "breadth-knob"))]
pub(crate) fn spilling() -> bool {
    true
}

/// The breadth this arrangement puts in flight, given the read's width.
///
/// **The narrowing arms only.** SPEC-API 8.3 makes the breadth and the
/// width one product against one ceiling, and leaves how the product is
/// spent to measurement (the lowest wall inside the memory
/// budget wins). When the ceiling divided by the breadth falls under
/// `read::lanes::MIN_USEFUL_LANES` there are two answers, and these are
/// the arms that take the second: narrow the breadth so that every member
/// in flight has a width worth having. The arm that ships keeps the
/// breadth and spends the remainder instead, which is `spilling` above.
#[cfg(feature = "breadth-knob")]
pub(crate) fn arranged_breadth(ceiling: usize, asked: usize) -> usize {
    match crate::probe::breadth_arm() {
        crate::probe::BREADTH_ARM_NARROW => crate::read::lanes::useful_breadth(ceiling, asked),
        crate::probe::BREADTH_ARM_IN_TURN => 1,
        _ => asked,
    }
}

#[cfg(not(feature = "breadth-knob"))]
pub(crate) fn arranged_breadth(_ceiling: usize, asked: usize) -> usize {
    asked
}

/// After how many dispatched members the breadth NARROWS, if it does.
///
/// **This is the question `arranged_breadth` above cannot answer, and
/// the reason it cannot is arithmetic rather than laziness.** SPEC-API
/// 8.3 makes the breadth and the width one product against one ceiling
/// and leaves the split to measurement; the split that measured best is
/// not the same one on every archive.
/// Measurement put narrowing at 1.279x on eight
/// members and 0.929x on four, both reproduced, and the pool is sized in
/// `extract_parallel_with` BEFORE the walk has read a single header, so
/// at that moment it does not know which archive it has.
///
/// What it does know, one member at a time, is how many the walk has
/// offered it so far. So the narrowing is deferred until the walk has
/// proved there are more than `narrow_after` members, which is the only
/// form of the rule the engine is in a position to apply. `None` is the
/// arrangement that does not narrow at all.
#[cfg(feature = "breadth-knob")]
pub(super) fn narrow_after() -> Option<usize> {
    match crate::probe::breadth_arm() {
        crate::probe::BREADTH_ARM_LATE_NARROW => Some(crate::probe::narrow_after()),
        _ => None,
    }
}

// NONE, and it is to be measured rather than argued. The threshold family
// was swept; until a threshold
// beats the shipped arrangement on every cell of a de-confounded grid,
// what ships is the arrangement that does not narrow.
#[cfg(not(feature = "breadth-knob"))]
pub(super) fn narrow_after() -> Option<usize> {
    None
}

/// THE KNOB:
/// `RARKIT_QUEUE_OWN=1` QUEUES a member the walk handled itself for its
/// turn to close instead of closing the whole flight first; `0`, unset or
/// unreadable keeps the flight drained at every such member, which is the
/// pool before this lever ([`Pool::close`], [`Pool::skipped`]).
///
/// **What it removes, counted.** A member the walk decodes itself (a
/// stored member below its floor, an empty one, a link) and a member the
/// sink skipped (a directory entry) used to be closed only after every
/// member in flight had been waited for and closed, so that `close` stays
/// in archive order. On the gate's 4 GiB binary set (21,618 entries, 41
/// members holding half the bytes) the walk spent 58 percent of `t`
/// inside that wait, 4,207 times, and no big member was in flight for 57
/// percent of the run; the 41 largest members alone, with their 74
/// directory entries, ran one at a time, and the same 41 with none ran
/// seven abreast (measured 1 Oct 2026).
///
/// **What does not move.** The order of `close` is still the queue's: the
/// walk's member is pushed where a dispatched one would be and closed
/// when it reaches the front. The first deferred error is still the first
/// in archive order, for the same reason. An EMPTY flight closes at once,
/// as before, so an archive nothing is dispatched from never queues.
pub(crate) const QUEUE_OWN_ENV: &str = "RARKIT_QUEUE_OWN";

/// Whether [`QUEUE_OWN_ENV`] is on when the variable says nothing: ON,
/// timed (1 Oct 2026: `t` of the
/// gate's binary set 4.82x on 64 cores and 2.62x at `-mt8`, K=5, with the
/// wait below; no row under its null).
pub(super) const QUEUE_OWN: bool = true;

pub(super) fn queue_own_env() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        match crate::knob::reader_var(QUEUE_OWN_ENV)
            .ok()
            .as_deref()
            .map(str::trim)
        {
            Some("1") => true,
            Some("0") => false,
            _ => QUEUE_OWN,
        }
    })
}

/// The knob for a pool opened on this thread: a test's, or the process's.
#[cfg(feature = "test-support")]
pub(super) fn queue_own() -> bool {
    crate::probe::queue_own().unwrap_or_else(queue_own_env)
}

#[cfg(not(feature = "test-support"))]
pub(super) fn queue_own() -> bool {
    queue_own_env()
}

/// THE SECOND KNOB of the same claim: `RARKIT_WAIT_ANY=1` makes the walk's
/// wait for a free worker end at WHICHEVER worker answers first; `0`,
/// unset or unreadable keeps the wait parked on the oldest member still
/// decoding, which is the pool before this lever
/// ([`Pool::wait_for_a_worker`]).
///
/// **What it removes, counted.** Once its sweep is spent the walk parked
/// on one worker's answer channel, the oldest member's. With a large
/// member at the head of the flight and small ones behind it, the walk
/// then slept until the LARGE one finished while the workers that had
/// answered sat idle: with the queue on, at a width of 8 on the gate's
/// binary set, the walk spent 96 percent of `t` in that wait with five of
/// the eight workers holding no task. Under this knob every worker
/// unparks the walking thread after each answer, and the walk parks on
/// nothing in particular: it harvests, and sleeps again only if no worker
/// came free.
pub(crate) const WAIT_ANY_ENV: &str = "RARKIT_WAIT_ANY";

/// Whether [`WAIT_ANY_ENV`] is on when the variable says nothing: ON,
/// timed with the queue (the same results file): alone it reads level,
/// and the queue alone leaves `-mt8` at 1.47x where the two read 2.62x.
pub(super) const WAIT_ANY: bool = true;

pub(super) fn wait_any_env() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        match crate::knob::reader_var(WAIT_ANY_ENV)
            .ok()
            .as_deref()
            .map(str::trim)
        {
            Some("1") => true,
            Some("0") => false,
            _ => WAIT_ANY,
        }
    })
}

/// THE THIRD KNOB of the same claim: `RARKIT_CLOSE_READY=0` keeps a
/// finished member waiting in the queue until the outputs bound is full;
/// `1`, unset or unreadable closes, at every member the walk offers,
/// whatever at the FRONT of the queue needs no wait
/// ([`Pool::close_ready`]). It acts only where the caller stated an
/// allowance of waiting writers (`ReadOptions::waiting_outputs`): with
/// none the bound of twice the breadth fills at once and the front is
/// closed by that.
///
/// **What it removes, counted.** The allowance lets finished writers wait
/// behind a large member still decoding, which is what it is for. With NO
/// large member in flight nothing needs to wait, and yet nothing closed
/// until the bound and the allowance together were full: on 16 threads
/// `x` of 20,000 small members held hundreds of finished files open and
/// read 0.209 s, against 0.179 s with no allowance at all and 0.206 s for
/// the pool before the queue
/// (measured 1 Oct 2026).
/// Closing the ready front costs no wait: where a large member IS at the
/// front it closes nothing and the walk runs on, as before.
pub(crate) const CLOSE_READY_ENV: &str = "RARKIT_CLOSE_READY";

pub(super) fn close_ready_env() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            crate::knob::reader_var(CLOSE_READY_ENV)
                .ok()
                .as_deref()
                .map(str::trim),
            Some("0")
        )
    })
}

/// The knob for a pool opened on this thread: a test's, or the process's.
#[cfg(feature = "test-support")]
pub(super) fn wait_any() -> bool {
    crate::probe::wait_any().unwrap_or_else(wait_any_env)
}

#[cfg(not(feature = "test-support"))]
pub(super) fn wait_any() -> bool {
    wait_any_env()
}

/// The most members a pool that queues ([`QUEUE_OWN_ENV`]) keeps waiting
/// to close, whatever they hold: a queued member is its header's fields
/// and its name, a few hundred bytes, so this bounds what a long run of
/// small members behind one slow one can cost. `RARKIT_QUEUE_OWN_CAP`
/// replaces it for a count.
pub(super) const QUEUE_OWN_CAP: usize = 16 * 1024;

pub(super) fn queue_own_cap() -> usize {
    static CAP: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CAP.get_or_init(|| {
        crate::knob::reader_var("RARKIT_QUEUE_OWN_CAP")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(QUEUE_OWN_CAP)
    })
}

/// What a member that takes the TAPE decode is charged at admission for
/// EACH LANE it can expect, beside its window, under a NAMED budget with
/// the queue on ([`QUEUE_OWN_ENV`]); `RARKIT_TAPE_RESERVE_KIB` replaces it
/// for a count.
///
/// `extract::window_of` declares a member's ring, its packed buffer and
/// its read window. A member of 16 MiB and up also holds its lanes' tapes
/// (`rar5_lz::tape`), which nothing declares: the pool's live arm sees
/// them only once they exist, which is after the member was admitted. With
/// the flight drained at every member the walk handled, large members
/// were seldom in flight together and the tapes of one sat inside the
/// process headroom. With the queue on, several are admitted in a burst
/// and their tapes arrive together: `t` of the gate's binary set under
/// `-mm512m` on 64 threads peaked at up to 528 MiB resident where the control's
/// pool peaked at 377 (and at 493 on a shape that fills it). The lanes a member can expect are its fair share
/// of the width beside the members decoding when it is admitted
/// (`read::lanes`), at most the tape's own ceiling.
///
/// **One MiB a lane, COUNTED** (a Graviton rental, 64 threads, twelve runs an
/// arm, 1 Oct 2026): under `-mm512m` the gate's binary set
/// then peaked at 499 MiB at most where it reached 516 without, and the
/// shapes that fill the control's own pool read no slower than the control (160 flat
/// members of 3 to 48 MiB 0.48 s against 0.51). Two MiB a lane bought no
/// lower peak and cost that shape 0.58 s.
pub(super) const TAPE_RESERVE_PER_LANE: u64 = 1 << 20;

pub(super) fn tape_reserve_per_lane() -> u64 {
    static BYTES: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *BYTES.get_or_init(|| {
        crate::knob::reader_var("RARKIT_TAPE_RESERVE_KIB")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map_or(TAPE_RESERVE_PER_LANE, |kib| kib << 10)
    })
}

/// A worker's own read window over the volume it is decoding from.
///
/// 64 KiB rather than the walk's 4 KiB (`read::cursor::MIN_READ`): the walk
/// reads HEADERS through its window and wants it small, and a worker reads
/// one member's packed bytes end to end and wants the syscall count down.
pub(super) const READ_BUF: usize = extract::WORKER_READ_BUF;

/// How long the walk waits for a worker WITHOUT parking, in microseconds.
///
/// **MEASURED, and it buys wall with CPU that would otherwise be idle,
/// which is what SPEC-API 8.3 asks of every default here.** With
/// members of tens of kilobytes the walk reaches the next header in a
/// microsecond or two and then has nothing to do but wait for a worker,
/// and a worker finishes every `decode / breadth` - about ten
/// microseconds on the source tree leg at breadth eight. Parking for ten
/// microseconds does not pay: a park and the unpark that ends it are a
/// pair of kernel round trips, and they cost several times the
/// wait itself. The walk therefore sweeps the workers for an answer for
/// about as long as parking would have cost, and parks only if none comes.
///
/// It is a CEILING on the spin and not a duration: the sweep returns the
/// instant any worker answers, so a pool that is genuinely busy for
/// milliseconds - the eight 16 MiB members of `f/extract-par-8x16-m3` -
/// spins for its budget out of 20 ms and parks, which is nothing. The
/// cost is paid only where the wait is short, which is exactly where it
/// is worth paying.
///
/// **100 us is SWEPT, on an Apple M3 Mac, 32 cores.**
/// Over the 4,017 member source tree at the shipped floor the
/// leg reads 61.8 ms at a spin of 0, 61.1 at 25, 60.5 at 50, **59.9 at
/// 100** and 60.3 at 200: the lowest wall is at 100 and 200 has begun to
/// give it back. It buys that wall with CPU that would otherwise be
/// idle, 0.386 s per run at a spin of 0 against 0.425 s at 100, which is
/// the trade SPEC-API 8.3 asks for,
/// wall first.
/// `f/extract-par-8x16-m3-vsconc`, whose members are 16 MiB, reads 8.8 ms
/// at a spin of 0, 50 and 200 alike: the ceiling costs a long member
/// nothing, which is what makes it safe to set for the short ones.
pub(super) const SETTLE_SPIN_US: u64 = 100;

/// The spin in force on this thread: the engine's, or a bench's.
#[cfg(feature = "offload-knob")]
pub(crate) fn settle_spin_us() -> u64 {
    crate::probe::settle_spin().unwrap_or(SETTLE_SPIN_US)
}

#[cfg(not(feature = "offload-knob"))]
pub(crate) fn settle_spin_us() -> u64 {
    SETTLE_SPIN_US
}

/// How long a WORKER sweeps its task channel before parking, in
/// microseconds.
///
/// The other end of [`SETTLE_SPIN_US`], and the argument is the same one
/// read from the worker's side. The walk sweeps for an answer rather than
/// parking because a worker on an archive of small members answers within
/// a few microseconds and a park plus the unpark that ends it costs
/// several times that. A worker waiting for its NEXT member is in exactly
/// that position: the walk reaches the next header in a microsecond or
/// two, and on a corpus of tens-of-kilobyte members it dispatches one
/// every few microseconds, so a worker that parks between two members
/// pays a pair of kernel round trips to sleep for less time than the
/// round trips cost.
///
/// **It is charged to the WALKING thread, which is why it is worth
/// removing.** A `sync_channel` send to a receiver that has parked has to
/// wake it; a send to one that is sweeping its own channel finds no
/// sleeper to wake and is a store. The walk makes one such send per
/// dispatched member, in archive order, on the one thread every member
/// passes through.
///
/// **MEASURED, on an Apple M3 Mac, 32 cores**:
/// a `sync_channel(1)` round trip with the receiver parked against the
/// same round trip with the receiver sweeping, 20,000 trips a cell, with
/// 15 us of the sender's own work between trips so the receiver is
/// genuinely asleep. The SEND alone, which is the walk's share, reads
/// 2.75 us parked against 0.25 us at a sweep of 100 us, and the whole
/// round trip 23.3 us against 7.9.
///
/// **100 us is SWEPT, on an Apple M3 Mac, 32 cores.**
/// One binary against itself across this constant, 9
/// pairs a cell, on `f/extract-par-src4k-m3`: a sweep of 25 us reads
/// 1.035x against no sweep at all, 100 us reads 1.075x and 200 us
/// 1.078x, the last two overlapping, so 100 is where the wall stops
/// falling. The gate halves agree at 15 pairs, 0.810x before and 0.870x
/// after against the old engine, and the verify leg, which is rarkit
/// measured alone, moves the same way, 0.05918 s to 0.05508.
///
/// It buys that wall with CPU: 0.4254 s a run against 0.5005, 17.6
/// percent, at one megabyte of peak RSS. That is the trade SPEC-API
/// 8.3 asks for, wall first, and it is
/// the same trade [`SETTLE_SPIN_US`] makes on the other end of this
/// channel.
///
/// **On a SATURATED box the sweep LOSES**, and that is measured rather
/// than feared: the same dial on a 32-core box at a one-minute load of
/// 100, carrying ten other builds, read 0.59x to 0.68x, because
/// eight sweeping workers take cores the walk needs. Every figure above
/// is a quiet-box figure, which is what the gate measures. That is why
/// the sweep is bounded (`read::spin`): a waiter that finds it lost its
/// core mid-sweep makes every wait park at once for a while, so a loaded
/// box stops sweeping and a quiet one sweeps as before.
///
/// Like the settle spin it is a CEILING and not a duration: the sweep
/// returns the instant a task arrives, so a worker whose pool is idle for
/// milliseconds spins its budget once and parks. An archive that
/// dispatches nothing spawns no worker at all and pays none of it, which
/// is every stored archive under [`extract::OFFLOAD_FLOOR`], every solid
/// one, and the 20,000 member legs.
pub(super) const TASK_SPIN_US: u64 = 100;

/// The worker sweep in force for this pool: the engine's, or a bench's.
#[cfg(feature = "offload-knob")]
pub(crate) fn task_spin_us() -> u64 {
    crate::probe::task_spin().unwrap_or(TASK_SPIN_US)
}

#[cfg(not(feature = "offload-knob"))]
pub(crate) fn task_spin_us() -> u64 {
    TASK_SPIN_US
}

/// The environment variable that sets how many OUTPUTS a pool may hold
/// open, as a whole multiple of its breadth, 1 to 4.
///
/// **The default is [`OUTPUTS_OVER_BREADTH_DEFAULT`], twice the breadth
/// (22 Sep 2026).** A worker whose answer has arrived is freed
/// at once and its answer waits beside its member for that member's turn
/// to close, still in archive order: the members DECODING at once stay at
/// most the breadth, the members OPEN at once are at most `factor` times
/// it. At 1 the pool is the one that shipped before: a worker is held from
/// dispatch until its member closes, so the outputs open are at most the
/// breadth. The variable stays so that one binary can be measured against
/// itself, and so that a caller who needs the tighter bound can have it.
///
/// Why twice and not more: the small compressed members work priced the
/// flight window from its own traced member costs and found nothing more
/// bought past twice the breadth (measured
/// 22 Sep 2026).
pub(crate) const OUTPUTS_OVER_BREADTH_ENV: &str = "RARKIT_OUTPUTS_OVER_BREADTH";

/// The largest factor the knob accepts: past twice the breadth the
/// profile priced nothing more, and a bound nobody asked for is not one
/// to leave open-ended.
pub(super) const OUTPUTS_OVER_BREADTH_MAX: usize = 4;

/// The factor a pool uses when [`OUTPUTS_OVER_BREADTH_ENV`] says nothing.
pub(crate) const OUTPUTS_OVER_BREADTH_DEFAULT: usize = 2;

/// The factor in force for this process, read once.
pub(super) fn outputs_over_breadth_env() -> usize {
    static FACTOR: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *FACTOR.get_or_init(|| {
        crate::knob::reader_var(OUTPUTS_OVER_BREADTH_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(OUTPUTS_OVER_BREADTH_DEFAULT)
            .clamp(1, OUTPUTS_OVER_BREADTH_MAX)
    })
}

/// The factor for a pool opened on this thread: a test's, or the
/// process's.
#[cfg(feature = "test-support")]
pub(super) fn outputs_over_breadth() -> usize {
    crate::probe::outputs_over_breadth().map_or_else(outputs_over_breadth_env, |f| {
        f.clamp(1, OUTPUTS_OVER_BREADTH_MAX)
    })
}

#[cfg(not(feature = "test-support"))]
pub(super) fn outputs_over_breadth() -> usize {
    outputs_over_breadth_env()
}

/// Small member batches: `<members>:<cap KiB>` hands compressed members
/// below the compressed offload floor (`extract::batchable`) to workers up
/// to `members` at a time and at most `cap` KiB of declared unpacked bytes
/// a batch. `0` is OFF; unset, empty or unreadable is the default,
/// [`SMALL_BATCH_DEFAULT`], which is ON on aarch64, ON on x86-64 for `t`
/// everywhere and for `x` on Linux only, and OFF elsewhere.
///
/// A RUNTIME knob so one binary measures every arm. Members open in a
/// batch count against the outputs bound like any other.
pub(crate) const SMALL_BATCH_ENV: &str = "RARKIT_SMALL_BATCH";

/// ON, in PAIRS of at most 64 KiB declared, by the untimed screens of 26
/// Sep 2026 (an Apple M3 Mac, 32 cores, and an M5 Air, 10 cores): on the 9,681 and 20,000
/// member sets `t` read 0.33x to 0.71x of the walk-only engine's wall and
/// `x` 0.79x to 0.93x, outputs equal on every cell. Pairs matched one
/// member at a time on wall with 10 to 25 percent less CPU, and held where
/// one at a time lost at the Air's default width (`small-k t` 0.858x
/// against 1.094x). Wider batches need a larger outputs bound than the default
/// gives, and bought nothing here.
///
/// **aarch64 only.** On an 8 vCPU x86-64 EPYC VM (untimed,
/// 26 Sep 2026) the same pairs read `t` 0.76x to 0.90x of the control's wall and
/// `x` 1.24x to 1.28x: a loss on `t`, where workers descheduled under a
/// VM cost the spin waits more than they save. So every other target
/// defaults to OFF and compiles the control's admission exactly unless the knob
/// asks; a bare-metal x86 hold may turn it on there.
#[cfg(target_arch = "aarch64")]
pub(crate) const SMALL_BATCH_DEFAULT: (usize, u64) = (2, 64 * 1024);

/// x86-64: the same pairs, at the default for `t` on
/// every operating system and for `x` on Linux only
/// (`extract::batches_for`), with the member team's DEFAULT
/// width at most HALF the box's hardware threads ([`small_team_room`]).
/// On an 8 vCPU
/// x86-64 VM a team as wide as the cores cost `t` its wall (the walk and
/// eight spinning workers on eight vCPUs: 2.1x to 2.3x the control's
/// instructions, thousands of context switches and hundreds of
/// migrations), where a team of four won `t` 1.4x to 1.8x (the
/// finer x86 form).
#[cfg(target_arch = "x86_64")]
pub(crate) const SMALL_BATCH_DEFAULT: (usize, u64) = (2, 64 * 1024);

/// x86-64: whether `RARKIT_SMALL_BATCH` was set to a shape BY NAME, which
/// is what lets the batches take a written member (`x`) off Linux too;
/// the default takes written ones on Linux only (`extract::batches_for`).
#[cfg(target_arch = "x86_64")]
pub(super) fn small_batch_named_env() -> bool {
    static NAMED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *NAMED.get_or_init(|| {
        parse_small_batch(&crate::knob::reader_var(SMALL_BATCH_ENV).unwrap_or_default()).is_some()
    })
}

#[cfg(all(target_arch = "x86_64", feature = "test-support"))]
pub(super) fn small_batch_named() -> bool {
    crate::probe::small_batch().is_some() || small_batch_named_env()
}

#[cfg(all(target_arch = "x86_64", not(feature = "test-support")))]
pub(super) fn small_batch_named() -> bool {
    small_batch_named_env()
}

/// OFF on every other target: see the aarch64 figure.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(crate) const SMALL_BATCH_DEFAULT: (usize, u64) = (0, 0);

/// x86-64: whether `RARKIT_SMALL_TEAM` was set BY NAME. A team set by
/// name is not held to [`small_team_room`].
#[cfg(target_arch = "x86_64")]
pub(super) fn small_team_named_env() -> bool {
    static NAMED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *NAMED.get_or_init(|| {
        crate::knob::reader_var(SMALL_TEAM_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .is_some()
    })
}

#[cfg(all(target_arch = "x86_64", feature = "test-support"))]
pub(super) fn small_team_named() -> bool {
    crate::probe::small_team().is_some() || small_team_named_env()
}

#[cfg(all(target_arch = "x86_64", not(feature = "test-support")))]
pub(super) fn small_team_named() -> bool {
    small_team_named_env()
}

/// x86-64: the most workers the DEFAULT member team may hold, half the
/// box's hardware threads (at least one), leaving the rest to the walking
/// thread and whatever else the box runs. Sized from the THREADS and not
/// the breadth: the loss it removes is the team oversubscribing the box
/// (a team of eight and the walk on eight vCPUs), and `-mt` narrowing the
/// breadth below the threads leaves the box room (a Windows desktop, 16 threads, at
/// `-mt8`: a team of eight read faster than four). A team set by name
/// has no such room.
#[cfg(target_arch = "x86_64")]
pub(super) fn small_team_room() -> usize {
    if small_team_named() {
        return usize::MAX;
    }
    static ROOM: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *ROOM.get_or_init(|| {
        team_room_of(std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get))
    })
}

/// x86-64: the DEFAULT member team's room on a box of `threads` hardware
/// threads: half of them, at least one.
#[cfg(target_arch = "x86_64")]
pub(super) fn team_room_of(threads: usize) -> usize {
    (threads / 2).max(1)
}

/// x86-64: the member team's width from the team knob (`0` uncapped), the
/// breadth and the room ([`small_team_room`]).
#[cfg(target_arch = "x86_64")]
pub(super) fn team_width(small_team: usize, breadth: usize, room: usize) -> usize {
    match small_team {
        0 => breadth,
        n => n.min(breadth),
    }
    .min(room)
    .max(1)
}

/// The member team's width (26 Sep 2026): the workers
/// members below the offload floor may hold at once, capped at the
/// breadth; `0` is no cap of its own. Unset or unreadable is
/// [`SMALL_TEAM_DEFAULT`].
pub(crate) const SMALL_TEAM_ENV: &str = "RARKIT_SMALL_TEAM";

/// The figure: at most eight, or the decode width if lower. At the
/// default width on 32 cores the batches spent 11 to 15 CPU seconds a wall
/// second for no wall over 4 to 8 workers.
pub(super) const SMALL_TEAM_DEFAULT: usize = 8;

pub(super) fn small_team_env() -> usize {
    static TEAM: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *TEAM.get_or_init(|| {
        crate::knob::reader_var(SMALL_TEAM_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(SMALL_TEAM_DEFAULT)
    })
}

#[cfg(feature = "test-support")]
pub(super) fn small_team() -> usize {
    crate::probe::small_team().unwrap_or_else(small_team_env)
}

#[cfg(not(feature = "test-support"))]
pub(super) fn small_team() -> usize {
    small_team_env()
}

/// The most members a batch may hold whatever the knob asks: the depth of
/// a worker's answer channel, which a batch must never fill.
pub(super) const SMALL_BATCH_MAX: usize = 64;

/// One small member batch arrangement.
#[derive(Clone, Copy)]
pub(super) struct SmallBatch {
    pub(super) members: usize,
    pub(super) cap: u64,
}

pub(super) fn small_batch_of(pair: (usize, u64)) -> Option<SmallBatch> {
    let (members, cap) = pair;
    (members > 0).then(|| SmallBatch {
        members: members.min(SMALL_BATCH_MAX),
        cap: cap.max(1),
    })
}

pub(super) fn small_batch_env() -> Option<SmallBatch> {
    static BATCH: std::sync::OnceLock<Option<SmallBatch>> = std::sync::OnceLock::new();
    *BATCH.get_or_init(|| {
        let text = crate::knob::reader_var(SMALL_BATCH_ENV).unwrap_or_default();
        match parse_small_batch(&text) {
            Some(named) => small_batch_of(named),
            // THE DEFAULT NEEDS TWO DISTINCT CORES, one for the walk and one
            // for a worker: on one core's SMT pair a batch puts a sweeping
            // worker on the walk's own core, and the census read `small t`
            // 0.80x and `small x` 0.95x of batching off there, with nothing
            // else running (measured 30 Sep 2026).
            None if crate::cores::physical() < 2 => None,
            None => small_batch_of(SMALL_BATCH_DEFAULT),
        }
    })
}

/// `0` or `0:<anything>` is off, `<members>:<cap KiB>` a batch; `None`
/// for anything else, which takes the default.
pub(super) fn parse_small_batch(text: &str) -> Option<(usize, u64)> {
    let text = text.trim();
    if text == "0" {
        return Some((0, 0));
    }
    let (members, cap) = text.split_once(':')?;
    let members = members.trim().parse::<usize>().ok()?;
    let cap = cap.trim().parse::<u64>().ok()?.saturating_mul(1024);
    Some((members, cap))
}

#[cfg(feature = "test-support")]
pub(super) fn small_batch() -> Option<SmallBatch> {
    crate::probe::small_batch().map_or_else(small_batch_env, small_batch_of)
}

#[cfg(not(feature = "test-support"))]
pub(super) fn small_batch() -> Option<SmallBatch> {
    small_batch_env()
}

/// Bytes handed to a writing worker at a time. The sink sees the same byte
/// stream whatever this is; it decides how often the walking thread and the
/// writer meet.
pub(super) const CHUNK: usize = 64 * 1024;

/// Buffers in flight per piped member: one being filled, one being written.
pub(super) const DEPTH: usize = 2;

// ---------------------------------------------------------------------------
// The packed bytes a worker reads for itself
// ---------------------------------------------------------------------------

/// `RARKIT_JOB_WIDE`: `0` (or `off`) reads a dispatched stored member,
/// encrypted or clear, on its one worker, the arrangement before 1 Oct 2026; a number
/// of two or more is the fewest lanes at which it is read wide
/// ([`job_wide`]); anything else, or nothing, is [`JOB_WIDE_LANES`]. A
/// RUNTIME knob, so one binary carries every arm.
pub(crate) const JOB_WIDE_ENV: &str = "RARKIT_JOB_WIDE";

/// The fewest lanes the pool's budget must grant a dispatched stored
/// member for its worker to read it wide.
///
/// A member ALONE in the pool is granted the whole width, and one beside
/// a neighbour half of it. Where the grant is under this, the pool is
/// already spending its width on members (eight like members at once on
/// sixteen threads are granted two lanes each), every core has a member's
/// cipher on it, and splitting each member in two only adds hand-overs:
/// such a member reads on its own worker as before, a buffer at a time,
/// and asks again, so it goes wide when its neighbours finish.
pub(super) const JOB_WIDE_LANES: usize = 3;

/// The fewest lanes at which a pool worker reads a STORED member wide
/// (`read::wide`): an ENCRYPTED one, verified or written,
/// and a clear one it only verifies ([`job_wide_clear`]), as the walk's
/// own stream reads both; zero for never.
///
/// **What it is for.** `rarfast t` and `x` take an archive of two or more
/// members through this pool, where each member is one worker's, and a
/// worker's reader answered `Span::Narrow`: a stored big member under `-hp`
/// beside any second member was deciphered and hashed on ONE core, while
/// `p` of the same archive, which walks, spread it across the width.
/// The worker is now the wide read's combiner, as the walking thread is
/// there: it joins the pieces in order, judges and writes them, and
/// deciphers nothing itself.
pub(super) fn job_wide() -> usize {
    #[cfg(feature = "test-support")]
    if let Some(lanes) = crate::probe::job_wide() {
        return lanes;
    }
    static LANES: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *LANES.get_or_init(|| {
        match crate::knob::reader_var(JOB_WIDE_ENV)
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("0" | "off") => 0,
            Some(text) => match text.parse::<usize>() {
                Ok(lanes) if lanes >= 2 => lanes,
                _ => JOB_WIDE_LANES,
            },
            None => JOB_WIDE_LANES,
        }
    })
}

/// `RARKIT_JOB_WIDE_CLEAR`: `0` (or `off`) leaves a dispatched CLEAR stored
/// member that is only verified (`t`) on its one worker, the arrangement
/// before 1 Oct 2026; anything else, or nothing, reads it wide under the
/// same rule as an encrypted one ([`job_wide`]). A RUNTIME knob.
pub(crate) const JOB_WIDE_CLEAR_ENV: &str = "RARKIT_JOB_WIDE_CLEAR";

/// Whether a pool worker reads a CLEAR stored member it only verifies
/// wide: the CRC32 of independent pieces, joined in order
/// (`read::wide`), as the walk's own stream has read one since the wide
/// verify.
///
/// **The same finding as the encrypted member's, on the commonest shape
/// there is**: a stored big member beside an `.nfo` is two members, so `rarfast
/// t` took it through the pool and hashed 12 GiB on one core, 2.229 s
/// against 0.922 s for `p` of the same archive on 5.96 cores (the
/// Windows big-media work, i5-10600KF, 1 Oct 2026). A member that is
/// WRITTEN to a file keeps its one worker (`extract::wide_plan` refuses
/// it: its wall is the write, and the wide read bought it nothing).
///
/// [`RangeRead::straight_through`] records three wider forms that lost;
/// they were measured on members of 16 to 256 MiB at the pool's own
/// breadth. This one is taken only from [`JOB_WIDE_LANES`] granted lanes
/// and from `read::wide::FLOOR` bytes, which is a large member with the
/// pool's width to spare.
pub(super) fn job_wide_clear() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            crate::knob::reader_var(JOB_WIDE_CLEAR_ENV)
                .ok()
                .map(|v| v.trim().to_ascii_lowercase())
                .as_deref(),
            Some("0" | "off")
        )
    })
}

/// `RARKIT_JOB_WIDE_WRITE`: `1` (or `on`) reads a dispatched CLEAR stored
/// member that is WRITTEN to a file wide as well, its worker writing the
/// pieces in order (`extract::Member::wide_write`, as `p` to a stream has
/// always been read); `0` (or `off`) leaves it on its one worker in
/// requests of `extract::STORED_REQUEST`; anything else, or nothing, is
/// [`WIDE_WRITE`]. A RUNTIME knob, so one binary carries both arms.
pub(crate) const JOB_WIDE_WRITE_ENV: &str = "RARKIT_JOB_WIDE_WRITE";

/// Whether a pool worker reads a CLEAR stored member it WRITES wide: on
/// Windows only, each system on its own rows
/// (timed 1 Oct 2026).
///
/// **Windows** (a Windows desktop, i5-10600KF, a QLC NVMe that folds through a
/// run, INDICATIVE twice over; the tree with the write gate's depth 1
/// writer, six samples an arm): the stored big member beside its `.nfo`
/// extracted COLD in 32.17 s on its worker and 15.36 s read wide (UnRAR
/// 20.52 s: 0.64x becomes 1.34x), because the worker's 128 KiB requests
/// are what the cold drive answers slowest; WARM it is 8 percent slower
/// read wide (5.44 s against 5.00 s, UnRAR 7.94 s). A TRADE, decided for
/// the cold first read (1 Oct 2026): the warm 8 percent is
/// left for the change that hands the writer aligned pieces. **macOS** keeps the worker: there the same
/// arm read 0.930 s against 1.466 s warm but 4.176 s against 3.147 s cold
/// (M5 Ultra), and a clear archive's `x` takes the walk anyway. **Linux**
/// keeps it too: 8.812 s against 12.735 s cold for the big member but 4.522 s
/// against 4.269 s warm for a set of many members (a Zen 4 rental); both wait for the
/// change that gives a worker the aligned-pieces writer.
pub(super) const WIDE_WRITE: bool = cfg!(windows);

pub(super) fn job_wide_write() -> bool {
    #[cfg(feature = "test-support")]
    if let Some(on) = crate::probe::job_wide_write() {
        return on;
    }
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| wide_write_of(crate::knob::reader_var(JOB_WIDE_WRITE_ENV).ok().as_deref()))
}

/// [`JOB_WIDE_WRITE_ENV`]'s value as an answer.
pub(super) fn wide_write_of(value: Option<&str>) -> bool {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("1" | "on") => true,
        Some("0" | "off") => false,
        _ => WIDE_WRITE,
    }
}

/// `RARKIT_JOB_WIDE_WRITTEN`: `always`, `beside` or `never`, for a
/// dispatched stored member that is WRITTEN ([`Written`]); anything else,
/// or nothing, is [`Written::DEFAULT`]. A RUNTIME knob, so one binary
/// carries the three arms.
pub(crate) const JOB_WIDE_WRITTEN_ENV: &str = "RARKIT_JOB_WIDE_WRITTEN";

/// When a pool worker reads a stored member it WRITES wide. A member it
/// only verifies is not asked about here.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Written {
    /// Whenever the lanes allow.
    Always,
    /// Only while another member is being decoded: a member ALONE in the
    /// pool reads on its own worker, in order, as before 1 Oct 2026.
    Beside,
    /// Never: the arrangement before for every written member.
    Never,
}

impl Written {
    /// **`Beside` on macOS, `Always` on Linux and on Windows, each on its
    /// timed rows** (1 Oct 2026). The wide read hands a written
    /// member's pieces to ONE thread, its worker, to write in order.
    /// On an M5 Ultra (macOS, load 2 to 7, INDICATIVE, `x` on disk) an
    /// `-hp` member of 12.9 GB beside its `.nfo`, which is a member ALONE
    /// in the pool, extracted COLD in 3.538 s on its one worker and 4.864
    /// s read wide (7-Zip 3.486 s), and WARM in 2.938 s against 0.951 s:
    /// the wide read loses the cold row there, so it is not taken, and
    /// the warm row waits for the change that reads one deep stream for
    /// the cipher's lanes. The `-hp` SET OF EIGHT, all in flight,
    /// read 3.938 s on its workers and 2.153 s wide cold (7-Zip 2.487 s),
    /// level warm: beside other members the wide read is what keeps the
    /// workers from reading one cold file at eight offsets in 128 KiB
    /// requests. On Linux (a Zen 4 rental, a quiet box) the big member read
    /// 12.59 s on its worker and 8.61 s wide cold, the set of eight level. On Windows
    /// (a Windows desktop, a folding QLC NVMe, INDICATIVE twice over; the tree
    /// with the write gate's depth 1 writer, six samples an arm) the
    /// `-hp` big member beside its `.nfo` read 24.51 s on its worker and 15.66
    /// s wide COLD (UnRAR 20.54 s), and WARM 7.97 s against a median of
    /// 7.38 s that is BIMODAL: 5.3 to 5.9 s while the output stays
    /// direct, 8.9 to 12.8 s in the runs where the write-rate gate fell
    /// back to the cached form under the wide read's 1 MiB pieces (the
    /// worker's own worst run read 12.87 s). Decided for the cold row; the
    /// fallback waits for the change that hands the writer aligned pieces.
    #[cfg(target_os = "macos")]
    pub(super) const DEFAULT: Written = Written::Beside;
    #[cfg(not(target_os = "macos"))]
    pub(super) const DEFAULT: Written = Written::Always;
}

pub(super) fn job_wide_written() -> Written {
    #[cfg(feature = "test-support")]
    match crate::probe::job_wide_written() {
        1 => return Written::Always,
        2 => return Written::Beside,
        3 => return Written::Never,
        _ => {}
    }
    static MODE: std::sync::OnceLock<Written> = std::sync::OnceLock::new();
    *MODE.get_or_init(|| {
        written_of(
            crate::knob::reader_var(JOB_WIDE_WRITTEN_ENV)
                .ok()
                .as_deref(),
        )
    })
}

/// [`JOB_WIDE_WRITTEN_ENV`]'s value as a rule.
pub(super) fn written_of(value: Option<&str>) -> Written {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("always") => Written::Always,
        Some("beside") => Written::Beside,
        Some("never") => Written::Never,
        _ => Written::DEFAULT,
    }
}

/// `RARKIT_STORED_CUT_WHEN`: `alone` or `always`, for a stored member its
/// pool worker cuts (`read::handed::cut_here`): only while no other member
/// is being decoded, or whenever the lanes allow; anything else, or
/// nothing, is [`CUT_WHEN`]. A RUNTIME knob, so one binary carries both.
pub(crate) const STORED_CUT_WHEN_ENV: &str = "RARKIT_STORED_CUT_WHEN";

/// **`Alone` on macOS, `Always` everywhere else, each on its timed rows**
/// (1 Oct 2026). On macOS the cut reads with ONE reader in
/// order, which is what a member alone in the pool wants (an `-hp` big member
/// beside its `.nfo`, M5 Ultra, INDICATIVE: cold 3.63 s to 2.42 s, warm 2.78
/// s to 0.955 s). Eight members cut at once are eight readers in order on
/// one file, which is no one sequential stream: the `-hp` set of eight read cold
/// in 2.37 s cut against 2.17 s by the joined wide read, and the clear one
/// warm in 0.749 s against 0.635 s on its workers' own loops. So beside
/// another member a worker reads as it did before the cut.
#[cfg(target_os = "macos")]
pub(super) const CUT_WHEN: extract::CutWhen = extract::CutWhen::Alone;

#[cfg(not(target_os = "macos"))]
pub(super) const CUT_WHEN: extract::CutWhen = extract::CutWhen::Always;

pub(super) fn stored_cut_when() -> extract::CutWhen {
    #[cfg(feature = "test-support")]
    match crate::probe::stored_cut_when() {
        1 => return extract::CutWhen::Always,
        2 => return extract::CutWhen::Alone,
        _ => {}
    }
    static WHEN: std::sync::OnceLock<extract::CutWhen> = std::sync::OnceLock::new();
    *WHEN.get_or_init(|| {
        match crate::knob::reader_var(STORED_CUT_WHEN_ENV)
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("always") => extract::CutWhen::Always,
            Some("alone") => extract::CutWhen::Alone,
            _ => CUT_WHEN,
        }
    })
}

/// The fewest lanes a CLEAR stored member its worker cuts is read at: the
/// two readers of its slabs, or the one reader in order and its writer.
pub(super) const CUT_LANES: usize = 2;

/// The bytes a dispatched member reads wide under one grant of the pool's
/// lanes (`PackedRead::grant_slice`): whole cipher blocks, and long enough
/// that starting the wide read's threads again is under a hundredth of
/// the slice (a few tens of microseconds a thread against a fifth of a
/// second of deciphering), short enough that a member which began beside
/// others takes the lanes they leave within the second.
pub(super) const GRANT_SLICE: u64 = 1 << 30;

#[cfg(test)]
mod job_knob_tests {
    use super::{wide_write_of, written_of, Written, WIDE_WRITE};

    /// `RARKIT_JOB_WIDE_WRITTEN` and `RARKIT_JOB_WIDE_WRITE` keep the
    /// arrangement before on every system, whatever its default is.
    #[test]
    fn the_knobs_keep_the_parents_path_on_every_system() {
        assert!(written_of(Some("never")) == Written::Never);
        assert!(written_of(Some(" Never ")) == Written::Never);
        assert!(!wide_write_of(Some("0")));
        assert!(!wide_write_of(Some("off")));
        assert!(written_of(Some("always")) == Written::Always);
        assert!(written_of(Some("beside")) == Written::Beside);
        assert!(wide_write_of(Some("1")));
        assert!(wide_write_of(Some("ON")));
    }

    /// The defaults, a system at a time: a written member is read wide
    /// always on Linux and Windows and only beside another member on
    /// macOS; a CLEAR written member is read wide on Windows alone.
    #[test]
    fn the_defaults_are_each_systems_own() {
        let written = if cfg!(target_os = "macos") {
            Written::Beside
        } else {
            Written::Always
        };
        assert!(written_of(None) == written);
        assert!(written_of(Some("anything else")) == written);
        assert_eq!(WIDE_WRITE, cfg!(windows));
        assert_eq!(wide_write_of(None), cfg!(windows));
        assert_eq!(wide_write_of(Some("2")), cfg!(windows));
    }
}
