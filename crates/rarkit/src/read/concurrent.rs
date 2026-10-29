//! `extract_parallel`: several members DECODED at once, on worker threads
//! (feature `parallel`).
//!
//! SPEC-API 4.4 allows a non-solid set's independent members to be decoded
//! side by side, and spec F 3.7.6 states the four things that may not
//! change when they are: every member's output is byte-identical to the
//! sequential path's, `close` is called in archive order, the worker count
//! keeps the working memory inside `MemoryPolicy::working_limit`, and a
//! member that fails in a worker is reported through ITS OWN `close` with
//! its own outcome, never as an operation-wide failure that hides which
//! member it was. That last one is spec F section 8's defect 3, the one
//! this project exists to remove, so it is the shape of this module rather
//! than a check inside it.
//!
//! **How the concurrency is got, and why it is not a channel of packed
//! bytes.** `RangeSource` has no cursor and takes `&self` - its own
//! documentation says several of the engine's threads may be inside one
//! source at once - and a member's `data` range is known from its header.
//! So the walking thread keeps the walk, the headers and `Sink::open`, and
//! hands a worker a member's byte RANGE rather than its bytes; the worker
//! reads that range itself and decodes it. The walk then only has to SKIP
//! the member, which reads nothing at all, so it reaches the next header
//! immediately and every byte of the archive is still read exactly once
//! (spec F 7.3.3).
//!
//! The earlier design had the walker read the packed
//! bytes and stream them to a worker through a bounded channel. That shape
//! is correct but it does not go wide: the channel is the read-ahead bound,
//! so the walker is throttled to the decode rate of the member it is
//! feeding and cannot reach the next one until that member is finished.
//! Eight members decode in the time eight members take. Handing over the
//! RANGE is what removes the coupling, and it is what the `&self` source
//! was shaped for.
//!
//! **Archive order is structural here.** Every member's `close` leaves this
//! module from one queue, `flight`, which the walk pushes to in archive
//! order and which is drained from the front. A member the walk decoded
//! itself is closed only after everything queued ahead of it, so the two
//! kinds cannot interleave and no comparison of finishing times is made
//! anywhere.
//!
//! **What stays on the walking thread**, and each for a reason the format
//! gives:
//!
//! - a SOLID chain, whose every member begins in the window the member
//!   before it left (spec F 3.6);
//! - a SPLIT member, whose later fragments are not known until the walk has
//!   crossed into the next volume and checked the three join fields there
//!   (spec F 3.5.4), so its ranges cannot be put in a job;
//! - a member no decoder claims, which is refused by name and never read;
//! - a member the sink skipped, and one that declares no bytes.
//!
//! A member below its offload floor used to stay here too. Since 26 Sep
//! 2026 a COMPRESSED one goes to a worker in a small batch
//! ([`SMALL_BATCH_ENV`]) and within the member team ([`SMALL_TEAM_ENV`]);
//! a stored one below its floor still stays.
//!
//! A member decoded on the walking thread still has its WRITES pipelined
//! onto a worker, which is what this module did and all it did before
//! 19 Sep 2026.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{Scope, ScopedJoinHandle};

use crate::checksum::blake2sp::Blake2sp;
use crate::error::{Error, ErrorKind, Result};
use crate::read::block::FileHdr;
use crate::read::extract::{
    self, Closed, Decoders, Driver, Job, Member, Out, PackedRead, Scratch, Tally,
};
use crate::read::reader::ReadCtx;
use crate::read::walk::{Span, TICK};
use crate::read::{
    Disposition, ExtractReport, MemberInfo, MemberOutcome, ParallelSink, ReadOptions,
};
use crate::source::{RangeSource, Volumes};
use crate::MemoryPolicy;

// The parts, one module a seam.
mod dials;
pub(crate) use dials::Written;
use dials::*;
#[cfg(feature = "breadth-knob")]
pub(crate) use dials::{arranged_breadth, shrinking, spilling};
#[cfg(not(feature = "breadth-knob"))]
pub(crate) use dials::{arranged_breadth, shrinking, spilling};
#[cfg(feature = "offload-knob")]
pub(crate) use dials::{settle_spin_us, task_spin_us};
#[cfg(not(feature = "offload-knob"))]
pub(crate) use dials::{settle_spin_us, task_spin_us};
mod range;
use range::*;
mod handoff;
use handoff::*;
pub(crate) use handoff::{next_on, Done, Handoff, PoolOut, Unfinished};
mod bench;
pub(crate) use bench::Bench;
mod pool;
pub(crate) use pool::Pool;
use pool::*;
mod driver;

/// Extract with the caller's members decoded on worker threads.
pub(crate) fn extract_parallel_with<V: Volumes, S: ParallelSink>(
    volumes: V,
    opts: &ReadOptions,
    sink: &S,
    workers: usize,
) -> Result<ExtractReport> {
    if workers == 0 {
        return Err(Error::new(ErrorKind::LimitExceeded {
            resource: crate::Resource::Workers,
            needed: 1,
            limit: 0,
        }));
    }
    opts.refuse_no_workers()?;
    // The breadth the read's WIDTH allows, never the one the caller asked
    // for alone: the members in flight and the tape lanes inside them are
    // one product against one ceiling (API 8.3), and since 8.4.2 that
    // ceiling is `ReadOptions::workers` rather than the memory policy.
    // The engine does NOT size this to the machine; the width is the
    // caller's, and `MemoryPolicy::working_limit` still lowers what the
    // bytes cannot afford (8.4.1).
    let limit = workers.min(opts.read_width());
    // AND NARROWED, when the arrangement in force is one that narrows.
    // The ceiling divided by the breadth can fall under the fewest lanes
    // worth granting (`read::lanes::MIN_USEFUL_LANES`), at which point
    // the product 8.3 bounds has bought breadth and nothing else; the
    // two answers to that are to spend the remainder and keep the
    // breadth, which `Pool::new`'s budget does, or to narrow the breadth
    // until each member has a width worth having, which is this. The
    // choice between them is made on measured wall, not here.
    let limit = arranged_breadth(opts.read_width(), limit).max(1);
    let mut ctx = ReadCtx::new(opts.clone());
    // A NAMED budget's up-front check and the room it leaves for windows
    // (`extract::budget_floor`), which `Pool::offer` admits
    // each member against by its own need.
    let (volumes, room) = crate::read::extract::budget_floor(volumes, &ctx)?;
    ctx.room = room;
    let limit = limit.min(room.map_or(usize::MAX, |room| room.workers));
    drive_parallel(volumes, opts, &mut ctx, sink, limit)
}

/// As [`extract_parallel_with`], reading through a context the caller
/// keeps, so that the keys an earlier open of the same set derived are
/// not derived again (SPEC-API 4.2, `Session::extract_parallel`).
///
/// `ctx.options` are the read's options; the checks and the breadth are
/// the free function's, in the same order, so the verdicts and the
/// errors are the same whichever entry the caller took.
pub(crate) fn extract_parallel_in<V: Volumes, S: ParallelSink>(
    volumes: V,
    ctx: &mut ReadCtx,
    sink: &S,
    workers: usize,
) -> Result<ExtractReport> {
    if workers == 0 {
        return Err(Error::new(ErrorKind::LimitExceeded {
            resource: crate::Resource::Workers,
            needed: 1,
            limit: 0,
        }));
    }
    let opts = ctx.options.clone();
    opts.refuse_no_workers()?;
    let limit = workers.min(opts.read_width());
    let limit = arranged_breadth(opts.read_width(), limit).max(1);
    let (volumes, room) = crate::read::extract::budget_floor(volumes, ctx)?;
    ctx.room = room;
    let limit = limit.min(room.map_or(usize::MAX, |room| room.workers));
    drive_parallel(volumes, &opts, ctx, sink, limit)
}

/// The concurrent walk itself, over a context either entry supplies.
fn drive_parallel<V: Volumes, S: ParallelSink>(
    volumes: V,
    opts: &ReadOptions,
    ctx: &mut ReadCtx,
    sink: &S,
    limit: usize,
) -> Result<ExtractReport> {
    // The caller's `open` refused a `Write` for a redirection member here,
    // once, for every member the pool opens (spec F 3.8.1).
    let sink = &extract::GuardedParallel(sink);
    std::thread::scope(|scope| {
        let mut pool = Pool::new(scope, sink, limit, opts);
        // A NAMED budget's room for windows (`extract::budget_floor`),
        // which `offer` prices each member against; under the
        // whole-process default, with no pre-scan and nothing reserved,
        // the limit itself, so that the LIVE arm of the admission is in
        // force (`MemoryPolicy::keeps_residency`).
        pool.room = ctx.room.map(|room| room.windows).or_else(|| {
            opts.memory
                .keeps_residency()
                .then_some(opts.memory.working_limit)
        });
        let outcome = extract::extract_driven(volumes, ctx, &mut pool, &mut ());
        // Dropping the pool closes every task channel, which is what ends
        // the worker threads before the scope joins them.
        drop(pool);
        outcome
    })
}

/// The x86-64 member team's cap (the finer x86 form), pinned
/// with INJECTED thread counts so it does not depend on the box the tests
/// run on.
#[cfg(all(test, target_arch = "x86_64"))]
mod small_team_room_tests {
    use super::{team_room_of, team_width, SMALL_TEAM_DEFAULT};

    #[test]
    fn the_default_team_is_at_most_half_the_hardware_threads() {
        // (threads, breadth, the default team)
        for (threads, breadth, want) in [
            (8usize, 8usize, 4usize), // the 8 vCPU VM, default or -mt8
            (8, 4, 4),
            (8, 2, 2),
            (16, 16, 8), // a 16-thread desktop at the default width
            (16, 8, 8),  // the same desktop at -mt8: the breadth is not halved
            (16, 4, 4),
            (32, 32, 8),
            (4, 4, 2),
            (2, 2, 1),
            (1, 1, 1),
            (1, 8, 1),
        ] {
            let room = team_room_of(threads);
            assert_eq!(
                team_width(SMALL_TEAM_DEFAULT, breadth, room),
                want,
                "{threads} threads, breadth {breadth}"
            );
        }
    }

    #[test]
    fn a_team_set_by_name_is_held_only_by_the_breadth() {
        // A named team's room is unbounded (`small_team_room`).
        for (team, breadth, want) in [(8usize, 8usize, 8usize), (0, 8, 8), (2, 8, 2), (8, 3, 3)] {
            assert_eq!(
                team_width(team, breadth, usize::MAX),
                want,
                "{team} {breadth}"
            );
        }
    }
}
