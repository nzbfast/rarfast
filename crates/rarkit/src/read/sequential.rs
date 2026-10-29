//! The SEQUENTIAL entry point, decoding ahead (feature `parallel`).
//!
//! `extract` hands a caller's [`Sink`] one member at a time, in archive
//! order, on the caller's own thread: `open`, the member's bytes, `close`,
//! and only then the next member (SPEC-API 4.4). Nothing in that contract
//! says the NEXT member may not already be decoded when the caller reaches
//! it, and this module is that: while the caller holds member N, workers
//! decode members N + 1 onward into a BOUNDED look-ahead, and each is
//! handed to the caller in order when its turn comes.
//!
//! **Why it exists (the sequential entry point decodes ahead,
//! 22 Sep 2026).** The sequential rows lost to an old arm that decodes
//! several members at once, on thread count alone: on the 4,018 member
//! source tree rarkit's one lane spent LESS CPU than the old arm's 7.7
//! threads and took six times the wall. The members are independent and
//! `extract_parallel` already decodes them side by side; what the
//! sequential path lacked was somewhere to put member N + 1's bytes while
//! the caller still held member N.
//!
//! **Why a driver of its own and not the parallel pool under an adapter.**
//! The pool calls `ParallelSink::open` as the walk reaches a member and
//! hands the caller's WRITER to a worker. A sequential sink is `&mut`, its
//! writer is not `Send`, and its `open` must not run before the members
//! ahead of it have closed. So here the engine owns a member's bytes until
//! the caller's turn: the walk gives the member a slot of the look-ahead
//! instead of the caller's writer, a worker decodes into the slot, and at
//! the member's turn this driver calls the caller's `open`, writes the
//! slot's bytes into the writer `open` returned, and calls `close` with the
//! worker's verdict. The workers, the read of a member's own byte range and
//! the decode are the parallel pool's (`concurrent::Bench`), reused.
//!
//! **What goes ahead**, and each exception is a cost somebody measured:
//!
//! - a member the parallel pool would dispatch (`extract::offloadable`)
//!   whose declared size fits the look-ahead's room. The declared size
//!   bounds the slot, because the engine never writes past it
//!   (`extract::emit`, spec F 4.2);
//! - but a STORED member only behind a member already in flight: alone,
//!   its copy is bound by memory bandwidth and the look-ahead would add a
//!   second copy of every byte with nothing to overlap it against;
//! - a COMPRESSED member under the offload floor goes to a worker too, one
//!   member a task, whether or not anything is in flight
//!   ([`SEQ_SMALL_ENV`], `Inner::goes_small`): an archive of such members
//!   otherwise decoded on the walking thread alone;
//! - any other member too small for a worker (a stored one, a directory,
//!   an empty member) is decoded by the WALK into a slot when members are
//!   already in flight, so that it does not drain the look-ahead as a
//!   barrier (the barrier finding under `extract::OFFLOAD_FLOOR_COMPRESSED`);
//! - nothing of a SOLID archive, which has no independent member: the
//!   sequential path over a solid archive is exactly the path it was;
//! - anything else (a split member, a member declaring no size, a member
//!   larger than the room) waits for the look-ahead to drain and then runs
//!   on the walking thread exactly as before, seam and all.
//!
//! - a LARGE member that barely packs, with little on either side of it
//!   (a big member beside its sample), is the walk's too: the thread that writes
//!   is the narrow place for it, and carries it for less through the seam
//!   than out of a slot ([`goes_home`]);
//!
//! **The bound** is two limits at once, and the look-ahead never holds more
//! than either: at most [`OUTPUTS_FACTOR`] times the breadth in members,
//! and the members' declared sizes at most a byte ceiling
//! ([`SEQ_AHEAD_BYTES_ENV`]), with the look-ahead and the workers' windows
//! together inside `MemoryPolicy::working_limit`, so a caller's own budget
//! binds it.
//!
//! **And the caller's writer bounds what is DECODED inside that**, where
//! one member's decode fills the machine: a worker waits once the
//! look-ahead holds a window of bytes the caller has not taken yet
//! (`slots::Gate`, [`SEQ_AHEAD_HOLD_ENV`]). Before it, a set of large
//! members was decoded whole into memory in front of a writer that was
//! never waiting for it.
//!
//! **What a caller can observe**, all of it stated in SPEC-API:
//!
//! - the order, count and arguments of `open`, `close` and the writes are
//!   the sequential path's exactly; so are the bytes and the verdicts;
//! - a member inside the look-ahead is READ AND DECODED before its `open`,
//!   so a sink that answers `Skip` for it has spent that decode (it is
//!   still never written, and closed and counted exactly as the
//!   sequential path closes and counts a skipped member). Once the caller
//!   skips a member that is not a directory, nothing more is decoded
//!   ahead: a caller that is SELECTING pays at most one look-ahead for it;
//! - `released` is held back behind every worker still reading, and
//!   `volume_done` (and so the walk's step into the next volume) first
//!   hands the whole look-ahead to the caller, after which no worker reads
//!   that volume ([`Held`]): SPEC-API 8.3's "the point behind which no
//!   member in flight still needs bytes" and 5.3's volume order.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::Scope;
use std::time::Duration;

use crate::checksum::Crc32;
use crate::error::{Error, ErrorKind, Result};
use crate::read::concurrent::{self, Bench, Done, PoolOut, Unfinished};
use crate::read::extract::{self, Closed, Driver, Job, Out};
use crate::read::reader::ReadCtx;
use crate::read::{handed, wide};
use crate::read::{Disposition, ExtractReport, MemberInfo, MemberOutcome, Progress, Sink};
use crate::source::Volumes;
use crate::types::Method;
use crate::MemoryPolicy;

// The parts, one module a seam.
mod slots;
#[cfg(feature = "test-support")]
pub(crate) use slots::Gate;
use slots::*;
pub(crate) use slots::{Deliver, Held, Reads, SeqOut, SlotOut};
mod inner;
pub(crate) use inner::Inner;
use inner::*;
mod drivers;
pub(crate) use drivers::Ahead;
use drivers::*;
mod solid;
use solid::*;

// ---------------------------------------------------------------------------
// The knob
// ---------------------------------------------------------------------------

/// Whether the sequential entry point decodes ahead: `1` or `on` turns it
/// on, `0` or `off` turns it off, anything else leaves the default.
///
/// A RUNTIME knob and never a cargo feature, so ONE binary measures the two
/// against each other in one hold.
pub(crate) const SEQ_AHEAD_ENV: &str = "RARKIT_SEQ_AHEAD";

/// The look-ahead's byte ceiling, in MiB; `0` is no ceiling of its own, the
/// look-ahead then bounded by `MemoryPolicy::working_limit` alone.
pub(crate) const SEQ_AHEAD_BYTES_ENV: &str = "RARKIT_SEQ_AHEAD_BYTES";

/// Whether decode-ahead is on when [`SEQ_AHEAD_ENV`] says nothing: ON,
/// on its timed price (an Apple M1 Mac, 22 Sep 2026: the three sequential rows
/// 0.169x, 0.318x and 0.945x to 1.586x, 1.047x and 3.125x, every
/// control unmoved) and its measured memory and CPU.
const SEQ_AHEAD_DEFAULT: bool = true;

/// The byte ceiling when [`SEQ_AHEAD_BYTES_ENV`] says nothing, in bytes;
/// zero is none of its own. NONE, by the timed run's knob cells: on
/// the M1 Mac a 64 MiB ceiling cost 8x16 47 percent of its wall and 32 MiB
/// 52 percent, while 128 MiB cost nothing and saved nothing; the
/// look-ahead is bounded by `MemoryPolicy::working_limit`, which a caller
/// who states a budget sets.
const AHEAD_BYTES_DEFAULT: u64 = 0;

/// The window the look-ahead's workers are held at, in MiB: the bytes
/// decoded and not yet delivered past which a worker waits for the
/// caller's writer (`slots::Gate`); `0` is no window. A RUNTIME knob, so
/// one binary measures every window against none.
pub(crate) const SEQ_AHEAD_HOLD_ENV: &str = "RARKIT_SEQ_AHEAD_HOLD_MIB";

/// The window when [`SEQ_AHEAD_HOLD_ENV`] says nothing, in bytes.
///
/// **128 MiB, counted at 64, 128 and 256** (eight cores, plain builds, five
/// repetitions, to an NVMe drive and to memory). The sets of several large
/// members read the same at 64 and 128 (a big member beside a half of its
/// size 1.18 times its wall with no gate, a set of many members on the
/// walk 1.44 to the drive and 1.26 to 1.30 to memory) and a little less
/// at 256. What decides it is a member that packs well, whose decode runs
/// in bursts: a
/// big binary beside small files read 0.975 of its wall to the drive at
/// 64 MiB, the window too small to carry the writer across the slow
/// stretches, and 0.990 at 128.
const HOLD_DEFAULT: u64 = 128 * MIB;

/// The bytes of a chunk the walking thread checksums and writes at a time
/// as it delivers a member from the look-ahead, in KiB; `0` is the whole
/// chunk. A RUNTIME knob, so one binary measures both.
pub(crate) const SEQ_AHEAD_PIECE_ENV: &str = "RARKIT_SEQ_AHEAD_PIECE_KIB";

/// The piece when [`SEQ_AHEAD_PIECE_ENV`] says nothing, in bytes.
const PIECE_DEFAULT: usize = 256 * 1024;

fn deliver_piece() -> usize {
    static BYTES: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *BYTES.get_or_init(|| {
        crate::knob::reader_var(SEQ_AHEAD_PIECE_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map_or(PIECE_DEFAULT, |kib| kib.saturating_mul(1024))
    })
}

/// Whether a large member that barely packs, with little behind it in its
/// volume, is decoded on the walking thread and not ahead ([`goes_home`]):
/// `0` or `off` sends it ahead as any other, a measuring arm.
pub(crate) const SEQ_AHEAD_HOME_ENV: &str = "RARKIT_SEQ_AHEAD_HOME";

fn homes_large() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            crate::knob::reader_var(SEQ_AHEAD_HOME_ENV)
                .ok()
                .map(|v| v.trim().to_ascii_lowercase())
                .as_deref(),
            Some("0" | "off")
        )
    })
}

/// The declared size from which [`goes_home`] asks.
const HOME_LARGE: u64 = 256 * MIB;

/// Whether the walking thread decodes a member itself, in its turn, where
/// a worker could take it. It does where the member is LARGE
/// ([`HOME_LARGE`] declared), BARELY PACKS (nine tenths of its size or
/// more), and has LITTLE ON EITHER SIDE: what the look-ahead holds in
/// front of it, and what its volume holds after it, are each a sixteenth
/// of its packed bytes at most. A big member with its sample and a text file
/// beside it.
///
/// `size` and `packed` are the member's declared and packed bytes,
/// `ahead` the declared bytes the look-ahead holds in front of it, `tail`
/// the bytes of its volume after it, `None` where the volume's length is
/// not known.
///
/// **Why each.** A member that barely packs decodes at several gigabytes
/// a second, faster than a drive or a memory file system takes it from
/// one thread. The thread that writes is then the narrow place, and it
/// carries the member for less through the one-member seam than out of a
/// slot: counted on eight cores, a big member beside its sample 2.66 s against
/// 2.98 s to an NVMe drive and 1.48 s against 1.62 s to memory, which is
/// what the same extraction took under a stated limit of 512 MiB, where
/// the member never fitted the look-ahead. A member that packs well is
/// bound by its decode, which a worker runs as well as the walking
/// thread does, and such a member taken home read 0.97 of its wall. Large,
/// because the walking thread decodes nothing else while it carries the
/// member. And little on either side, because a second large member
/// would have decoded beside this one: taken home with a large member
/// ahead of it, or behind it, the set read 0.84 to 0.96 of its wall where
/// there were cores to decode both.
fn goes_home(size: u64, packed: u64, ahead: u64, tail: Option<u64>) -> bool {
    let Some(tail) = tail else {
        return false;
    };
    size >= HOME_LARGE && barely_packs(size, packed) && ahead <= packed / 16 && tail <= packed / 16
}

/// Whether a large member that barely packs is decoded on the walking
/// thread in its turn WHATEVER is beside it: where one member's decode
/// fills the machine (`narrow`, [`holds`]).
///
/// **Why.** On such a machine a second large member decoding beside the
/// first buys nothing, there being no idle core for it, and held at the
/// gate it keeps the lanes it was granted: counted on eight cores at a
/// width of eight, a big member beside a half of its size read 0.98 of its
/// parent to memory with the half's worker held. One at a time on the
/// walking thread is what the same sets read under a stated limit, and
/// the best arm of every count on eight cores: a set of eight 2.66 s
/// to an NVMe drive and 1.53 s to memory, against 2.83 and 2.05 with the
/// workers held and 4.03 and 2.61 with nothing held.
///
/// **From [`IN_TURN_LARGE`], not from [`HOME_LARGE`].** One member at a
/// time is also one READER at a time, and on an archive the system has not
/// cached the read is the narrow place: with the rule asking from 256 MiB,
/// one member of a gibibyte and four of 256 MiB beside small files read
/// 0.956 and 0.947 of their wall cold to an NVMe drive, where the workers
/// read their members abreast. From two gibibytes the cold rows counted
/// are level or better (a big member beside a quarter, a third and a half of
/// its size 0.998 to 1.032).
fn in_turn_at_home(narrow: bool, size: u64, packed: u64) -> bool {
    narrow && size >= IN_TURN_LARGE && barely_packs(size, packed)
}

/// The declared size from which [`in_turn_at_home`] asks.
const IN_TURN_LARGE: u64 = 2048 * MIB;

/// Whether a member of `size` declared bytes in `packed` barely packs:
/// nine tenths of its size or more. Such a member decodes faster than a
/// writer takes it; one that packs well is bound by its decode.
fn barely_packs(size: u64, packed: u64) -> bool {
    packed / 9 >= size / 10
}

/// Whether the worker that takes this member is held at the gate
/// (`slots::Gate`): only a member that barely packs, unless
/// `RARKIT_SEQ_AHEAD_HOLD_PACKED` is `1`, a measuring arm.
///
/// **Why.** The gate is for a decode that outruns the writer. A member
/// that packs well decodes in bursts, slower than the writer over all and
/// faster in stretches, and what it gets ahead in the fast stretches is
/// what carries the writer across the slow ones: held at the window, a
/// big binary beside small files read 0.975 of its wall to a drive.
fn held_at_gate(size: u64, packed: u64) -> bool {
    static ALL: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    #[cfg(feature = "test-support")]
    if let Some(all) = crate::probe::seq_ahead_hold_packed() {
        return all || barely_packs(size, packed);
    }
    barely_packs(size, packed)
        || *ALL.get_or_init(|| {
            crate::knob::reader_var("RARKIT_SEQ_AHEAD_HOLD_PACKED").is_ok_and(|v| v.trim() == "1")
        })
}

/// Whether the look-ahead's workers are held at the window at all
/// (`slots::Gate`): `1` or `on` holds them, `0` or `off` does not,
/// anything else leaves it to the read's width. A measuring arm.
pub(crate) const SEQ_AHEAD_HOLD_ALL_ENV: &str = "RARKIT_SEQ_AHEAD_HOLD_ALL";

fn env_hold_all() -> Option<bool> {
    static ALL: std::sync::OnceLock<Option<bool>> = std::sync::OnceLock::new();
    *ALL.get_or_init(|| {
        match crate::knob::reader_var(SEQ_AHEAD_HOLD_ALL_ENV)
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("1" | "on") => Some(true),
            Some("0" | "off") => Some(false),
            _ => None,
        }
    })
}

/// Whether an extraction at a read width of `width` holds its workers at
/// the window: where one member's decode fills the machine
/// (`slots::ABREAST_UNITS`).
fn holds(width: usize) -> bool {
    env_hold_all().unwrap_or(width < slots::ABREAST_UNITS)
}

fn env_hold() -> u64 {
    static BYTES: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *BYTES.get_or_init(|| {
        crate::knob::reader_var(SEQ_AHEAD_HOLD_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map_or(HOLD_DEFAULT, |mib| mib.saturating_mul(MIB))
    })
}

/// The window in force for an extraction started on this thread.
fn hold_bytes() -> u64 {
    #[cfg(feature = "test-support")]
    if let Some(bytes) = crate::probe::seq_ahead_hold() {
        return bytes;
    }
    env_hold()
}

/// The members OPEN in the look-ahead, as a multiple of the members
/// DECODING at once: the parallel pool's measured factor
/// (`concurrent::OUTPUTS_OVER_BREADTH_DEFAULT`), on the same corpora.
const OUTPUTS_FACTOR: usize = 2;

/// The largest member the WALK decodes into the look-ahead itself when
/// members are in flight, rather than draining it as a barrier.
const LOCAL_MAX: u64 = 1 << 20;

/// The bytes a worker hands the caller at a time. The member at the front
/// of the look-ahead streams to the caller in these while it decodes.
const CHUNK: usize = 1 << 20;

/// The most a volume may hold past a member's packed bytes for the member
/// still to count as the LAST of its volume: the end record and a small
/// service header or two, never another member worth a worker.
const LAST_TAIL: u64 = 64 * 1024;

const MIB: u64 = 1 << 20;

fn env_on() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        match crate::knob::reader_var(SEQ_AHEAD_ENV)
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("1" | "on") => true,
            Some("0" | "off") => false,
            _ => SEQ_AHEAD_DEFAULT,
        }
    })
}

/// The workers the look-ahead decodes on, when a measurement asks for
/// fewer than [`look_ahead_breadth`] gives: `RARKIT_SEQ_AHEAD_WORKERS`,
/// `0` or unset for that default. A bench knob, so a run can price
/// the breadth against the CPU it spends; nothing ships reading it but the
/// default.
pub(crate) const SEQ_AHEAD_WORKERS_ENV: &str = "RARKIT_SEQ_AHEAD_WORKERS";

/// The workers the look-ahead decodes on, at a read width of `width`:
/// ONE FEWER than the width, and at least one.
///
/// **The walk is a decoder too.** It decodes a small member into a slot
/// while workers are in flight (this module's header), and a member too
/// large or too awkward to go ahead once the look-ahead has drained, and
/// each of those counts against the width exactly as a worker's member
/// does (SPEC-API 8.3 and 8.4.2: the members decoded at once and the lanes
/// inside them, together, at most the width). This was the whole width
/// until 29 Sep 2026, so `-mt2` decoded THREE members at once, two workers
/// and the walk: the width exceeded by a member. Once the ceiling was made
/// hard (`read::lanes`), the walk waited on the budget for nearly every
/// small member instead, and that wait is a sleep and a wake which load
/// stretches. One fewer worker is the breadth at which the walk and the
/// workers fit the width without waiting. Priced untimed on an x86-64 box
/// at 16 cores (29 Sep 2026): level with the old
/// breadth on every cell measured, the old one's extra thread included.
/// At a width of one it is still one worker, and the walk waits its turn.
fn look_ahead_breadth(width: usize, env: usize) -> usize {
    let most = width.saturating_sub(1).max(1);
    match env {
        0 => concurrent::arranged_breadth(width, most),
        n => n.min(most),
    }
    .max(1)
}

fn workers_env() -> usize {
    static WORKERS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *WORKERS.get_or_init(|| {
        crate::knob::reader_var(SEQ_AHEAD_WORKERS_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0)
    })
}

fn env_bytes() -> u64 {
    static BYTES: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *BYTES.get_or_init(|| {
        crate::knob::reader_var(SEQ_AHEAD_BYTES_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map_or(AHEAD_BYTES_DEFAULT, |mib| mib.saturating_mul(MIB))
    })
}

/// Whether the look-ahead takes a COMPRESSED member under the offload
/// floor (`extract::batchable`) onto its workers, rather than leaving it to
/// the walk: `RARKIT_SEQ_SMALL`, `0` or `off` for the walk alone, a
/// runtime knob so one binary measures both arms.
pub(crate) const SEQ_SMALL_ENV: &str = "RARKIT_SEQ_SMALL";

/// ON. With it off, an archive of members all under the floor never goes
/// ahead at all: every member is decoded on the walking thread, one core,
/// where `extract_parallel` pools the same members. `p` of 20,000 members
/// of 3.7 KiB (small-r) read 0.232 s against `t`'s 0.075 s on an EPYC
/// 4345P for that alone (a quiet box, 30 Sep
/// 2026).
const SEQ_SMALL_DEFAULT: bool = true;

fn small_env_on() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        match crate::knob::reader_var(SEQ_SMALL_ENV)
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("1" | "on") => true,
            Some("0" | "off") => false,
            _ => SEQ_SMALL_DEFAULT,
        }
    })
}

/// Whether an extraction started on this thread takes small members ahead.
#[cfg(feature = "test-support")]
fn small_engaged() -> bool {
    crate::probe::seq_small().unwrap_or_else(small_env_on)
}

#[cfg(not(feature = "test-support"))]
fn small_engaged() -> bool {
    small_env_on()
}

/// Whether an extraction started on this thread decodes ahead.
#[cfg(feature = "test-support")]
pub(crate) fn engaged() -> bool {
    crate::probe::seq_ahead().unwrap_or_else(env_on)
}

#[cfg(not(feature = "test-support"))]
pub(crate) fn engaged() -> bool {
    env_on()
}

/// The look-ahead's ceiling for a caller that writes each member to a file
/// in order (`ReadOptions::files_in_order`), where [`SEQ_AHEAD_BYTES_ENV`]
/// says nothing.
///
/// **1,024 MiB, counted at 256, 512, 1,024 and 2,048** (11 Oct 2026; six
/// members of 320 MiB, stored and packing two to one; an Apple M1 Ultra at
/// 20 threads and an AMD EPYC 4345P at 16; widths of 8, the machine's own
/// and the default; with a null). It is the smallest at which no row of
/// either machine read under 0.99 outside its null (1.005 to 1.17 on the
/// first, 0.987 to 1.14 on the second), for 157 to 906 MB held where
/// 1,277 to 1,847 MB were. At 512 the stored members read 0.95 on the
/// second machine and the packing ones 0.95 to 0.98 on the first; at 256
/// no member of that size goes ahead at all (0.56 to 0.91).
///
/// **Admission and not a hold.** A held window ([`HOLD_DEFAULT`]) at
/// every width was counted first and read 0.79 on the packing members at
/// a width of eight on the first machine, where the same row bounded by
/// admission alone, under a named limit of 512 MiB, read 1.00 at 67 MB:
/// what costs there is a worker parked half way through a member with its
/// lanes, not the bound.
const FILES_CEILING: u64 = 1024 * MIB;

/// The ceiling for such a caller under a working limit of `limit`: the
/// smaller of [`FILES_CEILING`] and the limit ITSELF, so that a named
/// budget, a cap of the environment and a small machine lower it.
///
/// **The whole limit and not a part of it.** Half the limit was built
/// first and read 0.73 on one row of the shipped pair (an Apple M1 Ultra,
/// `e -mt8 -mm512m` over six members of 320 MiB that pack: 0.464 s to
/// 0.635 s): under that budget half the limit is under one member, so no
/// member went ahead at all, where the limit itself lets one. Under a
/// limit below [`FILES_CEILING`] the look-ahead is therefore what it was
/// before this ceiling.
fn files_ceiling(limit: u64) -> u64 {
    FILES_CEILING.min(limit)
}

/// Whether a member is bounded by that ceiling: every member but one the
/// engine's own window already holds, which is a member that barely packs
/// at a read width one member fills (`narrow`, [`holds`]; who waits at
/// the window is [`held_at_gate`]'s to say).
///
/// **Each member by exactly one of the two measures.** Counted 11 Oct
/// 2026 on a 16 thread AMD Ryzen 7 7700, over a base whose window holds
/// (stored members about 200 MB there): the ceiling gave such members
/// nothing and cost them 2 to 3 percent of the wall in the drive's fast
/// state, and more at a stated width. At 20 threads on an Apple M1 Ultra,
/// where there is no window, the same stored members under the ceiling
/// read 1.06 with their peak cut from 1,611 to 736 MB. Members that pack
/// gained under it on both (1.12 to 1.20 and 1.13 to 1.14).
fn bounded_by_ceiling(narrow: bool, size: u64, packed: u64) -> bool {
    !(narrow && held_at_gate(size, packed))
}

/// The byte ceiling in force on this thread; zero is none of its own.
#[cfg(feature = "test-support")]
fn ceiling_bytes() -> u64 {
    crate::probe::seq_ahead_bytes().unwrap_or_else(env_bytes)
}

#[cfg(not(feature = "test-support"))]
fn ceiling_bytes() -> u64 {
    env_bytes()
}

/// `extract` with decode-ahead: the walk and the caller's sink on this
/// thread, the decodes on scoped workers joined before it returns
/// (SPEC-API 8.3).
pub(crate) fn extract_ahead<V: Volumes, K: Sink, P: Progress>(
    volumes: V,
    ctx: &mut ReadCtx,
    sink: &mut K,
    progress: &mut P,
) -> Result<ExtractReport> {
    ctx.options.refuse_no_workers()?;
    // A SOLID archive has no member to take ahead, so where the solid
    // path is on, the walk itself goes to a worker instead (below). Which
    // archive this is has to be known BEFORE the walk starts on this
    // thread, so volume 0's main header is read once, here.
    let mut volumes = Peeked::new(volumes);
    // And only for a caller whose writer is a FILE (`sink_is_file`, the
    // cost class SPEC-API 8.5 gives a caller to state): the path hands each
    // member between two threads, about 30 us a member, which an in-memory
    // sink never earns back (f/extract-solid290-m3, 290 members of 64 KiB,
    // read 0.32x its own wall with it; untimed, an Apple M3 Mac, 23 Sep 2026).
    if solid_engaged()
        && ctx.options.sink_is_file == Some(true)
        && volumes.first_is_solid(&ctx.options)?
    {
        match extract_solid(volumes, ctx, sink, progress) {
            Solid::Ran(report) => return report,
            // No thread for the walk: it runs here instead, as it does
            // where the solid path is off.
            Solid::NoThread(back) => volumes = back,
        }
    }
    let opts = ctx.options.clone();
    let room = ctx.room;
    // TWO PHASES OF ONE WALK. Until a member reaches the walk that could go
    // ahead, the walk runs under `Home`, which is the sequential driver and
    // nothing more: a member that cannot go ahead pays nothing for the
    // look-ahead existing. The first member that could is held unopened and
    // the rest of the archive runs under the look-ahead's driver from it.
    let mut walking = extract::Walking::begin(volumes, ctx)?;
    let mut home = Home {
        sink,
        closed: Closed::default(),
        selecting: false,
        floor_compressed: extract::offload_floor_compressed(),
        small: small_engaged(),
    };
    match walking.phase(&mut home, progress) {
        Ok(true) => {}
        Ok(false) => return walking.finish(&mut home, progress, Ok(())),
        Err(e) => return walking.finish(&mut home, progress, Err(e)),
    }
    walking.retire(&mut home)?;
    let sink = home.sink;
    std::thread::scope(|scope| {
        let shared = std::rc::Rc::new(std::cell::RefCell::new(Inner::new(
            scope, sink, &opts, room,
        )));
        let reads = Arc::clone(&shared.borrow().reads);
        let mut held = Held::new(progress, reads, std::rc::Rc::clone(&shared));
        let mut driver = Ahead(shared);
        let outcome = walking.phase(&mut driver, &mut held).map(|_| ());
        let report = walking.finish(&mut driver, &mut held, outcome);
        // Dropping both holders of the state closes every task channel,
        // which is what ends the workers before the scope joins them.
        drop(held);
        drop(driver);
        report
    })
}

#[cfg(test)]
mod home_words {
    use super::{
        barely_packs, goes_home, holds, in_turn_at_home, slots::ABREAST_UNITS, HOME_LARGE, MIB,
    };

    /// On a machine one member fills, every large member that barely
    /// packs is the walking thread's; on a wider one, and for a member
    /// that packs well or is small, nothing changes.
    #[test]
    fn a_narrow_machine_takes_large_barely_packed_members_one_at_a_time() {
        let gib = 1024 * MIB;
        assert!(in_turn_at_home(true, 2 * gib, 2 * gib));
        assert!(in_turn_at_home(true, 8 * gib, 8 * gib / 100 * 94));
        assert!(!in_turn_at_home(false, 8 * gib, 8 * gib));
        assert!(!in_turn_at_home(true, 8 * gib, 4 * gib));
        // A member of a gibibyte, or of 256 MiB, keeps its worker.
        assert!(!in_turn_at_home(true, gib, gib));
        assert!(!in_turn_at_home(true, HOME_LARGE, HOME_LARGE));
    }

    /// Nine tenths is the line, and a member that packs to half is far
    /// under it: its worker is not held at the gate.
    #[test]
    fn a_member_that_packs_well_is_not_one_that_barely_packs() {
        assert!(barely_packs(1000, 1000));
        assert!(barely_packs(8 * 1024 * MIB, 8 * 1024 * MIB / 100 * 94));
        assert!(!barely_packs(1600 * MIB, 640 * MIB));
        assert!(!barely_packs(1000, 500));
    }

    /// A big member beside its sample goes home; take any one of the four
    /// conditions away and it goes ahead as before.
    #[test]
    fn a_large_barely_packed_member_with_little_beside_it_goes_home() {
        let size = 8 * 1024 * MIB;
        let packed = size / 100 * 94;
        let sample = Some(64 * MIB);
        assert!(goes_home(size, packed, 0, sample));
        assert!(goes_home(size, packed, 64 * MIB, sample));
        assert!(goes_home(HOME_LARGE, HOME_LARGE, 0, Some(0)));
        // Not large.
        assert!(!goes_home(HOME_LARGE - 1, HOME_LARGE - 1, 0, Some(0)));
        // Packs well: its decode is the narrow place, not the writer.
        assert!(!goes_home(size, size / 2, 0, sample));
        // A large member ahead of it, or behind it, decodes beside it.
        assert!(!goes_home(size, packed, packed / 8, sample));
        assert!(!goes_home(size, packed, 0, Some(packed / 8)));
        // A volume of unknown length says nothing of what is behind.
        assert!(!goes_home(size, packed, 0, None));
    }

    /// The workers are held where one member fills the machine, and only
    /// there (no environment knob is set under `cargo test`).
    #[test]
    fn the_gate_is_for_a_width_one_member_fills() {
        if std::env::var_os(super::SEQ_AHEAD_HOLD_ALL_ENV).is_some() {
            return;
        }
        assert!(holds(1));
        assert!(holds(ABREAST_UNITS - 1));
        assert!(!holds(ABREAST_UNITS));
        assert!(!holds(96));
    }
}

#[cfg(test)]
mod stored_wide_words {
    use super::{handed::Dial, stored_wide_of};

    /// The knob's words, and that an unknown one leaves the default.
    #[test]
    fn the_knob_reads_its_words() {
        let default = Some(Dial::default());
        assert_eq!(stored_wide_of(None), default);
        assert_eq!(stored_wide_of(Some("1")), default);
        assert_eq!(stored_wide_of(Some("on")), default);
        assert_eq!(stored_wide_of(Some("nonsense")), default);
        assert_eq!(stored_wide_of(Some("0")), None);
        assert_eq!(stored_wide_of(Some(" OFF ")), None);
        assert_eq!(
            stored_wide_of(Some("1024")),
            Some(Dial {
                piece: Some(1 << 20),
                in_order: None
            })
        );
        assert_eq!(
            stored_wide_of(Some("seq")),
            Some(Dial {
                piece: None,
                in_order: Some(true)
            })
        );
        assert_eq!(
            stored_wide_of(Some("wide:512")),
            Some(Dial {
                piece: Some(512 << 10),
                in_order: Some(false)
            })
        );
        // Under 64 KiB is no piece.
        assert_eq!(stored_wide_of(Some("seq:8")).map(|d| d.piece), Some(None));
    }
}

#[cfg(test)]
mod tests {
    use super::look_ahead_breadth;

    /// SPEC-API 8.3 and 8.4.2: the members decoded at once, the walk's
    /// own among them, fit the width. At a width of one the walk and the
    /// one worker cannot both fit, and the lane budget makes the walk wait
    /// its turn there (`read::lanes`); at every other width they fit
    /// without waiting.
    #[test]
    fn the_look_ahead_and_the_walk_together_fit_the_width() {
        for width in 2usize..=64 {
            let breadth = look_ahead_breadth(width, 0);
            // The workers and the walk: `breadth + 1` members at most.
            assert!(
                breadth < width,
                "a width of {width} ran {breadth} workers beside the walk"
            );
            assert_eq!(breadth, width - 1, "and it spends the rest of the width");
        }
        assert_eq!(look_ahead_breadth(1, 0), 1);
        assert_eq!(look_ahead_breadth(0, 0), 1);
    }

    /// The bench knob can narrow the breadth and can never widen it past
    /// what fits.
    #[test]
    fn the_knob_narrows_and_never_widens() {
        assert_eq!(look_ahead_breadth(8, 3), 3);
        assert_eq!(look_ahead_breadth(8, 8), 7);
        assert_eq!(look_ahead_breadth(8, 64), 7);
    }
}

/// API section 8, whole-process: the look-ahead's chunk buffers are counted
/// by capacity, out and idle, and charged to the process counters.
#[cfg(test)]
mod spares_for_tests {
    use super::Spares;

    #[test]
    fn spares_count_every_buffer_by_capacity_and_shed_only_idle_ones() {
        let spares = Spares::new(8 << 20);
        let small = spares.take(4096);
        let big = spares.take(1 << 20);
        let (idle, out) = spares.resident();
        assert_eq!(idle, 0);
        assert_eq!(out, (small.capacity() + big.capacity()) as u64);

        // A warm 1 MiB buffer handed to a small member is counted at its
        // capacity, not at the few bytes the member declared.
        spares.put(big);
        let warm = spares.take(16);
        assert!(warm.capacity() >= 1 << 20);
        let (idle, out) = spares.resident();
        assert_eq!(idle, 0);
        assert_eq!(out, (small.capacity() + warm.capacity()) as u64);

        // Put back, both are idle; shedding drops idle ones only.
        let warm_cap = warm.capacity() as u64;
        spares.put(warm);
        spares.put(small);
        let (idle, out) = spares.resident();
        assert_eq!(out, 0);
        assert!(idle >= warm_cap);
        spares.shed(0);
        assert_eq!(spares.resident(), (0, 0));
        assert_eq!(spares.held(), 0);
    }

    #[test]
    fn the_pool_keeps_no_more_idle_capacity_than_its_ceiling() {
        let spares = Spares::new(1 << 20);
        let a = spares.take(1 << 20);
        let b = spares.take(1 << 20);
        spares.put(a);
        spares.put(b);
        let (idle, out) = spares.resident();
        assert_eq!(out, 0);
        assert!(idle <= (1 << 20) + (64 << 10), "{idle}");
    }
}

#[cfg(test)]
mod files_ceiling_words {
    use super::{
        bounded_by_ceiling, files_ceiling, holds, slots::ABREAST_UNITS, FILES_CEILING, MIB,
    };

    /// BOTH SIDES OF THE 18: under it, a member that barely packs (a
    /// stored one among them) is the window's and not the ceiling's; from
    /// it up, and for a member that packs at any width, the ceiling's.
    #[test]
    fn a_member_the_window_holds_is_not_the_ceilings() {
        assert_eq!(ABREAST_UNITS, 18);
        let (narrow, wide) = (holds(17), holds(18));
        assert!(narrow && !wide);
        let size = 320 * MIB;
        // Stored, and coded to nine tenths: barely packs.
        for packed in [size, size / 10 * 9] {
            assert!(!bounded_by_ceiling(narrow, size, packed));
            assert!(bounded_by_ceiling(wide, size, packed));
        }
        // Packs two to one: the ceiling's at either width.
        assert!(bounded_by_ceiling(narrow, size, size / 2));
        assert!(bounded_by_ceiling(wide, size, size / 2));
    }

    /// 1,024 MiB on a machine with room, and the working limit itself,
    /// whole, wherever that is smaller: a named budget, a cap of the
    /// environment or a small machine keeps the look-ahead it had.
    #[test]
    fn a_gibibyte_or_the_limit_where_that_is_smaller() {
        const GIB: u64 = 1024 * MIB;
        assert_eq!(FILES_CEILING, GIB);
        assert_eq!(files_ceiling(16 * GIB), GIB);
        assert_eq!(files_ceiling(GIB), GIB);
        assert_eq!(files_ceiling(GIB - 1), GIB - 1);
        assert_eq!(files_ceiling(480 * MIB), 480 * MIB);
        assert_eq!(files_ceiling(0), 0);
    }
}
