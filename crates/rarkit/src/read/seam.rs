//! The seam of spec F 3.7.7: the READ, the decrypt, the decode and the
//! member checksum of ONE member running while the walking thread writes
//! (feature `parallel`).
//!
//! This is the axis [`crate::read::concurrent`] cannot help with. That
//! module decodes several MEMBERS at once, and a downloaded archive is
//! very often one large member, where a breadth of eight is a breadth of
//! one (SPEC-API 8.5). Profiled on a 2 GiB stored CRC32 member the wall of
//! one member is the SUM of three stages on one thread: 59% in `write` to
//! the caller's writer, 25% in `pread` for the packed bytes and 13% in the
//! member checksum (measured). The floor of a perfectly
//! overlapped member is its LARGEST single stage, so putting the read and
//! the checksum behind the write reaches that floor with ONE extra thread.
//!
//! **Which unit goes where, and why it is not the other way round.** The
//! DELIVER unit - taking full buffers from the ring in order and writing
//! them to the caller's writer - stays on the walking thread, and the
//! SOURCE unit is the scoped thread. That assignment is what makes the
//! seam free of any signature change: the caller's `Sink::Out` and its
//! `Progress` never leave the thread that called `extract`, so neither
//! trait gains a `Send` bound, and `RangeSource` is already `Send + Sync`.
//! Moving the WRITE instead would reach the same floor - the floor is the
//! largest stage either way - and would cost `Sink::Out: Send`, which
//! narrows every caller's sink type for nothing (SPEC-API 8.5).
//!
//! **What layer 3 owes for this, and it is a bound and not a redesign.**
//! [`MemberStream`] borrows the walk, which is why the seam looked like a
//! `Volumes` question and is not: the walk is not touched while a member
//! is in flight, so the source unit may hold one member's stream for the
//! length of that member inside a `std::thread::scope` that joins before
//! the member is finished. The one thing that had to move is the
//! observer: the stream used to report `released` straight into
//! `Progress` through a `Gate`, and `Progress` may not be called from
//! here. It reports into [`Notes`] instead and the walking thread relays
//! them, which is `released` for the offset the source unit has CONSUMED -
//! ahead of the byte being delivered and still behind nothing that will be
//! read again, so spec F 3.7.3 is unweakened and a caller may release more
//! and sooner.
//!
//! **Cancellation is the hard requirement, not the overlap.** A caller's
//! writer returning an error must stop the WORK and not merely end the
//! call with the right error. A fuzz campaign found the concurrent member
//! path decoding for 7.92 s after a refusal at a ceiling of zero where the
//! sequential path took 0.20 ms, and a seam that adds a second
//! unit adds a second place for that to happen. So the source unit reads
//! [`Stop`] at every buffer boundary - both when it hands a full buffer
//! over and when it takes an empty one - and the walking thread sets it
//! before it returns from a failed write, a failed `Progress` callback or
//! a raised cancel flag. After the flag is set the source unit does at
//! most one more buffer's worth of work plus the read already in flight,
//! and then the scope joins. `tests/one_member_seam.rs` prices that in
//! SOURCE BYTES READ after the refusal, never in wall clock.
//!
//! The second half of that promise is what the refusing writer is
//! OFFERED, and it is why the ring carries the source unit's write
//! boundaries alongside its bytes ([`Slab`]). A deliver unit that wrote
//! each ring buffer with one `write_all` handed a refusing writer a whole
//! ring where the sequential path handed it one chunk, which on the
//! 512 MiB member of `tests/parallel.rs` was 1,049,096 bytes against
//! 131,592: spec F 3.7.6's promise loosened eightfold by the seam, on the
//! path the seam touches. 3.7.7 says the overlap is subordinate to that
//! promise, so it is the overlap that gives way: the caller's writer sees
//! the same calls with the seam as without it, and a caller wanting
//! larger writes wraps its own writer.
//!
//! **The memory is the caller's budget and the thread is the caller's
//! width.** The ring lives INSIDE `MemoryPolicy::read_ahead` rather than
//! beside it ([`ring_plan`]), so 3.7.2's read-ahead bound is unchanged in
//! words and in value, and it counts in
//! `ExtractReport::peak_working_memory`. The thread is ONE unit of the
//! read side's thread ceiling per member in flight, counted the way
//! `tests/breadth_width.rs` counts lanes; it is a thread and not a buffer
//! budget, so it is spent out of the width and never re-derived from a
//! memory figure (SPEC-API 8.4, 8.5). A policy with no room for a ring
//! runs the member in sequence and is never an error.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};

use crate::checksum::blake2sp::Blake2sp;
use crate::crypto::{MemberDecryptor, Rar5Keys};
use crate::error::{Error, ErrorKind, Result};
use crate::read::block::{Block, FileHdr};
use crate::read::extract::{
    self, land, Codec, Decoders, Landed, Member, Out, Scratch, Tally, COPY,
};
use crate::read::walk::{Gate, MemberStream, Notes, Walk, TICK};
use crate::read::Progress;
use crate::source::Volumes;
use crate::MemoryPolicy;

/// Buffers in the ring: one the source unit is filling, one the walking
/// thread is writing. Two is the whole of the overlap - a third buys no
/// stage's worth of hiding and costs its own size in read-ahead - and it
/// is what makes the arithmetic of [`ring_plan`] a halving rather than a
/// tuning parameter.
const RING: usize = 2;

/// Members below this run in sequence.
///
/// SPEC-API 8.5 does not promise that any given member is overlapped, so
/// that a later measurement can move this without breaking a caller: "a
/// member small enough that a hand-over costs more than the stage it
/// hides is run in sequence". It is a constant and not an API fact, which
/// is exactly the licence 8.5 grants.
///
/// **MEASURED, 21 Sep 2026, an Apple M1 Mac.** It was
/// 4 MiB, which was a guess made before any ladder existed. The ladder
/// says the seam's sign turns at a gigabyte and that it turns for BOTH
/// kinds of writer there, which no smaller floor achieves:
///
/// | member | to a real file | to an in-memory `Vec` |
/// |---|---|---|
/// | 64 MiB | 1.032x | 0.767x |
/// | 256 MiB | 1.029x UNSETTLED | 0.786x |
/// | 512 MiB | 0.992x UNSETTLED | 0.789x |
/// | **1 GiB** | **1.193x** | **1.120x** |
/// | **2 GiB** | **1.199x** | **1.107x** |
///
/// A gigabyte is also the lowest TOTAL wall across that set: summed over
/// the ladder it saves 0.176 s and costs nothing, where a 512 MiB floor
/// is 0.0115 s worse and a 256 MiB floor about a wash. And it is what
/// keeps the hard gate: overlapped, `f/extract-one-stored-blake` reads
/// 0.880x and `f/test-one-stored-blake` 0.906x against the old engine on
/// the M1 Mac, agreeing with 0.937x and 0.945x on an Apple M3 Mac, which is two
/// boxes saying FAIL. Both are 64 MiB legs and this clears them with a
/// factor of sixteen.
///
/// **What it is NOT is a prediction of where the seam wins.** The engine
/// cannot see what a caller's writer costs, so size is the only dial it
/// has, and the ladder says size is not the variable that decides the
/// sign: to a real file the seam was measured winning at 64 MiB on
/// the M3 Mac. A caller-side hint that the sink is an expensive writer is
/// the honest instrument.
const SEAM_FLOOR: u64 = 1 << 30;

/// A stored member that READS INTO THE RING ([`lends`]: clear, and not
/// checked by BLAKE2sp) is overlapped from this size, and from this size
/// its reads ask the ring for a whole slab (`extract::lent`): 32 MiB.
/// Every other stored member keeps [`SEAM_FLOOR`].
///
/// [`SEAM_FLOOR`]'s ladder of 21 Sep 2026 was taken when every stored
/// member under the seam was read into a copy buffer and copied into the
/// ring. Since 29 Sep 2026 a clear CRC32 member's reads land IN the ring,
/// so the seam costs it no copy, and with a whole slab asked at each read
/// it makes an eighth of the reads and writes. Counted again on that
/// member (11 Oct 2026, one plain build drawing every floor by word, K=7
/// with a null, an Apple M5 Ultra; shipped wall over the arm's):
///
/// | member | `x` and `e` to a drive, alone | a cold set of eight |
/// |---|---|---|
/// | 4 MiB | 0.93 to 0.97 | |
/// | 16 MiB | 1.03 to 1.07 | |
/// | **32 MiB** | **1.16 to 1.20** | **1.10 to 1.13** |
/// | 64 MiB | 1.28 to 1.34 | 1.16 to 1.19 |
/// | 128 MiB | 1.42 to 1.46 | 1.08 to 1.10 |
/// | 256 MiB | 1.58 to 1.65 | 1.08 to 1.09 |
///
/// and with a writer in memory, the gate's 64 MiB member, 1.20 written
/// and 1.37 folded away. Peak resident memory rises by the ring, 8 MiB.
/// 32 MiB is the lowest floor drawn that put no row under 0.99: at every
/// size the 4 MiB member loses the hand-over.
///
/// **What it costs, named:** a writer that REFUSES is offered a whole slab
/// where it was offered 128 KiB, so `f/extract-one-stored-cancel` reads
/// 0.86 (0.15 ms, once, on an extraction that is ending).
///
/// **Why the other two kinds stay.** A member under BLAKE2sp or a cipher
/// does not read into the ring, so a lower floor gives it the hand-over
/// and nothing else: the same count read 0.92 to 0.99 on the gate's
/// 64 MiB members of those kinds.
///
/// **Windows keeps a gibibyte** until it has rows of its own: no Windows
/// box sat this count.
///
/// A measured constant and not an API fact (SPEC-API 8.5).
pub(crate) const LENT_FLOOR: u64 = if cfg!(windows) { 1 << 30 } else { 32 << 20 };

/// Whether a stored member reads into the seam's ring: it is clear and its
/// checksum is not BLAKE2sp. `clear` is the caller's, who holds the
/// member's cipher. The one test [`LENT_FLOOR`] is asked by.
pub(crate) fn lends(codec: &Codec, file: &FileHdr, clear: bool) -> bool {
    matches!(codec, Codec::Stored)
        && clear
        && !matches!(file.checksum, Some(crate::types::Checksum::Blake2sp(_)))
}

/// WRITTEN members with a DECODER below this run in sequence; at or above
/// it they are overlapped whatever the caller's writer costs, and their
/// CRC32 moves to the deliver unit ([`checksum_on_deliver`]).
///
/// [`SEAM_FLOOR`] above was measured on STORED members, whose source unit
/// is a read and a checksum and whose deliver unit is the whole of the
/// rest, so the seam there trades a copy of every byte for hiding a
/// write, and a writer in memory has nothing to hide. A compressed
/// member is the other shape: its source unit APPLIES the decoded
/// operations to the window, one serial pass over every output byte,
/// and the profile of `f/extract-m3-text64` (the
/// wide-extract work, 22 Sep 2026) puts that pass at 87 percent
/// of the leg's wall with the decode lanes idle behind it. What sat
/// beside the apply on the same thread was the member's CRC32 and the
/// caller's writer, two more passes over the same bytes, 18 percent of
/// the wall between them. Moving both behind the apply reaches the
/// apply's own floor with the one thread the seam already spends; it
/// costs one copy into the ring, which is cheaper than the two passes it
/// hides, and it costs it only above a size where a hand-over is worth
/// having.
///
/// **MEASURED at 16 MiB, and the figure is the tape path's own floor
/// for a reason** (an Apple M3 Mac, untimed, the
/// floor ladder, minima over 40 to 400 rounds, seam forced on against
/// forced off, a CRC32-folding writer): 1 MiB 0.36 against 0.33 ms,
/// 2 MiB 0.71 against 0.68, 4 MiB 1.51 against 1.48, 8 MiB 3.18 against
/// 3.15, then 16 MiB 2.97 against 3.20, 32 MiB 5.50 against 5.93, 64 MiB
/// 10.44 against 11.18. Below 16 MiB the RAR 5 decoder opens no lane
/// (`MT_MIN_OUTPUT`, carried) and decodes on one thread at about 2.5
/// GB/s, so the checksum is a small share of a member that is already
/// serial end to end, and the seam's own hand-over is the larger cost;
/// from 16 MiB the lanes are open, the apply is the wall at about 5
/// GB/s, and the seam takes 7 percent off it at every rung.
///
/// A VERIFIED member is NOT overlapped on this rule: with no writer the
/// deliver unit would hide one checksum pass behind one ring copy, and
/// the same ladder read that a wash to a loss (16 MiB 3.08 against 2.91
/// ms, 32 MiB 5.41 against 5.32, 64 MiB level).
///
/// A measured constant and not an API fact (SPEC-API 8.5): the probe
/// `rarkit-cli/examples/f_wide_probe` prices the rungs, and the section
/// named above records where the sign turns.
const COMPRESSED_FLOOR: u64 = 16 << 20;

/// The ring's buffers and the size of each, out of `read_ahead`, or `None`
/// when the policy has no room for a ring.
///
/// **Inside the budget and not beside it.** The read-ahead bound of spec F
/// 3.7.2 is how far the engine may run ahead of the byte it is delivering,
/// and under the seam the bytes held ahead are the ring's PLUS whatever
/// the decode holds - for a stored member that is the copy buffer, which
/// is itself sized from `read_ahead` (`extract::stored_copy_len`). So the
/// budget is halved: the ring takes half and the decode is run with the
/// other half as its `read_ahead`. The sum is what it was before the seam
/// existed, which is what "unchanged in words and in value" means.
///
/// A chunk below [`COPY`] is refused rather than shrunk: at that size the
/// hand-over is a larger share of the work than the stage it hides, and
/// 8.5 says a policy too small for a ring runs the member in sequence and
/// is never an error. At the default 512 MiB budget `read_ahead` is 4 MiB
/// and this gives two chunks of a megabyte.
///
/// **A member with a decoder gets the WHOLE read-ahead budget as its
/// ring.** The other half was the decode's: a stored member's copy
/// buffer is sized from `read_ahead` (`extract::stored_copy_len`), so
/// the halving keeps the two inside what 3.7.2 allows. A decoder reads
/// its packed bytes through `extract::Buffered`, which the format sizes
/// (a block's payload, and the tape path's chunk) and `read_ahead` does
/// not, so for that member the decode spends none of the budget and the
/// ring may spend all of it: two 2 MiB buffers at the default policy
/// instead of two of 1 MiB, which is half the hand-overs per byte.
///
/// **So does a clear stored member on the LENT path** (`whole`, 29 Sep
/// 2026): its reads
/// land IN the ring (`extract::lent`), so there is no copy buffer
/// for the other half to pay for, and the sum is unchanged. What it buys
/// is the write's size: the deliver unit writes one slab at a time, and
/// a disk written past the cache takes 2 MiB blocks at 10.9 GB/s where it
/// takes 1 MiB at 8.65 (a WD SN8100, `io_ceiling`).
pub(crate) fn ring_plan(read_ahead: u64, whole: bool) -> Option<(usize, usize)> {
    let total = if whole { read_ahead } else { read_ahead / 2 };
    let chunk = total / RING as u64;
    if chunk < COPY as u64 {
        return None;
    }
    Some((RING, chunk.min(usize::MAX as u64) as usize))
}

/// Whether this member is overlapped at all.
///
/// Four things have to hold, and none of them is a promise to a caller
/// (8.5): the member must be written somewhere, because the DELIVER unit
/// is the write and a `Verify` member has no stage to hide behind; it must
/// be worth a hand-over ([`SEAM_FLOOR`], or [`LENT_FLOOR`] for a stored
/// member that reads into the ring, which `lent` says; or the caller's
/// `hint` in place of either); the policy must have room for a ring ([`ring_plan`]); and the
/// width must have a unit to spend, which a width of one does not.
///
/// **`hint` is `ReadOptions::sink_is_file`, and it is the only one of the
/// four a caller sets** (SPEC-API 8.5, 21 Sep 2026). The
/// comment on [`SEAM_FLOOR`] says why it had to exist: the engine cannot
/// see what a caller's writer costs, size is the only dial it has, and
/// the ladder says size is not the variable that decides the sign. So a
/// caller that knows its writer is a real FILE gets the seam whatever the
/// member's size, the ladder having measured a file writer ahead at every
/// rung from 64 MiB to 2 GiB; a caller that says its writer is in MEMORY,
/// and a caller that says nothing at all, get the floor. `Some(false)`
/// asks the floor rather than forcing the seam off above it, so the hint
/// can only ever move the threshold the ladder measured and never
/// contradict a later measurement over the top of it.
///
/// It is a COST CLASS and nothing more. It is never verified, it decides
/// no byte and no verdict, and a caller that sets it wrongly gets a real
/// member and a worse wall. The three conditions above it are unmoved by
/// it: a `Some(true)` member with no room for a ring, or at a width of
/// one, still runs in sequence, and that is not an error.
///
/// **`width` is the READ WIDTH and not the memory budget** (API 8.4.2,
/// spec F 3.7.6's own bullet on it). The seam's source unit is one unit of
/// the read side's thread ceiling for as long as the member is in flight,
/// and that ceiling became `ReadOptions::workers` - a plain CPU figure -
/// when the width dial landed; it is `Decoders::decode_width`, which is
/// the whole read width on the walking thread and a worker's share of it
/// inside `concurrent`. Before the dial this read `MemoryPolicy::max_workers`,
/// which was the width then and is now a ceiling over BYTES that the
/// driver lowers the members in flight with. A thread is spent out of the
/// width and never re-derived from a memory figure, which is the whole of
/// what 8.4 changed.
///
/// **A member with a DECODER is the other shape** (22 Sep 2026, see
/// [`COMPRESSED_FLOOR`]): its source unit is the serial apply, which is
/// the wall, so a WRITTEN member of that shape is overlapped from a far
/// lower floor whatever the writer costs. The stored rules above are
/// unchanged for a stored member, and a `Verify` member of either shape
/// stays in sequence, measured to gain nothing from a seam.
#[allow(clippy::too_many_arguments)]
pub(crate) fn engages<W>(
    out: Option<&Out<W>>,
    file: &FileHdr,
    packed: &Block,
    policy: &MemoryPolicy,
    width: usize,
    hint: Option<bool>,
    codec: &Codec,
    lent: bool,
) -> bool {
    let decoded = decodes(codec);
    if !matches!(out, Some(Out::Write(_))) {
        return false;
    }
    if width < 2 || ring_plan(policy.read_ahead, decoded).is_none() {
        return false;
    }
    // A writer the caller has told us is a real file: the size floor is
    // not asked, because the ladder measured that writer ahead at every
    // rung it took. Below the three conditions above, which this does not
    // reach past.
    // Except for a member CONTINUING a solid chain: under the seam it
    // decodes without the chain's look-ahead, which on a solid text set
    // cost more than the overlap bought (untimed, an Apple M3 Mac, 23 Sep 2026:
    // `x` 4.51 to 4.65 s without the hint, 4.86 to 4.96 s with it;
    // the solid extract to disk). A solid chain's write overlap is the
    // sequential driver's solid path (`read::sequential`), not this.
    if hint == Some(true) && !file.solid {
        return true;
    }
    // And for the same reason under any other hint: a DECODED member
    // continuing a solid chain is never the seam's. Under `Some(false)`
    // (`p` to a stream) the size floor took every such member of 16 MiB and
    // up, which then decoded serially without the chain's look-ahead and
    // broke the look-ahead's run for the members after it: `p` of a 2 GiB
    // `-s` text set cost 0.7 s more than `t` of it at the default width
    // (measured 30 Sep 2026). A stored member has no
    // look-ahead to lose and is left to the floor.
    if decoded && file.solid && seam_leaves_chains() {
        return false;
    }
    // The declared unpacked size where the header has one, and the
    // fragment's packed bytes where it does not: both are the archive's
    // claim and neither is trusted for anything but this choice.
    let size = file
        .unpacked_size
        .unwrap_or_else(|| packed.data.end.saturating_sub(packed.data.start));
    if decoded {
        return size >= compressed_floor();
    }
    let taken = size >= floor(lent);
    #[cfg(feature = "read-depth-knob")]
    say_stored(size, taken);
    taken
}

/// COUNT ONLY (feature `read-depth-knob`, never shipped):
/// `RARKIT_SEAM_FROM_MIB`, read once, states the size from which a stored
/// member is the seam's on its size alone, in MiB, in place of
/// [`SEAM_FLOOR`]: 0 is every size, 1024 the shipped figure. So one binary
/// draws every arm of a count of where that floor belongs.
#[cfg(feature = "read-depth-knob")]
fn stored_floor_knob() -> Option<u64> {
    static MIB: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *MIB.get_or_init(|| {
        std::env::var("RARKIT_SEAM_FROM_MIB")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|mib| *mib <= 1 << 20)
            .map(|mib| mib << 20)
    })
}

/// COUNT ONLY (feature `read-depth-knob`): `RARKIT_SEAM_SAY=1` says on
/// stderr, for each written stored member asked of the size floor, its
/// size and whether the seam took it, which is how a count proves the arm
/// it drew.
#[cfg(feature = "read-depth-knob")]
fn say_stored(size: u64, taken: bool) {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *ON.get_or_init(|| std::env::var("RARKIT_SEAM_SAY").is_ok_and(|v| v.trim() == "1")) {
        eprintln!(
            "rarkit seam: stored member of {size} bytes: {}",
            if taken { "seam" } else { "in sequence" }
        );
    }
}

/// Whether a decoded member continuing a solid chain is kept off the seam
/// under every hint ([`engages`]): yes, unless `RARKIT_SEAM_SOLID` is `1`,
/// which restores the size floor for it for a measuring arm. Read once.
fn seam_leaves_chains() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| crate::knob::reader_var_os("RARKIT_SEAM_SOLID").is_none_or(|v| v != "1"))
}

/// Whether the member's source unit is an APPLY stage rather than a copy:
/// every codec but `Stored`. A `Missing` codec never reaches the seam
/// (`member` refuses it first) and answers false for want of anything to
/// overlap.
fn decodes(codec: &Codec) -> bool {
    !matches!(codec, Codec::Stored | Codec::Missing(_))
}

/// Where the member's CRC32 runs under the seam.
///
/// On the DELIVER unit, beside the write, for a member the seam takes on
/// the strength of its decoder: there the source unit's apply is the wall
/// and the deliver unit has room. On the SOURCE unit, as spec F 3.7.7
/// first wrote it, for a stored member and for a writer the caller has
/// said is a real file, where the write is the wall and the checksum
/// would only lengthen it. Nothing about the verdict moves: the same
/// bytes reach one `Crc32` in the same order, and `verdict` reads it
/// after the scope has joined.
///
/// The other checksums stay where they were. A BLAKE2sp member's hasher
/// is the operation's one state, held by the source unit; a RAR 1.3
/// member's `Sum16` is a byte loop this engine does not overlap.
fn checksum_on_deliver<W>(out: &Out<W>, hint: Option<bool>, codec: &Codec) -> bool {
    match out {
        Out::Verify => true,
        Out::Write(_) => decodes(codec) && hint != Some(true),
    }
}

/// The floor in force for a member with a decoder. The same harness knob
/// as [`floor`] moves both, so a run that turns the seam off turns
/// the whole of it off.
#[cfg(feature = "seam-knob")]
fn compressed_floor() -> u64 {
    crate::probe::seam_floor().unwrap_or(COMPRESSED_FLOOR)
}

#[cfg(not(feature = "seam-knob"))]
fn compressed_floor() -> u64 {
    COMPRESSED_FLOOR
}

/// Whether the deliver unit coalesces. A measurement harness may turn
/// this on; nothing else does, and it is never on in a shipped build.
#[cfg(feature = "seam-knob")]
fn coalescing() -> bool {
    crate::probe::seam_coalesce()
}

#[cfg(not(feature = "seam-knob"))]
fn coalescing() -> bool {
    false
}

/// The floor in force for a stored member, which reads into the ring or
/// does not (`lent`). A test harness may move it, and a count build's
/// word ([`stored_floor_knob`]), for both kinds at once; nothing else
/// does.
fn floor(lent: bool) -> u64 {
    #[cfg(feature = "seam-knob")]
    if let Some(bytes) = crate::probe::seam_floor() {
        return bytes;
    }
    #[cfg(feature = "read-depth-knob")]
    if let Some(bytes) = stored_floor_knob() {
        return bytes;
    }
    if lent {
        LENT_FLOOR
    } else {
        SEAM_FLOOR
    }
}

/// The stop flag both units read.
///
/// One bit, `Relaxed` on both sides: it is a hint that becomes a
/// certainty at the join, and nothing is ordered against it except the
/// ring's own channels, which carry their own ordering.
struct Stop(AtomicBool);

impl Stop {
    fn set(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    fn raised(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// One buffer of the ring, and the write boundaries that made it.
///
/// **Why the boundaries travel with the bytes.** The DELIVER unit must
/// hand the caller's writer the same slices the decoder handed the
/// sequential path, and not one big one. A refusing writer is offered
/// exactly what refuses it, so coalescing a ring's worth of the decoder's
/// writes into a single `write_all` would offer a refusing writer a whole
/// ring where the sequential path offered it one chunk - which is spec F
/// 3.7.6's promise loosened by the size of the ring, and 3.7.7 says the
/// overlap is subordinate to that promise. `marks` holds the END offset
/// within `buf` of each of the source unit's writes, so the deliver unit
/// replays them one for one.
///
/// A caller that WANTS larger writes wraps its own writer, which it can
/// do today and which the engine must not do for it.
///
/// Kept in `Scratch::ring` between members rather than allocated per
/// member: a megabyte buffer is a fresh mapping each time and its pages
/// fault in on the source unit's critical path, which is an allocation
/// per member (spec F 7.3.5) once the seam engages on members of
/// ordinary size.
pub(crate) struct Slab {
    buf: Vec<u8>,
    /// Where the slab's bytes start in `buf`, and where every mark counts
    /// from: 0 for a written slab, the first [`SLAB_ALIGN`] boundary for a
    /// lent one (see the lent path's `impl RingOut`).
    at: usize,
    /// `u64` and not `u32`: a chunk is `read_ahead / 4`, and a caller may
    /// set `read_ahead` to anything, so a mark is not assumed to fit in
    /// four bytes. Two slabs of these cost sixteen kilobytes, which is
    /// counted against the budget beside the chunks themselves.
    marks: Vec<u64>,
}

impl Slab {
    /// The bytes this slab holds, its marks included: what an idle slab
    /// kept in the operation's scratch is charged at.
    pub(crate) fn held_bytes(&self) -> u64 {
        (self.buf.capacity() + self.marks.capacity() * std::mem::size_of::<u64>()) as u64
    }
}

impl Slab {
    /// The wake a volume crossing sends (`walk::Notes`): no marks, which
    /// no hand-over ever sends, and no allocation.
    pub(crate) fn marker() -> Slab {
        Slab {
            buf: Vec::new(),
            at: 0,
            marks: Vec::new(),
        }
    }
}

/// The boundary a lent slab's bytes start on.
///
/// A stored member's packed read lands in the lent slab, so the slab is
/// the destination of the kernel's page-cache copy. On Zen 4 (kernel 6.8)
/// that copy runs about four times slower per byte whenever the
/// destination's offset in its page is 1 to 15 bytes AHEAD of the
/// source's, and nowhere else. A slab is a fresh `mmap` from glibc whose
/// bytes start 16 past a page, and the stored readers read at offsets 8
/// past one, so every byte of a stored `x` fell in that band: 7.99 of
/// 8 GiB on the stored posting set, 1.44 CPU seconds of `sys`. Starting
/// the lent bytes on a page puts the difference at -8, outside it
/// (the Zen 4 copy band).
const SLAB_ALIGN: usize = 4096;

/// Write boundaries recorded per ring buffer before it is handed over
/// early.
///
/// The cap is what keeps `marks` from becoming unbounded working memory
/// under a decoder that writes a byte at a time: at that point the buffer
/// goes over whatever it holds. Nothing this engine decodes comes near
/// it, the smallest write the read path makes being [`COPY`], so a
/// megabyte chunk fills after sixteen marks; and it costs eight kilobytes
/// a slab.
const MARKS: usize = 1024;

/// The source unit's end of the ring: the writer a decoder's output goes
/// into, chunked and handed to the walking thread.
///
/// Every hand-over is a buffer boundary and every buffer boundary reads
/// [`Stop`], which is the whole of the cancellation bound: after the flag
/// is set this fills at most the buffer it is holding and then refuses.
/// The refusal is an `io::Error`, which the engine reads as the caller's
/// (see `Error::from`), and the walking thread's own error is the one
/// that is reported: a caller error and a source error raised in the same
/// member do not race, and the caller's wins (8.5).
struct RingOut<'a> {
    full: SyncSender<Slab>,
    empty: Receiver<Slab>,
    stop: &'a Stop,
    current: Option<Slab>,
    chunk: usize,
    /// Deliver each ring buffer with ONE write instead of replaying the
    /// source unit's boundaries. A measurement knob, never the shipped
    /// answer: see [`crate::probe::set_seam_coalesce`]. It restores the
    /// shape that loosened spec F 3.7.6's refusal bound, so the wall that
    /// shape was buying can be priced against the one that ships, with
    /// ONE BINARY against itself rather than two shas.
    coalesce: bool,
}

/// What a refusal after the stop flag looks like from inside a decoder.
fn stopped() -> io::Error {
    io::Error::other("the member's delivery unit stopped")
}

impl RingOut<'_> {
    /// The next empty buffer, or the stop.
    ///
    /// **A coalesced slab's bytes start on a page** (spec F 3.7.7):
    /// it is cut by count, `chunk` bytes at a
    /// time, so each lands at a slab-aligned offset of the member, and
    /// starting its bytes on a [`SLAB_ALIGN`] boundary of the buffer makes
    /// its address aligned too, which is what lets a writer past the OS
    /// cache take it straight from the ring. The lead is zeros the deliver
    /// unit never reaches (it slices from `at`), inside the
    /// `chunk + SLAB_ALIGN` the slab was allocated with, so the buffer never
    /// grows and never moves. A slab whose boundaries are replayed keeps
    /// its bytes at 0, as on main.
    fn take(&mut self) -> io::Result<Slab> {
        if self.stop.raised() {
            return Err(stopped());
        }
        match self.empty.recv() {
            Ok(mut slab) => {
                slab.buf.clear();
                slab.at = 0;
                slab.marks.clear();
                if self.coalesce {
                    // `align_offset` may in principle answer that it
                    // cannot; the slab is then merely unaligned, never wrong.
                    slab.at = match slab.buf.as_ptr().align_offset(SLAB_ALIGN) {
                        at if at < SLAB_ALIGN => at,
                        _ => 0,
                    };
                    slab.buf.resize(slab.at, 0);
                }
                Ok(slab)
            }
            // The walking thread is gone, which is a stop by another name.
            Err(_) => Err(stopped()),
        }
    }

    /// Hand the buffer being filled over, if it holds anything.
    fn hand_over(&mut self) -> io::Result<()> {
        let Some(slab) = self.current.take() else {
            return Ok(());
        };
        let mut slab = slab;
        let held = slab.buf.len() - slab.at;
        if held == 0 {
            self.current = Some(slab);
            return Ok(());
        }
        // A coalescing deliver unit records no boundaries as it fills, so
        // the whole buffer is one write on the other side.
        if slab.marks.is_empty() {
            slab.marks.push(held as u64);
        }
        if self.stop.raised() {
            return Err(stopped());
        }
        if self.full.send(slab).is_err() {
            return Err(stopped());
        }
        Ok(())
    }

    /// The buffer being filled, taking a fresh one where there is none.
    fn slab(&mut self) -> io::Result<&mut Slab> {
        if self.current.is_none() {
            self.current = Some(self.take()?);
        }
        Ok(self.current.as_mut().expect("filled above"))
    }
}

impl Write for RingOut<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        // A write is not SPLIT across two ring buffers while it would fit
        // whole in the next one, because the deliver unit replays these
        // boundaries into the caller's writer and a split boundary is a
        // boundary the sequential path did not have. A write larger than
        // a whole chunk is the one case that has to be split, and it only
        // ever offers a refusing writer LESS than the sequential path
        // did.
        // Counted from the slab's `at`, which is 0 unless it coalesces
        // (see `take`).
        let chunk = self.chunk;
        let keep = !self.coalesce;
        let slab = self.slab()?;
        let held = slab.buf.len() - slab.at;
        if keep && held > 0 && (held + data.len() > chunk || slab.marks.len() >= MARKS) {
            self.hand_over()?;
        }
        let slab = self.slab()?;
        let room = chunk.saturating_sub(slab.buf.len() - slab.at).max(1);
        let take = data.len().min(room);
        slab.buf.extend_from_slice(&data[..take]);
        let held = slab.buf.len() - slab.at;
        if keep {
            slab.marks.push(held as u64);
        }
        if held >= chunk || (keep && slab.marks.len() >= MARKS) {
            self.hand_over()?;
        }
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.hand_over()
    }
}

/// The source unit's tally: the cancel flag and the stop flag, once per
/// [`TICK`] of output.
///
/// `Progress` is NOT reported from here and cannot be: it belongs to the
/// thread that called `extract` (8.5). The walking thread reports it for
/// the bytes it has DELIVERED, which is the number a caller watching a
/// progress bar wants anyway.
struct Pump<'a> {
    cancel: Option<&'a AtomicBool>,
    stop: &'a Stop,
    since: u64,
}

impl Tally for Pump<'_> {
    fn output(&mut self, n: usize) -> Result<()> {
        self.since += n as u64;
        if self.since >= TICK {
            self.since = 0;
            if self.stop.raised() {
                return Err(Error::new(ErrorKind::Cancelled));
            }
            if self.cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                return Err(Error::new(ErrorKind::Cancelled));
            }
        }
        Ok(())
    }
}

/// Everything one member's decode needs that does not come from the walk.
pub(crate) struct Work {
    pub(crate) codec: Codec,
    pub(crate) decryptor: Option<MemberDecryptor>,
    pub(crate) keys: Option<Rar5Keys>,
    /// The member continues a solid chain, or begins one.
    pub(crate) continues: bool,
}

/// What the walking thread is left holding once one overlapped member has
/// stopped, whichever unit stopped it.
pub(crate) struct Overlapped<W> {
    pub(crate) landed: Landed,
    pub(crate) member: Member<W>,
}

/// What [`overlapped`] did with a member.
///
/// Moved once per member and matched at once, so the size difference
/// between the two is not worth an allocation per member to even out.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Seamed<W> {
    /// It ran, on the seam.
    Ran(Overlapped<W>),
    /// The host would not start the source unit's thread, so nothing ran:
    /// the caller's output and the work come back as they were given, for
    /// the member's ordinary path on this thread (`crate::threads`).
    NoThread { out: Out<W>, work: Work },
}

/// Run one member with its read, decrypt and decode on a scoped thread and
/// its WRITE here, with its CRC32 on whichever unit
/// [`checksum_on_deliver`] names.
///
/// The scope joins before this returns, so nothing of the member outlives
/// the call and `extract` cannot return with a thread still reading.
#[allow(clippy::too_many_arguments)]
pub(crate) fn overlapped<V: Volumes, W: Write, P: Progress>(
    walk: &mut Walk<'_, V>,
    gate: &Gate<'_, P>,
    block: &Block,
    file: &FileHdr,
    name: &[u8],
    format: crate::read::Format,
    mut out: Out<W>,
    hint: Option<bool>,
    work: Work,
    blake: &mut Option<Box<Blake2sp>>,
    decoders: &mut Decoders,
    scratch: &mut Scratch,
    policy: &MemoryPolicy,
    bytes: &mut u64,
    output_since_tick: &mut u64,
    cancel: Option<&AtomicBool>,
) -> Result<Seamed<W>> {
    let decoded = decodes(&work.codec);
    // A clear stored member READS INTO THE RING (`extract::lent`), so it
    // holds no copy buffer beside the ring and the ring may take the whole
    // read-ahead budget, as a member with a decoder does (`ring_plan`).
    let lent = matches!(work.codec, Codec::Stored) && blake.is_none() && work.decryptor.is_none();
    let (buffers, chunk) =
        ring_plan(policy.read_ahead, decoded || lent).expect("`engages` checked the policy");
    // A lent stored member's request of the ring, decided here on the
    // walking thread from the operation's own read-ahead (`extract::lent`).
    // A WHOLE-SLAB request fills each slab across its reads and hands it
    // over as ONE write, so the deliver unit's writes are whole slabs at
    // slab-aligned offsets of the member: what a writer past the OS cache
    // takes straight from the buffer.
    let lent_request =
        extract::lent::request(file.unpacked_size, blake.is_some(), policy.read_ahead, lent);
    // A member with a DECODER whose declared size asks for whole slabs (the
    // same floor and the same dial as the lent request's, 1 GiB) is cut the
    // same way: its window's drain pieces, about 1 MiB and never on a page
    // of the member, are packed into page-aligned slabs of exactly `chunk`
    // and each slab is ONE write, so an unbuffered writer takes every byte
    // but the tail straight from the ring (spec F 3.7.7). The
    // pieces' boundaries are the window's cadence and not a read's, so
    // nothing but the refusal bound moves, and it moves to the one slab a
    // stored member of that size already offers.
    let whole_slabs = lent_request == usize::MAX && (lent || decoded);
    let crc_here = checksum_on_deliver(&out, hint, &work.codec);
    // The decode runs with the OTHER half of the read-ahead budget, so
    // the ring and whatever the decode holds together stay inside what
    // spec F 3.7.2 allows (see `ring_plan`).
    let mut inner = *policy;
    // The marks are working memory too, small beside a chunk and counted
    // rather than ignored, so the ring and the decode together still come
    // to what the read-ahead budget was before the seam existed.
    let slab_bytes = (chunk + SLAB_ALIGN) as u64 + (MARKS * std::mem::size_of::<u64>()) as u64;
    let ring_bytes = (buffers as u64) * slab_bytes;
    inner.read_ahead = policy.read_ahead.saturating_sub(ring_bytes);

    // The ring is working memory like any other and reaches the caller
    // through `ExtractReport::peak_working_memory` (8.5): charged to the
    // counters for as long as the seam runs, which is the figure the
    // operation's meter reports.
    let peak_before = scratch.ring_peak;
    scratch.ring_peak = scratch.ring_peak.max(ring_bytes);
    let mut _ring_charge = crate::memory::Held::default();
    _ring_charge.set(ring_bytes);

    let stop = Stop(AtomicBool::new(false));
    let (full_tx, full_rx) = sync_channel::<Slab>(buffers);
    let notes = Notes::waking(full_tx.clone());
    let (empty_tx, empty_rx) = sync_channel::<Slab>(buffers);
    for _ in 0..buffers {
        // The operation's own slabs first, sized for THIS member's chunk
        // (a policy does not change inside an operation, so they fit);
        // fresh ones only when there are none to reuse.
        // Room for the lent path's boundary too, so aligning a slab never
        // grows it past its first allocation.
        let mut slab = scratch.ring.pop().unwrap_or_else(|| Slab {
            buf: Vec::with_capacity(chunk + SLAB_ALIGN),
            at: 0,
            marks: Vec::with_capacity(MARKS),
        });
        slab.buf.clear();
        slab.at = 0;
        slab.buf.reserve(chunk + SLAB_ALIGN);
        slab.marks.clear();
        empty_tx
            .send(slab)
            .expect("the receiver is alive and the channel holds them all");
    }

    let Work {
        codec,
        decryptor,
        keys,
        continues,
    } = work;
    let mut member = Member::of(
        Some(Out::Write(RingOut {
            full: full_tx,
            empty: empty_rx,
            stop: &stop,
            current: None,
            chunk,
            coalesce: coalescing() || whole_slabs,
        })),
        file,
        format,
        keys.clone(),
        blake,
        crate::read::extract::blake_workers(policy, decoders),
    );
    // The CRC32 the deliver unit runs in the source unit's place, when
    // that is where it belongs: the source unit's member then folds
    // nothing, and the state is handed back to it after the join.
    let mut crc = crc_here.then(|| member.detach_crc()).flatten();

    let stream = MemberStream::new(walk, &notes, block, file, name);
    stream.check_leading_fragment()?;

    // The source unit borrows the scratch buffers for the length of the
    // scope and this thread wants them back for the landing, so the
    // reborrow is written out: it ends with the block and not with the
    // call.
    // Where the host would not start the source unit (`crate::threads`),
    // the cipher and the codec come back here, untouched.
    let mut no_thread: Option<(Codec, Option<MemberDecryptor>)> = None;
    let seamed = {
        let scratch = &mut *scratch;
        let no_thread = &mut no_thread;
        std::thread::scope(|scope| {
            let stop_ref = &stop;
            let notes_ref = &notes;
            let inner_policy = inner;
            // The operation's meter follows its threads (API 8.4.1, `memory::Meter`).
            let op = crate::memory::op_slot();
            let state = (stream, member, codec, decryptor, blake, decoders, scratch);
            let started = crate::threads::scoped_with(scope, state, move |state| {
                let (mut stream, mut member, codec, decryptor, blake, decoders, scratch) = state;
                let _op = crate::memory::enter(op);
                // The ring's second sender goes when this unit does, even
                // by a panic, or the deliver loop would wait for ever.
                struct Unhook<'n>(&'n Notes);
                impl Drop for Unhook<'_> {
                    fn drop(&mut self) {
                        self.0.unhook();
                    }
                }
                let _unhook = Unhook(notes_ref);
                // One unit of the read side's thread ceiling, for as long as
                // this member is in flight (8.5). Counted rather than
                // inferred, the way `probe::LaneGuard` counts a tape lane.
                #[cfg(feature = "test-support")]
                let _unit = crate::probe::SeamGuard::enter();
                let mut pump = Pump {
                    cancel,
                    stop: stop_ref,
                    since: 0,
                };
                // A clear stored member READS INTO THE RING, through the
                // one out-of-line entry of `extract::lent`.
                let ran = if matches!(codec, Codec::Stored)
                    && extract::lent::lends(&member, decryptor.is_some())
                {
                    extract::lent::decode_lent(
                        &mut stream,
                        &mut member,
                        blake,
                        &mut pump,
                        decryptor,
                        decoders,
                        lent_request,
                    )
                } else {
                    extract::decode(
                        &mut stream,
                        &mut member,
                        blake,
                        &mut pump,
                        decryptor,
                        codec,
                        decoders,
                        scratch,
                        &inner_policy,
                        continues,
                        // The seam runs a member on its own thread with its own
                        // walk position; the solid chain's lookahead is the
                        // walking thread's and is not offered from here.
                        None,
                    )
                };
                // The buffer being filled when the member ended still has
                // to reach the walking thread, and the ring's SENDER has
                // to be dropped for that thread's loop to end at all: a
                // member carrying it back through the join leaves the
                // deliver unit waiting on a channel nothing will ever
                // close, which is a deadlock and not a slow member. So
                // the flush and the drop both happen HERE, on the unit
                // that owns them, and the member travels back with no
                // output at all - `retarget` gives it the caller's own
                // writer on the other side.
                let ran = ran.and_then(|()| match &mut member.out {
                    Some(Out::Write(w)) => Ok(w.flush()?),
                    _ => Ok(()),
                });
                // The ring's SENDER goes here, which is what ends the
                // deliver loop; its RECEIVER and the buffer in hand travel
                // back through the join, so every slab the deliver unit
                // hands back after this point is still received and none
                // is lost to a closed channel.
                let leftovers = match member.out.take() {
                    Some(Out::Write(RingOut { empty, current, .. })) => Some((empty, current)),
                    _ => None,
                };
                (stream, member, ran, leftovers)
            });
            let source = match started {
                Ok(source) => source,
                Err((stream, mut member, codec, decryptor, _, _, scratch)) => {
                    // Nothing was read: the stream only borrowed the walk,
                    // and the slabs go back to the operation's scratch.
                    drop(stream);
                    if let Some(Out::Write(RingOut { empty, current, .. })) = member.out.take() {
                        scratch.ring.extend(current);
                        scratch.ring.extend(empty.try_iter());
                    }
                    *no_thread = Some((codec, decryptor));
                    return None;
                }
            };

            // THE DELIVER UNIT, on this thread: full buffers in order into the
            // caller's own writer, with the drop-behind news the source unit
            // made relayed alongside them.
            let mut delivered = 0u64;
            let mut refused: Option<Error> = None;
            while let Ok(slab) = full_rx.recv() {
                // A volume crossing's wake (`Notes::crossing`): relay the
                // news now, before the source unit asks for the next
                // volume, and answer it whatever happened.
                if slab.marks.is_empty() {
                    let relayed = refused.is_none()
                        && match notes.drain_into(gate) {
                            Ok(()) => true,
                            Err(e) => {
                                stop.set();
                                refused = Some(e);
                                false
                            }
                        };
                    notes.reply(relayed);
                    continue;
                }
                if refused.is_none() {
                    let mut step = || -> Result<()> {
                        notes.drain_into(gate)?;
                        // ONE WRITE PER WRITE THE SOURCE UNIT MADE, in
                        // order, which is what keeps spec F 3.7.6's
                        // refusal bound at the value the sequential path
                        // has: a refusing writer is offered the slice
                        // that refuses it and not the ring around it
                        // (see [`Slab`]).
                        let mut from = 0usize;
                        for &mark in &slab.marks {
                            let upto = mark as usize;
                            let piece = &slab.buf[slab.at + from..slab.at + upto];
                            from = upto;
                            if let Some(crc) = &mut crc {
                                crc.update(piece);
                            }
                            if let Out::Write(w) = &mut out {
                                w.write_all(piece)?;
                            }
                            delivered += piece.len() as u64;
                            *bytes += piece.len() as u64;
                            *output_since_tick += piece.len() as u64;
                            if *output_since_tick >= TICK {
                                *output_since_tick = 0;
                                gate.borrow_mut().output(*bytes)?;
                                if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                                    return Err(Error::new(ErrorKind::Cancelled));
                                }
                            }
                        }
                        Ok(())
                    };
                    if let Err(e) = step() {
                        // STOP THE WORK, not merely the call (3.7.7). The
                        // source unit reads this at its next buffer boundary.
                        stop.set();
                        refused = Some(e);
                    }
                }
                // Handed back whatever happened, so a source unit blocked on
                // an empty buffer wakes up and sees the flag rather than
                // waiting for a reader that has given up.
                let _ = empty_tx.send(slab);
            }

            let (stream, mut member, ran, leftovers) = match source.join() {
                Ok(answer) => answer,
                Err(panic) => std::panic::resume_unwind(panic),
            };
            if let Some(crc) = crc.take() {
                member.attach_crc(crc);
            }
            let ran = match refused {
                // The CALLER's error wins over anything the source unit met
                // in the same member (8.5), and the bytes the member reports
                // are the ones that reached the writer.
                Some(e) => {
                    member.written = delivered;
                    Err(e)
                }
                None => ran,
            };
            Some((stream, member, ran, leftovers))
        })
    };
    let Some((stream, member, ran, leftovers)) = seamed else {
        let (codec, decryptor) = no_thread.expect("set wherever the source unit was refused");
        // The ring was never used, so it is not the operation's peak.
        scratch.ring_peak = peak_before;
        return Ok(Seamed::NoThread {
            out,
            work: Work {
                codec,
                decryptor,
                keys,
                continues,
            },
        });
    };

    // The slabs come back to the operation: the deliver loop above handed
    // every one it took back through `empty_tx`, whose receiver is in
    // hand, and the source unit's buffer in hand is the last of them.
    drop(empty_tx);
    if let Some((empty, current)) = leftovers {
        scratch.ring.extend(current);
        scratch.ring.extend(empty.try_iter());
    }

    // The ring's writer is finished with; the member carries the caller's
    // own writer from here, as it does on the sequential path, so `close`
    // is handed the same value.
    let landed = land(stream, ran, scratch);
    let member = member.retarget(Some(out));

    // Nothing the source unit reported is left unrelayed, and it is
    // relayed BEFORE the walk's own release of the member's last fragment,
    // so `released` reaches the observer in order (3.7.3).
    notes.drain_into(gate)?;
    Ok(Seamed::Ran(Overlapped { landed, member }))
}

/// The ring's side of the lent stored path (`extract::lent`), kept apart
/// from `write`, `take` and `hand_over` so that the path every decoder
/// writes through is the control's own text.
///
/// **A lent slab is a whole chunk long and its fill is its last mark.**
/// `write`'s slabs are grown by `extend_from_slice` from empty; a read
/// cannot land in bytes that do not exist yet, so a lent slab is grown to
/// the chunk ONCE, the first time this path takes it in an operation, and
/// then kept at that length: the deliver unit only ever slices up to the
/// marks, so the tail it never reaches is never seen. Growing it zeroes it,
/// once per slab and not once per read.
///
/// **A lent slab's bytes start on a page.** It is grown to a chunk and
/// [`SLAB_ALIGN`] more, and its bytes and marks count from the first
/// boundary inside it (`Slab::at`), so no `unsafe` is needed and no byte
/// moves. A short read shifts the next lend off the boundary and the next
/// read's file offset by the same amount, so the copy's page offsets keep
/// their difference.
///
/// **The caller's writer sees the same calls.** Each committed read is one
/// mark, as each `write` of that read was, and a slab is handed over before
/// a lend whenever the whole REQUEST would not fit: `write`'s own rule,
/// asked of the request rather than of the bytes that came back. A short
/// read can only end a slab EARLIER than `write` would have, which moves
/// where the deliver unit wakes and never what a refusing writer is
/// offered. Under the coalescing knob the one mark is moved forward rather
/// than added to, so the deliver unit still makes one write per slab.
impl RingOut<'_> {
    /// The slab being lent from, taking one where there is none.
    fn lent_slab(&mut self) -> io::Result<&mut Slab> {
        if self.current.is_none() {
            if self.stop.raised() {
                return Err(stopped());
            }
            let mut slab = match self.empty.recv() {
                Ok(slab) => slab,
                Err(_) => return Err(stopped()),
            };
            slab.marks.clear();
            if slab.buf.len() < self.chunk + SLAB_ALIGN {
                slab.buf.resize(self.chunk + SLAB_ALIGN, 0);
            }
            // `align_offset` may in principle answer that it cannot; the
            // slab is then merely unaligned, never wrong.
            slab.at = match slab.buf.as_ptr().align_offset(SLAB_ALIGN) {
                at if at < SLAB_ALIGN => at,
                _ => 0,
            };
            self.current = Some(slab);
        }
        Ok(self.current.as_mut().expect("filled above"))
    }

    /// Hand the lent slab over if it holds a committed byte.
    fn lent_hand_over(&mut self) -> io::Result<()> {
        let Some(slab) = self.current.take() else {
            return Ok(());
        };
        if slab.marks.is_empty() {
            self.current = Some(slab);
            return Ok(());
        }
        if self.stop.raised() {
            return Err(stopped());
        }
        if self.full.send(slab).is_err() {
            return Err(stopped());
        }
        Ok(())
    }
}

/// How much of a lent slab holds the member's bytes.
fn filled(slab: &Slab) -> usize {
    slab.marks.last().map_or(0, |&m| m as usize)
}

impl extract::lent::Lend for RingOut<'_> {
    fn lend(&mut self, want: usize) -> io::Result<&mut [u8]> {
        let chunk = self.chunk;
        // A request beyond the chunk asks for WHOLE SLABS
        // (`extract::lent::request`): the rest of this one, however much
        // of it the reads before filled, and never a hand-over short of
        // full. An ordinary request keeps `write`'s rule below.
        let whole = want >= chunk;
        let keep = !self.coalesce && !whole;
        let slab = self.lent_slab()?;
        let fill = filled(slab);
        if keep && fill > 0 && (fill + want > chunk || slab.marks.len() >= MARKS) {
            self.lent_hand_over()?;
        }
        let slab = self.lent_slab()?;
        let fill = filled(slab);
        let n = want.min(chunk - fill);
        let at = slab.at + fill;
        Ok(&mut slab.buf[at..at + n])
    }

    fn commit(&mut self, n: usize) -> io::Result<()> {
        if n == 0 {
            return Ok(());
        }
        let chunk = self.chunk;
        let keep = !self.coalesce;
        let slab = self.lent_slab()?;
        let fill = filled(slab) + n;
        match slab.marks.last_mut() {
            Some(last) if !keep => *last = fill as u64,
            _ => slab.marks.push(fill as u64),
        }
        if fill >= chunk || (keep && slab.marks.len() >= MARKS) {
            self.lent_hand_over()?;
        }
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        self.lent_hand_over()?;
        // A slab left in hand holds no committed byte; emptied, so that
        // `write`'s own `flush` after the member finds nothing to send, and
        // counted from 0 again, which is where `write` puts its bytes.
        if let Some(slab) = self.current.as_mut() {
            slab.buf.clear();
            slab.at = 0;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read::extract::lent::Lend;

    /// The ring's plan: a stored member that copies out of the ring gets
    /// half the read-ahead in two slabs, a member with a decoder or a lent
    /// stored member gets the whole of it, and a policy with no room for a
    /// chunk of [`COPY`] gets no ring.
    #[test]
    fn the_ring_takes_half_or_the_whole_read_ahead() {
        assert_eq!(ring_plan(4 << 20, false), Some((2, 1 << 20)));
        assert_eq!(ring_plan(4 << 20, true), Some((2, 2 << 20)));
        assert_eq!(ring_plan(8 << 20, true), Some((2, 4 << 20)));
        assert_eq!(ring_plan(COPY as u64 * 2, true), Some((2, COPY)));
        assert_eq!(ring_plan(COPY as u64 * 2, false), None);
    }

    /// Every slab the ring handed over, as (bytes, marks), after `drive`
    /// has written or lent into a fresh two-slab ring of `chunk`.
    fn slabs(chunk: usize, drive: impl FnOnce(&mut RingOut<'_>)) -> Vec<(Vec<u8>, Vec<u64>)> {
        slabs_of(chunk, false, drive)
            .into_iter()
            .map(|(bytes, marks, _)| (bytes, marks))
            .collect()
    }

    /// `slabs` with the coalescing deliver unit on or off, and each slab's
    /// bytes' address modulo [`SLAB_ALIGN`] beside it. The slabs are
    /// allocated as `overlapped` allocates them, a chunk and a page long.
    fn slabs_of(
        chunk: usize,
        coalesce: bool,
        drive: impl FnOnce(&mut RingOut<'_>),
    ) -> Vec<(Vec<u8>, Vec<u64>, usize)> {
        let stop = Stop(AtomicBool::new(false));
        let (full_tx, full_rx) = sync_channel::<Slab>(8);
        let (empty_tx, empty_rx) = sync_channel::<Slab>(8);
        for _ in 0..8 {
            let slab = Slab {
                buf: Vec::with_capacity(chunk + SLAB_ALIGN),
                at: 0,
                marks: Vec::new(),
            };
            empty_tx.send(slab).expect("room for every slab");
        }
        let mut ring = RingOut {
            full: full_tx,
            empty: empty_rx,
            stop: &stop,
            current: None,
            chunk,
            coalesce,
        };
        drive(&mut ring);
        ring.flush().expect("the ring flushes");
        drop(ring);
        full_rx
            .try_iter()
            .map(|slab| {
                // A written slab's bytes are its length, a lent one's its
                // last mark (its buffer is a whole chunk long).
                let end = slab.marks.last().map_or(slab.buf.len(), |&m| m as usize);
                let bytes = &slab.buf[slab.at..slab.at + end];
                let lead = bytes.as_ptr() as usize % SLAB_ALIGN;
                (bytes.to_vec(), slab.marks, lead)
            })
            .collect()
    }

    /// THE CALLER'S WRITER SEES THE SAME CALLS. A stored member's reads
    /// lent into the ring must hand the deliver unit the same bytes cut at
    /// the same marks as those reads written into it, short reads (a
    /// volume's end) included: the marks are what a refusing writer is
    /// offered (spec F 3.7.6), and the lent path exists only to remove the
    /// copy between.
    #[test]
    fn lent_reads_give_the_deliver_unit_the_marks_writes_give() {
        let chunk = 64 * 1024;
        let want = 16 * 1024;
        // Full requests, a short one mid-slab, and a run past two slabs.
        let reads: Vec<usize> = [want, want, 5_000, want, want, want, 1, want, want]
            .into_iter()
            .chain(std::iter::repeat_n(want, 7))
            .collect();
        let payload: Vec<u8> = (0..reads.iter().sum::<usize>())
            .map(|i| (i * 7 + i / 251) as u8)
            .collect();

        let written = slabs(chunk, |ring| {
            let mut at = 0;
            for &n in &reads {
                ring.write_all(&payload[at..at + n]).expect("write");
                at += n;
            }
        });
        let lent = slabs(chunk, |ring| {
            let mut at = 0;
            for &n in &reads {
                let region = ring.lend(want).expect("lend");
                assert!(
                    region.len() >= n,
                    "a lend is the whole request while it fits"
                );
                region[..n].copy_from_slice(&payload[at..at + n]);
                ring.commit(n).expect("commit");
                at += n;
            }
            ring.finish().expect("finish");
        });

        let pieces = |slabs: &[(Vec<u8>, Vec<u64>)]| -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            for (bytes, marks) in slabs {
                let mut from = 0;
                for &m in marks {
                    out.push(bytes[from..m as usize].to_vec());
                    from = m as usize;
                }
            }
            out
        };
        assert_eq!(pieces(&written), pieces(&lent));
        assert_eq!(pieces(&lent).concat(), payload);
    }

    /// THE PAGE BOUNDARY, LENT: a stored member's read lands on a page. Every
    /// lend that starts a slab, or follows only whole-page reads, starts on
    /// a [`SLAB_ALIGN`] boundary by address, the ring's slabs being fresh
    /// allocations like the engine's; and the bytes are the ones written.
    #[test]
    fn a_lent_region_starts_on_a_4_kib_boundary() {
        let chunk = 256 * 1024;
        let want = 64 * 1024;
        let mut seen = 0;
        let payload: Vec<u8> = (0..20 * want).map(|i| (i * 13 + i / 509) as u8).collect();
        let lent = slabs(chunk, |ring| {
            for piece in payload.chunks(want) {
                let region = ring.lend(want).expect("lend");
                assert!(
                    (region.as_ptr() as usize).is_multiple_of(SLAB_ALIGN),
                    "lend {seen} starts {} past a page",
                    region.as_ptr() as usize % SLAB_ALIGN
                );
                region[..piece.len()].copy_from_slice(piece);
                ring.commit(piece.len()).expect("commit");
                seen += 1;
            }
            // A short read moves the next lend off the page by its length,
            // as it moves the next read's file offset.
            let region = ring.lend(want).expect("lend");
            region[..100].fill(1);
            ring.commit(100).expect("commit");
            let region = ring.lend(want).expect("lend");
            assert_eq!((region.as_ptr() as usize) % SLAB_ALIGN, 100);
            region[..1].fill(2);
            ring.commit(1).expect("commit");
            ring.finish().expect("finish");
        });
        assert_eq!(seen, 20);
        let bytes: Vec<u8> = lent.into_iter().flat_map(|(b, _)| b).collect();
        assert_eq!(&bytes[..payload.len()], &payload[..]);
        assert_eq!(
            &bytes[payload.len()..],
            &[&[1u8; 100][..], &[2u8]].concat()[..]
        );
    }

    /// A slab the lent path used and `finish` left in hand is written into
    /// from its start again: its bytes reach the deliver unit whole.
    #[test]
    fn a_slab_written_after_a_lent_member_counts_from_its_start() {
        let chunk = 64 * 1024;
        let got = slabs(chunk, |ring| {
            let region = ring.lend(4096).expect("lend");
            region.fill(9);
            ring.commit(4096).expect("commit");
            ring.finish().expect("finish");
            // The lent slab went over at `finish`; lend again and commit
            // nothing, so one lent slab stays in hand, then write.
            let _ = ring.lend(4096).expect("lend");
            ring.finish().expect("finish");
            ring.write_all(b"written after").expect("write");
        });
        let bytes: Vec<u8> = got.into_iter().flat_map(|(b, _)| b).collect();
        assert_eq!(&bytes[..4096], &[9u8; 4096][..]);
        assert_eq!(&bytes[4096..], b"written after");
    }

    /// SPEC F 3.7.7: a member with a decoder, on the coalescing
    /// deliver unit, reaches the deliver unit as WHOLE page-aligned slabs.
    /// The window's drain pieces are about a megabyte, run past the cadence
    /// by an overshoot and are cut where the ring wraps, down to a few
    /// bytes; packed by count, every slab but the last is exactly `chunk`
    /// with ONE mark, its bytes start on a [`SLAB_ALIGN`] boundary, and the
    /// bytes are the pieces' in order. Replayed instead, the same pieces
    /// come back one mark each, as on main.
    #[test]
    fn drain_pieces_coalesce_into_whole_aligned_slabs() {
        // A megabyte chunk keeps the member inside the harness's eight
        // slabs, which nothing drains while `drive` runs.
        let chunk = 1024 * 1024;
        // A drain's shape at a 64 KiB cadence: overshoots, a wrap cut into
        // a long piece and a tiny one, a piece larger than a whole chunk.
        let pieces: Vec<usize> = [65_536 + 7, 65_536 + 4_100, 65_000, 536, 64, 65_536]
            .into_iter()
            .cycle()
            .take(60)
            .chain([chunk + 12_345, 3, 65_536 + 1])
            .collect();
        let total: usize = pieces.iter().sum();
        let payload: Vec<u8> = (0..total).map(|i| (i * 31 + i / 997) as u8).collect();
        let drive = |ring: &mut RingOut<'_>| {
            let mut at = 0;
            for &n in &pieces {
                ring.write_all(&payload[at..at + n]).expect("write");
                at += n;
            }
        };

        let whole = slabs_of(chunk, true, drive);
        let count = whole.len();
        assert_eq!(count, total.div_ceil(chunk));
        for (i, (bytes, marks, lead)) in whole.iter().enumerate() {
            assert_eq!(marks.len(), 1, "slab {i}: one write per slab");
            assert_eq!(marks[0] as usize, bytes.len());
            assert_eq!(*lead, 0, "slab {i} starts {lead} past a page");
            if i + 1 < count {
                assert_eq!(bytes.len(), chunk, "slab {i} is not whole");
            }
        }
        let joined: Vec<u8> = whole.iter().flat_map(|(b, _, _)| b.clone()).collect();
        assert!(joined == payload, "the coalesced bytes differ");

        let replayed = slabs_of(chunk, false, drive);
        let marks: usize = replayed.iter().map(|(_, m, _)| m.len()).sum();
        // One mark per piece, and one more for the piece larger than a
        // chunk, which is the one a replaying ring has to split.
        assert_eq!(marks, pieces.len() + 1);
        let joined: Vec<u8> = replayed.iter().flat_map(|(b, _, _)| b.clone()).collect();
        assert!(joined == payload, "the replayed bytes differ");
    }
}
