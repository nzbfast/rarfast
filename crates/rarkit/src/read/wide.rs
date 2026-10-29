//! The wide verify: one stored member's packed bytes read and hashed on
//! several threads at once, their CRC32s joined in order.
//!
//! **What it is for.** `t` on the posting shape, one large stored member
//! split across 1 GiB volumes, had nothing to decode and nothing to write,
//! so its whole cost was the read out of the source and the CRC32 over it,
//! and both ran on the walking thread: 2.00 s wall on 2.00 CPU s for 8 GiB
//! on a Zen 4 desktop, where UnRAR spread the same work over five cores.
//! A split member stays on the walking thread whatever the driver (spec F
//! 3.5.4 joins its fragments inside the walk), so the width has to come
//! from INSIDE the member, and for a stored member with nothing to write it
//! can: every byte's contribution to a CRC32 is independent of every other
//! byte's once the lengths are known, and [`Crc32::append`] joins two
//! registers exactly.
//!
//! **The arrangement.** The walking thread hands out the pieces and
//! combines them. It cuts the fragment into pieces of [`Plan::piece`] bytes and
//! hands piece indices to [`Plan::workers`] threads of the extraction's
//! team (`read::team`: kept from range to range, so none is started or
//! ended at a range's end), each of which reads its piece from the
//! volume's own [`RangeSource`] into a buffer of its own and hashes it. Results come back in any order and are joined in
//! piece order on the walking thread, which is the only thread that ever
//! touches the walk, the member, the caller's `Progress` or its `Tally`, so
//! none of those gains a `Send` bound (SPEC-API 8.5, spec F 3.7.7).
//!
//! **The bound.** A piece is dispatched only while its end lies within
//! [`Plan::workers`] pieces of the lowest piece not yet joined, and
//! `workers * piece` is at most `MemoryPolicy::read_ahead`. So no byte is
//! asked of the source more than `read_ahead` beyond the byte being
//! checked (spec F 3.7.2), the buffers held are at most `read_ahead`
//! whatever the member's size, and `released` still moves at least once
//! per MiB joined (3.7.3), because the combiner reports each piece to the
//! walk as it is joined.
//!
//! **Written members too.** Each piece's bytes come home with its CRC32,
//! so `p` and `x` write them from the walking thread in piece order: the
//! writer sees the same calls in the same order as the serial loop gives
//! it, only fed faster. The window bounds the buffers as it bounds the
//! reads.
//!
//! **The verdict does not move.** The member's CRC32, the fragment's packed
//! CRC32 and the drop-behind report are fed by the combiner exactly the
//! values and lengths a serial read of the same bytes feeds them, in the
//! same order. A source that ends inside the fragment joins the bytes it
//! did return and then ends the member as `Truncated` at the same offset
//! the serial read names; a source error ends it with that error.

use std::collections::VecDeque;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

use crate::crypto::Pieces;
use crate::error::Error;
use crate::read::cursor::read_upto_at;
use crate::source::RangeSource;

/// The smallest piece: below it the hand-over costs more of a piece than
/// the read and the hash save. Also the smallest `read_ahead` share a
/// worker is worth spawning for.
const MIN_PIECE: u64 = 128 * 1024;

/// The largest piece, which is only reached with a read-ahead budget far
/// above the default: a piece past it buys nothing and holds its size.
const MAX_PIECE: u64 = 4 << 20;

/// The piece the plan asks for first on macOS, where the budget allows two
/// workers of it: 1 MiB. The workers come second, as many as the width and
/// the budget both allow, so under the default 4 MiB read-ahead a wide Mac
/// reads four pieces of 1 MiB at once where it read thirty-two of 128 KiB.
///
/// **Why.** On macOS every `pread` of one file waits on the others in the
/// kernel, about 8 microseconds a call for each other reader, so system
/// CPU follows calls times readers: the warm stored big member's `t` on an M3
/// Ultra was 10.19 CPU s, 9.72 of it system, at thirty-two readers of 128
/// KiB, and 1.29 at four of 1 MiB with a faster wall (0.36 s against 0.53).
/// Cold, one reader or a few of 1 MiB get the drive's rate there, where
/// thirty-two of 128 KiB present it requests a third the size
/// (measured 30 Sep 2026).
#[cfg(target_os = "macos")]
const PIECE: u64 = 1 << 20;

/// Everywhere else the plan splits the budget across the width, as it
/// always has: Linux has no such lock, and there four readers of 1 MiB
/// tested the warm big member about a quarter slower than sixteen of 256
/// KiB, and the cold one too, where sixteen of 1 MiB were level with them
/// (a Zen 4 rental, the wide read's pieces per system).
#[cfg(not(target_os = "macos"))]
const PIECE: u64 = MIN_PIECE;

/// COUNT ONLY (feature `wide-piece-knob`, never shipped):
/// `RARKIT_WIDE_PIECE_KIB`, the piece the plan asks for first, in KiB,
/// read once; [`PIECE`] otherwise. 128 is the plan this lever replaced,
/// which split the budget across the whole width.
#[cfg(feature = "wide-piece-knob")]
fn piece_target() -> u64 {
    static KIB: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *KIB.get_or_init(|| {
        std::env::var("RARKIT_WIDE_PIECE_KIB")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(PIECE >> 10)
    }) << 10
}

/// The shipped piece target.
#[cfg(not(feature = "wide-piece-knob"))]
#[inline(always)]
fn piece_target() -> u64 {
    PIECE
}

/// Whether `plan`'s pieces are at least the piece this system's plan asks
/// for first ([`PIECE`]): the budget held two readers of it.
///
/// What a team KEPT across fragments asks before it starts
/// (`read::across`). On macOS a budget under two pieces of 1 MiB leaves two
/// readers of 128 KiB, and there every piece is a wake of a reader and a
/// wake of the joining thread that costs about what the piece saves: `t`
/// of a 12.9 GB stored member in 859 volumes of 15 MB under `-mm64m` read in
/// 0.920 s at 1.44 CPU seconds with such a team against 0.899 s at 0.90 on
/// the member's own thread (an Apple M3 Mac, K=3; 0.938 against 0.974 s in an
/// earlier run), and a named limit is a promise not to be slower
/// inside it. Everywhere else [`PIECE`] is the smallest piece there is, so
/// every plan passes: the same member under the same limit read in 0.330 s
/// against 0.614 s on an 8-core Zen 4
/// (2 Oct 2026).
pub(crate) fn full_pieces(plan: Plan) -> bool {
    plan.piece as u64 >= piece_target()
}

/// The smallest range worth going wide for: below it the member is read
/// the ordinary way. A spawn and a join of a handful of threads is tens of
/// microseconds; 16 MiB of serial read and hash is milliseconds.
pub(crate) const FLOOR: u64 = 16 << 20;

/// How wide, and in what pieces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    pub(crate) workers: usize,
    pub(crate) piece: usize,
}

/// The plan for a member granted `width` lanes under a read-ahead budget
/// of `read_ahead` bytes, or `None` where there is nothing to spread.
pub(crate) fn plan(width: usize, read_ahead: u64) -> Option<Plan> {
    plan_for(width, read_ahead, piece_target())
}

/// The plan for a member whose check is ONE ordered hash stream (a
/// BLAKE2sp record): its pieces are read apart and fed to the hasher in
/// order by the joining thread.
///
/// **Its piece is asked for at [`HASHED_PIECE`] first.** The hash is one
/// thread's work however many readers feed it, so a reader past the few
/// that keep it fed buys nothing, and every piece is a hand-over to the
/// joining thread: `t` of a 4 GiB stored BLAKE2sp member on an M5 Ultra
/// at its default width, under the test command's 32 MiB, read in 1.098 s
/// in pieces of 1 MiB, 0.913 in pieces of 2 and 0.808 in pieces of 4, on
/// 6.43, 6.06 and 5.99 CPU seconds at the same 44 MiB peak (K=11; 12 Oct
/// 2026), which is the wall eight threads read it in. A CRC32 member is
/// the other way about (0.042 s at 1 MiB, 0.065 at 4), its pieces being
/// hashed apart, and keeps [`plan`].
pub(crate) fn plan_hashed(width: usize, read_ahead: u64) -> Option<Plan> {
    plan_for(width, read_ahead, piece_target().max(HASHED_PIECE))
}

/// The piece [`plan_hashed`] asks for first: 4 MiB on macOS, where it was
/// counted, and the system's own [`PIECE`] everywhere else until it is.
#[cfg(target_os = "macos")]
const HASHED_PIECE: u64 = 4 << 20;
#[cfg(not(target_os = "macos"))]
const HASHED_PIECE: u64 = PIECE;

/// [`plan`] with the piece it asks for first stated.
///
/// The workers are as many pieces of `target` as the budget holds, never
/// more than the width and never fewer than two where two of the smallest
/// piece fit; each piece is then the budget's share of the workers, so it
/// is never below `target` unless the budget is below two of it. A
/// `target` of [`MIN_PIECE`] or less is exactly the plan before [`PIECE`]:
/// the budget split across the width.
fn plan_for(width: usize, read_ahead: u64, target: u64) -> Option<Plan> {
    let target = target.max(MIN_PIECE);
    let workers = (width as u64)
        .min((read_ahead / target).max(2))
        .min(read_ahead / MIN_PIECE);
    if workers < 2 {
        return None;
    }
    // Whole 4 KiB pages, so a piece never starts part way into one.
    let piece = (read_ahead / workers).clamp(MIN_PIECE, MAX_PIECE) & !4095;
    Some(Plan {
        workers: workers as usize,
        piece: piece as usize,
    })
}

/// `RARKIT_WIDE_BREADTH`: how many READERS the wide read keeps at work for
/// a width the caller did NOT state, while they are RUNNING. `cores` holds
/// them to the physical cores this process may run on;
/// `fast` to the fast cores where the system tells fast from slow (macOS's
/// performance levels), and to the physical cores everywhere else; `width`
/// (or `0`, `off`) leaves the width as given; anything else, or nothing,
/// is [`BREADTH`]. A RUNTIME knob, so one binary carries every arm. It
/// moves how many readers work at once and never a byte: the plan, its
/// pieces and its window are the width's own, as they always were, and the
/// readers past the rule's cores stand by.
///
/// **Why running.** Warm, the wide read is a copy out of the page cache
/// and a CRC32, and the copy is bound by the rate memory gives it, not by
/// cores. Counted on an 8 core, 16 thread Zen 4 (a rental, `t` of a
/// 12.9 GB stored member, K=3; 2 Oct 2026): 0.612 s at
/// one reader, 0.269 at four, 0.254 at six, eight and twelve, and 0.274 at
/// the sixteen the width gave, on 0.61, 1.07, 1.51, 1.96, 2.84 and 3.38 CPU
/// s. Instructions retired were level from one reader to sixteen and
/// cycles rose five times (0.65 instructions a cycle down to 0.16), 71
/// percent of the samples at sixteen in the kernel's copy and no lock in
/// the profile; one shared descriptor, a descriptor a reader and a
/// duplicate a reader read alike. A reader past the physical cores is the
/// second thread of a core already in that copy: it cost 8 percent of wall.
///
/// **Why the plan stays.** The first form of this rule planned at the
/// cores (eight readers of 512 KiB under a window of eight pieces, where
/// the width gives sixteen of 256 KiB) and read the same member COLD 0.966x.
/// Counted with the probe: eight readers of 256 KiB under the width's
/// sixteen-piece window read it cold as fast as sixteen (1.717 s against
/// 1.728) and warm fastest of all (0.250 s against 0.275), where eight of
/// 512 KiB under eight pieces read cold 1.794 s with the readers 0.8 s
/// idle behind the lowest piece. The loss was the window with no slack,
/// not the readers.
///
/// **Why not waiting.** Off the drive the readers are not running, they
/// are waiting on the source (1.2 threads busy of sixteen there), and a
/// source may want every request the width can keep out: four readers read
/// that member cold 1.976 s. So the rule asks the readers themselves
/// ([`Hold`]): each times one piece in [`SAMPLE`] by its own CPU clock and
/// the wall clock, and readers stand by only while the readers had the CPU
/// for half their pieces' time or more. A file half in the cache changes
/// over as it is read.
///
/// **A stated width is the caller's word** (`ReadOptions::workers`,
/// `-mt<n>`) and is never held.
pub(crate) const BREADTH_ENV: &str = "RARKIT_WIDE_BREADTH";

/// What the pieces out of an unstated width are held to ([`BREADTH_ENV`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Breadth {
    /// Nothing: a piece out a unit of width, the path before the knob.
    Width,
    /// The physical cores.
    Cores,
    /// The fast cores, where the system names them; the physical cores
    /// where it does not.
    Fast,
}

/// The rule where [`BREADTH_ENV`] says nothing: the fast cores, which are
/// the physical cores wherever the system names no fast ones.
///
/// Screened against the parent's own binary, the knob on against unset
/// (2 Oct 2026). An 8 core, 16 thread Zen 4
/// (a rental, K=5 warm and K=3 cold): `t` of a 12.9 GB stored member as
/// one archive 0.273 s to 0.249 s (1.100x) on 3.35 to 2.04 CPU s, `p`
/// 1.099x, 100 MB volumes 1.108x and 1.093x, a many-member set's `p` 1.078x, an
/// encrypted member 1.220x and 1.203x; every cold row level (0.995x to
/// 1.005x); `x`, a stated width and one thread level. An M3 Ultra (24
/// performance cores of 32, warm, indicative): the same member 0.125 s to
/// 0.097 s (1.29x) on 2.80 to 2.07 CPU s, the volumes 1.19x. Where every
/// core is fast and physical (a 96 core Zen 5) there is nothing to hold,
/// and a system with no thread clock (Windows) is never held: both read
/// as before. `RARKIT_WIDE_BREADTH=width` is the way back.
const BREADTH: Breadth = Breadth::Fast;

/// [`BREADTH_ENV`]'s value as a rule.
fn breadth_of(value: Option<&str>) -> Breadth {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("cores") => Breadth::Cores,
        Some("fast") => Breadth::Fast,
        Some("width" | "0" | "off") => Breadth::Width,
        _ => BREADTH,
    }
}

/// The rule: a test's answer, then the environment's, read once.
fn breadth() -> Breadth {
    #[cfg(feature = "test-support")]
    match crate::probe::wide_breadth() {
        1 => return Breadth::Width,
        2 => return Breadth::Cores,
        3 => return Breadth::Fast,
        _ => {}
    }
    static RULE: std::sync::OnceLock<Breadth> = std::sync::OnceLock::new();
    *RULE.get_or_init(|| breadth_of(crate::knob::reader_var(BREADTH_ENV).ok().as_deref()))
}

/// The fast cores, where the system tells them from slow ones.
fn fast_cores() -> Option<usize> {
    #[cfg(target_os = "macos")]
    {
        crate::cores::performance()
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// One piece in this many is timed by its reader ([`Hold`]): two reads of
/// the thread's clock in eight pieces, which no row sees.
const SAMPLE: u64 = 8;

/// The samples a [`Hold`] decides on: thirty-two pieces a decision, 8 MiB
/// of 256 KiB pieces and 32 MiB of 1 MiB ones.
const DECIDE: u32 = 4;

/// The breadth rule's hold on ONE member's wide read ([`BREADTH_ENV`]):
/// the most readers it keeps at work while they run, and what the readers
/// have said so far. Kept by the member's own loop across the
/// ranges it reads, so a member split across volumes decides once and
/// carries it.
pub(crate) struct Hold {
    /// The rule's cores, never under two.
    most: usize,
    /// Whether the readers at work are held to `most` now. Not until the
    /// readers have said they run: a member opens at the width, as it
    /// always did.
    held: bool,
    /// The sampled pieces' CPU time and wall time since the last decision.
    ran: std::time::Duration,
    took: std::time::Duration,
    samples: u32,
    /// What every sample says whatever the clocks say: `Some(true)` that
    /// its reader ran throughout, `Some(false)` that it waited throughout.
    /// A test's word; `None` reads the clocks.
    forced: Option<bool>,
}

impl Hold {
    fn new(most: usize) -> Hold {
        Hold {
            most: most.max(2),
            held: false,
            ran: std::time::Duration::ZERO,
            took: std::time::Duration::ZERO,
            samples: 0,
            forced: None,
        }
    }

    /// The readers of a range of `workers` that are at work now.
    #[cfg(test)]
    fn at_work(&self, workers: usize) -> usize {
        if self.held {
            workers.min(self.most)
        } else {
            workers
        }
    }

    /// One sampled piece: its reader had the CPU for `ran` of the `took`
    /// it spent on the piece. Every [`DECIDE`] samples the hold is decided
    /// afresh: on, where the readers ran for half that time or more; off,
    /// where they waited on the source for more of it.
    fn note(&mut self, ran: std::time::Duration, took: std::time::Duration) {
        self.ran += ran;
        self.took += took;
        self.samples += 1;
        if self.samples < DECIDE {
            return;
        }
        self.held = self.ran * 2 >= self.took;
        #[cfg(feature = "test-support")]
        if self.held {
            crate::probe::note_wide_held();
        }
        self.ran = std::time::Duration::ZERO;
        self.took = std::time::Duration::ZERO;
        self.samples = 0;
    }
}

/// Where the readers past a hold's cores stand by while the hold is on.
/// A reader asks before every piece; the joining thread says when the hold
/// goes on or off, and the range's end lets every reader go.
struct Gate {
    held: std::sync::atomic::AtomicBool,
    ended: std::sync::atomic::AtomicBool,
    lock: Mutex<()>,
    changed: std::sync::Condvar,
}

impl Gate {
    fn new(held: bool) -> Gate {
        Gate {
            held: std::sync::atomic::AtomicBool::new(held),
            ended: std::sync::atomic::AtomicBool::new(false),
            lock: Mutex::new(()),
            changed: std::sync::Condvar::new(),
        }
    }

    /// Stand by while the hold is on. `false` once the range has ended.
    fn pass(&self) -> bool {
        use std::sync::atomic::Ordering::SeqCst;
        if !self.held.load(SeqCst) {
            return true;
        }
        let mut guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        while self.held.load(SeqCst) && !self.ended.load(SeqCst) {
            guard = self.changed.wait(guard).unwrap_or_else(|e| e.into_inner());
        }
        !self.ended.load(SeqCst)
    }

    /// The hold is on, or off. The word is stored before the lock is taken
    /// to tell the readers, and a reader reads it under the lock, so no
    /// reader misses the change.
    fn set(&self, held: bool) {
        use std::sync::atomic::Ordering::SeqCst;
        if self.held.swap(held, SeqCst) != held {
            let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
            self.changed.notify_all();
        }
    }
}

/// Ends its gate when it is dropped, on every path out of a range: a
/// reader standing by must never outlast the range that would let it go.
struct Ended(Arc<Gate>);

impl Drop for Ended {
    fn drop(&mut self) {
        self.0
            .ended
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _guard = self.0.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.0.changed.notify_all();
    }
}

/// The hold on a member granted `width` lanes, or `None` where there is
/// none to keep: no rule is on, the caller `stated` the width, or the
/// width is within the rule's cores already.
pub(crate) fn hold(width: usize, stated: bool) -> Option<Hold> {
    let rule = breadth();
    if rule == Breadth::Width {
        return None;
    }
    #[cfg(feature = "test-support")]
    let (physical, fast) =
        crate::probe::wide_cores().unwrap_or_else(|| (crate::cores::physical(), fast_cores()));
    #[cfg(not(feature = "test-support"))]
    let (physical, fast) = (crate::cores::physical(), fast_cores());
    #[cfg_attr(not(feature = "test-support"), allow(unused_mut))]
    let mut hold = Hold::new(most_under(rule, width, stated, physical, fast)?);
    #[cfg(feature = "test-support")]
    {
        hold.forced = crate::probe::wide_running();
    }
    Some(hold)
}

/// The most pieces out under `rule` on a machine of `physical` cores,
/// `fast` of them fast where it says: `None` where the rule holds nothing
/// of this width. Never under two: a member that went wide stays wide.
fn most_under(
    rule: Breadth,
    width: usize,
    stated: bool,
    physical: usize,
    fast: Option<usize>,
) -> Option<usize> {
    if stated {
        return None;
    }
    let most = match rule {
        Breadth::Width => return None,
        Breadth::Cores => physical,
        Breadth::Fast => fast.map_or(physical, |fast| fast.min(physical)),
    }
    .max(2);
    (most < width).then_some(most)
}

/// The plan a range is read at when its pieces are WRITTEN straight to a
/// file by the thread that joins them (`read::handed`): the window `plan`
/// reads within (its workers times its piece, which is the read-ahead
/// budget), cut into pieces of `target` bytes, or of half the window where
/// `target` is `None`.
///
/// **Half the window, so two readers.** A write past the OS cache is one
/// request a piece, and a drive takes large requests faster than small ones
/// (a WD SN8100 4 MiB blocks at 1.2 s for 12 GiB where 98,000 of 128 KiB
/// took 2.34 s), which is why a
/// big stored member is delivered in slabs of half the read-ahead. The same slab here:
/// 4 MiB under `rarfast x`'s 8 MiB read-ahead, on two readers, which
/// between them read and hash faster than any drive this was counted on
/// writes. The window is unchanged, so no byte is asked of the source
/// further ahead than under `plan` (spec F 3.7.2).
pub(crate) fn slabs_of(plan: Plan, target: Option<u64>) -> Plan {
    let window = (plan.workers * plan.piece) as u64;
    let piece = target
        .unwrap_or(window / 2)
        .clamp(MIN_PIECE, MAX_PIECE)
        .min(window)
        & !4095;
    let piece = piece.max(4096);
    Plan {
        workers: ((window / piece).max(1) as usize).min(plan.workers.max(1)),
        piece: piece as usize,
    }
}

/// Why a wide read stopped short of the range's end.
pub(crate) enum Stop {
    /// The source ended at this offset, inside the range.
    Short(u64),
    /// The source failed.
    Source(Error),
    /// The combiner's own callback failed, and this is its error.
    Accepted(Error),
}

/// An ENCRYPTED stored member's AES-CBC chain, for a range of whole
/// blocks (SPEC-K 3.6.2, 3.7.4).
///
/// CBC decryption of a run needs its own ciphertext and the ONE block in
/// front of it (SPEC-K 2.1), so each piece is deciphered on its worker
/// from the 16 ciphertext bytes it reads in front of itself, and the first
/// piece from `chain`, the member's chaining value where the range starts.
/// Nothing is speculated: the block in front of a piece is ciphertext on
/// the source whatever any other worker has done to its own copy.
#[derive(Clone)]
pub(crate) struct Cipher {
    pub(crate) pieces: Pieces,
    pub(crate) chain: [u8; 16],
    /// Whether the fragment's PACKED CRC32 is wanted (spec F 3.5.6): over
    /// the ciphertext, so it is taken before the piece is deciphered, and
    /// only where the stream will judge it.
    pub(crate) packed_crc: bool,
    /// Whether a piece's PLAINTEXT starts on its buffer's page, its 16
    /// bytes of chain in front of the page ([`Aligned::headed`]): what a
    /// writer past the OS cache wants of a piece it is given whole
    /// (`read::handed`). Everywhere else the BUFFER starts on the page,
    /// as it did before the cut and for [`ALIGN`]'s reason: no row asked
    /// for the joined read's buffers to move, so they do not.
    pub(crate) page_plain: bool,
}

/// One piece as the calling thread joins it.
pub(crate) struct Piece<'b> {
    /// The CRC32 of the member's bytes: the plaintext, where there is a
    /// cipher.
    pub(crate) crc: u32,
    /// The CRC32 of the packed bytes, which is `crc` where there is no
    /// cipher and the ciphertext's where one was asked for (0 otherwise).
    pub(crate) packed_crc: u32,
    pub(crate) len: u64,
    /// The bytes, where they were lent.
    pub(crate) bytes: Option<&'b [u8]>,
    /// The piece's last ciphertext block, which chains into the next.
    pub(crate) chain: [u8; 16],
}

/// One piece's result: its CRCs, its buffer, how many of its bytes are
/// joined, how many the source gave, and its last ciphertext block; or
/// the source's error.
struct Done {
    crc: u32,
    packed_crc: u32,
    buf: Option<Aligned>,
    got: usize,
    gave: usize,
    chain: [u8; 16],
    /// A sampled piece under a [`Hold`]: the CPU time its reader ran for
    /// and the wall time the piece took it.
    ran: Option<(std::time::Duration, std::time::Duration)>,
}

type Outcome = Result<Done, Error>;

/// What a reader says of a piece: its index and its outcome, or `None` for
/// the outcome where the reader fell (panicked) on it.
type Said = (u64, Option<Outcome>);

/// A piece to read: its index, and the buffer lent for it, if any.
type Job = (u64, Option<Aligned>);

/// A reader's word to its range, and the piece it is on: if the reader
/// unwinds with a piece in hand, the range is told that the piece fell,
/// and panics on its own thread as a scope whose thread panicked did.
struct Says {
    to: Sender<Said>,
    on: Option<u64>,
}

impl Drop for Says {
    fn drop(&mut self) {
        if let Some(index) = self.on.take() {
            let _ = self.to.send((index, None));
        }
    }
}

fn next_job(jobs: &Mutex<Receiver<Job>>) -> Option<Job> {
    jobs.lock().unwrap_or_else(|e| e.into_inner()).recv().ok()
}

/// The buffers a written range lends its pieces, kept by the extraction
/// from range to range (`team::keep`) and charged to its meter for as long
/// as they live.
struct Lent {
    /// Each buffer's length, and the bytes in front of its page.
    size: usize,
    head: usize,
    bufs: Vec<Aligned>,
    charge: crate::memory::Held,
}

impl Lent {
    /// Charge what is held now.
    fn charged(&mut self) {
        let bytes = self.bufs.iter().map(Aligned::held_bytes).sum();
        self.charge.set(bytes);
    }
}

/// What every piece of one range is read with: shared by the range's jobs
/// on the team's threads, and by the calling thread where it reads a piece
/// itself.
struct Reading {
    source: Arc<dyn RangeSource>,
    at: u64,
    piece: u64,
    len: u64,
    cipher: Option<Cipher>,
    /// A buffer's length, and the bytes in front of its page.
    size: usize,
    page_head: usize,
    /// Whether sampled pieces are timed, and what a test has every sample
    /// say.
    timed: bool,
    forced: Option<bool>,
}

impl Reading {
    /// One piece's answer: read, deciphered where there is a cipher, and
    /// hashed, into the buffer lent for it or into `own`.
    fn answer(&self, own: &mut Aligned, index: u64, lent: Option<Aligned>) -> Outcome {
        let before = (self.timed && index.is_multiple_of(SAMPLE))
            .then(|| (crate::cores::thread_cpu(), std::time::Instant::now()));
        let mut lent = lent;
        let read = {
            let buf = match &mut lent {
                Some(buf) => buf,
                None => own,
            };
            piece(
                &*self.source,
                self.at,
                self.piece,
                self.len,
                index,
                &self.cipher,
                buf.bytes_mut(),
            )
        };
        let ran = before.and_then(|(cpu, wall)| {
            let took = wall.elapsed();
            match self.forced {
                Some(true) => Some((took, took)),
                Some(false) => Some((std::time::Duration::ZERO, took)),
                None => Some((crate::cores::thread_cpu()?.checked_sub(cpu?)?, took)),
            }
        });
        read.map(|(crc, packed_crc, got, gave, chain)| Done {
            crc,
            packed_crc,
            buf: lent,
            got,
            gave,
            chain,
            ran,
        })
    }
}

/// Where every piece buffer starts: a 4 KiB boundary.
///
/// **Why.** Each piece is a `pread` into this buffer, so the buffer is the
/// DESTINATION of the kernel's page-cache copy (`copy_to_user`, `rep movsb`
/// on x86-64). On a Zen 4 (Ryzen 7 7700, kernel 6.8) that copy runs about
/// four times slower per byte whenever the destination's offset in its
/// page is 1 to 15 bytes AHEAD of the source's, and at the same speed for
/// every other pair, "misaligned" ones included. A fresh 256 KiB `Vec` is
/// a fresh `mmap` from glibc whose bytes start 16 past a page, and the
/// stored readers read at file offsets 8 past one, so every piece of a
/// volume's first span sat in that band: the first volume of any read
/// cost about 0.49 CPU seconds a GiB against about 0.27 for later volumes,
/// whose buffers came from glibc's heap. On a page the difference is -8,
/// outside the band, and `t` of an 8 GiB stored member goes from 0.33 to
/// 0.21 s (the Zen 4 copy band).
const ALIGN: usize = 4096;

/// A piece buffer of `len` bytes starting on an [`ALIGN`] boundary: the
/// allocation is `ALIGN` longer and the usable bytes begin at the first
/// boundary inside it, so no `unsafe` is needed and no byte moves.
pub(crate) struct Aligned {
    raw: Vec<u8>,
    at: usize,
    len: usize,
}

impl Aligned {
    pub(crate) fn new(len: usize) -> Aligned {
        Aligned::headed(len, 0)
    }

    /// A buffer of `head + len` bytes whose byte `head` is the one on the
    /// boundary: a deciphered piece's 16 bytes of chain sit in front of
    /// the page its plaintext starts on, so a writer past the OS cache
    /// takes the plaintext from where it was deciphered.
    pub(crate) fn headed(len: usize, head: usize) -> Aligned {
        let raw = vec![0u8; head + len + ALIGN];
        // `align_offset` may in principle answer that it cannot; the
        // buffer is then merely unaligned, never wrong.
        let at = match raw.as_ptr().wrapping_add(head).align_offset(ALIGN) {
            at if at < ALIGN => at,
            _ => 0,
        };
        Aligned {
            raw,
            at,
            len: head + len,
        }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.raw[self.at..self.at + self.len]
    }

    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.raw[self.at..self.at + self.len]
    }

    /// The bytes the allocation holds, its alignment slack included: what
    /// a holder charges.
    pub(crate) fn held_bytes(&self) -> u64 {
        self.raw.capacity() as u64
    }
}

/// What the calling thread does with each piece, in order.
pub(crate) type Accept<'a> = dyn FnMut(Piece<'_>) -> crate::Result<()> + 'a;

/// Where a piece's bytes start in its buffer: after the 16 bytes of
/// ciphertext it chains from, where there is a cipher.
fn head(cipher: &Option<Cipher>) -> usize {
    if cipher.is_some() {
        16
    } else {
        0
    }
}

/// Where a piece's buffer meets its page: at the plaintext where the
/// cipher asks for it there ([`Cipher::page_plain`]), at its first byte
/// otherwise.
fn plain_at(cipher: &Option<Cipher>) -> usize {
    match cipher {
        Some(cipher) if cipher.page_plain => 16,
        _ => 0,
    }
}

/// Read piece `index` of the range into `buf` (at least `head + want`
/// long), decipher it where there is a cipher, and hash it.
fn piece(
    source: &dyn RangeSource,
    at: u64,
    piece: u64,
    len: u64,
    index: u64,
    cipher: &Option<Cipher>,
    buf: &mut [u8],
) -> Result<(u32, u32, usize, usize, [u8; 16]), Error> {
    let start = at + index * piece;
    let want = (len - index * piece).min(piece) as usize;
    #[cfg(test)]
    if !(buf[plain_at(cipher)..].as_ptr() as usize).is_multiple_of(ALIGN) {
        tests::MISALIGNED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    let Some(cipher) = cipher else {
        let got = read_upto_at(source, start, &mut buf[..want])?;
        let crc = crate::checksum::crc32(&buf[..got]);
        return Ok((crc, crc, got, got, [0; 16]));
    };
    // The chaining value in front of the piece's bytes: the member's own
    // for the first piece, the ciphertext block before it for any other,
    // which lies inside the range and is read with the piece.
    let gave = if index == 0 {
        buf[..16].copy_from_slice(&cipher.chain);
        read_upto_at(source, start, &mut buf[16..16 + want])?
    } else {
        read_upto_at(source, start - 16, &mut buf[..16 + want])?.saturating_sub(16)
    };
    // Whole blocks only: a source that ended inside one is `Short` at the
    // byte it ended, and the partial block is never deciphered.
    let got = gave & !15;
    let body = &mut buf[16..16 + got];
    let packed_crc = if cipher.packed_crc {
        crate::checksum::crc32(body)
    } else {
        0
    };
    let mut chain = [0u8; 16];
    chain.copy_from_slice(&buf[..16]);
    let body = &mut buf[16..16 + got];
    let chain = cipher.pieces.run_from(chain, body);
    Ok((crate::checksum::crc32(body), packed_crc, got, gave, chain))
}

/// Read `len` bytes at `at` of `source` on `plan.workers` threads of the
/// extraction's team (`read::team`), and hand each piece's CRC32 and bytes
/// to `accept` in order, on the calling thread.
///
/// **With `lend`, the bytes travel with the CRC**, so a member that is
/// WRITTEN (`p`, `x`) is written from the calling thread in piece order
/// exactly as a serial read would write it, and `accept` gets them. The
/// buffers then circulate: there are `workers` of them, a job carries one
/// out and its answer carries it home, and the window that bounds the
/// pieces in flight bounds them too.
///
/// **Without it** (`t`), each thread of the team keeps one buffer of its
/// own and `accept` gets the length alone. That is not a nicety: a buffer
/// that moves between cores brings its cache lines with it, and on a Zen 5
/// box the circulating form cost `t` 0.07 s against 0.05 s on a 4.2 GiB
/// member (0.75 CPU s against 0.58). Either way at most `workers * piece`
/// bytes are held, and 16 more a buffer where there is a cipher.
///
/// **With a `cipher`**, `len` is whole blocks and each piece is deciphered
/// on its thread ([`Cipher`]); `accept` gets the plaintext, its CRC32, the
/// ciphertext's where it was asked for, and the piece's last ciphertext
/// block, which the caller hands on to the member's own chain.
pub(crate) fn verify_range(
    source: &Arc<dyn RangeSource>,
    at: u64,
    len: u64,
    plan: Plan,
    lend: bool,
    cipher: Option<Cipher>,
    accept: &mut Accept<'_>,
) -> Result<(), Stop> {
    verify_range_held(source, at, len, plan, None, lend, cipher, accept)
}

/// [`verify_range`] under the breadth rule's `hold`, where the member has
/// one ([`BREADTH_ENV`]): the same pieces under the same window, with no
/// more than the hold's readers AT WORK while the readers say they are
/// running; the rest stand by ([`Gate`]) and come back when the readers
/// say they wait. One piece in [`SAMPLE`] is timed by its reader, by its
/// own CPU clock and the wall clock, and the hold is told as each answer
/// arrives. A range that opens with the hold already on (a member's later
/// fragment) takes only the readers it will use. With no hold nothing is
/// timed, nobody stands by and the range is read as it always was.
///
/// **No thread is started or ended here** unless the team has none free
/// for a seat this range takes (`read::team`). Each reader is a job that
/// runs the range's pieces on a thread of the extraction's team until the
/// range has no more, and then leaves the thread to the team: a member's
/// next fragment and the next member's cipher chain are read by the
/// threads that read this one. The range does not wait for its readers to
/// leave; they hold nothing of it but its last answer's making.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_range_held(
    source: &Arc<dyn RangeSource>,
    at: u64,
    len: u64,
    plan: Plan,
    mut hold: Option<&mut Hold>,
    lend: bool,
    cipher: Option<Cipher>,
    accept: &mut Accept<'_>,
) -> Result<(), Stop> {
    debug_assert!(cipher.is_none() || (len.is_multiple_of(16) && plan.piece.is_multiple_of(16)));
    let piece_len = plan.piece as u64;
    let pieces = len.div_ceil(piece_len);
    let workers = (plan.workers as u64).min(pieces).max(1) as usize;
    let head = head(&cipher);
    let size = plan.piece + head;
    // The bytes in front of the buffer's page: the chain, where the
    // plaintext is wanted on the page, and nothing otherwise.
    let page_head = plain_at(&cipher);
    // The readers that never stand by, and the readers this range takes:
    // all of them, unless the hold is on already.
    let core = hold.as_deref().map_or(workers, |h| workers.min(h.most));
    let opens_held = hold.as_deref().is_some_and(|h| h.held);
    let spawn = if opens_held { core } else { workers };
    let gate = Arc::new(Gate::new(opens_held));
    let reading = Arc::new(Reading {
        source: Arc::clone(source),
        at,
        piece: piece_len,
        len,
        cipher,
        size,
        page_head,
        timed: hold.is_some(),
        forced: hold.as_deref().and_then(|h| h.forced),
    });
    // The seats are taken FIRST, so they are given back LAST on every way
    // out, a panic's included: after the pieces' sender and the gate's end
    // below have let every reader go. A team of the range's own waits for
    // its threads where the seats are given back.
    let seats = crate::read::team::seats(spawn);
    // The pieces go to the readers down a channel of the range's own; its
    // SENDING end is dropped when this function returns, on every path,
    // which is what lets a reader waiting for a piece see the end and
    // leave its thread to the team.
    let (job_tx, job_rx) = channel::<Job>();
    let jobs = Arc::new(Mutex::new(job_rx));
    // Lets every reader standing by go, however this function is left.
    let _ended = Ended(Arc::clone(&gate));
    let started = seats.count();
    let (said_tx, said_rx) = channel::<Said>();
    for reader in 0..started {
        let (reading, gate, jobs) = (Arc::clone(&reading), Arc::clone(&gate), Arc::clone(&jobs));
        let mut says = Says {
            to: said_tx.clone(),
            on: None,
        };
        // A reader past the hold's cores asks the gate before a piece.
        let stands_by = reader >= core;
        seats.hand(Box::new(move |scratch| {
            while !stands_by || gate.pass() {
                let Some((index, lent)) = next_job(&jobs) else {
                    break;
                };
                says.on = Some(index);
                let own = scratch.buffer(reading.size, reading.page_head);
                let result = reading.answer(own, index, lent);
                says.on = None;
                if says.to.send((index, Some(result))).is_err() {
                    break;
                }
            }
        }));
    }
    drop(said_tx);
    // With no reader at all, this thread answers each piece itself as it
    // is sent, one in flight: the serial read of the same pieces.
    let inline = started == 0;
    // The window: the plan's, whatever readers are at work in it; the
    // readers had, where the host would start no more.
    let workers = if started < spawn {
        started.max(1)
    } else {
        workers
    };
    // The readers at work while the hold is on.
    let at_work = started.min(core);
    #[cfg(feature = "test-support")]
    if opens_held {
        crate::probe::note_wide_readers(at_work);
    }
    let mut own_here: Option<Aligned> = None;

    // `window[k]` is piece `joined + k`, `None` until its reader answers.
    // Its length is the number of pieces in flight or answered and not yet
    // joined, which the bound keeps at `workers`.
    let mut window: VecDeque<Option<Outcome>> = VecDeque::with_capacity(workers);
    // The buffers not out with a job. A piece is only sent while the
    // window has room, and the window never holds more than `workers`, so
    // there is always one here to send it with.
    // They are the extraction's, left with its team by the range before
    // this one where there was one of their shape (`team::keep`), so a
    // member's ranges do not each make, fault in and give back a window
    // of them; and they are charged for as long as they live ([`Lent`]).
    // A reader's own buffer is its thread's (`team::Scratch`).
    let mut lent = if lend {
        let mut lent = crate::read::team::kept(|l: &Lent| l.size == size && l.head == page_head)
            .unwrap_or_else(|| Lent {
                size,
                head: page_head,
                bufs: Vec::new(),
                charge: crate::memory::Held::default(),
            });
        lent.bufs.truncate(workers);
        while lent.bufs.len() < workers {
            lent.bufs.push(Aligned::headed(size - page_head, page_head));
        }
        lent.charged();
        Some(lent)
    } else {
        None
    };
    let mut spare: Vec<Aligned> = lent
        .as_mut()
        .map(|lent| std::mem::take(&mut lent.bufs))
        .unwrap_or_default();
    let mut joined = 0u64;
    let mut sent = 0u64;
    let outcome = (|| {
        while joined < pieces {
            while sent < pieces && sent - joined < workers as u64 {
                let buf = if lend {
                    let Some(buf) = spare.pop() else {
                        break;
                    };
                    Some(buf)
                } else {
                    None
                };
                if job_tx.send((sent, buf)).is_err() {
                    break;
                }
                window.push_back(None);
                sent += 1;
            }
            // The lowest piece answered: join it and go straight back to
            // send the piece its slot frees, so no reader waits on this
            // thread's next wait.
            if window.front().is_some_and(Option::is_some) {
                let result = window.pop_front().flatten().expect("checked");
                let index = joined;
                joined += 1;
                let start = at + index * piece_len;
                let want = (len - index * piece_len).min(piece_len);
                match result {
                    Ok(done) => {
                        if done.got > 0 {
                            let bytes =
                                done.buf.as_ref().map(|b| &b.bytes()[head..head + done.got]);
                            accept(Piece {
                                crc: done.crc,
                                packed_crc: done.packed_crc,
                                len: done.got as u64,
                                bytes,
                                chain: done.chain,
                            })
                            .map_err(Stop::Accepted)?;
                        }
                        if (done.gave as u64) < want {
                            return Err(Stop::Short(start + done.gave as u64));
                        }
                        spare.extend(done.buf);
                    }
                    Err(error) => return Err(Stop::Source(error)),
                }
                continue;
            }
            if inline {
                // The one piece sent and unanswered is the lowest.
                let job = jobs.lock().unwrap_or_else(|e| e.into_inner()).try_recv();
                let Ok((index, lent)) = job else {
                    break;
                };
                let own =
                    own_here.get_or_insert_with(|| Aligned::headed(size - page_head, page_head));
                let result = reading.answer(own, index, lent);
                told(&mut hold, &gate, at_work, &result);
                window[(index - joined) as usize] = Some(result);
                continue;
            }
            // The lowest piece is still in flight, so the window is not
            // empty and an answer is coming, unless a reader fell: every
            // reader gone with pieces unanswered, or one that says so. Its
            // thread has said why; this thread ends as a scope whose
            // thread panicked did.
            let Ok((index, Some(result))) = said_rx.recv() else {
                panic!("a reader of a wide range panicked");
            };
            told(&mut hold, &gate, at_work, &result);
            window[(index - joined) as usize] = Some(result);
        }
        Ok(())
    })();
    drop(job_tx);
    if let Some(mut lent) = lent {
        // What came home: every buffer, unless the range stopped with
        // pieces still out.
        lent.bufs = spare;
        lent.charged();
        crate::read::team::keep(lent);
    }
    outcome
}

/// Tell the hold, where there is one, what a sampled piece's reader said,
/// and the gate what the hold then is.
fn told(hold: &mut Option<&mut Hold>, gate: &Gate, at_work: usize, result: &Outcome) {
    let (Some(hold), Ok(done)) = (hold.as_deref_mut(), result) else {
        return;
    };
    let Some((ran, took)) = done.ran else {
        return;
    };
    hold.note(ran, took);
    gate.set(hold.held);
    #[cfg(feature = "test-support")]
    if hold.held {
        crate::probe::note_wide_readers(at_work);
    }
    #[cfg(not(feature = "test-support"))]
    let _ = at_work;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pieces whose buffer did not start on an `ALIGN` boundary, counted in
    /// `piece`. No output byte shows alignment, so the tests
    /// read this instead.
    pub(super) static MISALIGNED: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    /// A plan's pieces are full where they are at least the piece this
    /// system asks for first: every plan off macOS, and on macOS only a
    /// budget that held two readers of 1 MiB.
    #[test]
    fn full_pieces_are_the_systems_own_first_piece() {
        let small = plan_for(8, 256 * 1024, PIECE).expect("two readers of the smallest piece");
        assert_eq!(small.piece as u64, MIN_PIECE);
        assert_eq!(full_pieces(small), PIECE == MIN_PIECE);
        let roomy = plan_for(8, 4 << 20, PIECE).expect("a plan");
        assert!(full_pieces(roomy));
        let deep = plan_for(32, 32 << 20, PIECE).expect("a plan");
        assert!(full_pieces(deep));
    }

    #[test]
    fn an_aligned_buffer_starts_on_a_4_kib_boundary_at_every_size() {
        for len in [
            1usize,
            16,
            4095,
            4096,
            4097,
            128 << 10,
            (256 << 10) + 16,
            4 << 20,
        ] {
            let mut b = Aligned::new(len);
            assert_eq!(b.bytes().len(), len);
            assert!(
                (b.bytes().as_ptr() as usize).is_multiple_of(ALIGN),
                "len {len}"
            );
            assert!(
                (b.bytes_mut().as_ptr() as usize).is_multiple_of(ALIGN),
                "len {len}"
            );
            assert!(b.bytes().iter().all(|&x| x == 0));
        }
    }

    /// Both kinds of buffer the kernel copies into, the workers' own
    /// (`t`) and the lent ones (`p`, `x`), start on a 4 KiB boundary for
    /// every piece, pinned by address.
    #[test]
    fn every_piece_is_read_into_a_4_kib_aligned_buffer() {
        let src = source(3 * 1024 * 1024 + 777);
        let src = Arc::new(src);
        let plan = Plan {
            workers: 4,
            piece: 128 * 1024,
        };
        for lend in [false, true] {
            let before = MISALIGNED.load(std::sync::atomic::Ordering::Relaxed);
            let outcome =
                verify_range(&src, 0, src.data.len() as u64, plan, lend, None, &mut |p| {
                    if let Some(b) = p.bytes {
                        assert!((b.as_ptr() as usize).is_multiple_of(ALIGN), "a lent piece");
                    }
                    Ok(())
                });
            assert!(outcome.is_ok());
            assert_eq!(
                MISALIGNED.load(std::sync::atomic::Ordering::Relaxed),
                before,
                "lend {lend}"
            );
        }
    }
    use crate::checksum::{crc32, Crc32};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Recorded {
        data: Vec<u8>,
        /// The furthest byte any read has asked for.
        reach: AtomicU64,
        /// Offset at which reads start failing, if any.
        fail_at: Option<u64>,
        /// Offset whose read is held back, so every later piece in the
        /// window is answered before it.
        slow_at: Option<u64>,
        /// How long every read takes, so reads overlap and can be counted.
        pause: Option<std::time::Duration>,
        /// The reads in flight now, and the most at once among those at or
        /// past `late`.
        out: AtomicU64,
        late: u64,
        late_most: AtomicU64,
    }

    impl RangeSource for Recorded {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.slow_at == Some(offset) {
                std::thread::sleep(std::time::Duration::from_millis(30));
            }
            if let Some(pause) = self.pause {
                let out = self.out.fetch_add(1, Ordering::SeqCst) + 1;
                if offset >= self.late {
                    self.late_most.fetch_max(out, Ordering::SeqCst);
                }
                std::thread::sleep(pause);
                self.out.fetch_sub(1, Ordering::SeqCst);
            }
            if self.fail_at.is_some_and(|f| offset >= f) {
                return Err(std::io::Error::other("injected"));
            }
            let start = (offset as usize).min(self.data.len());
            let n = buf.len().min(self.data.len() - start);
            buf[..n].copy_from_slice(&self.data[start..start + n]);
            self.reach
                .fetch_max(offset + buf.len() as u64, Ordering::Relaxed);
            Ok(n)
        }
        fn available(&self) -> u64 {
            self.data.len() as u64
        }
        fn len(&self) -> Option<u64> {
            Some(self.data.len() as u64)
        }
    }

    fn source(len: usize) -> Recorded {
        let mut x = 0x9e37_79b9u32;
        let data = (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        Recorded {
            data,
            reach: AtomicU64::new(0),
            fail_at: None,
            slow_at: None,
            pause: None,
            out: AtomicU64::new(0),
            late: 0,
            late_most: AtomicU64::new(0),
        }
    }

    /// [`super::verify_range`] of a recorded source the test keeps a
    /// handle of.
    fn verify_range(
        src: &Arc<Recorded>,
        at: u64,
        len: u64,
        plan: Plan,
        lend: bool,
        cipher: Option<Cipher>,
        accept: &mut Accept<'_>,
    ) -> Result<(), Stop> {
        let shared: Arc<dyn RangeSource> = Arc::clone(src) as Arc<dyn RangeSource>;
        super::verify_range(&shared, at, len, plan, lend, cipher, accept)
    }

    /// [`super::verify_range_held`], likewise.
    #[allow(clippy::too_many_arguments)]
    fn verify_range_held(
        src: &Arc<Recorded>,
        at: u64,
        len: u64,
        plan: Plan,
        hold: Option<&mut Hold>,
        lend: bool,
        cipher: Option<Cipher>,
        accept: &mut Accept<'_>,
    ) -> Result<(), Stop> {
        let shared: Arc<dyn RangeSource> = Arc::clone(src) as Arc<dyn RangeSource>;
        super::verify_range_held(&shared, at, len, plan, hold, lend, cipher, accept)
    }

    fn joined(src: &Arc<Recorded>, at: u64, len: u64, plan: Plan) -> (Result<(), Stop>, u32, u64) {
        let mut crc = Crc32::new();
        let mut total = 0u64;
        let mut bytes = Vec::new();
        let outcome = verify_range(src, at, len, plan, true, None, &mut |p| {
            let (c, n, b) = (p.crc, p.len, p.bytes);
            let b = b.expect("lent");
            assert_eq!(b.len() as u64, n);
            crc.append(c, n);
            total += n;
            bytes.extend_from_slice(b);
            Ok(())
        });
        // The bytes arrive in order, whatever order the pieces finished.
        let from = at as usize;
        assert_eq!(bytes[..], src.data[from..from + bytes.len()]);
        (outcome, crc.finish(), total)
    }

    #[test]
    fn the_plan_stays_inside_the_read_ahead() {
        for width in 1..=64 {
            for ahead in [64 << 10, 1 << 20, 4 << 20, 16 << 20] {
                if let Some(p) = plan(width, ahead) {
                    assert!(p.workers >= 2 && p.workers <= width);
                    assert!(
                        (p.workers * p.piece) as u64 <= ahead,
                        "{width} {ahead} {p:?}"
                    );
                    assert!(p.piece as u64 >= MIN_PIECE && p.piece % 4096 == 0);
                }
            }
        }
        assert_eq!(plan(1, 4 << 20), None);
        assert_eq!(plan(8, 128 << 10), None);
    }

    /// The plan before [`PIECE`], restated, which a target of
    /// [`MIN_PIECE`] must give at every width and budget.
    fn split_across_the_width(width: usize, read_ahead: u64) -> Option<Plan> {
        let workers = (width as u64).min(read_ahead / MIN_PIECE);
        if workers < 2 {
            return None;
        }
        let piece = (read_ahead / workers).clamp(MIN_PIECE, MAX_PIECE) & !4095;
        Some(Plan {
            workers: workers as usize,
            piece: piece as usize,
        })
    }

    #[test]
    fn a_target_of_the_smallest_piece_is_the_old_plan() {
        for width in 1..=64 {
            for ahead in [
                64 << 10,
                300 << 10,
                1 << 20,
                (3 << 20) + 12_345,
                4 << 20,
                8 << 20,
                32 << 20,
                256 << 20,
            ] {
                assert_eq!(
                    plan_for(width, ahead, MIN_PIECE),
                    split_across_the_width(width, ahead),
                    "{width} {ahead}"
                );
            }
        }
    }

    /// A hashed member's plan asks for 4 MiB first on macOS, so at a wide
    /// default it is eight readers of 4 MiB under the test command's 32
    /// MiB and not thirty-two of one; a width of eight or fewer, and a
    /// budget under two such pieces, plan as they did.
    #[test]
    fn a_hashed_members_plan_asks_for_four_mebibytes_first() {
        let mib = 1usize << 20;
        let p = |workers, piece| Some(Plan { workers, piece });
        if cfg!(target_os = "macos") {
            assert_eq!(plan_hashed(36, 32 << 20), p(8, 4 * mib));
            assert_eq!(plan_hashed(20, 32 << 20), p(8, 4 * mib));
            assert_eq!(plan_hashed(36, 64 << 20), p(16, 4 * mib));
            assert_eq!(plan_hashed(36, 4 << 20), p(2, 2 * mib));
        } else {
            for width in [2, 8, 20, 36] {
                assert_eq!(plan_hashed(width, 32 << 20), plan(width, 32 << 20));
            }
        }
        assert_eq!(plan_hashed(8, 32 << 20), p(8, 4 * mib));
        assert_eq!(plan_hashed(4, 32 << 20), p(4, 4 * mib));
        assert_eq!(plan_hashed(1, 32 << 20), None);
    }

    /// Lever 1: pieces of 1 MiB first, then the workers the budget holds;
    /// a budget under two of them still goes wide in smaller pieces.
    #[test]
    fn the_piece_comes_first_and_the_workers_from_the_budget() {
        const PIECE: u64 = 1 << 20;
        let mib = 1usize << 20;
        let at = |width, ahead| plan_for(width, ahead, PIECE).expect("wide");
        let p = |workers, piece| Plan { workers, piece };
        assert_eq!(at(32, 4 << 20), p(4, mib));
        assert_eq!(at(16, 4 << 20), p(4, mib));
        assert_eq!(at(4, 4 << 20), p(4, mib));
        assert_eq!(at(2, 4 << 20), p(2, 2 * mib));
        assert_eq!(at(32, 32 << 20), p(32, mib));
        assert_eq!(at(16, 16 << 20), p(16, mib));
        assert_eq!(at(16, 32 << 20), p(16, 2 * mib));
        assert_eq!(at(16, 1 << 20), p(2, mib / 2));
        assert_eq!(at(16, 256 << 10), p(2, 128 << 10));
        assert_eq!(plan_for(16, 255 << 10, PIECE), None);
        assert_eq!(plan_for(1, 4 << 20, PIECE), None);
    }

    /// The shipped plan per system: 1 MiB pieces on macOS, the budget split
    /// across the width everywhere else (`super::PIECE`).
    #[cfg(not(feature = "wide-piece-knob"))]
    #[test]
    fn the_shipped_piece_is_1_mib_on_macos_only() {
        let (workers, piece) = if cfg!(target_os = "macos") {
            (4, 1 << 20)
        } else {
            (32, 128 << 10)
        };
        assert_eq!(plan(32, 4 << 20), Some(Plan { workers, piece }));
        let (workers, piece) = if cfg!(target_os = "macos") {
            (4, 1 << 20)
        } else {
            (16, 256 << 10)
        };
        assert_eq!(plan(16, 4 << 20), Some(Plan { workers, piece }));
    }

    /// The breadth rule: an unstated width over the rule's cores has a
    /// hold of that many pieces, never under two; a stated width, a width
    /// within the cores and no rule have none.
    #[test]
    fn an_unstated_width_over_the_rules_cores_has_a_hold() {
        use Breadth::{Cores, Fast, Width};
        // Sixteen threads on eight cores: SMT pairs counted once.
        assert_eq!(most_under(Cores, 16, false, 8, None), Some(8));
        assert_eq!(most_under(Fast, 16, false, 8, None), Some(8));
        assert_eq!(most_under(Width, 16, false, 8, None), None);
        // Twenty-four fast cores of thirty-two.
        assert_eq!(most_under(Cores, 32, false, 32, Some(24)), None);
        assert_eq!(most_under(Fast, 32, false, 32, Some(24)), Some(24));
        // A width within the cores has none, and nor has a stated one.
        assert_eq!(most_under(Cores, 4, false, 8, None), None);
        assert_eq!(most_under(Cores, 8, false, 8, None), None);
        assert_eq!(most_under(Cores, 16, true, 8, None), None);
        assert_eq!(most_under(Fast, 32, true, 32, Some(24)), None);
        // Never under two; a width of two is then within it.
        assert_eq!(most_under(Cores, 8, false, 1, None), Some(2));
        assert_eq!(most_under(Fast, 8, false, 4, Some(1)), Some(2));
        assert_eq!(most_under(Cores, 2, false, 1, None), None);
        // A fast count above the physical cores is not believed.
        assert_eq!(most_under(Fast, 64, false, 8, Some(12)), Some(8));
    }

    /// A hold opens at the width, takes hold when its readers say they ran
    /// for half their pieces' time or more, and lets go when they say they
    /// waited: a decision every [`DECIDE`] samples, each on its own samples.
    #[test]
    fn a_hold_follows_what_its_readers_say() {
        use std::time::Duration;
        let ms = Duration::from_millis;
        let mut hold = Hold::new(3);
        assert_eq!(hold.at_work(8), 8, "a range opens at the width");
        for _ in 0..DECIDE - 1 {
            hold.note(ms(9), ms(10));
            assert_eq!(hold.at_work(8), 8, "not before a decision's samples");
        }
        hold.note(ms(9), ms(10));
        assert_eq!(hold.at_work(8), 3, "the readers ran");
        assert_eq!(hold.at_work(2), 2, "never more than the readers");
        // Waiting on the source: a tenth of their time on the CPU.
        for _ in 0..DECIDE {
            hold.note(ms(1), ms(10));
        }
        assert_eq!(hold.at_work(8), 8, "the readers waited");
        // Exactly half is running; a hair under is waiting.
        for _ in 0..DECIDE {
            hold.note(ms(5), ms(10));
        }
        assert_eq!(hold.at_work(8), 3);
        for _ in 0..DECIDE {
            hold.note(Duration::from_micros(4999), ms(10));
        }
        assert_eq!(hold.at_work(8), 8);
        // Never under two.
        assert_eq!(Hold::new(1).most, 2);
    }

    /// The most reads of a [`Recorded`] source in flight at once, among
    /// those at or past `late`, on a range of six readers under a hold of
    /// two whose readers say `forced`, or under none.
    fn late_reads_out(forced: Option<bool>, late: u64) -> usize {
        let len = 24 * 1024 * 1024;
        let mut src = source(len);
        src.pause = Some(std::time::Duration::from_micros(300));
        src.late = late;
        let src = Arc::new(src);
        let plan = Plan {
            workers: 6,
            piece: 128 * 1024,
        };
        let mut hold = forced.map(|say| Hold {
            forced: Some(say),
            ..Hold::new(2)
        });
        let mut crc = Crc32::new();
        let mut total = 0u64;
        let outcome = verify_range_held(
            &src,
            0,
            len as u64,
            plan,
            hold.as_mut(),
            false,
            None,
            &mut |p| {
                crc.append(p.crc, p.len);
                total += p.len;
                Ok(())
            },
        );
        assert!(outcome.is_ok());
        assert_eq!(total, len as u64);
        assert_eq!(
            crc.finish(),
            crc32(&src.data),
            "the same CRC32 under a hold"
        );
        src.late_most.load(Ordering::Relaxed) as usize
    }

    /// A range that OPENS with its hold on (a member's later fragment)
    /// starts only the readers it will use, and reads the same bytes.
    #[test]
    fn a_range_that_opens_held_starts_only_its_readers() {
        let len = 8 * 1024 * 1024;
        let mut src = source(len);
        src.pause = Some(std::time::Duration::from_micros(300));
        let src = Arc::new(src);
        let plan = Plan {
            workers: 6,
            piece: 128 * 1024,
        };
        let mut hold = Hold {
            forced: Some(true),
            held: true,
            ..Hold::new(2)
        };
        let mut crc = Crc32::new();
        let outcome = verify_range_held(
            &src,
            0,
            len as u64,
            plan,
            Some(&mut hold),
            true,
            None,
            &mut |p| {
                crc.append(p.crc, p.len);
                Ok(())
            },
        );
        assert!(outcome.is_ok());
        assert_eq!(crc.finish(), crc32(&src.data));
        let most = src.late_most.load(Ordering::Relaxed);
        assert!((1..=2).contains(&most), "{most} reads out at once");
        // The window is the plan's: six pieces ahead, not two.
        assert!(hold.held);
    }

    /// Under a hold whose readers say they RUN, no more than the hold's
    /// readers are at work once it has decided; where they say they WAIT,
    /// and with no hold at all, the range stays at its readers.
    #[test]
    fn a_running_range_keeps_no_more_pieces_out_than_its_hold() {
        // The first decision is in by piece 32 of 192; `late` is past it
        // and past every piece then out.
        let late = 96 * 128 * 1024;
        let running = late_reads_out(Some(true), late);
        assert!(
            (1..=2).contains(&running),
            "{running} out under a hold of two"
        );
        let waiting = late_reads_out(Some(false), late);
        assert!(waiting > 2, "{waiting} out where the readers wait");
        let none = late_reads_out(None, late);
        assert!(none > 2, "{none} out with no hold");
    }

    #[test]
    fn the_knob_names_its_rules_and_nothing_else_moves_the_default() {
        assert_eq!(breadth_of(Some("cores")), Breadth::Cores);
        assert_eq!(breadth_of(Some(" Fast ")), Breadth::Fast);
        for off in ["width", "0", "off", "OFF"] {
            assert_eq!(breadth_of(Some(off)), Breadth::Width);
        }
        assert_eq!(breadth_of(None), BREADTH);
        assert_eq!(breadth_of(Some("")), BREADTH);
        assert_eq!(breadth_of(Some("9")), BREADTH);
        // Shipped: the fast cores.
        assert_eq!(BREADTH, Breadth::Fast);
    }

    #[test]
    fn the_joined_crc_is_one_pass_over_the_range() {
        let src = source(5 * 1024 * 1024 + 12_345);
        let src = Arc::new(src);
        let plan = Plan {
            workers: 4,
            piece: 128 * 1024,
        };
        for (at, len) in [
            (0u64, 5 * 1024 * 1024 + 12_345u64),
            (777, 3_000_001),
            (4096, 1),
        ] {
            let (outcome, crc, total) = joined(&src, at, len, plan);
            assert!(outcome.is_ok());
            assert_eq!(total, len);
            assert_eq!(crc, crc32(&src.data[at as usize..(at + len) as usize]));
        }
    }

    /// Found on the 8 GiB posting set: when the lowest piece is the LAST
    /// of the window to answer, joining it empties the window, and a
    /// combiner that then waited before sending more waited for ever.
    #[test]
    fn a_window_answered_behind_its_lowest_piece_keeps_going() {
        let len = 3 * 1024 * 1024;
        let plan = Plan {
            workers: 4,
            piece: 128 * 1024,
        };
        for slow in [0u64, 4, 9] {
            let mut src = source(len);
            src.slow_at = Some(slow * plan.piece as u64);
            let src = Arc::new(src);
            let (outcome, crc, total) = joined(&src, 0, len as u64, plan);
            assert!(outcome.is_ok());
            assert_eq!(total, len as u64);
            assert_eq!(crc, crc32(&src.data));
        }
    }

    /// `t`'s form, where each worker keeps its own buffer and only the
    /// CRC32 and the length come home: the same register as one pass.
    #[test]
    fn the_unlent_form_joins_the_same_crc() {
        let src = source(5 * 1024 * 1024 + 12_345);
        let src = Arc::new(src);
        let plan = Plan {
            workers: 4,
            piece: 128 * 1024,
        };
        let len = src.data.len() as u64 - 777;
        let mut crc = Crc32::new();
        let mut total = 0u64;
        let outcome = verify_range(&src, 777, len, plan, false, None, &mut |p| {
            let (c, n, b) = (p.crc, p.len, p.bytes);
            assert!(b.is_none(), "nothing is lent without a writer");
            crc.append(c, n);
            total += n;
            Ok(())
        });
        assert!(outcome.is_ok());
        assert_eq!(total, len);
        assert_eq!(crc.finish(), crc32(&src.data[777..]));
    }

    #[test]
    fn no_read_runs_past_the_window() {
        // With the combiner refusing after the first piece, no worker can
        // have been sent further than `workers` pieces from the start.
        let src = source(8 * 1024 * 1024);
        let src = Arc::new(src);
        let plan = Plan {
            workers: 4,
            piece: 128 * 1024,
        };
        let mut calls = 0;
        let outcome = verify_range(&src, 0, 8 * 1024 * 1024, plan, false, None, &mut |_| {
            calls += 1;
            Err(Error::new(crate::ErrorKind::Cancelled))
        });
        assert!(matches!(outcome, Err(Stop::Accepted(_))));
        assert_eq!(calls, 1);
        assert!(src.reach.load(Ordering::Relaxed) <= (plan.workers * plan.piece) as u64 * 2);
    }

    fn decryptor(key: u8, iv: u8) -> crate::crypto::MemberDecryptor {
        use aes::cipher::KeyInit;
        let key = [key; 32];
        crate::crypto::MemberDecryptor::new(crate::crypto::MemberCipher::Aes256Cbc(
            crate::crypto::cbc::CbcDec::new_with_key(
                aes::Aes256Dec::new(&key.into()),
                &key,
                [iv; 16],
            ),
        ))
    }

    /// The pieces, each deciphered from the ciphertext block in
    /// front of it, join to the serial decryptor's plaintext, its chain
    /// and both CRCs, from any block-aligned offset and at any piece size.
    #[test]
    fn deciphered_pieces_join_to_the_serial_chain() {
        let src = source(3 * 1024 * 1024 + 4096);
        let src = Arc::new(src);
        for (at, len, piece, workers) in [
            (0u64, 3 * 1024 * 1024u64, 128 * 1024usize, 4usize),
            (48, 2 * 1024 * 1024 + 16 * 77, 128 * 1024, 3),
            (4096, 16 * 1000, 128 * 1024, 2),
            (160, 1024 * 1024, 256 * 1024, 8),
        ] {
            let range = &src.data[at as usize..(at + len) as usize];
            let mut serial = decryptor(7, 9);
            // Put the serial chain where the wide one starts: through the
            // bytes in front of `at`, which are whole blocks.
            let mut front = src.data[..at as usize].to_vec();
            let _ = serial.update(&mut front);
            let mut plain = range.to_vec();
            assert_eq!(serial.update(&mut plain).body, plain.len());

            let mut wide = decryptor(7, 9);
            let mut front = src.data[..at as usize].to_vec();
            let _ = wide.update(&mut front);
            let (pieces, chain) = wide.pieces(piece).expect("AES-CBC, nothing carried");
            let cipher = Cipher {
                pieces,
                chain,
                packed_crc: true,
                page_plain: false,
            };
            let plan = Plan { workers, piece };
            let (mut crc, mut packed, mut out) = (Crc32::new(), Crc32::new(), Vec::new());
            let mut last = [0u8; 16];
            let outcome = verify_range(&src, at, len, plan, true, Some(cipher), &mut |p| {
                crc.append(p.crc, p.len);
                packed.append(p.packed_crc, p.len);
                out.extend_from_slice(p.bytes.expect("lent"));
                last = p.chain;
                Ok(())
            });
            assert!(outcome.is_ok());
            assert_eq!(out, plain, "at {at} len {len} piece {piece}");
            assert_eq!(crc.finish(), crc32(&plain));
            assert_eq!(
                packed.finish(),
                crc32(range),
                "the packed CRC is the ciphertext's"
            );
            wide.resume(last);
            // Both chains go on to the same next block.
            let next = &src.data[(at + len) as usize..(at + len) as usize + 32];
            let (mut a, mut b) = (next.to_vec(), next.to_vec());
            let _ = serial.update(&mut a);
            let _ = wide.update(&mut b);
            assert_eq!(a, b, "the chain handed back is the serial one");
        }
    }

    /// A source that ends inside the range joins its whole blocks and
    /// names the byte it ended at; the partial block is never deciphered.
    #[test]
    fn a_short_source_under_a_cipher_joins_whole_blocks_only() {
        let src = source(1_000_000 + 9);
        let src = Arc::new(src);
        let mut dec = decryptor(1, 2);
        let (pieces, chain) = dec.pieces(128 * 1024).expect("AES-CBC");
        let cipher = Cipher {
            pieces,
            chain,
            packed_crc: false,
            page_plain: false,
        };
        let plan = Plan {
            workers: 3,
            piece: 128 * 1024,
        };
        let mut total = 0u64;
        let outcome = verify_range(
            &src,
            0,
            2_000_000 & !15,
            plan,
            false,
            Some(cipher),
            &mut |p| {
                total += p.len;
                Ok(())
            },
        );
        match outcome {
            Err(Stop::Short(at)) => assert_eq!(at, 1_000_009),
            _ => panic!("expected a short source"),
        }
        assert_eq!(total, 1_000_009 & !15);
    }

    #[test]
    fn a_short_source_joins_what_it_gave_and_names_where_it_ended() {
        let src = source(1_000_000);
        let src = Arc::new(src);
        let plan = Plan {
            workers: 3,
            piece: 128 * 1024,
        };
        let (outcome, crc, total) = joined(&src, 100, 2_000_000, plan);
        match outcome {
            Err(Stop::Short(at)) => assert_eq!(at, 1_000_000),
            _ => panic!("expected a short source"),
        }
        assert_eq!(total, 1_000_000 - 100);
        assert_eq!(crc, crc32(&src.data[100..]));
    }

    #[test]
    fn a_source_error_ends_the_range_after_the_pieces_before_it() {
        let mut src = source(2_000_000);
        src.fail_at = Some(600_000);
        let src = Arc::new(src);
        let plan = Plan {
            workers: 4,
            piece: 128 * 1024,
        };
        let (outcome, crc, total) = joined(&src, 0, 2_000_000, plan);
        assert!(matches!(outcome, Err(Stop::Source(_))));
        // The source refuses reads that START at or past 600,000: pieces 0
        // to 4 start below it, piece 5 at 655,360 is refused.
        assert_eq!(total, 5 * 128 * 1024);
        assert_eq!(crc, crc32(&src.data[..5 * 128 * 1024]));
    }
}
