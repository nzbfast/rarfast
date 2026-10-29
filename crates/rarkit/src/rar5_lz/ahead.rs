//! Decode-ahead across the members of a SOLID CHAIN (SPEC-H2 section 3.8).
//!
//! **What this is for.** Section 3.8's parallel decode is bounded by the
//! blocks one member has: `width.min(in_flight).min(plan.blocks.len())`.
//! A chain whose members hold ONE BLOCK each therefore has no width to
//! spread at all, and `tape::workers` refuses it before the block count is
//! even reached, because a member below `MT_MIN_OUTPUT` takes the serial
//! path. Both gates are correct and neither can be lifted into a win: a
//! member of one block is serial however the two are set.
//!
//! The parallelism such a chain HAS is across its members, and section 3.8
//! is what makes it lawful to take:
//!
//! > A block's symbol stream depends only on the tables in force for that
//! > block. It does not depend on the window, on the repeated distances, on
//! > the last match length, or on any filter.
//!
//! The window is the only thing a solid chain carries between members, and
//! the decode does not read it. So the blocks of member N+1 can be Huffman
//! decoded into tapes while the operations of member N are being APPLIED,
//! and the apply stage then meets member N+1 with its symbols already
//! decoded.
//!
//! **What this deliberately does NOT do, and why the two hazards go with
//! it.** The apply stage stays exactly where it was: on the caller's
//! thread, inside one `member()` call, in archive order, with
//! `Window::begin_member()` at the top of it. Nothing here moves a member
//! boundary into the middle of a wave. That is what keeps section 3.6's
//! member-relative filter base (`Record::resolve` against
//! `Window::produced()`) and section 3.8's deferred-error rule untouched:
//!
//! - no filter record is ever resolved against another member's base,
//!   because resolution happens where it always did;
//! - a member's deferred failure is raised only if the apply stage reaches
//!   it, and the work decoded past a member that STOPS is discarded
//!   wholesale rather than carried, because a later member's tape is never
//!   applied before the earlier member's call has returned.
//!
//! **The table group is CARRIED across a member boundary, and how.** A
//! block with the table bit clear uses the set of the group before it
//! (section 3.2), and in a solid chain that group can belong to an EARLIER
//! MEMBER. Reference `rar` at `-m3 -s` writes exactly that shape on a chain
//! of small members: on the `rar5_small_solid_20k` corpus one set is
//! carried across 93 percent of the boundaries (counted 22 Sep
//! 2026), so a rule that offered only members opening a group of their own
//! reached 1,334 members of 20,000. The tables in force at a member's start
//! are those of the last table-carrying block anywhere before it, and
//! WHICH block that is can be read from block headers alone, decoding no
//! symbol (section 3.2). So the members are offered in RUNS: a member whose
//! first block carries tables starts a run, and every member after it whose
//! first block does not carry tables joins the run, until something is
//! stepped over. A whole run goes to ONE lane, in archive order, and that
//! lane keeps the set its last table-carrying block built as the carried
//! set for the member behind it. No table set ever crosses a thread except
//! from a lane to the apply stage, and a run's head resolves the group for
//! the members behind it. A member with the table bit clear is refused when
//! no run is open, exactly as every such member was refused before the
//! carry existed.
//!
//! **The carry check, and why it stays.** A member used to stop decoding
//! when its declared size had been produced (section 3.1 as first
//! written), so a member that reached its size in block `d` and carried
//! another table set in a later block left block `d`'s set in force for
//! the member behind it, where a lane, which decoded every located block,
//! would have carried the later set. Since SPEC-H2's change of 28 Sep 2026
//! a member decodes EVERY block it owns (3.1), the serial arm included, so
//! the lane's carried set and the apply stage's agree by construction.
//! The check is kept as the net under that construction: every claimed
//! member records the block its apply finished at, and [`Ahead::give`]
//! compares that block's group with the group the lane carried forward.
//! A mismatch POISONS the run, and every member still queued from it is
//! discarded and decoded serially. The comparison is made by the apply
//! stage on its own outcome, so it cannot be wrong about where the serial
//! arm stopped: the apply IS the serial arm's stop (section 3.8,
//! consequence 2).
//!
//! **The key is the CONTENT.** A decoded member is claimed by comparing
//! the caller's packed bytes against the offered ones, not by position or
//! by any identity the offering layer supplies. Two members with the same
//! packed bytes, algorithm and declared size decode to the same tape by
//! section 3.8, so a match cannot be wrong. A claim that does not match is
//! kept rather than discarded: on a chain whose members all declare the
//! same size, a member the cursor stepped over between two offered ones
//! matched the front's size key, failed on content and threw the front's
//! work away, which was measured at 158 to 199 claims of 200 eligible
//! members (22 Sep 2026). The front now waits for the
//! member it was decoded for, and only a front that has been passed over
//! more times than the queue is deep, which no offering layer here can
//! cause, is discarded as never reached.
//!
//! **Memory.** Section 4.2 allows no allocation per member, so the work
//! items are pooled: a member's packed copy, its chain, its tapes and its
//! table handles live in one `Work` that the apply stage hands back for
//! the next offer. What the stage holds is bounded twice over, by a byte
//! ceiling taken from `MemoryPolicy::working_limit` (a stated
//! budget is hard) and by a depth in members.

use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::Arc;

use super::block;
use super::tables::Tables;
use super::tape::{self, BlockTape, Plan};
use crate::Error;

/// The most a member may declare and still be decoded ahead.
///
/// Two jobs, and both of them are bounds rather than tuning. It caps what
/// one `Work` can hold, which is what makes the depth below a memory
/// figure; and it keeps the stage away from members the WIDTH already
/// serves, which are the ones `tape::workers` admits to the tape path.
/// Between this and `MT_MIN_OUTPUT` sits a band of members that get
/// neither, and that is deliberate: a member of several megabytes has
/// blocks to spread and does not need its neighbours, and a member large
/// enough to fill this is already many milliseconds of apply, which is
/// far more than the decode it would be waiting for.
pub(crate) const AHEAD_MEMBER_MAX: u64 = 1 << 20;

// The WIDE stage (every member below the tape path's floor decoded ahead,
// behind a test-support environment knob, a pricing instrument) was
// decided on 23 Sep 2026: it does not ship, and its code
// was removed. It read 3.4 and 4.8 percent faster than the tape lever on
// the c6 cells at 2.7x the lever's peak RSS.

/// The share of `MemoryPolicy::working_limit` this stage may hold.
///
/// Priced against the whole budget for the same reason `lanes_within_budget`
/// is, and kept SMALL on purpose, because the shape this stage exists for
/// needs very little of it. `f/extract-solid290-m3`'s members are 64 KiB
/// of output over about 3.2 KiB of packed bytes, so the deepest queue this
/// stage will open on it holds about 2.2 MiB; at the default 512 MiB
/// budget the ceiling here is 8 MiB, which is three times that and still
/// under a sixtieth of what the caller allowed. A caller who states 64 MiB
/// gets 1 MiB and a shallower queue rather than a refusal, and one who
/// states less than a member's charge gets no stage at all (a
/// stated budget is hard, and it beats a speed lever).
const AHEAD_BUDGET_SHARE: u64 = 64;

/// The most members this stage will hold decoded or in flight at once,
/// whatever the budget allows.
///
/// A ceiling on the QUEUE and not on the parallelism: the lanes are the
/// read width, and a queue deeper than a few times the width buys nothing
/// but latency between an offer and its use.
const AHEAD_DEPTH_MAX: usize = 64;

/// How many times the apply stage may wait on the lanes before a stage
/// that is allowed to GROW opens one more ([`Ahead::set_lanes`]).
///
/// A chain's own parallelism is the ratio of a member's decode to its
/// apply, and that is a property of the chain's SHAPE, not of the machine. The
/// two shapes this was priced on (22 Sep 2026, M3
/// Ultra, 32 cores): `f/extract-solid290-m3`, 290 one-block members of 64
/// KiB, waits about 3 times an extraction at two lanes; the 20,000 member
/// `rar5_small_solid_20k` chain waited about 500 times at two lanes with a
/// queue sized for two, and about 20 to 50 with a queue sized for the
/// width, which is what a growing stage keeps. A wait is the one signal
/// that says the lanes are behind, so the stage grows on waits, and a
/// handful of them is the price of starting narrow: a chain that keeps up
/// waits a few times as its lanes start and seldom reaches this count.
const GROW_AFTER_STALLS: usize = 8;

/// The most CAPACITY the stage's pool of finished work items keeps, as a
/// multiple of its byte ceiling.
///
/// **Why the pool needs a ceiling of its own.** The ceiling above charges a
/// member in flight its packed length and declared size, but an item that
/// comes back KEEPS what its buffers grew to, and a lane's tapes for a
/// member of binary code run to several times its output: on a solid
/// `-m3` archive of 8,568 system binaries an item held up to 7.5 MiB for a
/// member declared at 1 MiB or less, and the pool kept all 64 items the
/// depth allowed, 265 MiB, uncharged. `rarfast t` read 411 MiB of footprint
/// and `x` 444 (M5, 30 Sep 2026). The pool now keeps at
/// most this many times the in-flight ceiling, shedding its largest items
/// first, so a chain of small members, the shape this stage exists for
/// (its items well under a MiB each), still recycles every item, and a
/// chain of large ones reallocates a few.
const AHEAD_SPARE_FACTOR: u64 = 4;

/// A bench knob: `RARKIT_AHEAD_SPARE_FACTOR=<n>` puts the pool's ceiling at
/// `n` times the byte ceiling, and `0` takes the ceiling away (the pool as
/// it was), so one binary measures every setting. Read once.
pub(crate) const AHEAD_SPARE_ENV: &str = "RARKIT_AHEAD_SPARE_FACTOR";

/// The pool's ceiling for a stage whose byte ceiling is `limit`.
fn spare_limit(limit: u64) -> u64 {
    static FACTOR: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let factor = *FACTOR.get_or_init(|| {
        crate::knob::reader_var(AHEAD_SPARE_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(AHEAD_SPARE_FACTOR)
    });
    match factor {
        0 => u64::MAX,
        n => limit.saturating_mul(n),
    }
}

/// What this stage may hold, from the caller's stated budget.
pub(crate) fn bytes_within_budget(working_limit: u64) -> u64 {
    working_limit / AHEAD_BUDGET_SHARE
}

/// [`GROW_AFTER_STALLS`], or a pricing harness's figure in its place.
#[cfg(feature = "test-support")]
fn grow_after_stalls() -> usize {
    crate::probe::ahead_grow_after().unwrap_or(GROW_AFTER_STALLS)
}

#[cfg(not(feature = "test-support"))]
fn grow_after_stalls() -> usize {
    GROW_AFTER_STALLS
}

/// One member offered to the decode-ahead, and what a lane made of it.
///
/// Pooled: the apply stage hands it straight back, so a chain in the
/// steady state allocates nothing per member (section 4.2).
#[derive(Default)]
pub(crate) struct Work {
    /// A buffer whose first [`Work::len`] bytes are the member's whole
    /// packed data. It is filled by whoever offers the member, in place,
    /// and NEVER SHRUNK: a chain's members are alike in size, so after the
    /// first one the buffer is already long enough and nothing is zeroed
    /// to make room. The crate denies unsafe code, so a buffer that is cut
    /// back to each member's exact length is a memset of the whole member
    /// on every member, which on a chain of three hundred is real work on
    /// the one thread the lever exists to unblock.
    packed: Vec<u8>,
    /// How many of `packed` are this member's.
    len: usize,
    pub(crate) algorithm: u8,
    /// The member's declared unpacked size, part of the claim key.
    pub(crate) unpacked: u64,
    /// The member's block chain, located by the lane.
    pub(crate) plan: Plan,
    /// One tape per block of `plan`, filled by the lane. Longer than the
    /// chain is allowed: the surplus is a recycled allocation.
    pub(crate) tapes: Vec<BlockTape>,
    /// The table set each block used, as `tape::decode_one` answers it.
    pub(crate) held: Vec<Option<Arc<Tables>>>,
    /// What the CHAIN WALK met, if it could not be completed. This is the
    /// error the serial arm would have raised where it stopped, and it is
    /// raised by the apply stage or not at all.
    pub(crate) failure: Option<Error>,
    /// How many of `tapes` this work's chain actually uses.
    pub(crate) blocks: usize,
    /// Whether this member's first block carries its own table set, which
    /// makes it the HEAD of a run. Set by the offer, read by the lane.
    head: bool,
    /// The run this member belongs to, for the poison of the module
    /// header.
    run: u64,
    /// The lane could not decode this member: the set it would have
    /// carried in was lost by a member before it in the run. Discarded at
    /// the claim, never applied.
    lost: bool,
    /// The index in `plan.groups` of the set the lane carried FORWARD from
    /// this member, `None` when it carried nothing usable. What
    /// [`Ahead::give`] checks against [`Work::done_at`].
    carry_group: Option<usize>,
    /// The block the apply stage FINISHED the member at, which is where the
    /// serial arm would have stopped reading. `None` until the apply has
    /// run, and `None` after it when the member did not finish.
    pub(crate) done_at: Option<usize>,
    /// [`Work::capacity`] as the item last came back to the pool.
    kept: u64,
}

impl Work {
    /// The member's packed bytes, which is the front of the buffer and
    /// never the whole of it.
    pub(crate) fn packed(&self) -> &[u8] {
        &self.packed[..self.len]
    }

    /// What this item is charged against the stage's byte ceiling: its
    /// packed copy and the most its tapes can hold, which is the member's
    /// own declared output.
    fn charge(&self) -> u64 {
        self.len as u64 + self.unpacked
    }

    /// What this item's buffers HOLD, whatever member it last carried: its
    /// packed copy and its tapes, by capacity. The pool's ceiling reads it.
    fn capacity(&self) -> u64 {
        let tapes: usize = self
            .tapes
            .iter()
            .map(|t| {
                t.steps.capacity() * std::mem::size_of::<tape::TapeOp>()
                    + t.verbatim.capacity()
                    + t.records.capacity() * std::mem::size_of::<super::filters::RawRecord>()
            })
            .sum();
        (self.packed.capacity() + tapes) as u64
    }

    /// The chain, the member's packed bytes and the tapes, borrowed apart
    /// so the apply stage can hold one tape mutably beside the plan that
    /// located it and the bytes a parked block is finished from.
    pub(crate) fn parts(&mut self) -> (&Plan, &[u8], &mut [BlockTape]) {
        (&self.plan, &self.packed[..self.len], &mut self.tapes)
    }

    /// Room for `len` bytes at the front, without zeroing what is already
    /// there. Answers the slice to fill.
    fn room(&mut self, len: usize) -> &mut [u8] {
        if self.packed.len() < len {
            self.packed.resize(len, 0);
        }
        self.len = len;
        &mut self.packed[..len]
    }

    /// Whether the set this member carried forward is the set the serial
    /// arm would have had in force after it: the group of the block the
    /// apply finished at, against the group the lane carried.
    fn carry_agrees(&self) -> bool {
        match (self.done_at, self.carry_group) {
            (Some(done), Some(carried)) => self.plan.group_of.get(done) == Some(&carried),
            _ => false,
        }
    }
}

/// What an offer came to.
///
/// The distinction between the two refusals is the run's: a caller told
/// `Never` steps over the member, and the run closes with it; one told
/// `Later` offers the same member again once something has been claimed,
/// nothing is stepped over, and the run stays open for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Offered {
    /// Decoding on a lane.
    Taken,
    /// The stage is full: a property of the moment, not of the member.
    Later,
    /// This member is not one the stage will ever take here.
    Never,
}

/// One offer not yet claimed.
#[derive(Clone, Copy)]
struct Offer {
    /// The lane that holds it.
    lane: usize,
    /// The packed length and declared size the caller matches against
    /// before it fills anything.
    len: usize,
    unpacked: u64,
    /// The run it belongs to.
    run: u64,
}

/// One decode lane: a thread, the work it is sent and the work it answers.
struct Lane {
    /// `None` once the lane has been told to stop: dropping the sender is
    /// what ends its loop.
    work: Option<mpsc::SyncSender<Work>>,
    done: mpsc::Receiver<Work>,
    handle: Option<std::thread::JoinHandle<()>>,
}

/// The decode-ahead of one solid chain.
///
/// The lanes are this stage's OWN threads, for the reason `member_piped`
/// gives for its own: a lane blocks when the queue is full, which a task
/// on the caller's pool must never do, and the pool's width is the
/// caller's to size.
///
/// A RUN of members is handed to one lane and taken back from the same
/// lane, in archive order by construction, so no reordering buffer is
/// needed. A lane decodes its own members in the order it was given them,
/// which is what lets it carry a table set from one to the next.
pub(crate) struct Ahead {
    lanes: Vec<Lane>,
    /// The offers not yet claimed, in offer order.
    queued: VecDeque<Offer>,
    /// The oldest offer's decoded work, taken back from its lane and
    /// waiting for the member it was decoded for.
    parked: Option<(Offer, Work)>,
    /// How many claims in a row have passed the parked work over.
    misses: usize,
    /// Work items the apply stage has finished with, for the next offer.
    spare: Vec<Work>,
    /// The capacity `spare` holds, by [`Work::capacity`] as each item came
    /// back.
    spare_bytes: u64,
    /// The most capacity `spare` keeps ([`AHEAD_SPARE_FACTOR`]).
    spare_limit: u64,
    /// The bytes the queue is charged with, against `limit`.
    held: u64,
    /// The most this stage has ever held, which is what the operation's
    /// reported peak carries (SPEC-API 5.2).
    peak: u64,
    limit: u64,
    depth: usize,
    /// The lanes this stage opens on its first offer.
    width: usize,
    /// The most lanes it may GROW to, one at a time, when the apply stage
    /// keeps waiting on them. Equal to `width` for a stage that does not
    /// grow, which is every stage whose width a caller stated.
    ceiling: usize,
    /// Waits since the stage last grew.
    stalls: usize,
    /// Whether the last member offered ended a run that a member with the
    /// table bit clear may still join: nothing has been stepped over
    /// since.
    run_open: bool,
    /// The lane the open run is on.
    run_lane: usize,
    /// The run the next head starts. Runs are numbered so a poisoned one
    /// can be told from the one after it.
    run_id: u64,
    /// The lane the next run's head goes to.
    next_lane: usize,
    /// A run whose carried set was found wrong at the apply; its queued
    /// members are discarded.
    poisoned: Option<u64>,
    /// Whether the stream's tapes skip the far list
    /// (`Window::FAR_DICTIONARY_FLOOR`), copied into every work item's
    /// plan by the offer.
    far_off: bool,
}

impl Ahead {
    /// A stage that may hold `limit` bytes and `width` lanes.
    pub(crate) fn new(limit: u64, width: usize) -> Ahead {
        Ahead {
            lanes: Vec::new(),
            queued: VecDeque::new(),
            parked: None,
            misses: 0,
            spare: Vec::new(),
            spare_bytes: 0,
            spare_limit: spare_limit(limit),
            held: 0,
            peak: 0,
            limit,
            depth: (width.max(1) * 4).min(AHEAD_DEPTH_MAX),
            width: width.clamp(1, AHEAD_DEPTH_MAX),
            ceiling: width.clamp(1, AHEAD_DEPTH_MAX),
            stalls: 0,
            run_open: false,
            run_lane: 0,
            run_id: 0,
            next_lane: 0,
            poisoned: None,
            far_off: false,
        }
    }

    /// Whether the stream's tapes skip the far list: its dictionary is at
    /// or under `Window::FAR_DICTIONARY_FLOOR`.
    pub(crate) fn set_far_off(&mut self, far_off: bool) {
        self.far_off = far_off;
    }

    /// The lanes the next chain opens with, from the read width.
    pub(crate) fn set_width(&mut self, width: usize) {
        self.set_lanes(width, width);
    }

    /// Open `start` lanes on the next chain and grow toward `ceiling`, one
    /// lane each time the apply stage has waited [`GROW_AFTER_STALLS`]
    /// times since the last growth. The queue is sized for the ceiling, so
    /// a stage that grows has the room its later lanes need, and a stage
    /// that never grows holds no more than it did before growth existed.
    /// Like [`Ahead::set_width`], a stage whose lanes are already open is
    /// left as it is until its chain ends.
    pub(crate) fn set_lanes(&mut self, start: usize, ceiling: usize) {
        if self.lanes.is_empty() {
            self.ceiling = ceiling.clamp(1, AHEAD_DEPTH_MAX);
            self.width = start.clamp(1, self.ceiling);
            self.depth = (self.ceiling * 4).min(AHEAD_DEPTH_MAX);
        }
    }

    /// The oldest outstanding offer's packed length and declared size.
    ///
    /// What a caller reads BEFORE it fills its own source: a member is
    /// claimed on its whole packed bytes, and the length is what says how
    /// many of them to ask for. Asking for a fixed ceiling instead would
    /// buy the decode-ahead at the price of a buffer the size of that
    /// ceiling on every solid chain, which is memory a caller never asked
    /// for.
    pub(crate) fn front(&self) -> Option<(usize, u64)> {
        let offer = match &self.parked {
            Some((offer, _)) => Some(offer),
            None => self.queued.front(),
        };
        offer.map(|offer| (offer.len, offer.unpacked))
    }

    /// The most this stage has held at once, for the operation's report.
    pub(crate) fn peak_bytes(&self) -> u64 {
        self.peak
    }

    /// Whether this stage will take nothing more until something is
    /// claimed.
    ///
    /// The two bounds of this module's header, read as one question: the
    /// depth in members, and the byte ceiling a stated memory budget sets.
    /// It is what tells a caller walking ahead of the decode
    /// to STOP rather than to step over the member it is holding.
    pub(crate) fn full(&self) -> bool {
        self.queued.len() + usize::from(self.parked.is_some()) >= self.depth
            || self.held >= self.limit
    }

    /// Something between the last member offered and the next one was
    /// NOT offered: the run is over, and the next member offered must
    /// start one of its own.
    ///
    /// The offering layer owes this call for every member it steps over
    /// that could change the table set in force: a member it could not
    /// read, one it refused, one this stage refused, and a member that
    /// declares no bytes but carries packed ones, whose block may carry a
    /// table set (`Rar5Lz::member`). It does not owe it for a service
    /// record, a directory or a member with no packed bytes, none of which
    /// reads a table. Calling it when nothing was stepped
    /// over costs one run head's worth of lever and never a byte.
    pub(crate) fn break_run(&mut self) {
        self.run_open = false;
    }

    /// Whether this member's packed bytes may be decoded ahead.
    ///
    /// The run rule of this module's header, plus the two bounds. The
    /// chain walk is not done here: only the FIRST block is located, which
    /// is a header read and decodes no symbol (section 3.2). The offer
    /// itself asks the same question on the bytes it holds; this is the
    /// form the package's own tests ask it in.
    #[cfg(test)]
    pub(crate) fn eligible(&self, packed: &[u8], unpacked: u64) -> bool {
        if unpacked == 0 || unpacked > self.member_max() {
            return false;
        }
        if packed.is_empty() || packed.len() as u64 >= self.member_max() {
            return false;
        }
        match block::block_in_hand(packed) {
            Ok(first) => first.carries_tables() || self.run_open,
            Err(_) => false,
        }
    }

    /// Whether this member can be refused WITHOUT ITS BYTES BEING READ,
    /// from its declared sizes and the first five bytes of its packed data.
    ///
    /// **What this is for.** [`Ahead::offer_into`] tests the run rule on
    /// the bytes once they are in hand, because until `fill` has run nothing
    /// can see them. Before the table group was carried, that was every
    /// refused member's whole packed data read into this stage's buffer and
    /// thrown away: measured 22 Sep 2026 on a 20,000 member chain written
    /// by reference `rar` at `-m3 -s`, where 1,334 members open their own
    /// group and 18,666 do not, so the shipped read path read about 15 MB
    /// for nothing. The carry takes those 18,666 now, so this refuses far
    /// less than it did; what it still refuses is decidable from the first
    /// block's HEADER, which is five bytes at most (`block::header_says_tables`),
    /// so a caller that can see those five bytes cheaply refuses first and
    /// never reads the rest.
    ///
    /// **It is one direction only, and that is deliberate.** `true` means
    /// this member is certainly refused, so the caller may skip it. `false`
    /// means nothing except "ask properly": every bound is tested again in
    /// `offer_into`, which remains the only place a member is accepted. A
    /// head that cannot be read, or that is not a sound block header, gives
    /// `false` and costs the lever nothing, because a short read there is
    /// the archive ending rather than a statement about the member.
    ///
    /// **ONLY PERMANENT REFUSALS, and the distinction is the whole of why
    /// this function is not just `offer_into`'s tests moved earlier.** A
    /// caller told `true` STEPS OVER the member and never comes back to it,
    /// so a refusal that is a property of the STAGE'S CURRENT STATE rather
    /// than of the member would lose that member for good. The queue being
    /// full and the byte ceiling being reached are both temporary: the
    /// cursor stops on them, and `Lookahead::feed`'s own `ahead_full` test
    /// is what stops it, so neither belongs here.
    ///
    /// It was written the wrong way first, with the queue's depth and the
    /// running byte total tested here, and that form is what this paragraph
    /// exists to stop a reader restoring. It cannot be caught by a byte of
    /// output and it was not caught by a measurement either. The argument
    /// is what decides it, and the argument is the contract: `true` means
    /// stepped over for ever.
    ///
    /// What IS permanent: the member's own declared sizes against the
    /// stage's per-member ceiling, a member whose single charge could never
    /// fit the whole budget, and the table bit clear with no run open. The
    /// last is permanent for THIS member because a caller told `true` steps
    /// over it, and stepping over it is what closes the run.
    pub(crate) fn refused_by_head(&self, head: &[u8], unpacked: u64, len: usize) -> bool {
        if unpacked == 0 || unpacked > self.member_max() {
            return true;
        }
        if len == 0 || len as u64 >= self.member_max() {
            return true;
        }
        // The member ALONE over the whole ceiling can never be taken, at any
        // queue depth. `held + charge` is the temporary form and is not
        // tested here, for the reason above.
        if len as u64 + unpacked > self.limit {
            return true;
        }
        // The RUN RULE, from the header alone. `None` is "cannot say".
        block::header_says_tables(head) == Some(false) && !self.run_open
    }

    /// Offer one member to the stage, answering whether it was taken.
    ///
    /// `false` is never an error: the member decodes on the path it always
    /// did, and a caller offering into a full queue is told to stop rather
    /// than to grow it.
    // The SHIPPED read path offers from a source and uses `offer_into`
    // below; this borrowed-slice form is the one a caller holding the
    // whole archive already uses - the package's own tests and the
    // `internals_h2` seam the fuzz target runs through - and neither is
    // compiled into a shipped build.
    #[allow(dead_code)]
    pub(crate) fn offer(&mut self, packed: &[u8], unpacked: u64, algorithm: u8) -> bool {
        self.offer_into(unpacked, algorithm, packed.len(), |room| {
            room.copy_from_slice(packed);
            true
        }) == Offered::Taken
    }

    /// Offer one member whose bytes are read STRAIGHT INTO the stage's own
    /// buffer, answering whether it was taken.
    ///
    /// The form a caller reading from a source uses, and the reason it
    /// exists is the one thread this lever is about: an offer made from a
    /// borrowed slice costs the walking thread a read into the caller's
    /// buffer and then a copy out of it, and this costs one read.
    ///
    /// `fill` is handed room for exactly `len` bytes and answers whether
    /// it filled them. A `false` costs the stage nothing: the work item
    /// goes back to the pool unused.
    ///
    /// **A permanent refusal closes the run; a temporary one does not.** A
    /// caller told [`Offered::Never`] steps over the member, and a
    /// stepped-over member may change the table set in force, so the member
    /// after it may not join the run the stepped-over one would have been
    /// in. A caller told [`Offered::Later`] stops where it is and offers the
    /// same member again once something has been claimed; nothing was
    /// stepped over, and closing the run there would cost the rest of the
    /// run every time the queue filled, which on a chain of short runs is
    /// most of the lever.
    pub(crate) fn offer_into<F>(
        &mut self,
        unpacked: u64,
        algorithm: u8,
        len: usize,
        fill: F,
    ) -> Offered
    where
        F: FnOnce(&mut [u8]) -> bool,
    {
        let outcome = self.offer_inner(unpacked, algorithm, len, fill);
        if outcome == Offered::Never {
            self.run_open = false;
        }
        outcome
    }

    fn offer_inner<F>(&mut self, unpacked: u64, algorithm: u8, len: usize, fill: F) -> Offered
    where
        F: FnOnce(&mut [u8]) -> bool,
    {
        if self.full() {
            return Offered::Later;
        }
        if unpacked == 0 || unpacked > self.member_max() {
            return Offered::Never;
        }
        if len == 0 || len as u64 >= self.member_max() {
            return Offered::Never;
        }
        let charge = len as u64 + unpacked;
        if charge > self.limit {
            return Offered::Never;
        }
        if self.held + charge > self.limit {
            return Offered::Later;
        }
        self.open();
        if self.lanes.is_empty() {
            return Offered::Never;
        }
        let mut work = self.take_spare().unwrap_or_else(|| {
            // The pool could not answer. Compiled out entirely without
            // `h2-probes`; see `crate::probe::note_ahead_alloc`.
            #[cfg(feature = "h2-probes")]
            crate::probe::note_ahead_alloc();
            Work::default()
        });
        if !fill(work.room(len)) {
            self.keep(work);
            return Offered::Never;
        }
        // THE RUN RULE, checked on the bytes once they are in hand:
        // nothing before this point could see them. A member whose first
        // block carries tables starts a run; one whose first block does
        // not may only join the run that is open.
        let head = match block::block_in_hand(work.packed()) {
            Ok(first) => first.carries_tables(),
            Err(_) => {
                self.keep(work);
                return Offered::Never;
            }
        };
        if !head && !self.run_open {
            self.keep(work);
            return Offered::Never;
        }
        let lane = if head {
            // A NEW RUN, on the lanes' next round. The head resets that
            // lane's carried set from its own first block, so whatever the
            // lane carried out of its previous run is never read again.
            self.run_id = self.run_id.wrapping_add(1);
            let lane = self.next_lane % self.lanes.len();
            self.next_lane = (lane + 1) % self.lanes.len();
            lane
        } else {
            self.run_lane
        };
        work.algorithm = algorithm;
        work.unpacked = unpacked;
        work.plan.far_off = self.far_off;
        work.failure = None;
        work.blocks = 0;
        work.head = head;
        work.run = self.run_id;
        work.lost = false;
        work.carry_group = None;
        work.done_at = None;
        let sent = match &self.lanes[lane].work {
            Some(work_tx) => work_tx.send(work).is_ok(),
            None => false,
        };
        if !sent {
            // A lane that has gone away leaves the stage with fewer than it
            // was built with, which is a performance loss and not an error
            // (API section 8.2: running narrower is in contract). The stage
            // is closed rather than left half alive.
            self.close();
            return Offered::Never;
        }
        self.held += charge;
        self.peak = self.peak.max(self.held);
        self.queued.push_back(Offer {
            lane,
            len,
            unpacked,
            run: self.run_id,
        });
        self.run_open = true;
        self.run_lane = lane;
        Offered::Taken
    }

    /// Claim the decoded member whose packed bytes are `packed`.
    ///
    /// The oldest outstanding offer is the only one that can match, because
    /// a chain is consumed in the order it was offered. One that does NOT
    /// match is kept for the member it was decoded for (the module header
    /// says what discarding it cost); one whose run was poisoned, or whose
    /// lane could not decode it, is discarded here and the member decodes
    /// on the path it always did.
    pub(crate) fn claim(&mut self, packed: &[u8], unpacked: u64, algorithm: u8) -> Option<Work> {
        loop {
            if self.parked.is_none() {
                let offer = *self.queued.front()?;
                let Some(lane) = self.lanes.get(offer.lane) else {
                    self.close();
                    return None;
                };
                // TRY FIRST, so a claim that had to WAIT can be counted:
                // the one number that says whether the stage is genuinely
                // ahead of the apply point. Compiled out entirely without
                // `h2-probes`; see `crate::probe`.
                let work = match lane.done.try_recv() {
                    Ok(work) => work,
                    Err(mpsc::TryRecvError::Empty) => {
                        #[cfg(feature = "h2-probes")]
                        crate::probe::note_ahead_stall();
                        // THE LANES ARE BEHIND. Grow here, before blocking,
                        // so a new lane's start is paid in time this thread
                        // was about to spend waiting anyway. The new lane
                        // takes the next run's head; the member waited on
                        // stays on its own lane.
                        self.stalls += 1;
                        if self.stalls >= grow_after_stalls() && self.lanes.len() < self.ceiling {
                            self.stalls = 0;
                            self.spawn_lane();
                        }
                        let Some(lane) = self.lanes.get(offer.lane) else {
                            self.close();
                            return None;
                        };
                        match lane.done.recv() {
                            Ok(work) => work,
                            Err(_) => {
                                self.close();
                                return None;
                            }
                        }
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.close();
                        return None;
                    }
                };
                self.queued.pop_front();
                self.parked = Some((offer, work));
                self.misses = 0;
            }
            let (offer, work) = self.parked.as_ref().expect("parked just above");
            let useless = work.lost || self.poisoned == Some(offer.run);
            if useless {
                // Its lane could not decode it, or a member before it in
                // the run was found to have carried the wrong set. Section
                // 3.8's consequence 1 in its widest form: work the serial
                // decoder would never have done is discarded, errors and
                // all, and the next offer is looked at in its place.
                self.discard_parked();
                continue;
            }
            let matches = work.unpacked == unpacked
                && work.algorithm == algorithm
                && work.len == packed.len()
                && work.packed() == packed;
            if matches {
                let (_, work) = self.parked.take().expect("parked just above");
                self.held = self.held.saturating_sub(work.charge());
                self.misses = 0;
                return Some(work);
            }
            // Not the member this was decoded for. It waits, unless it has
            // now been passed over by more members than the queue could
            // ever have held ahead of it, which is a front that will never
            // be reached: no offering layer here produces one, and the
            // bound is what keeps a stage that met one from being wedged
            // for the rest of the chain.
            self.misses += 1;
            if self.misses > self.depth {
                self.discard_parked();
            }
            return None;
        }
    }

    /// Hand the parked work back to the pool.
    fn discard_parked(&mut self) {
        if let Some((_, work)) = self.parked.take() {
            self.held = self.held.saturating_sub(work.charge());
            self.keep(work);
        }
        self.misses = 0;
    }

    /// The largest member this stage takes: [`AHEAD_MEMBER_MAX`]. (A wide
    /// form was decided against and removed.)
    fn member_max(&self) -> u64 {
        AHEAD_MEMBER_MAX
    }

    /// Put a finished item in the pool, and shed the LARGEST items while
    /// the pool holds more than [`Ahead::spare_limit`] by capacity.
    fn keep(&mut self, mut work: Work) {
        work.kept = work.capacity();
        self.spare_bytes = self.spare_bytes.saturating_add(work.kept);
        self.spare.push(work);
        while self.spare_bytes > self.spare_limit {
            let Some((largest, _)) = self
                .spare
                .iter()
                .enumerate()
                .max_by_key(|(_, work)| work.kept)
            else {
                break;
            };
            let shed = self.spare.swap_remove(largest);
            self.spare_bytes = self.spare_bytes.saturating_sub(shed.kept);
        }
        self.peak = self.peak.max(self.held.saturating_add(self.spare_bytes));
    }

    /// Take an item from the pool.
    fn take_spare(&mut self) -> Option<Work> {
        let work = self.spare.pop()?;
        self.spare_bytes = self.spare_bytes.saturating_sub(work.kept);
        Some(work)
    }

    /// Hand a claimed item back for the next offer, and CHECK THE CARRY.
    ///
    /// The apply stage has finished with this member and recorded the
    /// block it finished at in [`Work::done_at`]. If that block's group is
    /// not the group the lane carried forward, every member of the run
    /// still queued was decoded under a set the serial arm would never
    /// have had in force, and the run is poisoned: those members are
    /// discarded at their claim and decoded serially. A member that did
    /// not finish at all poisons the run too; its error ends the chain in
    /// any case, and the members behind it are then never claimed.
    pub(crate) fn give(&mut self, work: Work) {
        if !work.carry_agrees() {
            self.poisoned = Some(work.run);
        }
        self.keep(work);
    }

    /// Forget every offer. The lanes and their allocations are kept.
    ///
    /// The budget test's alone since 27 Sep 2026: a stream that restarts
    /// the chain KEEPS the queue, because everything in it lies behind the
    /// break (`Rar5Lz::reset`).
    #[cfg(test)]
    pub(crate) fn clear(&mut self) {
        self.discard_parked();
        while let Some(offer) = self.queued.front() {
            match self.lanes.get(offer.lane) {
                Some(lane) => match lane.done.recv() {
                    Ok(work) => self.keep(work),
                    Err(_) => {
                        self.close();
                        return;
                    }
                },
                None => break,
            }
            self.queued.pop_front();
        }
        self.queued.clear();
        self.held = 0;
        self.run_open = false;
        self.poisoned = None;
    }

    /// The lanes open right now, for the growth tests.
    #[cfg(test)]
    pub(crate) fn lanes_open(&self) -> usize {
        self.lanes.len()
    }

    /// The items this stage is holding, for the bound its test reads.
    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> usize {
        self.queued.len() + usize::from(self.parked.is_some())
    }

    /// The bytes this stage is charged with, for the bound its test reads.
    #[cfg(test)]
    pub(crate) fn charged(&self) -> u64 {
        self.held
    }

    /// Start the lanes, once per stage.
    fn open(&mut self) {
        if !self.lanes.is_empty() {
            return;
        }
        self.next_lane = 0;
        self.run_open = false;
        self.stalls = 0;
        for _ in 0..self.width {
            if !self.spawn_lane() {
                // A host that will not give this stage a thread gets the
                // path it had before the stage existed.
                break;
            }
        }
    }

    /// Start one lane. False when the host will not give the stage a
    /// thread, which leaves the lanes already open as they are.
    fn spawn_lane(&mut self) -> bool {
        // The channels are as deep as the queue, so a whole run can
        // sit on one lane without the walking thread ever blocking in
        // `send`: the queue's depth bounds what all the channels hold
        // together, and the stage's memory is the queue's charge and
        // not the channels' appetite.
        let (work_tx, work_rx) = mpsc::sync_channel::<Work>(self.depth);
        let (done_tx, done_rx) = mpsc::sync_channel::<Work>(self.depth);
        let handle = std::thread::Builder::new()
            .name("rarkit-h2-ahead".to_string())
            .spawn(move || {
                // THE CARRIED SET, lane local. A run's head replaces
                // it from its own first block; a member behind the
                // head reads it and may replace it; nothing else can
                // reach it.
                let mut carry: Carry = Carry::None;
                while let Ok(mut work) = work_rx.recv() {
                    decode_ahead(&mut work, &mut carry);
                    if done_tx.send(work).is_err() {
                        break;
                    }
                }
            })
            .ok();
        match handle {
            Some(handle) => {
                self.lanes.push(Lane {
                    work: Some(work_tx),
                    done: done_rx,
                    handle: Some(handle),
                });
                // Compiled out entirely without `h2-probes`.
                #[cfg(feature = "h2-probes")]
                crate::probe::note_ahead_lanes(self.lanes.len());
                true
            }
            None => false,
        }
    }

    /// Stop every lane and forget every offer.
    fn close(&mut self) {
        self.queued.clear();
        self.parked = None;
        self.misses = 0;
        self.held = 0;
        self.run_open = false;
        self.poisoned = None;
        for mut lane in self.lanes.drain(..) {
            // Dropping the sender is what ends the lane's loop; draining
            // the answers rather than dropping them is what wakes a lane
            // parked in `send`.
            lane.work = None;
            while lane.done.recv().is_ok() {}
            if let Some(handle) = lane.handle.take() {
                // Section 4.3 says this package does not panic. If a lane
                // ever does, the panic is the caller's to see: swallowing
                // it would turn a bug into a silently serial decode.
                if let Err(payload) = handle.join() {
                    std::panic::resume_unwind(payload);
                }
            }
        }
    }
}

impl Drop for Ahead {
    fn drop(&mut self) {
        // A lane holds nothing borrowed, but a thread still running after
        // its owner is gone is a leak. A panic is NOT re-raised from here:
        // unwinding out of a drop during another unwind aborts the process.
        for mut lane in self.lanes.drain(..) {
            lane.work = None;
            while lane.done.recv().is_ok() {}
            if let Some(handle) = lane.handle.take() {
                let _ = handle.join();
            }
        }
    }
}

/// What a lane carries from one member of a run to the next.
enum Carry {
    /// Nothing: the next member must be a head.
    None,
    /// The set in force after the last member decoded.
    Tables(Arc<Tables>),
    /// A member of this run could not say what it left in force, so
    /// every member behind it in the run is lost.
    Lost,
}

/// Walk one offered member's chain and decode every block of it.
///
/// Touches no window, no repeated distance, no last length and no filter
/// queue: that is section 3.8's property, and it is the whole of why this
/// may run while another member is being applied.
///
/// The chain is walked WITH the set the lane carried when the member is
/// not a run's head, and with none when it is: a head's first block
/// carries its own set (`Ahead::offer_into` checked it), so every group a
/// head's walk finds begins inside its own packed bytes. What the lane
/// carries out is the set of the member's last group, or what it carried
/// in when the member opened no group of its own; the module header says
/// how the apply stage checks that against where the member actually
/// finished.
fn decode_ahead(work: &mut Work, carry: &mut Carry) {
    let Work {
        packed,
        len,
        algorithm,
        plan,
        tapes,
        held,
        failure,
        blocks,
        head,
        lost,
        carry_group,
        ..
    } = work;
    let carried: Option<Arc<Tables>> = if *head {
        None
    } else {
        match carry {
            Carry::Tables(tables) => Some(Arc::clone(tables)),
            Carry::None | Carry::Lost => {
                // A member behind a head that lost its set, or behind
                // nothing at all: undecodable here, and said so rather
                // than decoded under the wrong set.
                *lost = true;
                *carry = Carry::Lost;
                *carry_group = None;
                *blocks = 0;
                return;
            }
        }
    };
    // THE ONE DELIBERATE CORRUPTION, for the test that shows the carry
    // is what the equivalence rests on: a head keeps the set its lane
    // carried out of the PREVIOUS run instead of its own, so the members
    // behind it decode under a stale set. Compiled out entirely without
    // `test-support`; see `crate::probe::set_ahead_carry_stale`.
    #[cfg(feature = "test-support")]
    let stale = crate::probe::ahead_carry_stale();
    #[cfg(not(feature = "test-support"))]
    let stale = false;
    let packed = &packed[..*len];
    *failure = tape::plan(packed, carried.is_some(), plan).err();
    *blocks = plan.blocks.len();
    while tapes.len() < *blocks {
        // A block this work item has no tape for yet. Compiled out
        // entirely without `h2-probes`; see `crate::probe`.
        #[cfg(feature = "h2-probes")]
        crate::probe::note_ahead_alloc();
        tapes.push(BlockTape::default());
    }
    while held.len() < *blocks {
        held.push(None);
    }
    for index in 0..*blocks {
        held[index] = tape::decode_one_dispatch(
            plan,
            packed,
            *algorithm,
            carried.as_ref(),
            index,
            &mut tapes[index],
        );
    }
    // WHAT THE LANE CARRIES OUT. The member's last group is the last
    // block's, and `decode_one` answered `None` for that block only when
    // the group's set could not be built, in which case nothing usable is
    // in force and the run behind this member is lost.
    let groups = plan.groups.len();
    let own_groups = groups > usize::from(carried.is_some());
    let out = if !own_groups {
        carried.clone()
    } else {
        held.get(*blocks - 1).cloned().flatten()
    };
    if stale && *head {
        // The corruption: keep whatever was carried before this head.
        *carry_group = Some(groups.saturating_sub(1));
        if matches!(carry, Carry::None) {
            *carry = out.map_or(Carry::Lost, Carry::Tables);
        }
        return;
    }
    match out {
        Some(tables) => {
            *carry_group = Some(groups - 1);
            *carry = Carry::Tables(tables);
        }
        None => {
            *carry_group = None;
            *carry = Carry::Lost;
        }
    }
}

/// The pool of finished items is bounded by the CAPACITY they hold, and
/// sheds its largest items first.
#[cfg(test)]
mod spare_tests {
    use super::{spare_limit, Ahead, Work};

    fn item(bytes: usize) -> Work {
        Work {
            packed: Vec::with_capacity(bytes),
            ..Work::default()
        }
    }

    #[test]
    fn the_pool_keeps_no_more_capacity_than_its_ceiling_and_sheds_the_largest() {
        let limit = 1u64 << 20;
        let mut stage = Ahead::new(limit, 1);
        let ceiling = spare_limit(limit);
        // A chain of small members: every item is kept for the next offer.
        let small = (limit / 8) as usize;
        let fit = (ceiling / small as u64) as usize;
        for _ in 0..fit {
            stage.keep(item(small));
        }
        assert_eq!(
            stage.spare.len(),
            fit,
            "a small item was shed under the ceiling"
        );
        // One large item over the ceiling: the largest goes, the small stay.
        stage.keep(item(2 * limit as usize));
        assert!(
            stage.spare_bytes <= ceiling,
            "{} > {ceiling}",
            stage.spare_bytes
        );
        assert!(stage.spare.iter().all(|w| w.kept <= small as u64 * 2));
        // What the pool counts is what its items hold.
        let held: u64 = stage.spare.iter().map(Work::capacity).sum();
        assert_eq!(held, stage.spare_bytes);
        // Taking an item gives its capacity back to the count.
        let taken = stage.take_spare().expect("an item");
        assert_eq!(stage.spare_bytes, held - taken.kept);
    }
}
