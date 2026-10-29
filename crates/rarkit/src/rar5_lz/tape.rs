//! The parallel block decode (SPEC-H2 section 3.8).
//!
//! **Why this can exist at all.** A block's symbol stream depends only on
//! the tables in force for that block. It does not depend on the window, on
//! the repeated distances, on the last match length, or on any filter:
//! everything a symbol reads is a table lookup or a fixed width bit field.
//! The repeated distances and the last length are consumed only when a
//! decoded operation is APPLIED. So a block can be Huffman decoded ahead of
//! the blocks before it, into a TAPE whose repeat operations name a slot
//! rather than a distance, and a serial apply stage then resolves them in
//! archive order and reproduces the serial decoder's bytes, stops and
//! errors exactly.
//!
//! Two consequences section 3.8 requires and this module keeps:
//!
//! 1. A block located ahead of the decode point may fail. Its error is
//!    DEFERRED in [`BlockTape::failure`] and discarded unless the member
//!    genuinely reaches it: work the serial decoder would never have done
//!    must not produce an error the serial decoder would never have raised.
//! 2. The member's OUTPUT stops at its declared unpacked size at the same
//!    OPERATION in both arms, and both apply every remaining symbol of the
//!    member's blocks to the window and the repeat state (3.1, amended
//!    28 Sep 2026): [`apply`] walks every operation of its tape, and
//!    the window's drain caps what reaches the sink.
//!
//! The operation encoding, the caps and the buffer recycling are carried
//! (`tape_kind`, `TAPE_KIND_SHIFT`, `TAPE_OPS_CAP`, `TAPE_LITS_CAP`,
//! `TAPE_RECYCLE_BYTES_MAX`, `MT_MAX_WORKERS`, `MT_MIN_OUTPUT`,
//! `mt_worker_count`); the rest is this specification's.

use std::sync::{Arc, Mutex};

use super::bits::BitReader;
use super::block::Located;
use super::fault;
use super::filters::{self, Filters, RawRecord};
use super::ladders::fresh_match_length;
// `super::ladders` and `super::output` as the bodies in `tape/decode.rs` and
// `tape/census.rs` name them.
use super::output::{LzSink, Window};
use super::tables::{TableScratch, Tables, LUT_ENTRIES};
use super::{ladders, output};
use super::{
    lut_symbol, read_distance, read_length, read_length_slot, MatchState, SYMBOL_FILTER,
    SYMBOL_MATCH_BASE, SYMBOL_REPEAT_BASE, SYMBOL_REPEAT_LAST,
};
use crate::carry::c_lz::codec::rar50::{
    lut_entry_is_literal, mt_worker_count, TapeApplied, MT_MAX_WORKERS, MT_MIN_OUTPUT,
    TAPE_KIND_SHIFT, TAPE_LITS_CAP, TAPE_OPS_CAP, TAPE_RECYCLE_BYTES_MAX,
};
use crate::{Error, Result};

// The tape's parts, one module a seam.
#[cfg(any(
    feature = "h2-instruments",
    feature = "copy-census",
    feature = "h2-locality-census"
))]
mod census;
#[cfg(any(
    feature = "h2-instruments",
    feature = "copy-census",
    feature = "h2-locality-census"
))]
pub(crate) use census::*;
mod width;
pub(crate) use width::*;
mod wave;
pub(crate) use wave::*;
mod resolve;
pub(crate) use resolve::*;
mod apply;
pub(crate) use apply::*;
mod decode;
pub(crate) use decode::*;

/// The literal batch, a module of its own so the scalar decode below is
/// compiled exactly as it is without it (its own note says why).
pub(crate) mod batch;

/// The plain control decode, which the literal batch's region reads (the
/// fresh-match levers are the scalar region's alone), and with the
/// `h2-fresh-match-knob` feature the control's scalar region beside the levers',
/// for a timed run in one binary.
mod main_region;

/// THE LANE'S REACH ([`BlockTape::reach`]), after the block's decode and
/// outside its loop, where the piece is on ([`seq::TRUST`]): one pass over
/// the operations, BRANCH FREE, keeping the largest fresh distance and
/// whether any is zero. The apply stage asks the window ONCE a tape whether
/// it admits that reach ([`Window::admits_reach`]); where it does, no fresh
/// match of the tape can fail `copy_match`'s three range tests, and the
/// walk copies it without them.
#[inline(always)]
pub(crate) fn note_reach(tape: &mut BlockTape) {
    if seq_on() & seq::TRUST == 0 {
        return;
    }
    tape.reach = Some(reach_of(&tape.steps));
}

/// The farthest any fresh match of `ops` reaches back, or `usize::MAX`
/// where one's distance is zero ([`note_reach`]).
#[inline(always)]
pub(crate) fn reach_of(ops: &[TapeOp]) -> usize {
    let mut far = 0u32;
    let mut zero = false;
    for op in ops {
        let fresh = op.kind() == tape_kind::MATCH;
        far = far.max(op.distance & u32::from(fresh).wrapping_neg());
        zero |= fresh & (op.distance == 0);
    }
    if zero {
        usize::MAX
    } else {
        far as usize
    }
}

/// Tape op kinds; carried.
pub(crate) mod tape_kind {
    /// Emit the next `length` bytes from the tape's literal buffer.
    pub(crate) const LITS: u32 = 0;
    /// Fully resolved match (symbol 262..).
    pub(crate) const MATCH: u32 = 1;
    /// Repeat distance match (symbols 258..=261); `distance` carries the
    /// rep INDEX, resolved against the live state at apply.
    pub(crate) const REP: u32 = 2;
    /// Symbol 257: reuse the last distance and length.
    pub(crate) const REP_LAST: u32 = 3;
    /// Symbol 256: the payload is the next entry of `BlockTape::filters`
    /// and its start resolves at apply.
    pub(crate) const FILTER: u32 = 4;
}

/// WHAT A RESOLVED COPY WAS (form A4): bits 26 to 28 of a `MATCH` op's
/// length word on a tape [`resolve_repeats`] rewrote. 0 is a fresh match,
/// 1 to 4 a `REP` of index 0 to 3, [`WAS_REP_LAST`] a `REP_LAST`. The
/// length and the prefix end at bit 25 ([`LENGTH_BITS`]), so the bits are
/// always free; only [`apply_resolved`] and its replay read them, and
/// [`TapeOp::length`] and [`TapeOp::prefix`] never see them.
const WAS_SHIFT: u32 = 26;
/// See [`WAS_SHIFT`].
const WAS_REP_LAST: u32 = 5;
const _: () = assert!(2 * LENGTH_BITS <= WAS_SHIFT && WAS_SHIFT + 3 <= TAPE_KIND_SHIFT);
/// A repeat that reads the state the tape FOUND is kept as decoded and
/// applied against the live state replayed to it; a tape is resolved only
/// where every such repeat lies in its first this many operations, so the
/// replay is cheap.
const LIVE_WITHIN: usize = 64;
/// The fewest lanes a member may have for its lanes to take the repeat
/// pass: below this the lanes are the critical path (form A5).
pub(crate) const RESOLVE_MIN_LANES: usize = 8;
/// THE GATE: the repeats among a tape's first this many ops...
const GATE_SAMPLE: usize = 256;
/// ...must be at least one in this many, or the tape keeps the control's walk.
const GATE_EVERY: usize = 32;

/// THE SEQUENCE OP: every
/// operation carries the literal run that comes BEFORE it, its PREFIX, in
/// bits 13 to 25 of its length word, and its own length in bits 0 to 12.
/// A control symbol's length is at most 4,100 (SPEC-H2 3.5: slot 43 gives
/// 4,097, the bonus three more), so thirteen bits hold it, and the apply
/// walk copies the prefix and then the operation with no branch between
/// them: one operation a match and its literals rather than two, and no
/// `LITS` against `MATCH` dispatch for the walk to mispredict. A `LITS`
/// operation is a prefix and nothing else (its own length is zero); a
/// run longer than [`PREFIX_MAX`] is cut into several.
const LENGTH_BITS: u32 = 13;
/// An operation's own length.
const LENGTH_MASK: u32 = (1 << LENGTH_BITS) - 1;
/// The longest literal run one operation carries as its prefix.
pub(crate) const PREFIX_MAX: usize = (1 << LENGTH_BITS) - 1;

/// One decoded operation. A plain struct rather than a Rust enum so the
/// kind is a field and the whole op is eight bytes; carried.
#[derive(Clone, Copy)]
pub(crate) struct TapeOp {
    kind_length: u32,
    pub(crate) distance: u32,
}

impl TapeOp {
    /// A `LITS` of no bytes: what the operation cursor's room holds before
    /// the region writes it ([`open_ops`]), never an operation of a tape.
    pub(crate) const EMPTY: TapeOp = TapeOp {
        kind_length: 0,
        distance: 0,
    };

    /// A control operation with no prefix.
    #[inline(always)]
    pub(crate) fn new(kind: u32, length: usize, distance: u32) -> TapeOp {
        debug_assert!(length as u32 <= LENGTH_MASK);
        debug_assert!(kind != tape_kind::LITS || length == 0);
        TapeOp {
            kind_length: (kind << TAPE_KIND_SHIFT) | length as u32,
            distance,
        }
    }
    /// A `LITS` of `run` literals, at most [`PREFIX_MAX`].
    #[inline(always)]
    pub(crate) fn lits(run: usize) -> TapeOp {
        debug_assert!(run <= PREFIX_MAX);
        TapeOp {
            kind_length: (run as u32) << LENGTH_BITS,
            distance: 0,
        }
    }
    /// This operation with `run` literals before it, at most
    /// [`PREFIX_MAX`], in place of the prefix it had (none).
    #[inline(always)]
    pub(crate) fn after(self, run: usize) -> TapeOp {
        debug_assert!(run <= PREFIX_MAX && self.prefix() == 0);
        TapeOp {
            kind_length: self.kind_length | (run as u32) << LENGTH_BITS,
            distance: self.distance,
        }
    }
    #[inline(always)]
    pub(crate) fn kind(self) -> u32 {
        self.kind_length >> TAPE_KIND_SHIFT
    }
    /// The operation's own length: zero for a `LITS`, whose literals are
    /// its [`TapeOp::prefix`].
    #[inline(always)]
    pub(crate) fn length(self) -> usize {
        (self.kind_length & LENGTH_MASK) as usize
    }
    /// The literals before the operation.
    #[inline(always)]
    pub(crate) fn prefix(self) -> usize {
        (self.kind_length >> LENGTH_BITS & LENGTH_MASK) as usize
    }
    /// The bytes the operation produces as the tape says: its prefix and
    /// its own length (a `REP_LAST`'s own length is the live state's and
    /// counts zero here).
    #[inline(always)]
    pub(crate) fn bytes(self) -> usize {
        self.prefix() + self.length()
    }
}

/// One block decoded into operations, with the window untouched.
#[derive(Default)]
pub(crate) struct BlockTape {
    pub(crate) steps: Vec<TapeOp>,
    pub(crate) verbatim: Vec<u8>,
    pub(crate) records: Vec<RawRecord>,
    /// Where a PARKED block stopped, so the serial path finishes it. A
    /// worker parks when it exceeds `TAPE_OPS_CAP` or `TAPE_LITS_CAP`, or
    /// when a distance does not fit the op's `u32`. Parking is a
    /// performance decision and must not change a byte.
    pub(crate) parked_at: Option<usize>,
    /// The error this block met, raised only if the member reaches it.
    pub(crate) failure: Option<Error>,
    /// THE FAR LIST:
    /// every fresh match of `steps` reaching [`Window::FAR_GATE_DISTANCE`]
    /// or further, in operation order, written on the decode lane after
    /// the block's loop ([`build_far_list`]) and only for a tape the far
    /// prefetch's gate admits. ONE word on the tape, outside the fields
    /// the walk reads, so [`apply`] compiles as it did before the list.
    /// A tape that carries a whole list is walked by [`apply_listed`]
    /// instead of [`apply`] ([`listed`], asked by the apply stage).
    pub(crate) far: Option<Box<FarList>>,
    /// THE REPEATS RESOLVED ON THE LANE ([`resolve_repeats`]): `Some` when
    /// every `REP` and `REP_LAST` of `steps` was rewritten with its distance,
    /// holding the state the tape leaves behind in terms of the state it
    /// finds. The apply stage TAKES it ([`Option::take`]), so a recycled
    /// tape can never carry it into another block's decode.
    pub(crate) resolved: Option<RepeatEnd>,
    /// Build no far list for this tape: its stream's dictionary is at or
    /// under `Window::FAR_DICTIONARY_FLOOR`. Copied from the plan
    /// ([`Plan::far_off`]) by `decode_one` before each decode.
    pub(crate) far_off: bool,
    /// THE LANE'S ANSWER TO THE COPY'S RANGE TESTS ([`note_reach`]): the
    /// farthest any fresh match of `steps` reaches back, or `usize::MAX` for
    /// a tape holding a zero distance; `None` where the lane did not ask
    /// (the piece off, or a tape built by hand), which keeps every test.
    pub(crate) reach: Option<usize>,
}

impl BlockTape {
    fn clear(&mut self) {
        self.steps.clear();
        self.verbatim.clear();
        self.records.clear();
        self.parked_at = None;
        self.failure = None;
        // The far list is NOT reset here: `build_far_list` runs after every
        // decode into a tape and settles `complete` itself, and the one
        // path that clears a tape without decoding (a group whose tables
        // fail) leaves no operation to hint. Reset here, it put three
        // instructions into the decoder this is inlined into.
    }

    /// Whether this tape is small enough to keep for the next block; the
    /// bound is carried, and the far list is held to it too.
    fn worth_recycling(&self) -> bool {
        self.verbatim.capacity() <= TAPE_RECYCLE_BYTES_MAX
            && self.steps.capacity() * std::mem::size_of::<TapeOp>() <= TAPE_RECYCLE_BYTES_MAX
            && self.far.as_ref().map_or(0, |far| far.backs.capacity()) * std::mem::size_of::<u32>()
                <= TAPE_RECYCLE_BYTES_MAX
    }
}

/// The far list as a test reads it; unit tests only, so no build that is
/// measured carries this.
#[cfg(test)]
impl BlockTape {
    /// The list's entries SPREAD to one an operation (a far match's back
    /// where it sits, zero for every other operation), the dense form its
    /// specification is written in, and whether it is whole. Spreading
    /// checks the compact form on the way: one start a chunk and one for
    /// the end, every chunk's run exactly its far matches, no entry
    /// missing and none left over.
    pub(crate) fn far_entries(&self) -> (Vec<u32>, bool) {
        let Some(far) = self.far.as_deref().filter(|far| far.complete) else {
            return (Vec::new(), false);
        };
        let chunks = self.steps.len().div_ceil(far.chunk);
        assert_eq!(
            far.starts.len(),
            chunks + 1,
            "one start a chunk and the end"
        );
        let mut spread = Vec::with_capacity(self.steps.len());
        for (group, run) in self.steps.chunks(far.chunk).enumerate() {
            let mut next = far.starts[group] as usize;
            for op in run {
                if op.distance as usize >= Window::far_distance() {
                    spread.push(far.backs[next]);
                    next += 1;
                } else {
                    spread.push(0);
                }
            }
            assert_eq!(
                next,
                far.starts[group + 1] as usize,
                "chunk {group}: its run"
            );
        }
        assert_eq!(far.starts[chunks] as usize, far.len, "every entry used");
        (spread, true)
    }
}

/// A tape's far list, boxed so the tape grows by one word.
///
/// THE COMPACT HINT STREAM (form H1): the lane writes the
/// one number a hint needs for every FAR match only, in operation order,
/// and the start of each chunk's run of them, so the walk hints the next
/// chunk's far matches and nothing else. The dense stream it replaces
/// held an entry for
/// every operation, and every entry but a far match's was zero, a hint of
/// the write point repeated once an operation. A hint is still a load, a
/// subtract, one wrap and the prefetch ([`Window::prefetch_back`]).
#[derive(Default)]
pub(crate) struct FarList {
    /// Every FAR match's BACK, in operation order: its distance less its
    /// AHEAD, the tape lengths between the start of the chunk BEFORE its
    /// own and itself (a `REP_LAST` and a filter counting zero, as the
    /// prefetch pass counts them); that chunk's start is where the walk
    /// hints it, so the hint is the write point there less this back:
    /// exactly the pass's own address for that operation. Its first `len`
    /// entries are the stream; the rest are room a recycled tape keeps
    /// (the buffer only ever grows, to one slot an operation, so it is
    /// written without first being zeroed).
    pub(crate) backs: Vec<u32>,
    /// Where each chunk's far matches start in `backs`, one entry a chunk
    /// and one more for the end: chunk `g`'s are `starts[g]..starts[g + 1]`.
    pub(crate) starts: Vec<u32>,
    /// The chunk the backs were written for: the prefetch depth the lane
    /// read. The walk takes a stream only at its own depth ([`listed`]).
    pub(crate) chunk: usize,
    /// How many entries of `backs` are the stream: the tape's far matches.
    pub(crate) len: usize,
    /// Whether the list is the whole list of the tape's operations as
    /// they stand; false for a tape the builder refused and for a recycled
    /// tape not yet listed again.
    pub(crate) complete: bool,
}

/// The most operations a tape may have for its far list to be written. A
/// longer tape gets no list and is walked by [`apply`] as it ships, and a
/// list holds one `u32` an operation, at most 256 KiB a tape. Real tapes
/// run to about 16,000 operations (the far list census).
pub(crate) const FAR_LIST_CAP: usize = 1 << 16;

/// The fewest operations a tape must have for its far list to be written.
/// A shorter tape is walked by [`apply`] as it ships, the pass and its own
/// gate hinting it exactly as on main, so the floor is a price and never a
/// behaviour: the list's walk saves little on a tape of a few chunks,
/// while a lane that samples the gate for every tape of a small solid set
/// pays per member (`rar5_small_solid_20k_vsnull`, +3.5 percent
/// instructions and +6.7 percent CPU without it, an Apple M3 Mac, 24 Sep 2026).
/// The text rows' tapes run to about 16,000 operations. The test build's
/// tapes are capped at 1,024 operations (`TAPE_OPS_CAP`), so its floor is
/// a chunk, which keeps every list path under test.
#[cfg(not(test))]
pub(crate) const FAR_LIST_MIN_OPS: usize = 1024;
/// See the shipped `FAR_LIST_MIN_OPS`.
#[cfg(test)]
pub(crate) const FAR_LIST_MIN_OPS: usize = 64;

/// Whether the decode lane writes the far list and the apply stage walks a
/// tape that carries one with [`apply_listed`].
///
/// ON on every arch. ON on x86-64 from 25 Sep 2026 (replacing
/// the earlier far-prefetch default there): Zen 5 read text_m3
/// 1.117x and w4 1.107x by timed wall, the i9 held, and the serial rows'
/// sub-1 percent moves counted EQUAL instructions. Two cfg lines kept so the file's lines do not move.
/// A compile-time constant, not arm code: the same source on both arches.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) const FAR_LIST: bool = true;
/// See the other arches' `FAR_LIST`.
#[cfg(target_arch = "x86_64")]
pub(crate) const FAR_LIST: bool = true;

/// Whether this build carries the list knob ([`far_list_knob`]): with
/// `h2-far-list-knob`, the knob and nothing else, so its binary's
/// [`apply`] is the control's and a knob cell prices the list against the control's own
/// walk in one binary; or with `h2-apply-arms`, beside the arms. Either
/// way the decode lane writes the list whatever the default, so the knob
/// reaches the walk alone. The benchmark binary carries neither.
pub(crate) const LIST_KNOB: bool =
    cfg!(any(feature = "h2-apply-arms", feature = "h2-far-list-knob"));

/// A group's built table set and the bit its first block's own symbols
/// start at, or the KIND of the error the build met: `Error` is not
/// `Clone` and several blocks of a group ask for the same set.
type BuiltTables = std::result::Result<(Arc<Tables>, usize), String>;

/// The table set in force for a run of blocks, built once by whichever
/// worker needs it first and shared read only after.
///
/// A block that carries tables starts a group; the blocks after it with the
/// table bit clear use the group's set unchanged (section 3.2). The set
/// lives at the front of the group's FIRST block, so any worker can build
/// it without the blocks before it.
pub(crate) struct LazyDecodeTables {
    /// The group's first block, whose payload carries the lengths, or
    /// `None` for the group a previous member left behind.
    first: Option<usize>,
    /// The built set and the bit position the group's first block's own
    /// symbols start at, which is past the table section it carries.
    ///
    /// A `Mutex` rather than a `OnceLock` so the set can be RELEASED once
    /// the apply stage has passed the group: section 4.2 wants at most two
    /// table sets live at once, and a `OnceLock` would hold every group's
    /// set until the member ended, which is memory that scales with the
    /// archive.
    cell: Mutex<Option<BuiltTables>>,
}

/// How many table sets one thread keeps for its own next builds: as many
/// as a lane has OUT AT ONCE and one unit more. A lane's sets are out from
/// their build until the apply stage has passed their blocks, and it runs
/// up to three units ahead of that (the unit it decodes, the unit queued
/// and the unit being applied, `member_piped`), each of at most
/// [`TAPE_UNIT_BLOCKS`] blocks, each block with a set of its own where the
/// writer put tables in every block. Kept at fewer (it was four), a lane
/// of such a member found no set of its own free for most of its builds,
/// made a fresh one and let it go again, a block after a block.
///
/// A set is eight 2 KiB lookups and its lists, about 25 KiB, so a thread
/// keeps at most about 400 KiB, whatever the member; and it keeps only
/// sets it had out at once, which were live then whatever this number.
const OWN_SETS_MOST: usize = 4 * TAPE_UNIT_BLOCKS;

/// The table sets THIS thread built and still holds, and the scratch its
/// builds read lengths into.
///
/// **Why.** Section 4.2 wants no allocation per block, and the lanes' build
/// allocated a fresh set and a fresh scratch for EVERY group: four lookup
/// boxes zeroed, a fifth for the level table, and their lists grown. A
/// writer that puts tables in every block of about 16 KiB, which is what
/// the reference does to media-like input, paid that 255,227 times on 4
/// GiB, about 1.8 G cycles of the allocator's (29 Sep 2026,
/// the per block cost of reference-made small blocks).
///
/// **Why per thread, and not one free list for the plan.** A shared list
/// handed a set the apply thread had released to whichever worker asked
/// next, so the set was rewritten on a core that did not build it, and its
/// retention cost about 1.3 MiB. On a Zen 4 machine that form read rarkit's
/// OWN archives about 1 percent slower at `-mt16` and `-mt4`. Here a set is
/// only ever rewritten by the thread that built it, IN PLACE, once nothing
/// else holds it: the plan has released its group and every tape that used
/// it has been applied, which `Arc::get_mut` answers. A set built into a
/// reused allocation is the same set, because [`DecodeTable::build`]
/// rewrites every field it reads.
///
/// A held set is an idle allocation, not a live set: section 4.2's two
/// live sets are the ones blocks are decoded or applied with.
#[derive(Default)]
struct OwnTables {
    held: Vec<Arc<Tables>>,
    scratch: TableScratch,
}

thread_local! {
    static OWN_TABLES: std::cell::RefCell<OwnTables> = std::cell::RefCell::new(OwnTables::default());
}

/// Read a group's tables into one of this thread's held sets that nobody
/// else uses any more, or into a fresh one, and keep a hold on it for this
/// thread's later builds while it has room.
fn build_own(bits: &mut BitReader<'_>, algorithm: u8) -> Result<Arc<Tables>> {
    OWN_TABLES.with(|own| {
        let mut own = own.borrow_mut();
        let own = &mut *own;
        let free = own
            .held
            .iter_mut()
            .position(|held| Arc::get_mut(held).is_some());
        let mut tables = match free {
            Some(at) => own.held.swap_remove(at),
            None => Arc::new(Tables::default()),
        };
        let read = Arc::get_mut(&mut tables)
            .expect("a fresh set, or a held set nothing else holds")
            .read(bits, algorithm, &mut own.scratch);
        if own.held.len() < OWN_SETS_MOST {
            own.held.push(Arc::clone(&tables));
        }
        read.map(|()| tables)
    })
}

impl LazyDecodeTables {
    /// The tables of this group, building them if this is the first ask,
    /// into a set this thread holds ([`OwnTables`]).
    fn get(
        &self,
        plan: &Plan,
        packed: &[u8],
        algorithm: u8,
        carried: Option<&Arc<Tables>>,
    ) -> Result<(Arc<Tables>, usize)> {
        let Some(first) = self.first else {
            return carried
                .cloned()
                .map(|tables| (tables, 0))
                .ok_or_else(fault::empty_table);
        };
        let build = || {
            let block = &plan.blocks[first];
            let mut bits = BitReader::new(block.payload(packed), block.bits());
            build_own(&mut bits, algorithm).map(|tables| (tables, bits.position()))
        };
        let mut held = self.cell.lock().unwrap_or_else(|e| e.into_inner());
        if held.is_none() {
            // `Error` is not `Clone` and several blocks of a group ask for
            // the same set, so a failed build is remembered by its KIND,
            // which is what the two arms are compared on, and rebuilt into
            // a fresh error for each asker.
            *held = Some(build().map_err(|err| format!("{:?}", err.kind())));
        }
        match held.as_ref().expect("just filled") {
            Ok((tables, start)) => Ok((Arc::clone(tables), *start)),
            Err(_) => match build() {
                Err(err) => Err(err),
                // The build is deterministic, so this cannot happen; a
                // fresh `EmptyTable` rather than a panic if it ever did.
                Ok(_) => Err(fault::empty_table()),
            },
        }
    }

    /// Let the set go, for a group the apply stage has passed: the thread
    /// that built it reuses it once the last tape holding it is applied.
    fn release(&self) {
        self.cell.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
}

impl Plan {
    /// Drop the table sets of every group below `group`: no block still to
    /// be decoded or applied can ask for them, because `group_of` never
    /// decreases and the workers only ever run AHEAD of the apply stage.
    /// A released set goes back to the thread that built it ([`OwnTables`]),
    /// which rebuilds into it once nothing else holds it.
    ///
    /// **The scan starts where the last one stopped**, which is what makes
    /// it linear in the member's groups rather than quadratic in them.
    /// This runs once per BLOCK on the one apply thread, and `group_of` is
    /// non decreasing, so a scan that began at zero re-locked every group
    /// it had already emptied: on a 64 MiB incompressible member the
    /// reference writer cuts 3,152 blocks each carrying its own tables, so
    /// the scan took a mutex and moved an `Option<Tables>` 4,965,976 times
    /// for 3,152 sets to release, and a sampling profile put 37% of the
    /// apply thread inside it (21 Sep 2026). The low
    /// water mark below is the whole of the fix; which sets are live is
    /// unchanged, so section 4.2's "at most two table sets live at once"
    /// reads exactly as before.
    ///
    /// The mark is an atomic because [`Plan`] is shared with the decode
    /// lanes by reference, not because it is contended: only the apply
    /// stage ever calls this, so `Relaxed` is the whole ordering it needs.
    pub(crate) fn release_below(&self, group: usize) {
        let upto = group.min(self.groups.len());
        let from = self.released.load(std::sync::atomic::Ordering::Relaxed);
        if from >= upto {
            return;
        }
        for held in &self.groups[from..upto] {
            held.release();
        }
        self.released
            .store(upto, std::sync::atomic::Ordering::Relaxed);
    }

    /// Forget one member's chain, keeping the allocations.
    pub(crate) fn clear(&mut self) {
        self.blocks.clear();
        self.starts.clear();
        self.group_of.clear();
        self.groups.clear();
        self.released.store(0, std::sync::atomic::Ordering::Relaxed);
        self.saw_last = false;
        self.failure = None;
        self.units.clear();
    }
}

/// One member's chain, located and grouped, ready for the workers.
#[derive(Default)]
pub(crate) struct Plan {
    pub(crate) blocks: Vec<Located>,
    /// Each block's offset in the member's packed bytes.
    pub(crate) starts: Vec<usize>,
    /// Each block's table group.
    pub(crate) group_of: Vec<usize>,
    pub(crate) groups: Vec<LazyDecodeTables>,
    /// The group the next release scan starts at: every group below it has
    /// already handed its table set back. See [`Plan::release_below`].
    released: std::sync::atomic::AtomicUsize,
    /// Whether the chain ended on a block flagged last.
    pub(crate) saw_last: bool,
    /// Whether this plan's tapes skip the far list, because the stream's
    /// dictionary is at or under `Window::FAR_DICTIONARY_FLOOR`. Set by the
    /// plan's owner, which knows the stream, and NOT reset by
    /// [`Plan::clear`]: it is a property of the stream, not of a member.
    pub(crate) far_off: bool,
    /// Where the walk stopped, and why.
    ///
    /// A block located AHEAD of the decode point may fail. Its error is
    /// deferred here and raised only if the member genuinely reaches it
    /// (section 3.8, consequence 1): work the serial decoder would never
    /// have done must not produce an error the serial decoder would never
    /// have raised.
    pub(crate) failure: Option<Error>,
    /// The chain cut into TAPE UNITS, each a run of consecutive blocks as
    /// `start..end`, filled by [`Plan::cut_units`] for the piped lanes.
    pub(crate) units: Vec<(usize, usize)>,
}

/// The most PACKED bytes one tape unit may span (SPEC-API 8.2).
///
/// **Why a unit's tape stays within one block's per-tape cap before a
/// symbol is decoded.** Every RAR 5 symbol, literal or match, takes at
/// least one bit, so a run of blocks spanning at most 2^21 bits (256 KiB)
/// decodes to at most 2^21 operations and 2^21 literals: within
/// `TAPE_OPS_CAP` (2^21) and `TAPE_LITS_CAP` (4 MiB). 64 KiB is a quarter
/// of that. The plan knows every block's packed size, so the units come
/// from the plan alone.
///
/// **Why 64 KiB, counted.** On 4 GiB of media-like input written by the
/// reference in blocks of about 16 KiB (x86-64, untimed), 64 KiB units
/// read 1.069x at `-mt16` and 1.090x at `-mt4` against one block a unit,
/// with the lanes' context switches a third of what they were. 128 KiB
/// read better at `-mt4` but worse at `-mt16`, and 256 KiB lost at
/// `-mt16` (0.883x): a unit is applied only once all its blocks are
/// decoded, so a coarse unit starves the apply stage. rarkit's own writer
/// cuts blocks near 64 KiB on the same input (median 65,445 bytes), so
/// most of its blocks are a unit alone and only its smaller ones pair; its
/// rows read level in the count (29 Sep 2026, the tape
/// unit measurement).
pub(crate) const TAPE_UNIT_BYTES: usize = 64 << 10;

/// The most BLOCKS one tape unit may hold, beside [`TAPE_UNIT_BYTES`].
///
/// **Why a count as well as bytes.** A lane holds up to three units' tapes
/// (the unit it decodes, the one queued and the one being applied), so the
/// tapes in flight grow with the blocks a unit holds, and a recycled tape
/// keeps the capacity of the largest block it ever held. A member of blocks
/// of about a kilobyte fits some seventy blocks in 64 KiB; on bin4g, whose
/// larger members are such, unbounded units raised peak RSS 133 MiB (19
/// percent) for no wall. Four blocks is what a reference writer's media
/// blocks of about 16 KiB give by bytes anyway, so the rows units exist for
/// lose nothing (29 Sep 2026, the tape unit measurement).
pub(crate) const TAPE_UNIT_BLOCKS: usize = 4;

/// COUNT ONLY (feature `tape-unit-knob`, never shipped): `RARKIT_TAPE_UNIT`
/// in bytes, 0 for one block per unit, read once; the shipped constant
/// otherwise.
#[cfg(feature = "tape-unit-knob")]
pub(crate) fn unit_bytes() -> usize {
    static BYTES: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *BYTES.get_or_init(|| {
        std::env::var("RARKIT_TAPE_UNIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(TAPE_UNIT_BYTES)
    })
}

/// The shipped unit size.
#[cfg(not(feature = "tape-unit-knob"))]
#[inline(always)]
pub(crate) fn unit_bytes() -> usize {
    TAPE_UNIT_BYTES
}

impl Plan {
    /// Cut the chain into tape units: runs of at most [`TAPE_UNIT_BLOCKS`]
    /// CONSECUTIVE blocks whose packed bytes sum to at most `budget`
    /// ([`TAPE_UNIT_BYTES`] unless a
    /// test or the count knob says otherwise; 0 gives one block a unit),
    /// every block in exactly one unit and a block over the bound a unit
    /// alone. A writer that puts a table set in every block of about 16 KiB
    /// (the reference, on media-like input) gets about four blocks a unit,
    /// so the lanes hand the apply stage one message where they handed
    /// four; a writer whose blocks fill the bound gets one block a unit,
    /// exactly as before (29 Sep 2026, the tape unit measurement).
    pub(crate) fn cut_units(&mut self, budget: usize) {
        self.units.clear();
        let mut start = 0usize;
        let mut span = 0usize;
        for (at, block) in self.blocks.iter().enumerate() {
            let size = block.past() - self.starts[at];
            if at > start && (span + size > budget || at - start == TAPE_UNIT_BLOCKS) {
                self.units.push((start, at));
                start = at;
                span = 0;
            }
            span += size;
        }
        if start < self.blocks.len() {
            self.units.push((start, self.blocks.len()));
        }
    }

    /// Cut the chain into units for a chunk that may open `lanes` lanes:
    /// at `budget` as [`Plan::cut_units`] cuts, unless that leaves FEWER
    /// units than the lanes the per-block form would open (`lanes` or the
    /// block count, whichever is fewer), and then one block a unit. A unit
    /// saves the hand-offs of blocks a lane would send one at a time; it
    /// must never cost the chunk a lane. The sequential look-ahead's walk
    /// decodes a member of a few blocks itself, on the path every byte of
    /// the output waits on, and cut into one unit such a member decoded on
    /// one thread where the per-block form gave it a lane a block
    /// (the bin4g measurement). A long chain, where the unit
    /// earns its keep, has units to spare and is cut exactly as before.
    pub(crate) fn cut_units_for_lanes(&mut self, budget: usize, lanes: usize) {
        self.cut_units(budget);
        if self.units.len() < lanes.min(self.blocks.len()) {
            self.cut_units(0);
        }
    }
}

/// Walk the chain, locating every block and threading the table groups
/// through. Decodes no symbol (section 7.3 item 4).
pub(crate) fn plan(packed: &[u8], carried_tables: bool, plan: &mut Plan) -> Result<()> {
    plan.clear();
    if carried_tables {
        plan.groups.push(LazyDecodeTables {
            first: None,
            cell: Mutex::new(None),
        });
    }
    let mut at = 0usize;
    while at < packed.len() {
        let block = match locate_at(packed, at) {
            Ok(block) => block,
            Err(err) => {
                plan.failure = Some(err);
                break;
            }
        };
        if block.carries_tables() {
            plan.groups.push(LazyDecodeTables {
                first: Some(plan.blocks.len()),
                cell: Mutex::new(None),
            });
        }
        if plan.groups.is_empty() {
            // A first block with the table bit clear and no tables carried
            // is `EmptyTable` on its first symbol (section 3.2). This can
            // only be the FIRST block, which is the decode point, so it is
            // not a deferred error.
            return Err(fault::empty_table());
        }
        plan.group_of.push(plan.groups.len() - 1);
        plan.starts.push(at);
        let last = block.ends_member();
        // `locate_at` has already moved the payload into member
        // coordinates, so the block's end IS the next block's start.
        at = block.past();
        plan.blocks.push(block);
        if last {
            plan.saw_last = true;
            break;
        }
    }
    Ok(())
}

fn locate_at(packed: &[u8], at: usize) -> Result<Located> {
    Ok(super::block::block_in_hand(&packed[at..])?.placed_at(at))
}

/// THE FOLD: whether a control operation carries the literal run before
/// it ([`TapeOp::after`]). The apply walks read either form, so this is
/// the producers' choice alone. With `h2-sequence-op-knob`,
/// `RARKIT_SEQ` without an `f` turns it off for a timed run in one binary
/// ([`seq_pieces`]).
#[inline(always)]
pub(crate) fn fold() -> bool {
    seq_on() & seq::FOLD != 0
}

/// The sequence op's pieces in force: [`seq::SHIPPED`], or with
/// `h2-sequence-op-knob` the knob's ([`seq_pieces`]).
#[inline(always)]
pub(crate) fn seq_on() -> u8 {
    #[cfg(feature = "h2-sequence-op-knob")]
    return seq_pieces();
    #[cfg(not(feature = "h2-sequence-op-knob"))]
    return seq::SHIPPED;
}

/// The sequence op's pieces, each a bit, so a timed run can price each as an
/// arm of its own inside one binary (`h2-sequence-op-knob`).
pub(crate) mod seq {
    /// The literal run folded into the control operation after it.
    pub(crate) const FOLD: u8 = 1;
    /// The four repeated distances and the last length held in the walk's
    /// locals across the tape ([`Regs`]), not stored to the match state an
    /// operation at a time.
    pub(crate) const REGS: u8 = 2;
    /// The copy's range tests answered on the lane ([`note_reach`]).
    pub(crate) const TRUST: u8 = 4;
    /// A fast match past a stride read whole before it is written
    /// (`Window::copy_match_in`'s `WIDE`).
    pub(crate) const WIDE: u8 = 8;
    /// The pieces the walks are compiled for; the fold is the producers'.
    pub(crate) const WALK: u8 = REGS | TRUST | WIDE;
    /// What ships: the fold and the repeats in registers, the two pieces
    /// that won the apply stage's cycles on a quiet Zen 4 (text64 0.930 of
    /// the control's apply floor, code32 0.984, incompressible 0.965; `TRUST` level
    /// or worse for 40M more lane instructions, `WIDE` 1.110 on code32).
    pub(crate) const SHIPPED: u8 = FOLD | REGS;
}

/// The pieces a knob build runs: `RARKIT_SEQ`, read ONCE a process, a
/// string of the pieces' letters (`f` the fold), said once on stderr so a
/// timed run can show the knob reached the binary; unset is
/// [`seq::SHIPPED`]. `r` the repeats in registers, `l` the range tests on
/// the lane, `c` the whole-source copy.
#[cfg(feature = "h2-sequence-op-knob")]
pub(crate) fn seq_pieces() -> u8 {
    static PIECES: std::sync::OnceLock<u8> = std::sync::OnceLock::new();
    *PIECES.get_or_init(|| {
        let Some(v) = std::env::var_os("RARKIT_SEQ") else {
            return seq::SHIPPED;
        };
        let v = v.to_string_lossy();
        let mut pieces = 0;
        for (letter, bit) in [
            ('f', seq::FOLD),
            ('r', seq::REGS),
            ('l', seq::TRUST),
            ('c', seq::WIDE),
        ] {
            if v.contains(letter) {
                pieces |= bit;
            }
        }
        eprintln!("rarkit sequence op pieces: {v:?} = {pieces:#x}");
        pieces
    })
}

/// Whether the tape's literal buffer keeps the promise
/// [`super::output::Window::literals_padded`] is written against: that
/// from the start of EVERY literal run there are at least `STRIDE_MAX`
/// readable bytes, whatever that run's length is.
///
/// **A missing pad would be a PANIC on a valid archive, not a wrong
/// byte.** `literals_padded` slices `source[..STRIDE_MAX]`, and Rust
/// bounds-checks that in release as well as in debug, so a future change
/// that dropped the pad or moved it would turn a legal member into the
/// thing section 4.3 says this package does not do. The debug assertion
/// inside `literals_padded` catches it in a test build; this catches it
/// on the real tapes of the real archives, which is where a pad that is
/// added in the wrong place would actually show.
///
/// Walks the ops exactly as `apply` does, by a running offset, because
/// the promise is about the OFFSET a run starts at and not about the
/// buffer's total length.
#[cfg(test)]
pub(crate) fn literal_pad_holds(tape: &BlockTape) -> bool {
    use super::output::STRIDE_MAX;

    let mut literals = 0usize;
    for op in &tape.steps {
        // Every operation's prefix, empty or not: the walks copy it
        // padded either way.
        if literals + STRIDE_MAX > tape.verbatim.len() {
            return false;
        }
        literals += op.prefix();
    }
    true
}

#[cfg(all(test, feature = "parallel"))]
mod unit_charge {
    use super::*;

    const MIB: u64 = 1 << 20;

    /// The tape unit is charged as admission charges the per-block form,
    /// so it shrinks with the lanes and a small stated limit, and gives
    /// way to the per-block form when a lane's share leaves nothing.
    #[test]
    fn the_unit_shrinks_to_what_the_working_limit_leaves_each_lane() {
        let default = 512 * MIB;
        // The full 64 KiB unit fits up to seventeen lanes at the default.
        assert!(unit_bytes_within_budget(default, 16) >= TAPE_UNIT_BYTES);
        assert!(unit_bytes_within_budget(default, 17) >= TAPE_UNIT_BYTES);
        // Wider, it shrinks: about 46 KiB at twenty lanes.
        let twenty = unit_bytes_within_budget(default, 20);
        assert!(twenty < TAPE_UNIT_BYTES && twenty > 40 << 10, "{twenty}");
        // At thirty-two lanes each lane's share is its per-block charge.
        assert_eq!(unit_bytes_within_budget(default, 32), 0);
        // A small stated limit leaves nothing: one block a unit.
        assert_eq!(unit_bytes_within_budget(64 * MIB, 4), 0);
        // No stated limit never binds.
        assert!(unit_bytes_within_budget(u64::MAX, 64) >= TAPE_UNIT_BYTES);
        // A unit of what is left fits the charge it was sized against.
        for lanes in [1usize, 4, 8, 16, 20, 24, 32] {
            let unit = unit_bytes_within_budget(default, lanes) as u64;
            let charge =
                TAPE_BYTES_PER_LANE + UNITS_IN_FLIGHT_PER_LANE * UNIT_CHARGE_PER_PACKED_BYTE * unit;
            assert!(
                charge * lanes as u64 <= default || unit == 0,
                "{lanes} lanes"
            );
        }
    }

    /// The default width opens at its ceiling, falls a lane a calm chunk
    /// until a fall bounces, then waits twice as long before the next
    /// fall, and grows a lane when the apply waited on more than one unit
    /// in eight of a chunk that ran its whole target.
    /// The rule is one line a system and nothing else: Apple silicon holds
    /// from 18 physical cores, x86-64 Linux takes its wide rule from 48,
    /// and a system with no line moves at any core count.
    #[test]
    fn the_default_width_moves_only_under_the_steady_core_count() {
        use WidthRule::{Gated, Holds, Moves};
        assert_eq!(STEADY_CORES, 18, "the ceiling moved: read the rule again");
        assert_eq!(STEADY_CORES_X86_LINUX, 48);
        // Apple silicon: a 10 core laptop moves; an 18 core laptop, a 20
        // core M1 Ultra and a 32 core M3 Ultra hold.
        let apple = Some((STEADY_CORES, Holds));
        for cores in [1, 10, 17] {
            assert_eq!(rule_on(cores, apple), Moves);
        }
        for cores in [18, 20, 32] {
            assert_eq!(rule_on(cores, apple), Holds);
        }
        // x86-64 Linux: an 8 core Zen 4, a 16 core EPYC and anything under
        // 48 keep the fall; the 48 core Xeon and the 96 core Zen 5 gate it.
        let x86 = Some((STEADY_CORES_X86_LINUX, WIDE_X86_LINUX_RULE));
        for cores in [8, 16, 32, 47] {
            assert_eq!(rule_on(cores, x86), Moves);
        }
        for cores in [48, 96, 256] {
            assert_eq!(rule_on(cores, x86), Gated);
        }
        // Every other system (Windows, Linux on aarch64, an Intel Mac).
        for cores in [1, 8, 16, 17, 18, 20, 48, 96, 256] {
            assert_eq!(rule_on(cores, None), Moves, "{cores} cores with no line");
        }
        let here = if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            Some((18, Holds))
        } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            Some((48, Gated))
        } else {
            None
        };
        assert_eq!(SYSTEM_LINE, here);
    }

    /// The gate: at its ceiling until eight chunks in a row are calm, then
    /// a lane a calm chunk; a lane back on a light wait, the ceiling at
    /// once on a heavy one, and below the ceiling a lane back on a wait
    /// lighter still.
    #[test]
    fn the_gated_width_falls_after_a_calm_run_and_jumps_back() {
        let most = 8;
        let mut w = Width::open_gated();
        // Seven calm chunks, then a chunk with a wait under one in eight:
        // still at the ceiling, and the run starts again.
        for _ in 0..7 {
            assert_eq!(w.lanes(most), 8);
            w.after_chunk(8, 0, 80, most);
        }
        w.after_chunk(8, 3, 80, most);
        for _ in 0..7 {
            assert_eq!(w.lanes(most), 8);
            w.after_chunk(8, 0, 80, most);
        }
        assert_eq!(w.lanes(most), 8);
        // The eighth calm chunk in a row earns the fall, and the run keeps
        // falling a lane a calm chunk to the floor.
        for want in [7, 6, 5, 4, 3, 2, 2] {
            let run = w.lanes(most);
            w.after_chunk(run, 0, 80, most);
            assert_eq!(w.lanes(most), want);
        }
        // A light wait (more than one in eight, not more than one in four)
        // takes one lane back.
        w.after_chunk(2, 15, 80, most);
        assert_eq!(w.lanes(most), 3);
        // A heavy wait (more than one unit in four) goes to the ceiling.
        w.after_chunk(3, 21, 80, most);
        assert_eq!(w.lanes(most), 8);
        // Below the ceiling a wait on more than one unit in 32 takes a
        // lane back, a lighter one holds, and neither is a bounce: after
        // eight calm chunks at the ceiling the width falls again.
        let mut w = Width::open_gated();
        for _ in 0..8 {
            w.after_chunk(8, 0, 80, most);
        }
        assert_eq!(w.lanes(most), 7);
        w.after_chunk(7, 2, 80, most);
        assert_eq!(w.lanes(most), 7, "two units in 80 hold");
        w.after_chunk(7, 3, 80, most);
        assert_eq!(w.lanes(most), 8, "three units in 80 take the lane back");
        for _ in 0..7 {
            w.after_chunk(8, 0, 80, most);
            assert_eq!(w.lanes(most), 8);
        }
        w.after_chunk(8, 0, 80, most);
        assert_eq!(w.lanes(most), 7);
        // A chunk held narrow by its own size says nothing of the target.
        w.after_chunk(3, 3, 80, most);
        assert_eq!(w.lanes(most), 7);
        // At the ceiling a light wait only starts the calm run again.
        let mut w = Width::open_gated();
        w.after_chunk(8, 3, 80, most);
        assert_eq!(w.lanes(most), 8);
        // With another member decoded beside it the lane back is off: the
        // width holds, as it did before the rule.
        let mut w = Width::open_gated();
        for _ in 0..8 {
            w.after_chunk_beside(8, 0, 80, most, 2);
        }
        assert_eq!(w.lanes(most), 7);
        w.after_chunk_beside(7, 3, 80, most, 2);
        assert_eq!(w.lanes(most), 7);
        w.after_chunk_beside(7, 3, 80, most, 1);
        assert_eq!(w.lanes(most), 8);
        // The moving width never takes a lane back on a light wait.
        let mut moving = Width::open();
        moving.after_chunk(8, 0, 80, most);
        moving.after_chunk(7, 3, 80, most);
        assert_eq!(moving.lanes(most), 7);
        // The moving width, for contrast, takes a lane a chunk.
        let mut moving = Width::open();
        for run in [8, 7, 6] {
            moving.after_chunk(run, 0, 80, most);
        }
        assert_eq!(moving.lanes(most), 5);
        moving.after_chunk(5, 40, 80, most);
        assert_eq!(moving.lanes(most), 6);
    }

    /// THE WIDTH RULE REACHES RAR 5 MEMBERS AND NOTHING ELSE: no other
    /// decoder (RAR 1.5, 2.0, RAR 3 and 4 with their filters, PPMd) names
    /// this module or the RAR 5 decoder that owns it (they share only its
    /// packed source and its sink), so none can open a tape lane or read
    /// [`default_rule`]. Pinned by reading their sources, because a decode of a
    /// RAR 4 member has no width to observe: the day one of them reaches
    /// for the tape, this fails and that format owes its own rows.
    #[test]
    fn no_decoder_but_rar5_names_the_tape() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        for module in ["rar1x", "lz20", "rar3_lz", "rar3_filters", "ppmd"] {
            let single = src.join(format!("{module}.rs"));
            if single.is_file() {
                files.push(single);
            }
            let entries = std::fs::read_dir(src.join(module)).expect("a decoder's directory");
            files.extend(entries.map(|entry| entry.expect("a directory entry").path()));
        }
        assert!(
            files.len() >= 20,
            "only {} decoder sources found",
            files.len()
        );
        for file in files {
            let text = std::fs::read_to_string(&file).expect("a decoder's source");
            assert!(
                !text.contains("tape::") && !text.contains("Rar5Lz"),
                "{} names the RAR 5 decoder or its tape",
                file.display()
            );
        }
    }

    #[test]
    fn the_default_width_falls_while_calm_and_backs_off_a_bounce() {
        let most = 7;
        let mut w = Width::open();
        assert_eq!(w.lanes(most), 7);
        // Calm chunks: a lane each, down to the floor, and no further.
        for want in [6, 5, 4, 3, 2, 2, 2] {
            let run = w.lanes(most);
            w.after_chunk(run, 0, 60, most);
            assert_eq!(w.lanes(most), want);
        }
        // Starved at the floor: a bounce grows a lane and doubles patience.
        w.after_chunk(2, 30, 60, most);
        assert_eq!(w.lanes(most), 3);
        w.after_chunk(3, 0, 60, most);
        assert_eq!(w.lanes(most), 3, "one calm chunk is no longer enough");
        w.after_chunk(3, 0, 60, most);
        assert_eq!(w.lanes(most), 2, "two are");
        w.after_chunk(2, 30, 60, most);
        assert_eq!(w.lanes(most), 3);
        for _ in 0..3 {
            w.after_chunk(3, 0, 60, most);
            assert_eq!(w.lanes(most), 3, "now four are needed");
        }
        // A few waits, under one in eight, hold the width and break the
        // calm run.
        w.after_chunk(3, 5, 60, most);
        assert_eq!(w.lanes(most), 3);
        // A chunk held narrow by its size or budget never grows the target,
        // and one with nothing counted changes nothing.
        w.after_chunk(1, 1, 1, most);
        assert_eq!(w.lanes(most), 3);
        w.after_chunk(3, 0, 0, most);
        assert_eq!(w.lanes(most), 3);
        // Never above the ceiling; a ceiling below the target binds.
        let mut w = Width::open();
        for _ in 0..20 {
            let run = w.lanes(most);
            w.after_chunk(run, 60, 60, most);
        }
        assert_eq!(w.lanes(most), 7);
        assert_eq!(w.lanes(4), 4);
        // A ceiling of one is one.
        let mut w = Width::open();
        w.after_chunk(1, 0, 60, 1);
        assert_eq!(w.lanes(1), 1);
    }
}
