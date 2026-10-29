//! The decode of one block to its tape: the symbol loop, the fast region
//! and its levers, the control decoders and the tape's room. The loop and
//! every helper it inlines are in this one module.

use super::*;

/// Decode one block into a tape, touching no window state.
pub(crate) fn decode_block_tape(
    tables: &Tables,
    packed: &[u8],
    block: &Located,
    from_bit: usize,
    tape: &mut BlockTape,
) {
    decode_block_tape_body(tables, packed, block, from_bit, tape);
    // THE PAD, and it is what lets the apply stage's literal arm write a
    // FIXED width without asking how many bytes the run has left.
    // `Window::literals_padded` reads `STRIDE_MAX` bytes from the run's
    // start whatever the run's length is, so the buffer owes it that much
    // room past its last literal. It is added here, once per block, rather
    // than reasoned about at the call site, because the call site is the
    // hot loop and this is the only place that can promise it.
    //
    // It changes nothing the apply stage READS: every operation names its
    // own length and the stage indexes by a running offset, so bytes past
    // the last run are unreachable through the tape's own operations.
    tape.verbatim
        .resize(tape.verbatim.len() + super::output::STRIDE_MAX, 0);
    // THE FAR LIST, on the decode lane, after the block and outside its
    // loop: an operation in the decode loop itself cost the decode-bound
    // rows 12 to 15 percent of their cycles on M3 (the declined far list,
    // 23 Sep 2026). A build with the measuring arms
    // writes it whatever the default, so the knob reaches the walk alone.
    if FAR_LIST || LIST_KNOB {
        build_far_list(tape);
    }
    note_reach(tape);
}

/// THE CAP-FREE ADMISSION: the most symbol bits a block may have left
/// for its tape to be decoded with no cap test at all.
///
/// **Why the caps cannot be reached.** The tape starts empty. Every
/// symbol the loop takes consumes at least one bit (a code is one to
/// fifteen bits long, `DecodeTable::build` gives no symbol a code of
/// length zero, and a lookup that would pass the block's end answers
/// `Truncated` and stops the loop), and the loop tests the caps only while
/// a bit is left. So at the test before symbol `k`, with `R` bits left
/// from the start bit, `k <= R - 1`. A literal symbol pushes one byte, so
/// the literal buffer holds at most `k` bytes. A control symbol pushes one
/// operation, and a flushed literal run pushes one operation per
/// [`TAPE_LENGTH_MASK`] literals or fewer, each charged to a literal
/// symbol of its own; so the operation list holds at most `k` operations.
/// Both are below their caps whenever `R` is at most the smaller cap, and
/// the test the checked loop makes before each symbol never parks: the
/// tape, the parked bit and the failure are the checked loop's, exactly.
///
/// A block with more bits left keeps the checked loop. The admission
/// counts the table bits of a first block too (`from_bit` is where its
/// symbols start), and the final flush after the loop is the same in both.
pub(crate) const CAP_FREE_BITS: usize = if TAPE_OPS_CAP < TAPE_LITS_CAP {
    TAPE_OPS_CAP
} else {
    TAPE_LITS_CAP
};

/// Whether the block's symbols from `from_bit` are within
/// [`CAP_FREE_BITS`]. Asked once per block, never per symbol.
#[inline(always)]
pub(crate) fn cap_free(block: &Located, from_bit: usize) -> bool {
    block.bits().saturating_sub(from_bit) <= CAP_FREE_BITS
}

/// The block's symbols, by the admitted loop or the checked one.
///
/// **Both loops are inlined HERE, and the reader is never handed to a
/// call**. Counted on an Apple M3 Mac (untimed, 27 Sep 2026),
/// each other form
/// cost more than the cap test it removed. With `seek` inside each copy
/// of the loop, `seek` and `decode_control` went out of line and the
/// reader lived in memory on every symbol: +6 to +11 percent user
/// instructions on every row. With the checked copy out of line and the
/// reader handed to it by value, which the ABI passes as an address, the
/// one reader both branches share still escaped: +1 to +5 percent. Both
/// inline, with the checked branch marked cold by [`cold_path`] so its
/// copy is laid out apart: -1.5 to -4.5 percent on every row.
///
/// The admitted loop opens with the FAST REGION ([`fast_region`]), on
/// every architecture: until 29 Sep 2026 the admission was aarch64's
/// alone (on x86-64 its two loops doubled `decode_one` for a
/// cap test, +0.4 to +2.2 percent user instructions, on a small x86-64 VPS), and
/// the x86-64 body was the control's checked loop verbatim. The region takes far
/// more than the cap test out of the admitted loop, so the admission is
/// re-counted on x86-64 with it (the decode symbol race
/// of 29 Sep 2026).
pub(super) fn decode_block_tape_body(
    tables: &Tables,
    packed: &[u8],
    block: &Located,
    from_bit: usize,
    tape: &mut BlockTape,
) {
    let Some(bits) = symbols_from(tables, packed, block, from_bit, tape) else {
        return;
    };
    if cap_free(block, from_bit) {
        decode_symbols::<false>(tables, bits, tape);
    } else {
        cold_path();
        decode_symbols::<true>(tables, bits, tape);
    }
}

/// Marks the branch that calls it cold, so the checked loop's copy is laid
/// out away from the admitted one. It takes nothing, so nothing escapes;
/// it is the only call either branch makes.
#[cold]
#[inline(never)]
pub(crate) fn cold_path() {}

/// The tape cleared and a reader at the block's first symbol bit, or
/// `None` with the tape already answered (an empty table).
///
/// **Before the choice of loop, and one call site, on purpose**, so
/// `seek` keeps the one caller it had and stays inlined: see
/// [`decode_block_tape_body`] for what a second one cost. For the same
/// reason `decode_control`, which each copy of the loop calls, is always
/// inlined.
#[inline(always)]
pub(super) fn symbols_from<'a>(
    tables: &Tables,
    packed: &'a [u8],
    block: &Located,
    from_bit: usize,
    tape: &mut BlockTape,
) -> Option<BitReader<'a>> {
    tape.clear();
    let mut bits = BitReader::new(block.payload(packed), block.bits());
    // On x86-64 the tape decode's own always-inlined copy, which takes
    // this call off the build's partition (see `BitReader::seek_tape`).
    // Elsewhere `seek` as it was: on aarch64 it is inlined here already,
    // and the forced copy cost 1.1 percent of instructions at the default
    // width (counted 6 Oct 2026). Chosen by `target_arch`, as every
    // per-system choice in this decoder is.
    #[cfg(target_arch = "x86_64")]
    bits.seek_tape(from_bit);
    #[cfg(not(target_arch = "x86_64"))]
    bits.seek(from_bit);
    // THE EMPTY TABLE, asked once. The loop's first lookup would answer
    // `EmptyTable` at its first symbol, with nothing pushed and no cap
    // reached (the tape was just cleared), and a block with no bits never
    // looks up at all; this is both, before the loop, so the loop's lookup
    // carries no test the compiler may or may not hoist (see
    // `DecodeTable::lookup_filled`).
    if tables.main.is_empty() {
        if !bits.at_end() {
            tape.failure = Some(fault::empty_table());
        }
        return None;
    }
    Some(bits)
}

/// [`decode_block_tape`] with the checked loop whatever the block's size:
/// the fallback every block took before the admission, for the tests that
/// prove the two agree.
#[cfg(test)]
pub(crate) fn decode_block_tape_checked(
    tables: &Tables,
    packed: &[u8],
    block: &Located,
    from_bit: usize,
    tape: &mut BlockTape,
) {
    if let Some(bits) = symbols_from(tables, packed, block, from_bit, tape) {
        decode_symbols::<true>(tables, bits, tape);
    }
    tape.verbatim
        .resize(tape.verbatim.len() + super::output::STRIDE_MAX, 0);
    if FAR_LIST || LIST_KNOB {
        build_far_list(tape);
    }
    note_reach(tape);
}

/// The symbol loop over a non-empty main table. `CAPPED` is whether it
/// tests the tape's caps before each symbol; only a block [`cap_free`]
/// admits may run it without, and only that block opens with the fast
/// region, whose tail this loop then finishes with the literal run the
/// region left open (so a run crossing the boundary is one operation, as
/// the checked loop makes it).
#[inline(always)]
pub(super) fn decode_symbols<const CAPPED: bool>(
    tables: &Tables,
    mut bits: BitReader<'_>,
    tape: &mut BlockTape,
) {
    let mut literal_run = 0usize;
    if !CAPPED && fast_region_knobbed(tables, &mut bits, tape, &mut literal_run) == Region::Stopped
    {
        return;
    }
    let fold = fold();
    while !bits.at_end() {
        let op_start = bits.position();
        if CAPPED && (tape.steps.len() >= TAPE_OPS_CAP || tape.verbatim.len() >= TAPE_LITS_CAP) {
            flush_literals(tape, &mut literal_run);
            tape.parked_at = Some(op_start);
            return;
        }
        let entry = match tables.main.lookup_filled(&mut bits) {
            Ok(entry) => entry,
            Err(err) => {
                flush_literals(tape, &mut literal_run);
                tape.failure = Some(err);
                return;
            }
        };
        if lut_entry_is_literal(entry) {
            tape.verbatim.push(lut_symbol(entry) as u8);
            literal_run += 1;
            continue;
        }
        let symbol = lut_symbol(entry);
        let decoded = decode_control(tables, &mut bits, symbol, tape);
        match decoded {
            Ok(Some(op)) => {
                push_after(&mut tape.steps, fold, literal_run, op);
                literal_run = 0;
            }
            Ok(None) => {
                // A distance the op's `u32` cannot hold: park here and let
                // the serial path finish the block, which cannot disagree
                // because it starts from this very bit.
                flush_literals(tape, &mut literal_run);
                tape.parked_at = Some(op_start);
                return;
            }
            Err(err) => {
                flush_literals(tape, &mut literal_run);
                tape.failure = Some(err);
                return;
            }
        }
    }
    flush_literals(tape, &mut literal_run);
}

/// THE REGION BY THE BLOCK'S SHAPE, asked once a block:
/// the fresh-match levers'
/// region ([`fast_region`]) for a block whose main table gives its control
/// symbols at least [`LEVER_MASS_FLOOR`] of the code space, and the control's
/// region (`main_region`) for the rest. The levers make a MATCH cheaper and
/// leave a literal as it was, but their region's loop carries more state,
/// and on a block of few matches the control's loop is the faster: inside one
/// binary on x86-64 the levers read text64 1.085, code32 1.060, incompr64
/// 1.018 and bin4g 1.018 but the S8 set 0.988 (about 77 literals a
/// match; the fresh match's cost measurement). With the
/// `h2-fresh-match-knob` feature, `RARKIT_FRESH_MATCH=0` takes the control's
/// region for every block.
#[inline(always)]
pub(super) fn fast_region_knobbed(
    tables: &Tables,
    bits: &mut BitReader<'_>,
    tape: &mut BlockTape,
    literal_run: &mut usize,
) -> Region {
    #[cfg(feature = "h2-fresh-match-knob")]
    if main_region::use_main() {
        return main_region::fast_region_main(tables, bits, tape, literal_run);
    }
    if tables.main.control_mass() < LEVER_MASS_FLOOR {
        return main_region::fast_region_main(tables, bits, tape, literal_run);
    }
    fast_region(tables, bits, tape, literal_run)
}

/// The control mass ([`super::tables::DecodeTable::control_mass`], units of
/// `2^-15`) from which a block takes the levers' region: one twentieth of
/// the code space. By their shares of control symbols the rows sit far to
/// either side of it: text64 about 0.87, code32 0.55, bin4g 0.22,
/// incompressible data 0.13 (all faster with the levers), the S8 set
/// about 0.013 (slower); a Huffman code's mass tracks its symbols' shares.
pub(super) const LEVER_MASS_FLOOR: u32 = (1 << 15) / 20;

/// Where [`fast_region`] (or the literal batch's `batch::batched_region`)
/// stopped.
#[derive(PartialEq, Eq)]
pub(in crate::rar5_lz) enum Region {
    /// The reader stands at the block's tail, the tape as far as the
    /// region took it and the literal run still open: the checked loop
    /// finishes the block.
    Tail,
    /// The tape is answered (a failure or a park); nothing more to do.
    Stopped,
}

/// THE FAST REGION of an admitted block: the symbol loop with every
/// per-symbol test that the block's OWN shape makes redundant left out.
///
/// **What goes, and why each is exact.** `bits.rs`'s "THE FAST REGION"
/// note proves that while the refill's next byte is `FAST_MARGIN` bytes
/// short of the payload, no symbol can pass the block's end and no refill
/// can pass the slice: so no `remaining` per read, no position per
/// symbol, no bounds branch per refill, and `Truncated` cannot be the
/// answer to anything read here. The caps cannot be reached in an
/// admitted block ([`cap_free`]). And a literal consumes at least the main
/// table's shortest literal code, so the literals a block can still push
/// are bounded by its bits left over that length: the literal buffer is
/// grown ONCE to that bound, and a literal is one store and a count, not a
/// `Vec::push` with its length, capacity and pointer read back from the
/// tape on every symbol. What is left per literal is the lookup, the
/// advance, the literal test and the store.
///
/// **What does not change.** The entries read, the bits consumed, the
/// operations and literals pushed and the order they are pushed in are
/// the checked loop's exactly, so the tape is the same tape: the tests
/// that decode every block by both loops (`the_batch_agrees`) say so. The
/// literal run stays open across the boundary into the checked loop for
/// that reason. The buffer is truncated back to the literals pushed
/// before the region hands over, so nothing after it sees the bound.
///
/// **The bound is an invariant, not a test.** `get_mut` on the buffer is
/// the one bounds check per literal; by the bound it cannot fail, and if
/// it ever did the literal is pushed the slow way from there on, so the
/// tape is still right. A main table with no literal at all has no bound
/// and takes the checked loop whole.
#[inline(always)]
pub(super) fn fast_region(
    tables: &Tables,
    bits: &mut BitReader<'_>,
    tape: &mut BlockTape,
    literal_run: &mut usize,
) -> Region {
    let shortest = tables.main.shortest_literal() as usize;
    let fast_end = bits.fast_end();
    if shortest == 0 || bits.next_byte() >= fast_end {
        return Region::Tail;
    }
    // THE TAPE'S FIELDS APART, so the literal buffer's pointer and length
    // are locals of the loop and not re-read from the tape at every
    // literal; the operation list is pushed to as before.
    let BlockTape {
        steps: ops,
        verbatim: literals,
        records,
        parked_at,
        failure,
        ..
    } = tape;
    let base = literals.len();
    let room = bits.remaining() / shortest + 1;
    literals.resize(base + room, 0);
    // THE BUFFER AS A SLICE CURSOR: a fat pointer held in registers for
    // the loop, where a `&mut Vec` is memory the compiler re-read at every
    // literal (counted 29 Sep 2026: two loads a literal); and a literal
    // takes its head, so the loop carries the cursor's pointer and length
    // and nothing else per literal. Where it stands is `end - lits.len()`,
    // asked only at a control symbol.
    let end = base + room;
    let mut lits: &mut [u8] = &mut literals[base..end];
    let mut run_start = base - *literal_run;
    // THE OPERATION LIST AS A SLICE CURSOR too ([`open_ops`]): a control
    // symbol writes its operation, and the literal run before it, through
    // `out` and not through `Vec::push`.
    let (ops_start, mut ops_end) = open_ops(ops, bits.remaining());
    let mut out: &mut [TapeOp] = &mut ops[ops_start..ops_end];
    let side = SideLookups::of(tables);
    let fold = fold();
    let region = loop {
        if bits.next_byte() >= fast_end {
            break Region::Tail;
        }
        let entry = match tables.main.lookup_filled_in_region(bits) {
            Ok(entry) => entry,
            Err(err) => {
                let at = end - lits.len();
                literals.truncate(at);
                let written = ops_end - out.len();
                ops.truncate(written);
                flush_run(ops, at - run_start);
                *literal_run = 0;
                *failure = Some(err);
                return Region::Stopped;
            }
        };
        if lut_entry_is_literal(entry) {
            let byte = lut_symbol(entry) as u8;
            match std::mem::take(&mut lits).split_first_mut() {
                Some((slot, rest)) => {
                    *slot = byte;
                    lits = rest;
                }
                None => {
                    // Unreachable by the bound. Right if reached: the
                    // region ends here with the literal pushed the slow
                    // way, and the checked loop takes the rest.
                    debug_assert!(false, "a literal past the region's bound");
                    let written = ops_end - out.len();
                    ops.truncate(written);
                    literals.push(byte);
                    *literal_run = end + 1 - run_start;
                    bits.leave_fast_region();
                    return Region::Tail;
                }
            }
            continue;
        }
        let at = end - lits.len();
        let op = match control_in_region(tables, side, bits, entry, records) {
            Ok(op) => op,
            Err(stop) => {
                literals.truncate(at);
                let written = ops_end - out.len();
                ops.truncate(written);
                flush_run(ops, at - run_start);
                *literal_run = 0;
                match stop {
                    Stop::Park(bit) => *parked_at = Some(bit),
                    Stop::Fail(err) => *failure = Some(err),
                }
                return Region::Stopped;
            }
        };
        let mut run = at - run_start;
        let mut cursor = std::mem::take(&mut out);
        // ONE cold call site, as the room's growth always had: a run too
        // long for a prefix is the same call.
        if cursor.len() < 2 || run > PREFIX_MAX {
            let written = ops_end - cursor.len();
            (cursor, run) = make_room(ops, written, &mut ops_end, run);
        }
        out = put_op(cursor, fold, run, op);
        run_start = at;
    };
    let written = ops_end - out.len();
    ops.truncate(written);
    let at = end - lits.len();
    literals.truncate(at);
    *literal_run = at - run_start;
    bits.leave_fast_region();
    region
}

/// [`flush_literals`] on the operation list alone: a run of `run`
/// literals as one `LITS` operation, or several at [`PREFIX_MAX`].
#[inline(always)]
pub(in crate::rar5_lz) fn flush_run(ops: &mut Vec<TapeOp>, run: usize) {
    let mut left = run;
    while left > 0 {
        let take = left.min(PREFIX_MAX);
        ops.push(TapeOp::lits(take));
        left -= take;
    }
}

/// A control operation and the literal run before it, onto the list: ONE
/// operation carrying the run as its prefix ([`TapeOp::after`]) where the
/// fold is on ([`fold`]), a run too long for a prefix leaving its head in
/// `LITS` operations before it; with the fold off, the run's own `LITS`
/// operations and then the operation. Every loop that pushes to the list writes its
/// control operations through this, with `fold` read once a block.
#[inline(always)]
pub(in crate::rar5_lz) fn push_after(
    ops: &mut Vec<TapeOp>,
    fold: bool,
    mut run: usize,
    op: TapeOp,
) {
    if fold {
        // A run too long for a prefix leaves its head in `LITS` operations
        // of [`PREFIX_MAX`] each, as the fast region's [`make_room`] does,
        // so every loop writes the same tape.
        while run > PREFIX_MAX {
            ops.push(TapeOp::lits(PREFIX_MAX));
            run -= PREFIX_MAX;
        }
        ops.push(op.after(run));
    } else {
        flush_run(ops, run);
        ops.push(op);
    }
}

/// The fast region's cold call: the operations written so far kept, the
/// literal run's head pushed as `LITS` operations of [`PREFIX_MAX`] each
/// until what is left fits a prefix, and the cursor reopened over a fresh
/// chunk of room ([`OP_CHUNK`]). Answers the cursor and the run left for
/// the operation's prefix. Out of line: a region reaches it once a chunk
/// of operations, or at a run of more than eight thousand literals.
#[cold]
#[inline(never)]
pub(in crate::rar5_lz) fn make_room<'v>(
    ops: &'v mut Vec<TapeOp>,
    written: usize,
    end: &mut usize,
    mut run: usize,
) -> (&'v mut [TapeOp], usize) {
    ops.truncate(written);
    while run > PREFIX_MAX {
        ops.push(TapeOp::lits(PREFIX_MAX));
        run -= PREFIX_MAX;
    }
    let from = ops.len();
    *end = from + OP_CHUNK;
    ops.resize(*end, TapeOp::EMPTY);
    (&mut ops[from..], run)
}

/// THE OPERATION CURSOR'S ROOM COMES IN CHUNKS of this many operations
/// (32 KiB): the first room is a chunk, or one operation for every eight
/// symbol bits the block has left where that is less, and a region that
/// fills it grows it by a chunk more ([`make_room`]). The room has to be
/// ZEROED before a safe slice can hold it, and zeroing is a write pass the
/// `Vec::push` it replaces never made, so the room tracks the operations
/// actually written: at most a chunk of zeroes past them a block, written
/// just before the region writes over them. A first form sized the room
/// at one operation per 16 bits up front, about 2.3 times incompressible
/// data's operations (one in 36 bits), and cost `incompressible_64m` 2
/// percent of wall on the M5 (230 MB of zeroes against 101 MB of
/// operations) and the pooled tapes up to 18 MiB of peak RSS.
pub(super) const OP_CHUNK: usize = 4096;

/// The first room [`open_ops`] gives a block with `bits_left` symbol
/// bits: at least the two operations one control symbol writes.
#[inline(always)]
pub(super) fn op_room(bits_left: usize) -> usize {
    (bits_left / 8 + 2).min(OP_CHUNK)
}

/// OPEN THE OPERATION CURSOR of a region: grow the list by its first room,
/// zeroed (a safe slice has to hold something), and answer where the room
/// starts and ends. The region writes through a slice of it and, at every
/// way out, cuts the list back to what it wrote, so nothing after the
/// region sees the room.
#[inline(always)]
pub(in crate::rar5_lz) fn open_ops(ops: &mut Vec<TapeOp>, bits_left: usize) -> (usize, usize) {
    let start = ops.len();
    let end = start + op_room(bits_left);
    ops.resize(end, TapeOp::EMPTY);
    (start, end)
}

/// ONE CONTROL SYMBOL'S OPERATIONS, through the region's cursor, a run of
/// at most [`PREFIX_MAX`] (the caller sends a longer one to [`make_room`]).
/// With the fold ([`fold`]) the run is the operation's prefix and the
/// cursor moves on by one. Without it, BRANCH FREE: both slots are
/// written, the first with the run's `LITS` or with the operation itself
/// when the run is empty (which is six control symbols in seven on the
/// text rows), and the cursor moves on by one or two. The cursor has room
/// for two by the caller's test.
#[inline(always)]
pub(in crate::rar5_lz) fn put_op(
    cursor: &mut [TapeOp],
    fold: bool,
    run: usize,
    op: TapeOp,
) -> &mut [TapeOp] {
    debug_assert!(run <= PREFIX_MAX);
    if fold {
        cursor[0] = op.after(run);
        return &mut cursor[1..];
    }
    let lits = usize::from(run != 0);
    let (pair, _) = cursor.split_at_mut(2);
    pair[0] = if lits != 0 { TapeOp::lits(run) } else { op };
    pair[1] = op;
    &mut cursor[1 + lits..]
}

/// THE SIDE TABLES' LOOKUPS a region reads (lever 4 of the fresh match):
/// each table's own, or the shared all-miss one for a table with no
/// symbols ([`super::tables::DecodeTable::region_lookup`]), chosen ONCE a
/// block, so a lookup of the distance, alignment or length table carries
/// no `empty` test and an empty table still answers `EmptyTable` at the
/// symbol that reads it.
#[derive(Clone, Copy)]
pub(in crate::rar5_lz) struct SideLookups<'t> {
    pub(in crate::rar5_lz) distance: &'t [u32; LUT_ENTRIES],
    pub(in crate::rar5_lz) align: &'t [u32; LUT_ENTRIES],
    pub(in crate::rar5_lz) length: &'t [u32; LUT_ENTRIES],
}

impl<'t> SideLookups<'t> {
    #[inline(always)]
    pub(in crate::rar5_lz) fn of(tables: &'t Tables) -> SideLookups<'t> {
        SideLookups {
            distance: tables.distance.region_lookup(),
            align: tables.align.region_lookup(),
            length: tables.length.region_lookup(),
        }
    }
}

/// The length slot refusal as a region reader's whole answer, out of line.
#[cfg_attr(target_arch = "aarch64", cold, inline(never))]
#[cfg_attr(not(target_arch = "aarch64"), inline(always))]
fn length_slot_stop() -> std::result::Result<TapeOp, Stop> {
    Err(Stop::Fail(super::ladders::no_such_length_slot()))
}

/// Why a control symbol inside the fast region ended the region.
pub(in crate::rar5_lz) enum Stop {
    /// A distance the op's `u32` cannot hold: park at this bit, the
    /// symbol's first, and let the serial path finish the block.
    Park(usize),
    /// The block's error.
    Fail(Error),
}

/// [`decode_control`] inside the fast region: the same fields in the same
/// order, read by the region's rules, answering the operation itself. The
/// FRESH MATCH is asked first and read by [`fresh_match_in_region`]; the
/// rest are [`decode_control`]'s arms. The record reader keeps its checked
/// reads on a side copy of the reader, as `decode_control` has it, topped
/// up first so either architecture's read surface finds its bits.
#[inline(always)]
pub(in crate::rar5_lz) fn control_in_region(
    tables: &Tables,
    side: SideLookups<'_>,
    bits: &mut BitReader<'_>,
    entry: u32,
    records: &mut Vec<RawRecord>,
) -> std::result::Result<TapeOp, Stop> {
    let symbol = lut_symbol(entry);
    if symbol >= SYMBOL_MATCH_BASE {
        return fresh_match_in_region(tables, side, bits, entry);
    }
    match symbol {
        SYMBOL_FILTER => {
            bits.ensure_in_region(56);
            let mut spill = *bits;
            let record = filters::read_record(&mut spill);
            *bits = spill;
            records.push(record.map_err(Stop::Fail)?);
            Ok(TapeOp::new(tape_kind::FILTER, 0, 0))
        }
        SYMBOL_REPEAT_LAST => Ok(TapeOp::new(tape_kind::REP_LAST, 0, 0)),
        _ => {
            // The length code (15 bits) and its extra bits (at most 9) on
            // one refill test, as the fresh match reads its head.
            bits.ensure_in_region(24);
            let entry = tables
                .length
                .lookup_raw_in_region(side.length, bits)
                .map_err(Stop::Fail)?;
            let slot = lut_symbol(entry);
            let Some(extra_bits) = super::ladders::bits_after_slot(slot) else {
                return length_slot_stop();
            };
            let extra = bits.take_raw_in_region(u32::from(extra_bits));
            bits.keep_watermark_in_region();
            let length = (super::ladders::LENGTH_SLOT_BASE[slot] + extra) as usize;
            let index = (symbol - SYMBOL_REPEAT_BASE) as u32;
            Ok(TapeOp::new(tape_kind::REP, length, index))
        }
    }
}

/// A FRESH MATCH inside the fast region, `entry` its main code's: the
/// length slot's extra bits, the distance ([`distance_in_region`]'s reads)
/// and the bonus, into a `MATCH` operation.
///
/// **The park is decided on the SLOT.** A distance past the op's `u32`
/// needs a slot of 30 extra bits or more (slot 62 and up), so every other
/// slot is read with no test of the distance at all; those few slots take
/// [`far_slot_in_region`], which parks at the symbol's first bit when the
/// distance does not fit. (Until 30 Sep 2026 the region parked at the bit
/// after the whole match less the main code's length, which is not the
/// symbol's first bit; `a_distance_past_u32_parks_at_the_match_in_every_loop`
/// holds it to the checked loop's.)
#[inline(always)]
pub(super) fn fresh_match_in_region(
    tables: &Tables,
    side: SideLookups<'_>,
    bits: &mut BitReader<'_>,
    entry: u32,
) -> std::result::Result<TapeOp, Stop> {
    let slot = lut_symbol(entry) - SYMBOL_MATCH_BASE;
    let Some(extra_bits) = super::ladders::bits_after_slot(slot) else {
        return length_slot_stop();
    };
    // ONE TOP UP FOR THE HEAD OF THE MATCH. A refill leaves at least 56
    // bits buffered. The length's extra bits (at most 9) and the distance
    // code (at most 15) spend 24 of them, which leaves 32: a distance of
    // up to [`ONE_FILL_BITS`] extra bits, 15 of them the alignment code's
    // reach, is read with no test between its fields.
    bits.ensure_in_region(56);
    let laddered = (super::ladders::LENGTH_SLOT_BASE[slot]
        + bits.take_raw_in_region(u32::from(extra_bits))) as usize;
    let distance_entry = tables
        .distance
        .lookup_raw_in_region(side.distance, bits)
        .map_err(Stop::Fail)?;
    if distance_entry & crate::carry::c_lz::codec::rar50::HUFF_LUT_DISTANCE_INVALID_BIT != 0 {
        // A slot of 66 to 79, whose count of extra bits the table's entry
        // has no room for. It is not refused (section 3.5): the block
        // parks at the match's first bit, which is the reader's position
        // less the main code, the length's extra bits and the distance
        // code, and the serial reader, which reads such a slot, takes the
        // block up from there.
        let taken =
            (entry & 0xff) as usize + usize::from(extra_bits) + (distance_entry & 0xff) as usize;
        return Err(Stop::Park(bits.position() - taken));
    }
    let count = (distance_entry >> crate::carry::c_lz::codec::rar50::HUFF_LUT_DISTANCE_BITS_SHIFT)
        & crate::carry::c_lz::codec::rar50::HUFF_LUT_DISTANCE_BITS_MASK;
    if count >= u32::from(FAR_SLOT_BITS) {
        return far_slot_in_region(tables, bits, entry, slot, laddered, distance_entry);
    }
    if count > ONE_FILL_BITS {
        // Up to 25 plain bits and the alignment code's 15.
        bits.ensure_in_region(40);
    }
    // Section 3.5: under four extra bits they are all read plain. With four
    // or more, the plain bits come first, four fewer than the count, and
    // the value's low four are one symbol of the alignment code after them.
    let extra = if count < 4 {
        bits.take_raw_in_region(count)
    } else {
        let above = bits.take_raw_in_region(count - 4);
        let low = tables
            .align
            .lookup_raw_in_region(side.align, bits)
            .map_err(Stop::Fail)?;
        super::ladders::extra_bits_value(above, lut_symbol(low))
    };
    bits.keep_watermark_in_region();
    // Under `FAR_SLOT_BITS` the slot's first distance less one and its
    // extra bits sum inside a `u32`, and so does the one more.
    let distance = super::ladders::DISTANCE_SLOT_BASE[lut_symbol(distance_entry)] + extra + 1;
    let length = fresh_match_length(laddered, distance as usize);
    Ok(TapeOp::new(tape_kind::MATCH, length, distance))
}

/// The most extra bits a distance slot may have for the one top up at the
/// head of [`fresh_match_in_region`] to hold its whole distance: 32 bits
/// are left after the length's extra bits and the distance code, the
/// alignment code may look at 15 of them, and the plain part is the count
/// less four.
const ONE_FILL_BITS: u32 = 32 - 15 + 4;

/// The fewest extra bits a distance slot has for its distance to reach
/// past `u32::MAX`: slot 62 has 30, and its largest distance is
/// `(2 << 30) + (1 << 30) = 3 << 30`, still inside; slot 63's reaches
/// `1 << 32`. Every slot under this is inside by the ladder (SPEC-H2 3.5).
pub(super) const FAR_SLOT_BITS: u8 = 30;

/// [`fresh_match_in_region`]'s slots of [`FAR_SLOT_BITS`] or more, where
/// the distance may not fit the op. Parks at the symbol's first bit: the
/// reader's position now less the bits the symbol has taken, its main
/// code, its length's extra bits and its distance code, every one of which
/// is known here.
#[inline(always)]
pub(super) fn far_slot_in_region(
    tables: &Tables,
    bits: &mut BitReader<'_>,
    entry: u32,
    slot: usize,
    length: usize,
    distance_entry: u32,
) -> std::result::Result<TapeOp, Stop> {
    let taken = (entry & 0xff) as usize
        + usize::from(super::ladders::LENGTH_SLOT_EXTRA_BITS[slot])
        + (distance_entry & 0xff) as usize;
    let first_bit = bits.position() - taken;
    let slot_bits = ((distance_entry
        >> crate::carry::c_lz::codec::rar50::HUFF_LUT_DISTANCE_BITS_SHIFT)
        & crate::carry::c_lz::codec::rar50::HUFF_LUT_DISTANCE_BITS_MASK) as u8;
    let distance =
        distance_extra_in_region(tables, bits, distance_entry, slot_bits).map_err(Stop::Fail)?;
    let length = fresh_match_length(length, distance);
    match u32::try_from(distance) {
        Ok(distance) => Ok(TapeOp::new(tape_kind::MATCH, length, distance)),
        Err(_) => Err(Stop::Park(first_bit)),
    }
}

/// `read_distance` inside the fast region (SPEC-H2 3.5), past the
/// distance table's entry, which the caller has read and found valid: its
/// extra bits (the high part topped up to hold 27 plus the alignment
/// code's 15), the alignment symbol where the slot has four or more.
#[inline(always)]
pub(super) fn distance_extra_in_region(
    tables: &Tables,
    bits: &mut BitReader<'_>,
    entry: u32,
    slot_bits: u8,
) -> Result<usize> {
    let count = u32::from(slot_bits);
    // Whatever the caller's reads left buffered: the plain part (at most
    // 27 bits) and the alignment code's 15 on one test.
    bits.ensure_in_region(42);
    // Section 3.5, as the near slots read it: the plain bits, then the
    // alignment symbol as the low four where the count is four or more.
    // An alignment list with no code answers `EmptyTable` from its walk.
    let extra = if count < 4 {
        bits.take_raw_in_region(count)
    } else {
        let above = bits.take_raw_in_region(count - 4);
        let low = tables
            .align
            .lookup_raw_in_region(tables.align.region_lookup(), bits)?;
        super::ladders::extra_bits_value(above, lut_symbol(low))
    };
    bits.keep_watermark_in_region();
    // The whole distance, which a `u32` may not hold: the caller asks.
    Ok(super::ladders::distance_named(lut_symbol(entry), extra))
}

#[inline(always)]
pub(super) fn flush_literals(tape: &mut BlockTape, run: &mut usize) {
    // A literal run is one op however long it is, so the apply stage
    // copies it in a burst rather than a byte at a time.
    flush_run(&mut tape.steps, *run);
    *run = 0;
}

/// One control symbol, into an op. `Ok(None)` asks the caller to park.
/// Always inlined: each copy of the symbol loop is a caller, and out of
/// line it takes the reader's address (see `symbols_from`).
#[inline(always)]
pub(super) fn decode_control(
    tables: &Tables,
    bits: &mut BitReader<'_>,
    symbol: usize,
    tape: &mut BlockTape,
) -> Result<Option<TapeOp>> {
    match symbol {
        SYMBOL_FILTER => {
            // A COPY of the reader goes out of line and comes back. The
            // record reader is the one callee of this loop that takes the
            // reader's address, and a reader whose address escapes lives in
            // memory for the whole loop: a load and a store of its fields
            // on every symbol (the serial decoder's `READER_LOCAL` reason,
            // `bits.rs`). Filters are a few per block; symbols are
            // millions.
            let mut spill = *bits;
            let record = filters::read_record(&mut spill);
            *bits = spill;
            let record = record?;
            tape.records.push(record);
            Ok(Some(TapeOp::new(tape_kind::FILTER, 0, 0)))
        }
        SYMBOL_REPEAT_LAST => Ok(Some(TapeOp::new(tape_kind::REP_LAST, 0, 0))),
        258..=261 => {
            let length = read_length(tables, bits)?;
            let index = (symbol - SYMBOL_REPEAT_BASE) as u32;
            Ok(Some(TapeOp::new(tape_kind::REP, length, index)))
        }
        _ => {
            let slot = symbol - SYMBOL_MATCH_BASE;
            let length = read_length_slot(bits, slot)?;
            let distance = read_distance(tables, bits)?;
            let length = fresh_match_length(length, distance);
            match u32::try_from(distance) {
                Ok(distance) => Ok(Some(TapeOp::new(tape_kind::MATCH, length, distance))),
                Err(_) => Ok(None),
            }
        }
    }
}
