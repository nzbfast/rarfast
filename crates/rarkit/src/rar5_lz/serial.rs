//! The serial decode of one block: the symbol loop on the calling
//! thread, the repeats it carries, and the length and distance reads the
//! tape's decode shares.

use super::*;

/// Decode every symbol of one block and apply it to the window.
///
/// Stops at the block's bit count even when whole bytes remain (3.2), and
/// at the member's declared unpacked size (3.1).
///
/// **THE LOOP'S OWN STATE IS HELD IN LOCALS, NOT BEHIND THE CALLER'S
/// POINTERS.** The reader and the four repeated distances arrive as `&mut`
/// and leave the same way, and the loop between runs on copies. Before 22
/// Sep 2026 it ran on the pointers themselves, and because a cold call in
/// the loop (the long table walk, the filter record) received the reader's
/// address, the compiler kept the reader IN MEMORY for the whole loop:
/// every symbol loaded the bit buffer and its count, shifted, and stored
/// both back, so the NEXT symbol's table index waited on a store to load
/// round trip. That round trip is on the critical chain of every symbol,
/// on aarch64 and x86-64 alike, and the disassembly of both showed it.
/// The same held for the repeated distances, which a fresh match shifted
/// with a 16 byte load across two earlier stores. What makes the copies
/// stay in registers is that nothing takes their address: the long walk
/// answers an entry instead of consuming bits, the filter record reads a
/// side copy, and the repeats are four scalars rather than an array a
/// variable index would pin to the stack (profiled and priced
/// 22 Sep 2026, the serial symbol loop).
pub(super) fn decode_block<S: LzSink>(
    tables: &Tables,
    state: &mut MatchState,
    window: &mut Window,
    filters: &mut Filters,
    bits: &mut BitReader<'_>,
    unpacked: u64,
    sink: &mut S,
) -> Result<()> {
    #[cfg(feature = "h2-serial-arms")]
    match serial_arms::arm() {
        serial_arms::POINTERS => {
            return decode_block_body::<_, _, false>(
                tables, state, window, filters, bits, unpacked, sink,
            );
        }
        serial_arms::READER_LOCAL => {
            let mut reader = *bits;
            let result = decode_block_body::<_, _, false>(
                tables,
                state,
                window,
                filters,
                &mut reader,
                unpacked,
                sink,
            );
            *bits = reader;
            return result;
        }
        _ => {}
    }
    let mut reader = *bits;
    let mut repeats = LoopRepeats::load(state);
    let result = decode_block_body::<_, _, ONE_PASS>(
        tables,
        &mut repeats,
        window,
        filters,
        &mut reader,
        unpacked,
        sink,
    );
    *bits = reader;
    repeats.store(state);
    result
}

/// The serial loop's A/B dial, for pricing the state-in-locals lever in
/// ONE binary with its layout held still. Behind its own feature so no
/// benchmark binary and no shipped build compiles more than the shipped loop.
/// All three arms are BYTE EXACT: they differ only in where the loop's
/// state lives while it runs.
#[cfg(feature = "h2-serial-arms")]
pub(crate) mod serial_arms {
    /// The loop on the caller's pointers, as it was before 22 Sep 2026.
    pub(crate) const POINTERS: u8 = 0;
    /// The reader in a local, the repeats behind the pointer.
    pub(crate) const READER_LOCAL: u8 = 1;
    /// The reader and the repeats in locals: what ships.
    pub(crate) const SHIPPED: u8 = 2;

    /// `RARKIT_H2_SERIAL_ARM`, read once per process, and ANNOUNCED once
    /// on stderr so a paired harness can refuse an arm that silently ran
    /// under another arm's label. Unset reads as [`SHIPPED`] and prints
    /// nothing.
    pub(crate) fn arm() -> u8 {
        static ARM: std::sync::OnceLock<u8> = std::sync::OnceLock::new();
        *ARM.get_or_init(|| {
            let arm = std::env::var("RARKIT_H2_SERIAL_ARM")
                .ok()
                .and_then(|v| v.parse::<u8>().ok())
                .unwrap_or(SHIPPED);
            if arm != SHIPPED {
                eprintln!("h2 serial arm {arm} live");
            }
            arm
        })
    }
}

/// What the serial loop asks of the repeated distances (section 3.5), so
/// the one loop body runs on [`MatchState`] or on [`LoopRepeats`].
pub(super) trait RepeatState {
    fn last_length(&self) -> usize;
    fn nearest(&self) -> usize;
    fn fresh(&mut self, distance: usize, length: usize);
    fn rotate(&mut self, k: usize, length: usize) -> Result<usize>;
    /// Repeated distance `k`, zero while uninitialised, changing nothing:
    /// the one-pass region asks before it applies anything.
    #[cfg(feature = "parallel")]
    fn repeat(&self, k: usize) -> usize;
    /// [`RepeatState::rotate`] for a `k` whose distance is known non-zero.
    #[cfg(feature = "parallel")]
    fn promote(&mut self, k: usize, length: usize);
}

impl RepeatState for MatchState {
    #[inline(always)]
    fn last_length(&self) -> usize {
        self.last_length
    }
    #[inline(always)]
    fn nearest(&self) -> usize {
        self.repeats[0]
    }
    #[inline(always)]
    fn fresh(&mut self, distance: usize, length: usize) {
        MatchState::fresh(self, distance, length);
    }
    #[inline(always)]
    fn rotate(&mut self, k: usize, length: usize) -> Result<usize> {
        MatchState::rotate(self, k, length)
    }
    #[cfg(feature = "parallel")]
    #[inline(always)]
    fn repeat(&self, k: usize) -> usize {
        self.repeats[k]
    }
    #[cfg(feature = "parallel")]
    #[inline(always)]
    fn promote(&mut self, k: usize, length: usize) {
        let _ = MatchState::rotate(self, k, length);
    }
}

/// [`MatchState`] as five scalars, for the serial loop alone.
///
/// Section 3.5's rules, the same as `MatchState::fresh` and
/// `MatchState::rotate`, spelled out per `k` so no array is indexed by a
/// variable: an array indexed that way has to live in memory, and a
/// scalar need not. `rar5_lz_oracle`'s differential tests and the
/// serial-against-parallel property test hold the two to the same bytes.
#[derive(Clone, Copy)]
pub(super) struct LoopRepeats {
    pub(super) r0: usize,
    pub(super) r1: usize,
    pub(super) r2: usize,
    pub(super) r3: usize,
    pub(super) last: usize,
}

impl LoopRepeats {
    #[inline(always)]
    pub(super) fn load(state: &MatchState) -> LoopRepeats {
        let [r0, r1, r2, r3] = state.repeats;
        LoopRepeats {
            r0,
            r1,
            r2,
            r3,
            last: state.last_length,
        }
    }

    #[inline(always)]
    pub(super) fn store(&self, state: &mut MatchState) {
        state.repeats = [self.r0, self.r1, self.r2, self.r3];
        state.last_length = self.last;
    }
}

impl RepeatState for LoopRepeats {
    #[inline(always)]
    fn last_length(&self) -> usize {
        self.last
    }
    #[inline(always)]
    fn nearest(&self) -> usize {
        self.r0
    }
    #[inline(always)]
    fn fresh(&mut self, distance: usize, length: usize) {
        self.r3 = self.r2;
        self.r2 = self.r1;
        self.r1 = self.r0;
        self.r0 = distance;
        self.last = length;
    }
    #[inline(always)]
    fn rotate(&mut self, k: usize, length: usize) -> Result<usize> {
        // The chosen distance moves to the front and the ones before it
        // shift back one; the ones after it do not move. A zero distance
        // is an uninitialised repeat and changes nothing.
        let distance = match k {
            0 => self.r0,
            1 => self.r1,
            2 => self.r2,
            _ => self.r3,
        };
        if distance == 0 {
            return Err(fault::uninitialised_repeat());
        }
        if k >= 3 {
            self.r3 = self.r2;
        }
        if k >= 2 {
            self.r2 = self.r1;
        }
        if k >= 1 {
            self.r1 = self.r0;
        }
        self.r0 = distance;
        self.last = length;
        Ok(distance)
    }
    #[cfg(feature = "parallel")]
    #[inline(always)]
    fn repeat(&self, k: usize) -> usize {
        match k {
            0 => self.r0,
            1 => self.r1,
            2 => self.r2,
            _ => self.r3,
        }
    }
    #[cfg(feature = "parallel")]
    #[inline(always)]
    fn promote(&mut self, k: usize, length: usize) {
        // `rotate`'s moves with no zero test: the caller has asked
        // `repeat(k)` and found it non-zero.
        let distance = self.repeat(k);
        if k >= 3 {
            self.r3 = self.r2;
        }
        if k >= 2 {
            self.r2 = self.r1;
        }
        if k >= 1 {
            self.r1 = self.r0;
        }
        self.r0 = distance;
        self.last = length;
    }
}

/// Whether the one-thread member path (`Rar5Lz::member_one_thread`) keeps
/// the tape for a block of this table set: where `tape::decode_one_dispatch`
/// would decode it by the literal batch, which is aarch64 and x86-64.
#[cfg(all(
    feature = "parallel",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[inline]
pub(super) fn tape_batch_takes(tables: &Tables) -> bool {
    tape::batch::admits(tables)
}

/// See the aarch64 and x86-64 form: elsewhere the tape has no batch.
#[cfg(all(
    feature = "parallel",
    not(any(target_arch = "aarch64", target_arch = "x86_64"))
))]
#[inline]
pub(super) fn tape_batch_takes(_tables: &Tables) -> bool {
    false
}

/// Whether the shipped serial loop runs the one-pass region
/// (`onepass::region`) between its checked symbols: wherever the tape's
/// fast region exists to borrow, which is the `parallel` feature.
pub(super) const ONE_PASS: bool = cfg!(feature = "parallel");

/// [`decode_block`]'s loop, on whatever state it is handed. With
/// `ONE_PASS`, the one-pass region (`onepass::region`) takes every symbol it
/// can between the checked loop's drain head and its checked symbol.
#[inline(always)]
pub(super) fn decode_block_body<S: LzSink, R: RepeatState, const ONE_PASS: bool>(
    tables: &Tables,
    state: &mut R,
    window: &mut Window,
    filters: &mut Filters,
    bits: &mut BitReader<'_>,
    // The member's declared size bounds its OUTPUT, which the window's
    // drain caps, and not this loop (SPEC-H2 3.1, amended 28 Sep
    // 2026); the filter queue has it from `Filters::begin`.
    _unpacked: u64,
    sink: &mut S,
) -> Result<()> {
    // **The byte-denominated question is asked ONCE and counted down.**
    // The drain cadence is a question asked in bytes, and answering it per
    // symbol computes `window.produced()` every time. `Window::apply_budget`
    // is that answer, and the parallel apply stage asks it the same way.
    // Zero means the checked head must run again, which is what a due
    // drain reduces to. (Until the change of 28 Sep 2026 the budget also
    // counted down to the member's declared size, where this loop
    // stopped; it now decodes every symbol of the block.)
    //
    // The third test, the block's own bit count (3.2), is NOT budgeted:
    // it is not denominated in output bytes, and bounding it is the shape
    // section 7.3 item 5's comment below records as measured and lost.
    //
    // **What this is not.** It does not bound a literal RUN and it
    // recomputes nothing per run, which is the difference between it and
    // shape 2 in the comment below: that shape recomputed a bound every
    // two or three symbols on text and lost 5 percent there. This
    // counter is refreshed only at a drain, thousands of symbols apart on
    // these members, and a literal spends one byte of it with a single
    // decrement.
    //
    // **A match is not clamped by it.** A match that overshoots the
    // cadence saturates the counter to zero and the drain happens on the
    // next iteration, which is what the per-symbol form did too.
    //
    // Measured by subtraction before it was written, one binary against
    // itself across an environment dial with the arms interleaved, on an
    // M3 Ultra: 1.039x, 1.056x and 1.033x of rarkit's own wall on
    // `rar5_text_64m_m3_serial`, `rar5_code_32m_m3_nofilter_serial` and
    // `rar5_incompressible_64m_serial`.
    let mut fuel: usize = 0;
    loop {
        if fuel == 0 {
            // The block's bit count ends the loop, and the member's
            // declared size does NOT (SPEC-H2 3.1, amended 28 Sep
            // 2026): every symbol the block holds is applied, and the
            // window's drain caps what reaches the sink.
            if bits.at_end() {
                break;
            }
            if window.drain_due() {
                window.drain(sink, filters, false)?;
            }
            fuel = window.apply_budget();
            if fuel == 0 {
                // Unreachable on a sound window: a drain having just run
                // if one was due, the cadence is a whole batch away, or
                // unbounded once the output is complete. Breaking rather
                // than spinning is the safe reading of a window that
                // disagreed, and it FAILS LOUDLY where the member's
                // output is short: `finish_member` raises
                // `IncompleteMember`.
                break;
            }
        } else if bits.at_end() {
            break;
        }
        // THE ONE-PASS REGION: symbols decoded and applied at once, inside
        // this budget, handing back to the checked symbol below whatever it
        // does not take whole (`onepass`, whose module comment has why that
        // leaves every byte and every error where this loop puts them).
        #[cfg(feature = "parallel")]
        if ONE_PASS {
            let spent = onepass::region(tables, bits, state, window, fuel);
            if spent != 0 {
                fuel = fuel.saturating_sub(spent);
                if fuel == 0 {
                    continue;
                }
            }
        }
        // The literal class comes from the lookup entry's own bit, so a
        // run of literals is decoded straight through the primary table
        // with no comparison per symbol (section 7.3 item 5).
        //
        // THREE shapes of "decode a RUN of literals" have now been
        // measured on this package and none of them pays. Keep the
        // figures here rather than the ideas, so a fourth attempt spends
        // its time on the apply stage instead.
        //
        // 1. Staging 64 literals through a stack buffer and copying them
        //    into the ring: 9.2 to 9.5 ns a symbol against 8.8 for this
        //    loop (18 Sep 2026).
        // 2. Bounding a run by the four per symbol tests at once - the
        //    block's bits, the declared size, the drain cadence and the
        //    ring's end - and decoding into the ring under that bound:
        //    +3% on `rar5_incompressible_64m_serial`, whose runs are
        //    about fifty symbols, and -5% on `rar5_text_64m_m3_serial`,
        //    whose runs are two or three, two timed runs agreeing on both
        //    signs (an Apple M3 Mac, 20 Sep 2026). This loop's per literal
        //    cost is ONE masked ring store, so a bound recomputed every
        //    couple of symbols costs more than the tests it removes.
        // 3. The same run in the TAPE decode, where a literal also paid a
        //    `Vec::push` and a bit position recompute: worth 22% of
        //    `rar5_incompressible_64m` against an eight lane tape
        //    (the same M3 Mac, 20 Sep), and NOTHING at all - 0.2801 s, 0.2794,
        //    0.2806 with the base gated at both ends - against the
        //    engine's default width on twenty cores (an Apple M1 Mac, 21 Sep).
        //
        // Item 3 is the one that says where the time now is: at a real
        // width the parallel arm is APPLY bound, not decode bound, so
        // making the symbol loop cheaper buys nothing there.
        let entry = tables.main.lookup(bits)?;
        if lut_entry_is_literal(entry) {
            window.literal(lut_symbol(entry) as u8);
            fuel -= 1;
            continue;
        }
        let symbol = lut_symbol(entry);
        let (distance, length) = match symbol {
            SYMBOL_FILTER => {
                // A SIDE COPY, so the reader's own address never reaches
                // a call that is not inlined (see `decode_block`).
                let mut side = *bits;
                let raw = filters::read_record(&mut side);
                *bits = side;
                push_serial(filters, raw?.resolve(window.produced()))?;
                continue;
            }
            SYMBOL_REPEAT_LAST => {
                // Copy `last length` bytes from repeated distance 0. With
                // no match yet in the stream, do nothing: no rotation and
                // no state change.
                if state.last_length() == 0 {
                    continue;
                }
                (state.nearest(), state.last_length())
            }
            258..=261 => {
                let length = read_length(tables, bits)?;
                let distance = state.rotate(symbol - SYMBOL_REPEAT_BASE, length)?;
                (distance, length)
            }
            _ => {
                let slot = symbol - SYMBOL_MATCH_BASE;
                let length = read_length_slot(bits, slot)?;
                let distance = read_distance(tables, bits)?;
                // The bonus is a fresh match's alone (section 3.5).
                let length = fresh_match_length(length, distance);
                state.fresh(distance, length);
                (distance, length)
            }
        };
        // WHOLE, even where it crosses the member's declared size: the
        // surplus stays in the window and the next member counts from
        // after it; the drain keeps it from the output (SPEC-H2 3.1 and
        // 3.8, consequence 2).
        window.copy_match(distance, length)?;
        fuel = fuel.saturating_sub(length);
    }
    Ok(())
}

/// One length slot from the length alphabet, plus its extra bits.
#[inline(always)]
pub(super) fn read_length(tables: &Tables, bits: &mut BitReader<'_>) -> Result<usize> {
    let slot = tables.length.decode(bits)?;
    read_length_slot(bits, slot)
}

#[inline(always)]
pub(super) fn read_length_slot(bits: &mut BitReader<'_>, slot: usize) -> Result<usize> {
    let Some(extra_bits) = bits_after_slot(slot) else {
        // WHERE THE REFUSAL IS BUILT IS CHOSEN BY THE TARGET, and nothing
        // else is: the rule and the answer are section 1.3.1's on both.
        // Measured on shipped builds at one thread (9 Oct 2026): built in
        // place it costs the profile-use build about 1 percent on aarch64
        // (`incompressible_64m` 0.988 of its own plain build, a 4 GiB
        // member 0.7 to 0.9 percent), and built out of line it costs an
        // x86-64 Zen 4 build 2.3 to 2.7 percent at one thread.
        #[cfg(target_arch = "aarch64")]
        return Err(super::ladders::no_such_length_slot());
        #[cfg(not(target_arch = "aarch64"))]
        return Err(fault::length_slot());
    };
    let extra = bits.take_small(u32::from(extra_bits))?;
    Ok(length_from_slot(slot, extra))
}

/// A fresh match's distance (section 3.5): one symbol of the distance
/// code, which is the slot, and then the slot's extra bits. Under four of
/// them they are plain bits. With four or more the plain bits come first,
/// four fewer than the count, and one symbol of the alignment code after
/// them is the value's lowest four.
///
/// Every slot of the alphabet in force is read, and none is refused here.
/// The distance goes to the window, which is what says whether the match
/// can be honoured.
#[inline(always)]
pub(super) fn read_distance(tables: &Tables, bits: &mut BitReader<'_>) -> Result<usize> {
    let entry = tables.distance.lookup(bits)?;
    let slot = lut_symbol(entry);
    if entry & HUFF_LUT_DISTANCE_INVALID_BIT != 0 {
        // A slot whose count of extra bits the table's entry has no room
        // for: 66 to 79, which only a version 1 member's alphabet holds.
        // A SIDE COPY, so the reader's own address never reaches a call
        // that is not inlined (see `decode_block`).
        let mut side = *bits;
        let passed = pass_unplaced_slot(tables, &mut side, slot);
        *bits = side;
        passed?;
        return Ok(distance_named(slot, 0));
    }
    let count = (entry >> HUFF_LUT_DISTANCE_BITS_SHIFT) & HUFF_LUT_DISTANCE_BITS_MASK;
    let extra = if count < 4 {
        bits.take_small(count)?
    } else {
        let plain = bits.take(count - 4)?;
        extra_bits_value(plain, tables.align.decode(bits)?)
    };
    Ok(distance_named(slot, extra))
}

/// Take from the stream what a distance slot of 66 to 79 takes, so that
/// the symbols after it are read from the right bits: its count of extra
/// bits less four as plain bits, then one symbol of the alignment code
/// (section 3.5, where HOW MANY bits these slots take is measured and
/// what distance they name is not). Their value is not kept: no distance
/// is formed from it.
#[cold]
#[inline(never)]
fn pass_unplaced_slot(tables: &Tables, bits: &mut BitReader<'_>, slot: usize) -> Result<()> {
    // 28 to 34 plain bits, more than one read may ask for.
    let mut plain = u32::from(DISTANCE_SLOT_BITS[slot]) - 4;
    while plain > 0 {
        let now = plain.min(16);
        bits.take(now)?;
        plain -= now;
    }
    tables.align.decode(bits)?;
    Ok(())
}

/// [`Filters::push`] for the serial loop. Defined LAST in this file on
/// purpose: its two forms below differ by architecture, and nothing above
/// them moves by a line, so on aarch64 the build is the one before it, panic
/// locations included.
///
/// **Out of line on x86-64.** `push` is inlined into its callers by
/// attribute, but the ordered insert inside it is core's generic
/// `VecDeque::partition_point`, which the inliner takes or leaves per
/// codegen unit. On x86-64 that one decision split `decode_block` into two
/// bodies by which crate compiled the instance, not by anything in its sink:
/// the shipped `rarfast` carried six at 3758 instructions and two at 3577,
/// and the benchmark binary the reverse. Behind this call every instance in both
/// binaries reads 3559, and the four `_serial` rows retire 3.6 to 5.5
/// percent fewer instructions (25 Sep 2026, the
/// x86-64 serial shape). A filter record is rare against the symbols
/// around it, so the price is one call a record.
///
/// **Inline elsewhere.** On aarch64 every instance was already one shape,
/// calling `partition_point` out of line; this call there bought 0.4 to 1.9
/// percent of instructions and no wall, and a timed measurement read the partition
/// shift it caused as up to 1 percent on some rows. So aarch64 keeps `push`
/// inline, exactly as before.
///
/// **What was screened beside it.** The whole filter arm out of line costs
/// `md128k` 2.9 percent of instructions on aarch64; the main table's empty
/// test asked once before the loop costs aarch64 5 to 7 percent; the
/// repeated distances behind the pointer on x86-64 cost the text and code
/// rows; one body for every sink behind a `dyn` seam cuts less.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
pub(super) fn push_serial(filters: &mut Filters, record: filters::Record) -> Result<()> {
    filters.push(record)
}

/// [`push_serial`] off x86-64: `push` inline, as before (see above).
#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub(super) fn push_serial(filters: &mut Filters, record: filters::Record) -> Result<()> {
    filters.push(record)
}
