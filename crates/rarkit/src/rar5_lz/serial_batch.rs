//! The serial loop's eight bit literal batch (SPEC-H2 3.2, 3.4, 3.5, 3.7),
//! asked for once per block at the two call sites; the tape path is untouched.
use super::*;
const WIDTH: usize = 7;

#[inline(always)]
pub(super) fn admits(tables: &Tables) -> bool {
    tables.main.serial_literal_admitted()
}

#[inline(never)]
pub(super) fn run<S: LzSink, R: RepeatState>(
    tables: &Tables,
    state: &mut R,
    window: &mut Window,
    filters: &mut Filters,
    bits: &mut BitReader<'_>,
    unpacked: u64,
    sink: &mut S,
) -> Result<()> {
    if let Some(hole) = tables.main.serial_single_gap() {
        run_gap::<false, _, _>((tables, hole), state, window, filters, bits, unpacked, sink)
    } else if tables.main.serial_full_byte() {
        // Every code an eight bit literal and code `c` literal `c`
        // (`DecodeTable::serial_full_byte`): the gap loop with no hole.
        run_gap::<true, _, _>((tables, 0), state, window, filters, bits, unpacked, sink)
    } else {
        run_fallback(tables, state, window, filters, bits, unpacked, sink)
    }
}

#[inline(never)]
fn run_fallback<S: LzSink, R: RepeatState>(
    tables: &Tables,
    state: &mut R,
    window: &mut Window,
    filters: &mut Filters,
    bits: &mut BitReader<'_>,
    // The member's declared size bounds its OUTPUT, which the window's
    // drain caps, and not this loop (SPEC-H2 3.1, 28 Sep 2026).
    _unpacked: u64,
    sink: &mut S,
) -> Result<()> {
    // **The byte-denominated question is asked ONCE and counted down.**
    // The drain cadence is a question asked in bytes, and answering it per
    // symbol computes `window.produced()` every time. `Window::apply_budget`
    // is that answer, as in `decode_block`. Zero means the checked head
    // must run again, which is what a due drain reduces to. (Until the
    // change of 28 Sep 2026 the budget also counted down to the member's
    // declared size, where this loop stopped.)
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
    let (first, end) = tables.main.serial_literal_interval();
    debug_assert!(
        first <= (256 - tables::SERIAL_BATCH_LITERALS) as u64
            && (tables::SERIAL_BATCH_LITERALS as u64..=256).contains(&end)
    );
    let low = first * 0x0101_0101_0101_0101;
    let high = (end - 128) * 0x0101_0101_0101_0101;
    let mut fuel: usize = 0;
    loop {
        if fuel == 0 {
            // The block's bit count ends the loop, not the member's
            // declared size (SPEC-H2 3.1, amended 28 Sep 2026).
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
                // disagreed, and it FAILS LOUDLY where the member's output
                // is short: `finish_member` raises `IncompleteMember`.
                break;
            }
        } else if bits.at_end() {
            break;
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
        // Only this table-qualified loop attempts a batch. A successful
        // group consumes exactly the scalar codes, within the drain/output fuel.
        if fuel >= WIDTH && bits.remaining() >= WIDTH * 8 {
            let look = bits.serial_window();
            let mut out = [0u8; WIDTH];
            // Each adjusted lane is >=128 and each threshold <=128:
            // subtraction cannot borrow across byte boundaries.
            let adjusted = look | 0x8080_8080_8080_8080;
            let below = !((adjusted - low) | look);
            let above = (adjusted - high) & look;
            let invalid = (below | above) & 0x8080_8080_8080_8000;
            for (i, byte) in out.iter_mut().enumerate() {
                let index = (((look >> (56 - 8 * i)) & 255) << 1) as usize;
                let entry = tables.main.lut[index];
                *byte = lut_symbol(entry) as u8;
            }
            if invalid == 0 {
                window.literals(&out);
                bits.advance_buffered((WIDTH * 8) as u32);
                fuel -= WIDTH;
                continue;
            }
            let prefix = invalid.leading_zeros() as usize / 8;
            if prefix > 0 {
                window.literals(&out[..prefix]);
                bits.advance_buffered((prefix * 8) as u32);
                fuel -= prefix;
                continue;
            }
        }
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
        // surplus stays in the window and the drain keeps it from the
        // output (SPEC-H2 3.1 and 3.8, consequence 2).
        window.copy_match(distance, length)?;
        fuel = fuel.saturating_sub(length);
    }
    Ok(())
}
/// `FULL`: a full-byte main table, whose seven codes a batch takes are
/// the seven literals themselves; there is no escape to refuse and no hole
/// to step over (`hole` is unused). The scalar step below is unchanged.
#[inline(never)]
fn run_gap<const FULL: bool, S: LzSink, R: RepeatState>(
    (tables, hole): (&Tables, u8),
    state: &mut R,
    window: &mut Window,
    filters: &mut Filters,
    bits: &mut BitReader<'_>,
    // The member's declared size bounds its OUTPUT, which the window's
    // drain caps, and not this loop (SPEC-H2 3.1, 28 Sep 2026).
    _unpacked: u64,
    sink: &mut S,
) -> Result<()> {
    // **The byte-denominated question is asked ONCE and counted down.**
    // The drain cadence is a question asked in bytes, and answering it per
    // symbol computes `window.produced()` every time. `Window::apply_budget`
    // is that answer, as in `decode_block`. Zero means the checked head
    // must run again, which is what a due drain reduces to. (Until the
    // change of 28 Sep 2026 the budget also counted down to the member's
    // declared size, where this loop stopped.)
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
    let hole = u64::from(hole);
    let threshold = (hole & 127) * 0x0101_0101_0101_0101;
    let mut fuel: usize = 0;
    loop {
        if fuel == 0 {
            // The block's bit count ends the loop, not the member's
            // declared size (SPEC-H2 3.1, amended 28 Sep 2026).
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
                // disagreed, and it FAILS LOUDLY where the member's output
                // is short: `finish_member` raises `IncompleteMember`.
                break;
            }
        } else if bits.at_end() {
            break;
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
        // Only this table-qualified loop attempts a batch. A successful
        // group consumes exactly the scalar codes, within the drain/output fuel.
        if fuel >= WIDTH && bits.remaining() >= WIDTH * 8 {
            let look = bits.serial_window();
            if FULL {
                // Each of the seven codes is its own literal.
                window.literals(&look.to_be_bytes()[..WIDTH]);
                bits.advance_buffered((WIDTH * 8) as u32);
                fuel -= WIDTH;
                continue;
            }
            // The unused low byte is zero: it must neither invalidate a
            // batch nor carry into one of its seven translated bytes.
            let codes = look & !255u64;
            let inverted = !codes;
            let invalid =
                inverted.wrapping_sub(0x0101_0101_0101_0101) & !inverted & 0x8080_8080_8080_8080;
            if invalid == 0 {
                // Every used code is <=254. Each maps to rank, plus one
                // iff the omitted symbol is at or below that rank.
                // Lane operands are >=128 and threshold <=127, so no
                // subtraction borrows across bytes. The addition cannot
                // carry because its code is <=254 and increment <=1.
                let comparison = (codes | 0x8080_8080_8080_8080) - threshold;
                let selected = if hole < 128 {
                    comparison | codes
                } else {
                    comparison & codes
                };
                let increment = ((selected & 0x8080_8080_8080_8080) >> 7) & !255u64;
                let out = (codes + increment).to_be_bytes();
                window.literals(&out[..WIDTH]);
                bits.advance_buffered((WIDTH * 8) as u32);
                fuel -= WIDTH;
                continue;
            }
            // The zero-byte test can flag a preceding 254 after a lower
            // 255 borrows. This only shortens the accepted prefix.
            let prefix = invalid.leading_zeros() as usize / 8;
            if prefix > 0 {
                let mask = u64::MAX << (64 - prefix * 8);
                // Clear the rejected suffix before translation, so a
                // rejected 255 cannot carry into the accepted prefix.
                let codes = codes & mask;
                let comparison = (codes | 0x8080_8080_8080_8080) - threshold;
                let selected = if hole < 128 {
                    comparison | codes
                } else {
                    comparison & codes
                };
                let increment = ((selected & 0x8080_8080_8080_8080) >> 7) & mask;
                let out = (codes + increment).to_be_bytes();
                window.literals(&out[..prefix]);
                bits.advance_buffered((prefix * 8) as u32);
                fuel -= prefix;
                continue;
            }
        }

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
        // surplus stays in the window and the drain keeps it from the
        // output (SPEC-H2 3.1 and 3.8, consequence 2).
        window.copy_match(distance, length)?;
        fuel = fuel.saturating_sub(length);
    }
    Ok(())
}
#[cfg(test)]
mod batch_tests {
    use super::*;

    #[test]
    fn serial_batch_matches_scalar_at_bit_output_and_ring_edges() {
        for shape in 0..4 {
            let mut tables = Tables::default();
            let mut lengths = [0u8; tables::MAIN_SYMBOLS];
            lengths[..256].fill(8);
            if shape > 0 {
                lengths[255] = 9;
                // Incomplete table, a filter, or a fresh-match escape.
                if shape == 2 {
                    lengths[256] = 9;
                }
                if shape == 3 {
                    lengths[262] = 9;
                }
            }
            tables.main.build(&lengths, tables::Role::Main).unwrap();
            assert!(admits(&tables));
            // Shape 0 is the full-byte table, which `run` sends to the gap
            // loop with no hole (`run_gap::<true, ..>`); the rest are gaps.
            assert_eq!(tables.main.serial_full_byte(), shape == 0);
            assert_eq!(tables.main.serial_single_gap().is_some(), shape > 0);
            for seed in 0..12u64 {
                let mut rng = seed + 1;
                let data: Vec<u8> = (0..67)
                    .map(|_| {
                        rng ^= rng << 13;
                        rng ^= rng >> 7;
                        rng ^= rng << 17;
                        if seed == 0 {
                            255
                        } else {
                            rng as u8
                        }
                    })
                    .collect();
                for nbits in (0usize..=536).step_by(7) {
                    for output in [0, 1, 2, 3, 6, 17, 64, 72] {
                        for near_end in [false, true] {
                            let exercise = |batch: bool| {
                                let mut bits = BitReader::new(&data[..nbits.div_ceil(8)], nbits);
                                let mut window = Window::new(128 << 10, 128 << 10).unwrap();
                                if near_end {
                                    window.literals(&vec![42; window.ring_bytes() - 5]);
                                    window.begin_member();
                                }
                                let mut state = MatchState::default();
                                let mut filters = Filters::default();
                                filters.begin(output);
                                let mut sink = Vec::new();
                                let result = if batch {
                                    run(
                                        &tables,
                                        &mut state,
                                        &mut window,
                                        &mut filters,
                                        &mut bits,
                                        output,
                                        &mut sink,
                                    )
                                } else {
                                    decode_block_body::<_, _, { super::ONE_PASS }>(
                                        &tables,
                                        &mut state,
                                        &mut window,
                                        &mut filters,
                                        &mut bits,
                                        output,
                                        &mut sink,
                                    )
                                };
                                let error = result.err().map(|e| format!("{:?}", e.kind()));
                                let produced = window.produced();
                                let drain = window
                                    .drain(&mut sink, &mut filters, true)
                                    .err()
                                    .map(|e| format!("{:?}", e.kind()));
                                (
                                    error,
                                    drain,
                                    bits.position(),
                                    produced,
                                    state.repeats,
                                    state.last_length,
                                    sink,
                                )
                            };
                            assert_eq!(exercise(false), exercise(true), "shape={shape} seed={seed} bits={nbits} output={output} edge={near_end}");
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[test]
fn canonical_gate_matches_lookup_census_at_admission_boundary() {
    for literals in 0..=256 {
        for controls in 0..=(256 - literals).min(50) {
            let mut tables = Tables::default();
            let mut lengths = [0u8; tables::MAIN_SYMBOLS];
            lengths[..literals].fill(8);
            lengths[256..256 + controls].fill(8);
            tables.main.build(&lengths, tables::Role::Main).unwrap();
            assert_eq!(admits(&tables), literals >= tables::SERIAL_BATCH_LITERALS);
        }
    }
}

#[inline(never)]
pub(super) fn dispatch<S: LzSink>(
    tables: &Tables,
    state: &mut MatchState,
    window: &mut Window,
    filters: &mut Filters,
    bits: &mut BitReader<'_>,
    unpacked: u64,
    sink: &mut S,
) -> Result<()> {
    let mut reader = *bits;
    let mut repeats = LoopRepeats::load(state);
    let result = run(
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
#[cfg(test)]
#[test]
fn varied_tables_offsets_matches_and_tails_match_scalar() {
    // Deterministic differential cases against our specification-based scalar
    // decoder, including valid and incomplete main tables and live history.
    let mut rng = 0x1234_5678_9abc_def0u64;
    let mut next = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    for case in 0..2048 {
        let mut tables = Tables::default();
        let mut lengths = [0u8; tables::MAIN_SYMBOLS];
        const EIGHT: usize = tables::SERIAL_BATCH_LITERALS;
        lengths[..EIGHT].fill(8);
        // Up to 7 short codes move the eight-bit interval's lower bound.
        // At most 14 depth-eight slots go to those codes, leaving 10.
        // The other <=74 codes at length >=11 consume at most 9.25.
        let short = case % 8;
        lengths[EIGHT..EIGHT + short].fill(7);
        for length in &mut lengths[EIGHT + short..] {
            let value = next();
            *length = if value & 15 == 0 {
                0
            } else {
                11 + (value % 5) as u8
            };
        }
        // Move length-eight codes throughout the literal alphabet without
        // changing the Kraft sum or the guaranteed admission count.
        for i in (1..256).rev() {
            lengths.swap(i, next() as usize % (i + 1));
        }
        if case.is_multiple_of(4) {
            lengths.fill(0);
            lengths[..256].fill(8);
            lengths[(case / 4) % 256] = 9;
            lengths[256 + case % 50] = 9;
        }
        tables.main.build(&lengths, tables::Role::Main).unwrap();
        assert!(admits(&tables));
        tables
            .distance
            .build(&[6; 64], tables::Role::Distance)
            .unwrap();
        tables.align.build(&[4; 16], tables::Role::Plain).unwrap();
        tables.length.build(&[6; 44], tables::Role::Plain).unwrap();
        let bytes: Vec<u8> = (0..257).map(|_| next() as u8).collect();
        for offset in 0..8 {
            for tail in [0usize, 1, 7, 8, 15, 31, 55, 56, 57, 63, 64, 65, 511, 2056] {
                let nbits = tail.max(offset);
                let output = [0, 1, 3, 6, 7, 8, 63, 256, 4097][next() as usize % 9];
                let edge = next() & 1 != 0;
                let exercise = |batch: bool| {
                    let mut bits = BitReader::new(&bytes[..nbits.div_ceil(8)], nbits);
                    bits.seek(offset);
                    let mut window = Window::new(128 << 10, 128 << 10).unwrap();
                    let history = if edge { window.ring_bytes() - 3 } else { 160 };
                    window.literals(&vec![42; history]);
                    window.begin_member();
                    let mut state = MatchState {
                        repeats: [1, 3, 17, 128],
                        last_length: 3,
                    };
                    let mut filters = Filters::default();
                    filters.begin(output);
                    let mut sink = Vec::new();
                    let result = if batch {
                        run(
                            &tables,
                            &mut state,
                            &mut window,
                            &mut filters,
                            &mut bits,
                            output,
                            &mut sink,
                        )
                    } else {
                        decode_block_body::<_, _, { super::ONE_PASS }>(
                            &tables,
                            &mut state,
                            &mut window,
                            &mut filters,
                            &mut bits,
                            output,
                            &mut sink,
                        )
                    };
                    let error = result.err().map(|e| format!("{:?}", e.kind()));
                    let produced = window.produced();
                    let drain = window
                        .drain(&mut sink, &mut filters, true)
                        .err()
                        .map(|e| format!("{:?}", e.kind()));
                    let position = bits.position();
                    let mut continuation = Vec::new();
                    while bits.remaining() != 0 {
                        let count = bits.remaining().min(8) as u32;
                        continuation.push(bits.take(count).unwrap());
                    }
                    (error, drain, position, produced, state, sink, continuation)
                };
                assert_eq!(
                    exercise(false),
                    exercise(true),
                    "case={case} offset={offset} bits={nbits} output={output} edge={edge}"
                );
            }
        }
    }
}
#[cfg(test)]
#[test]
fn every_single_gap_and_every_valid_wire_byte_matches_canonical_symbols() {
    for hole in 0..256usize {
        let mut tables = Tables::default();
        let mut lengths = [0u8; tables::MAIN_SYMBOLS];
        lengths[..256].fill(8);
        lengths[hole] = 9;
        lengths[256] = 9;
        tables.main.build(&lengths, tables::Role::Main).unwrap();
        assert_eq!(tables.main.serial_single_gap(), Some(hole as u8));
        for code in 0..255usize {
            let data = [code as u8; 7];
            let mut bits = BitReader::new(&data, 56);
            let mut window = Window::new(128 << 10, 128 << 10).unwrap();
            let mut state = MatchState::default();
            let mut filters = Filters::default();
            filters.begin(7);
            let mut sink = Vec::new();
            run(
                &tables,
                &mut state,
                &mut window,
                &mut filters,
                &mut bits,
                7,
                &mut sink,
            )
            .unwrap();
            window.drain(&mut sink, &mut filters, true).unwrap();
            let expected = (code + usize::from(code >= hole)) as u8;
            assert_eq!(sink, [expected; 7], "hole={hole} code={code}");
            assert_eq!(bits.position(), 56);
        }
    }
}
#[cfg(test)]
#[test]
fn every_gap_with_exception_in_each_lane_matches_scalar() {
    for hole in 0..256 {
        let mut tables = Tables::default();
        let mut lengths = [0u8; tables::MAIN_SYMBOLS];
        lengths[..256].fill(8);
        lengths[hole] = 9;
        lengths[256] = 9;
        tables.main.build(&lengths, tables::Role::Main).unwrap();
        for lane in 0..7 {
            // A 255 may borrow into the preceding 254 in the conservative
            // zero-byte mask. Translation must never carry across it.
            let mut data = [254u8; 10];
            data[lane] = 255;
            data[lane + 1] = 0;
            let exercise = |batch: bool| {
                let mut bits = BitReader::new(&data, 80);
                let mut window = Window::new(128 << 10, 128 << 10).unwrap();
                window.literals(&vec![42; window.ring_bytes() - 3]);
                window.begin_member();
                let mut state = MatchState::default();
                let mut filters = Filters::default();
                filters.begin(9);
                let mut sink = Vec::new();
                let result = if batch {
                    run(
                        &tables,
                        &mut state,
                        &mut window,
                        &mut filters,
                        &mut bits,
                        9,
                        &mut sink,
                    )
                } else {
                    decode_block_body::<_, _, { super::ONE_PASS }>(
                        &tables,
                        &mut state,
                        &mut window,
                        &mut filters,
                        &mut bits,
                        9,
                        &mut sink,
                    )
                };
                let error = result.err().map(|e| format!("{:?}", e.kind()));
                let produced = window.produced();
                let position = bits.position();
                let drain = window
                    .drain(&mut sink, &mut filters, true)
                    .err()
                    .map(|e| format!("{:?}", e.kind()));
                let mut remaining = Vec::new();
                while bits.remaining() != 0 {
                    let count = bits.remaining().min(8) as u32;
                    remaining.push(bits.take(count).unwrap());
                }
                (error, drain, position, produced, state, sink, remaining)
            };
            assert_eq!(exercise(false), exercise(true), "hole={hole} lane={lane}");
        }
    }
}
