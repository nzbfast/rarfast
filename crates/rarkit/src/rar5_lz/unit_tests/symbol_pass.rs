//! THE SYMBOL PASS (`rar5_lz::symbols`): a block its lane walked into 32-bit
//! symbols must apply exactly as the shipped walk applies its tape.

use super::*;

/// THE WIDE GATHER AT EVERY PLACEMENT:
/// `Window::put_symbols`
/// driven straight, on the 256 KiB and 512 KiB dictionaries' floor rings
/// and on rings a ceiling keeps under two gather windows, with the part's
/// first byte put on each edge that decides a form: the ring's start and
/// end, one stride either side, each fixed view's length either side, and
/// the part's reach either side (where the history turns from one run into
/// two). A part may continue from a lap before (`origin` past the write
/// point) or cross the ring's end itself. Its names are the nearest byte,
/// the farthest, the two bytes either side of the ring's end, and random,
/// among literals, including the literal zero, which is a name of zero
/// once untagged. Every byte of the ring is compared against a model that
/// reads each name at its own index before anything is written, which is
/// what the caller's admission promises; the forms' counters show both
/// forms ran at each size.
#[cfg(feature = "parallel")]
#[test]
fn the_wide_gather_reads_every_name_where_the_walk_would_at_every_placement() {
    use super::output::{Window, WIDE_FORMS};
    let lit = Window::SYMBOL_LITERAL;
    let mut rng = rarkit_testdata::Seeded::new(0x3a5e_77ed_0b0e_2f11);
    // (declared, ceiling): floor rings, then rings under two windows.
    let rings: [(u64, u64); 5] = [
        (128 << 10, u64::MAX),
        (256 << 10, u64::MAX),
        (512 << 10, u64::MAX),
        (128 << 10, 128 << 10),
        (256 << 10, 256 << 10),
    ];
    let mut checked = 0u64;
    for (declared, ceiling) in rings {
        let mut w = Window::new(declared, ceiling).expect("window");
        let ring_len = w.ring_bytes();
        if ceiling == u64::MAX {
            // The floor rings are the masked form's; the ceiling rings are
            // not powers of two, so both direct forms are driven here.
            assert_eq!(ring_len, RING_FLOOR);
        } else {
            assert!(!ring_len.is_power_of_two());
        }
        let declared = declared as usize;
        let mut noise = vec![0u8; ring_len];
        for chunk in noise.chunks_mut(8) {
            let v = rng.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        w.fill_for_test(&noise, 0);
        let mut reaches = vec![1, 255, Window::GATHER_WINDOW, declared];
        reaches.extend([Window::GATHER_WINDOW + 1, declared - 1, declared / 2 + 3]);
        reaches.retain(|&r| r >= 1 && r <= declared && r + 64 < ring_len);
        let forms_before = WIDE_FORMS.with(|c| c.get());
        for &reach in &reaches {
            let mut starts = vec![0usize, 1, 15, 16, 17, reach - 1, reach, reach + 1];
            for view in [
                Window::GATHER_WINDOW,
                Window::WIDE_VIEW / 2,
                Window::WIDE_VIEW,
            ] {
                starts.extend([view - 1, view, view + 1]);
            }
            starts.extend([ring_len - 1, ring_len - 17, ring_len - reach]);
            starts.retain(|&s| s < ring_len);
            for &start in &starts {
                // (origin, length): from the part's first byte; a
                // continuation from a lap before; one crossing the ring's
                // end; the longest the ring admits.
                let room = ring_len - reach;
                let mut shapes = vec![(0usize, 1usize), (0, 700), (3, 64), (1, 7)];
                shapes.push((ring_len - start + 5, 300));
                if ring_len - start <= 4096 {
                    shapes.push((0, ring_len - start + 40));
                }
                if start == reach {
                    shapes.push((room / 3, room - room / 3));
                }
                for (origin, len) in shapes {
                    if len == 0 || origin + len + reach > ring_len {
                        continue;
                    }
                    let at = (start + origin) % ring_len;
                    // The ring as the last case left it, fresh bytes
                    // under the history this case reads.
                    let mut history = w.ring_for_test().to_vec();
                    for k in 1..=reach.min(4096) {
                        history[(start + ring_len - k) % ring_len] = rng.next_u64() as u8;
                    }
                    for k in [reach, reach / 2, reach.saturating_sub(4097)] {
                        if k >= 1 {
                            history[(start + ring_len - k) % ring_len] = rng.next_u64() as u8;
                        }
                    }
                    w.fill_for_test(&history, at);
                    let special = [
                        1usize,
                        reach,
                        start % ring_len,
                        (start + 1) % ring_len,
                        reach.saturating_sub(1),
                    ];
                    let symbols: Vec<u32> = (0..len)
                        .map(|i| {
                            if i % 7 == 3 {
                                lit | (i as u32 & 0xff)
                            } else if i % 11 == 5 {
                                lit
                            } else if i % 5 == 1 {
                                let name = special[i % special.len()];
                                if (1..=reach).contains(&name) {
                                    name as u32
                                } else {
                                    1
                                }
                            } else {
                                1 + rng.below(reach as u64) as u32
                            }
                        })
                        .collect();
                    let mut want = history.clone();
                    for (i, &symbol) in symbols.iter().enumerate() {
                        let slot = (start + origin + i) % ring_len;
                        want[slot] = if symbol & lit != 0 {
                            symbol as u8
                        } else {
                            history[(start + ring_len - symbol as usize) % ring_len]
                        };
                    }
                    w.put_symbols(&symbols, origin, reach);
                    assert!(
                        w.ring_for_test() == &want[..],
                        "ring {ring_len}, reach {reach}, start {start}, origin {origin}, \
                         length {len}: the gather wrote other bytes than the model"
                    );
                    assert_eq!(w.at_for_test(), (at + len) % ring_len);
                    checked += 1;
                }
            }
        }
        let forms = WIDE_FORMS.with(|c| c.get());
        let (views, direct) = (forms.0 - forms_before.0, forms.1 - forms_before.1);
        eprintln!("ring {ring_len}: {views} fixed view runs, {direct} direct runs");
        if declared > Window::GATHER_WINDOW || ring_len < 2 * Window::GATHER_WINDOW {
            assert!(direct > 0, "ring {ring_len}: direct borrowing never ran");
        } else {
            assert_eq!((views, direct), (0, 0), "md128k's gather left its own form");
        }
        if declared > Window::GATHER_WINDOW && ceiling == u64::MAX {
            assert!(views > 0, "ring {ring_len}: the fixed view never ran");
        }
    }
    eprintln!("{checked} placements checked");
}

/// THE SEQUENCE OP'S WALK PIECES CHANGE NO BYTE, NO DRAIN PIECE, NO
/// REPEAT AND NO ERROR.
/// Every random symbol case (literal runs folded into the operation after
/// them half the time, repeats of every slot, filters, zero distances,
/// distances past the window and past the stream, members that end inside
/// the block) is walked by all eight sets of the walk pieces (`r` the
/// repeats in registers, `l` the lane's reach, `c` the whole-source copy),
/// by the plain walk and by the far list's, with the lane's reach written;
/// each must leave exactly what the plain walk without a piece leaves.
///
/// IN BOTH FILTER MODES, each walk against the plain walk of ITS OWN
/// mode. Where a transform is handed to a pool task (the filter offload)
/// a drain is cut at the span it completes, which is that path's own
/// behaviour and one more drain piece than with it off; so a walk with
/// the offload on is not to be held to a plain walk with it off. The
/// plain walk and its piece sets run with it off and with it on. The far
/// list's walk sets the mode itself, from the process's own answer
/// (`filters::offload_wanted`), and is held to the plain walk of that
/// mode.
#[cfg(feature = "parallel")]
#[test]
fn every_walk_piece_set_matches_the_plain_walk() {
    use super::filters::Filters;
    use super::output::{NoFilters, Window};
    use super::tape::{self, FarList};

    let run = |case: &SymbolCase, pieces: u8, listed: bool, offload: bool| -> SymbolOutcome {
        let mut window = Window::new(case.declared, case.ceiling).unwrap();
        window.reset();
        let mut sink = Pieces::default();
        window.literals_chunked(&case.history, &mut sink, &mut NoFilters);
        if case.solid {
            window.drain(&mut sink, &mut NoFilters, true).unwrap();
            window.begin_member();
        }
        let mut state = case.state;
        // The other fields are private to the filters: no struct literal.
        #[allow(clippy::field_reassign_with_default)]
        let mut filters = {
            let mut filters = Filters::default();
            filters.offload = offload;
            filters
        };
        let unpacked = window.produced() + (1 << 40);
        let mut far = FarList::default();
        tape::fill_far_list(&case.tape.steps, 64, &mut far);
        let result = tape::apply_pieces(
            pieces,
            listed.then_some(&far),
            &case.tape,
            &mut state,
            &mut window,
            &mut filters,
            unpacked,
            &mut sink,
        )
        .map(|_| true)
        .map_err(|e| format!("{:?}", e.kind()));
        if result.is_ok() {
            let _ = window.drain(&mut sink, &mut filters, true);
        }
        SymbolOutcome {
            result,
            produced: window.produced(),
            state,
            pieces: sink,
        }
    };
    let mut trusted_cases = 0;
    let mut listed_cases = 0;
    for seed in 0..400u64 {
        let mut case = symbol_case(seed);
        case.tape.reach = Some(tape::reach_of(&case.tape.steps));
        for offload in [false, true] {
            let base = run(&case, 0, false, offload);
            trusted_cases += usize::from(!offload && base.result.is_ok());
            for pieces in [0u8, 2, 4, 6, 8, 10, 12, 14] {
                let got = run(&case, pieces, false, offload);
                assert_eq!(
                    got, base,
                    "seed {seed}: pieces {pieces:#x}, offload {offload}"
                );
                // The far list's walk runs in the process's own mode.
                if offload == super::filters::offload_wanted() {
                    let got = run(&case, pieces, true, offload);
                    assert_eq!(
                        got, base,
                        "seed {seed}: pieces {pieces:#x}, listed, offload {offload}"
                    );
                    listed_cases += 1;
                }
            }
        }
    }
    assert!(trusted_cases > 100, "most cases run to their end");
    assert_eq!(
        listed_cases,
        400 * 8,
        "the far list's walk was held in one mode"
    );
}

/// Run one case through the shipped walk, or (`resolve` true) through the
/// lane's repeat resolution and, where it took the tape, the resolved walk.
/// Answers the outcome and whether the tape was resolved.
#[cfg(feature = "parallel")]
fn run_resolved_case(
    case: &mut SymbolCase,
    resolve: bool,
    end: Option<u64>,
) -> (SymbolOutcome, bool) {
    use super::filters::Filters;
    use super::output::{NoFilters, Window};
    use super::tape;
    use crate::carry::c_lz::codec::rar50::TapeApplied;

    let mut window = Window::new(case.declared, case.ceiling).unwrap();
    window.reset();
    let mut sink = Pieces::default();
    window.literals_chunked(&case.history, &mut sink, &mut NoFilters);
    if case.solid {
        window.drain(&mut sink, &mut NoFilters, true).unwrap();
        window.begin_member();
    }
    let mut state = case.state;
    let mut filters = Filters::default();
    let unpacked = match end {
        Some(block) if case.unpacked_slack < 0 => {
            let cut = (case.unpacked_slack.unsigned_abs()) % block.max(1);
            window.produced() + block - cut
        }
        _ => window.produced() + (1 << 40),
    };
    let taken = resolve && tape::resolve_repeats(&mut case.tape);
    let result = match case.tape.resolved.take() {
        Some(ends) => tape::apply_resolved(
            &case.tape,
            ends,
            &mut state,
            &mut window,
            &mut filters,
            unpacked,
            &mut sink,
        ),
        None => tape::apply(
            &case.tape,
            &mut state,
            &mut window,
            &mut filters,
            unpacked,
            &mut sink,
        ),
    };
    let result = result
        .map(|a| matches!(a, TapeApplied::BlockDone))
        .map_err(|e| format!("{:?}", e.kind()));
    if result.is_ok() {
        let _ = window.drain(&mut sink, &mut filters, true);
    }
    (
        SymbolOutcome {
            result,
            produced: window.produced(),
            state,
            pieces: sink,
        },
        taken,
    )
}

/// THE RESOLVED WALK'S DIFFERENTIAL:
/// every random tape the
/// symbol pass's differential uses, walked by the shipped walk and by the
/// lane's resolution plus the resolved walk on twin windows, leaves the
/// same bytes in the same drain pieces, the same repeat state and last
/// length, the same stop and the same error, including a stop or an error
/// part way through a resolved tape (the replay). Each case is drawn twice:
/// as it comes, where a repeat early in the tape reads an incoming slot and
/// the resolution refuses; and with every repeat before the tape's fourth
/// fresh match dropped, so every slot is the tape's own and it resolves.
/// Requires the resolution both taken and refused.
#[cfg(feature = "parallel")]
#[test]
fn a_resolved_tape_is_the_walk_byte_for_byte_piece_for_piece() {
    use super::tape::{tape_kind, TapeOp};
    let (mut taken, mut refused, mut stopped, mut failed) = (0u64, 0u64, 0u64, 0u64);
    for seed in 0..3_000u64 {
        let draw = |seed: u64| {
            let mut case = symbol_case(seed % 1_500);
            if seed >= 1_500 {
                let mut fresh = 0;
                let ops: Vec<TapeOp> = case
                    .tape
                    .steps
                    .iter()
                    .copied()
                    .filter(|op| {
                        fresh += usize::from(op.kind() == tape_kind::MATCH);
                        fresh >= 4 || !matches!(op.kind(), tape_kind::REP | tape_kind::REP_LAST)
                    })
                    .collect();
                case.tape.steps = ops;
            }
            case
        };
        let (whole, _) = run_resolved_case(&mut draw(seed), false, None);
        let before = draw(seed).history.len() as u64 * u64::from(!draw(seed).solid);
        let block = whole.produced.saturating_sub(before);
        let (walk, _) = run_resolved_case(&mut draw(seed), false, Some(block));
        let (resolved, took) = run_resolved_case(&mut draw(seed), true, Some(block));
        if took {
            taken += 1;
            stopped += u64::from(resolved.result == Ok(true));
            failed += u64::from(resolved.result.is_err());
        } else {
            refused += 1;
        }
        assert_eq!(walk.result, resolved.result, "case {seed}: result");
        assert_eq!(walk.produced, resolved.produced, "case {seed}: produced");
        assert_eq!(walk.state, resolved.state, "case {seed}: repeat state");
        assert_eq!(
            walk.pieces.0.len(),
            resolved.pieces.0.len(),
            "case {seed}: drain piece count"
        );
        for (i, (a, b)) in walk.pieces.0.iter().zip(&resolved.pieces.0).enumerate() {
            assert!(a == b, "case {seed}: drain piece {i} differs");
        }
    }
    eprintln!("resolved {taken} (stopped {stopped}, failed {failed}), refused {refused}");
    assert!(
        taken >= 500 && refused >= 300,
        "taken {taken}, refused {refused}"
    );
    assert!(
        stopped >= 20 && failed >= 20,
        "stopped {stopped}, failed {failed}"
    );
}

/// A tape the lane cannot resolve comes back EXACTLY as decoded: the one
/// pass writes as it walks, so a repeat past the live window that reads the
/// incoming state must put back every repeat it already rewrote.
#[cfg(feature = "parallel")]
#[test]
fn an_unresolvable_tape_is_put_back_as_decoded() {
    use super::tape::{self, tape_kind, BlockTape, TapeOp};
    let pairs = |t: &BlockTape| -> Vec<(u32, usize, usize, u32)> {
        t.steps
            .iter()
            .map(|o| (o.kind(), o.prefix(), o.length(), o.distance))
            .collect()
    };
    // 100 literal ops, then fresh matches each followed by a REP of index 0
    // (the tape's own slot, so rewritten) and a REP_LAST (rewritten too).
    let mut ops: Vec<TapeOp> = (0..100).map(|_| TapeOp::lits(1)).collect();
    for i in 0..20u32 {
        ops.push(TapeOp::new(tape_kind::MATCH, 3, 5 + i));
        ops.push(TapeOp::new(tape_kind::REP, 3, 0));
        ops.push(TapeOp::new(tape_kind::REP_LAST, 0, 0));
    }
    // Resolvable as it stands: every repeat reads a slot of the tape.
    let mut whole = BlockTape {
        steps: ops.clone(),
        ..Default::default()
    };
    assert!(tape::resolve_repeats(&mut whole));
    // Op 106 is a REP of index 3 after only three fresh matches: it reads
    // incoming slot 3 past the live window, so the tape is refused and the
    // repeats rewritten before it are put back.
    ops.insert(106, TapeOp::new(tape_kind::REP, 3, 3));
    let mut refused = BlockTape {
        steps: ops,
        ..Default::default()
    };
    let decoded = pairs(&refused);
    assert!(!tape::resolve_repeats(&mut refused));
    assert_eq!(
        pairs(&refused),
        decoded,
        "the refused tape is put back as decoded"
    );
    assert!(refused.resolved.is_none());
}

/// The symbolic end state is the live one: on a resolved tape the state
/// after the resolved walk equals the shipped walk's for EVERY incoming
/// state, zero slots included, since the end state names incoming slots.
#[cfg(feature = "parallel")]
#[test]
fn a_resolved_tapes_end_state_holds_for_every_incoming_state() {
    use super::tape::{self, tape_kind, BlockTape, TapeOp};
    let mut rng = rarkit_testdata::Seeded::new(0x005e_ed2b_55a6);
    let mut checked = 0;
    for _ in 0..4_000 {
        let mut ops = vec![];
        for _ in 0..(1 + rng.below(60)) {
            ops.push(match rng.below(10) {
                0..=3 => TapeOp::new(
                    tape_kind::MATCH,
                    2 + rng.below(9) as usize,
                    1 + rng.below(50) as u32,
                ),
                4..=7 => TapeOp::new(
                    tape_kind::REP,
                    2 + rng.below(9) as usize,
                    rng.below(4) as u32,
                ),
                _ => TapeOp::new(tape_kind::REP_LAST, 0, 0),
            });
        }
        let mut t = BlockTape {
            steps: ops.clone(),
            ..Default::default()
        };
        if !tape::resolve_repeats(&mut t) {
            continue;
        }
        let end = t.resolved.take().unwrap();
        for _ in 0..8 {
            let mut live = super::MatchState {
                repeats: [0, 1, 2, 3].map(|_| rng.below(3) as usize * (1 + rng.below(70) as usize)),
                last_length: rng.below(2) as usize * 7,
            };
            let mut ends = live;
            end.settle_for_test(&mut ends);
            let mut faulted = false;
            for op in &ops {
                match op.kind() {
                    tape_kind::MATCH => live.fresh(op.distance as usize, op.length()),
                    // A zero incoming slot is the fault, raised at apply;
                    // the tape then leaves no end state to compare.
                    tape_kind::REP if live.rotate(op.distance as usize, op.length()).is_err() => {
                        faulted = true;
                        break;
                    }
                    _ => {}
                }
            }
            if faulted {
                continue;
            }
            assert_eq!(live, ends);
            checked += 1;
        }
    }
    assert!(checked > 1_000, "only {checked} resolved tapes");
}

/// THE SCALAR RING IS THE `u128` RING:
/// the four-slot `tape::Ring` the
/// resolver walks takes every rep index and every fresh match exactly as
/// the one-`u128` ring it replaced, slot `j` in bits `32 j` up, whose
/// formula is restated here as the reference. Every `k` from the seeded
/// ring, then long random streams of repeats and fresh matches over values
/// that include zero and `u32::MAX`.
#[cfg(feature = "parallel")]
#[test]
fn the_scalar_ring_rotates_as_the_u128_ring() {
    use super::tape::Ring;
    fn take_u128(ring: &mut u128, k: usize) -> u32 {
        const RING_BELOW: [u128; 4] = [0, (1 << 32) - 1, (1 << 64) - 1, (1 << 96) - 1];
        const RING_ABOVE: [u128; 4] = [!((1 << 32) - 1), !((1 << 64) - 1), !((1 << 96) - 1), 0];
        let chosen = (*ring >> (32 * k)) as u32;
        *ring = (*ring & RING_ABOVE[k]) | (*ring & RING_BELOW[k]) << 32 | u128::from(chosen);
        chosen
    }
    fn slots_u128(ring: u128) -> [u32; 4] {
        [0, 1, 2, 3].map(|j| (ring >> (32 * j)) as u32)
    }
    let seeded: u128 = 1 << 32 | 2 << 64 | 3 << 96;
    assert_eq!(Ring::SEEDED.slots(), slots_u128(seeded));
    for k in 0..4 {
        let (mut wide, mut ring) = (seeded, Ring::SEEDED);
        assert_eq!(ring.take(k), take_u128(&mut wide, k), "k {k}");
        assert_eq!(ring.slots(), slots_u128(wide), "k {k}");
    }
    let mut rng = rarkit_testdata::Seeded::new(0x005c_a1a2_0917);
    let value = |rng: &mut rarkit_testdata::Seeded| match rng.below(8) {
        0 => 0,
        1 => u32::MAX,
        _ => rng.next_u64() as u32,
    };
    let mut steps = 0;
    for _ in 0..1_024 {
        let start = [0; 4].map(|_| value(&mut rng));
        let mut wide = start
            .iter()
            .rev()
            .fold(0u128, |acc, &s| acc << 32 | u128::from(s));
        let mut ring = Ring::from_slots(start);
        assert_eq!(ring.slots(), slots_u128(wide));
        for _ in 0..512 {
            if rng.chance(250) {
                let distance = value(&mut rng);
                ring.push(distance);
                wide = wide << 32 | u128::from(distance);
            } else {
                let k = rng.below(4) as usize;
                assert_eq!(ring.take(k), take_u128(&mut wide, k));
            }
            assert_eq!(ring.slots(), slots_u128(wide));
            steps += 1;
        }
    }
    assert_eq!(steps, 1_024 * 512);
}

/// THE SYMBOL PASS ON EVERY VECTOR ARCHIVE: the whole decode with the pass
/// forced on and forced off gives the same bytes, and a damaged member
/// stops with the same error and the same bytes either way.
#[cfg(all(feature = "repo-tests", feature = "test-support"))]
#[test]
fn the_symbol_pass_changes_no_byte_and_no_error_on_any_archive() {
    // The pass runs the tape lanes, and `probe::peak_lanes` is a process
    // wide high-water mark another test reads: hold its lock.
    let _counter = LANE_COUNTER.lock().unwrap_or_else(|e| e.into_inner());
    use super::symbols::{set_dial, GATHERED};
    let gathered_before = GATHERED.with(|g| g.get());
    for stem in ARCHIVES {
        let data = archive(stem);
        set_dial(Some(false));
        let off = decode_archive(&data, true);
        set_dial(Some(true));
        let on = decode_archive(&data, true);
        set_dial(None);
        eprintln!(
            "{stem}: {} blocks gathered so far",
            GATHERED.with(|g| g.get()) - gathered_before
        );
        assert_eq!(off.len(), on.len(), "{stem}");
        for (a, b) in off.iter().zip(&on) {
            assert_eq!(a.0, b.0, "{stem}: member order");
            assert!(a.1 == b.1, "{stem}/{}: bytes", a.0);
        }
    }
    assert!(
        GATHERED.with(|g| g.get()) > gathered_before,
        "no vector archive reached the symbol pass: this test would be vacuous"
    );
    let data = archive("h5_text_m5");
    let member = members(&data)
        .into_iter()
        .find(|m| m.method != 0)
        .expect("a compressed member");
    for byte in (0..member.packed.len().min(4096)).step_by(13) {
        let mut packed = member.packed.clone();
        packed[byte] ^= 1 << 5;
        let mut runs = Vec::new();
        for on in [false, true] {
            set_dial(Some(on));
            let mut lz = Rar5Lz::new(member.window, &policy()).unwrap();
            lz.set_parallel(true);
            let mut sink: Vec<u8> = Vec::new();
            let mut source = SliceSource::new(&packed);
            let outcome = lz.member(&mut source, member.unpacked, member.algorithm, &mut sink);
            runs.push((outcome.map_err(|e| format!("{:?}", e.kind())), sink));
        }
        set_dial(None);
        assert_eq!(runs[0].0, runs[1].0, "byte {byte}: error kind");
        assert!(runs[0].1 == runs[1].1, "byte {byte}: output");
    }
}

/// THE WIDE GATHER ON REAL MEMBERS, at 256 KiB and 512 KiB:
/// the pass forced on gives
/// exactly the walk's bytes, takes BOTH the fixed view and direct
/// borrowing (counted, so the test cannot pass by never reaching them),
/// and a damaged copy stops with the same error and the same bytes either
/// way.
#[cfg(all(feature = "parallel", feature = "test-support", feature = "repo-tests"))]
#[test]
fn the_wide_gather_takes_written_md256k_and_md512k_members_and_changes_no_byte() {
    let _counter = LANE_COUNTER.lock().unwrap_or_else(|e| e.into_inner());
    use super::output::WIDE_FORMS;
    use super::symbols::set_dial;
    for dictionary in [256u64 << 10, 512 << 10] {
        let data = written_text(4 << 20, dictionary);
        let member = members(&data)
            .into_iter()
            .find(|m| m.method != 0)
            .expect("a compressed member");
        assert_eq!(member.window, dictionary, "the member's declared window");
        let decode = |packed: &[u8], on: bool| {
            set_dial(Some(on));
            let mut lz = Rar5Lz::new(member.window, &policy()).unwrap();
            lz.set_parallel(true);
            let mut sink: Vec<u8> = Vec::new();
            let mut source = SliceSource::new(packed);
            let outcome = lz.member(&mut source, member.unpacked, member.algorithm, &mut sink);
            set_dial(None);
            (outcome.map_err(|e| format!("{:?}", e.kind())), sink)
        };
        let off = decode(&member.packed, false);
        let before = WIDE_FORMS.with(|c| c.get());
        let on = decode(&member.packed, true);
        let after = WIDE_FORMS.with(|c| c.get());
        let (views, direct) = (after.0 - before.0, after.1 - before.1);
        assert!(off.0.is_ok(), "the member decodes: {:?}", off.0);
        assert_eq!(off.0, on.0);
        assert!(
            off.1 == on.1,
            "{dictionary}: the bytes differ with the pass on"
        );
        eprintln!("written {dictionary} member: {views} fixed view runs, {direct} direct runs");
        assert!(views > 0, "{dictionary}: the fixed view never ran");
        assert!(direct > 0, "{dictionary}: direct borrowing never ran");
        for byte in (0..member.packed.len()).step_by(member.packed.len() / 11 + 1) {
            let mut packed = member.packed.clone();
            packed[byte] ^= 1 << 3;
            let off = decode(&packed, false);
            let on = decode(&packed, true);
            assert_eq!(off.0, on.0, "{dictionary}, byte {byte}: error kind");
            assert!(off.1 == on.1, "{dictionary}, byte {byte}: output");
        }
    }
}

/// A PRE-EXISTING DRAIN LAP in the SHIPPED WALK, found by the symbol pass's
/// differential and reproduced here with the walk alone (no symbol pass):
/// a filter span emitted in the middle of a drain batch leaves the rest of
/// the batch unemitted (`ready < emit_batch`), the next drain is a whole
/// batch later, and a literal run's checked path writes a whole
/// `drain_batch` chunk past a budget of one byte. With a ring of two
/// batches (dictionary at most 2 MiB; here 128 KiB, ring 1,048,576, batch
/// 524,288, since the ring floor counts its spill) about three batches sit
/// unemitted: `Window::drain`'s lap
/// assertion fires in a test build, and a release build emits lapped bytes.
///
/// Un-ignored by the fix:
/// a remainder left in the ring now brings the next drain forward. The
/// same lap across the dictionary ladder is
/// `a_filtered_member_never_laps_the_ring_at_the_tape_walks_cadence`.
#[cfg(feature = "parallel")]
#[test]
fn a_filter_span_emitted_mid_batch_then_a_long_literal_run_laps_the_ring() {
    use super::filters::{FilterKind, Filters, RawRecord};
    use super::output::Window;
    use super::tape::{self, tape_kind, BlockTape, TapeOp};
    let mut window = Window::new(128 << 10, u64::MAX).unwrap();
    window.reset();
    window.begin_member();
    assert_eq!(window.ring_bytes(), 1_048_576);
    assert_eq!(window.drain_batch(), 524_288);
    let runs = [524_288usize, 524_287, 600_000];
    let mut tape = BlockTape::default();
    tape.records.push(RawRecord {
        offset: 100,
        length: 100,
        kind: FilterKind::Delta(1),
    });
    tape.steps.push(TapeOp::new(tape_kind::FILTER, 0, 0));
    let mut literals = Vec::new();
    for (i, &run) in runs.iter().enumerate() {
        literals.extend((0..run).map(|k| (k as u8) ^ (i as u8 * 85)));
        super::tape::flush_run(&mut tape.steps, run);
    }
    tape.verbatim = literals.clone();
    tape.verbatim
        .resize(literals.len() + super::output::STRIDE_MAX, 0);
    let mut state = super::MatchState::default();
    let mut filters = Filters::default();
    let mut sink: Vec<u8> = Vec::new();
    let unpacked = literals.len() as u64;
    tape::apply(
        &tape,
        &mut state,
        &mut window,
        &mut filters,
        unpacked,
        &mut sink,
    )
    .unwrap();
    window.drain(&mut sink, &mut filters, true).unwrap();
    assert_eq!(sink.len(), literals.len());
    // Outside the filtered span the member is its literals, byte for byte.
    assert!(
        sink[200..] == literals[200..],
        "the drain emitted lapped bytes"
    );
}

/// THE DRAIN NEVER LETS THE RING LAP A BYTE THAT HAS NOT LEFT IT, on a
/// filtered member, at every ring size a dictionary can give.
///
/// Found in the md128k work on 23 Sep 2026 under the shipped walk: a span
/// emitted in the middle of a drain batch left the rest of the batch in
/// the ring (less than a batch, so not emitted), the next drain was set a
/// whole batch after the bytes PRODUCED rather than after the bytes that
/// had LEFT, and the tape walk's checked arm writes a whole `drain_batch`
/// chunk before its due test. In a ring of two batches (every dictionary
/// up to 2 MiB) about three batches then sat unemitted: a test build
/// tripped the drain's lap assertion and a release build emitted lapped
/// bytes. The handed (offload) drain has the same hole on a ring of four
/// batches: a span still open at one drain keeps its bytes in the ring
/// for two more.
///
/// The ladder runs from the smallest ring a dictionary can have (a stated
/// 128 KiB budget) through 2 MiB and one step above, with the span in the
/// middle of a batch, ending at a batch edge, straddling one, and open
/// across a drain; every case must equal the member written into a ring
/// that cannot lap.
#[test]
fn a_filtered_member_never_laps_the_ring_at_the_tape_walks_cadence() {
    use super::filters::FilterKind;
    use super::output::lap::{walk, Step, LADDER};
    use Step::Lits;
    let delta = |offset: u64, length: usize| Step::Filter {
        offset,
        length,
        kind: FilterKind::Delta(1),
    };

    let mut failures = Vec::new();
    for (dictionary, ceiling) in LADDER {
        let probe = super::output::Window::new(dictionary, ceiling).unwrap();
        let (ring, b) = (probe.ring_bytes(), probe.drain_batch());
        let open = super::filters::MAX_FILTER_BLOCK_LENGTH;
        let shapes: Vec<(&str, Vec<Step>)> = vec![
            (
                "the md128k lane's shape: a span mid-batch, then runs of b, b - 1 and past the ring",
                vec![delta(100, 100), Lits(b), Lits(b - 1), Lits(ring + b / 7)],
            ),
            (
                "a held remainder one byte under a batch, then one run of exactly a chunk",
                vec![delta(0, 1), Lits(b), Lits(b - 1), Lits(b), Lits(b / 3)],
            ),
            (
                "a span ending exactly at the batch edge",
                vec![delta(b as u64 - 100, 100), Lits(b), Lits(b - 1), Lits(2 * b)],
            ),
            (
                "a span straddling the batch edge",
                vec![delta(b as u64 - 50, 100), Lits(b), Lits(b - 1), Lits(2 * b)],
            ),
            (
                "a span open across a drain, then two chunk-wide overshoots",
                vec![
                    delta((b as u64).saturating_sub(200_000), open),
                    Lits(b),
                    Lits(b - 1),
                    Lits(b),
                    Lits(b - 1),
                    Lits(b),
                    Lits(b / 5),
                ],
            ),
            (
                "short runs only, with spans every so often",
                (0..400)
                    .flat_map(|k| {
                        let run = Lits(1 + (k * 7_919) % 9_000);
                        if k % 37 == 5 {
                            vec![delta((k % 3) as u64 * 1_000, 3_000), run]
                        } else {
                            vec![run]
                        }
                    })
                    .collect(),
            ),
        ];
        for (what, steps) in &shapes {
            let want = walk(dictionary, ceiling, false, steps, true).unwrap();
            for offload in [false, true] {
                let got = std::panic::catch_unwind(|| {
                    walk(dictionary, ceiling, offload, steps, false).unwrap()
                });
                let ok = matches!(&got, Ok(bytes) if *bytes == want);
                if !ok {
                    failures.push(format!(
                        "dictionary {dictionary} (ring {ring}, batch {b}), offload {offload}: {what}: {}",
                        if got.is_err() { "panicked" } else { "wrong bytes" }
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "the ring lapped unemitted bytes:\n{}",
        failures.join("\n")
    );
}

/// THE LONGEST SPAN THAT RUNS, at every rung, on both drain arms (SPEC-H2
/// 3.6, "Long records", rule 4, of 28 Sep 2026).
///
/// A kept record shorter than `W = max(D, 256 KiB)` runs over its whole
/// span, so at a 4 MiB dictionary a span of `0x3fffff` bytes, as long as
/// the ring itself, is legal. Until 28 Sep every span was at most
/// `0x3ffff` and the transform offload left a span still open at a drain
/// in the RING, on the argument that it was at most "two batches and a
/// span old"; a span as long as the ring breaks that argument, and the
/// offload must hand such a span to the hold instead. Every case must equal
/// the member written into a ring that cannot lap.
#[test]
fn the_longest_span_that_runs_never_laps_the_ring() {
    use super::filters::{FilterKind, IGNORED_ABOVE, MIN_SPAN_BOUND};
    use super::output::lap::{walk, Step, LADDER};
    use Step::Lits;
    let delta = |offset: u64, length: usize| Step::Filter {
        offset,
        length,
        kind: FilterKind::Delta(3),
    };
    let x86 = |offset: u64, length: usize| Step::Filter {
        offset,
        length,
        kind: FilterKind::X86Call,
    };

    let mut rungs = LADDER.to_vec();
    rungs.push((8 << 20, u64::MAX));
    let mut failures = Vec::new();
    for (dictionary, ceiling) in rungs {
        let probe = super::output::Window::new(dictionary, ceiling).unwrap();
        let (ring, b) = (probe.ring_bytes(), probe.drain_batch());
        let longest = (dictionary.max(MIN_SPAN_BOUND) - 1).min(IGNORED_ABOVE as u64) as usize;
        let shapes: Vec<(&str, Vec<Step>)> = vec![
            (
                "the longest span, from the member's first byte",
                vec![delta(0, longest), Lits(longest + ring / 3), Lits(b)],
            ),
            (
                "the longest span, open across a drain",
                vec![
                    Lits(b - 7),
                    x86(100, longest),
                    Lits(b),
                    Lits(longest),
                    Lits(b / 3),
                ],
            ),
            (
                "a short span, then the longest, then a short one after it",
                vec![
                    delta(10, 1_000),
                    delta(2_000, longest),
                    Lits(longest + 3_000),
                    delta(5, 900),
                    Lits(b + 2_000),
                ],
            ),
            (
                "the longest span starting 0x50000 bytes ahead",
                vec![delta(0x5_0000, longest), Lits(0x5_0000 + longest + b)],
            ),
        ];
        for (what, steps) in &shapes {
            let want = walk(dictionary, ceiling, false, steps, true).unwrap();
            for offload in [false, true] {
                let got = std::panic::catch_unwind(|| {
                    walk(dictionary, ceiling, offload, steps, false).unwrap()
                });
                let ok = matches!(&got, Ok(bytes) if *bytes == want);
                if !ok {
                    failures.push(format!(
                        "dictionary {dictionary} (ring {ring}, batch {b}, span {longest:#x}), offload {offload}: {what}: {}",
                        if got.is_err() { "panicked" } else { "wrong bytes" }
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "a long span went wrong:\n{}",
        failures.join("\n")
    );
}

/// The same lap, reached by a real RAR 5 stream through the decoder, on
/// the serial walk and on the tape walk.
///
/// The member is blocks of `BLOCK` literals, each a whole tape operation
/// under this build's shrunken tape caps, so the tape walk's drains fall
/// `over` bytes past the cadence (the operation that does not fit the
/// budget is written whole), and one match of distance 1 sits just short
/// of the second drain point, which is where the serial walk overshoots.
/// A delta span is placed where each walk's remainder is largest: ending
/// just past the tape walk's first drain overshoot, and in the member's
/// first two bytes for the serial one; a third ends exactly on the batch
/// edge. Every member must be its literals with the span delta decoded.
#[test]
fn a_filtered_stream_never_laps_the_ring_on_either_walk() {
    use super::ladders::length_from_slot;
    use super::output::Window;

    const BLOCK: usize = 16_000;
    let mut failures = Vec::new();
    for (dictionary, ceiling) in [
        (128u64 << 10, 128u64 << 10),
        (128 << 10, 1 << 33),
        (2 << 20, 1 << 33),
    ] {
        let probe = Window::new(dictionary, ceiling).unwrap();
        let (ring, b) = (probe.ring_bytes(), probe.drain_batch());
        let over = b.div_ceil(BLOCK) * BLOCK - b;
        assert!(
            over > 128,
            "the block size puts the tape walk's drain past the cadence"
        );
        let length_slot = 28;
        let match_length = length_from_slot(length_slot, 0);
        let match_at = 2 * b - 10;
        let total = ring * 3 + 12_345;
        let spans = [
            (
                "past the tape walk's first overshoot",
                over + over / 2 - 100,
                100usize,
            ),
            ("the member's first two bytes", 0, 2),
            ("ending on the batch edge", b - 100, 100),
        ];
        for (what, span_at, span_len) in spans {
            let mut raw: Vec<u8> = Vec::with_capacity(total);
            let mut blocks: Vec<Vec<u8>> = Vec::new();
            let mut block = BlockBuilder::default();
            block.filter(span_at as u32, span_len as u32, 0, 1);
            let literals = super::output::lap::run(dictionary as usize ^ span_at, total);
            let mut in_block = 0usize;
            while raw.len() < total {
                if raw.len() == match_at {
                    block.fresh(length_slot, 0, 0, 0);
                    let last = *raw.last().unwrap();
                    raw.extend(std::iter::repeat_n(last, match_length));
                    in_block += match_length;
                } else {
                    let byte = literals[raw.len()];
                    block.literal(byte);
                    raw.push(byte);
                    in_block += 1;
                }
                if in_block >= BLOCK || raw.len() >= total {
                    blocks.push(block.finish(true, raw.len() >= total));
                    block = BlockBuilder::default();
                    in_block = 0;
                }
            }
            let mut want = raw.clone();
            let mut previous = 0u8;
            for at in span_at..span_at + span_len {
                previous = previous.wrapping_sub(raw[at]);
                want[at] = previous;
            }
            let mut packed = Vec::new();
            for block in &blocks {
                packed.extend_from_slice(block);
            }
            let policy = MemoryPolicy {
                max_window: ceiling,
                ..policy()
            };
            for parallel in [false, true] {
                let got = std::panic::catch_unwind(|| {
                    let mut lz = Lz::new(dictionary, &policy).unwrap();
                    lz.set_parallel(parallel);
                    let mut sink: Vec<u8> = Vec::new();
                    let mut source = SliceSource::new(&packed);
                    lz.member(&mut source, raw.len() as u64, 0, &mut sink)
                        .unwrap();
                    sink
                });
                match got {
                    Ok(bytes) if bytes == want => {}
                    Ok(_) => failures.push(format!(
                        "dictionary {dictionary} (ring {ring}, batch {b}), parallel {parallel}, {what}: wrong bytes"
                    )),
                    Err(_) => failures.push(format!(
                        "dictionary {dictionary} (ring {ring}, batch {b}), parallel {parallel}, {what}: panicked"
                    )),
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "the ring lapped unemitted bytes:\n{}",
        failures.join("\n")
    );
}

/// The fuzz seam `fuzz:rar5_drain_lap` over a spread of scripts, ten on
/// every rung of the ladder, both offload arms: what the fuzzer runs, run
/// here without it, so the seam cannot rot between campaigns. At an
/// earlier revision about one script in five on a ring of two batches lapped (63
/// of 300 in a sweep of sixty per rung, none on the rings of three and
/// four batches); none does with the fix.
#[test]
fn the_drain_lap_fuzz_seam_agrees_over_seeded_scripts() {
    use super::output::lap::{agrees, LADDER};
    for seed in 0u32..10 * LADDER.len() as u32 {
        let rung = (seed as usize % LADDER.len()) as u8;
        let script: Vec<u8> = [rung, (seed / 7) as u8]
            .into_iter()
            .chain(seed.wrapping_mul(0x9E37_79B1).to_le_bytes())
            .collect();
        assert!(agrees(&script) > 0, "seed {seed}: the member is empty");
    }
}
