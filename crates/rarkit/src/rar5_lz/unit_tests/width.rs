//! The width a leg NAMES is the width that runs (section 3.8, API 8.4.2).

use super::*;

/// Material an `-m3` member can hold: about half of it compresses and
/// half does not, so the block chain keeps growing and there are blocks
/// enough to spread over lanes. A single repeated byte gives a chain of
/// one block, which takes no lane at any width.
#[cfg(all(feature = "parallel", feature = "repo-tests"))]
fn spreadable(bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes);
    let mut seed = 0x2026_0921u64;
    while out.len() < bytes {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let run = 16 + (seed >> 59) as usize;
        if seed & 0x10 == 0 {
            out.extend(std::iter::repeat_n(
                b"the quick brown fox "[out.len() % 20],
                run,
            ));
        } else {
            out.extend((0..run).map(|i| (seed >> (i % 40)) as u8));
        }
    }
    out.truncate(bytes);
    out
}

/// THE CANARY THIS SEAM LOST ONCE AND MUST NOT LOSE AGAIN.
///
/// Until 21 Sep 2026 both `scheduled` helpers - this file's and
/// `internals_h2`'s, which the `rar5_wave_overlap_w2`, `_w4`, `_w8`,
/// `rar5_code_wave_overlap_w4`, `rar5_text_64m_m3_w4` and
/// `rar5_code_32m_m3_w4` bench legs come through - put `max_workers` in a
/// `MemoryPolicy` and nothing else. `Rar5Lz::new` has not read a worker
/// count out of the policy since an earlier revision (a memory budget is not a
/// thread count, API 8.4.2), so every one of those legs ran at the
/// ENGINE'S DEFAULT width whatever its name said, and a sweep over
/// widths compared a number with itself. Nothing published was wrong,
/// because the legs had not been printed since; what was wrong was that
/// nothing would have noticed.
///
/// So this asserts the property rather than the line: at a named width
/// the decode spreads over AT MOST that many lanes, and at a wide one it
/// genuinely spreads. The member is 24 MiB, which is blocks enough to
/// spread at any width this fleet has.
///
/// The two readings are taken the two robust ways round, because
/// `peak_lanes` is a process-wide high-water mark: the CEILING is the
/// MINIMUM over repeated runs, so another test's lanes leaking in cannot
/// fail it, and the FLOOR is the maximum, so one unlucky run where the
/// lanes never overlapped in time cannot fail it either.
#[cfg(all(feature = "parallel", feature = "repo-tests"))]
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn the_named_width_is_the_width_that_runs() {
    let _counter = LANE_COUNTER.lock().unwrap_or_else(|e| e.into_inner());
    let body = spreadable(24 << 20);
    let dictionary = 4u32 << 20;
    let packed = crate::internals_h3::rar5_encode(&body, 3, dictionary);
    let mut narrow = Vec::new();
    let mut wide = Vec::new();
    for _ in 0..3 {
        for (width, seen) in [(1usize, &mut narrow), (8usize, &mut wide)] {
            crate::probe::reset_peak_lanes();
            let (out, failure) = crate::internals_h2::decode_member_probe_scheduled(
                &packed,
                body.len() as u64,
                u64::from(dictionary),
                0,
                width,
                None,
                true,
            );
            assert_eq!(failure, None, "at width {width}");
            assert_eq!(out, body, "at width {width}");
            seen.push(crate::probe::peak_lanes());
        }
    }
    let ceiling = |seen: &[usize]| *seen.iter().min().expect("three runs");
    let floor = |seen: &[usize]| *seen.iter().max().expect("three runs");
    assert!(
        ceiling(&narrow) <= 1,
        "a width of one spread over {narrow:?} lanes: the seam is not setting the width"
    );
    assert!(
        ceiling(&wide) <= 8,
        "a width of eight spread over {wide:?} lanes"
    );
    assert!(
        floor(&wide) >= 2,
        "a width of eight never spread at all ({wide:?}): the canary would pass vacuously"
    );
}

/// Run one chain of hand built blocks down BOTH arms and answer what each
/// produced, so a test can assert section 3.8 consequence 2 directly: the
/// member stops at its declared size at the same OPERATION, with the same
/// bytes and the same fault, whichever arm decoded the block.
/// **WHY A TAPE LANE CANNOT WRITE ITS LITERAL RUNS STRAIGHT INTO THE
/// RING**, shown rather than derived (SPEC-H2 sections 3.7 and 4.2's
/// erratum; 21 Sep 2026).
///
/// The ring is the declared dictionary plus [`SPILL`] slots, so the slots
/// just ahead of the write point hold the OLDEST live bytes of the
/// stream: writing member position `P` destroys stream position
/// `P - ring_len`. With the apply point at `Q`, a match may name any
/// distance up to the dictionary, so that byte is still READABLE exactly
/// when `ring_len - (P - Q) <= limit`, which is `P - Q >= SPILL`.
///
/// So the room ahead of the apply point is the margin and nothing more -
/// [`SPILL`] `- 1` bytes - at EVERY dictionary size, which is why the
/// direction is closed by the window's shape and not by the small
/// dictionary that first showed it. This walks the boundary from both
/// sides:
///
/// - a write `SPILL - 1` ahead is unobservable, because the only distance
///   that names it is one past the declared window and `copy_match`
///   refuses it;
/// - a write `SPILL` ahead is read by a match at a distance of exactly
///   the declared window, which is legal, and the wrong byte comes out
///   with no error raised. That is the 19 Sep window edge defect's class
///   arriving from the other direction.
#[test]
fn the_room_ahead_of_the_apply_point_is_the_spill_margin_and_no_more() {
    // AT OR ABOVE THE RING FLOOR, which is where the bound BINDS. Below
    // the floor the ring is longer than the dictionary by more than
    // `SPILL`, so the room ahead is larger there and this test would be
    // demonstrating a weaker statement; the case that closes the direction
    // is the one where the ring is the dictionary plus the margin and
    // nothing else, and that is every dictionary from `RING_FLOOR` up.
    // `the_room_ahead_below_the_ring_floor_is_the_floors_slack` states the
    // other half.
    for window in [RING_FLOOR as u64, 1 << 21, 1 << 22] {
        let dictionary = window as usize;
        let ring_len = dictionary + SPILL;
        // Past one whole lap, so the slots ahead of the write point hold
        // live history rather than the zeroed allocation.
        let seed: Vec<u8> = (0..ring_len + ring_len / 4)
            .map(|i| (i * 31 + i / 7) as u8 | 1)
            .collect();

        // 1. THE ARITHMETIC, as an executable statement: the distance that
        //    names the slot `ahead` past the write point is
        //    `ring_len - ahead`, and it is acceptable exactly from
        //    `SPILL` on.
        for ahead in 1..=SPILL + 8 {
            let distance = ring_len - ahead;
            assert_eq!(
                distance <= dictionary,
                ahead >= SPILL,
                "window {window}, {ahead} ahead: the margin is not SPILL"
            );
        }

        // 2. `SPILL - 1` AHEAD IS UNOBSERVABLE: no distance the decoder
        //    accepts can name it.
        let mut win = Window::new(window, u64::MAX).unwrap();
        win.begin_member();
        assert_eq!(win.limit_for_test(), dictionary);
        let mut sink: Vec<u8> = Vec::new();
        let mut filters = NoFilters;
        win.literals_chunked(&seed, &mut sink, &mut filters);
        win.drain(&mut sink, &mut filters, true).unwrap();
        let ahead = SPILL - 1;
        // What a lane would write there: even and not zero, where every
        // seed byte is odd. A match at the one distance that names the
        // slot is past the window, so it gives a ZERO (section 3.7) and
        // reads neither the lane's write nor the history.
        win.poke_ahead_for_test(ahead, 0xa4);
        assert!(
            !win.admits_reach(ring_len - ahead),
            "window {window}: a lane's write {ahead} ahead is reachable"
        );
        win.copy_match(ring_len - ahead, 1)
            .expect("a distance past the window is no fault");
        win.drain(&mut sink, &mut filters, true).unwrap();
        assert_eq!(
            *sink.last().expect("a byte was produced"),
            0,
            "window {window}: a lane's write {ahead} ahead was READ"
        );

        // 3. `SPILL` AHEAD IS READ, at a distance of exactly the declared
        //    window, and the wrong byte leaves the decoder in silence.
        let mut win = Window::new(window, u64::MAX).unwrap();
        win.begin_member();
        let mut sink: Vec<u8> = Vec::new();
        let mut filters = NoFilters;
        win.literals_chunked(&seed, &mut sink, &mut filters);
        win.drain(&mut sink, &mut filters, true).unwrap();
        let history = win.peek_ahead_for_test(SPILL);
        // What a lane would write there; `| 1` above keeps every seed
        // byte odd, so zero is a byte the history cannot hold.
        win.poke_ahead_for_test(SPILL, 0);
        assert_ne!(history, 0, "the poke has to differ from the history");
        win.copy_match(dictionary, 1)
            .expect("a distance of exactly the declared window is legal");
        win.drain(&mut sink, &mut filters, true).unwrap();
        assert_eq!(
            *sink.last().expect("a byte was produced"),
            0,
            "window {window}: the match did NOT read the lane's write, so \
             this test no longer demonstrates anything"
        );
        // And it is silent: no error, and the byte the stream should have
        // produced is gone.
        assert_ne!(*sink.last().unwrap(), history);
    }
}

/// THE FLOOR IS A RING SIZE AND NOT A WINDOW SIZE, which is the one
/// mistake this change invites and the one that would corrupt output.
///
/// [`RING_FLOOR`] makes the ring longer than a small declared dictionary.
/// The dictionary is what bounds a distance (SPEC-H2 3.7 and 4.1's last
/// row), so if a later edit ever sizes `limit` from the ring instead, the
/// decoder would ACCEPT a distance the format refuses and read a slot that
/// holds no history of this stream - silently, because a longer ring makes
/// that slot readable rather than absent. This pins both halves: the ring
/// grew, and not one distance changed its legality.
#[test]
fn the_ring_floor_moves_no_distance_and_no_byte() {
    for window in [128u64 << 10, 256 << 10, 512 << 10] {
        // The declared dictionary, or the format's own least reach where
        // that is more (section 3.7): what a match is honoured to.
        let dictionary = (window as usize).max(WINDOW_FLOOR);
        let mut win = Window::new(window, u64::MAX).unwrap();
        win.begin_member();

        // The ring took the floor, and the window did NOT.
        assert_eq!(
            win.ring_bytes(),
            RING_FLOOR,
            "window {window}: the ring did not take the floor"
        );
        assert_eq!(
            win.limit_for_test(),
            dictionary,
            "window {window}: the RING's floor reached the window, so a \
             distance the format gives zeros for would now be honoured"
        );

        // Past one lap of the RING, so every slot holds live history and a
        // distance is past the window rather than past the stream.
        let seed: Vec<u8> = (0..win.ring_bytes() + win.ring_bytes() / 4)
            .map(|i| (i * 17 + i / 5) as u8 | 1)
            .collect();
        let mut sink: Vec<u8> = Vec::new();
        let mut filters = NoFilters;
        win.literals_chunked(&seed, &mut sink, &mut filters);
        win.drain(&mut sink, &mut filters, true).unwrap();

        // Exactly the window is honoured, one past it gives a zero (every
        // seed byte is odd, so the history holds none), and the ring being
        // larger than both changes neither answer.
        assert!(win.admits_reach(dictionary) && !win.admits_reach(dictionary + 1));
        win.copy_match(dictionary, 1)
            .expect("a distance of exactly the window is honoured");
        win.drain(&mut sink, &mut filters, true).unwrap();
        assert_eq!(
            *sink.last().unwrap(),
            seed[seed.len() - dictionary],
            "window {window}: the byte at the window's edge"
        );
        win.copy_match(dictionary + 1, 1)
            .expect("one past the window is no fault");
        win.drain(&mut sink, &mut filters, true).unwrap();
        assert_eq!(
            *sink.last().unwrap(),
            0,
            "window {window}: one past the window was honoured"
        );
    }
}

/// The other half of `the_room_ahead_of_the_apply_point_is_the_spill_margin_and_no_more`,
/// recorded because [`RING_FLOOR`] CHANGED it and a later reader must not
/// take the older statement as still covering the small dictionaries.
///
/// The room ahead of the apply point is `ring_len - limit`, which is
/// [`SPILL`] exactly when the ring is the dictionary plus the margin. Below
/// the floor the ring is the floor, so the room is the floor's slack and it
/// is larger. That does NOT reopen the direction the write-in-place work
/// closed: the binding case is the dictionaries at or above the floor,
/// where the room is 63 bytes and a block's output is unbounded (section 8
/// item 1). It is written down so the two statements cannot be confused.
#[test]
fn the_room_ahead_below_the_ring_floor_is_the_floors_slack() {
    for window in [128u64 << 10, 512 << 10] {
        let dictionary = (window as usize).max(WINDOW_FLOOR);
        let win = Window::new(window, u64::MAX).unwrap();
        let room = win.ring_bytes() - win.limit_for_test();
        assert_eq!(
            room,
            RING_FLOOR - dictionary,
            "window {window}: the room ahead is not the floor's slack"
        );
        assert!(
            room > SPILL,
            "window {window}: below the floor the room must EXCEED the margin"
        );
    }
    // And at the floor and above, it is the margin and nothing more, which
    // is the statement that closes the direction.
    for window in [RING_FLOOR as u64, 1 << 22] {
        let win = Window::new(window, u64::MAX).unwrap();
        assert_eq!(win.ring_bytes() - win.limit_for_test(), SPILL);
    }
}

/// A STATED MEMORY BUDGET BEATS THE SPEED FLOOR, which is
/// API 8.4.1's hard ceiling rather than this package's preference.
///
/// [`RING_FLOOR`] buys wall by spending about a megabyte of ring on a
/// small dictionary. A caller who has actually said how much memory the
/// read may use has not agreed to that, and RAR 5's smallest dictionary is
/// 128 KiB, so a caller can legitimately set `max_window` to 128 KiB and
/// mean it. The floor is therefore capped by the ceiling: such a caller
/// gets the ring it allowed and the cold copy path back, which is the
/// trade it asked for.
///
/// `SPILL` and `MIN_RING` are NOT capped and must not be: they are
/// correctness margins, `SPILL` being what keeps a stride copy off the
/// window's oldest bytes (section 4.2's erratum) and `MIN_RING` what keeps
/// the drain cadence able to hold one operation. Section 4.2 puts the
/// margin outside `max_window` for exactly that reason.
#[test]
fn a_stated_window_budget_caps_the_ring_floor() {
    // A caller who stated a ceiling BELOW the speed floor does not get
    // the speed floor. What the ring still holds is the FORMAT's least
    // reach, 256 KiB whatever the header declares (section 3.7, as amended
    // on 11 Oct 2026), and the margin on top of it: neither is a speed
    // constant and neither is capped.
    let win = Window::new(128 << 10, 128 << 10).unwrap();
    assert_eq!(win.limit_for_test(), WINDOW_FLOOR);
    assert_eq!(
        win.ring_bytes(),
        WINDOW_FLOOR + SPILL,
        "the speed floor overrode a memory budget the caller stated"
    );
    // A ceiling between the two is under the speed floor as well: the
    // same ring.
    let win = Window::new(128 << 10, 256 << 10).unwrap();
    assert_eq!(win.ring_bytes(), WINDOW_FLOOR + SPILL);
    let win = Window::new(128 << 10, 512 << 10).unwrap();
    assert_eq!(win.ring_bytes(), 512 << 10);
    // A ceiling at or above the floor lets the floor do its work.
    let win = Window::new(128 << 10, RING_FLOOR as u64).unwrap();
    assert_eq!(win.ring_bytes(), RING_FLOOR);
    let win = Window::new(128 << 10, u64::MAX).unwrap();
    assert_eq!(win.ring_bytes(), RING_FLOOR);
    // Still at least the declared size plus the margin, for a dictionary
    // just under the floor.
    let win = Window::new((RING_FLOOR - 1) as u64, u64::MAX).unwrap();
    assert_eq!(win.ring_bytes(), RING_FLOOR - 1 + SPILL);
    // And the correctness margins survive a ceiling that would squeeze
    // them: the format's reach and `SPILL` are not the speed floor and
    // are not capped (`MIN_RING` is under the format's reach).
    let win = Window::new(1 << 10, 1 << 10).unwrap();
    assert_eq!(win.ring_bytes(), MIN_RING.max(WINDOW_FLOOR) + SPILL);
    assert_eq!(win.limit_for_test(), WINDOW_FLOOR);
}

/// THE FIXED WIDTH LITERAL STORE SPILLS INSIDE THE MARGIN, and the bytes
/// it spills are nobody's.
///
/// `Window::literals_padded` writes a constant width - [`STRIDE`] for a
/// short run and [`STRIDE_MAX`] for a long one - whatever the run's
/// length is, and pays for the bytes past the run's end out of the ring's
/// [`SPILL`] margin, exactly as `Window::copy_match`'s stride ladder
/// already does on the other arm of the apply loop. The margin is what
/// makes that safe, so the margin is what this holds it to:
///
/// 1. the WIDEST spill this can produce is `STRIDE_MAX - 1` bytes, for a
///    run of one byte on the wide arm, and `SPILL` is `STRIDE_MAX`. So
///    the arithmetic leaves exactly one byte of margin and no more, which
///    is the thing a later change would silently spend;
/// 2. a spilled slot is UNNAMEABLE: the only distance that reaches the
///    slot `j` ahead of the write point is `ring_len - j`, which is past
///    the declared window for every `j` below `SPILL`, and `copy_match`
///    gives a zero for it without reading the slot;
/// 3. the store writes the RUN correctly however far it spills, which is
///    the part an over-wide write would not break and a mis-indexed one
///    would.
///
/// It is written against the INVARIANT and not against the constants, so
/// it keeps meaning something if the ring is reshaped. SHOWN TO FAIL:
/// widening the narrow arm's store from `STRIDE` to `STRIDE + SPILL`
/// fails item 2 here, and fails the write side guard in
/// `Window::literals_padded` first, with the slot, the distance and the
/// section named.
#[test]
fn the_fixed_width_literal_store_spills_only_inside_the_margin() {
    // 1. THE ARITHMETIC, as an executable statement.
    const {
        assert!(
            STRIDE_MAX - 1 < SPILL,
            "the widest spill a one byte run can produce is STRIDE_MAX - 1, and it has to stay inside SPILL"
        );
        assert!(STRIDE <= STRIDE_MAX);
    }

    // AT OR ABOVE THE RING FLOOR, for the reason
    // `the_room_ahead_of_the_apply_point_is_the_spill_margin_and_no_more`
    // gives: below the floor the ring is longer than the dictionary by
    // more than `SPILL`, so the unnameable room is LARGER there and the
    // test would be demonstrating a weaker statement. The case that has
    // to hold is the tight one, where the ring is the dictionary plus the
    // margin and nothing else.
    for window in [RING_FLOOR as u64, 1 << 21, 1 << 22] {
        let dictionary = window as usize;
        let ring_len = dictionary + SPILL;
        // Past one whole lap, so the slots ahead of the write point hold
        // live history rather than the zeroed allocation. Every byte odd,
        // so the pad's zero is a byte the history cannot hold.
        let seed: Vec<u8> = (0..ring_len + ring_len / 4)
            .map(|i| (i * 31 + i / 7) as u8 | 1)
            .collect();

        for (count, width) in [(1usize, STRIDE), (STRIDE, STRIDE), (STRIDE + 1, STRIDE_MAX)] {
            let mut win = Window::new(window, u64::MAX).unwrap();
            win.begin_member();
            assert_eq!(win.ring_bytes(), ring_len, "the ring is not the tight one");
            let mut sink: Vec<u8> = Vec::new();
            let mut filters = NoFilters;
            win.literals_chunked(&seed, &mut sink, &mut filters);
            win.drain(&mut sink, &mut filters, true).unwrap();
            let before = win.produced();

            // A source of the run's bytes followed by a pad, which is what
            // the tape hands the apply stage. `2` is even, so it cannot be
            // mistaken for the history and cannot be mistaken for the pad.
            let mut source = vec![2u8; count];
            source.resize(count + STRIDE_MAX, 0);
            win.literals_padded(&source, count);

            // 3. The RUN landed, and the write point moved by the run and
            //    not by the width.
            assert_eq!(win.produced(), before + count as u64, "window {window}");
            win.drain(&mut sink, &mut filters, true).unwrap();
            assert_eq!(
                &sink[sink.len() - count..],
                &vec![2u8; count][..],
                "window {window}, run of {count}: the run itself is wrong"
            );

            // 2. Every slot the store may have spilled on is unnameable.
            //    `width - count` is how far past the run it wrote.
            //    Asked of the window without writing, so that every slot
            //    is asked from the same write point; then one match at the
            //    nearest of them, which gives a zero and not the pad's
            //    neighbour (section 3.7).
            for ahead in 1..width - count.min(width) + 1 {
                assert!(
                    !win.admits_reach(ring_len - ahead),
                    "window {window}, run of {count} at width {width}: the store's \
                     spill {ahead} ahead is REACHABLE"
                );
            }
            win.poke_ahead_for_test(1, 0xa4);
            win.copy_match(ring_len - 1, 1)
                .expect("a distance past the window is no fault");
            win.drain(&mut sink, &mut filters, true).unwrap();
            assert_eq!(*sink.last().unwrap(), 0, "window {window}, run of {count}");
        }
    }
}

/// THE TAPE'S LITERAL PAD HOLDS ON EVERY BLOCK OF EVERY ARCHIVE, which
/// is what the apply stage's fixed-width literal store is written
/// against.
///
/// `Window::literals_padded` reads `STRIDE_MAX` bytes from a run's start
/// whatever the run's length is, and the tape owes it that room. **If
/// the pad ever goes the failure is a PANIC on a valid archive**, not a
/// wrong byte: the slice is bounds-checked in release as well as in
/// debug, so a member that decodes today would abort instead, which is
/// the one thing section 4.3 says this package does not do.
///
/// The debug assertion inside `literals_padded` covers a test build.
/// This covers the case that assertion cannot see: a pad added in the
/// wrong PLACE - after an early return, say, or outside the park-and-
/// resume loop - which shows only on real streams with real block
/// boundaries.
#[cfg(feature = "repo-tests")]
#[test]
fn the_tapes_literal_pad_holds_on_every_block_of_every_archive() {
    use super::tape;

    let mut blocks = 0usize;
    for stem in ARCHIVES {
        let data = archive(stem);
        for member in members(&data) {
            if member.directory || member.method == 0 {
                continue;
            }
            let mut plan = tape::Plan::default();
            if tape::plan(&member.packed, false, &mut plan).is_err() {
                continue;
            }
            let mut tape = tape::BlockTape::default();
            for index in 0..plan.blocks.len() {
                tape::decode_one(
                    &plan,
                    &member.packed,
                    member.algorithm,
                    None,
                    index,
                    &mut tape,
                );
                assert!(
                    tape::literal_pad_holds(&tape),
                    "{stem}, member {}, block {index}: a literal run starts within \
                     STRIDE_MAX of the end of the tape's literal buffer, so the apply \
                     stage's fixed-width store would panic on this archive",
                    member.name
                );
                blocks += 1;
            }
        }
    }
    // A test that walked no block would pass silently and say nothing.
    // The figure is the vector corpus's own: 41 blocks across every
    // archive of section 5.2 when this was written, so the floor is set
    // below that and not at a round number nobody measured.
    assert!(blocks >= 40, "only {blocks} blocks walked");
}
