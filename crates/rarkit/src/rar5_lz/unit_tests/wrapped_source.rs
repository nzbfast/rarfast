//! THE WRAPPED SOURCE ON THE STRIDE COPY, and the far list beside it.

use super::*;

// ---------------------------------------------------------------------------
// THE WRAPPED SOURCE ON THE STRIDE COPY.
// `Window::copy_match` takes a
// source behind the ring's start down the stride copy unless it sits within
// `STRIDE_MAX` behind that start; the two tests below hold the bytes to the
// byte at a time reference at every boundary of that test, and the PATH to
// what the test says, because a fast path narrowed back to the slow one
// produces the same bytes and only the count can see it.
// ---------------------------------------------------------------------------

/// What `copy_match` must decide for a copy of `length` from `distance`
/// with the write point at ring index `at`: `true` for the stride copy.
fn wrap_fast_expected(at: usize, ring: usize, distance: usize, length: usize) -> bool {
    length <= STRIDE_MAX
        && distance >= STRIDE
        && (distance <= at || distance >= at + STRIDE_MAX)
        && at + STRIDE_MAX < ring
}

/// A window on a ring that CANNOT be longer than the declared dictionary
/// plus `SPILL` (the caller's budget caps the speed floor), filled past one
/// lap so every legal distance names live history, with its write point at
/// ring index `at`. The seed is returned as the reference's starting point.
fn lapped_window_at(at: usize) -> (Window, Vec<u8>, Vec<u8>) {
    let window = 128u64 << 10;
    let mut win = Window::new(window, window).unwrap();
    win.begin_member();
    let ring = win.ring_bytes();
    let seed: Vec<u8> = (0..ring + at)
        .map(|i| ((i as u32).wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect();
    let mut sink: Vec<u8> = Vec::new();
    let mut filters = NoFilters;
    win.literals_chunked(&seed, &mut sink, &mut filters);
    win.drain(&mut sink, &mut filters, true).unwrap();
    assert_eq!(
        win.at_for_test(),
        at,
        "the fill did not land the write point"
    );
    (win, sink, seed)
}

#[test]
fn a_wrapped_source_takes_the_stride_copy_byte_exact_at_every_edge() {
    let probe = Window::new(128 << 10, 128 << 10).unwrap();
    let ring = probe.ring_bytes();
    let limit = probe.limit_for_test();
    assert_eq!(ring, limit + SPILL, "this test wants the capped ring");
    let ats = [
        0usize,
        1,
        15,
        16,
        17,
        47,
        48,
        62,
        63,
        64,
        65,
        1_000,
        ring - 200,
        ring - 100,
        ring - 65,
        ring - 64,
    ];
    let lengths = [1usize, 2, 15, 16, 17, 33, 48, 63, 64, 65, 200];
    let (mut fast_wrapped, mut slow_wrapped) = (0u32, 0u32);
    for at in ats {
        let mut distances: Vec<usize> = [1usize, 15, 16, 17, 47, 48, 62, 63, 64, 65, 66, 1_000]
            .iter()
            .map(|k| at + k)
            .chain([16, 17, at.max(16), limit - 1, limit])
            .filter(|&d| (1..=limit).contains(&d))
            .collect();
        distances.sort_unstable();
        distances.dedup();
        for &distance in &distances {
            for &length in &lengths {
                let (mut win, mut sink, mut want) = lapped_window_at(at);
                let mut filters = NoFilters;
                win.copy_match(distance, length).unwrap();
                let slow = win.slow_copies_for_test();
                win.drain(&mut sink, &mut filters, true).unwrap();
                reference_copy(&mut want, distance, length);
                assert!(
                    sink == want,
                    "at {at}, distance {distance}, length {length}: wrong bytes"
                );
                let fast = wrap_fast_expected(at, ring, distance, length);
                assert_eq!(
                    slow,
                    u64::from(!fast),
                    "at {at}, distance {distance}, length {length}: the copy took the \
                     {} path where the fast test says {}",
                    if slow == 0 { "fast" } else { "slow" },
                    if fast { "fast" } else { "slow" }
                );
                if distance > at && fast {
                    fast_wrapped += 1;
                }
                if distance > at && !fast && length <= STRIDE_MAX {
                    slow_wrapped += 1;
                }
            }
        }
    }
    // Both sides of the edge were actually exercised.
    assert!(
        fast_wrapped > 100,
        "only {fast_wrapped} wrapped copies were fast"
    );
    assert!(
        slow_wrapped > 50,
        "only {slow_wrapped} short wrapped copies stayed slow"
    );
}

/// Distance one is a FILL in `copy_match_slow` (round 5): the byte before
/// the write point, one span a lap. At every write point around the ring's
/// end and start, including slot 0 where that byte is the ring's LAST, and
/// for lengths that end short of the ring's end, end on it and cross it, up
/// to the longest match the format has (4,100 bytes; a longer copy would
/// overwrite its own readable history, which the debug spill watch
/// refuses), the bytes against the byte at a time reference, and the slow
/// copy counted once a call whatever the spans.
#[test]
fn distance_one_fills_byte_exact_across_every_lap_edge() {
    let ring = Window::new(128 << 10, 128 << 10).unwrap().ring_bytes();
    for at in [
        0usize,
        1,
        2,
        63,
        64,
        1_000,
        ring - 4_000,
        ring - 65,
        ring - 64,
        ring - 2,
        ring - 1,
    ] {
        for length in [
            1usize,
            2,
            ring - at - 1,
            ring - at,
            ring - at + 1,
            ring - at + 64,
            4_100,
        ] {
            if length == 0 || length > 4_100 {
                continue;
            }
            let (mut win, mut sink, mut want) = lapped_window_at(at);
            let mut filters = NoFilters;
            let before = win.slow_copies_for_test();
            win.copy_match(1, length).unwrap();
            assert_eq!(
                win.slow_copies_for_test() - before,
                1,
                "at {at}, length {length}: distance one is one slow call"
            );
            win.drain(&mut sink, &mut filters, true).unwrap();
            reference_copy(&mut want, 1, length);
            assert!(sink == want, "at {at}, length {length}: wrong bytes");
            // A later match reads what the fill left in the ring.
            win.copy_match(4_000, 300).unwrap();
            win.drain(&mut sink, &mut filters, true).unwrap();
            reference_copy(&mut want, 4_000, 300);
            assert!(sink == want, "at {at}, length {length}: the history after");
        }
    }
}

/// A seeded walk of copies on the capped ring, with the distance drawn half
/// the time from just around the ring's start (where the wrap test lives)
/// and otherwise from the whole window, the lengths from 1 to 80 across
/// every stride boundary; every byte against the byte at a time reference.
#[test]
fn a_seeded_walk_near_the_ring_start_matches_the_byte_at_a_time_reference() {
    let window = 128u64 << 10;
    for seed_value in [1u64, 7, 0x5EED, 0xDEAD_BEEF] {
        let mut win = Window::new(window, window).unwrap();
        win.begin_member();
        let ring = win.ring_bytes();
        let limit = win.limit_for_test();
        let mut rng = seed_value;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let seed: Vec<u8> = (0..ring + ring / 3).map(|_| next() as u8).collect();
        let mut sink: Vec<u8> = Vec::new();
        let mut filters = NoFilters;
        win.literals_chunked(&seed, &mut sink, &mut filters);
        win.drain(&mut sink, &mut filters, true).unwrap();
        let mut want = seed;
        let mut checked = sink.len();
        sink.clear();
        let (mut wrapped, mut fast_wrapped) = (0u32, 0u32);
        for step in 0..60_000u32 {
            let at = win.at_for_test();
            let length = 1 + (next() % 80) as usize;
            let distance = if next() % 2 == 0 {
                // Around the ring's start: behind it by up to 160 bytes,
                // or in front of it by up to 160.
                let k = (next() % 320) as usize;
                (at + k).saturating_sub(160).clamp(1, limit)
            } else {
                1 + (next() % limit as u64) as usize
            };
            let slow_before = win.slow_copies_for_test();
            win.copy_match(distance, length).unwrap();
            let took_fast = win.slow_copies_for_test() == slow_before;
            assert_eq!(
                took_fast,
                wrap_fast_expected(at, ring, distance, length),
                "seed {seed_value} step {step}: at {at}, distance {distance}, length {length}"
            );
            if distance > at {
                wrapped += 1;
                fast_wrapped += u32::from(took_fast);
            }
            reference_copy(&mut want, distance, length);
            if win.drain_due() || step % 4_096 == 0 {
                win.drain(&mut sink, &mut filters, true).unwrap();
                assert!(
                    sink[..] == want[checked..checked + sink.len()],
                    "seed {seed_value} step {step}: wrong bytes"
                );
                checked += sink.len();
                sink.clear();
            }
        }
        win.drain(&mut sink, &mut filters, true).unwrap();
        assert!(
            sink[..] == want[checked..],
            "seed {seed_value}: wrong bytes at the end"
        );
        assert!(
            wrapped > 1_000 && fast_wrapped > 500,
            "seed {seed_value}: {wrapped} wrapped, {fast_wrapped} fast"
        );
    }
}

/// THE DENSE HINT STREAM AS ITS SPECIFICATION WRITES IT: one BACK an operation, in
/// operation order. A fresh match of the tape reaching
/// `Window::FAR_GATE_DISTANCE` or further has its distance less the tape
/// length from the start of the chunk before its own to it (chunks of
/// `chunk` operations, the first chunk's counted from the tape's start);
/// every other operation has zero. `distances` lists the far matches'
/// distances, for the tests that count them. The lane's stream and the
/// listed walk are held to this.
#[cfg(feature = "parallel")]
struct FarSpec {
    backs: Vec<u32>,
    distances: Vec<u32>,
    far: Vec<bool>,
}

#[cfg(feature = "parallel")]
fn far_list_of(ops: &[super::tape::TapeOp], chunk: usize) -> FarSpec {
    use super::tape::tape_kind;
    // The tape length before every operation, and so before every chunk.
    let mut prefix = vec![0usize];
    for op in ops {
        prefix.push(prefix.last().unwrap() + op.bytes());
    }
    let mut spec = FarSpec {
        backs: Vec::new(),
        distances: Vec::new(),
        far: Vec::new(),
    };
    for (index, op) in ops.iter().enumerate() {
        let far = op.distance as usize >= Window::FAR_GATE_DISTANCE;
        // Only a fresh match carries a distance this large.
        assert!(
            !far || op.kind() == tape_kind::MATCH,
            "a far op is a fresh match"
        );
        spec.far.push(far);
        if far {
            let group = index / chunk;
            let from = prefix[group.saturating_sub(1) * chunk];
            let ahead = prefix[index] - from + op.prefix();
            spec.backs.push(op.distance.wrapping_sub(ahead as u32));
            spec.distances.push(op.distance);
        } else {
            spec.backs.push(0);
        }
    }
    spec
}

/// The chunk a lane writes its list for in this build: the prefetch depth.
#[cfg(feature = "parallel")]
fn lane_chunk_wanted() -> usize {
    #[cfg(feature = "h2-apply-arms")]
    let chunk = crate::probe::far_prefetch();
    #[cfg(not(feature = "h2-apply-arms"))]
    let chunk = Window::FAR_PREFETCH_DEPTH;
    chunk
}

/// What the lane must leave in a tape's list: the specification's list,
/// whole, when the list is built at all (`tape::FAR_LIST`, or any build
/// with the measuring arms), the gate admits the tape and it is within the
/// cap; else nothing whole.
#[cfg(feature = "parallel")]
fn far_list_wanted(ops: &[super::tape::TapeOp]) -> (FarSpec, bool) {
    use super::tape::{far_gate_admits, FAR_LIST, FAR_LIST_CAP, FAR_LIST_MIN_OPS};
    let built = FAR_LIST || super::tape::LIST_KNOB;
    let chunk = lane_chunk_wanted();
    if built
        && chunk > 0
        && (FAR_LIST_MIN_OPS..=FAR_LIST_CAP).contains(&ops.len())
        && far_gate_admits(ops)
    {
        (far_list_of(ops, chunk), true)
    } else {
        (far_list_of(ops, chunk.max(1)), false)
    }
}

/// The spec's list as the walk takes it: the far matches' backs alone, in
/// operation order, and each chunk's start among them, with one more for
/// the end.
#[cfg(feature = "parallel")]
fn far_list_built(spec: &FarSpec, chunk: usize) -> super::tape::FarList {
    let mut backs = Vec::new();
    let mut starts = Vec::new();
    for (index, (&back, &far)) in spec.backs.iter().zip(&spec.far).enumerate() {
        if index % chunk == 0 {
            starts.push(backs.len() as u32);
        }
        if far {
            backs.push(back);
        }
    }
    starts.push(backs.len() as u32);
    super::tape::FarList {
        len: backs.len(),
        backs,
        starts,
        chunk,
        complete: true,
    }
}

/// A member whose matches reach far back, built symbol by symbol: 300 KiB
/// of noise in its first block (so nothing near can stand in for a far
/// source), then blocks of at most 800 operations each: short literal
/// runs, fresh matches near and far, some EXACTLY `FAR_GATE_DISTANCE` back
/// so the list's `>=` is on trial, repeats of every slot (whose lengths
/// the walk's offsets must count) and now and then symbol 257. Answers the
/// output the member must decode to, worked out here from the symbols
/// written, and the packed member.
#[cfg(feature = "parallel")]
fn far_member() -> (Vec<u8>, Vec<u8>) {
    use super::ladders::fresh_match_length;
    let mut rng = rarkit_testdata::Seeded::new(0x5eed_fa12_0000_0001);
    let mut out: Vec<u8> = (0..300 << 10).map(|_| rng.below(256) as u8).collect();
    let mut packed = Vec::new();
    let mut first = BlockBuilder::default();
    first.literals(&out);
    packed.extend_from_slice(&first.finish(true, false));
    // The repeat state as section 3.5 keeps it, so the output can be
    // worked out for symbols 257 and 258 to 261.
    let mut reps = [0usize; 4];
    let mut last_length = 0usize;
    let blocks = 24;
    for block in 0..blocks {
        let mut builder = BlockBuilder::default();
        let mut ops = 0;
        while ops < 790 {
            for _ in 0..rng.below(4) {
                let byte = rng.below(256) as u8;
                builder.literal(byte);
                out.push(byte);
                ops += 1;
            }
            if last_length != 0 && rng.chance(50) {
                builder.repeat_last();
                for _ in 0..last_length {
                    out.push(out[out.len() - reps[0]]);
                }
                ops += 1;
                continue;
            }
            let k = rng.below(4) as usize;
            if reps[k] != 0 && rng.chance(100) {
                // A repeat's length slot comes from the LENGTH alphabet and
                // carries no distance bonus.
                let slot = rng.below(8) as usize;
                builder.repeat(k, slot, 0);
                let distance = reps[k];
                reps.copy_within(0..k, 1);
                reps[0] = distance;
                last_length = slot + 2;
                for _ in 0..last_length {
                    out.push(out[out.len() - distance]);
                }
                ops += 1;
                continue;
            }
            let roll = rng.below(100);
            let distance = if roll < 5 {
                Window::FAR_GATE_DISTANCE
            } else if roll < 50 {
                Window::FAR_GATE_DISTANCE + rng.below(40_000) as usize
            } else {
                1 + rng.below(4096) as usize
            };
            let slot = rng.below(8) as usize;
            let (distance_slot_, extra) = distance_slot(distance);
            builder.fresh(slot, 0, distance_slot_, extra);
            let length = fresh_match_length(slot + 2, distance);
            for _ in 0..length {
                out.push(out[out.len() - distance]);
            }
            reps = [distance, reps[0], reps[1], reps[2]];
            last_length = length;
            ops += 1;
        }
        packed.extend_from_slice(&builder.finish(true, block + 1 == blocks));
    }
    (out, packed)
}

/// THE DECODER WRITES THE LIST ITS SPECIFICATION DOES, on every tape of a
/// member whose matches reach past the far distance: the same entries,
/// whole, and a recycled tape never keeps the list of the block before.
/// Non-vacuous where the list is built: thousands of entries and one at
/// exactly the far distance.
#[cfg(feature = "parallel")]
#[test]
fn the_decoders_far_list_is_every_far_match_of_its_tape() {
    use super::tape::{self, BlockTape, Plan};
    let (_, packed) = far_member();
    let mut plan = Plan::default();
    tape::plan(&packed, false, &mut plan).unwrap();
    let mut entries = 0usize;
    let mut exact = 0usize;
    let mut carried = None;
    // ONE tape for every block, as a lane recycles it: the first block's
    // noise is gated off, so a list left over from any block would show.
    let mut held = BlockTape::default();
    for index in 0..plan.blocks.len() {
        carried = tape::decode_one(&plan, &packed, 0, carried.as_ref(), index, &mut held);
        let tables = carried.clone().expect("the block's tables build");
        loop {
            assert!(held.failure.is_none(), "block {index} decodes");
            let (want, whole) = far_list_wanted(&held.steps);
            let (have, have_whole) = held.far_entries();
            assert_eq!(have_whole, whole, "block {index}: whole or not");
            if whole {
                assert_eq!(have, &want.backs[..], "block {index}: the far list");
            }
            entries += want.backs.len();
            exact += want
                .distances
                .iter()
                .filter(|&&d| d as usize == Window::FAR_GATE_DISTANCE)
                .count();
            match held.parked_at {
                Some(at) => {
                    tape::decode_block_tape(&tables, &packed, &plan.blocks[index], at, &mut held)
                }
                None => break,
            }
        }
    }
    eprintln!("far member: {entries} far entries, {exact} at exactly the far distance");
    if tape::FAR_LIST || tape::LIST_KNOB {
        assert!(
            entries > 1_000,
            "the far member carries far matches: {entries}"
        );
        assert!(exact > 0, "one entry sits at exactly the far distance");
    }
}

/// The same over the repository's archives, and over DAMAGED members,
/// where a tape stops early with its failure deferred: the list is whole
/// for what the tape holds.
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
#[test]
fn the_decoders_far_list_holds_on_every_archive_and_every_damaged_tape() {
    use super::tape::{self, BlockTape, Plan};
    let check = |packed: &[u8], algorithm: u8, what: &str| {
        let mut plan = Plan::default();
        if tape::plan(packed, false, &mut plan).is_err() {
            return;
        }
        for index in 0..plan.blocks.len() {
            let mut held = BlockTape::default();
            tape::decode_one(&plan, packed, algorithm, None, index, &mut held);
            if held.steps.is_empty() && held.failure.is_some() {
                continue;
            }
            let (want, whole) = far_list_wanted(&held.steps);
            let (have, have_whole) = held.far_entries();
            assert_eq!(have_whole, whole, "{what} block {index}: whole or not");
            if whole {
                assert_eq!(have, &want.backs[..], "{what} block {index}");
            }
        }
    };
    for stem in ARCHIVES {
        for member in members(&archive(stem)) {
            if member.method == 0 || member.directory {
                continue;
            }
            check(&member.packed, member.algorithm, stem);
        }
    }
    let data = archive("h5_text_m5");
    let member = members(&data)
        .into_iter()
        .find(|m| m.method != 0)
        .expect("a compressed member");
    for byte in (0..member.packed.len().min(4096)).step_by(17) {
        let mut packed = member.packed.clone();
        packed[byte] ^= 1 << 2;
        check(&packed, member.algorithm, "damaged");
    }
}

/// THE DICTIONARY FLOOR (`Window::FAR_DICTIONARY_FLOOR`): a stream whose
/// declared dictionary is at or under it is never hinted, one above it is
/// as before, and the floor is the DECLARED size, not the ring's. A tape
/// the gate admits gets no list when its plan says the stream is off, and
/// its list back when the plan says it is not.
#[cfg(feature = "parallel")]
#[test]
fn the_far_list_is_off_at_or_under_the_dictionary_floor() {
    use super::tape::{build_far_list, tape_kind, BlockTape, TapeOp};
    let floor = Window::FAR_DICTIONARY_FLOOR;
    if floor > 0 {
        assert!(Window::new(floor as u64, u64::MAX).unwrap().far_off());
        assert!(Window::new(128 << 10, u64::MAX).unwrap().far_off());
    }
    assert!(!Window::new(floor as u64 + 1, u64::MAX).unwrap().far_off());
    assert!(!Window::new(32 << 20, u64::MAX).unwrap().far_off());

    let far_match = TapeOp::new(tape_kind::MATCH, 3, Window::FAR_GATE_DISTANCE as u32);
    let mut tape = BlockTape {
        steps: vec![far_match; 4096],
        far_off: true,
        ..BlockTape::default()
    };
    build_far_list(&mut tape);
    assert!(!tape.far_entries().1, "off: no list");
    assert!(super::tape::listed(&tape).is_none(), "and never walked");
    tape.far_off = false;
    build_far_list(&mut tape);
    assert!(tape.far_entries().1, "on: the list");
}

/// THE LIST HAS A CAP, A FLOOR AND A GATE: a tape of `FAR_LIST_CAP`
/// operations gets its list, one of a single operation more gets none and
/// is marked incomplete (so the apply stage walks it as main does), so does
/// one a single operation under `FAR_LIST_MIN_OPS` while one at it is
/// listed, a tape the gate refuses gets none either, and a shorter list
/// written into a longer buffer is exactly the shorter list.
#[cfg(feature = "parallel")]
#[test]
fn the_far_list_is_written_only_within_its_cap_and_its_gate() {
    use super::tape::{
        build_far_list, tape_kind, BlockTape, TapeOp, FAR_LIST_CAP, FAR_LIST_MIN_OPS,
    };
    let far_match = TapeOp::new(tape_kind::MATCH, 3, Window::FAR_GATE_DISTANCE as u32);
    let near_match = TapeOp::new(tape_kind::MATCH, 3, 16);
    let mut tape = BlockTape {
        steps: vec![far_match; FAR_LIST_CAP],
        ..BlockTape::default()
    };
    let chunk = lane_chunk_wanted();
    build_far_list(&mut tape);
    let (have, whole) = tape.far_entries();
    assert!(whole, "at the cap: whole");
    assert_eq!(have.len(), FAR_LIST_CAP);
    let spec = far_list_of(&tape.steps, chunk);
    assert_eq!(have, &spec.backs[..]);

    tape.steps.push(far_match);
    build_far_list(&mut tape);
    let (have, whole) = tape.far_entries();
    assert!(!whole, "one past the cap: incomplete");
    // An incomplete list's entries are never read (the builder refuses
    // without touching them, to allocate nothing): what matters is that
    // the apply stage will not walk it.
    let _ = have;
    assert!(super::tape::listed(&tape).is_none(), "and never walked");

    tape.steps = vec![far_match; FAR_LIST_MIN_OPS - 1];
    build_far_list(&mut tape);
    let (_, whole) = tape.far_entries();
    assert!(!whole, "one under the floor: incomplete");
    tape.steps.push(far_match);
    build_far_list(&mut tape);
    let (have, whole) = tape.far_entries();
    assert!(whole, "at the floor: whole");
    let spec = far_list_of(&tape.steps, chunk);
    assert_eq!(
        have,
        &spec.backs[..],
        "and exactly the list, in a longer buffer"
    );

    tape.steps = vec![near_match; 1000];
    build_far_list(&mut tape);
    let (have, whole) = tape.far_entries();
    let _ = have;
    assert!(!whole, "a gated-off tape: incomplete");
    assert!(super::tape::listed(&tape).is_none(), "and never walked");

    // Far and near interleaved, as the branch free writer must place them.
    tape.steps = (0..999)
        .map(|i| if i % 3 == 0 { far_match } else { near_match })
        .collect();
    build_far_list(&mut tape);
    let (have, whole) = tape.far_entries();
    assert!(whole, "an interleaved tape the gate admits: whole");
    let spec = far_list_of(&tape.steps, chunk);
    assert_eq!(have, &spec.backs[..]);
    assert_eq!(have.len(), 999, "an entry an operation, spread");
    // Compact, the list holds the far matches alone: one in three here,
    // so it sheds two entries in three of the dense stream's.
    let far = tape.far.as_deref().expect("a list");
    assert_eq!(far.len, 333, "one entry a far match");
    assert_eq!(far.starts.len(), 999usize.div_ceil(chunk) + 1);
    // Shipped, the apply stage walks exactly such a tape listed; with
    // the measuring arms that is the knob's to say.
    if !super::tape::LIST_KNOB {
        assert_eq!(
            super::tape::listed(&tape).is_some(),
            super::tape::FAR_LIST,
            "the apply stage walks a whole list exactly where the list is on"
        );
    }
}

/// One random case through either walk, the far prefetch at `depth`: the
/// pass over every operation (`tape::apply`, ungated, so every case is
/// hinted) or the listed walk (`tape::apply_listed`) with the tape's list
/// as its specification writes it. `end`, when the case asks for it, puts
/// the member's declared end inside the block. Answers the outcome and
/// the hints in order, `(distance, ring index)` from the pass and
/// `(back, ring index)` from the listed walk, and the ring's length.
#[cfg(all(feature = "parallel", feature = "h2-apply-arms"))]
fn run_far_case(
    case: &SymbolCase,
    depth: usize,
    list: bool,
    end: Option<u64>,
) -> (SymbolOutcome, Vec<(usize, usize)>, usize) {
    use super::filters::Filters;
    use super::output::NoFilters;
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
    let spec = far_list_of(&case.tape.steps, depth);
    let far = far_list_built(&spec, depth);
    crate::probe::set_far_prefetch(Some(depth));
    crate::probe::set_far_prefetch_mode(crate::probe::far_prefetch_modes::UNGATED);
    tape::take_hints(true);
    let result = if list {
        tape::apply_listed(
            &case.tape,
            &far,
            &mut state,
            &mut window,
            &mut filters,
            unpacked,
            &mut sink,
        )
    } else {
        tape::apply(
            &case.tape,
            &mut state,
            &mut window,
            &mut filters,
            unpacked,
            &mut sink,
        )
    };
    let hints = tape::take_hints(false);
    crate::probe::set_far_prefetch(None);
    crate::probe::set_far_prefetch_mode(crate::probe::far_prefetch_modes::ALL);
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
        hints,
        window.ring_bytes(),
    )
}

/// THE DIFFERENTIAL: over random tapes of every operation kind, the listed
/// walk hints EXACTLY the addresses the pass over every operation hints
/// for the far matches, in the same order, and nothing else; and it writes
/// the same bytes, the same drain pieces, the same repeat state and the
/// same stop or error, with the member's end past the block and inside it.
/// Non-vacuous: the far hints compared must number in the thousands.
#[cfg(all(feature = "parallel", feature = "h2-apply-arms"))]
#[test]
fn the_far_list_hints_what_the_pass_hints_for_every_far_match() {
    // The pass's far hints and the list's, pair by pair: the same number,
    // and the same ring index for every far match whose distance the ring
    // can hold. A distance past the ring (only an invalid tape carries
    // one, and its copy is refused) is the same hint too unless the pass
    // CLAMPED it onto the ring's last byte, where the list names another
    // byte of the ring or none: one line of bandwidth either way, on a
    // member that is about to fail. `past` counts those. And a far match
    // further into its two chunks than its own distance (a back the lane
    // wrapped below zero, which only a random tape's long runs reach) the
    // list leaves unhinted; `wrapped` counts those.
    let mut past = 0usize;
    let mut wrapped = 0usize;
    let mut same = |pass: &[(usize, usize)], list: &[(usize, usize)], ring: usize, what: &str| {
        // The listed walk hints exactly the far matches the pass hints,
        // one for one and in order; the pass's other hints are not the
        // list's to give.
        let pass: Vec<_> = pass
            .iter()
            .filter(|&&(distance, _)| distance >= Window::FAR_GATE_DISTANCE)
            .collect();
        assert_eq!(pass.len(), list.len(), "{what}: how many far hints");
        let mut far = 0usize;
        for (&&(distance, want), &(back, have)) in pass.iter().zip(list) {
            far += 1;
            if back > distance {
                wrapped += 1;
                assert!(have >= ring, "{what}: a wrapped back names no byte");
            } else if distance > ring && want == ring - 1 && have != want {
                past += 1;
            } else {
                assert_eq!(want, have, "{what}: the hint of a match {distance} back");
            }
        }
        far
    };
    let mut compared = 0usize;
    let mut cut = 0usize;
    // Every case here declares 128 to 512 KiB, under the aarch64 dictionary
    // floor (`Window::FAR_DICTIONARY_FLOOR`) that turns the pass's hints off
    // as it ships. This test holds the two hint walks against each other,
    // not the floor (`the_far_list_is_off_at_or_under_the_dictionary_floor`
    // pins that), so the floor is zero for its length.
    crate::probe::set_far_floor(Some(0));
    for seed in 0..300u64 {
        let case = symbol_case(seed);
        for depth in [1usize, 3, 8, 17, 64] {
            let (pass, pass_hints, ring) = run_far_case(&case, depth, false, None);
            let (list, list_hints, _) = run_far_case(&case, depth, true, None);
            assert_eq!(pass, list, "case {seed} depth {depth}: outcome");
            compared += same(
                &pass_hints,
                &list_hints,
                ring,
                &format!("case {seed} depth {depth}"),
            );
            // The member's end inside the block, where the walk stops at
            // an operation and not at the tape's end.
            let block = pass.produced - {
                let (empty, _, _) = run_far_case(
                    &SymbolCase {
                        tape: super::tape::BlockTape::default(),
                        ..symbol_case(seed)
                    },
                    depth,
                    false,
                    None,
                );
                empty.produced
            };
            if case.unpacked_slack < 0 && block > 0 {
                let (pass, pass_hints, ring) = run_far_case(&case, depth, false, Some(block));
                let (list, list_hints, _) = run_far_case(&case, depth, true, Some(block));
                assert_eq!(pass, list, "case {seed} depth {depth}: outcome, end inside");
                same(
                    &pass_hints,
                    &list_hints,
                    ring,
                    &format!("case {seed} depth {depth}, end inside"),
                );
                cut += 1;
            }
        }
    }
    crate::probe::set_far_floor(None);
    eprintln!(
        "far hints compared: {compared}; cases cut inside the block: {cut}; \
         backs wrapped: {wrapped}; distances past the ring: {past}"
    );
    assert!(compared > 5_000, "the far hints compared: {compared}");
    assert!(cut > 100, "cases cut inside the block: {cut}");
}

/// A far member through the whole parallel decode, as it ships: the
/// output byte for byte, whichever walk the default sends each tape to.
#[cfg(feature = "parallel")]
#[test]
fn the_far_list_changes_no_byte_of_a_far_member_as_it_ships() {
    let (input, packed) = far_member();
    let mut lz = Rar5Lz::new(4 << 20, &policy()).unwrap();
    lz.set_parallel(true);
    let mut sink: Vec<u8> = Vec::new();
    let mut source = SliceSource::new(&packed);
    lz.member(&mut source, input.len() as u64, 0, &mut sink)
        .unwrap();
    assert!(sink == input, "bytes");
}

/// And with the knob: the list on and off and the prefetch at several
/// depths, gated as it ships, every run writes the input byte for byte.
#[cfg(all(feature = "parallel", feature = "h2-apply-arms"))]
#[test]
fn the_far_list_changes_no_byte_of_a_far_member_at_any_setting() {
    let (input, packed) = far_member();
    for (depth, list) in [(0, false), (64, false), (64, true), (8, true), (1, true)] {
        crate::probe::set_far_prefetch(Some(depth));
        crate::probe::set_far_list(Some(list));
        let mut lz = Rar5Lz::new(4 << 20, &policy()).unwrap();
        lz.set_parallel(true);
        let mut sink: Vec<u8> = Vec::new();
        let mut source = SliceSource::new(&packed);
        lz.member(&mut source, input.len() as u64, 0, &mut sink)
            .unwrap();
        crate::probe::set_far_prefetch(None);
        crate::probe::set_far_list(None);
        assert!(sink == input, "depth {depth} list {list}: bytes");
    }
}

/// And over the repository's archives and a damaged member: the list on
/// and off changes no byte and no error.
#[cfg(all(feature = "repo-tests", feature = "h2-apply-arms"))]
#[test]
fn the_far_list_changes_no_byte_and_no_error_on_any_archive() {
    for stem in ARCHIVES {
        let data = archive(stem);
        crate::probe::set_far_list(Some(false));
        let off = decode_archive(&data, true);
        for depth in [1usize, 8, 64] {
            crate::probe::set_far_prefetch(Some(depth));
            crate::probe::set_far_list(Some(true));
            let on = decode_archive(&data, true);
            assert_eq!(off.len(), on.len(), "{stem} depth {depth}");
            for (a, b) in off.iter().zip(&on) {
                assert_eq!(a.0, b.0, "{stem} depth {depth}: member order");
                assert!(a.1 == b.1, "{stem}/{} depth {depth}: bytes", a.0);
            }
        }
        crate::probe::set_far_prefetch(None);
    }
    let data = archive("h5_text_m5");
    let member = members(&data)
        .into_iter()
        .find(|m| m.method != 0)
        .expect("a compressed member");
    for byte in (0..member.packed.len().min(4096)).step_by(13) {
        let mut packed = member.packed.clone();
        packed[byte] ^= 1 << 5;
        let mut runs = Vec::new();
        for list in [false, true] {
            crate::probe::set_far_prefetch(Some(8));
            crate::probe::set_far_list(Some(list));
            let mut lz = Rar5Lz::new(member.window, &policy()).unwrap();
            lz.set_parallel(true);
            let mut sink: Vec<u8> = Vec::new();
            let mut source = SliceSource::new(&packed);
            let outcome = lz.member(&mut source, member.unpacked, member.algorithm, &mut sink);
            runs.push((outcome.map_err(|e| format!("{:?}", e.kind())), sink));
        }
        crate::probe::set_far_prefetch(None);
        assert_eq!(runs[0].0, runs[1].0, "byte {byte}: error kind");
        assert!(runs[0].1 == runs[1].1, "byte {byte}: output");
    }
    crate::probe::set_far_list(None);
}

/// The list knob alone (`h2-far-list-knob`, or beside the arms): a far
/// member through the whole parallel decode with the list's walk on and
/// off writes the input byte for byte, and the knob's off is the control's walk.
#[cfg(all(
    feature = "parallel",
    any(feature = "h2-apply-arms", feature = "h2-far-list-knob")
))]
#[test]
fn the_far_list_knob_changes_no_byte_of_a_far_member() {
    let (input, packed) = far_member();
    for list in [false, true] {
        crate::probe::set_far_list(Some(list));
        let mut lz = Rar5Lz::new(4 << 20, &policy()).unwrap();
        lz.set_parallel(true);
        let mut sink: Vec<u8> = Vec::new();
        let mut source = SliceSource::new(&packed);
        let outcome = lz.member(&mut source, input.len() as u64, 0, &mut sink);
        crate::probe::set_far_list(None);
        outcome.unwrap();
        assert!(sink == input, "list {list}: bytes");
    }
}
