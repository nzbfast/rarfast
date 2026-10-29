//! Section 5.5: the window and parallel property tests.

use super::*;

/// One window, one seed, then a SEQUENCE of copies, against the byte at a
/// time reference doing the same sequence. Batching the crosses this way
/// is what keeps the screen inside a test run: the property under test is
/// per copy either way.
fn copies_match(seed: &[u8], window: u64, copies: impl Iterator<Item = (usize, usize)> + Clone) {
    let mut win = Window::new(window, u64::MAX).unwrap();
    win.begin_member();
    let mut sink: Vec<u8> = Vec::new();
    let mut filters = NoFilters;
    win.literals_chunked(seed, &mut sink, &mut filters);
    win.drain(&mut sink, &mut filters, true).unwrap();
    let mut want = seed.to_vec();
    for (distance, length) in copies {
        win.copy_match(distance, length).unwrap();
        win.drain(&mut sink, &mut filters, true).unwrap();
        reference_copy(&mut want, distance, length);
        assert!(
            sink == want,
            "d {distance} l {length} at {} bytes",
            want.len()
        );
    }
}

/// Section 5.5: distances crossed with lengths against a byte at a time
/// reference. The FULL cross of 4,096 distances by 4,100 lengths copies
/// about 34 GB and is `the_whole_distance_length_cross`, which runs with
/// `--ignored`; this is the screen `make ci` runs: every distance against
/// a length ladder that covers every boundary the copy has, and the whole
/// length range against the distances the strides turn on.
#[test]
fn the_window_copy_matches_a_byte_at_a_time_reference() {
    let seed: Vec<u8> = (0..8192u32).map(|i| (i * 31 + i / 11) as u8).collect();
    let ladder = [
        1usize, 2, 3, 4, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 127, 128, 4_099, 4_100,
    ];
    for distance in 1..=4096usize {
        copies_match(
            &seed,
            1 << 20,
            ladder.iter().map(move |&length| (distance, length)),
        );
    }
    for distance in 1..=80usize {
        copies_match(&seed, 1 << 20, (1..=4_100usize).map(move |l| (distance, l)));
    }
}

/// The whole cross of section 5.5, which copies about 34 GB.
#[test]
#[ignore = "the full 4,096 by 4,100 cross; run with --ignored"]
fn the_whole_distance_length_cross() {
    let seed: Vec<u8> = (0..8192u32).map(|i| (i * 31 + i / 11) as u8).collect();
    for distance in 1..=4096usize {
        copies_match(&seed, 1 << 24, (1..=4_100usize).map(move |l| (distance, l)));
    }
}

/// Section 3.7: a copy that wraps the ring, and one at exactly the window's
/// own length, produce the byte at a time result too.
#[test]
fn a_copy_that_wraps_the_ring_is_still_byte_at_a_time() {
    let window = 1u64 << 17;
    for fill in [
        (window - 10) as usize,
        (window - 1) as usize,
        window as usize,
        (window + 5) as usize,
    ] {
        let seed: Vec<u8> = (0..fill as u32).map(|i| (i * 7 + i / 3) as u8).collect();
        for distance in [1usize, 2, 17, 4096, 65_536, window as usize] {
            if distance > fill {
                continue;
            }
            for length in [1usize, 2, 64, 1000, 4100] {
                let mut win = Window::new(window, u64::MAX).unwrap();
                win.begin_member();
                let mut sink: Vec<u8> = Vec::new();
                let mut filters = NoFilters;
                win.literals_chunked(&seed, &mut sink, &mut filters);
                win.drain(&mut sink, &mut filters, true).unwrap();
                win.copy_match(distance, length).unwrap();
                win.drain(&mut sink, &mut filters, true).unwrap();
                let mut want = seed.clone();
                reference_copy(&mut want, distance, length);
                assert!(sink == want, "fill {fill} d {distance} l {length}");
            }
        }
    }
}

/// Section 3.7: the distances AT THE EDGE of the window, on a ring that has
/// LAPPED, and each one preceded by a short match.
///
/// This is the screen that was missing. The window copy had a fast path
/// that rounded a short match's length up to a whole sixteen byte stride,
/// which is free in a buffer that slides and is not free in a ring: the
/// bytes it wrote past the match are the OLDEST live bytes of the window,
/// and they are exactly what a distance within a stride of the dictionary
/// size reads. The decode then returned wrong bytes with NO error. Spec
/// H3's encoder follow-up found it on a 46 MB member at a 4 MiB dictionary
/// (18 Sep 2026) and held its own reach 64 bytes short of the dictionary
/// until it was fixed.
///
/// Three conditions have to meet before it shows, which is why every test
/// here passed: the ring must have LAPPED, so the slot ahead of the write
/// point holds a live byte rather than a byte the stream never produced;
/// the edge distance must follow a fast path match within a stride; and
/// the distance must be within fifteen of the dictionary. The crosses of
/// 5.5 never filled their window, and `a_copy_that_wraps_the_ring_is_
/// still_byte_at_a_time` fills it but does ONE copy, with nothing in front
/// of it to leave a scribble.
#[test]
fn v5_edge_a_distance_at_the_window_reads_the_oldest_byte_not_a_scribble() {
    for window in [1u64 << 16, 1 << 17, 1 << 18, 1 << 20] {
        edge_cross(window, false);
    }
}

/// The same cross across a solid member boundary: `begin_member` starts a
/// member's offsets again and does NOT clear the ring, so the second
/// member's matches reach back into the first one's bytes at every
/// distance up to the dictionary (section 3.7).
#[test]
fn v5_edge_the_window_edge_holds_across_a_solid_member_boundary() {
    for window in [1u64 << 16, 1 << 17] {
        edge_cross(window, true);
    }
}

/// Fill past a lap, then walk a lead match and an edge distance together.
/// The lead is what leaves a scribble to read, and its length is crossed
/// because how far a stride ladder over runs is a function of the length.
fn edge_cross(window: u64, solid: bool) {
    let ring = window as usize;
    let fill = ring + ring / 2;
    let seed: Vec<u8> = (0..fill)
        .map(|i| ((i as u32).wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let mut win = Window::new(window, u64::MAX).unwrap();
    win.begin_member();
    let mut sink: Vec<u8> = Vec::new();
    let mut filters = NoFilters;
    win.literals_chunked(&seed, &mut sink, &mut filters);
    win.drain(&mut sink, &mut filters, true).unwrap();
    let mut want = seed.clone();
    if solid {
        // A fresh member over the same ring: the stream's bytes stay, the
        // member's offsets start again, and the sink takes the new member
        // only. The reference keeps the whole stream, which is what a
        // distance is measured against.
        win.begin_member();
        sink.clear();
    }
    // What the sink holds is the MEMBER; what the reference holds is the
    // stream, and a distance is measured against the stream.
    let skew = want.len() - sink.len();
    let mut checked = sink.len();
    for lead in [
        1usize, 2, 3, 5, 7, 8, 11, 15, 16, 17, 23, 31, 32, 33, 47, 48, 49, 63, 64,
    ] {
        for k in 0..=64usize {
            for (distance, length) in [(1024usize, lead), (ring - k, 70usize)] {
                win.copy_match(distance, length)
                    .unwrap_or_else(|e| panic!("window {window} lead {lead} k {k}: {e}"));
                reference_copy(&mut want, distance, length);
            }
            win.drain(&mut sink, &mut filters, true).unwrap();
            let fresh = &want[skew + checked..];
            assert!(
                sink[checked..] == *fresh,
                "window {window} solid {solid} lead {lead} k {k}: \
                 {} bytes differ from the byte at a time reference",
                sink[checked..]
                    .iter()
                    .zip(fresh)
                    .filter(|(a, b)| a != b)
                    .count()
            );
            checked = sink.len();
        }
    }
}

/// The last `count` bytes a window has produced, by draining it.
fn last_bytes(win: &mut Window, sink: &mut Vec<u8>, count: usize) -> Vec<u8> {
    win.drain(sink, &mut NoFilters, true).unwrap();
    sink[sink.len() - count..].to_vec()
}

/// Section 3.7: a distance one past the window gives zero bytes, on a ring
/// that could physically serve it. The window is the larger of the
/// DECLARED dictionary and 256 KiB, and not the ring's allocation.
#[test]
fn a_distance_one_past_the_window_gives_zeros_on_a_ring_that_holds_the_bytes() {
    for window in [1u64 << 17, 1 << 19] {
        let reach = (window as usize).max(WINDOW_FLOOR);
        // Every byte odd, so a zero is a byte the stream does not hold.
        let seed: Vec<u8> = (0..reach + reach / 2).map(|i| (i * 11) as u8 | 1).collect();
        for over in [1usize, 2, 15, 16, 64, 1024] {
            let mut win = Window::new(window, u64::MAX).unwrap();
            win.begin_member();
            assert!(win.ring_bytes() >= reach + over, "the ring holds the place");
            let mut sink: Vec<u8> = Vec::new();
            let mut filters = NoFilters;
            win.literals_chunked(&seed, &mut sink, &mut filters);
            // The stream has produced more than the window, so the only
            // thing that makes these zeros is the window.
            assert!(seed.len() > reach + over);
            win.copy_match(reach + over, 2)
                .expect("a distance past the window is no fault");
            assert_eq!(
                last_bytes(&mut win, &mut sink, 2),
                [0, 0],
                "window {window} over {over}"
            );
            // And the last distance that IS honoured still copies the
            // stream's bytes.
            let from = sink.len() - reach;
            let want = sink[from..from + 2].to_vec();
            win.copy_match(reach, 2).expect("the window's edge");
            assert_eq!(last_bytes(&mut win, &mut sink, 2), want, "window {window}");
        }
    }
}

/// The ring is the dictionary plus a spill margin, and its write point
/// laps at a length that is not a power of two. Short matches, each
/// followed at once by a match from the declared size back or a few bytes
/// short of it, are walked across the ring's end and a lap beyond, so the
/// far match's source and the short match's spill meet the seam in every
/// alignment, against the byte at a time reference.
#[test]
fn short_and_far_matches_walk_across_the_rings_seam() {
    let window = 1usize << 17;
    // Not periodic in the window, or a spill would equal what it lands on.
    let mut state = 0x9e37_79b9u32;
    let seed: Vec<u8> = (0..window + 1000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect();
    let walk = (0..3_000usize).flat_map(|i| {
        let short = 2 + (i * 7) % 63;
        let back = (i * 5) % 17;
        [(100 + i % 50, short), (window - back, 3 + i % 40)]
    });
    copies_match(&seed[..window + 10], window as u64, walk.clone());
    copies_match(&seed, window as u64, walk);
}

/// Section 5.5: every archive of 5.2 decoded with the parallel path forced
/// on and forced off must give byte identical output.
#[cfg(feature = "repo-tests")]
#[test]
fn the_parallel_and_serial_paths_agree_on_every_archive() {
    for stem in ARCHIVES {
        let data = archive(stem);
        let serial = decode_archive(&data, false);
        let parallel = decode_archive(&data, true);
        assert_eq!(serial.len(), parallel.len(), "{stem}");
        for (a, b) in serial.iter().zip(&parallel) {
            assert_eq!(a.0, b.0, "{stem}: member order");
            assert!(a.1 == b.1, "{stem}/{}: bytes", a.0);
        }
    }
}

/// The hint's address arithmetic takes ANY estimate without a panic or
/// a write: a distance past the ring (which only an invalid tape
/// carries), an `ahead` past a whole lap, both at once, and zero. The
/// window's bytes and its write point are unchanged after all of them.
#[cfg(feature = "parallel")]
#[test]
fn the_far_prefetch_takes_any_estimate_and_moves_nothing() {
    let mut window = Window::new(1 << 16, u64::MAX).unwrap();
    for i in 0..5_000u32 {
        window.literal(i as u8);
    }
    let before = window.stream_produced();
    let ring = window.ring_bytes();
    let peek: Vec<u8> = (1..=64)
        .map(|back| window.peek_ahead_for_test(ring - back))
        .collect();
    for ahead in [
        0,
        1,
        63,
        4_999,
        ring - 1,
        ring,
        ring + 1,
        3 * ring,
        usize::MAX / 2,
    ] {
        for distance in [0, 1, 16, 4_999, 5_000, ring - 1, ring, ring + 1, usize::MAX] {
            window.prefetch_source(ahead, distance);
        }
    }
    assert_eq!(window.stream_produced(), before);
    let after: Vec<u8> = (1..=64)
        .map(|back| window.peek_ahead_for_test(ring - back))
        .collect();
    assert_eq!(peek, after);
}

/// THE MATCH COPY ADMITS EXACTLY WHAT SECTION 3.7 ADMITS, at both of
/// its edges and on both sides of each.
///
/// `Window::copy_match` asks three questions of every match: distance
/// zero, distance above what the stream has produced, distance above
/// the declared window. Subtracted on an Apple M1 Mac on 22 Sep 2026 those
/// three cost 3.13 to 5.10 percent of the apply stage, the largest
/// removable per-operation cost in the walk, and a one-compare form
/// against a cached bound was written, measured and DECLINED: it read
/// 0.9963x, 1.0142x and 0.9750x against this form in one binary
/// (22 Sep 2026).
///
/// This test outlived that lever and is the reason to keep it. Nothing
/// in this package tested the EDGES of section 3.7 in both directions
/// before, and any future attempt to make this test cheaper has to
/// refuse exactly what it refuses now. A cheaper test that refuses a
/// little less is a window read out of bounds on an untrusted archive.
///
/// Both bounds are exercised in both directions: a stream that has
/// produced LESS than its window, where produced binds, and one that
/// has produced more, where the window binds; the largest admissible
/// distance honoured in each; the next one giving zeros and no fault
/// (section 3.7 as amended on 11 Oct 2026); zero refused; and a fresh stream after
/// `reset` honouring nothing.
#[test]
fn the_match_copy_admits_exactly_what_section_3_7_admits() {
    let dictionary: u64 = 1 << 18;
    let kind =
        |outcome: &crate::Result<()>| outcome.as_ref().err().map(|e| format!("{:?}", e.kind()));

    // 1. PRODUCED BINDS: fewer bytes written than the window holds.
    for produced in [1usize, 2, 1000, (dictionary as usize) - 1] {
        let mut win = Window::new(dictionary, u64::MAX).unwrap();
        win.begin_member();
        let mut sink: Vec<u8> = Vec::new();
        let mut filters = NoFilters;
        let seed: Vec<u8> = (0..produced).map(|i| (i * 7 + 1) as u8).collect();
        win.literals_chunked(&seed, &mut sink, &mut filters);

        assert!(
            win.copy_match(produced, 2).is_ok(),
            "produced {produced}: the whole of what the stream has written is nameable"
        );
        let mut win = Window::new(dictionary, u64::MAX).unwrap();
        win.begin_member();
        let mut sink: Vec<u8> = Vec::new();
        win.literals_chunked(&seed, &mut sink, &mut filters);
        // One byte before the stream's start: a zero for that byte, and
        // then the stream's own first byte, as any match goes byte by byte.
        win.copy_match(produced + 1, 2)
            .expect("a distance before the stream's start is no fault");
        assert_eq!(
            last_bytes(&mut win, &mut sink, 2),
            [0, seed[0]],
            "produced {produced}: one byte before the stream's start"
        );
        assert_eq!(
            kind(&win.copy_match(0, 2)),
            Some("Corrupt(Rar5(DistanceOutOfRange))".to_string()),
            "produced {produced}: a distance of zero must be refused"
        );
    }

    // 2. THE WINDOW BINDS: more bytes written than the window holds, so
    //    the oldest are gone and the dictionary is the smaller bound.
    let mut win = Window::new(dictionary, u64::MAX).unwrap();
    win.begin_member();
    let mut sink: Vec<u8> = Vec::new();
    let mut filters = NoFilters;
    let seed: Vec<u8> = (0..(dictionary as usize) * 2)
        .map(|i| (i * 11 + 3) as u8)
        .collect();
    win.literals_chunked(&seed, &mut sink, &mut filters);
    win.drain(&mut sink, &mut filters, true).unwrap();
    assert!(
        win.copy_match(dictionary as usize, 2).is_ok(),
        "the oldest byte the window still holds is nameable"
    );
    win.copy_match(dictionary as usize + 1, 2)
        .expect("a distance past the window is no fault");
    assert_eq!(
        last_bytes(&mut win, &mut sink, 2),
        [0, 0],
        "one byte past the window gives zeros, whatever the stream holds there"
    );

    // 3. AND THE LIMIT IS PER STREAM, not per member. `reset` takes the
    //    produced count back to zero, so a fresh stream can name
    //    nothing at all. This case is what caught the declined lever's
    //    worst failure mode, a bound cached across a reset, and it is
    //    the one way any future cheaper form can be wrong that no
    //    single-stream test would ever see.
    win.reset();
    win.begin_member();
    let mut fresh: Vec<u8> = Vec::new();
    win.copy_match(1, 2)
        .expect("a distance before a fresh stream's start is no fault");
    assert_eq!(
        last_bytes(&mut win, &mut fresh, 2),
        [0, 0],
        "a fresh stream has produced nothing, so no distance copies a byte of the old one"
    );
}

/// Section 3.8, consequence 2 and 5.5: a damaged archive gives the same
/// error kind at the same output position with the parallel path on and
/// off.
#[cfg(feature = "repo-tests")]
#[test]
fn a_damaged_member_fails_the_same_way_in_both_arms() {
    let data = archive("h5_text_m5");
    let member = members(&data)
        .into_iter()
        .find(|m| m.method != 0)
        .expect("a compressed member");
    for byte in (0..member.packed.len().min(4096)).step_by(7) {
        for bit in [1u32, 5] {
            let mut packed = member.packed.clone();
            packed[byte] ^= 1 << bit;
            let mut both = Vec::new();
            for parallel in [false, true] {
                let mut lz = Rar5Lz::new(member.window, &policy()).unwrap();
                lz.set_parallel(parallel);
                let mut sink: Vec<u8> = Vec::new();
                let mut source = SliceSource::new(&packed);
                let outcome = lz.member(&mut source, member.unpacked, member.algorithm, &mut sink);
                both.push((outcome.map_err(|e| format!("{:?}", e.kind())), sink));
            }
            assert_eq!(both[0].0, both[1].0, "byte {byte} bit {bit}: error kind");
            assert!(both[0].1 == both[1].1, "byte {byte} bit {bit}: output");
        }
    }
}

/// The scheduling knobs the overlap of section 3.8 is measured and tested
/// across: the workers, the blocks in one wave, and whether wave N+1 is
/// decoded while wave N is applied at all.
///
/// A vector archive is a handful of blocks, so the default wave - twice
/// the worker count - holds the whole chain and the overlap is never
/// reached. Forcing the wave to one or two blocks is what crosses wave
/// boundaries on the archives this suite has. `overlap` false is the bulk
/// synchronous driver the overlap replaced, kept so both are under test.
#[cfg(all(feature = "parallel", feature = "repo-tests"))]
const SCHEDULES: &[(usize, Option<usize>, bool)] = &[
    (1, Some(1), true),
    (1, Some(1), false),
    (1, Some(2), true),
    (2, Some(1), true),
    (2, Some(3), true),
    (2, Some(3), false),
    (4, Some(1), true),
    (4, Some(2), true),
    (8, Some(1), true),
    (8, Some(1), false),
    (8, Some(5), true),
    (1, None, true),
    (2, None, true),
    (4, None, true),
    (8, None, true),
    (8, None, false),
];

/// The subset of [`SCHEDULES`] the damaged member sweep runs, which is a
/// member decode per bit flip per schedule: one worker count either side
/// of the wave being smaller than the chain, and both drivers.
#[cfg(all(feature = "parallel", feature = "repo-tests"))]
const DAMAGE_SCHEDULES: &[(usize, Option<usize>, bool)] = &[
    (1, Some(1), true),
    (1, Some(1), false),
    (4, Some(2), true),
    (8, Some(1), true),
    (8, None, true),
];

/// One decoder with the tape path on and its scheduling forced.
#[cfg(all(feature = "parallel", feature = "repo-tests"))]
fn scheduled(window: u64, schedule: (usize, Option<usize>, bool)) -> Rar5Lz {
    let (tape_width, wave_blocks, overlap) = schedule;
    let mut lz = Rar5Lz::new(window, &policy()).expect("window");
    lz.set_parallel(true);
    // The width is a PARAMETER and never a policy field: a memory budget
    // is not a thread count (API 8.4.2). See `internals_h2::scheduled`,
    // and `the_named_width_is_the_width_that_runs` below, which fails
    // without this line.
    lz.set_tape_width(tape_width.max(1));
    lz.set_wave_blocks(wave_blocks);
    lz.set_overlap(overlap);
    lz
}

/// [`decode_archive`] with the tape path's scheduling forced.
#[cfg(all(feature = "parallel", feature = "repo-tests"))]
fn decode_archive_scheduled(
    data: &[u8],
    schedule: (usize, Option<usize>, bool),
) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut decoder: Option<Rar5Lz> = None;
    for member in members(data) {
        if member.directory || member.method == 0 {
            continue;
        }
        if !member.solid || decoder.is_none() {
            decoder = Some(scheduled(member.window, schedule));
        }
        let lz = decoder.as_mut().unwrap();
        let mut sink: Vec<u8> = Vec::with_capacity(member.unpacked as usize);
        let mut source = SliceSource::new(&member.packed);
        lz.member(&mut source, member.unpacked, member.algorithm, &mut sink)
            .unwrap_or_else(|e| panic!("{}: {e}", member.name));
        out.push((member.name.clone(), sink));
    }
    out
}

/// Section 3.8, consequence 2, under the OVERLAP: wave N+1 decodes while
/// wave N is applied, and neither how the waves are cut nor how many
/// workers cut them can change a byte.
///
/// The worker count, the wave length and the overlap itself are all
/// scheduling. This crosses them - one worker to eight, a wave of one
/// block to the carried default, both drivers - against the serial arm on
/// every archive of section 5.2.
#[test]
#[cfg(all(feature = "parallel", feature = "repo-tests"))]
fn every_wave_length_and_worker_count_gives_the_same_bytes() {
    for stem in ARCHIVES {
        let data = archive(stem);
        let serial = decode_archive(&data, false);
        for &schedule in SCHEDULES {
            let got = decode_archive_scheduled(&data, schedule);
            assert_eq!(serial.len(), got.len(), "{stem} at {schedule:?}");
            for (a, b) in serial.iter().zip(&got) {
                assert_eq!(a.0, b.0, "{stem} at {schedule:?}: member order");
                assert!(a.1 == b.1, "{stem}/{} at {schedule:?}: bytes", a.0);
            }
        }
    }
}

/// Section 3.8, consequence 1, under the overlap: a wave decoded ahead of
/// the failure must not move where the member stops or what it raises.
///
/// The overlap decodes further ahead than the wave at a time driver did -
/// a whole wave further - so a damaged member has MORE work running past
/// its own stop than before, which is exactly the work whose errors have
/// to stay deferred.
#[test]
#[cfg(all(feature = "parallel", feature = "repo-tests"))]
fn a_damaged_member_stops_in_the_same_place_at_every_wave_length() {
    let data = archive("h5_text_m5");
    let member = members(&data)
        .into_iter()
        .find(|m| m.method != 0)
        .expect("a compressed member");
    for byte in (0..member.packed.len().min(4096)).step_by(53) {
        for bit in [0u32, 6] {
            let mut packed = member.packed.clone();
            packed[byte] ^= 1 << bit;
            let want = probe_serial(&member, &packed);
            for &schedule in DAMAGE_SCHEDULES {
                let got = probe_scheduled(&member, &packed, schedule);
                assert_eq!(
                    want.0, got.0,
                    "byte {byte} bit {bit} at {schedule:?}: error kind"
                );
                assert!(
                    want.1 == got.1,
                    "byte {byte} bit {bit} at {schedule:?}: output"
                );
            }
        }
    }
}

/// One member decoded, keeping what it produced BEFORE the error: the two
/// arms must stop at the same output position and not merely with the same
/// kind (section 5.5).
#[cfg(all(feature = "parallel", feature = "repo-tests"))]
fn probe(mut lz: Rar5Lz, member: &Member, packed: &[u8]) -> (Result<(), String>, Vec<u8>) {
    let mut sink: Vec<u8> = Vec::new();
    let mut source = SliceSource::new(packed);
    let outcome = lz
        .member(&mut source, member.unpacked, member.algorithm, &mut sink)
        .map_err(|e| format!("{:?}", e.kind()));
    (outcome, sink)
}

#[cfg(all(feature = "parallel", feature = "repo-tests"))]
fn probe_serial(member: &Member, packed: &[u8]) -> (Result<(), String>, Vec<u8>) {
    let mut lz = Rar5Lz::new(member.window, &policy()).expect("window");
    lz.set_parallel(false);
    probe(lz, member, packed)
}

#[cfg(all(feature = "parallel", feature = "repo-tests"))]
fn probe_scheduled(
    member: &Member,
    packed: &[u8],
    schedule: (usize, Option<usize>, bool),
) -> (Result<(), String>, Vec<u8>) {
    probe(scheduled(member.window, schedule), member, packed)
}

/// The pipeline's memory bound, stated in TAPES and checked rather than
/// argued: at most two per lane are alive at once.
///
/// A lane holds the tape it is filling and the one it has handed to the
/// apply stage, and no more, because the hand-over channel holds ONE: the
/// lane parks in `send` until the apply stage takes what is in it. API
/// section 8.2 allows `4 * W` tape buffers for a wave width of `W`, so two
/// per lane is inside it with room to spare, and a member gives every tape
/// back before it returns, which is what makes the count readable here.
#[test]
#[cfg(all(feature = "parallel", feature = "repo-tests"))]
fn the_tapes_in_flight_are_bounded_by_the_lanes() {
    let data = archive("h5_text_m5");
    let member = members(&data)
        .into_iter()
        .find(|m| m.method != 0)
        .expect("a compressed member");
    for workers in [1usize, 2, 4, 8] {
        let mut lz = scheduled(member.window, (workers, None, true));
        for _ in 0..4 {
            let mut sink = NullSink { bytes: 0 };
            let mut source = SliceSource::new(&member.packed);
            lz.member(&mut source, member.unpacked, member.algorithm, &mut sink)
                .expect("the member decodes");
            assert!(
                lz.tapes_held() <= 2 * workers,
                "a ceiling of {workers} left {} tapes: the hand-over has \
                 stopped bounding them",
                lz.tapes_held()
            );
        }
    }
}

/// Section 3.7 and 4.2: a member LONGER than its window, cut into many
/// blocks none of which is big enough to be a batch on its own.
///
/// The drain cadence belongs to the member, not to a block. When it was
/// restarted at every block it never came due, the ring lapped what had
/// not left it, and a 64 MiB text member came out rotated by exactly one
/// window (found by the bench's own byte comparison, 18 Sep 2026). Every
/// vector archive has few enough blocks to hide it.
#[test]
fn a_member_of_many_small_blocks_outlives_its_window() {
    let window = 1u64 << 16;
    let chunk = 8 * 1024usize;
    let blocks = 24;
    let mut want = Vec::with_capacity(chunk * blocks);
    let mut packed = Vec::new();
    let mut seed = 0x1234_5678u32;
    for index in 0..blocks {
        let mut bytes = Vec::with_capacity(chunk);
        for _ in 0..chunk {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            bytes.push((seed >> 24) as u8);
        }
        let mut block = BlockBuilder::default();
        block.literals(&bytes);
        packed.extend_from_slice(&block.finish(true, index + 1 == blocks));
        want.extend_from_slice(&bytes);
    }
    let out = run(&[packed], want.len() as u64, window).unwrap();
    assert_eq!(out.len(), want.len());
    assert!(out == want, "the member came out of order");
}

/// V5-WIDE, the decode half: slot 63 with every extra bit set names
/// `2^32` (section 3.5), a distance no `u32` holds. It must reach the
/// window whole, never wrapped into a near one, and the window answers
/// for it as for any distance past what the stream has produced: a zero
/// for each of the match's bytes, and no fault (section 3.7). Length slot
/// 0 is 2 and so far a distance adds all three of a fresh match's bytes.
#[test]
fn v5_wide_the_widest_distance_gives_zeros() {
    let mut block = BlockBuilder::default();
    block.literals(b"abcdefgh");
    block.fresh(0, 0, 63, (1 << 30) - 1);
    block.literals(b"ij");
    let out = run(&[block.finish(true, true)], 15, 1 << 20).expect("no fault");
    assert_eq!(out, b"abcdefgh\0\0\0\0\0ij");
}

/// Section 3.1: a member is never reported whole when bytes a pending
/// filter held back never reached the sink. The order rule of section 3.6
/// keeps a stream from building such a queue, so this builds it directly:
/// before 27 Sep 2026 the member's end checked what was PRODUCED, and two
/// records on one span answered a 259 byte member OK with 230 bytes.
#[test]
fn a_member_a_filter_kept_short_is_incomplete() {
    use super::filters::{FilterKind, Record};
    use super::output::Span;
    let mut lz = Lz::new(1 << 17, &policy()).unwrap();
    lz.window.begin_member();
    lz.filters.clear();
    for byte in 0..259u32 {
        lz.window.literal(byte as u8);
    }
    let span = Span {
        start: 19,
        length: 211,
    };
    for channels in [19, 14] {
        lz.filters.push_unordered_for_test(Record {
            span,
            kind: FilterKind::Delta(channels),
        });
    }
    let mut sink: Vec<u8> = Vec::new();
    assert_fault(
        lz.finish_member(259, &mut sink),
        Rar5Fault::IncompleteMember,
    );
    assert!(sink.len() < 259, "the drain did keep bytes back");
}

/// Section 4.2 and section 8 item 2: the pending filter queue's bounds are
/// NUMBERS and produce `LimitExceeded` naming the resource, never an
/// unbounded queue and never a generic invalid data error.
#[test]
fn the_filter_queue_bounds_are_limit_exceeded() {
    use super::filters::WAITING_AT_ONCE;
    // The number is the section's floor, which the reference runs whole.
    assert_eq!(WAITING_AT_ONCE, 8_192);
    // At the edge and one past it: records of one byte at distinct
    // positions, all read before a byte is produced, so all wait at once.
    for (records, refused) in [(WAITING_AT_ONCE, false), (WAITING_AT_ONCE + 1, true)] {
        let mut block = BlockBuilder::default();
        for index in 0..records as u32 {
            block.filter(index, 1, 1, 0);
        }
        let outcome = run(&[block.finish(true, true)], records as u64 + 8, 1 << 20);
        let limit = match outcome.as_ref().map_err(|err| err.kind()) {
            Err(ErrorKind::LimitExceeded {
                resource: crate::Resource::Window,
                needed,
                limit,
            }) => Some((*needed, *limit)),
            _ => None,
        };
        if refused {
            let edge = WAITING_AT_ONCE as u64;
            assert_eq!(
                limit,
                Some((edge + 1, edge)),
                "one past the edge: {outcome:?}"
            );
        } else {
            // The block holds records and no byte, so the member is short;
            // what matters is that the queue did not refuse it.
            assert_eq!(limit, None, "at the edge: {outcome:?}");
        }
    }
}

/// The other half of the same bound, and why it cannot fire.
///
/// Bytes BEFORE a pending filter's span may leave for the sink, and a
/// queued span is at most `IGNORED_ABOVE` (4 MiB, section 3.6 "Long
/// records": a longer record is never read), so the hold only ever covers
/// the front filter's own span plus at most one drain batch and one
/// operation past it. `STREAM_FILTER_HOLD_LIMIT` is eight megabytes, so
/// every span section 3.6 runs is admitted (`min(W - 1, 0x400000)` at every
/// dictionary), and the vectors' peak is zero, which is what this measures:
/// the bound is checked on every drain and no legal stream reaches it. An
/// implementation that held every byte from the first pending record
/// onward WOULD reach it, and that is the shape the carried constant
/// exists to refuse.
#[cfg(feature = "repo-tests")]
#[test]
fn the_filter_hold_stays_far_inside_its_bound() {
    use super::filters::{FILTER_HOLD_LIMIT, IGNORED_ABOVE};
    use super::output::MAX_APPEND;
    use crate::carry::c_lz::codec::rar50::FLAT_EMIT_THRESHOLD;
    let ceiling = IGNORED_ABOVE + FLAT_EMIT_THRESHOLD + MAX_APPEND;
    assert!(
        ceiling < FILTER_HOLD_LIMIT,
        "the bound has room over the peak"
    );

    let mut peak = 0u64;
    // The non solid filtered archives: a solid chain shares one decoder
    // and `decode_archive` is what drives those.
    for stem in ["h5_x86_m5", "h5_delta_m5"] {
        let data = archive(stem);
        for member in members(&data) {
            if member.directory || member.method == 0 {
                continue;
            }
            let mut lz = Rar5Lz::new(member.window, &policy()).unwrap();
            let mut sink: Vec<u8> = Vec::new();
            let mut source = SliceSource::new(&member.packed);
            lz.member(&mut source, member.unpacked, member.algorithm, &mut sink)
                .unwrap();
            peak = peak.max(lz.held_bytes());
            assert_eq!(lz.held_bytes(), 0, "{stem}: nothing is held at the end");
        }
    }
    assert_eq!(
        peak, 0,
        "every filter of the vectors completes inside its member"
    );
}

/// Both sides of [`Window::drain`]'s filter split, on the same bytes.
///
/// A span the ring can still serve when it completes is copied ONCE,
/// straight out of the ring and into the scratch the transform runs over. A
/// span the ring LAPS before the span completes cannot be: it has to be
/// held, byte for byte, as it is produced. That second case is the only
/// reason the hold exists, and no vector archive reaches it - the test
/// above measures its peak at zero on every one of them - so the shape is
/// built here by hand. The same 200,000 byte x86 span is decoded over a
/// 64 KiB window, which the span laps three times, and over a 1 MiB
/// window, which it does not lap at all, on both arms.
#[test]
fn the_held_and_the_ring_served_filter_paths_agree() {
    use crate::carry::h_ours::codec::address_filters::x86_pass;

    let length = 200_000usize;
    assert!(length <= super::filters::MAX_FILTER_BLOCK_LENGTH);
    let mut bytes = Vec::with_capacity(length);
    let mut seed = 0x5150_2026u32;
    while bytes.len() < length {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        // One byte in sixteen is a near call, so the transform has plenty
        // of operands to convert and the two paths differ in more than a
        // memcpy.
        bytes.push(if seed >> 28 == 0 {
            0xE8
        } else {
            (seed >> 20) as u8
        });
    }
    let mut want = bytes.clone();
    x86_pass::<false, false, true>(&mut want, 0);
    assert_ne!(want, bytes, "the transform changed something");

    let mut block = BlockBuilder::default();
    block.filter(0, length as u32, 1, 0);
    block.literals(&bytes);
    let packed = block.finish(true, true);

    for parallel in [false, true] {
        for (window, how) in [
            (1u64 << 16, "lapped, so held"),
            (1 << 20, "still in the ring"),
        ] {
            let mut lz = Lz::new(window, &policy()).unwrap();
            lz.set_parallel(parallel);
            let mut sink: Vec<u8> = Vec::new();
            let mut source = SliceSource::new(&packed);
            lz.member(&mut source, length as u64, 0, &mut sink).unwrap();
            assert_eq!(sink, want, "{how}, parallel {parallel}");
            assert_eq!(lz.held_bytes(), 0, "nothing is held at the end");
        }
    }
}

/// THE HOLD IS SHIFTED ONCE A DRAIN, not once a span. A member of about
/// 3 MiB covered end to end by 1000 byte spans has a span straddling every
/// drain point (a drain is every 512 KiB over the 1 MiB ring floor, which
/// no 1000 byte boundary meets), so from the first drain on everything
/// goes through the hold and each drain serves about five hundred spans
/// out of it. Shifted after every span, the hold moved many times what
/// went into it (`hold_memmove` against `ring_to_hold`); shifted once a
/// drain, it moves at most what went in.
/// Every arm and both windows still agree on the bytes.
#[test]
fn the_hold_is_shifted_once_a_drain_not_once_a_span() {
    let short = 1000usize;
    let spans = 3200usize;
    let length = spans * short;
    let bytes: Vec<u8> = (0..length as u32)
        .map(|i| {
            if i % 13 == 0 {
                0xE8
            } else {
                (i * 29 + i / 11) as u8
            }
        })
        .collect();
    let mut block = BlockBuilder::default();
    for index in 0..spans {
        block.filter((index * short) as u32, short as u32, 1, 0);
    }
    block.literals(&bytes);
    let packed = block.finish(true, true);

    let mut seen: Option<Vec<u8>> = None;
    for parallel in [false, true] {
        for window in [1u64 << 16, 1 << 20] {
            let mut lz = Lz::new(window, &policy()).unwrap();
            lz.set_parallel(parallel);
            let mut sink: Vec<u8> = Vec::new();
            let mut source = SliceSource::new(&packed);
            lz.member(&mut source, length as u64, 0, &mut sink).unwrap();
            assert_eq!(sink.len(), length, "the member is its declared size");
            assert_eq!(lz.held_bytes(), 0, "nothing is held at the end");
            if !parallel && window == 1 << 16 {
                let c = lz.drain_counts();
                eprintln!("the hold's census: {c:?}");
                assert!(c.drains >= 5, "the member drains mid-way: {c:?}");
                assert!(
                    c.spans_held as usize >= spans / 2,
                    "the short spans are served from the hold: {c:?}"
                );
                assert!(
                    c.hold_memmove <= c.ring_to_hold,
                    "the hold moves at most what went into it: {c:?}"
                );
            }
            match &seen {
                None => seen = Some(sink),
                Some(first) => assert_eq!(
                    *first, sink,
                    "every arm and every window agree, parallel {parallel}"
                ),
            }
        }
    }
}

/// The shipped scan-then-convert x86 pass writes exactly what the walking
/// form wrote, on every direction, both record types and both the RAR 5
/// and RAR 3 offset rules.
///
/// The two forms are equivalent only because the scan reads OPCODE bytes
/// and the conversion writes OPERAND bytes, and the five byte skip keeps
/// an accepted operand out of the scan. This walks the shapes that break
/// that if it is got wrong: triggers packed closer than five bytes apart,
/// a trigger in the last five bytes where there is no whole operand, a
/// trigger straddling the eight byte scan stride, and a long barren run
/// which sends the scan into its vector search and must come back to the
/// trigger rather than past it.
///
/// Shown to FAIL when broken, each checked by making the change and
/// running this: a resume cursor of `position + 4`, the `position < resume`
/// test dropped, and the byte re-check after the SWAR mask dropped. The one
/// thing here that is NOT load bearing is rounding the vector search's
/// answer back to the scan's stride, which is an optimisation: the word
/// scan finds the trigger either way, and this test passes without it.
#[test]
fn the_walking_and_the_split_x86_passes_agree() {
    use crate::carry::h_ours::codec::address_filters::{
        x86_pass, x86_pass_adaptive, x86_pass_walking,
    };

    let cases = x86_pass_equivalence_cases();

    for (index, case) in cases.iter().enumerate() {
        for offset in [0u32, 1, 5, 0x00FF_FFFF, 0x0100_0000, 0x8000_0000, u32::MAX] {
            // THE ADAPTIVE against BOTH, which is the property that lets
            // it choose at all: it runs the split's scan over the first
            // batch and may then hand the rest to the walking form, so it
            // is only sound if the two agree everywhere AND the handover
            // position is one the format's rule allows a scan to resume
            // at. A single wrong byte at that seam would show here and
            // nowhere else in this file.
            for (jump, rar5, encode, what) in [
                (false, true, false, "decode, call, rar5"),
                (true, true, false, "decode, call+jump, rar5"),
                (false, false, false, "decode, call, rar3"),
                (true, false, false, "decode, call+jump, rar3"),
                (true, false, true, "encode, call+jump, rar3"),
            ] {
                let mut walked = case.clone();
                let mut adaptive = case.clone();
                match (encode, jump, rar5) {
                    (false, false, true) => {
                        x86_pass_walking::<false, false, true>(&mut walked, offset);
                        x86_pass_adaptive::<false, false, true>(&mut adaptive, offset);
                    }
                    (false, true, true) => {
                        x86_pass_walking::<false, true, true>(&mut walked, offset);
                        x86_pass_adaptive::<false, true, true>(&mut adaptive, offset);
                    }
                    (false, false, false) => {
                        x86_pass_walking::<false, false, false>(&mut walked, offset);
                        x86_pass_adaptive::<false, false, false>(&mut adaptive, offset);
                    }
                    (false, true, false) => {
                        x86_pass_walking::<false, true, false>(&mut walked, offset);
                        x86_pass_adaptive::<false, true, false>(&mut adaptive, offset);
                    }
                    _ => {
                        x86_pass_walking::<true, true, false>(&mut walked, offset);
                        x86_pass_adaptive::<true, true, false>(&mut adaptive, offset);
                    }
                }
                assert_eq!(
                    walked, adaptive,
                    "case {index}, adaptive against walking, {what}, f {offset}"
                );
            }
            let mut walked = case.clone();
            let mut split = case.clone();
            x86_pass_walking::<false, false, true>(&mut walked, offset);
            x86_pass::<false, false, true>(&mut split, offset);
            assert_eq!(
                walked, split,
                "case {index}, decode, call, rar5, f {offset}"
            );

            let mut walked = case.clone();
            let mut split = case.clone();
            x86_pass_walking::<false, true, true>(&mut walked, offset);
            x86_pass::<false, true, true>(&mut split, offset);
            assert_eq!(
                walked, split,
                "case {index}, decode, call+jump, rar5, f {offset}"
            );

            let mut walked = case.clone();
            let mut split = case.clone();
            x86_pass_walking::<true, true, false>(&mut walked, offset);
            x86_pass::<true, true, false>(&mut split, offset);
            assert_eq!(
                walked, split,
                "case {index}, encode, call+jump, rar3, f {offset}"
            );

            let mut walked = case.clone();
            let mut split = case.clone();
            x86_pass_walking::<false, false, false>(&mut walked, offset);
            x86_pass::<false, false, false>(&mut split, offset);
            assert_eq!(
                walked, split,
                "case {index}, decode, call, rar3, f {offset}"
            );
        }
    }
}

/// A filtered member whose spans do NOT divide the drain's batch, so the
/// drain serves spans out of the ring and out of the hold in the same
/// member, and the transform runs across both.
///
/// The code leg's own shape is 256 spans of 65,536 bytes against a 1 MiB
/// drain batch, which divides exactly; a member whose records are a size
/// the batch does not divide crosses the boundary on nearly every drain,
/// and a span released early or applied to the wrong bytes shows up as a
/// byte difference against the transform run over the whole member.
///
/// Shown to FAIL when broken: releasing the hold's front span before the
/// hold holds all of it makes this test and
/// `the_held_and_the_ring_served_filter_paths_agree` disagree with the
/// transform's own output. (Serving a span that starts behind the emission
/// cursor out of the ring is caught by
/// `an_overlapping_filter_span_keeps_going_through_the_hold`, which is
/// where that rule belongs.)
#[test]
fn filter_spans_that_straddle_the_drain_batch_are_applied_once_and_in_place() {
    use crate::carry::h_ours::codec::address_filters::x86_pass;

    let span = 100_003usize;
    let spans = 24usize;
    let length = span * spans;
    let mut bytes = Vec::with_capacity(length);
    let mut seed = 0x2109_2026u32;
    while bytes.len() < length {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        bytes.push(match seed >> 27 {
            0 | 1 => 0xE8,
            2 => 0xE9,
            _ => (seed >> 13) as u8,
        });
    }
    let mut want = bytes.clone();
    for index in 0..spans {
        let at = index * span;
        x86_pass::<false, true, true>(&mut want[at..at + span], at as u32);
    }
    assert_ne!(want, bytes, "the transform changed something");

    let mut block = BlockBuilder::default();
    for index in 0..spans {
        block.filter((index * span) as u32, span as u32, 2, 0);
    }
    block.literals(&bytes);
    let packed = block.finish(true, true);

    for parallel in [false, true] {
        for (window, how) in [
            (1u64 << 17, "the ring laps every span"),
            (1 << 22, "the ring holds several spans"),
        ] {
            let mut lz = Lz::new(window, &policy()).unwrap();
            lz.set_parallel(parallel);
            let mut sink: Vec<u8> = Vec::new();
            let mut source = SliceSource::new(&packed);
            lz.member(&mut source, length as u64, 0, &mut sink).unwrap();
            assert_eq!(sink.len(), length, "{how}, parallel {parallel}");
            assert_eq!(sink, want, "{how}, parallel {parallel}");
            assert_eq!(lz.held_bytes(), 0, "nothing is held at the end");
        }
    }
}

/// Two filter records whose spans OVERLAP, which section 3.6 neither
/// requires nor forbids.
///
/// The drain serves a complete span straight out of the ring, but only
/// when the span starts at or after the emission cursor. A span reaching
/// back BEHIND it goes down the hold path, where it has always gone,
/// because the hold takes the next `length` bytes of what it is holding
/// and serving the span's own offsets out of the ring instead would
/// answer a question section 3.6 does not ask: what the bytes of an
/// overlapping span are. That is an open specification question, and this test pins
/// the behaviour so a later change cannot move it without noticing.
///
/// The shape is a short span that completes first, then one starting
/// inside it, so the second is behind the cursor when it reaches the
/// front.
#[test]
fn an_overlapping_filter_span_keeps_going_through_the_hold() {
    let length = 200_000usize;
    let bytes: Vec<u8> = (0..length as u32).map(|i| (i * 31 + i / 7) as u8).collect();
    let mut block = BlockBuilder::default();
    block.filter(0, 4_096, 1, 0);
    block.filter(64, 100, 1, 0);
    block.literals(&bytes);
    let packed = block.finish(true, true);

    let mut seen: Option<Vec<u8>> = None;
    for parallel in [false, true] {
        for window in [1u64 << 16, 1 << 20] {
            let mut lz = Lz::new(window, &policy()).unwrap();
            lz.set_parallel(parallel);
            let mut sink: Vec<u8> = Vec::new();
            let mut source = SliceSource::new(&packed);
            lz.member(&mut source, length as u64, 0, &mut sink).unwrap();
            assert_eq!(sink.len(), length, "the member is its declared size");
            match &seen {
                None => seen = Some(sink),
                Some(first) => assert_eq!(
                    *first, sink,
                    "every arm and every window agree, parallel {parallel}"
                ),
            }
        }
    }
}

/// Section 3.1 at sizes a test machine cannot produce: a member's declared
/// unpacked size is a 64 bit field, members above 4 GiB are ordinary
/// traffic, and `armv7-unknown-linux-musleabihf` is a shipped artifact.
///
/// Every machine this project is built on is 64-bit, so until this module nothing
/// here had ever run the arithmetic a 32-bit target runs. These tests take
/// the two shapes that made that possible: the counters are SEEDED past
/// 4 GiB rather than produced, and the room-left arithmetic takes the
/// pointer width as a PARAMETER, so `u32::MAX` drives what a 32-bit build
/// computes on a 64-bit host.
///
/// WHAT THESE DO NOT DO: they do not run on 32-bit hardware. No 32-bit
/// host was available and `cargo test --target
/// i686-unknown-linux-gnu` is not runnable on macOS; `make cross` keeps
/// the 32-bit target COMPILING and clippy-clean, and a real 32-bit test
/// run is not done yet: it needs a 32-bit host.
#[cfg(test)]
mod pointer_width {
    use super::super::output::{NoFilters, Window};

    const GIB: u64 = 1 << 30;
    /// The largest count a 32-bit `usize` holds.
    const U32_MAX: u64 = u32::MAX as u64;

    /// `Window::produced` is the MEMBER's count, and it stays whole past
    /// 4 GiB. Before this it returned a `usize`, so on a 32-bit target it
    /// truncated inside the accessor and every termination test in the
    /// decode loop compared a wrapped count against the true size.
    #[test]
    fn a_members_count_stays_whole_past_four_gib() {
        let mut window = Window::new(1 << 16, u64::MAX).unwrap();
        for (stream, base, expect) in [
            (U32_MAX - 1, 0, U32_MAX - 1),
            (U32_MAX, 0, U32_MAX),
            (U32_MAX + 1, 0, U32_MAX + 1),
            (4 * GIB + 30, 0, 4 * GIB + 30),
            // The solid-chain shape: the member starts 5 GiB into the
            // stream and has produced 1 GiB of its own.
            (6 * GIB, 5 * GIB, GIB),
            (9 * GIB + 7, 4 * GIB, 5 * GIB + 7),
        ] {
            window.seed_counters_for_test(stream, base);
            assert_eq!(window.produced(), expect, "stream {stream}, base {base}");
            assert_eq!(window.stream_produced(), stream);
            // What the accessor used to answer on a 32-bit target.
            let truncated = expect as u32 as u64;
            if truncated != expect {
                assert_ne!(window.produced(), truncated);
            }
        }
    }

    /// The decode loop's termination test, at the sizes where a truncated
    /// count gets it wrong. `4 GiB + 30` produced against `4 GiB + 20`
    /// declared is DONE; truncated to 30 it reads as not done, and the
    /// member over-produces with no error at all.
    #[test]
    fn the_termination_test_is_right_either_side_of_four_gib() {
        let mut window = Window::new(1 << 16, u64::MAX).unwrap();
        // The last field says whether a TRUNCATED count gets this case
        // wrong. It does not get every case wrong: truncation always makes
        // the count look SMALLER, so it reads as "not done" either way
        // wherever the member genuinely has bytes left. What it cannot do
        // is notice that a member is finished, which is the over-produce
        // case and the one that loses bytes.
        for (produced, unpacked, done, truncating_differs) in [
            (U32_MAX, U32_MAX, true, false),
            (U32_MAX - 1, U32_MAX, false, false),
            (4 * GIB + 30, 4 * GIB + 20, true, true),
            (4 * GIB + 10, 4 * GIB + 20, false, false),
            (8 * GIB, 8 * GIB, true, true),
        ] {
            window.seed_counters_for_test(produced, 0);
            assert_eq!(window.produced() >= unpacked, done, "{produced}/{unpacked}");
            // The truncating form, stated so the defect is written down
            // rather than only fixed.
            let truncated = produced as u32 as u64;
            assert_eq!(
                (truncated >= unpacked) != done,
                truncating_differs,
                "a truncated count gets {produced}/{unpacked} \
                 {}, and the table says otherwise",
                if truncating_differs { "right" } else { "wrong" }
            );
        }
    }

    /// The emission path still works with the counters seeded past 4 GiB:
    /// the offsets it hands `ring_slices` are `u64` now, and what it
    /// derives from them - the distance back of the write point, and the
    /// span's length - are the only figures it narrows.
    #[test]
    fn a_drain_works_with_the_counters_past_four_gib() {
        let mut window = Window::new(1 << 16, u64::MAX).unwrap();
        window.seed_counters_for_test(7 * GIB, 6 * GIB);
        let mut sink = crate::rar5_lz::output::NullSink { bytes: 0 };
        let bytes: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
        window.literals(&bytes);
        assert_eq!(window.produced(), GIB + 4096);
        window.drain(&mut sink, &mut NoFilters, true).unwrap();
        assert_eq!(sink.bytes, 4096);
    }
}
