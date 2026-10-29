//! The parallel walk: the hints it leaves are the serial walk's, at any
//! width and across a slide.

use super::*;

/// The tree's walk, in parallel, must leave the SERIAL walk's hints.
///
/// The walk deals a chunk into bins of buckets and offers them biggest
/// first to whichever walker is free, so which walker walks a bucket is
/// settled by the timing of the run and by nothing in the input. What
/// makes that sound is that a bin holds WHOLE buckets and a bucket's
/// positions stay in order inside it, so every descent reads and writes
/// only its own bucket's nodes and sees them in the order one walker
/// would have. This is that argument checked rather than made: the hints
/// a walk leaves are compared slot for slot against one walker's, at
/// every count the API pins and at the cap.
///
/// It is a sharper instrument than the encoders' own byte identity tests,
/// which see the walk only through a parse: a hint the walk got wrong is
/// a match the parse may not have taken.
#[cfg(feature = "parallel")]
#[test]
fn the_parallel_walk_leaves_the_serial_walks_hints() {
    use crate::carry::h_ours::codec::rar50::tree::{empty_slots, BucketTrees};

    // Text of a small vocabulary: the four byte buckets come out as
    // skewed as real text's, which is what the offer has to balance and
    // what a bin boundary has to hold whole.
    let span = rarkit_testdata::chatter_of(0x7761_6c6b, 48, 1_500_000);
    // Two ranges: one of several chunks, and a short one after it, which
    // is the arm where the bin count follows the chunk rather than the
    // walker count.
    let split = 1_300_000;
    let stride = 4;
    let walk = |threads: usize| {
        let mut tree = BucketTrees::new(1 << 20);
        let mut hints = Vec::new();
        for range in [0..split, split..span.len()] {
            let slots = empty_slots(range.len() * stride);
            tree.advance_range(&span, range, Some(&slots), stride, threads);
            hints.extend(slots.iter().map(|slot| slot.load(Ordering::Relaxed)));
        }
        hints
    };
    let serial = walk(1);
    assert!(
        serial.iter().filter(|&&distance| distance != 0).count() > 100_000,
        "the walk found almost nothing, so the comparison would prove nothing"
    );
    // Past twelve too: the cap follows the machine's cores
    // (`drive::tree_walkers_most`), and a walker that never gets a thread
    // holds nothing up, so a narrow pool walks these as well.
    for threads in [2usize, 4, 8, 12, 16, 20, 32, 40] {
        assert!(
            walk(threads) == serial,
            "{threads} walkers left different hints from one"
        );
    }
}

/// Text one chunk of the tree walk long, then a chunk of one byte, and so
/// on for `chunks` chunks: the chunk of one byte deals almost every bin
/// EMPTY, between two chunks that fill them all with the same buckets.
#[cfg(feature = "parallel")]
fn text_between_empty_chunks(chunks: usize) -> Vec<u8> {
    let chunk = 256 << 10;
    let text = few_words(chunk, 0x7E57);
    let mut span = Vec::with_capacity(chunks * chunk);
    for index in 0..chunks {
        if index % 2 == 0 {
            span.extend_from_slice(&text);
        } else {
            span.resize(span.len() + chunk, 0);
        }
    }
    span
}

/// Holds the walk's test stall on ([`WALK_STALLS`]) while it lives.
///
/// [`WALK_STALLS`]: crate::carry::h_ours::codec::rar50::tree::WALK_STALLS
#[cfg(feature = "parallel")]
struct WalkStalled;

#[cfg(feature = "parallel")]
impl WalkStalled {
    fn new() -> Self {
        use crate::carry::h_ours::codec::rar50::tree::WALK_STALLS;
        WALK_STALLS.fetch_add(1, Ordering::SeqCst);
        WalkStalled
    }
}

#[cfg(feature = "parallel")]
impl Drop for WalkStalled {
    fn drop(&mut self) {
        use crate::carry::h_ours::codec::rar50::tree::WALK_STALLS;
        WALK_STALLS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A bucket is walked in order past a chunk that has no position for it,
/// with one walker held back (the defect of 1 Oct 2026: level 4 and 5
/// archives of one big member that differed run to run on a loaded box).
///
/// The ring leaves room for eight chunks in flight. Chunk 0 is text,
/// chunk 1 one byte, chunk 2 the same text: with a walker asleep in a
/// bin of chunk 0, the others reach the same bin of chunk 2 across the
/// empty bin of chunk 1. Walked then, before chunk 0's, those positions
/// find nothing 512 KiB back and leave other hints than the serial walk.
#[cfg(feature = "parallel")]
#[test]
fn the_parallel_walk_keeps_a_bucket_in_order_past_an_empty_bin() {
    use crate::carry::h_ours::codec::rar50::tree::{empty_slots, BucketTrees};

    let span = text_between_empty_chunks(7);
    let stride = 1;
    let walk = |threads: usize| {
        let mut tree = BucketTrees::new(4 << 20);
        tree.window = 1 << 20;
        let slots = empty_slots(span.len() * stride);
        tree.advance_range(&span, 0..span.len(), Some(&slots), stride, threads);
        slots
            .iter()
            .map(|slot| slot.load(Ordering::Relaxed))
            .collect::<Vec<u32>>()
    };
    let serial = walk(1);
    let _stalled = WalkStalled::new();
    for threads in [4usize, 8] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("a pool");
        let wide = pool.install(|| walk(threads));
        let moved = wide.iter().zip(&serial).filter(|(a, b)| a != b).count();
        assert!(
            moved == 0,
            "{threads} walkers, one held back: {moved} hints differ from the serial walk's"
        );
    }
}

/// Holds the walk's cap at `drive::WIDE_WALK_FOR_TEST` while it lives,
/// so a pool wider than twelve walks at its width on any machine.
#[cfg(feature = "parallel")]
struct WalkWide;

#[cfg(feature = "parallel")]
impl WalkWide {
    fn new() -> Self {
        super::drive::WIDE_WALKS.fetch_add(1, Ordering::SeqCst);
        WalkWide
    }
}

#[cfg(feature = "parallel")]
impl Drop for WalkWide {
    fn drop(&mut self) {
        super::drive::WIDE_WALKS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One thread's bytes against four and eight threads' with a walker held
/// back ([`WalkStalled`]), at levels 4 and 5; and against twenty and
/// thirty-six threads', past the twelve walkers the cap stood at until 1
/// Oct 2026, with the cap held wide ([`WalkWide`]) so that a machine of
/// few cores walks them too.
#[cfg(feature = "parallel")]
fn a_held_back_walker_moves_no_byte(what: &str, run: &(dyn Fn(u8) -> Vec<u8> + Sync)) {
    let in_pool = |threads: usize, level: u8| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("a pool")
            .install(|| run(level))
    };
    for level in [4u8, 5] {
        let one = in_pool(1, level);
        let _stalled = WalkStalled::new();
        for threads in [4usize, 8] {
            assert!(
                in_pool(threads, level) == one,
                "level {level}, {threads} threads, {what}: a byte moved"
            );
        }
        let _wide = WalkWide::new();
        for threads in [20usize, 36] {
            assert!(
                in_pool(threads, level) == one,
                "level {level}, {threads} threads and as many walkers, {what}: a byte moved"
            );
        }
    }
}

/// The cap on the walk is twelve, and on macOS the machine's fast cores
/// where they are more; a member that keeps the tree by its own class
/// walks at that, or on x86-64 Linux at the machine's physical cores of
/// one kind where they are more.
#[cfg(feature = "parallel")]
#[test]
fn the_walk_cap_is_the_cores_and_never_under_twelve() {
    use super::drive::{tree_walkers_by_class, tree_walkers_most, TREE_WALKERS_FLOOR, WIDE_WALKS};
    // A test holding the cap wide beside this one moves the figure, so it
    // is read with no such test on either side of the reading.
    let before = WIDE_WALKS.load(Ordering::SeqCst);
    let most = tree_walkers_most();
    let by_class = tree_walkers_by_class();
    let after = WIDE_WALKS.load(Ordering::SeqCst);
    if before == 0 && after == 0 {
        #[cfg(target_os = "macos")]
        assert_eq!(
            most,
            TREE_WALKERS_FLOOR.max(crate::cores::performance().unwrap_or(0))
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(most, TREE_WALKERS_FLOOR);
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(by_class, most.max(crate::cores::alike().unwrap_or(0)));
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        assert_eq!(by_class, most);
    }
    assert!(most >= TREE_WALKERS_FLOOR);
    assert!(by_class >= most || before != after);
}

/// The same through the encoder, where the defect showed: a NON-SOLID
/// member longer than the reach (the full reach, the wide ring)
/// writes the bytes of one thread with a walker held back.
#[cfg(feature = "parallel")]
#[test]
fn a_held_back_walker_moves_no_byte_of_a_long_member() {
    let dictionary = 1u32 << 20;
    let input = text_between_empty_chunks(12);
    a_held_back_walker_moves_no_byte("a long member", &|level| {
        rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, dictionary)).encode(&input)
    });
}

/// And a SOLID run (the wide ring), two members of it.
#[cfg(feature = "parallel")]
#[test]
fn a_held_back_walker_moves_no_byte_of_a_solid_run() {
    let dictionary = 1u32 << 20;
    let input = text_between_empty_chunks(12);
    a_held_back_walker_moves_no_byte("a solid run", &|level| {
        let mut options = rar5::EncodeOptions::for_level(level, dictionary);
        options.plan.wide_ring = true;
        let mut encoder = rar5::Rar5Encoder::new(options);
        encoder.reset_history();
        let mut packed = Vec::new();
        for member in input.chunks(input.len() / 2) {
            encoder.stage(member, true);
            for bytes in encoder.flush().iter() {
                packed.extend_from_slice(bytes);
            }
        }
        packed
    });
}

/// Several contiguous ranges walked in ONE call (`advance_ranges`), each
/// position compared up to its own range's end, leave exactly the hints
/// of one `advance_range` call a range, at any walker count: which is
/// what lets a solid set's small members be walked together (the solid
/// -m5 work, 28 Sep 2026) without moving a byte.
///
/// The ranges are short, as a set of small members' are, and of uneven
/// lengths, down to three bytes (no position with four bytes inside its
/// range, so none is indexed); the text repeats across their ends, so a
/// comparison that ran past a range's end would find longer matches and
/// leave other hints.
#[cfg(feature = "parallel")]
#[test]
fn ranges_walked_together_leave_the_hints_of_one_call_a_range() {
    use crate::carry::h_ours::codec::rar50::tree::{empty_slots, BucketTrees};

    let span = few_words(1_200_000, 7);
    let stride = 4;
    let mut ends = Vec::new();
    let mut at = 0usize;
    let mut state = 0x9E37_79B9u32;
    while at < span.len() {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let len = match state >> 29 {
            0 => 3,
            1 => 40_000 + (state as usize >> 8) % 30_000,
            _ => 200 + (state as usize >> 8) % 9_000,
        };
        at = (at + len).min(span.len());
        ends.push(at);
    }
    let narrow_apart = {
        let mut tree = BucketTrees::new(1 << 20);
        let mut hints = Vec::new();
        let mut from = 0;
        for &end in &ends {
            let slots = empty_slots((end - from) * stride);
            tree.advance_range(&span, from..end, Some(&slots), stride, 1);
            hints.extend(slots.iter().map(|slot| slot.load(Ordering::Relaxed)));
            from = end;
        }
        hints
    };
    assert!(
        narrow_apart
            .iter()
            .filter(|&&distance| distance != 0)
            .count()
            > 100_000,
        "the walk found almost nothing, so the comparison would prove nothing"
    );
    // Two trees: one whose ring leaves room for one chunk of drift, where
    // every chunk ends at a barrier, and one whose ring leaves room for
    // several (a 1 MiB window in a 4 MiB ring, as a solid run's widened
    // ring does), where chunks overlap.
    let trees = || {
        let narrow = BucketTrees::new(1 << 20);
        let mut wide = BucketTrees::new(4 << 20);
        wide.window = 1 << 20;
        [narrow, wide]
    };
    let apart: Vec<Vec<u32>> = trees()
        .into_iter()
        .map(|mut tree| {
            let mut hints = Vec::new();
            let mut from = 0;
            for &end in &ends {
                let slots = empty_slots((end - from) * stride);
                tree.advance_range(&span, from..end, Some(&slots), stride, 1);
                hints.extend(slots.iter().map(|slot| slot.load(Ordering::Relaxed)));
                from = end;
            }
            hints
        })
        .collect();
    assert!(
        apart[0] != apart[1],
        "the two windows found the same matches, so the wide one proves nothing"
    );
    // Passes of several ranges each, as the driver walks a batch of small
    // members, and one pass of them all, five chunks long.
    for (threads, per_pass) in [1usize, 2, 8, 12]
        .into_iter()
        .flat_map(|threads| [(threads, 37), (threads, ends.len())])
    {
        for (which, mut tree) in trees().into_iter().enumerate() {
            let apart = &apart[which];
            let mut hints = Vec::new();
            let mut from = 0;
            for pass in ends.chunks(per_pass) {
                let end = *pass.last().expect("a pass has a range");
                // Filled with a value no walk writes: the walk writes every
                // slot of every position it visits, and it visits all but
                // the span's last three, which the driver clears itself.
                let slots = empty_slots((end - from) * stride);
                for (index, slot) in slots.iter().enumerate() {
                    let pos = from + index / stride;
                    let junk = if pos + 3 >= span.len() { 0 } else { u32::MAX };
                    slot.store(junk, Ordering::Relaxed);
                }
                tree.advance_ranges(&span, from, pass, Some(&slots), stride, threads);
                hints.extend(slots.iter().map(|slot| slot.load(Ordering::Relaxed)));
                from = end;
            }
            assert!(
                hints == *apart,
                "{threads} walkers, passes of {per_pass}: ranges walked together left different \
                 hints (tree {which})"
            );
        }
    }
}

/// A SOLID run whose history slides keeps its tree's index across the
/// slide (spec H3 section 4), and every member still decodes in
/// the one window the run shares. The run after it, once the history is
/// reset, writes exactly what a fresh engine writes: the heads the dropped
/// bytes wrote, which a forget over the history cannot reach, are cleared.
/// A 256 KiB dictionary slides every megabyte or so, which keeps the run
/// short.
#[test]
fn a_solid_run_keeps_its_index_across_a_slide_and_decodes() {
    let dictionary = 256u32 << 10;
    let members_of = |mut state: u64, most: usize| {
        let mut members = Vec::new();
        let mut total = 0;
        while total < most {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let len = match (state >> 60) % 4 {
                0 => 200_000 + (state >> 20) as usize % 56_000,
                _ => 1_000 + (state >> 20) as usize % 40_000,
            };
            members.push(few_words(len, state));
            total += len;
        }
        members
    };
    let encoder = || {
        let mut options = rar5::EncodeOptions::for_level(5, dictionary);
        options.plan.wide_ring = true;
        let mut encoder = rar5::Rar5Encoder::new(options);
        encoder.reset_history();
        encoder
    };
    let run = |encoder: &mut rar5::Rar5Encoder, members: &[Vec<u8>]| {
        let mut packed = Vec::new();
        let mut at = 0;
        while at < members.len() {
            let from = at;
            while at < members.len() && (at == from || encoder.may_stage(members[at].len())) {
                encoder.stage(&members[at], true);
                at += 1;
            }
            packed.extend(encoder.flush().iter().cloned());
        }
        packed
    };
    let long = members_of(0x51, 4 << 20);
    let mut slid = encoder();
    let packed = run(&mut slid, &long);
    assert!(
        slid.slid_for_test(),
        "no slide kept the index, so the run proves nothing"
    );
    let policy = crate::memory::MemoryPolicy {
        working_limit: u64::MAX,
        max_window: 1 << 33,
        ..crate::memory::MemoryPolicy::default()
    };
    let mut lz = crate::rar5_lz::Rar5Lz::new(u64::from(dictionary), &policy).expect("a window");
    for (index, (member, packed)) in long.iter().zip(&packed).enumerate() {
        let mut sink: Vec<u8> = Vec::new();
        let mut source = crate::rar5_lz::SliceSource::new(packed);
        lz.member(&mut source, member.len() as u64, 0, &mut sink)
            .expect("decodes");
        assert!(sink == *member, "member {index} of the slid run");
    }
    slid.reset_history();
    let next = members_of(0x77, 1 << 20);
    let after = run(&mut slid, &next);
    let fresh = run(&mut encoder(), &next);
    assert!(
        after == fresh,
        "the run after a slid one is not a fresh run"
    );
}
