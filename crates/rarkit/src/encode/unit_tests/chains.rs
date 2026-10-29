//! The chain levels: the chains built across the pool, the streamed
//! member, the sliding waves, the backward extension, the fast parse and
//! level 5's choice between the chains and the tree.

use super::*;

#[test]
fn the_dense_code_is_complete_within_fifteen_and_as_cheap_as_the_package_merge() {
    // A carried set's lengths come from the plain Huffman code
    // where it is no deeper than 15, else from the package merge: either
    // way complete, within depth 15, and exactly as many bits as the
    // package merge's optimal code, on shallow and on skewed inputs.
    let mut state = 0x148u64;
    for round in 0..400 {
        let symbols = [20usize, 44, 64, 306, 430][round % 5];
        let skew = 1 + (round % 7) as u32 * 5;
        let frequency: Vec<u32> = (0..symbols)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let r = (state >> 33) as u32;
                if round % 3 == 0 {
                    1 + r % 50
                } else {
                    1 + (r % 1000).pow(1 + skew % 3) % (1 << (8 + skew % 12))
                }
            })
            .collect();
        let mut dense = vec![0u8; symbols];
        let mut merge = vec![0u8; symbols];
        code_lengths_dense(&frequency, &mut dense);
        code_lengths(&frequency, &mut merge);
        assert!(is_complete(&dense), "round {round}: incomplete");
        assert!(
            dense.iter().all(|&l| l <= MAX_CODE_LEN),
            "round {round}: too deep"
        );
        let cost = |lengths: &[u8]| -> u64 {
            frequency
                .iter()
                .zip(lengths)
                .map(|(&f, &l)| u64::from(f) * u64::from(l))
                .sum()
        };
        assert_eq!(cost(&dense), cost(&merge), "round {round}: not optimal");
    }
}

/// The chains' pass built across the pool (`chain::Build`) leaves every
/// link the one-thread pass leaves, so the packed bytes cannot move: at
/// levels 1 to 3 of both formats, at several pool widths against one
/// thread with the build off, over text, noise and a mixture of the two.
/// Three shapes reach it: a windowed member whose history slides (the
/// relink after a slide is the build's first pieces), one region of
/// several waves' worth of pieces, and a solid batch of members of uneven
/// lengths, whose pieces stop at each member's end, the last three
/// positions of which no piece links.
#[cfg(feature = "parallel")]
#[test]
fn the_chains_built_across_the_pool_are_the_passes_bytes() {
    let dictionary = 256u32 << 10;
    let mixed: Vec<u8> = few_words(3 << 20, 3)
        .chunks(300_000)
        .zip(nothing_to_find(1 << 20, 5).chunks(100_000))
        .flat_map(|(text, noise)| text.iter().chain(noise).copied())
        .collect();
    let inputs = [
        ("text", few_words(5 << 20, 11)),
        ("noise", nothing_to_find(2 << 20, 13)),
        ("mixed", mixed),
    ];
    let mut members = Vec::new();
    let mut state = 0x9Eu64;
    let mut total = 0;
    while total < 3 << 20 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let len = match (state >> 60) % 3 {
            0 => 300_000 + (state >> 20) as usize % 900_000,
            _ => 3 + (state >> 20) as usize % 70_000,
        };
        members.push(few_words(len, state));
        total += len;
    }
    trait Chunked {
        fn chunk(&mut self, chunk: &[u8], last: bool, out: &mut Vec<u8>);
        fn restart(&mut self);
        fn build_from(&mut self, width: usize);
    }
    impl Chunked for rar5::Rar5Encoder {
        fn chunk(&mut self, chunk: &[u8], last: bool, out: &mut Vec<u8>) {
            self.encode_chunk(chunk, last, out);
        }
        fn restart(&mut self) {
            self.reset_history();
        }
        fn build_from(&mut self, width: usize) {
            self.set_chain_build_from(width);
        }
    }
    impl Chunked for rar29::Rar29Encoder {
        fn chunk(&mut self, chunk: &[u8], last: bool, out: &mut Vec<u8>) {
            self.encode_chunk(chunk, last, out);
        }
        fn restart(&mut self) {
            self.reset_history();
        }
        fn build_from(&mut self, width: usize) {
            self.set_chain_build_from(width);
        }
    }
    fn windowed<E: Chunked>(encoder: &mut E, data: &[u8], from: usize) -> Vec<u8> {
        encoder.build_from(from);
        encoder.restart();
        let mut out = Vec::new();
        let chunks: Vec<&[u8]> = data.chunks(1 << 20).collect();
        for (index, chunk) in chunks.iter().enumerate() {
            encoder.chunk(chunk, index + 1 == chunks.len(), &mut out);
        }
        out
    }
    let in_pool = |threads: usize, run: &(dyn Fn() -> Vec<Vec<u8>> + Sync)| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(run)
    };
    for level in 1u8..=3 {
        let rar5_new = || rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, dictionary));
        let rar29_new =
            || rar29::Rar29Encoder::new(rar29::EncodeOptions::for_level(level, dictionary));
        let run = |from: usize| {
            let mut packed = Vec::new();
            for (_, data) in &inputs {
                packed.push(windowed(&mut rar5_new(), data, from));
                packed.push(windowed(&mut rar29_new(), data, from));
                let mut encoder = rar5_new();
                encoder.set_chain_build_from(from);
                let mut out = Vec::new();
                encoder.encode_region(data, 0, true, &mut out);
                packed.push(out);
            }
            let mut encoder = rar5_new();
            encoder.set_chain_build_from(from);
            encoder.reset_history();
            let mut out = Vec::new();
            let mut at = 0;
            while at < members.len() {
                let first = at;
                while at < members.len() && (at == first || encoder.may_stage(members[at].len())) {
                    encoder.stage(&members[at], true);
                    at += 1;
                }
                for member in encoder.flush().iter() {
                    out.extend_from_slice(member);
                }
            }
            packed.push(out);
            packed
        };
        let expected = in_pool(1, &|| run(usize::MAX));
        let builds = super::chain::BUILDS.load(Ordering::Relaxed);
        let history = super::chain::HISTORY_PIECES.load(Ordering::Relaxed);
        for threads in [2usize, 3, 8] {
            let built = in_pool(threads, &|| run(2));
            for (index, (built, expected)) in built.iter().zip(&expected).enumerate() {
                assert!(
                    built == expected,
                    "level {level}, {threads} threads: run {index} moved a byte"
                );
            }
        }
        // Tests beside this one can only add to the counts, and the
        // pools of more than one thread here build on every flush.
        assert!(super::chain::BUILDS.load(Ordering::Relaxed) > builds + 20);
        assert!(super::chain::HISTORY_PIECES.load(Ordering::Relaxed) > history);
    }
}

/// A member streamed a window at a time is written the same by ONE engine
/// that slides its history as it goes and by a fresh engine a stretch
/// between two slides, each resumed from the dictionary the slide before
/// it kept (`Engine::resume_slid`, `Engine::streamed_period`): the
/// property the writer's segment team rests on. Chain levels 1 to 3, both
/// formats, over text, noise and a mixture, at window and slack sizes that
/// put a slide every few windows, a member that ends on a window's edge
/// and one that does not.
#[test]
fn a_streamed_member_is_the_same_bytes_from_one_engine_and_from_one_a_stretch() {
    trait Streamed {
        fn restart(&mut self);
        fn resume(&mut self, kept: &[u8]);
        fn slack(&mut self, multiple: usize);
        fn fits(&self, chunk: usize) -> bool;
        fn take(&mut self, chunk: &[u8], last: bool);
        fn parse(&mut self, out: &mut Vec<u8>);
        fn period(&self, window: usize, history: usize, left: u64) -> u64;
        fn kept(&self, history: usize) -> usize;
    }
    macro_rules! streamed {
        ($encoder:ty) => {
            impl Streamed for $encoder {
                fn restart(&mut self) {
                    self.reset_history();
                }
                fn resume(&mut self, kept: &[u8]) {
                    self.resume_slid(kept);
                }
                fn slack(&mut self, multiple: usize) {
                    self.set_slack_multiple(multiple);
                }
                fn fits(&self, chunk: usize) -> bool {
                    self.may_stage(chunk)
                }
                fn take(&mut self, chunk: &[u8], last: bool) {
                    self.stage(chunk, last);
                }
                fn parse(&mut self, out: &mut Vec<u8>) {
                    for packed in self.flush().iter() {
                        out.extend_from_slice(packed);
                    }
                }
                fn period(&self, window: usize, history: usize, left: u64) -> u64 {
                    self.streamed_period(window, history, left)
                }
                fn kept(&self, history: usize) -> usize {
                    self.kept_by_slide(history)
                }
            }
        };
    }
    streamed!(rar5::Rar5Encoder);
    streamed!(rar29::Rar29Encoder);
    // The writer's own walk of a stretch of windows (`stage_window`): a
    // batch is flushed where the next window may not join it, and at the
    // stretch's end.
    fn windows<E: Streamed>(encoder: &mut E, data: &[u8], window: usize, ends: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut staged = 0;
        let count = data.len().div_ceil(window);
        for (index, chunk) in data.chunks(window).enumerate() {
            if staged > 0 && !encoder.fits(chunk.len()) {
                encoder.parse(&mut out);
                staged = 0;
            }
            encoder.take(chunk, ends && index + 1 == count);
            staged += 1;
        }
        if staged > 0 {
            encoder.parse(&mut out);
        }
        out
    }
    fn check<E: Streamed>(new: &dyn Fn() -> E, data: &[u8], window: usize, multiple: usize) {
        let mut one = new();
        one.restart();
        one.slack(multiple);
        let expected = windows(&mut one, data, window, true);
        let probe = {
            let mut probe = new();
            probe.slack(multiple);
            probe
        };
        let mut packed = Vec::new();
        let mut at = 0;
        let mut history = 0;
        let mut stretches = 0;
        while at < data.len() {
            let period = probe.period(window, history, (data.len() - at) as u64) as usize;
            assert!(period > 0);
            let mut engine = new();
            if at == 0 {
                engine.restart();
            } else {
                engine.resume(&data[at - history..at]);
            }
            engine.slack(multiple);
            let ends = at + period == data.len();
            packed.extend_from_slice(&windows(&mut engine, &data[at..at + period], window, ends));
            history = probe.kept(history + period);
            at += period;
            stretches += 1;
        }
        assert!(
            stretches >= 3,
            "the member slid at least twice: {stretches}"
        );
        assert!(packed == expected, "{stretches} stretches moved a byte");
    }
    let dictionary = 256u32 << 10;
    let mixed: Vec<u8> = few_words(3 << 20, 61)
        .chunks(300_000)
        .zip(nothing_to_find(1 << 20, 62).chunks(100_000))
        .flat_map(|(text, noise)| text.iter().chain(noise).copied())
        .collect();
    let inputs = [
        few_words((5 << 20) + 12_345, 63),
        few_words(6 << 20, 64),
        nothing_to_find(3 << 20, 65),
        mixed,
    ];
    for level in 1u8..=3 {
        for data in &inputs {
            for (window, multiple) in [(256usize << 10, 4usize), (128 << 10, 2), (256 << 10, 1)] {
                check(
                    &|| rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, dictionary)),
                    data,
                    window,
                    multiple,
                );
                check(
                    &|| {
                        rar29::Rar29Encoder::new(rar29::EncodeOptions::for_level(level, dictionary))
                    },
                    data,
                    window,
                    multiple,
                );
            }
        }
    }
    // And the packed stream is a member: it decodes to its input.
    let data = &inputs[0];
    let mut one = rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(1, dictionary));
    one.reset_history();
    let packed = windows(&mut one, data, 256 << 10, true);
    assert_eq!(
        &rar5_decode(&packed, data.len(), u64::from(dictionary)),
        data
    );
}

/// The chain levels' SLIDING waves (`Engine::chains_sliding`) are the
/// waves' bytes with the pass on one thread and with it built across the
/// pool, at one thread and several.
///
/// The run is what the command line gives a large member: 2 MiB windows
/// staged in batches at the streamed slack, 36 MiB, so the history slides
/// twice. A flush after a slide is an 18 MiB span over 16 Mi links, cut
/// into waves of 55 blocks, and relinks the dictionary it kept, which the
/// build takes as its first pieces: the paths a sliding flush has to get
/// right. Mostly noise, which parses at the floor, so level 3 costs a
/// test's time.
#[cfg(feature = "parallel")]
#[test]
fn sliding_chain_waves_are_the_waves_bytes() {
    let dictionary = 2u32 << 20;
    let member: Vec<u8> = few_words(9 << 20, 17)
        .chunks(256_000)
        .zip(nothing_to_find(27 << 20, 19).chunks(768_000))
        .flat_map(|(text, noise)| text.iter().chain(noise).copied())
        .collect();
    let windowed = |level: u8, from: usize, slide: bool| {
        let mut encoder = rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, dictionary));
        encoder.set_chain_build_from(from);
        encoder.set_waves_slide(slide);
        encoder.reset_history();
        encoder.set_slack_multiple(super::drive::STREAMED_SLACK_MULTIPLE);
        let windows: Vec<&[u8]> = member.chunks(dictionary as usize).collect();
        let mut out = Vec::new();
        let mut staged = 0;
        for (index, window) in windows.iter().enumerate() {
            if staged > 0 && !encoder.may_stage(window.len()) {
                for packed in encoder.flush().iter() {
                    out.extend_from_slice(packed);
                }
                staged = 0;
            }
            encoder.stage(window, index + 1 == windows.len());
            staged += 1;
        }
        for packed in encoder.flush().iter() {
            out.extend_from_slice(packed);
        }
        out
    };
    let in_pool = |threads: usize, run: &(dyn Fn() -> Vec<u8> + Sync)| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(run)
    };
    for level in [1u8, 3] {
        let expected = in_pool(1, &|| windowed(level, usize::MAX, false));
        let slid = super::drive::SLID_FLUSHES.load(Ordering::Relaxed);
        let builds = super::chain::BUILDS.load(Ordering::Relaxed);
        let history = super::chain::HISTORY_PIECES.load(Ordering::Relaxed);
        for threads in [1usize, 3, 8] {
            for (from, slide) in [(usize::MAX, true), (2, true), (2, false)] {
                let got = in_pool(threads, &|| windowed(level, from, slide));
                assert!(
                    got == expected,
                    "level {level}, {threads} threads, build from {from}, slide {slide}: a byte moved"
                );
            }
        }
        // Tests beside this one can only add to the counts. One flush a
        // run slides (the second: the first does not wrap its links and
        // the last is one wave), and six runs slide.
        assert!(super::drive::SLID_FLUSHES.load(Ordering::Relaxed) >= slid + 6);
        assert!(super::chain::BUILDS.load(Ordering::Relaxed) > builds);
        assert!(super::chain::HISTORY_PIECES.load(Ordering::Relaxed) > history);
    }
}

/// The chains' links taken from a zeroed allocation (`chain::zeroed_slots`,
/// the Linux default) are as many slots as asked, every one zero, and
/// each one a working atomic: the same links `empty_slots` fills by hand.
#[test]
fn zeroed_links_are_the_filled_links() {
    use crate::carry::h_ours::codec::rar50::tree::empty_slots;
    use std::sync::atomic::Ordering;
    for count in [0usize, 1, 4096, 1 << 20] {
        let zeroed = super::chain::zeroed_slots(count);
        let filled = empty_slots(count);
        assert_eq!(zeroed.len(), count);
        assert!(zeroed
            .iter()
            .zip(&filled)
            .all(|(a, b)| a.load(Ordering::Relaxed) == b.load(Ordering::Relaxed)));
        if let Some(last) = zeroed.last() {
            last.store(7, Ordering::Relaxed);
            assert_eq!(last.load(Ordering::Relaxed), 7);
        }
    }
}

#[test]
fn the_backward_extension_is_levels_3_to_5_and_never_the_optimal_tree_or_the_floor() {
    // `drive::back_for`: a parse may begin an offered match up to
    // `lz::BACK_LIMIT` bytes earlier at level 3 over the chains and, since
    // 1 Oct 2026, at the lazy tree plans of levels 4 and 5 (SPEC-H3 8.1,
    // the ladder's order); levels 1 and 2 only by `Plan::extend_low`
    // (`WriteOptions::low_levels_extend`). The optimal tree plans the
    // options keep and the floor never do, so `level4_optimal` and
    // `level5_optimal` keep their bytes, and so do the store rule's
    // samples (spec G 3.8.3, packed at the floor) and level 3's lazy
    // floor.
    use super::drive::Plan;
    use super::lz::BACK_LIMIT;
    for level in 1u8..=5 {
        let plan = Plan::for_level(level);
        let on = |yes: bool| if yes { BACK_LIMIT } else { 0 };
        assert_eq!(plan.back, on(level >= 3), "level {level}");
        assert_eq!(plan.extend_low().back, BACK_LIMIT, "level {level} extended");
        assert_eq!(
            plan.optimal_tree(level).back,
            on(level == 3),
            "level {level}: the optimal tree option takes none"
        );
        assert_eq!(plan.floor_for_test().back, 0, "level {level}'s floor");
        assert_eq!(plan.lazy_floor().floor_for_test().back, 0, "level {level}");
    }
}

#[test]
fn the_backward_extension_takes_back_a_lost_head_and_the_member_decodes() {
    // What the extension is for, over both finders (the chains at levels 1
    // to 4, the tree at level 5): the same member, the same plan,
    // with the extension and without it, and the one with it is smaller,
    // decodes to its input, and is the same at any width. Level 1 in its
    // PRICED form, the lazy parse: level 1's fast parse has no
    // extension and reads nothing of `back`.
    let input = far_sentences(1 << 20, 5);
    let window = 2 << 20;
    for level in 1u8..=5 {
        let encode = |back: usize, workers: usize| {
            let mut options = rar5::EncodeOptions::for_level(level, window as u32);
            if level == 1 {
                assert_eq!(
                    rar5::Rar5Encoder::new(options).encode(&input),
                    {
                        let mut extended = options;
                        extended.plan.back = super::lz::BACK_LIMIT;
                        rar5::Rar5Encoder::new(extended).encode(&input)
                    },
                    "the fast parse reads no extension"
                );
                options.plan = options.plan.priced_level1();
            }
            // The level's own plan alone: a member's class would give it
            // the level's other effort, whose extension is not this dial.
            options.plan.other = None;
            options.plan.back = back;
            options.workers = workers;
            rar5::Rar5Encoder::new(options).encode(&input)
        };
        let back = super::lz::BACK_LIMIT;
        let (with, without) = (encode(back, usize::MAX), encode(0, usize::MAX));
        assert!(
            with.len() < without.len(),
            "level {level}: {} bytes with the extension, {} without",
            with.len(),
            without.len()
        );
        assert_eq!(
            rar5_decode(&with, input.len(), window),
            input,
            "level {level}"
        );
        assert_eq!(encode(back, 1), with, "level {level} on one thread");
    }
}

/// Bytes for the fast parse's tests: stretches of noise, of one byte, of a
/// short period and of earlier bytes copied back, each of a length the
/// generator draws, so literal runs and matches of every length meet the
/// blind cut's boundary.
fn fast_parse_bytes(seed: u32, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    let mut next = move || {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        x >> 8
    };
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        let run = 1 + (next() as usize % 97) * (1 + next() as usize % 3000) / 16;
        match next() % 5 {
            0 => bytes.extend((0..run).map(|_| next() as u8)),
            1 => bytes.extend(std::iter::repeat_n(next() as u8, run.min(9000))),
            2 => {
                let period = 1 + next() as usize % 7;
                let from = bytes.len();
                bytes.extend((0..period).map(|_| next() as u8));
                for at in 0..run {
                    bytes.push(bytes[from + at % period]);
                }
            }
            _ if bytes.len() > 64 => {
                let back = 1 + next() as usize % bytes.len().min(300_000);
                for _ in 0..run.min(70_000) {
                    bytes.push(bytes[bytes.len() - back]);
                }
            }
            _ => bytes.extend((0..run).map(|_| (next() % 4) as u8 + b'a')),
        }
    }
    bytes.truncate(len);
    bytes
}

#[test]
fn the_fast_parse_cuts_and_counts_as_the_blind_cut_and_a_count_of_its_tokens_do() {
    // The parse hands the emitter its entropy block cuts and each block's
    // symbol counts; the two-pass form is the blind cut over its tokens and
    // a count of every block's tokens through the format's own visitor.
    use super::chain::{Chains, KEY_WIDE};
    use super::lz::{fast_parse, Block, Format};
    fn check<F: Format>(format: &F, bytes: &[u8], start: usize, end: usize) {
        let mut chains = Chains::new(4 << 20, bytes.len(), usize::MAX, KEY_WIDE);
        let (heads, links) = (&mut chains.heads, &chains.links);
        links.insert(heads, bytes, 0..end);
        let block = Block {
            span: bytes,
            start,
            end,
            dictionary: 4 << 20,
        };
        let (mut tokens, mut cuts, mut counts) = (Vec::new(), Vec::new(), Vec::new());
        fast_parse(format, block, links, &mut tokens, &mut cuts, &mut counts);
        let sent: usize = tokens.iter().map(|t| t.length as usize).sum();
        assert_eq!(sent, end - start, "the tokens cover the block");
        let mut blind = Vec::new();
        cut::cut_blind(&tokens, &mut blind);
        assert_eq!(cuts, blind, "block {start}..{end}");
        let symbols = format.symbols();
        assert_eq!(counts.len(), cuts.len() * symbols);
        for (cut, counted) in cuts.iter().zip(counts.chunks_exact(symbols)) {
            let mut wanted = vec![0u32; symbols];
            for &token in &tokens[cut.clone()] {
                format.visit(token, &mut |symbol| wanted[symbol] += 1);
            }
            assert_eq!(counted, &wanted[..], "block {start}..{end}, cut {cut:?}");
        }
    }
    for seed in 1..=12u32 {
        let bytes = fast_parse_bytes(seed * 7919, 700_000 + (seed as usize * 37_123) % 200_000);
        // A parse block from the member's start, one with history before
        // it, and ends that leave under four bytes, a few tokens and none.
        let blocks = [
            (0, 262_144),
            (262_144, 524_288),
            (300_001, bytes.len()),
            (0, 65_536),
            (0, 65_535),
            (5, 65_541 + seed as usize),
            (0, 3),
            (100, 100),
            (0, bytes.len()),
        ];
        for (start, end) in blocks {
            check(&rar5::wire_for_tests(), &bytes, start, end);
        }
        check(&rar29::wire_for_tests(), &bytes, 0, 262_144);
    }
    // Noise alone, where a literal run crosses several cuts, and one byte
    // alone, where one match does.
    let mut x = 99u32;
    let noise: Vec<u8> = (0..300_000)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (x >> 16) as u8
        })
        .collect();
    check(&rar5::wire_for_tests(), &noise, 0, noise.len());
    check(&rar5::wire_for_tests(), &noise, 1, 65_537);
    // A cut that would leave the last block the least tokens a table set
    // is worth, one fewer and one more: the first two are not made.
    use crate::carry::c_lz::codec::rar50::ENTROPY_BLOCK_MIN_TOKENS;
    for left in [
        ENTROPY_BLOCK_MIN_TOKENS - 1,
        ENTROPY_BLOCK_MIN_TOKENS,
        ENTROPY_BLOCK_MIN_TOKENS + 1,
    ] {
        check(
            &rar5::wire_for_tests(),
            &noise,
            0,
            cut::BLIND_CUT_BYTES + left,
        );
        check(
            &rar5::wire_for_tests(),
            &noise,
            7,
            7 + 3 * cut::BLIND_CUT_BYTES + left,
        );
    }
    let zeros = vec![0u8; 300_000];
    check(&rar5::wire_for_tests(), &zeros, 0, zeros.len());
}

#[test]
fn the_six_byte_pass_links_the_same_across_the_cyclic_buffers_wrap() {
    // The pass goes a run of slots at a time up to the cyclic buffer's
    // wrap. Its links are held to a plain statement of what a link is: the
    // newest earlier position of the same six byte bucket, from empty
    // heads, in a buffer the span wraps several times over.
    use super::chain::{Chains, KEY_WIDE};
    let bytes = fast_parse_bytes(41, 400_000);
    // A dictionary of 16 KiB over waves of 16 KiB: a cyclic buffer of
    // 32 KiB positions, which a 400 KB span laps a dozen times.
    let mut chains = Chains::new(16 << 10, bytes.len(), 16 << 10, KEY_WIDE);
    let cyclic = chains.links.len();
    assert!(cyclic < bytes.len() / 4, "the span must lap the buffer");
    assert!(chains.wave_bytes(bytes.len()) >= 16 << 10);
    let mut newest = std::collections::HashMap::new();
    let mut at = 0;
    // Ranges of uneven lengths, none past a wave (a longer one would
    // overwrite its own first links before they are read here), so runs
    // begin and end everywhere in the buffer, the wrap included.
    let mut step = 1usize;
    while at < bytes.len() {
        let end = (at + step).min(bytes.len());
        let (heads, links) = (&mut chains.heads, &chains.links);
        links.insert(heads, &bytes, at..end);
        for position in at..end {
            if position + KEY_WIDE > bytes.len() {
                continue;
            }
            let key = &bytes[position..position + KEY_WIDE];
            let before = newest.insert(chains.heads_bucket_for_tests(&bytes, position), position);
            let wanted = before.filter(|&earlier| position - earlier <= 16 << 10);
            assert_eq!(
                chains.links.nearest(position),
                wanted,
                "position {position}, key {key:?}"
            );
        }
        at = end;
        step = step * 3 % 16_001 + 1;
    }
}

#[test]
fn a_held_writer_and_a_steady_one_write_what_the_plain_writer_writes() {
    // The token loops write through a writer held by value, flushing
    // words (`hold`) or whole bytes after every field (`steady`): the
    // same fields must leave the same bytes, the same valid bits in the
    // last, and a writer the plain push can go on from.
    use super::bits::Push;
    let mut source = rarkit_testdata::Seeded::new(0x6869_7473);
    let mut next = move || source.next_u32();
    for round in 0..200 {
        let fields: Vec<(u32, u8)> = (0..1 + next() % 5000)
            .map(|_| {
                // Widths of every size, zero and 32 among them, with the
                // short ones a code has most often.
                let count = match next() % 8 {
                    0 => (next() % 33) as u8,
                    1 => 0,
                    _ => 1 + (next() % 15) as u8,
                };
                let value = if count == 32 {
                    next()
                } else {
                    next() & ((1u32 << count) - 1)
                };
                (value, count)
            })
            .collect();
        // Some fields before and after through the plain push, so a held
        // writer is taken with bits waiting and handed back with some.
        let lead = fields.len() / 3;
        let tail = fields.len() - fields.len() / 5;
        let mut plain = BitWriter::new();
        for &(value, count) in &fields {
            plain.push(value, count);
        }
        let (wanted, wanted_bits) = {
            let (bytes, bits) = plain.finish();
            (bytes.to_vec(), bits)
        };
        for steady in [false, true] {
            let mut out = BitWriter::new();
            for &(value, count) in &fields[..lead] {
                out.push(value, count);
            }
            if steady {
                let mut held = out.steady();
                for &(value, count) in &fields[lead..tail] {
                    held.push(value, count);
                }
            } else {
                let mut held = out.hold();
                for &(value, count) in &fields[lead..tail] {
                    Push::push(&mut held, value, count);
                }
            }
            for &(value, count) in &fields[tail..] {
                out.push(value, count);
            }
            let (bytes, bits) = out.finish();
            assert_eq!(
                (bytes, bits),
                (&wanted[..], wanted_bits),
                "round {round}, steady {steady}"
            );
        }
    }
}

#[test]
fn a_level_5_member_reading_far_takes_the_chains_where_its_head_holds_long_matches() {
    // SPEC-H3 8.1, the class's SECOND statistic. A member whose head reads
    // the cut-off or more takes the chains all the same where a greedy
    // parse of the head takes `LEVEL5_CHAINS_LONG` long matches or more; a
    // member reading far with fewer keeps the tree. With
    // `WriteOptions::level5_far_links_only` (`Plan::far_links_only_level5`)
    // level 5 goes by far links alone, as it did, and the two differ ONLY
    // on a member whose class the statistic moves: a member under the
    // cut-off, one under a megabyte, a lone one and levels 1 to 4 write
    // one archive either way. A solid run goes by its first member the
    // same way.
    use super::class;
    use super::drive::{Finder, Parse, Plan, LEVEL5_CHAINS_LONG, LEVEL5_CHAINS_UNDER};
    use super::lz::BACK_LIMIT;
    let dictionary = 1 << 20;
    let head = class::HEAD_BYTES;
    let near = few_words(head + 300_000, 3);
    let far = far_linked(head + 300_000);
    let phrased = far_linked_with_phrases(head + 300_000, 20);
    let sparse = far_linked_with_phrases(head + 300_000, 100);
    let read = |bytes: &[u8]| {
        let reading = class::of_head(bytes).expect("a megabyte reads");
        (reading.per_mille(), reading.long_matches())
    };
    // What the four heads read, so the cases below are the cases meant.
    let (far_reads, far_long) = read(&far);
    let (phrased_reads, phrased_long) = read(&phrased);
    let (sparse_reads, sparse_long) = read(&sparse);
    let (near_reads, near_long) = read(&near);
    assert!(far_reads >= LEVEL5_CHAINS_UNDER && far_long < LEVEL5_CHAINS_LONG / 8);
    assert!(phrased_reads >= LEVEL5_CHAINS_UNDER && phrased_long >= LEVEL5_CHAINS_LONG * 2);
    assert!(
        sparse_reads >= LEVEL5_CHAINS_UNDER
            && sparse_long < LEVEL5_CHAINS_LONG
            && sparse_long > LEVEL5_CHAINS_LONG / 8,
        "the sparse member reads {sparse_reads} and holds {sparse_long}"
    );
    assert!(near_reads < LEVEL5_CHAINS_UNDER && near_long >= LEVEL5_CHAINS_LONG);
    let short = &phrased[..head - 1];
    let lone = few_words(200_000, 5);

    let dress = |text: &str| {
        let mut options = rar5::EncodeOptions::spelled(text, dictionary).expect("a plan");
        if text.contains("tree") {
            options.plan.candidates = 1;
            options.plan.full_reach = true;
        }
        options.plan.back = BACK_LIMIT;
        options
    };
    let spelled = |text: &str, input: &[u8]| rar5::Rar5Encoder::new(dress(text)).encode(input);
    const TREE: &str = "lazy:tree:16:0";
    const CHAINS: &str = "lazy:chain:80:256";
    let on = Plan::for_level(5);
    let off = on.far_links_only_level5();
    assert!(off.other.expect("it keeps the other effort").long.is_none());
    assert_eq!(
        on.other.expect("level 5 has another effort").long,
        Some(LEVEL5_CHAINS_LONG)
    );
    let with = |plan: Plan, level: u8| {
        let mut options = rar5::EncodeOptions::for_level(level, dictionary);
        options.plan = plan;
        rar5::Rar5Encoder::new(options)
    };
    // (the member, its plan by far links alone, its plan as shipped)
    let members: [(&str, &[u8], &str, &str); 5] = [
        ("far with long matches", &phrased, TREE, CHAINS),
        ("far with none", &far, TREE, TREE),
        ("far with too few", &sparse, TREE, TREE),
        ("near", &near, CHAINS, CHAINS),
        ("under a megabyte", short, CHAINS, CHAINS),
    ];
    for (name, input, was, is) in members {
        for (plan, text) in [(off, was), (on, is)] {
            let took = plan.for_member(input, input.len() as u64);
            let finder = if text == TREE {
                Finder::Tree
            } else {
                Finder::Chain
            };
            assert_eq!((took.parse, took.finder), (Parse::Lazy, finder), "{name}");
            assert!(took.other.is_none(), "{name}: a member has one plan");
            assert_eq!(
                plan.for_member_on(input, input.len() as u64, 8).finder,
                finder,
                "{name}: the same class on a pool"
            );
        }
        let packed =
            rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(5, dictionary)).encode(input);
        assert!(packed == spelled(is, input), "{name}: the plan {is}");
        assert_eq!(
            rar5_decode(&packed, input.len(), u64::from(dictionary)),
            input,
            "{name}: it decodes"
        );
        let by_far = with(off, 5).encode(input);
        assert!(
            by_far == spelled(was, input),
            "{name}: by far links alone, the plan {was}"
        );
        assert_eq!(
            packed == by_far,
            was == is,
            "{name}: only a member whose class moves moves a byte"
        );
        // The RAR 2.9 method takes the same class.
        let options29 = rar29::EncodeOptions::for_level(5, dictionary);
        let mut spelled29 = rar29::EncodeOptions::spelled(is, dictionary).expect("a plan");
        spelled29.plan = dress(is).plan;
        assert!(
            rar29::Rar29Encoder::new(options29).encode(input)
                == rar29::Rar29Encoder::new(spelled29).encode(input),
            "{name}: the RAR 2.9 method"
        );
    }
    assert_eq!(
        format!("{:?}", on.for_member(&lone, lone.len() as u64)),
        format!("{on:?}"),
        "a lone member keeps the level's plan and its lone effort"
    );
    // The statistic is level 5's: levels 1 to 4 have no other effort for
    // it to reach, and write what they wrote.
    for level in 1u8..=4 {
        let lower = Plan::for_level(level);
        assert_eq!(
            format!("{:?}", lower.far_links_only_level5()),
            format!("{lower:?}"),
            "level {level}"
        );
    }
    // The two options that take the class away leave it nothing.
    assert_eq!(
        format!("{:?}", on.tree_level5()),
        format!("{:?}", off.tree_level5())
    );
    assert_eq!(
        format!("{:?}", on.optimal_tree(5)),
        format!("{:?}", off.optimal_tree(5))
    );
    // A solid run, by its first member: far with long matches, the chains
    // at 72 for the whole run (the run's own plan); far with none, the
    // one-slot tree, which is the tree option's solid plan exactly.
    let (solid_off, solid_on) = (off.solid_run(5), on.solid_run(5));
    let run_tree = format!("{:?}", off.tree_level5().solid_run(5));
    for (name, first, was_tree, is_tree) in [
        ("far with long matches", &phrased[..], true, false),
        ("far with none", &far[..], true, true),
        ("near", &near[..], false, false),
        ("under a megabyte", short, false, false),
    ] {
        for (plan, tree) in [(solid_off, was_tree), (solid_on, is_tree)] {
            let took = plan.for_member(first, first.len() as u64);
            if tree {
                assert_eq!(format!("{took:?}"), run_tree, "{name}: the run's tree");
            } else {
                assert_eq!(
                    (took.parse, took.finder, took.depth, took.enough),
                    (Parse::Lazy, Finder::Chain, 72, 256),
                    "{name}: the run keeps the chains"
                );
                assert!(took.wide_ring && took.other.is_none(), "{name}");
            }
        }
    }
}

#[test]
fn a_level_5_member_takes_the_chains_or_the_tree_by_the_reading_of_its_head() {
    // SPEC-H3 8.1, level 5 by class. A whole non-solid member past the
    // lone bound is read by its first megabyte (`encode::class`, far links
    // a byte) and takes the chains at 80 links where the head reads under
    // the level's cut-off, and where the member is under a megabyte and
    // has no reading; the tree at cut 16 otherwise. The class is the
    // HEAD's: what follows the first megabyte is not read. It is the same
    // through every entry a writer feeds a member by (one region, a whole
    // run, windows after `start_member`), an engine that has encoded one
    // class writes the other as a fresh engine does, and the options that
    // keep the level one finder read nothing. LEVEL 4 has one effort and
    // reads nothing: every one of these members takes its chains at 64.
    use super::class;
    use super::drive::{Finder, Parse, Plan, LEVEL5_CHAINS_UNDER};
    use super::lz::BACK_LIMIT;
    let dictionary = 1 << 20;
    let head = class::HEAD_BYTES;
    let near = few_words(head + 300_000, 3);
    let far = far_linked(head + 300_000);
    let reading = |bytes: &[u8]| class::of_head(bytes).expect("a megabyte reads").per_mille();
    let (near_reads, far_reads) = (reading(&near), reading(&far));
    assert!(
        near_reads < LEVEL5_CHAINS_UNDER / 2,
        "the near member reads {near_reads}"
    );
    assert!(
        far_reads >= LEVEL5_CHAINS_UNDER * 2,
        "the far member reads {far_reads}"
    );
    // A near head in front of far bytes, and the reverse.
    let mut near_headed = near[..head].to_vec();
    near_headed.extend_from_slice(&far[..300_000]);
    let mut far_headed = far[..head].to_vec();
    far_headed.extend_from_slice(&near[..300_000]);
    let short = &far[..head - 1];

    let dress = |text: &str| {
        let mut options = rar5::EncodeOptions::spelled(text, dictionary).expect("a plan");
        if text.contains("tree") {
            options.plan.candidates = 1;
            options.plan.full_reach = true;
        }
        options.plan.back = BACK_LIMIT;
        options
    };
    let spelled = |text: &str, input: &[u8]| rar5::Rar5Encoder::new(dress(text)).encode(input);
    let spelled29 = |text: &str, input: &[u8]| {
        let mut options = rar29::EncodeOptions::spelled(text, dictionary).expect("a plan");
        options.plan = dress(text).plan;
        rar29::Rar29Encoder::new(options).encode(input)
    };
    let level_n =
        |level: u8| rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, dictionary));
    const TREE: &str = "lazy:tree:16:0";
    const CHAINS: &str = "lazy:chain:80:256";
    let members: [(&str, &[u8], &str); 5] = [
        ("near", &near, CHAINS),
        ("far", &far, TREE),
        ("a near head", &near_headed, CHAINS),
        ("a far head", &far_headed, TREE),
        ("under a megabyte", short, CHAINS),
    ];

    // Which plan, and that nothing is read where no answer needs it.
    let plan = Plan::for_level(5);
    assert!(plan.reads_head(head as u64));
    assert!(!plan.reads_head(head as u64 - 1), "under a megabyte");
    for level in 1u8..=4 {
        let lower = Plan::for_level(level);
        assert!(lower.other.is_none(), "level {level} has one effort");
        assert!(
            !lower.reads_head(head as u64),
            "level {level} reads nothing"
        );
        assert_eq!(
            format!("{:?}", lower.for_member(&far, far.len() as u64)),
            format!("{lower:?}"),
            "level {level}: every member takes the level's plan"
        );
    }
    for (name, input, text) in members {
        let took = plan.for_member(input, input.len() as u64);
        let finder = if text == TREE {
            Finder::Tree
        } else {
            Finder::Chain
        };
        assert_eq!((took.parse, took.finder), (Parse::Lazy, finder), "{name}");
        assert!(took.other.is_none(), "{name}: a member has one plan");
    }
    let lone = few_words(200_000, 5);
    assert_eq!(
        format!("{:?}", plan.for_member(&lone, lone.len() as u64)),
        format!("{plan:?}"),
        "a lone member keeps the level's plan and its lone effort"
    );

    // The bytes, RAR 5 and the RAR 2.9 method.
    for (name, input, text) in members {
        let packed = level_n(5).encode(input);
        assert!(packed == spelled(text, input), "{name}: the plan {text}");
        assert_eq!(
            rar5_decode(&packed, input.len(), u64::from(dictionary)),
            input,
            "{name}: it decodes"
        );
        assert!(
            rar29::Rar29Encoder::new(rar29::EncodeOptions::for_level(5, dictionary)).encode(input)
                == spelled29(text, input),
            "{name}: the RAR 2.9 method"
        );
        // Level 4 beside it: its chains at 64 links whatever the class.
        assert!(
            level_n(4).encode(input) == spelled("lazy:chain:64:256", input),
            "{name}: level 4 takes its chains"
        );
        // A whole run in one chunk, and windows after `start_member`.
        let mut whole = Vec::new();
        level_n(5).encode_whole_run(input, &mut whole, &[]);
        let mut whole_spelled = Vec::new();
        rar5::Rar5Encoder::new(dress(text)).encode_whole_run(input, &mut whole_spelled, &[]);
        assert!(
            whole == whole_spelled,
            "{name}: a whole run takes the same class"
        );
        let window = dictionary as usize;
        let windows = |encoder: &mut rar5::Rar5Encoder| {
            let mut out = Vec::new();
            let mut at = 0;
            while at < input.len() {
                let to = (at + window).min(input.len());
                encoder.encode_chunk(&input[at..to], to == input.len(), &mut out);
                at = to;
            }
            out
        };
        let mut encoder = level_n(5);
        encoder.start_member(input, input.len() as u64);
        let windowed = windows(&mut encoder);
        let mut reference = rar5::Rar5Encoder::new(dress(text));
        reference.reset_history();
        assert!(
            windowed == windows(&mut reference),
            "{name}: windows after start_member take the same class"
        );
    }

    // One engine, both classes, either order: each member is what a fresh
    // engine writes, and the engine then holds both finders, which is what
    // it is charged.
    let mut both = level_n(5);
    let first = both.encode(&far);
    let one_finder = both.structure_bytes();
    let second = both.encode(&near);
    let third = both.encode(&far);
    assert!(first == level_n(5).encode(&far), "far first");
    assert!(second == level_n(5).encode(&near), "near after far");
    assert!(third == first, "far after near");
    assert!(
        both.structure_bytes() > one_finder,
        "an engine that met both classes holds both finders"
    );
    assert!(
        both.structure_bytes() <= both.member_structure_bytes(near.len(), false),
        "{} held, {} charged",
        both.structure_bytes(),
        both.member_structure_bytes(near.len(), false)
    );

    // The options that keep the level one finder read nothing.
    assert!(
        !plan.tree_level5().reads_head(head as u64),
        "the tree option"
    );
    assert!(!plan.optimal_tree(5).reads_head(head as u64));
    assert!(
        plan.solid_run(5).reads_head(head as u64),
        "a solid run is read at its first member"
    );
    assert!(!plan.tree_level5().solid_run(5).reads_head(head as u64));
    let mut options = rar5::EncodeOptions::for_level(5, dictionary);
    options.plan = plan.tree_level5();
    assert!(
        rar5::Rar5Encoder::new(options).encode(&near) == spelled(TREE, &near),
        "the tree option keeps the tree on a near member"
    );
}

/// The carried history asks for huge pages when its block is taken, on
/// Linux and nowhere else (`crate::pages`), and not again while the block
/// stands.
#[test]
fn the_carried_history_asks_for_huge_pages_once_a_block() {
    use crate::pages::asking_tests::{asked_by, here};
    let mut engine = super::drive::Engine::new(super::drive::Plan::for_level(3), 8 << 20, 1);
    let chunk = vec![5u8; 64 << 10];
    // A chunk that does not end its member reserves the history to its
    // cap, past the dictionary: a block of 8 MiB and more.
    let first = asked_by(|| engine.stage(&chunk, false));
    let second = asked_by(|| engine.stage(&chunk, false));
    if let Some(want) = here([0, 1]) {
        assert_eq!(first, want, "the history's block");
    }
    assert_eq!(second, [0, 0], "the same block asks nothing more");
}

/// The room a carried history is given ([`super::drive::history_room`]):
/// a solid run of small members reaches a long dictionary's cap in a few
/// doubling steps, where a block grown by each member's own bytes moved
/// thousands of times; a non-solid member and a run's first take exactly
/// their bytes; a window of a longer member takes the cap at once; and
/// the room is never under what is staged nor, for a chunk the cap holds,
/// over the cap.
#[test]
fn a_solid_run_of_small_members_grows_its_history_in_few_steps() {
    use super::drive::history_room;
    const MEMBER: usize = 8 << 10;
    // A 32 MiB dictionary and its 64 MiB of slack, and a 2 MiB one's.
    for cap in [96usize << 20, 10 << 20] {
        let (mut len, mut capacity, mut moves) = (0usize, 0usize, 0u32);
        for _ in 0..20_000 {
            if len + MEMBER > cap {
                // The slide: the dictionary is kept, the block stands.
                len = cap / 3;
            }
            let room = history_room(len, capacity, MEMBER, cap, true);
            assert!(room >= len + MEMBER, "room for the member");
            assert!(room <= cap, "inside the cap");
            if room != capacity {
                moves += 1;
                capacity = room;
            }
            len += MEMBER;
        }
        assert!(moves <= 16, "{moves} moves to a cap of {cap}");
    }
    // The first member of a run, and every non-solid member: exactly.
    assert_eq!(history_room(0, 0, 5_000, 96 << 20, true), 5_000);
    assert_eq!(history_room(0, 4_000, 5_000, 96 << 20, true), 5_000);
    assert_eq!(history_room(0, 8_000, 5_000, 96 << 20, true), 8_000);
    // A window of a longer member: the cap at once, and no more after.
    assert_eq!(history_room(0, 0, 1 << 20, 10 << 20, false), 10 << 20);
    assert_eq!(
        history_room(1 << 20, 10 << 20, 1 << 20, 10 << 20, false),
        10 << 20
    );
    // A chunk longer than the cap's slack is never split.
    assert_eq!(
        history_room(1 << 20, 2 << 20, 12 << 20, 10 << 20, true),
        13 << 20
    );
}

/// Sweep L-13, the first site: the wave a history longer than the cyclic
/// buffer may parse at once, at a 2 GiB dictionary. Arithmetic only: no
/// pool, no memory.
#[cfg(target_pointer_width = "64")]
#[test]
#[ignore = "sweep L-13: fails at a04189031 (chain.rs wave_for, subtract with overflow); not reachable since Run::new refuses the write (tests/dictionary_over_span.rs); passes only with wider links"]
fn a_history_past_the_cyclic_buffer_has_a_wave_at_a_2_gib_dictionary() {
    let dictionary = 1usize << 31;
    // What `Engine::history_cap` sizes the chains from (the span bound),
    // and the history after the first slide that keeps a whole dictionary.
    let sizing = 1usize << 31;
    let span = dictionary + (8 << 20);
    let wave = chain::Chains::wave_for(dictionary, sizing, usize::MAX, span);
    assert!(wave >= 1 && wave <= span, "a wave of {wave} bytes");
}

/// Sweep L-13, the reported site: a position at and past 2^32 is linked
/// and found again. Memory: 4 GiB and 64 KiB of zeroed pages reserved,
/// a few of them touched.
#[cfg(target_pointer_width = "64")]
#[test]
#[ignore = "sweep L-13: fails at a04189031 (chain.rs insert, add with overflow); not reachable since Run::new refuses the write (tests/dictionary_over_span.rs); passes only with wider links"]
fn a_position_past_4_gib_is_linked_and_found() {
    let len = (1usize << 32) + (64 << 10);
    let mut span = vec![0u8; len];
    let from = (1usize << 32) - 64;
    for (i, byte) in span[from - 4096..].iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    let mut chains = chain::Chains::new(1 << 20, 1 << 20, usize::MAX, chain::KEY_SHORT);
    let (heads, links) = (&mut chains.heads, &chains.links);
    links.insert(heads, &span, from - 4096..from + 1024);
    // The pattern has period 251: every position has the one 251 back.
    for at in [from + 62, from + 63, from + 64, from + 500] {
        assert_eq!(links.nearest(at), Some(at - 251), "position {at:#x}");
    }
}

#[test]
fn the_empty_stride_run_form_leaves_the_links_and_heads_the_position_form_does() {
    // `Links::insert_sparse` (whole runs, only the taken positions
    // visited) against `Links::insert_sparse_each` (a position at a
    // time), over noise with some repeats so that heads collide: at every
    // stride the drive may ask for, over ranges that start and end off
    // the grid and off a window of sixteen, across the cyclic buffer's
    // wrap (a buffer of 64 Ki links under a held wave, over 300,000
    // positions) and in one that never wraps, and over a span's last
    // three positions, which are never linked. Every slot, the ended
    // ones too, and every head must be equal after each range. No pool
    // (one thread); about 24 MiB of chains.
    use super::chain::{Chains, EMPTY_ASK_EVERY, KEY_SHORT};
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut span: Vec<u8> = (0..300_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    span.copy_within(3_000..60_000, 150_000);
    span.copy_within(10_000..10_400, 299_000);
    let cuts = [
        0,
        7,
        40_000,
        100_001,
        131_075,
        200_003,
        262_150,
        299_998,
        span.len(),
    ];
    for (dictionary, wave) in [(1 << 15, 1 << 15), (1 << 20, usize::MAX)] {
        for stride in [2, 4, 8, EMPTY_ASK_EVERY] {
            let mut each = Chains::new(dictionary, span.len(), wave, KEY_SHORT);
            let mut runs = Chains::new(dictionary, span.len(), wave, KEY_SHORT);
            let wraps = each.links.slots_for_tests().len() < span.len();
            assert_eq!(wraps, wave != usize::MAX, "the held buffer wraps");
            for chains in [&mut each, &mut runs] {
                // A lap linked whole first, so the ended chains are seen
                // to be ended and not merely never written.
                let (heads, links) = (&mut chains.heads, &chains.links);
                links.insert(heads, &span, 0..span.len());
            }
            for pair in cuts.windows(2) {
                let range = pair[0]..pair[1];
                each.links
                    .insert_sparse_each(&mut each.heads, &span, range.clone(), stride);
                runs.links
                    .insert_sparse(&mut runs.heads, &span, range.clone(), stride);
                assert!(
                    each.links.slots_for_tests() == runs.links.slots_for_tests(),
                    "stride {stride}, range {range:?}, wraps {wraps}: the links"
                );
                assert!(
                    each.heads == runs.heads,
                    "stride {stride}, range {range:?}, wraps {wraps}: the heads"
                );
            }
        }
    }
}
