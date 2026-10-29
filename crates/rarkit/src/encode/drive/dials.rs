//! The drive's dials: the block, wave and batch sizes, the walkers of the
//! tree walk, the history slack, and the knobs a count or a test turns.

use super::*;

/// How much of the member one parse covers. A constant, because the
/// output depends on it; small enough that a few megabytes of input still
/// spread over every core. Measured 18 Sep 2026 on the 4.38 MB corpus, a
/// block of 256 KiB against one of 1 MiB: level 1 0.012 s against 0.030 s
/// for 0.13% more archive, level 3 0.024 s against 0.060 s for 0.12% more,
/// and level 5 0.25% LESS archive, because the prices follow the input
/// more closely.
pub(crate) const PARSE_BLOCK_BYTES: usize = 256 << 10;

// A parse block is one piece of the chains' build.
#[cfg(feature = "parallel")]
const _: () = assert!(PARSE_BLOCK_BYTES <= PIECE_MOST);

/// The most the tree's hint buffer may hold: sixteen blocks in flight at
/// the shipped four candidates, which keeps the parses fed while the walk
/// runs on.
pub(crate) const HINT_BUDGET_BYTES: usize = 64 << 20;

/// The longest span a FILTERED member is copied in one piece
/// (`Engine::encode_region_filtered`): a whole number of parse blocks.
///
/// 256 MiB, decided 28 Sep 2026. A carried run of pieces
/// drains the parse wave at every piece: the timed libraries rows on
/// an Apple M3 Mac read a filtered libLLVM 1.10x (arm64) and 1.07x (x86-64)
/// Off's create wall in 32 MiB pieces, and 0.98x and 0.97x (FASTER) copied
/// whole. The whole copy holds the member's size again beside the
/// caller's copy (the 199.6 MB library peaked at 575 MiB against 386 MiB
/// unfiltered), so past 256 MiB the pieces bound it instead. What 64 and
/// 128 MiB pieces cost in width is not timed yet.
pub(crate) const FILTER_PIECE_BYTES: usize = 1024 * PARSE_BLOCK_BYTES;

/// [`FILTER_PIECE_BYTES`], or in a bench build
/// `RARKIT_FILTER_PIECE_MIB` whole parse blocks' worth of MiB, for the
/// piece size's wall and memory sweep.
pub(super) fn filter_piece_bytes() -> usize {
    #[cfg(feature = "bench-internals")]
    {
        static PIECE: OnceLock<usize> = OnceLock::new();
        *PIECE.get_or_init(|| {
            std::env::var("RARKIT_FILTER_PIECE_MIB")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .map_or(FILTER_PIECE_BYTES, |mib| (mib << 20).max(PARSE_BLOCK_BYTES))
        })
    }
    #[cfg(not(feature = "bench-internals"))]
    FILTER_PIECE_BYTES
}

/// A walk group shorter than this is walked by one thread (`with_tree`).
/// An eighth of a parse block: a non-solid set's small members are well
/// under it, and a group of a whole block is well over it.
pub(super) const WALK_ALONE_BYTES: usize = PARSE_BLOCK_BYTES / 8;

/// How many parse blocks one call of the tree's walk covers. More than
/// one, so the walk can deal its next chunk while it walks this one; worth
/// 5% to 7% of level 5's wall when measured.
pub(crate) const WALK_BLOCKS: usize = 4;

/// The most parse blocks one BATCH of a carried run stages before it is
/// flushed, which is how wide a solid set's parse can get.
///
/// A solid member of the create legs' corpus is 512 KiB, which is two
/// parse blocks, and a wave that ends with the member it started in is
/// two blocks wide: that was measured as 1.90x
/// parallel where one 32 MiB member of the same bytes runs 10.63x, for
/// the same CPU to within 6%. A batch of this many blocks lets the wave
/// span whichever members it needs to fill, so the width follows the
/// BATCH and not the member.
///
/// Sixty-four, raised from thirty-two on 30 Sep 2026.
/// A batch ends when
/// its slowest block does, with every other thread idle, so a windowed
/// member of bin4g at `-m3` on 32 cores was at most eight threads wide for
/// about half its wall (measured 30 Sep 2026).
/// At the default 2 MiB dictionary a NON-SOLID streamed
/// member's slack is sixteen MiB ([`STREAMED_SLACK_MULTIPLE`]), which is
/// sixty-four blocks, so a batch now runs from one slide to the next and
/// ends only where the history has to slide anyway; a SOLID run's slack
/// is eight MiB there, and its batch is what it was. It moves no byte:
/// [`Engine::may_stage`] ends a batch before anything that would. What it
/// costs is stated at `Engine::batch_cap`.
///
/// Two hundred and fifty-six, raised from sixty-four on 15 Oct 2026, for
/// a run whose slack is longer than sixty-four blocks. The batch is held
/// to the slack either way ([`Engine::batch_cap`]), so a run whose slack
/// is sixty-four blocks or fewer is batched as it was. A flush is a barrier: it ends on its slowest
/// parse, and between flushes nothing parses while the writer stages the
/// next. On 1 GiB of a big member at `-m3` on 18 threads (Apple M5 Max, 64 MiB
/// of slack), the parses were bimodal (a median of 1.8 ms, the thin blocks'
/// 20 to 29 ms), only 7.9 were in flight on average, and the flushes' tails
/// came to 0.69 s and their gaps to 0.37 s of 3.20 s. Batches of 128, 256
/// and 1024 took 2.80 to 2.87 s, 2.64 to 2.77 s and 2.66 to 2.78 s, every
/// archive the same to the byte, RSS 322 MiB at 64 and 363 at 256; 1024
/// is no wider there, being held to the slack (counted 15 Oct 2026).
pub(crate) const BATCH_BLOCKS_MOST: usize = 256;

/// The pass's stride over an empty block: [`EMPTY_STRIDE`], or in a
/// build with `writer-knobs` what `RARKIT_EMPTY_STRIDE` names (1 links
/// every position, as before the stride), read once, so the arms are
/// timed inside one binary.
pub(super) fn empty_stride() -> usize {
    static STRIDE: OnceLock<usize> = OnceLock::new();
    *STRIDE.get_or_init(|| {
        crate::knob::writer_var("RARKIT_EMPTY_STRIDE")
            .ok()
            .and_then(|word| word.trim().parse::<usize>().ok())
            .filter(|&stride: &usize| stride.is_power_of_two() && stride <= EMPTY_ASK_EVERY)
            .unwrap_or(EMPTY_STRIDE)
    })
}

/// The parse blocks one batch stages: [`BATCH_BLOCKS_MOST`], or what a
/// test's [`wave_arms`] or the count-only `wave-knob` sets.
pub(crate) fn batch_blocks() -> usize {
    #[cfg(feature = "bench-internals")]
    {
        let blocks = WAVE_ARMS.0.load(Ordering::Relaxed);
        if blocks != 0 {
            return blocks;
        }
    }
    knob_batch_blocks()
}

/// Under the COUNT-ONLY feature `wave-knob` (never shipped),
/// `RARKIT_BATCH_BLOCKS` blocks, read once, so the lever is timed inside
/// one binary against its old setting of 32.
#[cfg(feature = "wave-knob")]
pub(super) fn knob_batch_blocks() -> usize {
    static BLOCKS: OnceLock<usize> = OnceLock::new();
    *BLOCKS.get_or_init(|| {
        std::env::var("RARKIT_BATCH_BLOCKS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .map_or(BATCH_BLOCKS_MOST, |blocks| blocks.max(1))
    })
}

#[cfg(not(feature = "wave-knob"))]
#[inline(always)]
pub(super) fn knob_batch_blocks() -> usize {
    BATCH_BLOCKS_MOST
}

/// Whether the chain levels' waves SLIDE (`Engine::chains_sliding`): on
/// in a shipped build, and off where a test's [`wave_arms`] or the
/// count-only `wave-knob` turns it off. Neither setting moves a byte.
#[cfg(feature = "parallel")]
pub(super) fn waves_slide() -> bool {
    #[cfg(feature = "bench-internals")]
    {
        match WAVE_ARMS.1.load(Ordering::Relaxed) {
            1 => return true,
            2 => return false,
            _ => {}
        }
    }
    knob_slide()
}

/// Under the COUNT-ONLY feature `wave-knob`, `RARKIT_WAVE_SLIDE=0`
/// restores the waves that end on their slowest block, read once, so the
/// two are timed inside one binary.
#[cfg(all(feature = "parallel", feature = "wave-knob"))]
pub(super) fn knob_slide() -> bool {
    static SLIDE: OnceLock<bool> = OnceLock::new();
    *SLIDE.get_or_init(|| std::env::var("RARKIT_WAVE_SLIDE").map_or(true, |v| v != "0"))
}

#[cfg(all(feature = "parallel", not(feature = "wave-knob")))]
#[inline(always)]
pub(super) fn knob_slide() -> bool {
    true
}

/// Whether a member's later windows in a batch append to its first
/// window's buffer (`Job::out`, [`Engine::lend_first`]): on in a shipped
/// build, and off where a test's [`wave_arms`] or the count-only
/// `wave-knob` (`RARKIT_WAVE_MERGE=0`) turns it off. It moves no byte.
pub(super) fn merge_windows() -> bool {
    #[cfg(feature = "bench-internals")]
    {
        match WAVE_ARMS.2.load(Ordering::Relaxed) {
            1 => return true,
            2 => return false,
            _ => {}
        }
    }
    knob_merge()
}

#[cfg(feature = "wave-knob")]
pub(super) fn knob_merge() -> bool {
    static MERGE: OnceLock<bool> = OnceLock::new();
    *MERGE.get_or_init(|| std::env::var("RARKIT_WAVE_MERGE").map_or(true, |v| v != "0"))
}

#[cfg(not(feature = "wave-knob"))]
#[inline(always)]
pub(super) fn knob_merge() -> bool {
    true
}

/// A test's batch and wave setting, process-wide because the waves run on
/// pool threads: the batch's blocks (0 for the shipped figure), whether
/// waves slide and whether a member's windows share one output buffer (0
/// shipped, 1 on, 2 off). Set only inside [`wave_arms`].
#[cfg(feature = "bench-internals")]
pub(super) static WAVE_ARMS: (AtomicUsize, AtomicUsize, AtomicUsize) = (
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
);

/// How many flushes have taken [`Engine::chains_sliding`] since the
/// process started. This repository's tests only.
#[cfg(any(test, feature = "bench-internals"))]
pub(crate) static SLID_FLUSHES: AtomicUsize = AtomicUsize::new(0);

/// Runs `work` with every encoder in the process batching `blocks` parse
/// blocks (`None`: [`BATCH_BLOCKS_MOST`]), its chain waves sliding or not
/// and a member's windows sharing one output buffer or not (`None`: the
/// shipped setting), then puts all three back. Calls are
/// serialised, so two tests that set arms cannot interleave; a test that
/// runs beside one without calling it sees the arm it set. This
/// repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn wave_arms<T>(
    blocks: Option<usize>,
    slide: Option<bool>,
    merge: Option<bool>,
    work: impl FnOnce() -> T,
) -> T {
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
    let _held = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    WAVE_ARMS.0.store(blocks.unwrap_or(0), Ordering::Relaxed);
    let code = |on: Option<bool>| match on {
        None => 0,
        Some(true) => 1,
        Some(false) => 2,
    };
    WAVE_ARMS.1.store(code(slide), Ordering::Relaxed);
    WAVE_ARMS.2.store(code(merge), Ordering::Relaxed);
    // Put back however `work` ends, so a failed test leaves the next one
    // the shipped arms.
    struct Shipped;
    impl Drop for Shipped {
        fn drop(&mut self) {
            WAVE_ARMS.0.store(0, Ordering::Relaxed);
            WAVE_ARMS.1.store(0, Ordering::Relaxed);
            WAVE_ARMS.2.store(0, Ordering::Relaxed);
        }
    }
    let _shipped = Shipped;
    work()
}

/// How many flushes have taken the sliding waves so far in this process.
#[cfg(feature = "bench-internals")]
pub(crate) fn slid_flushes() -> usize {
    SLID_FLUSHES.load(Ordering::Relaxed)
}

/// The most MEMBERS one batch stages, beside [`BATCH_BLOCKS_MOST`]'s
/// bytes.
///
/// A member of a few KiB is one short block, and at the tree's levels the
/// walk, not the parse, is the wall: a batch of thirty-two such members is
/// about 120 KiB of positions, far less than one walk worth dealing to
/// the walkers (`Engine::with_tree`), so a solid set of small members was
/// walked by one thread (the solid -m5 work, 28 Sep 2026: small20k from
/// the command line ran at 1.16 CPU seconds a wall second). A batch is
/// bounded in bytes by [`Engine::batch_cap`] either way; this bounds the
/// per-member state beside it (an output buffer and a segment each).
pub(crate) const BATCH_MEMBERS_MOST: usize = 1024;

/// The fewest threads the cap on the tree's walk allows, on any machine:
/// [`tree_walkers_most`] is this, or on macOS the machine's fast cores
/// where they are more.
///
/// The carried cap is four, chosen on CPU: a descent is a chain of
/// dependent loads, so more walkers mostly stall on memory, and the stall
/// is charged as user time. This project ranks wall first, and the walk is
/// the wall of level 5, so the cap here is twelve. Measured 18 Sep 2026 at
/// level 5 and load 10, the same bytes at every width, on the 4.38 MB and
/// the 46 MB corpus: 4 walkers 0.18 and 1.65 s wall for 0.65 and 6.2 CPU
/// s; 8 walkers 0.156 and 1.39 s; 12 walkers 0.133 and 1.12 s for 0.81 and
/// 8.4; 16 walkers no better than 12.
///
/// Twelve stays the floor where the machine has fewer cores than that: on
/// eight cores and sixteen threads (a Ryzen 7 7700, 1 Oct 2026, indicative)
/// twelve walkers read level with sixteen and EIGHT, the physical cores,
/// read 0.82x, so the cap never follows the cores down.
pub(crate) const TREE_WALKERS_FLOOR: usize = 12;

/// The most threads that split the tree's walk between them: on macOS the
/// machine's cores of every level but the efficiency level
/// (`cores::performance`) and never fewer than [`TREE_WALKERS_FLOOR`]; on
/// every other system, and on a Mac that reports no performance level (an
/// Intel one), [`TREE_WALKERS_FLOOR`], as it was. The pool's width and
/// `WriteOptions::workers` bound it as before, so it is reached only
/// where the caller's pool is that wide. (On x86-64 Linux a member that
/// keeps the tree by its own class walks wider:
/// [`tree_walkers_by_class`].)
///
/// It moves no byte: the walk's answers are the serial walk's at any
/// walker count (`BucketTrees::advance_ranges`). What follows it is
/// the deal's bins, 32 a walker at twenty bytes each over nine slots
/// (`BucketTrees::bins_most`): about 5.8 KiB a walker, which
/// [`Engine::flight_term_over`] charges from this same figure.
///
/// **Why the cores.** A fixed twelve left a wide machine's walk at twelve
/// threads while its parses had the rest. Timed 1 Oct 2026 on an M3 Ultra
/// (24 performance and 8 efficiency cores, K=5, level 5, the default
/// width, the same bytes in every arm, every arm one binary), 24 walkers
/// against 12: text64 1.60x faster for 19 percent more CPU, a tree of
/// small files 1.06x, a solid tree 1.04x and code32 1.03x for 79 and 88
/// percent more CPU. An M1 Ultra (16 and 4) had read text64 1.21x at 16.
///
/// **Why not every core.** At 32 walkers the same timed run read text64
/// 1.66x and code32 1.09x, and the solid tree 0.97x, in every shape (a
/// volume set 0.93x) and for 2.5 times the CPU of twelve; the M1 Ultra
/// had read it 0.96x at 20. `cores::performance` says why a slow core
/// costs the walk more than it adds, and what an M5 Ultra, whose 36 cores
/// are all fast ones, read at 36 (text64 1.83x, the solid tree 1.10x,
/// indicative).
///
/// **Why macOS alone.** No machine of another system with more than
/// twelve cores had been timed when this was set, and the two arms that
/// lost in that timed run are what such a machine could be: slow cores
/// counted (a hybrid x86 part's physical count has them), and a wider walk
/// without the same-value store skip (24 walkers without it read code32
/// 0.93x; a Linux machine under one L3 never takes the skip). A shape
/// without a row keeps the default. These rows were
/// measured 1 Oct 2026; what a wide x86-64 Linux
/// machine then read is [`tree_walkers_by_class`]'s.
pub(crate) fn tree_walkers_most() -> usize {
    #[cfg(test)]
    if WIDE_WALKS.load(Ordering::Relaxed) != 0 {
        return WIDE_WALK_FOR_TEST;
    }
    if let Some(most) = reach_knob().tree_walkers {
        return most;
    }
    // Without the `parallel` feature the pool is one thread wide and the
    // cap is never reached.
    #[cfg(all(feature = "parallel", target_os = "macos"))]
    {
        // No level readable (an Intel Mac): the floor, as it was.
        TREE_WALKERS_FLOOR.max(crate::cores::performance().unwrap_or(0))
    }
    #[cfg(not(all(feature = "parallel", target_os = "macos")))]
    {
        TREE_WALKERS_FLOOR
    }
}

/// The fewest long matches in a member's head (`class::Reading::long_matches`)
/// for its walk to take [`tree_walkers_by_class`]: a member that keeps
/// the tree by its class and holds fewer walks at [`tree_walkers_most`].
///
/// **Measured** on a Xeon 8488C (48 cores, 96 threads, level 5, the
/// default width, K=9, the same bytes in both arms,
/// 3 Oct 2026): thirteen real members of 1 to 24 MiB that keep the tree and are
/// not prose, twelve walkers against 48. Every member holding 82 long
/// matches or more held or gained (a sorted word list of 206, 1.00; a CJK
/// dictionary of 82, 1.04; an image of 127, 1.05; a password dictionary
/// of 241, 1.30; a model of 402, 1.08; a table of 1,020, 1.03; text64,
/// 687, 1.87). Of the seven holding 47 or fewer, five LOST (an embedding
/// table of 23 MiB with none, 0.86 for four times the CPU; a tokenizer
/// table of 10, 0.61; a LUT of 10, 0.77; a model of 47, 0.87; a saliency
/// table of 21, 0.94) and two gained (27, 1.05; a dictionary of 29,
/// 1.39). Bytes with no long match are what a walk stalls on, one
/// dependent load after another, and more walkers add stall and not
/// work. The figure sits between 47 and 82; the two small members it
/// leaves at twelve walkers are 50 ms runs.
pub(crate) const WIDE_WALK_LONG_LEAST: u32 = 64;

/// The most threads that split the walk of a member that keeps the tree
/// BY ITS OWN CLASS and holds [`WIDE_WALK_LONG_LEAST`] long matches or
/// more in its head ([`Engine::start_member`]: a whole non-solid member
/// whose head was read and reads over level 5's cut-off): on x86-64 Linux
/// the machine's physical cores where they are of one kind
/// (`cores::alike`) and never fewer than [`tree_walkers_most`]; everywhere
/// else, and on a Linux machine the kernel calls hybrid,
/// [`tree_walkers_most`]. It moves no byte, as that cap does not.
///
/// **Counted 3 Oct 2026 on a Xeon 8488C** (48 cores, 96 threads, level 5,
/// the default width, the same bytes in every arm): text64,
/// which keeps the tree by its class, at twelve walkers kept 12.6 cores
/// busy of 96 and took 1.50 s, 0.73x of reference `rar`; 24 walkers 1.07
/// s, 48 walkers 0.82 s (1.35x of `rar`, 1.84x of twelve, for 1.9 times
/// the CPU and the same peak), and 96, a walker a THREAD, 1.30 s for six
/// times the CPU. A second hardware thread of a core adds the walk's
/// stall, not work, which is the slow core's cost again: so the cores,
/// never the threads.
///
/// **Why by the class, and not every walk.** The same timed run forced
/// every member under the tree with the class knob, twelve walkers
/// against 48: one 4 GiB member of binaries took 76 s at twelve and 84 s
/// at 48 for FOUR times the CPU, and a set of 9,516 binaries was level
/// for 3.3 times the CPU, where 32 MiB of generated code gained 1.19x.
/// The class rule gives those binaries to the chains, so no shipped route
/// walks them; what reaches the tree another way (a solid run, which is
/// its first member's class for members that are not read; an option
/// that keeps the tree for every member) may be such bytes, and keeps the
/// cap it had. Not measured yet, and needed before either widens: a solid run, and a real
/// member of the tree's class that is not text (a word list, a model
/// table).
pub(crate) fn tree_walkers_by_class() -> usize {
    let most = tree_walkers_most();
    // One kind of core, or the cap as it was: a machine the kernel calls
    // hybrid has no row. The count-only knob stands for both caps.
    #[cfg(all(feature = "parallel", target_os = "linux", target_arch = "x86_64"))]
    {
        if reach_knob().tree_walkers.is_some() {
            return most;
        }
        most.max(crate::cores::alike().unwrap_or(0))
    }
    #[cfg(not(all(feature = "parallel", target_os = "linux", target_arch = "x86_64")))]
    {
        most
    }
}

/// TEST ONLY. While this is not zero the walk's cap is
/// [`WIDE_WALK_FOR_TEST`] whatever the machine, so a test on a small box
/// walks as a wide one does. A count, as the walk's own stall is, so tests
/// that ask at once do not turn each other's off; it moves no byte, so a
/// test running beside one is not disturbed.
#[cfg(test)]
pub(crate) static WIDE_WALKS: AtomicUsize = AtomicUsize::new(0);

/// The cap while [`WIDE_WALKS`] is held: more walkers than any machine
/// this was measured on has cores.
#[cfg(test)]
pub(crate) const WIDE_WALK_FOR_TEST: usize = 40;

/// The finders store positions as `u32`, so a longer member is encoded as
/// spans of this many bytes, each with its own finder. A match does not
/// reach across the seam, which costs one dictionary's worth of matches
/// every two gibibytes.
pub(super) const SPAN_BYTES: usize = 1 << 31;

/// How far a CARRIED history may run past the dictionary before it is
/// slid down, as a multiple of the dictionary, and the ceiling on it.
///
/// The buffer holds the dictionary, which is everything a match may
/// reach, plus this much room to run. When it fills, the dictionary is
/// kept, everything older is dropped, and the index is built again over
/// what was kept: so carrying costs one rebuild of the dictionary per
/// slack bytes of input, where indexing the history once per MEMBER cost
/// one rebuild PER MEMBER and was what made a solid set eight times its
/// non-solid twin. A SOLID run's tree keeps its
/// index across the slide instead
/// (`Engine::slide_keeps_index`), and there a slide costs only the drop;
/// the rebuild is the chains' and a non-solid windowed member's. A multiple is the right
/// shape for it, because it makes that amortised cost a RATIO - at four,
/// a quarter of the index work - whatever the dictionary is, and because
/// everything else this engine holds is sized from the dictionary too.
/// The ceiling bounds the buffer's own bytes for the largest
/// dictionaries, at the price of a larger ratio there.
pub(crate) const HISTORY_SLACK_MULTIPLE: usize = 4;

pub(super) const HISTORY_SLACK_CEIL: usize = 64 << 20;

/// The slack multiple of ONE member streamed a window at a time (spec G
/// 3.7.3) where the caller set no memory ceiling: the writer's
/// `Run::compress_streaming` sets it with [`Engine::set_slack_multiple`]
/// for that member alone, and every other run keeps
/// [`HISTORY_SLACK_MULTIPLE`].
///
/// **Why eight, and what it moves.** A slide costs a rebuild of the index
/// over the dictionary it keeps (outside a solid run, which keeps the
/// tree's index), and it ends a batch of staged windows, so
/// a slide every four dictionaries was a fifth of a large member's wall at
/// the chain levels. Counted untimed on a Zen 5 rental (16 cores, 28 Sep
/// 2026): text64 `-m1` 0.30 s at four against 0.25
/// at eight, code32 `-m3` 0.24 against 0.20, code32 `-m5` 2.88 against
/// 2.61; sixteen bought nothing more at levels 1 to 3. It MOVES BYTES, a
/// few either way (text64 `-m3` +1, code32 `-m5` -14), because a slide
/// is not invisible to the output: the rebuild links the positions of the
/// history that no call had linked, the last three of each window, which
/// had no four bytes inside their own window.
/// The history buffer holds the dictionary and the slack, so
/// this is four dictionaries more at most, under the ceiling.
///
/// **Only from [`STREAMED_SLACK_LEAST_DICTIONARY`] up**, because below it
/// the wider history is what the chains' links are sized from, and it
/// doubled them: at a 256 KiB dictionary 2 Mi links became 4 Mi, a
/// streamed member's finder 12 MiB became 20, and the memory bounds
/// `tests/writers.rs` holds a windowed member to failed. From 2 MiB up
/// the links are already at their ceiling of `2 * dictionary` or 16 Mi at
/// either slack, and the tree's ring follows the dictionary alone, so no
/// finder grows and only the history does.
pub(crate) const STREAMED_SLACK_MULTIPLE: usize = 8;

/// The smallest dictionary a streamed member takes
/// [`STREAMED_SLACK_MULTIPLE`] at; see there.
pub(crate) const STREAMED_SLACK_LEAST_DICTIONARY: usize = 2 << 20;

/// The hint slots level 4's lazy tree plan keeps a position in a SOLID run
/// ([`Plan::solid_run`]).
pub(super) const SOLID_LEVEL4_SLOTS: usize = 2;

/// Dictionaries up to this size get a tree ring that reaches all of them.
pub(super) const TREE_FULL_REACH_MOST: usize = 4 << 20;

/// The most a block of bytes no level compresses adds to them when it is
/// encoded: its block header and code length tables, whose whole alphabet
/// at four bits a length is about 250 bytes, and nothing on the literals,
/// which a table of 256 equally likely bytes codes at eight bits.
/// Measured 28 Sep 2026 on 4 MiB of xorshift output at every level, RAR 5
/// and RAR 4, a member at a time and a window at a time: 2,233 to 2,278
/// bytes over 16 blocks, about 142 a block (the -m4 and -m5 memory work;
/// `encode::tests`'s packed bound test pins it). The writer's allowance
/// before that was 64 a block, which 20 MiB of such bytes outgrew.
pub(crate) const BLOCK_ROOM_BYTES: usize = 512;

/// The most a member (or a window) of `len` bytes packs to, whatever the
/// bytes are: `len` and [`BLOCK_ROOM_BYTES`] a parse block, at least one.
/// What the writer bounds a member's packed output by
/// (`Run::packed_bound`) and reserves a held member's buffer to.
pub(crate) fn packed_most(len: usize) -> usize {
    let blocks = len.div_ceil(PARSE_BLOCK_BYTES).max(1);
    len.saturating_add(blocks.saturating_mul(BLOCK_ROOM_BYTES))
}

/// What one block's packed output buffer is reserved at, for a block of
/// `len` bytes ([`packed_most`] of it). Reserved before the emit, so a
/// block's output does not regrow (a regrowth doubled a 256 KiB buffer to
/// 512 KiB for a block of incompressible bytes), and the buffers are kept
/// between waves ([`Engine::spare_outs`]).
pub(super) const fn block_out_bytes(len: usize) -> usize {
    len + BLOCK_ROOM_BYTES
}

/// What a parse's price model and entropy cuts hold, at most, for either
/// format: a few hundred symbols of prices and counts, and one cut per
/// fine grid point of a block. A bound, for [`Engine::flight_term`].
pub(super) const PARSE_TABLES_MOST: usize = 16 << 10;

/// The most output buffers [`keep_out`] keeps: two a thread of the pool,
/// and at least a full wave of sixteen blocks' worth.
pub(super) fn spare_outs_most() -> usize {
    (2 * threads()).max(2 * (HINT_BUDGET_BYTES / (PARSE_BLOCK_BYTES * 16)))
}

/// Whether a count build turned the carried sets off
/// (`RARKIT_CARRY_SETS=0` under the `carry-sets-knob` feature), the
/// control arm that writes a fresh set in every member as before. Read
/// once; a shipped build always carries.
pub(super) fn carry_off() -> bool {
    #[cfg(feature = "carry-sets-knob")]
    {
        static OFF: OnceLock<bool> = OnceLock::new();
        *OFF.get_or_init(|| std::env::var("RARKIT_CARRY_SETS").is_ok_and(|v| v == "0"))
    }
    #[cfg(not(feature = "carry-sets-knob"))]
    false
}

/// A count build's LOOKAHEAD arm (`RARKIT_CARRY_LOOKAHEAD=1` under the
/// `carry-sets-knob` feature): a chain's forced opener builds its set
/// from the counts of every member of its chain, not its own alone. Off
/// in every shipped build.
pub(super) fn carry_lookahead() -> bool {
    #[cfg(feature = "carry-sets-knob")]
    {
        static ON: OnceLock<bool> = OnceLock::new();
        *ON.get_or_init(|| std::env::var("RARKIT_CARRY_LOOKAHEAD").is_ok_and(|v| v == "1"))
    }
    #[cfg(not(feature = "carry-sets-knob"))]
    false
}

/// Whether a chain's forced opener builds its set from the counts of the
/// members written before it in the run beside its own (the WINDOW form,
/// the shipped one). A count build turns it off with
/// `RARKIT_CARRY_WINDOW=0` under the `carry-sets-knob` feature, the arm
/// whose opener reads its own counts alone.
pub(super) fn carry_window_on() -> bool {
    #[cfg(feature = "carry-sets-knob")]
    {
        static ON: OnceLock<bool> = OnceLock::new();
        *ON.get_or_init(|| std::env::var("RARKIT_CARRY_WINDOW").map_or(true, |v| v != "0"))
    }
    #[cfg(not(feature = "carry-sets-knob"))]
    true
}

/// The pool width from which the chains' pass is built across the pool
/// ([`Build`]) rather than run on one thread ahead of the parses: NEVER,
/// until the build is level everywhere it would run. Where it runs is a
/// wall question only: the links are the pass's either way, and
/// `RARKIT_CHAIN_BUILD` turns it on for a timed run.
///
/// Measured 30 Sep 2026, against the pass with zeroed links: on a Zen
/// 4 box of N cores, code32 and text64 at levels 1 to 3, 1.02x to 1.10x
/// at 32 cores but 0.96x at 24 (text64 -m2) and 0.95x on a solid small20k
/// at -m3 and 32; on the M5 Ultra at its default width, 0.94x on text64
/// -m1. Every builder links its piece against a head table of its own,
/// and eight 4 MiB tables beside the parses cost each position about
/// three times the pass (x86 `perf record`: the link step 15 percent of
/// the cycles where the pass was 6), which is what a next form has to
/// take away.
#[cfg(feature = "parallel")]
pub(super) const CHAIN_BUILD_FROM: usize = usize::MAX;

/// A bench knob over [`CHAIN_BUILD_FROM`]: a width, or `off`. Read once.
/// Nothing ships setting it.
#[cfg(feature = "parallel")]
pub(crate) const CHAIN_BUILD_ENV: &str = "RARKIT_CHAIN_BUILD";

/// The most builders one wave's build puts to work.
#[cfg(feature = "parallel")]
pub(super) const CHAIN_BUILDERS_MOST: usize = 8;

/// A bench knob over [`CHAIN_BUILDERS_MOST`]. Read once. Nothing ships
/// setting it.
#[cfg(feature = "parallel")]
pub(crate) const CHAIN_BUILDERS_ENV: &str = "RARKIT_CHAIN_BUILDERS";

#[cfg(feature = "parallel")]
pub(super) fn chain_build_from() -> usize {
    static FROM: OnceLock<usize> = OnceLock::new();
    *FROM.get_or_init(|| {
        match crate::knob::writer_var(CHAIN_BUILD_ENV)
            .ok()
            .as_deref()
            .map(str::trim)
        {
            Some("off") => usize::MAX,
            Some(width) => width
                .parse::<usize>()
                .map_or(CHAIN_BUILD_FROM, |width| width.max(2)),
            None => CHAIN_BUILD_FROM,
        }
    })
}

#[cfg(feature = "parallel")]
pub(super) fn chain_builders_most() -> usize {
    static MOST: OnceLock<usize> = OnceLock::new();
    *MOST.get_or_init(|| {
        crate::knob::writer_var(CHAIN_BUILDERS_ENV)
            .ok()
            .and_then(|most| most.trim().parse::<usize>().ok())
            .filter(|&most| most > 0)
            .unwrap_or(CHAIN_BUILDERS_MOST)
    })
}

pub(super) fn threads() -> usize {
    #[cfg(feature = "parallel")]
    {
        rayon::current_num_threads().max(1)
    }
    #[cfg(not(feature = "parallel"))]
    {
        1
    }
}
