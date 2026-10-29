//! How wide this process runs, and why it is not the core count.
//!
//! THE ENGINE HAS TWO worker controls, and they are not the same dial
//! (since 20 Sep 2026).
//! [`ReadOptions::workers`](rarkit::ReadOptions::workers) (API 8.4.2) is
//! the READ side's width and
//! [`WriteOptions::workers`](rarkit::WriteOptions::workers) (API 7.2) the
//! ENCODER'S, and both are plain CPU figures derived from no memory
//! budget. `MemoryPolicy::max_workers` is the MEMORY one and is no longer
//! either side's width: until 20 Sep 2026 a read had no CPU dial at all
//! and `-mt<n>` had to land on that memory field, where the default
//! budget held it at `working_limit / 64 MiB`, which is eight, on every
//! box. API 8.4 removed that ceiling; this module is the caller's half of
//! the same question.
//!
//! NEITHER `workers` field says anything about the thread pool those
//! workers run on, because the pool is not the engine's to own - a
//! library that resized the process's pool would be reaching past its
//! caller, and a host calls the engine directly with a pool it has sized
//! itself.
//!
//! This binary IS the application, so here the pool is ours.
//!
//! **AND SINCE THE DIAL, THE POOL IS ALSO THE READ'S WIDTH.** API 8.4.3
//! resolves a `ReadOptions::workers` of `None` - which is every run with
//! no `-mt<n>` on it, and so the default arm of every table anyone
//! quotes - to the width of the pool the caller owns. So a cap here is
//! not a CPU economy any more. It is the number of members the engine
//! decodes at once, and the number of lanes one member's tape decode may
//! use, set from a caller that used to be deciding only how many threads
//! existed. That is the whole of the finding below.
//!
//! ## The cap, why it was kept twice, and why it went
//!
//! This module capped a READ at six from 19 Sep 2026. The two tables that
//! put it there and kept it are further down and they are honest
//! measurements, but they are NOT evidence about today and must not be
//! cited as though they were: both were taken while `max_workers` held
//! the engine at eight members in flight whatever the pool was, so the
//! pool width could not buy a member and could only buy threads to spin.
//! Of course capping it was free. The dial is what gave the pool width
//! something to buy.
//!
//! Measured again on the dial tip, this binary against itself with the
//! cap removed, over the corpus in the stored tool gap script - eight
//! 32 MiB members, nine 16 MiB members and one 256 MiB member, each at
//! `-m0` and at `-m3`, plus a solid set, all half incompressible.
//! An M3 Mac, 32 cores, one-minute load 6.31 before and 5.14 after,
//! five rounds after a discarded warmup with the arms alternated inside
//! each round. PAIRED medians with a bootstrap interval, five pairs, so
//! every reading is the interval's and not the point estimate's. Above
//! 1.000x means the UNCAPPED build is slower:
//!
//! | leg | `t` | `x` |
//! |---|---|---|
//! | 8 x 32 MiB `-m0` | **0.727x** | 1.018x, straddles parity |
//! | 9 x 16 MiB `-m0` | **0.825x** | 0.995x, straddles parity |
//! | 1 x 256 MiB `-m0` | 0.992x, straddles | 1.032x, straddles parity |
//! | 8 x 32 MiB `-m3` | **0.448x** | **0.489x** |
//! | 9 x 16 MiB `-m3` | **0.495x** | **0.492x** |
//! | 1 x 256 MiB `-m3` | **0.967x** | **0.951x** |
//! | 8 x 32 MiB `-m3 -s` | 0.960x, straddles | 0.979x, straddles |
//!
//! NO LEG IS PROVEN WORSE and the LZ class halves. The stored class
//! splits, and the `-mt<n>` ladder says why: a stored member has no
//! decode at all - it is a read, a CRC32 and a write - so stored EXTRACT
//! saturates at a width of about eight and contends above it, where LZ
//! keeps gaining to 32 because every member in flight is another real
//! decoder. `8 x 32 MiB -m0` extract reads 32.5 ms at width 6, 29.1 at 8,
//! 29.6 at 16 and 33.3 at 32; the same corpus at `-m3` reads 92.6, 73.0,
//! 49.9 and 45.6.
//!
//! **Which is why the cap goes rather than moving to sixteen.** Summed
//! over the seven legs the uncapped width wins both commands: `x` 413 ms
//! against 426 at width 16 and 500 at width 6, `t` 292 ms against 307 and
//! 456. A cap would buy 4 ms on one stored leg and cost 20 to 40 on the
//! LZ ones.
//!
//! A laptop sign check taken first agreed on direction everywhere and
//! disagreed on one row - it read `1 x 256 MiB -m0` `t` at 1.048x, which
//! the quiet box settles at 0.992x with an interval of 0.989x to 1.004x.
//! That is the loaded-box trap (a figure taken under load is not a
//! result) caught the right way round, and it is why
//! the loaded figure is not the one in this table.
//!
//! **CPU does rise, and that is the trade being made rather than a
//! defect.** The 19 Sep table below found CPU tracking the pool, and it
//! still does: `8 x 32 MiB -m3` extract costs 0.688 CPU s against 0.499,
//! and 300 MiB of peak RSS against 295, for a wall that halves. The
//! project's gates all order those the same way - wall first, CPU and
//! RSS after - so the cap is gone and the observation stays as an
//! observation.
//!
//! The run was on aarch64; the x86-64
//! half is not measured, nor is a box wider than 32 cores, where the stored
//! class's contention above a width of eight might turn a flat row into
//! a losing one.
//!
//! ## The two older tables, kept because they say what was measured
//!
//! Timing `rarfast t` over two archives on an 18-core box, with the
//! per-stage width (`-mt<n>`) and the pool size crossed against each
//! other, CPU seconds tracked the POOL and barely moved with the width:
//!
//! | pool | 8 x 64 MiB members: wall / CPU | 8 x 24 MiB members: wall / CPU |
//! |---|---|---|
//! | 18 (core count) | 0.57 s / 1.23 s | 0.27 s / 0.55 s |
//! | 8 | 0.58 s / 1.19 s | - |
//! | 6 | - | 0.24 s / 0.44 s |
//! | 4 | 0.56 s / 1.08 s | 0.33 s / 0.44 s |
//! | 2 | 0.75 s / 1.02 s | 0.32 s / 0.42 s |
//!
//! And re-measured on 19 Sep after the engine stopped putting its decode
//! on this pool, over a 768 MiB solid volume set and 8 x 64 MiB
//! non-solid:
//!
//! | leg | capped at 6 | uncapped (18) | uncapped / capped |
//! |---|---|---|---|
//! | `t` solid volume set | 0.290 s / 1.71 CPU s | 0.300 s / 1.72 CPU s | 1.034 |
//! | `t` 8 non-solid members | 0.170 s / 0.94 CPU s | 0.170 s / 0.93 CPU s | 1.000 |
//! | `x` solid volume set | 0.380 s / 1.81 CPU s | 0.380 s / 1.80 CPU s | 1.000 |
//! | `x` 8 non-solid members | 0.230 s / 0.99 CPU s | 0.230 s / 1.00 CPU s | 1.000 |
//!
//! Both say a pool that could not buy a member was free to cap. Neither
//! says anything about a pool that can.
//!
//! **The create path was always the opposite, and measuring it is what
//! found that.** The first version of this module capped both, and the
//! encoder lost 50% of its wall for a 3% CPU saving: `rar a -m3` over
//! 4 x 64 MiB, five alternating pairs on an 18-core box, ran 15.2 s /
//! 98.9 CPU s at the box's own width against 23.1 s / 95.3 CPU s at a
//! pool of 6 - a paired median of 0.66x, nowhere near the 0.97x gate. An
//! encode's tree walk is long and genuinely parallel and uses every core
//! it is given. So the two sides now agree on the answer and still not on
//! the reasoning, which is why [`Work`] survives the cap that created it.

/// A ceiling on the pool a READ builds when the command line does not
/// say, or `None` for the box's own width.
///
/// `None` since 20 Sep 2026, and the module comment is why: for a run
/// with no `-mt<n>` on it, API 8.4.3 makes this figure "how many members
/// the engine decodes at once" and not merely "how many threads exist",
/// and six of them cost up to 55 percent of wall on a 32-core box.
///
/// **Reinstating one is not trimming a bonus.** On the default path the
/// engine's width and this pool are ONE figure and not two that add:
/// 8.4.3 resolves `workers: None` to the pool, so a cap here does not
/// shave something off the top of API 8.4's win, it decides whether a
/// user who types no switch receives that win at all. Measure the
/// ladder again before putting a number back.
///
/// It binds the DEFAULT and nothing else. `-mt<n>` sets
/// `ReadOptions::workers` to `Some(n)` in `crate::engine`, and 8.4.3
/// takes a `Some` exactly, so a switched run never reaches this constant
/// at all - which is why the class round's default arm was the one
/// carrying the gap.
///
/// It stays a named dial rather than disappearing into the expression
/// below, because a cap here is a MEASURED choice and a box wide enough
/// to want one is a measurement nobody has yet taken: reinstating one is
/// this one line, and [`width`]'s test says what a reinstated cap must
/// still do.
///
/// It is a CAP and never a floor: a box with fewer cores than a cap keeps
/// its own count. It does NOT apply to a WRITE; see [`Work`].
const READ_CAP: Option<usize> = None;

/// The largest LONE member a read runs on a pool of one.
///
/// A read of one member with data can use a second thread only where the
/// engine has one to give it, and for a member this small it has none:
/// the tape path's lanes start at 16 MiB (`MT_MIN_OUTPUT`), the cipher
/// and hash overlap needs two 4 MiB chunks, and member offload needs a
/// second member. What a pool at the box's width buys such a run is one
/// thread spawn per core and nothing to do on any of them.
///
/// Such a read now builds no worker at all ([`configure_serial`]).
///
/// A member of EXACTLY this size is one too (FROM-STUDIO 454 B): none of
/// the reasons above starts at 4 MiB, and a member of 4,194,304 bytes took
/// a pool at the box's width, 18 threads on an Apple M5 Max and 4.6M to
/// 5.9M instructions more than `-mt1` (counted 15 Oct 2026).
///
/// Counted on a small VPS (x86-64, 8 cores), `rarfast t` on the rivals
/// comparison's 1 MiB `-p` and `-hp` members: user instructions 48.4M against
/// 48.7M, kernel instructions 4.0M against 6.1M, task clock 10.6 ms
/// against 14 to 15 ms, eight `clone3` calls down to one
/// (the small encrypted member's fixed cost). On
/// the i9 the pool was 32 threads, and with `-p` it was spawned just
/// before the key derivation ran on the walking thread.
pub(crate) const LONE_MEMBER_MAX: u64 = 4 << 20;

/// Whether a read's members, given as the unpacked sizes of those that
/// carry data (directories left out by the caller), are one member of at
/// most [`LONE_MEMBER_MAX`], so that [`configure`] should size the pool at
/// one.
pub(crate) fn lone_small_member(sizes: impl IntoIterator<Item = u64>) -> bool {
    let mut sizes = sizes.into_iter();
    matches!((sizes.next(), sizes.next()), (Some(size), None) if size <= LONE_MEMBER_MAX)
}

/// Whether a read's members, given by the facts of those that carry data
/// (directories left out by the caller) as `(method, encrypted, has a
/// CRC32, split)`, are ONE clear stored member under a CRC32 that lies whole
/// in one volume: a run whose route hands the pool NO job (FROM-STUDIO
/// 518 C, the idle pool form's part (1)), so the walking thread can be its
/// whole pool ([`configure_serial`]) at any size.
///
/// **Why it hands the pool nothing, read from the route and not its
/// name.** One member is a breadth of one, so the walk drives it on the
/// walking thread and never through the engine's member pool (nor create
/// ahead's helpers, which `extract::Run::drive` arms only there). What the
/// engine does for such a member beside the walk, the seam's second thread
/// and the lanes of a wide read, is its own `std::thread::scope` threads,
/// sized by `ReadOptions::workers` and not by this pool, which is why the
/// caller states that width at what it is today. A CRC32 asks no pool.
///
/// **And why each other kind is out.** A BLAKE2sp member may hash its
/// leaves on the pool (the engine's `rayon::scope`), so it keeps today's
/// pool until its own count is home (518 C (2)). An encrypted member and a
/// split one are not counted. A member of [`LONE_MEMBER_MAX`] or less is
/// already serial, at a read width of one ([`lone_small_member`]). The
/// caller leaves out a stated `-mt<n>` and a solid set (518 C (3)).
///
/// Counted at 9a64f5843 (the seventh reading lane, 17 Oct 2026; plain
/// builds): `x` of one stored 16 MiB member at the default width made a
/// pool as wide as the box (18 threads on an Apple M5 Max, 20 on an M1
/// Ultra, 36 on an M5 Ultra, 16 on a Zen 4) and not one of them touched
/// the data, every read and write on the walking thread at both widths;
/// they spun 33 yields each, and the default lost to `-mt1` by 0.13 to 0.50
/// ms of wall on every box.
pub(crate) fn lone_clear_stored_member(
    facts: impl IntoIterator<Item = (u8, bool, bool, bool)>,
) -> bool {
    let mut facts = facts.into_iter();
    matches!(
        (facts.next(), facts.next()),
        (Some((0, false, true, false)), None)
    )
}

/// Make the walking thread the process's whole pool, for a read
/// [`lone_small_member`] has proven serial: no worker is created at all.
///
/// A pool of one built the ordinary way still spawns one idle worker.
/// Here the global pool adopts the calling thread as its only worker
/// (rayon's `use_current_thread`), so the engine's own asks of the pool,
/// its default width and any job it hands the pool, find a width of one
/// and never start a thread. Work handed to that pool is not taken up by
/// the walking thread on its own, which is safe here because the one
/// such hand-off on this path, the RAR 5 filter batch, is run by the
/// thread that collects it when no worker has started it.
///
/// Like [`configure`], it builds the pool once and a later call answers
/// what the first did.
pub(crate) fn configure_serial() -> Result<(), String> {
    #[cfg(feature = "parallel")]
    {
        BUILT.get_or_init(|| build(1, true)).clone()
    }
    #[cfg(not(feature = "parallel"))]
    {
        Ok(())
    }
}

/// What the one build of the process's pool answered: `Ok`, or why no
/// pool could be started. Shared by [`configure`] and
/// [`configure_serial`], so a second call of either never builds again.
#[cfg(feature = "parallel")]
static BUILT: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();

/// Build the global pool `width` wide (`serial`: the calling thread as its
/// one worker), and say why where the SYSTEM refused its threads.
///
/// Until 1 Oct 2026 the build's error was discarded. A pool that cannot
/// spawn its workers (an address space limit, a thread limit) leaves the
/// process with NO pool, and it cannot be built a second time: the first
/// use then panics, "The global thread pool has not been initialized",
/// exit 101, with the archive already created and left at 0 bytes
/// (counted under `ulimit -v 1048576` on 96 threads,
/// 1 Oct 2026). The caller now gets the
/// reason BEFORE it creates anything, and says it in its own words.
///
/// A pool that is ALREADY built (something used the pool before this ran)
/// is left alone and is not a failure: that error carries no system
/// error beneath it, which is how the two are told apart.
#[cfg(feature = "parallel")]
fn build(width: usize, serial: bool) -> Result<(), String> {
    let mut builder = rayon::ThreadPoolBuilder::new().num_threads(width);
    if serial {
        builder = builder.use_current_thread();
    }
    let built = builder.build_global();
    // `h2-probes` builds only (no shipped build reads it):
    // `RARFAST_POOL_SAY=1` says on stderr whether THIS call built the pool
    // and how wide it is, which `tests/one_member_pool.rs` reads.
    #[cfg(feature = "h2-probes")]
    if std::env::var("RARFAST_POOL_SAY").is_ok_and(|v| v.trim() == "1") {
        eprintln!(
            "rarfast pool: asked {width} serial {serial} built {} width {}",
            built.is_ok(),
            rayon::current_num_threads()
        );
    }
    match built {
        Ok(()) => Ok(()),
        Err(err) => match std::error::Error::source(&err) {
            None => Ok(()),
            Some(system) => Err(format!(
                "Cannot start {width} worker thread{}: {system}",
                if width == 1 { "" } else { "s" }
            )),
        },
    }
}

/// Which side of the engine is about to run.
///
/// They want opposite defaults, which is measured rather than assumed:
/// see the module comment. Nothing else about them differs here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Work {
    /// Extract, test, list: the box's own width, bounded by [`READ_CAP`]
    /// where one is set. It is not only this process's thread count: API
    /// 8.4.3 resolves the engine's own read width from it.
    Read,
    /// Create: the box's own width, because the encoder uses it. This
    /// sizes the POOL; the encoder's own ceiling inside it is
    /// `WriteOptions::workers`, which the create path sets from the same
    /// `-mt<n>` and leaves at `None` when there is none.
    Write,
}

/// Size the process's worker pool, once.
///
/// `threads` is `-mt<n>` where the command line gave one. Later calls do
/// nothing, which is what lets every command path call it without any of
/// them having to know whether another already has.
///
/// A pool that is already built is left alone rather than reported: the
/// only way that happens is a second call, and the first one's figure is
/// the one the run asked for.
///
/// `Err` carries why the system refused the pool's threads (`build`); the
/// caller says it and stops before it creates or writes anything.
pub(crate) fn configure(threads: Option<u64>, work: Work) -> Result<(), String> {
    configure_within(threads, work, None)
}

/// [`configure`], with the pool at most `most` wide where a figure is
/// given: an extract's width inside the open file limit
/// ([`extract_width_fit`]), which the caller has checked a stated
/// `-mt<n>` against first, so only the default is ever narrowed here.
pub(crate) fn configure_within(
    threads: Option<u64>,
    work: Work,
    most: Option<usize>,
) -> Result<(), String> {
    #[cfg(not(feature = "parallel"))]
    {
        let _ = (threads, work, most);
        Ok(())
    }
    #[cfg(feature = "parallel")]
    {
        BUILT
            .get_or_init(|| build(width_within(threads, work, most), false))
            .clone()
    }
}

/// The width [`configure_within`] builds the pool at: [`width`], at most
/// `most` where a figure is given, never below one. A read that takes the
/// serial pool in place of it states this figure as its read width
/// ([`lone_clear_stored_member`]), so the engine reads as wide as it would
/// have with the pool built.
pub(crate) fn width_within(threads: Option<u64>, work: Work, most: Option<usize>) -> usize {
    width(threads, work).min(most.unwrap_or(usize::MAX)).max(1)
}

/// The pool width for a run, from `-mt<n>` and the box.
///
/// Split out from [`configure`] so the rule is testable without building
/// a pool: a process gets exactly one global pool, so a test that built
/// one would decide the answer for every test after it.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
pub(crate) fn width(threads: Option<u64>, work: Work) -> usize {
    width_under(threads, work, address_space_limit())
}

/// [`width`] under a finite `RLIMIT_AS` of `address_space` bytes, or none.
/// Split out so the rule is testable on a box with no limit set.
fn width_under(threads: Option<u64>, work: Work, address_space: Option<u64>) -> usize {
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    // **Every width is held to what the address space maps** (1 Oct 2026,
    // under SPEC-API 8.2, "running
    // narrower is never an error"): a stated `-mt<n>` is an upper bound,
    // and completing narrower beats aborting with a 0-byte archive where
    // the reference completes. Until then only the default READ width was
    // held, and under `ulimit -v 1048576` a create at the default width or
    // at `-mt16` aborted on a failed allocation or a pool that could not
    // spawn, where rar 7.23 completed (1 Oct 2026).
    let mapped = width_within_address_space(address_space);
    match threads {
        // The parser has already bounded it to the reference's 1..=64.
        Some(n) => usize::try_from(n)
            .unwrap_or(usize::MAX)
            .clamp(1, cores.max(1))
            .min(mapped),
        // Both sides take the box's own width, and they arrive there by
        // different measurements: the read because its width is also the
        // engine's breadth (8.4.3), the write because the encoder's tree
        // walk uses every core it is given. Only the read has a dial for
        // a ceiling, and only because only the read has ever had one.
        None => match work {
            Work::Read => READ_CAP
                .map_or(cores, |cap| cores.min(cap))
                .min(mapped)
                .max(1),
            Work::Write => cores.min(mapped).max(1),
        },
    }
}

/// The address space one unit of width maps, at the most counted.
///
/// A read at width `n` runs about `3n + 1` threads, and under glibc each
/// reserves a 64 MiB malloc arena and its stack before it touches a page,
/// beside the windows and rings the engine's working limit bounds. Counted
/// on 30 Sep 2026 (a Zen 4 rental, x86-64, glibc), the
/// process's peak mapped size at `t` over four shapes (eight 64 MiB
/// members, 658 members, a solid set, one 1 GiB member): 138 MiB at `-mt1`,
/// 344 to 508 at `-mt2`, 574 to 906 at `-mt4`, 1164 to 1922 at `-mt8`, and
/// 1632 to 3003 at the box's own sixteen. 256 MiB a unit covers the worst
/// of every width counted.
///
/// A CREATE is inside the same figure: counted 1 Oct 2026 (a Zen 4 rental
/// and a 96-thread box, tree5k and text64 at `-m3`), the
/// widest stated width that completed was `-mt12` under 1 GiB, `-mt8`
/// under 768 MiB, `-mt4` under 512 MiB and `-mt2` under 256 MiB, where
/// this gives 4, 3, 2 and 1.
const ADDRESS_PER_WIDTH: u64 = 256 << 20;

/// The widest run a finite `RLIMIT_AS` of `limit` bytes can map, never
/// below one; unbounded with no limit.
///
/// Without it a shell's `ulimit -v 1048576` failed EVERY shape at the
/// default width within 10 ms, most with a panic on a thread that could
/// not be spawned, while `-mt4` ran level with no limit. It held only the
/// default read until 1 Oct 2026; it now holds a create and a stated
/// `-mt<n>` too (`width_under`).
fn width_within_address_space(limit: Option<u64>) -> usize {
    limit.map_or(usize::MAX, |bytes| {
        usize::try_from(bytes / ADDRESS_PER_WIDTH)
            .unwrap_or(usize::MAX)
            .max(1)
    })
}

/// A finite `RLIMIT_AS` (`ulimit -v`), where the per-width figure above
/// was counted: glibc on Linux, whose arenas are what a thread maps.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[allow(unsafe_code)]
pub(crate) fn address_space_limit() -> Option<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a live, writable `rlimit`, which is all
    // `getrlimit` writes; it reads nothing of ours.
    let ok = unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut limit) } == 0;
    (ok && limit.rlim_cur != libc::RLIM_INFINITY && limit.rlim_cur > 0).then_some(limit.rlim_cur)
}

/// Elsewhere not read: macOS does not enforce the limit on a map, and a
/// target without glibc's arenas was not counted.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub(crate) fn address_space_limit() -> Option<u64> {
    None
}

/// THE WAITING OUTPUTS this tool allows a read
/// (`rarkit::ReadOptions::waiting_outputs`, SPEC-API section 4, "Outputs
/// open at once"): how many extracted files may stay open, finished,
/// while they wait their turn to be closed in archive order.
///
/// The smaller of [`WAITING_MULTIPLE`] times the read's width and what
/// HALF THE SOFT DESCRIPTOR LIMIT leaves once the files still being
/// written (twice the width, the engine's bound) and
/// [`DESCRIPTORS_HELD`] are taken off it; the multiple alone where the
/// limit cannot be read, is unlimited, or does not exist (Windows).
/// `None`, which is the engine's one bound of twice the breadth, where
/// the multiple is 0. `RARKIT_OUTPUTS_WAITING` replaces the multiple for
/// a count.
///
/// **Half, and the writers off it, because the other half is spoken
/// for**: the volumes of a set the walk has crossed ahead of its workers
/// may hold up to half the limit open themselves (`rarkit`'s
/// `read::forwarded`), and a set of small volumes whose members are
/// written while others wait to close has both at once.
pub(crate) fn waiting_outputs(width: usize) -> Option<usize> {
    static MULTIPLE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let multiple = *MULTIPLE.get_or_init(|| {
        crate::knob::reader_var("RARKIT_OUTPUTS_WAITING")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(WAITING_MULTIPLE)
    });
    waiting_within(multiple, width, soft_limit())
}

/// [`waiting_outputs`]'s arithmetic, over a soft descriptor limit the
/// caller read (`None`: none to respect).
fn waiting_within(multiple: usize, width: usize, soft_limit: Option<u64>) -> Option<usize> {
    if multiple == 0 {
        return None;
    }
    let width = width.max(1);
    let by_width = multiple.saturating_mul(width);
    let by_files = soft_limit.map(|soft| {
        usize::try_from(soft / 2)
            .unwrap_or(usize::MAX)
            .saturating_sub(width.saturating_mul(2))
            .saturating_sub(DESCRIPTORS_HELD)
    });
    Some(by_files.map_or(by_width, |files| by_width.min(files)))
}

/// THE DESCRIPTORS CREATE AHEAD may hold at once (`extract::ahead`): the
/// files it has made ahead of the walk and the files whose close waits
/// for a helper, together. `None` where no soft limit binds.
///
/// The pool's own half of the limit is spent already ([`waiting_outputs`]:
/// the writers, the waiting files and [`DESCRIPTORS_HELD`]), so this is
/// the OTHER half, less [`DESCRIPTORS_HELD`] again for what neither counts
/// (the archive, directories being read, the system's own); and where a
/// selected member is split, whose forwarded volumes may take that half
/// (`rarkit`'s `read::forwarded`), a quarter, less the same.
///
/// **Why (counted 15 Oct 2026, an Apple M5 Max, `x` of 20,000 small
/// files at macOS's default soft limit of 256).** The close queue was
/// bounded by a constant 256 whatever the limit: once the helpers' closes
/// lagged the walk (100 us a close, planted for the count) the queue
/// reached 252 and every run ended `Too many open files`, and an M1 Ultra
/// met it unplanted (rep 26, 17,948 of 20,000 files written).
#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "parallel"))]
pub(crate) fn ahead_descriptors(any_split: bool) -> Option<usize> {
    ahead_within(soft_limit(), any_split)
}

/// [`ahead_descriptors`]'s arithmetic, over a soft descriptor limit the
/// caller read (`None`: none to respect).
#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "parallel"))]
fn ahead_within(soft_limit: Option<u64>, any_split: bool) -> Option<usize> {
    soft_limit.map(|soft| {
        let share = if any_split { soft / 4 } else { soft / 2 };
        usize::try_from(share)
            .unwrap_or(usize::MAX)
            .saturating_sub(DESCRIPTORS_HELD)
    })
}

/// THE WIDEST EXTRACT the soft descriptor limit holds, with that limit:
/// `None` where no limit binds.
///
/// An extract writes up to twice its width in files at once (the engine's
/// bound of twice the breadth), and no limit bounds that below the engine
/// (FROM-STUDIO 453 D). Those writers and [`DESCRIPTORS_HELD`] must fit
/// the pool's half of the limit ([`waiting_outputs`]), the other half
/// being create ahead's or the forwarded volumes'
/// ([`ahead_descriptors`]): `(soft / 2 - 16) / 2`, never below one. That
/// is 8 at a limit of 64, 56 at macOS's default 256 and 248 at Linux's
/// 1,024. Counted 15 Oct 2026 on an Apple M5 Max (`x` of 20,000 small
/// files at a limit of 64, create ahead held to its share): about
/// 2 x width + 9 descriptors live, so at 64 a width past about 26 fails
/// whatever create ahead holds.
pub(crate) fn extract_width_fit() -> Option<(u64, usize)> {
    let soft = soft_limit()?;
    Some((soft, width_fit_within(soft)))
}

/// [`extract_width_fit`]'s arithmetic over a soft limit the caller read.
fn width_fit_within(soft: u64) -> usize {
    (usize::try_from(soft / 2)
        .unwrap_or(usize::MAX)
        .saturating_sub(DESCRIPTORS_HELD)
        / 2)
    .max(1)
}

/// Whether this is the first time the process says its width was held
/// to the open file limit: it says so once, however many archives the
/// command reads.
pub(crate) fn first_width_note() -> bool {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    !SAID.swap(true, std::sync::atomic::Ordering::Relaxed)
}

/// The soft `RLIMIT_NOFILE` ([`descriptor_limit`]), read once.
fn soft_limit() -> Option<u64> {
    static LIMIT: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *LIMIT.get_or_init(descriptor_limit)
}

/// The multiple of the read's width [`waiting_outputs`] allows when
/// `RARKIT_OUTPUTS_WAITING` says nothing.
///
/// **Thirty-two, TIMED**
/// (1 Oct 2026; a 64-core
/// box, K=5, `x` of the gate's 4 GiB binary set to disk): with none the
/// extract reads 1.35x of the earlier pool, at 4 times the width 1.86x, at 8
/// 1.95x, at 16 2.12x and at 32 2.27x; at `-mt8` 1.04x, 1.33x, 1.52x,
/// 1.71x and 2.04x. The wall still falls at 32, and past it the
/// descriptor half is what binds on every box measured (at a soft limit
/// of 1,024, 464 waiting files on 16 threads and 368 on 64), so a larger
/// multiple would be a figure nothing reads.
/// Under `-mm512m` the process stays inside its budget at 32 (480 MiB at
/// most, six runs).
const WAITING_MULTIPLE: usize = 32;

/// The descriptors this tool holds whatever it extracts, taken off the
/// half of the limit the waiting files may use: the three standard
/// streams, the volume the walk is in and each member's own, and room to
/// spare.
const DESCRIPTORS_HELD: usize = 16;

/// The soft `RLIMIT_NOFILE`, read where there is one; `None` where it is
/// unlimited or cannot be read.
#[cfg(unix)]
#[allow(unsafe_code)]
fn descriptor_limit() -> Option<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a live, writable `rlimit`, which is all
    // `getrlimit` writes; it reads nothing of ours.
    let ok = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0;
    #[allow(clippy::unnecessary_cast)]
    let soft = limit.rlim_cur as u64;
    (ok && limit.rlim_cur != libc::RLIM_INFINITY && soft > 0).then_some(soft)
}

/// No descriptor limit of this kind off Unix.
#[cfg(not(unix))]
fn descriptor_limit() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cores() -> usize {
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    }

    /// One small member runs on a pool of one; two members, one large
    /// member or none keep the box's width.
    #[test]
    fn a_lone_small_member_takes_a_pool_of_one() {
        assert!(lone_small_member([1 << 20]));
        assert!(lone_small_member([0]));
        assert!(lone_small_member([LONE_MEMBER_MAX]));
        assert!(!lone_small_member([LONE_MEMBER_MAX + 1]));
        assert!(!lone_small_member([1, 1]));
        assert!(!lone_small_member([]));
    }

    /// One clear stored member under a CRC32, whole in one volume, hands
    /// the pool no job; every other kind, and two members or none, keep
    /// the pool they had (FROM-STUDIO 518 C).
    #[test]
    fn only_a_lone_clear_stored_crc32_member_hands_the_pool_nothing() {
        let plain = (0u8, false, true, false);
        assert!(lone_clear_stored_member([plain]));
        // Coded, encrypted, under BLAKE2sp, split.
        assert!(!lone_clear_stored_member([(3, false, true, false)]));
        assert!(!lone_clear_stored_member([(0, true, true, false)]));
        assert!(!lone_clear_stored_member([(0, false, false, false)]));
        assert!(!lone_clear_stored_member([(0, false, true, true)]));
        // Two members, or none.
        assert!(!lone_clear_stored_member([plain, plain]));
        assert!(!lone_clear_stored_member([]));
    }

    /// The width the pool is built at, which the serial pool's read
    /// states in its place: [`width`], held to `most`, never below one.
    #[test]
    fn the_width_within_is_the_pools_own() {
        for work in [Work::Read, Work::Write] {
            assert_eq!(width_within(None, work, None), width(None, work));
            assert_eq!(width_within(Some(1), work, None), 1);
            assert_eq!(width_within(None, work, Some(1)), 1);
            assert_eq!(width_within(None, work, Some(0)), 1);
            assert_eq!(width_within(None, work, Some(2)), width(None, work).min(2));
        }
    }

    /// `-mt<n>` is exact, up to what the box has, on BOTH sides.
    #[test]
    fn the_switch_sets_the_width() {
        for work in [Work::Read, Work::Write] {
            assert_eq!(width_under(Some(1), work, None), 1);
            assert_eq!(width_under(Some(2), work, None), 2.min(cores()));
            // Past the box's own count it saturates there: threads the box
            // cannot run at once are threads that only contend.
            assert_eq!(width_under(Some(64), work, None), 64.min(cores()));
        }
    }

    /// A finite address space holds EVERY width to what it maps, a unit
    /// per 256 MiB and never below one: a stated `-mt<n>` on either side
    /// and the default create, as the default read already was.
    #[test]
    fn the_address_space_holds_every_width() {
        const GIB: u64 = 1 << 30;
        for work in [Work::Read, Work::Write] {
            // 1 GiB maps four; `-mt16` and `-mt64` run at four.
            assert_eq!(width_under(Some(16), work, Some(GIB)), 4.min(cores()));
            assert_eq!(width_under(Some(64), work, Some(GIB)), 4.min(cores()));
            // A width inside it is exact.
            assert_eq!(width_under(Some(2), work, Some(GIB)), 2.min(cores()));
            // The default follows it too, on both sides.
            assert_eq!(width_under(None, work, Some(GIB)), 4.min(cores()));
            assert_eq!(width_under(None, work, Some(GIB / 2)), 2.min(cores()));
            // Never below one, however small the space.
            assert_eq!(width_under(None, work, Some(64 << 20)), 1);
            assert_eq!(width_under(Some(8), work, Some(64 << 20)), 1);
            // A space the box's width fits inside changes nothing.
            assert_eq!(
                width_under(None, work, Some(1024 * GIB)),
                width_under(None, work, None)
            );
            assert_eq!(
                width_under(Some(8), work, Some(1024 * GIB)),
                width_under(Some(8), work, None)
            );
        }
    }

    /// A pool that is already built is not a failure, from either door,
    /// and a second call answers what the first did.
    #[cfg(feature = "parallel")]
    #[test]
    fn a_built_pool_is_not_a_refusal() {
        assert_eq!(configure(Some(2), Work::Write), Ok(()));
        assert_eq!(configure(Some(64), Work::Read), Ok(()));
        assert_eq!(configure_serial(), Ok(()));
        // The build itself, asked again: the pool is there, and that is
        // told apart from a system that refused its threads.
        assert_eq!(build(2, false), Ok(()));
    }

    /// With no switch a READ takes the box's own width, which since API
    /// 8.4.3 is also the width the engine resolves for it. A cap of six
    /// here was the class round's stored and LZ gap.
    #[test]
    fn a_read_takes_the_boxs_own_width() {
        // Under a shell's `ulimit -v` the address space binds instead,
        // which the test below pins; the box's width is the unlimited case.
        if address_space_limit().is_none() {
            assert_eq!(width(None, Work::Read), cores());
        }
    }

    /// SPEC-API 8.4.6: a finite `RLIMIT_AS` narrows the
    /// DEFAULT read to what it can map, a
    /// unit of width per 256 MiB and never below one: 1 GiB is `-mt4`,
    /// the widest the count found level with no limit; 4 GiB is sixteen.
    #[test]
    fn the_address_space_bounds_the_default_read() {
        assert_eq!(width_within_address_space(None), usize::MAX);
        assert_eq!(width_within_address_space(Some(1 << 30)), 4);
        assert_eq!(width_within_address_space(Some(4 << 30)), 16);
        assert_eq!(width_within_address_space(Some(200 << 20)), 1);
        assert_eq!(width_within_address_space(Some(0)), 1);
    }

    /// And what a reinstated [`READ_CAP`] would have to do, pinned so that
    /// putting a measured figure back is one line and not a rewrite: bind
    /// from above, and never raise a box that has fewer cores than it.
    #[test]
    fn a_cap_would_bind_from_above_and_never_from_below() {
        let capped = |cap: Option<usize>| cap.map_or(cores(), |c| cores().min(c)).max(1);
        assert_eq!(capped(None), cores());
        assert_eq!(capped(Some(1)), 1);
        assert_eq!(capped(Some(usize::MAX)), cores());
        assert_eq!(capped(Some(cores() + 1)), cores());
    }

    /// And a WRITE is not capped: the encoder uses every core, and capping
    /// it cost 50% of the create wall when this module first did. (Under a
    /// shell's `ulimit -v` the address space binds, which the test above
    /// pins.)
    #[test]
    fn a_write_keeps_the_boxs_own_width() {
        assert_eq!(width_under(None, Work::Write, None), cores());
    }

    /// The allowance for finished files waiting to close: nothing at a
    /// multiple of 0; the multiple of the width where no limit binds; and
    /// never more than half the soft descriptor limit less what the tool
    /// holds anyway, down to none at all under a very small limit.
    #[test]
    fn the_waiting_outputs_stay_inside_half_the_descriptor_limit() {
        assert_eq!(waiting_within(0, 64, Some(1024)), None);
        assert_eq!(waiting_within(8, 8, None), Some(64));
        assert_eq!(waiting_within(8, 8, Some(1024)), Some(64));
        // 64 threads under Linux's 1,024: half, less 128 writers, less 16.
        assert_eq!(waiting_within(32, 64, Some(1024)), Some(512 - 128 - 16));
        // 16 threads: 512 - 32 - 16, under the multiple's 512.
        assert_eq!(waiting_within(32, 16, Some(1024)), Some(512 - 32 - 16));
        // macOS's 256 on 32 threads: 128 - 64 - 16.
        assert_eq!(waiting_within(32, 32, Some(256)), Some(48));
        // A limit the writers alone fill leaves no allowance, never a wrap.
        assert_eq!(waiting_within(32, 96, Some(256)), Some(0));
        assert_eq!(waiting_within(8, 32, Some(24)), Some(0));
        assert_eq!(waiting_within(8, 0, None), Some(8));
        for soft in [16u64, 64, 256, 1024, 4096, 1 << 20] {
            for width in [1usize, 8, 64, 96] {
                for multiple in [1usize, 4, 16, 32] {
                    let n = waiting_within(multiple, width, Some(soft)).expect("a multiple");
                    assert!(
                        n == 0 || (n + 2 * width + DESCRIPTORS_HELD) as u64 <= soft / 2,
                        "{n} waiting beside {width} threads' writers under a limit of {soft}"
                    );
                    assert!(n <= multiple * width);
                }
            }
        }
    }

    /// The widest extract a limit holds: its writers (twice the width) and
    /// what the tool holds inside the pool's half, never below one.
    #[test]
    fn an_extracts_width_fits_its_writers_in_half_the_descriptor_limit() {
        assert_eq!(width_fit_within(64), 8);
        assert_eq!(width_fit_within(256), 56);
        assert_eq!(width_fit_within(1024), 248);
        assert_eq!(width_fit_within(36), 1);
        assert_eq!(width_fit_within(16), 1);
        assert_eq!(width_fit_within(0), 1);
        for soft in [40u64, 64, 96, 256, 1024, 4096, 1 << 20] {
            let fit = width_fit_within(soft);
            assert!(
                (2 * fit + DESCRIPTORS_HELD) as u64 <= soft / 2,
                "{fit} under {soft}"
            );
            assert!(
                (2 * (fit + 1) + DESCRIPTORS_HELD) as u64 > soft / 2,
                "{fit} under {soft}"
            );
        }
    }

    /// Create ahead's descriptors: the half of the limit the pool does not
    /// spend, less what the tool holds anyway; a quarter where a split
    /// member's forwarded volumes may take that half; none to respect
    /// where no limit binds; never a wrap under a very small limit.
    #[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "parallel"))]
    #[test]
    fn create_ahead_stays_inside_the_other_half_of_the_descriptor_limit() {
        assert_eq!(ahead_within(None, false), None);
        assert_eq!(ahead_within(None, true), None);
        // macOS's default 256: 128 - 16, and 64 - 16 beside a split member.
        assert_eq!(ahead_within(Some(256), false), Some(112));
        assert_eq!(ahead_within(Some(256), true), Some(48));
        assert_eq!(ahead_within(Some(64), false), Some(16));
        assert_eq!(ahead_within(Some(1024), false), Some(496));
        assert_eq!(ahead_within(Some(24), false), Some(0));
        assert_eq!(ahead_within(Some(0), true), Some(0));
        for soft in [16u64, 64, 256, 1024, 4096, 1 << 20] {
            for any_split in [false, true] {
                let n = ahead_within(Some(soft), any_split).expect("a limit");
                assert!(n == 0 || n as u64 + DESCRIPTORS_HELD as u64 <= soft / 2);
            }
        }
    }
}
