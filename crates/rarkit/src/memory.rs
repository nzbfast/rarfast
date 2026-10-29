//! Memory policy and accounting (API spec section 8, spec F section 4).
//!
//! Section 8 asks for ONE budget behind every kind of work the engine
//! does, so a caller sizes the engine once instead of reasoning separately
//! about reading, writing and repair; [`MemoryPolicy::from_limit`] spreads
//! a single figure over the fields, and each stays public so a caller with
//! a reason can move one.
//!
//! The counters below are the other half of section 8: they answer what
//! the engine is holding right now, PROCESS-wide rather than per call, and
//! they include memory nothing is currently using - the buffers an idle
//! decoder keeps so the next member need not allocate them again. An
//! operation that wants only its own high-water mark reads it from the
//! report it is handed.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// What the engine is allowed to hold, for every kind of work it does.
///
/// Derive the whole of it from one figure with
/// [`from_limit`](MemoryPolicy::from_limit), which is what section 8
/// intends, and then move a field if a particular caller needs it moved:
/// nothing here is private, and nothing re-derives behind your back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryPolicy {
    /// The most the engine may hold at once for one operation. Every other
    /// field is bounded by this one, with ONE exception: the DEFAULT
    /// policy's `max_window`, which is sized from the machine rather than
    /// from this figure (see [`MemoryPolicy::default`]).
    pub working_limit: u64,
    /// The largest window a member may NEED and still be decoded; a member
    /// needing more is refused rather than served. What a member needs is
    /// its declared dictionary, or its unpacked size where that is smaller
    /// and nothing after it continues the window.
    pub max_window: u64,
    /// The largest dictionary a writer of ours will choose to use.
    pub max_dictionary: u64,
    /// The ceiling for repair, which holds parity rather than a window and
    /// so is budgeted apart from the two above.
    pub repair_limit: u64,
    /// How far beyond the byte it needs the engine may ask a source to
    /// read, which is what buys sequential throughput from a source that
    /// rewards it.
    pub read_ahead: u64,
    /// The most threads any one operation may put to work.
    pub max_workers: usize,
    /// Largest header this crate parses, before any allocation is sized by
    /// a header field (spec F 4.1).
    pub max_header: u64,
    /// Ceiling on one volume's member table plus its name arena, counted in
    /// bytes (spec F 4.2).
    pub max_member_table: u64,
    /// Largest archive comment decoded; a comment above it is reported as
    /// no comment, never as an error (spec F 3.2.9).
    pub max_comment: u64,
    /// Whether the caller NAMED `working_limit`, which its figure cannot
    /// say (SPEC-API 8, 28 Sep 2026): [`MemoryPolicy::default`] sets it
    /// false and [`from_limit`](MemoryPolicy::from_limit) (so
    /// [`for_process`](MemoryPolicy::for_process)) sets it true for every
    /// figure, [`DEFAULT_LIMIT`](MemoryPolicy::DEFAULT_LIMIT)
    /// included, so a caller who names 512 MiB has named a ceiling. Set
    /// it as you mean when building a policy field by field: true makes
    /// `working_limit` a ceiling the caller chose, false an allowance.
    /// It is what a write asks whether a ceiling was set (spec G 3.5's
    /// streaming mode, `WriteReport::ceiling_exceeded_by`), and what a
    /// read asks before its one-member floor and its breadth cap: only a
    /// named ceiling is refused up front.
    pub limit_named: bool,
    /// What the process holds BESIDES engine working memory, when the
    /// policy was built for a whole-process budget
    /// ([`for_process`](MemoryPolicy::for_process),
    /// [`process_default`](MemoryPolicy::process_default)): the
    /// [`PROCESS_HEADROOM`](MemoryPolicy::PROCESS_HEADROOM) plus the
    /// caller's stated resident holdings. Zero for an engine budget. It
    /// sizes nothing; it is what turns a refusal's figures back into the
    /// terms the caller stated (`needed` and `limit` in the
    /// terms of the constructor that built the policy).
    pub process_overhead: u64,
    /// The memory cap of the process's ENVIRONMENT that lowered the default
    /// budget, in bytes: the cgroup memory limit (the smallest on the
    /// process's own path and its ancestors) or a finite `RLIMIT_AS`,
    /// whichever left the smaller budget. Zero where no cap bound, and
    /// zero from [`from_limit`](MemoryPolicy::from_limit),
    /// [`for_process`](MemoryPolicy::for_process) and
    /// [`default`](MemoryPolicy::default): a named figure is the caller's,
    /// not the environment's. Only
    /// [`process_default`](MemoryPolicy::process_default) sets it.
    ///
    /// It sizes nothing. It is what a CREATE is refused against, before
    /// its first byte, where even its narrowest plan cannot fit: past this
    /// figure the kernel kills the process (a cgroup) or refuses its
    /// memory (an address space), and a killed create leaves a partial
    /// archive under the final name (SPEC-API 8.4.1, spec G 3.5).
    pub environment_cap: u64,
}

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// The ceiling [`MemoryPolicy::from_limit`] clamps `max_window` and
/// `repair_limit` to, and the one it clamps `max_dictionary` to, BY
/// POINTER WIDTH.
///
/// On a 64-bit target these are spec F section 4's figures, 4 GiB and
/// 1 GiB, and nothing here changes.
///
/// On a 32-BIT target a 4 GiB ceiling is the whole address space, of which
/// a user process gets 2 or 3 GiB at best and shares that with the packed
/// buffer, the decoder's tables, the output path, the allocator's own
/// fragmentation and every other mapping. A ceiling nothing can ever map
/// is not a ceiling. `armv7-unknown-linux-musleabihf` is a shipped
/// artifact and the consuming application clamps its OWN budget to 1 GiB
/// of address space there, so rarkit takes half of that for a decode
/// window and a quarter for an encode dictionary: a window at the ceiling
/// still leaves the rest of the process room to work in. A dictionary
/// above the clamp is refused as
/// `LimitExceeded { resource: Window }` before any allocation
/// (spec F section 4.2), which `Rar5Lz::new` already does; it is never
/// attempted and then found to fail.
///
/// NOT YET SPECIFIED: `SPEC-API-rarkit.md` section 8 and spec F
/// section 4 say nothing about pointer width, so these two figures are a
/// conservative choice made here and not a pinned answer. The spec text
/// that pins them is not written yet.
#[cfg(target_pointer_width = "64")]
const WINDOW_CEILING: u64 = 4 * GIB;
/// The 32-bit arm. Written as `not("64")` so a target narrower than 32
/// bits gets the conservative figure too rather than no arm at all; the
/// `usize::try_from` in the window constructors refuses what such a target
/// still cannot address.
#[cfg(not(target_pointer_width = "64"))]
const WINDOW_CEILING: u64 = 512 * MIB;

#[cfg(target_pointer_width = "64")]
const DICTIONARY_CEILING: u64 = GIB;
#[cfg(not(target_pointer_width = "64"))]
const DICTIONARY_CEILING: u64 = 256 * MIB;

/// `value` clamped into `[low, high]`, with `low` winning a crossed pair so
/// the result is monotone in `value` whatever the bounds are.
const fn clamp(value: u64, low: u64, high: u64) -> u64 {
    if value > high {
        high
    } else if value < low {
        low
    } else {
        value
    }
}

impl MemoryPolicy {
    /// The floor under `max_dictionary`: below this a writer gains nothing
    /// from a smaller window and pays for it in ratio. PROVISIONAL, and
    /// spec G is what fixes the figure.
    pub const MIN_DICTIONARY: u64 = 128 * KIB;

    /// The budget [`MemoryPolicy::default`] derives every field from, all
    /// but `max_window`.
    pub const DEFAULT_LIMIT: u64 = 512 * MIB;

    /// Derive every field from one budget.
    ///
    /// Monotone: every field is a clamped monotone function of
    /// `working_limit`, so a larger limit never yields a smaller field.
    /// The default budget reproduces the figures spec F section 4 names:
    /// a 1 MiB header, a 64 MiB member table, a 1 MiB comment and 4 MiB of
    /// read-ahead.
    ///
    /// The ceilings in the table are the 64-bit ones; on a 32-bit target
    /// the window and repair ceilings are 512 MiB and the dictionary
    /// ceiling is 256 MiB: a 4 GiB ceiling is the whole address space of a
    /// 32-bit process, so it is no ceiling at all there. At the
    /// default budget every field is well under both, so the default
    /// policy is the same figure on either width.
    ///
    /// The last column is `from_limit(DEFAULT_LIMIT)`.
    /// [`MemoryPolicy::default`] is that, except that its `max_window` is
    /// half of physical memory.
    ///
    /// **`max_window` is the limit itself** (SPEC-API 8.4.1, the account's
    /// item 4; half of it until 12 Oct 2026). What refuses a member's
    /// window under a stated budget is the ACCOUNT at a width of one, one
    /// window and the fixed part against the limit, and not a share of the
    /// limit: a half refused members a width of one holds with room to
    /// spare. A caller may still set the field lower by hand.
    ///
    /// | Field | Derivation | At the default budget |
    /// |---|---|---|
    /// | `max_window` | the limit, in \[1 MiB, 4 GiB\] | 512 MiB |
    /// | `max_dictionary` | limit / 4, in \[`MIN_DICTIONARY`, 1 GiB\] | 128 MiB |
    /// | `repair_limit` | limit / 2, in \[1 MiB, 4 GiB\] | 256 MiB |
    /// | `read_ahead` | limit / 64, in \[64 KiB, 4 MiB\] | 4 MiB |
    /// | `max_workers` | limit / 64 MiB, in \[1, 64\] | 8 |
    /// | `max_header` | limit / 512, in \[64 KiB, 2 MiB\] | 1 MiB |
    /// | `max_member_table` | limit / 8, in \[1 MiB, 1 GiB\] | 64 MiB |
    /// | `max_comment` | limit / 512, in \[64 KiB, 2 MiB\] | 1 MiB |
    pub const fn from_limit(working_limit: u64) -> MemoryPolicy {
        MemoryPolicy {
            working_limit,
            max_window: clamp(working_limit, MIB, WINDOW_CEILING),
            max_dictionary: clamp(
                working_limit / 4,
                MemoryPolicy::MIN_DICTIONARY,
                DICTIONARY_CEILING,
            ),
            repair_limit: clamp(working_limit / 2, MIB, WINDOW_CEILING),
            read_ahead: clamp(working_limit / 64, 64 * KIB, 4 * MIB),
            max_workers: clamp(working_limit / (64 * MIB), 1, 64) as usize,
            max_header: clamp(working_limit / 512, 64 * KIB, 2 * MIB),
            max_member_table: clamp(working_limit / 8, MIB, GIB),
            max_comment: clamp(working_limit / 512, 64 * KIB, 2 * MIB),
            limit_named: true,
            process_overhead: 0,
            environment_cap: 0,
        }
    }

    /// The most threads ONE RAR 5 member whose window is `window` bytes is
    /// decoded on under this policy's budget (SPEC-API 8.4.1, the account
    /// per width): the widest arrangement whose account fits, down to one.
    /// `None` where a member of `unpacked` bytes is decoded on one thread
    /// whatever the budget, so no budget narrowed it.
    ///
    /// A caller that named a width asks this to learn whether the budget
    /// ran a member narrower than it asked; the read itself never needs
    /// it.
    pub fn member_width(&self, window: u64, unpacked: u64) -> Option<usize> {
        crate::rar5_lz::member_width(self, window, unpacked)
    }

    /// What a process holds besides the engine's own working memory while
    /// it reads, DERIVED BY COUNT: thread stacks, the
    /// process's base, and memory the allocator keeps after a free.
    ///
    /// Counted on 29 Sep 2026, bin4g (9,516
    /// real binaries, rar 7.23 `-m3`) read through the library at stated
    /// budgets of 96 to 256 MiB and the default, one to eighteen
    /// look-ahead workers, the process peak minus `memory::peak`: at most
    /// 22.6 MiB on x86-64 (a Zen 5 rental, glibc with its trim threshold at
    /// 0, maximum resident set) and 17.9 MiB on macOS (M5 Max,
    /// `phys_footprint`). 32 MiB covers both with 9 MiB to
    /// spare; a test pins it against those counts.
    pub const PROCESS_HEADROOM: u64 = 32 * MIB;

    /// A policy for a WHOLE-PROCESS budget (8.4.1): the caller
    /// states `budget` for the process and `caller_resident`, what it holds
    /// itself; the engine's `working_limit` is `budget -
    /// PROCESS_HEADROOM - caller_resident`, and every other field is
    /// derived from that as [`from_limit`](MemoryPolicy::from_limit)
    /// derives it. A STATED budget, hard as any. A budget below the two
    /// overheads alone derives a zero limit, which the read refuses before
    /// any member as `LimitExceeded { resource: WorkingMemory }` in process
    /// terms.
    pub const fn for_process(budget: u64, caller_resident: u64) -> MemoryPolicy {
        let overhead = MemoryPolicy::PROCESS_HEADROOM.saturating_add(caller_resident);
        let mut policy = MemoryPolicy::from_limit(budget.saturating_sub(overhead));
        policy.process_overhead = overhead;
        policy
    }

    /// [`for_process`](MemoryPolicy::for_process) applied to the DEFAULT
    /// process budget when the caller stated none, with `max_window` raised
    /// as [`default`](MemoryPolicy::default) raises it.
    ///
    /// **The default budget scales with the machine (1 Oct
    /// 2026): the larger of [`DEFAULT_LIMIT`](MemoryPolicy::DEFAULT_LIMIT)
    /// (512 MiB, the floor rarkit must run in) and a QUARTER of physical
    /// memory**, the reading `max_window`'s default takes (installed
    /// memory, lowered to a cgroup limit, read once); the floor where it
    /// cannot be read. `working_limit` follows it, and `repair_limit`,
    /// which is half of it (in \[1 MiB, 4 GiB\], as
    /// [`from_limit`](MemoryPolicy::from_limit) derives it): every other
    /// field is `DEFAULT_LIMIT`'s, and `limit_named` stays false. A caller that
    /// NAMES a budget (`for_process`, `from_limit`) gets that figure on any
    /// machine, above the scaled default or below it.
    ///
    /// **Where the process runs under a MEMORY CAP of its environment, the
    /// cap binds `working_limit`.** The caps read are the cgroup memory
    /// limit (the smallest on the process's own cgroup path and its
    /// ancestors, as [`default`](MemoryPolicy::default) reads it for the
    /// window) and, on Linux and Android, a finite `RLIMIT_AS`. The
    /// process budget they leave is three quarters of the cgroup limit or
    /// the limit less 96 MiB, whichever is larger (the rest is the page
    /// cache and kernel memory the cgroup is also charged for), and a
    /// quarter of the address space (the rest is the
    /// stacks and allocator arenas every thread maps), whichever is
    /// smaller, and where that is below the scaled default budget,
    /// `working_limit` is what `for_process` derives from it instead.
    /// `repair_limit` is half of the lowered limit, so a repair stays
    /// under the cap too. Nothing else moves: every other field is
    /// `DEFAULT_LIMIT`'s, so no
    /// header, member table or comment the uncapped default accepts is
    /// refused, the window stays the machine's, and the policy stays an
    /// allowance (`limit_named` false: no pre-scan, no floor refusal). The
    /// read then narrows by itself: a member is admitted against the
    /// operation's live charges within the lowered limit (so the members
    /// in flight fall to what fits, never below one), and the tape lanes,
    /// the decode-ahead and the solid walk's queue are each sized from
    /// `working_limit`. Without this a cap below the default breadth's
    /// working set got the extract killed by the kernel with a partial
    /// tree on disk (eight 64 MiB members under a 256 MiB `MemoryMax`,
    /// counted 30 Sep 2026 on x86-64).
    ///
    /// The lowered limit NARROWS BREADTH and refuses no window (SPEC-API
    /// 8.1 term 2): a member alone is admitted whatever its
    /// window, up to `max_window`, and no pre-scan is run. The only
    /// checks it can newly fail are the two that compare against
    /// `working_limit` itself, both RAR 3 and at the member before its
    /// allocation: the text model beside its window, and the filter
    /// staging. What refuses a window is `max_window`, which under a
    /// finite `RLIMIT_AS` is also at most half of it (see
    /// [`default`](MemoryPolicy::default)).
    ///
    /// With no cap, or one whose share is at or above the scaled default
    /// budget, the policy is the machine's scaled default.
    pub fn process_default(caller_resident: u64) -> MemoryPolicy {
        let (budget, cap) = environment_budget();
        let physical = physical_memory();
        let mut policy = process_default_under(caller_resident, budget, physical);
        policy.environment_cap = bound_cap(budget, cap, physical);
        policy
    }

    /// Whether a read keeps what the process HOLDS to `working_limit`, and
    /// not only what it declares: every dropped ring's pages given back,
    /// the rings rebuilt small between members
    /// (`Shrink::Tight`), each worker's scratch given back after every
    /// member, and each member admitted against the operation's LIVE
    /// charges as well as the windows declared (SPEC-API 8.4.1).
    ///
    /// True under a NAMED budget, where the ceiling is hard; and true for
    /// a WHOLE-PROCESS policy whose limit was not named
    /// ([`process_default`](MemoryPolicy::process_default), what `rarfast`
    /// reads under with no `-mm`), because the default 512 MiB is a
    /// figure for the process and a process is measured in resident
    /// bytes: with no `-mm`, `rarfast x` of bin4g on macOS aarch64 held
    /// 526.8 MiB (`phys_footprint`, 20 cores) while the engine's meter
    /// peaked at 183 to 196 MiB, the gap being what this switched off
    /// (counted 29 Sep 2026). It
    /// refuses nothing and reserves nothing: the default stays an
    /// allowance, a member with nothing else in flight is always admitted,
    /// and no pre-scan is run for it (the one-member floor is a NAMED
    /// budget's alone). False for the engine's own
    /// [`default`](MemoryPolicy::default), which states no process and is
    /// as it was.
    pub fn keeps_residency(&self) -> bool {
        self.limit_named || self.process_overhead > 0
    }
}

impl Default for MemoryPolicy {
    /// [`from_limit`](MemoryPolicy::from_limit) at
    /// [`DEFAULT_LIMIT`](MemoryPolicy::DEFAULT_LIMIT), with `max_window`
    /// raised to HALF OF THE MACHINE'S PHYSICAL MEMORY.
    ///
    /// By default rarkit opens every archive unrar opens. A flat 256 MiB
    /// window refused a 512 MiB dictionary that reference `rar` 7.23
    /// writes whenever `-md512m` or more meets more than 256 MiB of input,
    /// and that unrar reads. Memory stays disciplined by SIZING instead:
    /// a non-solid member's window is no larger than its unpacked size,
    /// so the large ceiling is committed only by a member
    /// that needs it, which in practice is a solid stream with its
    /// declared dictionary.
    ///
    /// The figure is never below `from_limit`'s own 256 MiB and never
    /// above the pointer-width ceiling (4 GiB, or 512 MiB on a 32-bit
    /// target), except that under a finite `RLIMIT_AS` (Linux and
    /// Android) it is never above HALF of that, the floor included, so a
    /// window the address space cannot map is refused as `Window` before
    /// any allocation. Physical memory is read once per
    /// process:
    ///
    /// - on Linux, Android, macOS, iOS and the BSDs as `sysconf`'s page
    ///   count times its page size, and on Linux and Android lowered to
    ///   the cgroup's memory limit when one is set, so a container gets
    ///   half of what it may hold rather than half of the host;
    /// - on Windows as `GlobalMemoryStatusEx`'s total physical memory;
    /// - WHERE IT CANNOT BE READ (any other target, or a query that
    ///   fails) the ceiling stays at `from_limit`'s figure, 256 MiB, which
    ///   is what every build did before the window followed the machine.
    ///
    /// The default's limit is NOT named (`limit_named` false): a default
    /// is an allowance, not a ceiling anybody chose.
    ///
    /// Only the default moves. A policy a caller builds with `from_limit`
    /// or by setting `max_window` is a STATED budget and stays hard:
    /// a member needing more is refused as `LimitExceeded {
    /// resource: Window }` before any allocation.
    fn default() -> Self {
        let mut policy = MemoryPolicy::from_limit(MemoryPolicy::DEFAULT_LIMIT);
        policy.max_window = default_window(window_floor(policy.max_window));
        policy.limit_named = false;
        policy
    }
}

/// What a DEFAULT process budget leaves unused of a cgroup memory limit:
/// a quarter of it, or 96 MiB where that is more, so the budget is the
/// larger of three quarters of the limit and the limit less 96 MiB.
///
/// The kernel charges a cgroup for more than this process's own pages:
/// the page cache an extract fills as it writes, and kernel memory (page
/// tables, socket and file structures). Clean cache is reclaimed before
/// the OOM killer runs and dirty cache is written back under pressure;
/// what is left over is what keeps that reclaim from ever being the
/// difference between a completed extract and a kill. That need does not
/// grow with the limit, so above 384 MiB a fixed 96 MiB is left rather
/// than a quarter, which at 512 MiB narrowed eight 64 MiB members that
/// fit (1.22x slower). Counted on 30 Sep 2026 (a Zen 4 rental, x86-64,
/// cgroup v2): at
/// 256 MiB the default then peaked at 162 MiB resident, 94 MiB under.
const CAP_SHARE_CGROUP: (u64, u64) = (3, 4);
const CAP_SLACK_CGROUP: u64 = 96 * MIB;

/// The share of a finite `RLIMIT_AS` a DEFAULT process budget takes: a
/// quarter.
///
/// Address space is not resident memory. Every thread reserves its stack,
/// and under glibc a malloc arena of 64 MiB, before it touches a page, so
/// a default-width read on sixteen threads maps about 3 GiB to hold 65 to
/// 350 MiB resident (counted 30 Sep 2026, a Zen 4 rental, VmPeak against
/// the maximum resident set). The windows and rings the working limit
/// bounds are mapped too, and a quarter leaves the rest for the threads,
/// whose number the command line narrows under the same limit.
const CAP_SHARE_ADDRESS_SPACE: (u64, u64) = (1, 4);

/// [`MemoryPolicy::process_default`] under an environment's process
/// budget, `None` where nothing caps the process. Split out so the
/// arithmetic is testable on a box with no cap.
fn process_default_under(
    caller_resident: u64,
    environment: Option<u64>,
    physical: Option<u64>,
) -> MemoryPolicy {
    let mut policy = MemoryPolicy::for_process(MemoryPolicy::DEFAULT_LIMIT, caller_resident);
    // The default budget scales with the machine, then a cap
    // of the environment binds wherever it is below THAT figure, then the
    // process arithmetic. `working_limit` follows it, and `repair_limit`
    // with it.
    let scaled = scaled_default_budget(physical);
    let budget = environment.map_or(scaled, |cap| cap.min(scaled));
    policy.working_limit = MemoryPolicy::for_process(budget, caller_resident).working_limit;
    // A repair's limit is its half of the working limit, as `from_limit`
    // derives it, so it follows the machine and the cap too: held at the
    // floor's 240 MiB on a large machine, a repair that charges what it
    // holds would refuse work the machine has room for.
    policy.repair_limit = clamp(policy.working_limit / 2, MIB, WINDOW_CEILING);
    policy.max_window = default_window(window_floor(policy.max_window));
    policy.limit_named = false;
    policy
}

/// The share of physical memory a DEFAULT process budget may take where
/// that is more than [`MemoryPolicy::DEFAULT_LIMIT`]: a quarter.
const DEFAULT_SHARE_PHYSICAL: u64 = 4;

/// The default PROCESS budget of a machine with `physical` bytes of
/// memory (1 Oct 2026): the larger of
/// [`MemoryPolicy::DEFAULT_LIMIT`] and a quarter of it;
/// `DEFAULT_LIMIT` where it cannot be read.
///
/// 512 MiB is the floor rarkit must be able to run in, not a target:
/// nothing is held to 512 MiB where more memory is available. The engine
/// uses available memory for the best wall time, unless the user has
/// restricted its memory use or the machine does not have enough. Held to
/// 512 MiB of process on a 192 core machine, a create's
/// worker team ran four crews where it had run ten, 5.5 percent of wall
/// at 32 threads and 8.7 at 48 (a Zen 4 rental, timed with the box
/// to itself, 30 Sep 2026). A machine under 2 GiB
/// gets the floor; `physical` is [`physical_memory`]'s reading, already
/// lowered to a cgroup limit.
const fn scaled_default_budget(physical: Option<u64>) -> u64 {
    match physical {
        Some(bytes) if bytes / DEFAULT_SHARE_PHYSICAL > MemoryPolicy::DEFAULT_LIMIT => {
            bytes / DEFAULT_SHARE_PHYSICAL
        }
        _ => MemoryPolicy::DEFAULT_LIMIT,
    }
}

/// The process budget the environment's caps leave, and the cap that
/// leaves it, read once.
fn environment_budget() -> (Option<u64>, Option<u64>) {
    static BUDGET: std::sync::OnceLock<(Option<u64>, Option<u64>)> = std::sync::OnceLock::new();
    *BUDGET.get_or_init(|| {
        let (cgroup, address_space) = (cgroup_limit_once(), address_space_limit());
        (
            budget_under_caps(cgroup, address_space),
            cap_under_caps(cgroup, address_space),
        )
    })
}

/// [`MemoryPolicy::environment_cap`] for a default policy: `cap` where
/// the budget it leaves, `budget`, is under the machine's scaled default
/// (so that it is what lowered `working_limit`), else zero.
const fn bound_cap(budget: Option<u64>, cap: Option<u64>, physical: Option<u64>) -> u64 {
    match (budget, cap) {
        (Some(budget), Some(cap)) if budget < scaled_default_budget(physical) => cap,
        _ => 0,
    }
}

/// The cap whose budget is the one [`budget_under_caps`] answers: the
/// cgroup limit or the address space, whichever leaves the smaller budget;
/// `None` where neither is set.
const fn cap_under_caps(cgroup: Option<u64>, address_space: Option<u64>) -> Option<u64> {
    match (cgroup, address_space) {
        (Some(group), Some(space)) => {
            let of_group = match budget_under_caps(Some(group), None) {
                Some(budget) => budget,
                None => u64::MAX,
            };
            let of_space = match budget_under_caps(None, Some(space)) {
                Some(budget) => budget,
                None => u64::MAX,
            };
            Some(if of_group < of_space { group } else { space })
        }
        (Some(cap), None) | (None, Some(cap)) => Some(cap),
        (None, None) => None,
    }
}

/// The smaller of what each cap leaves, `None` where neither is set.
const fn budget_under_caps(cgroup: Option<u64>, address_space: Option<u64>) -> Option<u64> {
    let cgroup = match cgroup {
        Some(bytes) => {
            let share = bytes / CAP_SHARE_CGROUP.1 * CAP_SHARE_CGROUP.0;
            let less_slack = bytes.saturating_sub(CAP_SLACK_CGROUP);
            Some(if share > less_slack {
                share
            } else {
                less_slack
            })
        }
        None => None,
    };
    let address_space = match address_space {
        Some(bytes) => Some(bytes / CAP_SHARE_ADDRESS_SPACE.1 * CAP_SHARE_ADDRESS_SPACE.0),
        None => None,
    };
    match (cgroup, address_space) {
        (Some(a), Some(b)) => Some(if a < b { a } else { b }),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}

/// An allocation of `needed` bytes that the policy admitted and the HOST
/// refused (SPEC-API 8.1 term 4): `LimitExceeded { AddressSpace }`, its
/// limit the finite `RLIMIT_AS` where one is set, else `policy`, the
/// policy's own figure for the allocation. Where the caller set no figure
/// at all (`u64::MAX`) the one true figure is the request itself, so no
/// message quotes `u64::MAX` as a limit.
pub(crate) fn host_refused(needed: u64, policy: u64) -> crate::Error {
    let limit = address_space_limit().unwrap_or(if policy == u64::MAX { needed } else { policy });
    crate::Error::new(crate::ErrorKind::LimitExceeded {
        resource: crate::Resource::AddressSpace,
        needed,
        limit,
    })
}

/// A finite `RLIMIT_AS` (`ulimit -v`), or `None`.
///
/// Read on Linux and Android, where the kernel enforces it on every map.
/// Not on macOS, where it cannot be lowered to a figure that binds:
/// macOS 27 refuses `setrlimit(RLIMIT_AS)` below what the process has
/// already mapped ("Invalid argument" from every shell's `ulimit -v`,
/// counted 30 Sep 2026), so reading it there could only narrow a read
/// that nothing threatens.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn address_space_limit() -> Option<u64> {
    static LIMIT: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *LIMIT.get_or_init(read_address_space_limit)
}

/// `getrlimit(RLIMIT_AS)`, finite, or `None`.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(unsafe_code, clippy::useless_conversion)]
fn read_address_space_limit() -> Option<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a live, writable `rlimit`, which is all
    // `getrlimit` writes; it reads nothing of ours.
    let ok = unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut limit) } == 0;
    (ok && limit.rlim_cur != libc::RLIM_INFINITY)
        .then(|| u64::try_from(limit.rlim_cur).ok())
        .flatten()
        .filter(|&bytes| bytes > 0)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn address_space_limit() -> Option<u64> {
    None
}

/// The floor under a DEFAULT policy's `max_window`: half of the window
/// `from_limit` derives for the default budget, which is the figure the
/// floor has always been (256 MiB at the default limit). `from_limit`
/// itself derives the whole limit since 12 Oct 2026, and the defaults are
/// not moved by that (SPEC-API 8.4.1, the account's item 4).
const fn window_floor(derived: u64) -> u64 {
    clamp(derived / 2, MIB, WINDOW_CEILING)
}

/// The default `max_window`: half of [`physical_memory`], inside
/// `[floor, WINDOW_CEILING]`, or `floor` where physical memory cannot be
/// read.
fn default_window(floor: u64) -> u64 {
    window_under(
        floor,
        physical_memory(),
        cgroup_limit_once(),
        address_space_limit(),
    )
}

/// [`default_window`] from its three readings, testable on any box: half
/// of `physical` inside `[floor, WINDOW_CEILING]`, then at most half of a
/// cgroup limit and half of a finite address space, both of which beat
/// the floor. Half of the cgroup limit beating the 256 MiB floor dates
/// from 30 Sep 2026:
/// without it an 80 MiB window was admitted alone into a 96 MiB
/// cgroup and the kernel killed the extract, leaving a partial file.
fn window_under(
    floor: u64,
    physical: Option<u64>,
    cgroup: Option<u64>,
    address_space: Option<u64>,
) -> u64 {
    let window = physical.map_or(floor, |bytes| clamp(bytes / 2, floor, WINDOW_CEILING));
    let window = cgroup.map_or(window, |bytes| window.min(bytes / 2));
    address_space.map_or(window, |bytes| window.min(bytes / 2))
}

/// The cgroup memory limit this process runs under, in bytes: the smallest
/// on the process's own cgroup path and its ancestors, as
/// [`MemoryPolicy::process_default`] and [`MemoryPolicy::default`] read it,
/// read once a process and kept. `None` where there is none, and on a
/// target with no cgroups.
///
/// The policy states the cap only where it lowered the default budget
/// ([`MemoryPolicy::environment_cap`]); this is the cap itself, for a
/// caller that sizes something the policy does not count: a cgroup's
/// limit also counts the page cache its processes dirty, and a caller
/// writing its output through the cache paces those writes under it.
///
/// NOT YET PART OF THE STATED API (hidden from the documentation): added
/// for rarfast 0.9.0's extract under a cap; its
/// SPEC-API entry is not written yet.
#[doc(hidden)]
pub fn container_cap() -> Option<u64> {
    cgroup_limit_once()
}

/// [`container_limit`], read once and kept.
fn cgroup_limit_once() -> Option<u64> {
    static CGROUP: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *CGROUP.get_or_init(container_limit)
}

/// The memory this process could hold, read once and kept.
fn physical_memory() -> Option<u64> {
    static PHYSICAL: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *PHYSICAL.get_or_init(|| {
        let installed = installed_memory()?;
        Some(match container_limit() {
            Some(limit) => installed.min(limit),
            None => installed,
        })
    })
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
#[allow(unsafe_code)]
fn installed_memory() -> Option<u64> {
    // SAFETY: `sysconf` takes an integer name, touches no memory of ours
    // and answers -1 for a name the platform does not know.
    let (pages, page) = unsafe {
        (
            libc::sysconf(libc::_SC_PHYS_PAGES),
            libc::sysconf(libc::_SC_PAGESIZE),
        )
    };
    let pages = u64::try_from(pages).ok().filter(|&n| n > 0)?;
    let page = u64::try_from(page).ok().filter(|&n| n > 0)?;
    pages.checked_mul(page)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn installed_memory() -> Option<u64> {
    /// `MEMORYSTATUSEX`, field for field.
    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_phys: u64,
        avail_phys: u64,
        total_page_file: u64,
        avail_page_file: u64,
        total_virtual: u64,
        avail_virtual: u64,
        avail_extended_virtual: u64,
    }
    #[link(name = "kernel32")]
    extern "system" {
        #[allow(non_snake_case)]
        fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32;
    }
    let mut status = MemoryStatusEx {
        length: std::mem::size_of::<MemoryStatusEx>() as u32,
        memory_load: 0,
        total_phys: 0,
        avail_phys: 0,
        total_page_file: 0,
        avail_page_file: 0,
        total_virtual: 0,
        avail_virtual: 0,
        avail_extended_virtual: 0,
    };
    // SAFETY: `status` is a live, writable `MEMORYSTATUSEX` whose length
    // field names its own size, which is all the call requires; it writes
    // only inside that struct.
    let ok = unsafe { GlobalMemoryStatusEx(&mut status) };
    (ok != 0 && status.total_phys > 0).then_some(status.total_phys)
}

/// Every other target: not read, so the default keeps its old figure.
#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
)))]
fn installed_memory() -> Option<u64> {
    None
}

/// The cgroup memory limit this process runs under, or `None` where there
/// is none.
///
/// The cap that binds a process may sit on its OWN cgroup, which is
/// rarely the root of the hierarchy: a systemd unit or slice
/// (`systemd-run -p MemoryMax=`), a container that shares the host's
/// cgroup namespace, a pod. So the process's cgroup is read from
/// `/proc/self/cgroup` and every cgroup from it up to the root is
/// consulted, and the SMALLEST limit found binds, since the kernel
/// enforces each ancestor's limit on everything beneath it. v2's
/// `memory.max` and v1's `memory.limit_in_bytes` are both read. A limit
/// of "max", or v1's near-`i64::MAX` spelling of no limit, is larger than
/// any machine and loses the `min` it is taken into.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn container_limit() -> Option<u64> {
    let own = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    cgroup_limit(&own, |path| std::fs::read_to_string(path).ok())
}

/// The smallest memory limit on the cgroup paths `own` (the text of
/// `/proc/self/cgroup`) names, each file read through `read`. The roots of
/// both hierarchies are always consulted, so a container whose namespace
/// makes its own cgroup the root is read as before.
#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn cgroup_limit(own: &str, read: impl Fn(&str) -> Option<String>) -> Option<u64> {
    let mut files = Vec::new();
    for line in own.lines() {
        let mut fields = line.splitn(3, ':');
        let (Some(_), Some(controllers), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let (mount, name) = if controllers.is_empty() {
            ("/sys/fs/cgroup", "memory.max")
        } else if controllers.split(',').any(|c| c == "memory") {
            ("/sys/fs/cgroup/memory", "memory.limit_in_bytes")
        } else {
            continue;
        };
        // A path outside this process's cgroup namespace reads as "/.."
        // and names nothing under the mount; only the root is read.
        let mut at = if path.split('/').any(|part| part == "..") {
            ""
        } else {
            path.trim_end_matches('/')
        };
        loop {
            files.push(format!("{mount}{at}/{name}"));
            match at.rfind('/') {
                Some(cut) => at = &at[..cut],
                None => break,
            }
        }
    }
    files.push("/sys/fs/cgroup/memory.max".to_string());
    files.push("/sys/fs/cgroup/memory/memory.limit_in_bytes".to_string());
    files
        .iter()
        .filter_map(|file| read(file)?.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .min()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn container_limit() -> Option<u64> {
    None
}

static CURRENT: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);

/// Add `bytes` to the process-wide working-memory counter, raising the peak,
/// and to the [`Meter`] of the operation whose thread this is, if any.
pub(crate) fn charge(bytes: u64) {
    if bytes == 0 {
        return;
    }
    let now = CURRENT.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(now, Ordering::Relaxed);
    if let Some(index) = op_slot() {
        let slot = &SLOTS[index];
        let now = slot.current.fetch_add(bytes, Ordering::Relaxed) + bytes;
        slot.peak.fetch_max(now, Ordering::Relaxed);
    }
}

/// Take `bytes` off the process-wide working-memory counter and off the
/// calling thread's operation's [`Meter`], if any.
pub(crate) fn release(bytes: u64) {
    if bytes == 0 {
        return;
    }
    // Saturating: a release can never drive the counter below zero, whatever
    // order concurrent operations finish in.
    let _ = CURRENT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_sub(bytes))
    });
    if let Some(index) = op_slot() {
        let _ = SLOTS[index]
            .current
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(bytes))
            });
    }
}

/// One operation's own view of the counters: what it has charged since it
/// opened, and the SIMULTANEOUS peak of that (API section 5.2: each report
/// carries the operation's own peak). A report built from each buffer's own
/// high-water mark sums maxima that never coexisted; this is the figure the
/// counters actually reached.
///
/// A charge is the operation's when it is made on one of the operation's
/// threads: the thread that opened the meter, and every thread the
/// operation spawns, which enters the slot ([`enter`]) before it charges
/// anything. Several operations running at once each see only their own.
/// When every slot is taken a meter opens unslotted and reads the process's
/// own peak, which is never under the operation's.
pub(crate) struct Meter {
    slot: Option<usize>,
    /// The opening thread's slot before this meter, put back on drop (a
    /// meter opened inside another operation's thread nests).
    outer: Option<usize>,
}

struct Slot {
    open: AtomicBool,
    current: AtomicU64,
    peak: AtomicU64,
}

/// Enough for every operation a process runs at once in practice, a test
/// harness running one extraction per core included; beyond it a meter
/// reads the process peak, which errs high.
const SLOT_COUNT: usize = 256;

#[allow(clippy::declare_interior_mutable_const)]
const EMPTY_SLOT: Slot = Slot {
    open: AtomicBool::new(false),
    current: AtomicU64::new(0),
    peak: AtomicU64::new(0),
};

static SLOTS: [Slot; SLOT_COUNT] = [EMPTY_SLOT; SLOT_COUNT];

impl Meter {
    /// Open a meter for an operation starting now.
    pub(crate) fn open() -> Meter {
        for (index, slot) in SLOTS.iter().enumerate() {
            if slot
                .open
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                slot.current.store(0, Ordering::Relaxed);
                slot.peak.store(0, Ordering::Relaxed);
                let outer = OP.with(|op| op.replace(Some(index)));
                return Meter {
                    slot: Some(index),
                    outer,
                };
            }
        }
        Meter {
            slot: None,
            outer: op_slot(),
        }
    }

    /// The most this operation's charges reached at once since it opened.
    pub(crate) fn peak(&self) -> u64 {
        match self.slot {
            Some(index) => SLOTS[index].peak.load(Ordering::Relaxed),
            None => PEAK.load(Ordering::Relaxed),
        }
    }
}

impl Drop for Meter {
    fn drop(&mut self) {
        if let Some(index) = self.slot {
            OP.with(|op| op.set(self.outer));
            SLOTS[index].open.store(false, Ordering::Release);
        }
    }
}

thread_local! {
    /// The meter slot of the operation this thread is working for.
    static OP: Cell<Option<usize>> = const { Cell::new(None) };
}

/// The calling thread's operation slot, for a thread about to be spawned to
/// carry into [`enter`].
pub(crate) fn op_slot() -> Option<usize> {
    OP.with(Cell::get)
}

/// What the operation this thread is working for holds this instant: its
/// own slot's current figure, or the process's where the meter opened
/// unslotted (which is never under the operation's). The pools admit a
/// member against this under a NAMED budget (API 8.4.1): a worker holds
/// more than the window admission declared for it (its scratch, its read
/// window, a ring rebuilt for a larger member), the walk holds its own
/// ring and the seam's, and every one of those is charged here, so this
/// is the figure the ceiling is measured against.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
pub(crate) fn op_current() -> u64 {
    match op_slot() {
        Some(index) => SLOTS[index].current.load(Ordering::Relaxed),
        None => current(),
    }
}

/// Charge to `slot`'s operation from this thread on, until the value drops.
/// Every thread an operation spawns calls it first thing.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
pub(crate) fn enter(slot: Option<usize>) -> Entered {
    Entered(OP.with(|op| op.replace(slot)))
}

/// What [`enter`] replaced, put back when this drops.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
pub(crate) struct Entered(Option<usize>);

/// A way to give charges back to the operation that do not need this
/// thread to come back: it waits until they have, and says whether it
/// asked anything of anyone.
pub(crate) type Giver = Box<dyn Fn() -> bool>;

thread_local! {
    /// What this thread's operation can give back when a charge this
    /// thread is about to make would pass a NAMED limit: the solid path's
    /// queue, lent to its walk's thread (`read::sequential::solid`).
    static GIVER: std::cell::RefCell<Option<Giver>> = const { std::cell::RefCell::new(None) };
}

/// Ask what this thread was lent ([`lend_giver`]) to give its charges
/// back, and wait until it has. `false` when nothing was lent, or nothing
/// will come back, so a charge that does not fit is refused as before.
pub(crate) fn make_room() -> bool {
    GIVER
        .try_with(|giver| giver.borrow().as_ref().is_some_and(|give| give()))
        .unwrap_or(false)
}

/// Lend this thread `giver` until the value returned drops.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
pub(crate) fn lend_giver(giver: Giver) -> Lent {
    Lent(GIVER.with(|slot| slot.replace(Some(giver))))
}

/// What [`lend_giver`] replaced, put back when this drops.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
pub(crate) struct Lent(Option<Giver>);

impl Drop for Lent {
    fn drop(&mut self) {
        let outer = self.0.take();
        let _ = GIVER.try_with(|slot| slot.replace(outer));
    }
}

impl Drop for Entered {
    fn drop(&mut self) {
        OP.with(|op| op.set(self.0));
    }
}

/// Bytes charged to the process counters for exactly as long as this value
/// lives: [`charge`]d as [`Held::set`] raises it and [`release`]d as it
/// falls or the value drops.
///
/// An operation's decoders hold one for every window they commit (API
/// section 8: the counters MUST include every decode window). Owning the
/// charge, rather than calling the two functions by hand, is what makes a
/// window counted once however it ends: dropped with its decoders,
/// replaced when a dictionary changes, or kept idle for the next member.
#[derive(Debug, Default)]
pub(crate) struct Held(u64);

impl Held {
    /// Hold `bytes` from now on, charging or releasing only the
    /// difference, so a figure that moves is never counted twice.
    pub(crate) fn set(&mut self, bytes: u64) {
        if bytes > self.0 {
            charge(bytes - self.0);
        } else {
            release(self.0 - bytes);
        }
        self.0 = bytes;
    }

    /// The bytes this value holds charged.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> u64 {
        self.0
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        release(self.0);
    }
}

/// What the engine is holding this instant, summed over every operation in
/// the process.
pub fn current() -> u64 {
    CURRENT.load(Ordering::Relaxed)
}

/// The largest [`current`] has ever returned, measured from the start of
/// the process or from the last [`reset_peak`], whichever is later.
pub fn peak() -> u64 {
    PEAK.load(Ordering::Relaxed)
}

/// Forget the high-water mark, starting [`peak`] again from whatever is
/// held now.
pub fn reset_peak() {
    PEAK.store(CURRENT.load(Ordering::Relaxed), Ordering::Relaxed);
}

/// A policy for an operation that only repairs, with `repair_limit` set
/// and every other field at a value that does not constrain it.
///
/// Spec F owns [`MemoryPolicy::from_limit`] and the default budget; this
/// is what the recovery entry points that take no policy of their own use,
/// with the header, member-table and comment limits left at the derived
/// defaults since a repair reads no member table.
pub(crate) fn repair_only(repair_limit: u64) -> MemoryPolicy {
    MemoryPolicy {
        working_limit: repair_limit,
        max_window: repair_limit,
        max_dictionary: MemoryPolicy::MIN_DICTIONARY,
        repair_limit,
        read_ahead: 1 << 20,
        max_workers: 1,
        ..MemoryPolicy::from_limit(repair_limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_the_figures_spec_f_section_4_names() {
        let p = MemoryPolicy::default();
        assert_eq!(p.max_header, MIB);
        assert_eq!(p.max_member_table, 64 * MIB);
        assert_eq!(p.max_comment, MIB);
        assert_eq!(p.read_ahead, 4 * MIB);
    }

    #[test]
    fn from_limit_is_monotone() {
        let mut last = MemoryPolicy::from_limit(0);
        for shift in 0..48 {
            let next = MemoryPolicy::from_limit(1u64 << shift);
            assert!(next.max_window >= last.max_window);
            assert!(next.max_dictionary >= last.max_dictionary);
            assert!(next.repair_limit >= last.repair_limit);
            assert!(next.read_ahead >= last.read_ahead);
            assert!(next.max_workers >= last.max_workers);
            assert!(next.max_header >= last.max_header);
            assert!(next.max_member_table >= last.max_member_table);
            assert!(next.max_comment >= last.max_comment);
            last = next;
        }
    }

    /// The 32-bit arm is a CEILING and nothing else: every field of the
    /// default policy is far below both ceilings, so the two widths agree
    /// on the figures spec F section 4 names, and they part only for a
    /// caller asking for a budget a 32-bit process could not map.
    #[test]
    fn the_pointer_width_ceilings_bind_only_a_large_budget() {
        // The derived default; `MemoryPolicy::default`'s window is the
        // machine's and is held by its own test below.
        let default = MemoryPolicy::from_limit(MemoryPolicy::DEFAULT_LIMIT);
        assert_eq!(default.max_window, 512 * MIB);
        assert_eq!(default.max_dictionary, 128 * MIB);
        assert_eq!(default.repair_limit, 256 * MIB);

        // A budget far past any 32-bit address space.
        let huge = MemoryPolicy::from_limit(64 * GIB);
        assert_eq!(huge.max_window, WINDOW_CEILING);
        assert_eq!(huge.repair_limit, WINDOW_CEILING);
        assert_eq!(huge.max_dictionary, DICTIONARY_CEILING);
        assert!(huge.max_window <= usize::MAX as u64);
        assert!(huge.max_dictionary <= usize::MAX as u64);

        // Stated per width so the arm this box does not build is written
        // down as well as the one it does.
        if cfg!(target_pointer_width = "64") {
            assert_eq!(WINDOW_CEILING, 4 * GIB);
            assert_eq!(DICTIONARY_CEILING, GIB);
        } else {
            assert_eq!(WINDOW_CEILING, 512 * MIB);
            assert_eq!(DICTIONARY_CEILING, 256 * MIB);
        }
    }

    /// A figure the tests below state for a 64-bit target, as a 32-bit
    /// target answers it: no window and no repair limit passes the
    /// pointer width's ceiling, which is 512 MiB there by this module's
    /// own choice (`WINDOW_CEILING`, pinned per width by
    /// `the_pointer_width_ceilings_bind_only_a_large_budget`). Run on
    /// armv7 under qemu-arm on 4 Oct 2026, three tests that wrote a
    /// figure over 512 MiB failed on exactly that ceiling.
    fn under_the_width_ceiling(on_64_bit: u64) -> u64 {
        if cfg!(target_pointer_width = "64") {
            on_64_bit
        } else {
            on_64_bit.min(512 * MIB)
        }
    }

    /// A fake cgroup tree for [`cgroup_limit`]: each file's text by path.
    fn tree<'a>(files: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |path| {
            files
                .iter()
                .find(|(at, _)| *at == path)
                .map(|(_, text)| text.to_string())
        }
    }

    /// The cgroup rule: a cap on the process's OWN cgroup binds,
    /// not only one at the root. `systemd-run -p MemoryMax=4G` puts the
    /// process in a nested unit whose `memory.max` the root never shows.
    #[test]
    fn a_nested_cgroup_v2_cap_binds() {
        let own = "0::/system.slice/run-u7.scope\n";
        let files = [
            (
                "/sys/fs/cgroup/system.slice/run-u7.scope/memory.max",
                "4294967296\n",
            ),
            ("/sys/fs/cgroup/system.slice/memory.max", "max\n"),
        ];
        assert_eq!(cgroup_limit(own, tree(&files)), Some(4 * GIB));
    }

    /// The kernel enforces every ancestor's limit, so the SMALLEST on the
    /// path binds, wherever on it it sits.
    #[test]
    fn the_smallest_cap_on_the_path_binds() {
        let own = "0::/a/b/c\n";
        let files = [
            ("/sys/fs/cgroup/a/b/c/memory.max", "17179869184"),
            ("/sys/fs/cgroup/a/b/memory.max", "max"),
            ("/sys/fs/cgroup/a/memory.max", "8589934592"),
        ];
        assert_eq!(cgroup_limit(own, tree(&files)), Some(8 * GIB));
    }

    /// A container with its own cgroup namespace sees itself as "/" and
    /// its cap at the root, which is what the reader did before.
    #[test]
    fn a_namespaced_container_reads_its_root() {
        let files = [("/sys/fs/cgroup/memory.max", "2147483648\n")];
        assert_eq!(cgroup_limit("0::/\n", tree(&files)), Some(2 * GIB));
        // With no /proc/self/cgroup at all, the root is still read.
        assert_eq!(cgroup_limit("", tree(&files)), Some(2 * GIB));
    }

    /// cgroup v1: the memory controller's line, possibly shared with
    /// others, names the path under the memory mount; v1's no-limit
    /// figure is larger than any machine and a v2-style "max" is none.
    #[test]
    fn a_cgroup_v1_cap_binds_and_no_limit_is_none() {
        let own = "12:cpu,cpuacct:/docker/abc\n9:memory:/docker/abc\n0::/\n";
        let files = [
            (
                "/sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes",
                "1073741824",
            ),
            (
                "/sys/fs/cgroup/memory/memory.limit_in_bytes",
                "9223372036854771712",
            ),
            ("/sys/fs/cgroup/memory.max", "max"),
        ];
        assert_eq!(cgroup_limit(own, tree(&files)), Some(GIB));
        let unlimited = [
            ("/sys/fs/cgroup/memory.max", "max"),
            ("/sys/fs/cgroup/a/memory.max", "max"),
        ];
        assert_eq!(cgroup_limit("0::/a\n", tree(&unlimited)), None);
    }

    /// A path outside the process's namespace ("/../x") names nothing
    /// under the mount and is never joined to it; only the root is read.
    #[test]
    fn a_path_outside_the_namespace_reads_only_the_root() {
        let seen = std::cell::RefCell::new(Vec::new());
        let read = |path: &str| {
            seen.borrow_mut().push(path.to_string());
            None
        };
        assert_eq!(cgroup_limit("0::/../../x\n", read), None);
        assert!(
            seen.borrow().iter().all(|path| !path.contains("..")),
            "{:?}",
            seen.borrow()
        );
    }

    /// The DEFAULT window is half of physical memory, inside
    /// the old figure and the pointer-width ceiling, and it is the only
    /// field the default moves; `from_limit` itself is untouched, so a
    /// stated budget means what it meant.
    #[test]
    fn the_default_window_is_half_of_physical_memory() {
        let derived = MemoryPolicy::from_limit(MemoryPolicy::DEFAULT_LIMIT);
        let default = MemoryPolicy::default();
        let expected = match physical_memory() {
            Some(bytes) => clamp(bytes / 2, 256 * MIB, WINDOW_CEILING),
            None => 256 * MIB,
        };
        assert_eq!(default.max_window, expected);
        assert!(default.max_window >= window_floor(derived.max_window));
        assert!(default.max_window <= WINDOW_CEILING);
        assert_eq!(
            MemoryPolicy {
                max_window: derived.max_window,
                limit_named: true,
                ..default
            },
            derived,
            "the default moved a field other than max_window and limit_named"
        );
        assert_eq!(derived.max_window, 512 * MIB);
        assert_eq!(window_floor(derived.max_window), 256 * MIB);
        // Every box this crate is built and tested on can read its own
        // memory: the fallback is for targets outside the three
        // named below.
        if cfg!(any(target_os = "linux", target_os = "macos", windows)) {
            let bytes = physical_memory().expect("physical memory read");
            assert!(bytes >= 64 * MIB, "{bytes} bytes of physical memory");
        }
    }

    /// One test, not two, and a charge far above anything else here: the
    /// counters are PROCESS-wide, and since every decode window is charged
    /// (API section 8) the other unit tests in this binary move them on
    /// other threads while this one runs, so an exact before and after
    /// would race. What no other test can reach is a figure this large.
    #[test]
    fn counters_track_charge_release_and_a_held_charge() {
        const HUGE: u64 = 1 << 50;
        charge(HUGE);
        assert!(current() >= HUGE);
        assert!(peak() >= HUGE);
        release(HUGE);
        assert!(current() < HUGE);

        let mut held = Held::default();
        held.set(HUGE);
        assert!(current() >= HUGE);
        held.set(2 * HUGE);
        assert!(current() >= 2 * HUGE);
        assert_eq!(held.bytes(), 2 * HUGE);
        held.set(HUGE);
        assert!(current() >= HUGE && current() < 2 * HUGE);
        drop(held);
        assert!(current() < HUGE, "a dropped Held left its bytes charged");
    }

    /// API section 5.2 and 8.4.1: an operation's report is the SIMULTANEOUS
    /// peak of its own charges. Two holdings that peak at different moments
    /// are not summed, and another operation's charges on another thread
    /// are not this one's.
    #[test]
    fn a_meter_reads_the_simultaneous_peak_of_its_own_charges() {
        let meter = Meter::open();
        let mut first = Held::default();
        first.set(10 << 20);
        drop(first);
        let mut second = Held::default();
        second.set(7 << 20);
        // A sum of the two holdings' own high-water marks would read 17 MiB.
        assert_eq!(meter.peak(), 10 << 20);
        drop(second);

        // Another operation on another thread, never entered into this one.
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let other = Meter::open();
                    let mut big = Held::default();
                    big.set(64 << 20);
                    assert_eq!(other.peak(), 64 << 20);
                })
                .join()
                .expect("the other operation");
        });
        assert_eq!(meter.peak(), 10 << 20, "another operation leaked in");

        // A thread this operation spawns and enters is this operation's.
        let slot = op_slot();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let _op = enter(slot);
                let mut mine = Held::default();
                mine.set(12 << 20);
            });
        });
        assert_eq!(meter.peak(), 12 << 20);
    }

    /// A whole-process budget leaves the headroom and the
    /// caller's holdings out of the engine's limit, is named when stated,
    /// and reports the subtraction; the default is the same arithmetic on
    /// DEFAULT_LIMIT, not named, with the machine's window.
    #[test]
    fn a_process_budget_leaves_the_headroom_and_the_callers_holdings_out() {
        let stated = MemoryPolicy::for_process(256 * MIB, 8 * MIB);
        assert_eq!(
            stated.working_limit,
            256 * MIB - MemoryPolicy::PROCESS_HEADROOM - 8 * MIB
        );
        assert_eq!(
            stated.process_overhead,
            MemoryPolicy::PROCESS_HEADROOM + 8 * MIB
        );
        assert!(stated.limit_named);
        let engine = MemoryPolicy::from_limit(stated.working_limit);
        assert_eq!(
            MemoryPolicy {
                process_overhead: 0,
                ..stated
            },
            engine,
            "every other field is from_limit's of the derived limit"
        );
        // A budget below the overheads alone derives nothing to read with,
        // which the read refuses up front.
        assert_eq!(
            MemoryPolicy::for_process(16 * MIB, 8 * MIB).working_limit,
            0
        );

        // The UNCAPPED arm, so a test box under a cgroup or `ulimit -v`
        // (a CI container) reads the same; the capped arms are below.
        let default = process_default_under(8 * MIB, None, None);
        assert!(!default.limit_named);
        assert_eq!(
            default.working_limit,
            MemoryPolicy::DEFAULT_LIMIT - MemoryPolicy::PROCESS_HEADROOM - 8 * MIB
        );
        // The machine's window over this policy's own floor, which is
        // the engine default's window wherever the machine's figure is
        // over both floors. Where it is not (memory that cannot be read,
        // or a small machine) each keeps its own floor, 236 MiB here and
        // 256 MiB there, and the two differ: run on armv7 under qemu-arm
        // on 4 Oct 2026 this test read exactly those two figures.
        let floor = window_floor(
            MemoryPolicy::for_process(MemoryPolicy::DEFAULT_LIMIT, 8 * MIB).max_window,
        );
        assert_eq!(default.max_window, default_window(floor));
        let machine = MemoryPolicy::default().max_window;
        if machine > 256 * MIB {
            assert_eq!(default.max_window, machine);
        }
        assert!(MemoryPolicy::from_limit(MemoryPolicy::DEFAULT_LIMIT).limit_named);
    }

    /// The default process budget is the larger of 512 MiB and
    /// a quarter of physical memory, a cap of the environment below that
    /// wins, a named budget overrides both ways, and only `working_limit`
    /// follows the scaled figure, with the repair limit that is its half.
    #[test]
    fn the_default_budget_scales_with_physical_memory() {
        let floor = MemoryPolicy::DEFAULT_LIMIT - MemoryPolicy::PROCESS_HEADROOM - 8 * MIB;
        // Unreadable, and every machine up to 2 GiB: the floor.
        for physical in [None, Some(GIB), Some(2 * GIB)] {
            assert_eq!(
                process_default_under(8 * MIB, None, physical).working_limit,
                floor,
                "{physical:?}"
            );
        }
        // Above it, a quarter, less the process terms.
        for gib in [4u64, 16, 64, 376] {
            let policy = process_default_under(8 * MIB, None, Some(gib * GIB));
            assert_eq!(
                policy.working_limit,
                gib * GIB / 4 - MemoryPolicy::PROCESS_HEADROOM - 8 * MIB,
                "{gib} GiB"
            );
            // Nothing else moves, and it is still nobody's named ceiling.
            let small = process_default_under(8 * MIB, None, None);
            assert_eq!(
                MemoryPolicy {
                    working_limit: small.working_limit,
                    repair_limit: small.repair_limit,
                    ..policy
                },
                small
            );
            assert!(!policy.limit_named);
            assert_eq!(
                policy.process_overhead,
                MemoryPolicy::PROCESS_HEADROOM + 8 * MIB
            );
        }
        // A cap of the environment below the scaled budget wins, above it
        // does not.
        let capped = process_default_under(0, Some(GIB), Some(64 * GIB));
        assert_eq!(capped.working_limit, GIB - MemoryPolicy::PROCESS_HEADROOM);
        let roomy = process_default_under(0, Some(32 * GIB), Some(64 * GIB));
        assert_eq!(
            roomy.working_limit,
            16 * GIB - MemoryPolicy::PROCESS_HEADROOM
        );
        let low =
            process_default_under(0, budget_under_caps(Some(256 * MIB), None), Some(64 * GIB));
        assert_eq!(
            low.working_limit,
            192 * MIB - MemoryPolicy::PROCESS_HEADROOM
        );
        // A NAMED budget is its own figure on any machine.
        assert_eq!(
            MemoryPolicy::for_process(256 * MIB, 0).working_limit,
            256 * MIB - MemoryPolicy::PROCESS_HEADROOM
        );
        assert_eq!(
            MemoryPolicy::for_process(8 * GIB, 0).working_limit,
            8 * GIB - MemoryPolicy::PROCESS_HEADROOM
        );
        assert_eq!(
            MemoryPolicy::default().working_limit,
            MemoryPolicy::DEFAULT_LIMIT
        );
    }

    /// The environment's caps, as a process budget: three quarters of a
    /// cgroup limit, a quarter of `RLIMIT_AS`, the smaller where both are
    /// set, nothing where neither is.
    /// `environment_cap` is the cap that lowered the budget, and zero
    /// where none did or the figure was named.
    #[test]
    fn the_environment_cap_is_the_cap_that_bound() {
        assert_eq!(cap_under_caps(None, None), None);
        assert_eq!(cap_under_caps(Some(256 * MIB), None), Some(256 * MIB));
        assert_eq!(cap_under_caps(None, Some(GIB)), Some(GIB));
        // 256 MiB of cgroup leaves 192, a quarter of 1 GiB leaves 256: the
        // cgroup binds; against 4 GiB of cgroup the address space does.
        assert_eq!(cap_under_caps(Some(256 * MIB), Some(GIB)), Some(256 * MIB));
        assert_eq!(cap_under_caps(Some(4 * GIB), Some(GIB)), Some(GIB));
        let bound = |cgroup, space, physical| {
            bound_cap(
                budget_under_caps(cgroup, space),
                cap_under_caps(cgroup, space),
                physical,
            )
        };
        // It binds where its budget is under the machine's default budget.
        assert_eq!(bound(Some(96 * MIB), None, Some(64 * GIB)), 96 * MIB);
        assert_eq!(bound(Some(8 * GIB), None, Some(64 * GIB)), 8 * GIB);
        assert_eq!(bound(Some(32 * GIB), None, Some(64 * GIB)), 0);
        assert_eq!(bound(Some(GIB), None, None), 0);
        assert_eq!(bound(None, None, Some(64 * GIB)), 0);
        // Named figures and the engine's default carry none.
        assert_eq!(MemoryPolicy::from_limit(64 * MIB).environment_cap, 0);
        assert_eq!(MemoryPolicy::for_process(96 * MIB, 0).environment_cap, 0);
        assert_eq!(MemoryPolicy::default().environment_cap, 0);
    }

    #[test]
    fn the_caps_leave_their_shares_and_the_smaller_binds() {
        assert_eq!(budget_under_caps(None, None), None);
        assert_eq!(budget_under_caps(Some(256 * MIB), None), Some(192 * MIB));
        assert_eq!(budget_under_caps(Some(96 * MIB), None), Some(72 * MIB));
        // Above 384 MiB the fixed 96 MiB of slack is the larger.
        assert_eq!(budget_under_caps(Some(384 * MIB), None), Some(288 * MIB));
        assert_eq!(budget_under_caps(Some(512 * MIB), None), Some(416 * MIB));
        assert_eq!(budget_under_caps(None, Some(GIB)), Some(256 * MIB));
        assert_eq!(
            budget_under_caps(Some(256 * MIB), Some(GIB)),
            Some(192 * MIB)
        );
        assert_eq!(budget_under_caps(Some(4 * GIB), Some(GIB)), Some(256 * MIB));
        assert_eq!(budget_under_caps(Some(GIB), None), Some(GIB - 96 * MIB));
        // An unlimited spelling never reaches here as a figure, and a huge
        // one cannot overflow: it is divided before it is multiplied.
        assert_eq!(
            budget_under_caps(Some(u64::MAX), None),
            Some(u64::MAX - CAP_SLACK_CGROUP)
        );
    }

    /// With no cap, or a cap whose share is at or above DEFAULT_LIMIT,
    /// `process_default` is EXACTLY what it was: the null this change owes.
    #[test]
    fn no_cap_and_a_high_cap_leave_the_default_as_it_was() {
        let before = {
            let mut p = MemoryPolicy::for_process(MemoryPolicy::DEFAULT_LIMIT, 8 * MIB);
            p.max_window = default_window(window_floor(p.max_window));
            p.limit_named = false;
            p
        };
        assert_eq!(process_default_under(8 * MIB, None, None), before);
        assert_eq!(
            process_default_under(8 * MIB, Some(MemoryPolicy::DEFAULT_LIMIT), None),
            before
        );
        let high = budget_under_caps(Some(64 * GIB), None);
        assert_eq!(process_default_under(8 * MIB, high, None), before);
        // The cgroup cap at which what it leaves reaches DEFAULT_LIMIT
        // (608 MiB, where the 96 MiB of slack is the larger), and a step
        // under it, which is the first to bind.
        let edge = MemoryPolicy::DEFAULT_LIMIT + CAP_SLACK_CGROUP;
        assert_eq!(
            process_default_under(8 * MIB, budget_under_caps(Some(edge), None), None),
            before
        );
        assert!(
            process_default_under(8 * MIB, budget_under_caps(Some(edge - 4), None), None)
                .working_limit
                < before.working_limit
        );
    }

    /// A cap below the default binds `working_limit` and NOTHING else: the
    /// header, member table, comment and read-ahead figures are the
    /// uncapped default's (so nothing the default accepts is refused), the
    /// window is the machine's, and the policy stays an unnamed allowance
    /// that keeps its residency (no pre-scan, no floor refusal).
    #[test]
    fn a_cap_binds_the_working_limit_and_nothing_else() {
        let uncapped = process_default_under(8 * MIB, None, None);
        let capped = process_default_under(8 * MIB, budget_under_caps(Some(256 * MIB), None), None);
        assert_eq!(
            capped.working_limit,
            192 * MIB - MemoryPolicy::PROCESS_HEADROOM - 8 * MIB
        );
        assert_eq!(
            MemoryPolicy {
                working_limit: uncapped.working_limit,
                repair_limit: uncapped.repair_limit,
                ..capped
            },
            uncapped
        );
        assert!(!capped.limit_named);
        assert!(capped.keeps_residency());

        // 96 MiB of cgroup: 72 MiB of process budget, 32 of headroom.
        let small = process_default_under(0, budget_under_caps(Some(96 * MIB), None), None);
        assert_eq!(small.working_limit, 40 * MIB);
        // 1 GiB of address space: a quarter of it.
        let spaced = process_default_under(0, budget_under_caps(None, Some(GIB)), None);
        assert_eq!(spaced.working_limit, 224 * MIB);
        // A cap below the headroom alone leaves nothing to price members
        // against, which the read's admission meets by taking one member
        // at a time; it is not a refusal, the policy being unnamed.
        let tiny = process_default_under(0, budget_under_caps(Some(32 * MIB), None), None);
        assert_eq!(tiny.working_limit, 0);
        assert!(!tiny.limit_named);
    }

    /// A repair's limit under the process default is half the working
    /// limit, so it follows the machine and a cap of the environment as
    /// the working limit does, inside the pointer width's ceiling. The
    /// physical figure and the cap are stated here, never read from the
    /// box the test runs on.
    #[test]
    fn the_default_repair_limit_follows_the_working_limit() {
        let headroom = MemoryPolicy::PROCESS_HEADROOM;
        let half = |working: u64| clamp(working / 2, MIB, WINDOW_CEILING);
        // The floor, where memory cannot be read or is 2 GiB or less: 240
        // MiB of the 480 the process default leaves the engine.
        for physical in [None, Some(GIB), Some(2 * GIB)] {
            let policy = process_default_under(0, None, physical);
            assert_eq!(policy.repair_limit, 240 * MIB, "{physical:?}");
        }
        // 8 GiB: a quarter is 2 GiB, the repair's half of that less the
        // headroom is 1,008 MiB.
        let policy = process_default_under(0, None, Some(8 * GIB));
        assert_eq!(policy.repair_limit, half(2 * GIB - headroom));
        assert_eq!(policy.repair_limit, under_the_width_ceiling(1_008 * MIB));
        // 64 GiB: half of 16 GiB is past the ceiling, which holds.
        let policy = process_default_under(0, None, Some(64 * GIB));
        assert_eq!(policy.repair_limit, WINDOW_CEILING);
        // A cap of the environment below the machine's figure binds the
        // repair as it binds the working limit: 1 GiB of budget on a 64
        // GiB machine, and a 256 MiB cgroup.
        let capped = process_default_under(0, Some(GIB), Some(64 * GIB));
        assert_eq!(capped.repair_limit, half(GIB - headroom));
        assert_eq!(capped.repair_limit, 496 * MIB);
        let low =
            process_default_under(0, budget_under_caps(Some(256 * MIB), None), Some(64 * GIB));
        assert_eq!(low.repair_limit, 80 * MIB);
        // A cap below the headroom leaves the repair its 1 MiB floor.
        let tiny = process_default_under(0, budget_under_caps(Some(32 * MIB), None), None);
        assert_eq!(tiny.repair_limit, MIB);
        // Never more than the working limit's half anywhere in between.
        for gib in [1u64, 3, 4, 12, 16, 128, 376] {
            let policy = process_default_under(8 * MIB, None, Some(gib * GIB));
            assert_eq!(policy.repair_limit, half(policy.working_limit), "{gib}");
        }
        // The engine's own default states no process and is as it was.
        assert_eq!(MemoryPolicy::default().repair_limit, 256 * MIB);
    }

    /// SPEC-API 8.1 term 2: a cap lowers `working_limit`
    /// and leaves `max_window` alone, so a member alone is still admitted
    /// up to its window whatever the lowered limit; `default()`'s
    /// `working_limit` is never lowered.
    #[test]
    fn a_cap_lowers_the_limit_and_leaves_the_window() {
        let uncapped = process_default_under(0, None, None);
        let capped = process_default_under(0, budget_under_caps(Some(96 * MIB), None), None);
        assert_eq!(capped.working_limit, 40 * MIB);
        assert_eq!(capped.max_window, uncapped.max_window);
        assert_eq!(
            MemoryPolicy::default().working_limit,
            MemoryPolicy::DEFAULT_LIMIT
        );
    }

    /// SPEC-API 8.1 term 2: under a finite `RLIMIT_AS` the
    /// default window, `default()`'s and `process_default`'s alike, is at most
    /// half of it, below the 256 MiB floor if need be, so a window the
    /// address space cannot map is refused as `Window` rather than a
    /// failed map; with no limit it is the machine's figure unchanged.
    #[test]
    fn the_address_space_caps_the_default_window() {
        let floor = 256 * MIB;
        assert_eq!(
            window_under(floor, Some(64 * GIB), None, None),
            under_the_width_ceiling(4 * GIB)
        );
        assert_eq!(
            window_under(floor, Some(64 * GIB), None, Some(GIB)),
            512 * MIB
        );
        assert_eq!(
            window_under(floor, Some(64 * GIB), None, Some(256 * MIB)),
            128 * MIB
        );
        assert_eq!(window_under(floor, None, None, Some(256 * MIB)), 128 * MIB);
        assert_eq!(window_under(floor, None, None, None), floor);
        assert_eq!(
            window_under(floor, Some(GIB), None, Some(64 * GIB)),
            512 * MIB
        );
    }

    /// SPEC-API 8.1 term 2: half a cgroup limit beats the
    /// 256 MiB floor as half of `RLIMIT_AS` does,
    /// so a window the cgroup cannot hold is refused as `Window` rather
    /// than killed: a 96 MiB cgroup takes a window of at most 48 MiB. A
    /// cgroup of 512 MiB or more leaves the machine's figure unchanged.
    #[test]
    fn half_a_cgroup_limit_caps_the_default_window() {
        let floor = 256 * MIB;
        // `physical` is already the smaller of the machine and the cgroup.
        assert_eq!(
            window_under(floor, Some(96 * MIB), Some(96 * MIB), None),
            48 * MIB
        );
        assert_eq!(
            window_under(floor, Some(512 * MIB), Some(512 * MIB), None),
            floor
        );
        assert_eq!(
            window_under(floor, Some(8 * GIB), Some(8 * GIB), None),
            under_the_width_ceiling(4 * GIB)
        );
        assert_eq!(
            window_under(floor, Some(96 * MIB), Some(96 * MIB), Some(64 * MIB)),
            32 * MIB
        );
    }

    /// PROCESS_HEADROOM against its count (29 Sep 2026): the worst process
    /// peak over memory::peak measured was 22.6 MiB on x86-64 (glibc, max
    /// resident set) and 17.9 MiB on macOS (phys_footprint). A change to
    /// the constant, or a larger count, must be made here too.
    #[test]
    fn the_process_headroom_covers_the_worst_measured_gap() {
        let worst_x86_64 = 22 * MIB + 615 * KIB;
        let worst_macos = 17 * MIB + 922 * KIB;
        assert!(MemoryPolicy::PROCESS_HEADROOM >= worst_x86_64 + 8 * MIB);
        assert!(MemoryPolicy::PROCESS_HEADROOM >= worst_macos + 8 * MIB);
    }
}

#[cfg(test)]
mod limit_named_tests {
    use super::MemoryPolicy;

    /// SPEC-API 8: `from_limit` names its figure, the default included,
    /// and `Default` does not, although the two agree on every other
    /// figure but the window the default raises.
    #[test]
    fn from_limit_names_its_figure_and_default_does_not() {
        let named = MemoryPolicy::from_limit(MemoryPolicy::DEFAULT_LIMIT);
        let default = MemoryPolicy::default();
        assert!(named.limit_named);
        assert!(!default.limit_named);
        assert_eq!(
            MemoryPolicy {
                limit_named: true,
                max_window: named.max_window,
                ..default
            },
            named
        );
        assert!(MemoryPolicy::from_limit(1 << 20).limit_named);
    }

    /// `keeps_residency`: every
    /// NAMED budget keeps it, the whole-process default keeps it although
    /// its limit is not named, and the engine's own default does not.
    #[test]
    fn residency_is_kept_under_a_named_budget_and_the_process_default() {
        assert!(MemoryPolicy::from_limit(1 << 20).keeps_residency());
        assert!(MemoryPolicy::for_process(1 << 30, 0).keeps_residency());
        let process_default = MemoryPolicy::process_default(0);
        assert!(!process_default.limit_named);
        assert!(process_default.keeps_residency());
        let default = MemoryPolicy::default();
        assert!(!default.limit_named);
        assert!(!default.keeps_residency());
    }
}
