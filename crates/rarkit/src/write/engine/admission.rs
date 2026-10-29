//! The admission: the ceiling a run is held to, the rung and the hold it
//! chooses under it, and the held wave under a cap.

use super::*;

// The hold the last run built on this thread chose for its encoders under
// a caller's ceiling (`Run::chosen_hold`), so that a test can read the
// CHOICE, which is a function of the options and the member table, and
// not a peak that moves with the threads' timing.
#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static CHOSEN_HOLD: std::cell::Cell<Option<Option<usize>>> =
        const { std::cell::Cell::new(None) };
}

/// The hold a run has just chosen.
/// The widest a run on the small path's dials runs under a ceiling the
/// caller asked to have kept (`Run::narrow_width`).
pub(super) const NARROW_WIDTH_MOST: usize = 16;

/// What one pool thread past `NARROW_WIDTH_MOST` costs the process beside
/// the engine, counted 24 Oct 2026 on the M5 Ultra under a named 420 MiB:
/// process less stated peak rose by 15 to 16 MiB from sixteen threads to
/// thirty-six in four shapes of six, about 0.8 MiB a thread, and this
/// rounds it up (`Run::choose_rung`).
const WIDE_THREAD_BYTES: u64 = 1 << 20;

pub(super) fn note_chosen_hold(hold: Option<usize>) {
    #[cfg(feature = "bench-internals")]
    CHOSEN_HOLD.with(|last| last.set(Some(hold)));
    #[cfg(not(feature = "bench-internals"))]
    let _ = hold;
}

/// The hold chosen by the last run built on this thread, or `None` where
/// none has been. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn last_chosen_hold() -> Option<Option<usize>> {
    CHOSEN_HOLD.with(std::cell::Cell::get)
}

// Whether the last run on this thread, under a small limit nobody named,
// took the narrow rung (`Run::choose_rung`): a CHOICE, read by the tests.
#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static NARROW_RUNG: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// The chains' wave a capped run is held to and what its parses are
/// charged, for the count's print.
pub(super) fn note_cap_wave(blocks: Option<usize>, flight: u64) {
    #[cfg(feature = "bench-internals")]
    if std::env::var_os("RARKIT_RUNG_SAY").is_some() {
        eprintln!(
            "rarkit rung: the capped wave is {blocks:?} blocks, its parses charged {} MiB",
            flight >> 20
        );
    }
    #[cfg(not(feature = "bench-internals"))]
    let _ = (blocks, flight);
}

/// The rung a run has just chosen.
pub(super) fn note_rung(narrow: bool) {
    #[cfg(feature = "bench-internals")]
    NARROW_RUNG.with(|last| last.set(Some(narrow)));
    #[cfg(not(feature = "bench-internals"))]
    let _ = narrow;
}

/// The rung chosen by the last run on this thread that ran under a small
/// unnamed limit and compressed: `Some(true)` the narrow one,
/// `Some(false)` the default's admission, `None` where no such run has
/// been. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn last_rung() -> Option<bool> {
    NARROW_RUNG.with(std::cell::Cell::get)
}

/// Forget the rung read by [`last_rung`].
#[cfg(feature = "bench-internals")]
pub(crate) fn forget_rung() {
    NARROW_RUNG.with(|last| last.set(None));
}

/// The fewest blocks the chains' wave is held to in a run admitted under
/// an environment's cap (`Run::parses_under_cap`): the eight blocks of one
/// window at the shipped 2 MiB dictionary, which is the wave every held
/// run already has there (`Run::chosen_hold`). So no cell at that
/// dictionary moves, and a longer dictionary's wave (32 blocks from 8 MiB
/// up) is brought to what the shipped one holds: about 20 MiB of parses in
/// flight where 96 threads held 69 to 72.
pub(super) const PARSES_UNDER_CAP_LEAST: usize =
    (2 << 20) / crate::encode::drive::PARSE_BLOCK_BYTES;

/// What stands in the cgroup beside the chains, the history, a window and
/// the parses of a run held under an environment's cap
/// (`Run::parses_under_cap`): the writer's other buffers, the process
/// above what the writer states, and what the kernel charges the group
/// for an archive being written. Counted 3 Oct 2026 on a quiet box
/// (x86-64, 96 threads, one 1 GiB member at a 32 MiB dictionary, levels 3
/// and 5, the wave at 8 and 16 blocks, K=3): the cgroup's peak stood 53 to
/// 62 MiB above the writer's stated peak.
pub(super) const CAP_WAVE_BESIDE: u64 = 56 << 20;

/// Under the COUNT-ONLY feature `wave-knob`, `RARKIT_CAP_WAVE=N` holds the
/// chains' wave of a run admitted under an environment's cap to `N` blocks
/// (`Run::parses_under_cap`), read once, so the widths are counted inside
/// one binary. A width and never a byte.
#[cfg(feature = "wave-knob")]
pub(super) fn knob_cap_wave() -> Option<usize> {
    static WAVE: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *WAVE.get_or_init(|| {
        std::env::var("RARKIT_CAP_WAVE")
            .ok()
            .and_then(|wave| wave.trim().parse::<usize>().ok())
            .filter(|&wave| wave > 0)
    })
}

#[cfg(not(feature = "wave-knob"))]
#[inline(always)]
pub(super) fn knob_cap_wave() -> Option<usize> {
    None
}

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    /// [`Run::encoder_held`] with its parses held to `parses` at once
    /// (`Engine::hold_parses`), or not held.
    pub(super) fn encoder_capped(&self, hold: Option<usize>, parses: Option<usize>) -> Encoder {
        let dictionary = u32::try_from(self.dictionary.min(u64::from(u32::MAX)))
            .expect("the dictionary is clamped to 4 GiB by Writer::new");
        let level = self.options.method;
        // A solid member is never LONE (`encode::drive::Lone`): whether a
        // member of a solid set is parsed alone would otherwise follow the
        // batch it was staged in, and the batch is a width, never a byte.
        let solid = self.options.solid;
        let lone = |lone: Option<crate::encode::drive::Lone>| lone.filter(|_| !solid);
        // A rarkit-only option: levels 4 and 5 parse a lone
        // member lazily by default (`WriteOptions::small_member_lazy`, on
        // by default); off, they give it level 3's optimal chain parse.
        let small_lazy = self.options.small_member_lazy;
        // An option: level 3's empty blocks take the floor's lazy
        // parse instead of the floor scan (`WriteOptions::level3_floor_lazy`,
        // off by default), applied here where the level is known.
        let floor_lazy = self.options.level3_floor_lazy && level == 3;
        // A rarkit-only option: level 3's optimal parse as it
        // was (`WriteOptions::level3_optimal`, off by default). It moves the
        // parse only; whether an empty block scans is `floor_lazy`'s.
        let level3_optimal = self.options.level3_optimal && level == 3;
        // The backward extension's option: level 3's lazy parse 64 links
        // deep, the first plan (`WriteOptions::level3_deep`, off by
        // default); `level3_optimal` overrides it.
        let level3_deep = self.options.level3_deep && level == 3;
        // Its option at levels 1 and 2 (`WriteOptions::low_levels_extend`,
        // off by default).
        let extend_low = self.options.low_levels_extend && level <= 2;
        // Two options: level 4 or 5 keeps the optimal parse over
        // the tree on a member that is not lone (`WriteOptions::level4_optimal`
        // and `level5_optimal`, off by default); a solid set takes the
        // same rule (`SOLID_TAKES_LAZY_TREE`).
        let optimal_tree = (solid && !SOLID_TAKES_LAZY_TREE)
            || match level {
                4 => self.options.level4_optimal,
                5 => self.options.level5_optimal,
                _ => false,
            };
        // Level 4 keeps the lazy parse over the TREE on a member that is
        // not lone (`WriteOptions::level4_tree`, off by default), where
        // by default it walks level 3's chains at 64 links (SPEC-H3 8.1).
        // `level4_optimal` overrides it: `optimal_tree` is applied after.
        let level4_tree = self.options.level4_tree && level == 4;
        // Level 5 keeps the tree for every member that is not lone
        // (`WriteOptions::level5_tree`, off by default), where by default
        // a member's class may give it the chains at 80 links (SPEC-H3
        // 8.1). `level5_optimal` overrides it the same way.
        let level5_tree = self.options.level5_tree && level == 5;
        // Level 5's class without its second statistic
        // (`WriteOptions::level5_far_links_only`, off by default): a member
        // reading many far links keeps the tree whatever long matches its
        // head holds, as before 2 Oct 2026. Applied before the two options
        // that take the class away.
        let level5_far_only = self.options.level5_far_links_only && level == 5;
        // A rarkit-only option: level 1's lazy parse as it was
        // (`WriteOptions::level1_priced`, off by default), applied before
        // the extension, which is the lazy parse's.
        let level1_priced = self.options.level1_priced && level <= 1;
        // The far-link budget (`WriteOptions::far_link_budget`, none by
        // default): it reaches every chain search of whatever plan the
        // options above arrive at, so it is applied last. Level 1 takes
        // none: its searches follow one link (the fast parse) or three
        // (the priced form, and one in an empty block's floor scan), and
        // a budget is for a search deep enough to have a cost to hold.
        let far_links = self.options.far_link_budget.filter(|_| level >= 2);
        let plan_of = |plan: crate::encode::drive::Plan| {
            let plan = if level1_priced {
                plan.priced_level1()
            } else {
                plan
            };
            let plan = if extend_low { plan.extend_low() } else { plan };
            let plan = if level3_deep {
                plan.deep_level3()
            } else {
                plan
            };
            let plan = if level3_optimal {
                plan.optimal_level3()
            } else {
                plan
            };
            let plan = if small_lazy {
                plan
            } else {
                plan.optimal_small_members(level)
            };
            let plan = if level4_tree {
                plan.tree_level4()
            } else {
                plan
            };
            let plan = if level5_far_only {
                plan.far_links_only_level5()
            } else {
                plan
            };
            let plan = if level5_tree {
                plan.tree_level5()
            } else {
                plan
            };
            let plan = if optimal_tree {
                plan.optimal_tree(level)
            } else {
                plan
            };
            let plan = if floor_lazy { plan.lazy_floor() } else { plan };
            match far_links {
                Some(budget) => plan.far_links(budget),
                None => plan,
            }
        };
        let mut encoder = match self.options.format {
            // The ENCODER'S width reaches the encoder here, and it comes
            // from `WriteOptions::workers` rather than from the memory
            // policy (API 8.2's encoder walk row).
            // The memory ceiling is a different dial and still bounds
            // the rows 8.2 leaves to it, the BLAKE2sp leaf team below among
            // them; a memory derived figure has nothing to say about how
            // many tree walkers an encode wants.
            //
            // It cannot change a byte the writer emits: the tree's walk
            // answers the same at any walker count, which is what
            // `with_tree` documents and what the sha-identical
            // 1-to-32-thread measurement shows.
            //
            // Spec G 3.8.2: `FilterPolicy::Detect` judges every member a
            // level from `filters::LEAST_LEVEL` up encodes. A storing level
            // filters nothing (it builds no encoder at all), and nor does
            // level 1: decided 27 Sep 2026, "like rar", whose level
            // 1 writes no filter either, on the timed rows in which
            // detection made -m1 media 1.3x to 1.5x the wall.
            WriteFormat::Rar5 => {
                let mut options = rar5_encode::EncodeOptions {
                    workers: self.options.encoder_width(),
                    ..rar5_encode::EncodeOptions::for_level(level, dictionary)
                };
                options.plan = plan_of(options.plan);
                options.plan.lone = lone(options.plan.lone);
                if solid {
                    options.plan = options.plan.solid_run(level);
                }
                Encoder::Rar5(
                    Box::new(rar5_encode::Rar5Encoder::new(options)),
                    (self.options.filters == FilterPolicy::Detect
                        && level >= filters::least_level())
                    .then(Vec::new),
                )
            }
            WriteFormat::Rar4(_) => {
                let mut options = rar29::EncodeOptions {
                    workers: self.options.encoder_width(),
                    ..rar29::EncodeOptions::for_level(level, dictionary.min(4 << 20))
                };
                options.plan = plan_of(options.plan);
                options.plan.lone = lone(options.plan.lone);
                if solid {
                    options.plan = options.plan.solid_run(level);
                }
                Encoder::Rar29(Box::new(rar29::Rar29Encoder::new(options)))
            }
        };
        if let Some(hold) = hold {
            encoder.hold_wave(hold);
        }
        if let Some(parses) = parses {
            encoder.hold_parses(parses);
        }
        if let Some(blocks) = self.chain_width {
            encoder.hold_chain_width(blocks);
        }
        // A solid volume set's tree walk is as wide as one archive's. It
        // was held to twelve walkers while such a set was encoded a member
        // at a time and its short walks lost wall to a wider one; batched
        // (`Run::may_batch`), the wide walk is 1.04x the held one at level
        // 5 and level with it at level 4 (M3 Ultra, K=5, one binary across
        // a knob, 1 Oct 2026).
        if !self.lead_builds() {
            encoder.no_chain_build();
        }
        encoder
    }

    /// Whether a hold of the lead may be taken to widen the worker team
    /// (`Run::chosen_hold`, `Run::team_width`).
    ///
    /// At levels 1 to 3 always. At levels 4 and 5 only where the members
    /// the team takes are at least half the run's bytes. The tree's walk
    /// runs wide inside the lead's own members, so where most of the bytes
    /// are the lead's, a hold that narrows the lead to free a crew is wall
    /// lost; where most are the team's, the crew is the wall. Counted 28
    /// Sep 2026 under a caller's budget with the charges this change made
    /// honest: holding to widen the team took
    /// mixednoise -m5 -mm256 from 0.853x base's wall to 1.105x and mixed
    /// -m4 -mm256 from 0.882x to 0.979x, and tree5k -m5 -mm96, whose bytes
    /// are mostly its large members, from 0.992x to 0.840x. Before this
    /// change the tree's levels never held for the team, since a crew there
    /// cost more than it was charged. A function of the options and the
    /// member table.
    pub(super) fn hold_widens_team(&self) -> bool {
        if !self.new_encoder().walks_tree() {
            return true;
        }
        let (team, all) = (0..self.members.len())
            .filter(|&index| !self.members[index].is_directory)
            .fold((0u64, 0u64), |(team, all), index| {
                let size = self.members[index].size;
                let team = if self.team_takes(index) {
                    team.saturating_add(size)
                } else {
                    team
                };
                (team, all.saturating_add(size))
            });
        team.saturating_mul(2) >= all
    }

    /// How many of the lead's tree blocks are parsed at once under a
    /// CALLER'S budget, or `None` for as many as the pool runs.
    ///
    /// The last dial, taken after the hold (`Run::chosen_hold`) and only
    /// where it is still needed: at the tree's levels, in a non-solid run
    /// with no worker team, where what the lead holds alone
    /// (`Run::alone_bytes`) passes the budget less [`PROCESS_ROOM_BYTES`]
    /// at the hold chosen. The widest count that fits, since each parse
    /// fewer is wall; where even one does not fit, `None`, because the
    /// terms that do not follow the parses (a member's packed output held
    /// whole, the finder) are what passes, and narrowing would buy no
    /// memory the budget can see. Each parse held is about 2.6 MiB at the
    /// optimal parse (`Engine::hold_parses`).
    ///
    /// A function of the options and the member table.
    pub(super) fn chosen_parses(&self) -> Option<usize> {
        // A caller's ceiling is an engine figure and keeps the process's
        // room back; an unnamed limit (`Run::dial_ceiling`) is already the
        // process budget less its overhead.
        let limit = match self.small_ceiling() {
            Some(ceiling) => ceiling.saturating_sub(PROCESS_ROOM_BYTES),
            None => self.dial_ceiling()?,
        };
        if self.options.solid || !self.new_encoder().walks_tree() || self.team_width() >= 2 {
            return None;
        }
        if self.alone_bytes(self.hold, None) <= limit {
            return None;
        }
        let pool = width::pool_width();
        // Where not even one fits nothing is narrowed, under a caller's
        // ceiling and under an environment's cap alike. Counted 2 Oct 2026
        // under real cgroup limits with ONE parse taken there: a 64 MiB
        // text at level 5 under 96 to 192 MiB ran at 0.64 of the wall
        // (1.60 s against 1.02) for 1.5 MiB less of process, and a 4 GiB
        // set of binaries under 192 MiB was killed with and without it.
        (1..pool)
            .rev()
            .find(|&parses| self.alone_bytes(self.hold, Some(parses)) <= limit)
    }

    /// The hold for this run's encoders under a CALLER'S budget: `None`
    /// (unheld), one window, or one parse block. None of them moves a byte
    /// (`Engine::hold_wave`), so this chooses a wall and a peak, never an
    /// archive. At the shipped 2 MiB dictionary the three are the lead's
    /// chains at 16 Mi, 4 Mi and 4 Mi links (68, 20 and 20 MiB with their
    /// heads; a window's eight blocks parse in one wave either way) and its
    /// tree's hints at eight, eight and four blocks (32, 32 and 16 MiB). `None` at the default policy, whose run is the one it
    /// was. A function of the options and the member table, as the team's
    /// width is.
    ///
    /// A NON-SOLID run takes the one that
    ///
    /// 1. keeps what runs inside the budget, since a budget the user set
    ///    is hard, and where none does, holds least: the lead
    ///    and what beside it the team needs (`Run::beside_team_bytes`)
    ///    where the hold leaves a team, the lead alone
    ///    (`Run::alone_bytes`) where it does not;
    /// 2. of those, at levels 1 to 3, leaves the widest worker team
    ///    (`Run::team_width`; one crew is no team), which is the fastest
    ///    wall where the set has small members: counted 28 Sep
    ///    2026, tree5k and mixed at `-mm128` ran 1.3x to 2.4x base's wall
    ///    inside the budget, where the window's hold left no team;
    /// 3. of those, is the widest, because a narrower hold parses the lead
    ///    member's window in more waves.
    ///
    /// At levels 4 and 5 the team is a reason to hold only where the team
    /// takes at least half the run's bytes (`Run::hold_widens_team`);
    /// elsewhere `Run::team_width` sizes it from the unheld lead.
    ///
    /// A SOLID run holds one window: its chains are sized from the carried
    /// history (16 Mi links at 2 MiB), which the member terms of
    /// `Run::beside_team_bytes` do not see. Counted, small9k solid at
    /// `-mm96` peaked at 65 MiB held against 93 to 96 unheld, at the same
    /// wall.
    pub(super) fn chosen_hold(&self) -> Option<usize> {
        let limit = self.dial_ceiling()?;
        if self.options.solid {
            return Some(self.window_bytes());
        }
        let widens = self.hold_widens_team();
        let crew = self.crew_bytes();
        let holds = [
            None,
            Some(self.window_bytes()),
            Some(crate::encode::drive::PARSE_BLOCK_BYTES),
        ];
        let mut best = None;
        let mut best_key = None;
        for hold in holds {
            let beside = self.beside_team_bytes(hold);
            let width = self.team_share(limit.saturating_sub(beside) / crew);
            let team = if width >= 2 && widens { width } else { 0 };
            // What has to fit is what runs: the team's batches and kept
            // buffers only where this hold leaves a team.
            let held = if team > 0 {
                beside
            } else {
                self.alone_bytes(hold, self.parses)
            };
            let fits = held <= limit;
            let key = (fits, team, if fits { 0 } else { u64::MAX - held });
            if best_key.is_none_or(|best| key > best) {
                best_key = Some(key);
                best = hold;
            }
        }
        // Where NO hold fits a small limit nobody named, at the tree's
        // levels with no team: one window where the environment's cap
        // certainly admits it (`Run::lead_certain_bytes`), not the least.
        // Under a caller's ceiling the least is held, since that budget
        // is hard and its overshoot is reported; under an environment's
        // cap what ends the run is the cap, and the working limit under
        // it is a planning figure the lead's sum passes long before the
        // process does. Counted 2 Oct 2026 under real cgroup limits:
        // a 64 MiB text at level 5 under 96 to 192 MiB held one parse
        // block at 1.08 s and 92 MiB of process, where one window ran 1.00
        // s at 96 MiB under 256 MiB and the unheld default 1.02 s at 98.
        if best_key.is_some_and(|key| !key.0 && key.1 == 0)
            && self.small_ceiling().is_none()
            && self.new_encoder().walks_tree()
        {
            let cap = self.options.memory.environment_cap;
            let window = Some(self.window_bytes());
            let certain = self
                .lead_certain_bytes(window, self.parses)
                .saturating_add(PROCESS_ROOM_BYTES);
            if cap > 0 && certain <= cap {
                return window;
            }
        }
        best
    }

    /// An UPPER BOUND on member `index`'s packed bytes, which the writer
    /// cannot know before it encodes and therefore bounds by the
    /// UNPACKED size, which it does know, plus the room a block that
    /// will not compress spends on being stored instead.
    ///
    /// **Spec G 3.5's own term**, quoted there as "the member's UNPACKED
    /// size plus the per-block overhead of a stored block". It is shared
    /// Used by [`Run::held_whole_bytes`], which is what decides whether
    /// a member may be held whole at all. The withdrawn reserve
    /// asked for this same figure, so that the room reserved and the
    /// promise it honoured could not drift apart; the comment in
    /// [`Run::compress`] says why it is not taken.
    pub(super) fn packed_bound(&self, index: usize) -> u64 {
        let size = usize::try_from(self.members[index].size).unwrap_or(usize::MAX);
        crate::encode::drive::packed_most(size) as u64
    }

    /// Reserve [`Run::packed`] to member `index`'s packed bound, where the
    /// member is held and its packed bytes would otherwise be grown by
    /// appends.
    ///
    /// Two cases. UNDER A CALLER'S CEILING, a held non-solid member, as
    /// the comment in [`Run::compress`] says. And, whatever the policy, a
    /// held member of a SOLID set LONGER THAN A WINDOW, which is encoded a
    /// window at a time ([`Run::compress_streaming`]): grown by appends
    /// its buffer doubled to 512 MiB of capacity for S8's 356 MB member,
    /// beside the buffer the engine was handed by the swap in
    /// [`flush_windows`], which that function no longer takes where the
    /// buffer has the room (spec G 3.5's held-member rule, 30 Sep 2026).
    ///
    /// Not a member at most a window long: the note in [`Run::compress`]
    /// measured that as a retention cost, and its bytes are bounded by the
    /// window. Not a non-solid member whose bytes are in memory, which is
    /// encoded as one region into a buffer of the engine's that is
    /// swapped in whole, so a reserve here would be handed away. And not
    /// a NON-SOLID member from a reader at the default policy, measured:
    /// reserved, tree5k at -m3 -mt1 on macOS 27.0 peaked at 108 to 110
    /// MiB of `phys_footprint` against 103 to 107 unreserved, three runs
    /// each, a new block per member whose bound passed the last and the
    /// old one kept by the allocator, where a solid set's big members
    /// are few.
    pub(super) fn reserve_held(&mut self, index: usize) {
        if self.streams_packed(index) {
            return;
        }
        if self.held_kept(index) && !self.packed_held && self.held_spare.capacity() > 0 {
            self.packed = std::mem::take(&mut self.held_spare);
            self.packed_held = true;
        }
        if (!self.options.solid && self.dial_ceiling().is_some()) || self.held_kept(index) {
            let bound = usize::try_from(self.packed_bound(index)).unwrap_or(usize::MAX);
            self.packed.reserve_exact(bound);
            self.packed_held |= self.held_kept(index);
        }
    }

    /// Whether member `index`, held, has [`Run::packed`] reserved for it
    /// by [`Run::reserve_held`] as a member longer than a window encoded a
    /// window at a time (a solid set's, or a reader's), and so is appended
    /// to window by window rather than swapped (`flush_windows`).
    ///
    /// A NON-SOLID reader longer than a window was left to grow by appends
    /// until 30 Sep 2026, and on bin4g at `-m3` its buffer doubled to 108
    /// MiB for a 95 MB member that would not compress, beside the doubling
    /// it grew from, and stayed resident for the rest of the run, stated
    /// at its length (counted with a scratch allocator on an Apple M3 Mac). Reserved to its
    /// bound, it is one buffer of the member's size, kept for the next and
    /// grown only by a larger one (`Run::write_member`). Such
    /// members are few (269 of bin4g's 9,516); tree5k's, which the reserve
    /// was measured against, are all within a window. This is also the held-buffer charge a caller's
    /// admission can read: such a member holds `Run::packed_bound` once,
    /// beside the engine's per-window buffers; every other held member is
    /// charged its packed bytes twice (`Run::held_whole_bytes`).
    pub(super) fn held_kept(&self, index: usize) -> bool {
        let member = &self.members[index];
        member.size > self.window_bytes() as u64
            && (self.options.solid || matches!(member.payload, Payload::Reader { .. }))
    }

    /// The memory ceiling the CALLER set, or `None` where the caller set
    /// none. Spec G 3.5's case (b) turns on this and on nothing else.
    ///
    /// "The caller set one" is `MemoryPolicy::limit_named` (SPEC-API 8, 28
    /// Sep 2026): `from_limit` names its figure, `DEFAULT_LIMIT` included,
    /// and `MemoryPolicy::default` does not. Before that field existed this
    /// read `working_limit != DEFAULT_LIMIT`, the only spelling the policy
    /// then had, and a caller who named exactly 512 MiB (the CLI's
    /// `-mm512m`) was read as having named nothing.
    pub(super) fn caller_ceiling(&self) -> Option<u64> {
        let memory = &self.options.memory;
        memory.limit_named.then_some(memory.working_limit)
    }

    /// A caller's ceiling too SMALL for the default's admission, or `None`:
    /// a NAMED limit whose budget (`working_limit` and the policy's
    /// `process_overhead`) is under [`MemoryPolicy::DEFAULT_LIMIT`].
    ///
    /// **A named ceiling of 512 MiB and more is a budget, and inside it
    /// the writer admits what the default admits at that `working_limit`**
    /// (spec G 3.7.3, "A NAMED ceiling admits what the default admits", 1
    /// Oct 2026): the staged flush, the team's members and its lane, the
    /// segment team, the batch planned ahead, the judges kept, and the
    /// default's history slack, so its packed streams are the default's.
    /// One form stays off under ANY named ceiling: the lane's reach past a
    /// window (`Run::choose_large_lane` says why).
    /// Until then every one of those was off under any named ceiling, and
    /// `-mm512m` ran bin4g at `-m3` about four cores wide on any pool:
    /// 30.61 s against the default's 19.44 at the same 512 MiB on sixteen
    /// threads (measured 1 Oct 2026; staged flushes
    /// 1.29x alone, the lane 1.09x, the slack the last 8 percent).
    ///
    /// **Under 512 MiB the named path is the one it was**, and wherever
    /// this file says what happens "under a caller's ceiling" of a width,
    /// a hold, a batch or a flush, it is this ceiling it means: one window
    /// a flush, team members of one parse block, `max_workers` in the
    /// width, the lead's hold and parses dials, the shipped slack, and the
    /// bytes it wrote. The default's admission was proven inside its limit
    /// at the 512 MiB floor and above; counted under it, it stated 236 MiB
    /// at `-m5` under a 128 MiB figure and fielded no team at `-m3` under
    /// 256 MiB where this path fields five crews.
    ///
    /// What still asks [`Run::caller_ceiling`] at any figure: whether a
    /// member is held or streamed (spec G 3.5), the sampled head's charge,
    /// and `WriteReport::ceiling_exceeded_by`.
    pub(super) fn small_ceiling(&self) -> Option<u64> {
        let memory = &self.options.memory;
        let budget = memory.working_limit.saturating_add(memory.process_overhead);
        self.caller_ceiling()
            .filter(|_| budget < MemoryPolicy::DEFAULT_LIMIT)
    }

    /// The `working_limit` of a policy NOBODY NAMED whose budget
    /// (`working_limit` and the policy's `process_overhead`) is under
    /// [`MemoryPolicy::DEFAULT_LIMIT`], or `None`: the unnamed twin of
    /// [`Run::small_ceiling`], the same predicate on the same figures.
    ///
    /// It is what `MemoryPolicy::process_default` derives where an
    /// ENVIRONMENT's cap binds (a cgroup limit under 608 MiB, an address
    /// space under 2 GiB; SPEC-API 8.1 term 2), and what a
    /// library caller gets who lowers `working_limit` and leaves
    /// `limit_named` false. At a budget of 512 MiB and above it is `None`
    /// and nothing below runs.
    pub(super) fn unnamed_small_limit(&self) -> Option<u64> {
        let memory = &self.options.memory;
        let budget = memory.working_limit.saturating_add(memory.process_overhead);
        (!memory.limit_named && budget < MemoryPolicy::DEFAULT_LIMIT)
            .then_some(memory.working_limit)
    }

    /// The limit this run's BYTE-NEUTRAL dials are chosen against, or
    /// `None` where the default's admission runs: a small named ceiling
    /// ([`Run::small_ceiling`]), or a small unnamed limit where this run
    /// took the narrow rung ([`Run::choose_rung`]).
    ///
    /// The dials: one window a flush, the team's members of one parse
    /// block, no large-member lane, the base batch, the team's width from
    /// what a crew holds, the lead's hold and its parses in flight, the
    /// held buffer reserved, the samples judged on the walking thread, no
    /// reader pulled ahead in a solid run, one engine a member. None of
    /// them moves a byte.
    ///
    /// **What does NOT read this, and reads [`Run::small_ceiling`]
    /// instead: the history slack**, the one dial of the small named path
    /// that moves tokens. Under an unnamed limit the slack stays the
    /// default's, so the archive is the uncapped default's whatever the
    /// cap (an archive's bytes do not follow the machine, SPEC-API 8.4.1).
    /// Whether a member is held or streamed is the default's rule too
    /// (`Run::held_member_limit`, which SPEC-G 3.5 already lowers under
    /// such a cap).
    pub(super) fn dial_ceiling(&self) -> Option<u64> {
        self.small_ceiling()
            .or_else(|| self.unnamed_small_limit().filter(|_| self.narrow))
            .or_else(|| self.large_named_ceiling().filter(|_| self.narrow))
    }

    /// The width a run on the small path's dials takes under a ceiling the
    /// caller asked to have kept (`WriteOptions::refuse_over_ceiling`):
    /// `NARROW_WIDTH_MOST`, or fewer where the caller asked for fewer; `None`
    /// for every other run, which keeps its width.
    ///
    /// Counted 24 Oct 2026 on the M5 Ultra under a named 420 MiB (`-m5
    /// -md32m`, one 2 GiB member and up to thirty-two smaller): on the
    /// small path the write's stated peak stayed inside its limit at sixteen
    /// threads and fewer and passed it by 12 to 17 MiB at thirty-six. A run
    /// on the default's plan is not narrowed: under a named 2, 4 or 12 GiB a
    /// sixteen-thread cap took that member from 17.5 to 18.3 s to 31.6 s.
    /// It moves no byte (API promise 2.6).
    pub(super) fn narrow_width(&self) -> Option<usize> {
        (self.options.refuse_over_ceiling && self.dial_ceiling().is_some())
            .then(|| self.options.encoder_width().min(NARROW_WIDTH_MOST))
    }

    /// A ceiling the caller named, of 512 MiB and more, that the caller
    /// asked to have kept (`WriteOptions::refuse_over_ceiling`), or `None`.
    ///
    /// Under such a ceiling the writer admits what the default admits
    /// (`Run::small_ceiling`), and where the default's plan cannot fit it,
    /// [`Run::choose_rung`] takes the small path's byte-neutral dials
    /// instead (`Run::narrow`), so that a larger named figure never holds
    /// less than a smaller one does. Counted 24 Oct 2026 on the M5 Ultra
    /// (`-m5 -md32m`, one 2 GiB member and eight of 256 MiB): a named
    /// 501 MiB ran both on the small path, and 512 MiB, where the default's
    /// admission begins, was refused as needing 529.
    pub(super) fn large_named_ceiling(&self) -> Option<u64> {
        self.caller_ceiling()
            .filter(|_| self.options.refuse_over_ceiling && self.small_ceiling().is_none())
    }

    /// Chooses the admission of a run under a small limit nobody named,
    /// once, before a byte is written: [`Run::narrow`].
    ///
    /// **Why.** Under a cgroup cap below the floor the default's admission
    /// ran at the small `working_limit` the policy derives and had nothing
    /// left to narrow: no hold, no parses dial, a solid run that read no
    /// limit. Counted on 1 Oct 2026 (x86-64,
    /// `MemoryMax`): a create of 9,516 binaries
    /// stated 170 MiB at a limit of 144 and stood at 225 to 236 MiB of
    /// process, and under 96, 128 and 192 MiB the kernel killed it at
    /// every level, leaving a partial archive; a solid run of 5,000 small
    /// files stated 112 to 117 MiB at every cap. The small named path's
    /// dials, at their narrowest, held the same sets in 87 to 133 MiB.
    ///
    /// **The rungs.**
    ///
    /// 1. The default's admission, where what it plans fits the limit:
    ///    nothing moves, and the wall is the default's (a staged flush,
    ///    the lane).
    /// 2. Otherwise the byte-neutral dials of the small named path
    ///    ([`Run::dial_ceiling`]), chosen against `working_limit` as a
    ///    small named ceiling chooses them, and where none of them fits,
    ///    a hold all the same: one window at the tree's levels where the
    ///    cap certainly admits it, else the least (`Run::chosen_hold`).
    ///
    /// 3. A refusal, before the first byte, where the policy carries an
    ///    environment's cap (`MemoryPolicy::environment_cap`) and what the
    ///    lead certainly holds cannot fit it (`Run::lead_one_finder_bytes`,
    ///    one finder charged where the member's class decides between two):
    ///    `LimitExceeded { WorkingMemory }`, the cap its limit. Nothing
    ///    that could complete is refused; between `working_limit` and the
    ///    cap the narrowest plan runs.
    ///
    /// Where BOTH of the first two fit, the narrow rung is taken only
    /// where it fields a worker team, the default's admission fields
    /// none, and the team's members are at least half the run's bytes
    /// (`Run::team_has_most_bytes`): inside a limit the widest team is the
    /// fastest wall for a set of small members, and the
    /// default's unheld lead leaves a small limit no room for one. Counted on the same day, the two arms back to back under each
    /// cap: 5,000 small members under 256 MiB ran 2.2x and 1.8x faster
    /// narrow at levels 3 and 5, and a 4 GiB set under 384 MiB ran 1.13x
    /// to 1.31x faster on the default's admission.
    ///
    /// A SOLID run and a storing level choose nothing: they run as they
    /// did (the solid run's own sum is not done yet).
    ///
    /// A function of the options and the member table, as every dial is.
    pub(super) fn choose_rung(&mut self) -> Result<()> {
        self.narrow = false;
        self.chain_width = None;
        if let Some(ceiling) = self.large_named_ceiling() {
            // A named ceiling of 512 MiB and more, asked to be kept: the
            // default's admission where what its lead certainly holds fits
            // the ceiling, else the small path's dials, chosen against the
            // ceiling as a small named ceiling chooses them. Neither moves
            // a byte: the history slack reads `Run::small_ceiling`, which
            // stays `None` here. A storing level has no encoder, and a
            // SOLID run keeps the default's path, as below.
            // The default's plan runs at the pool's own width, and each
            // pool thread past `NARROW_WIDTH_MOST` costs the process about
            // `WIDE_THREAD_BYTES` the caller's room did not count (the room
            // is taken at a fixed width, so that bytes do not follow the
            // machine): charged here, where it decides only which dials
            // run, never a byte.
            let wide = (super::width::pool_width().min(self.options.encoder_width()) as u64)
                .saturating_sub(NARROW_WIDTH_MOST as u64)
                .saturating_mul(WIDE_THREAD_BYTES);
            if !self.options.stored()
                && !self.options.solid
                && self
                    .lead_one_finder_bytes(self.hold, self.parses)
                    .saturating_add(wide)
                    > ceiling
            {
                self.narrow = true;
                self.hold = self.chosen_hold();
                self.parses = self.chosen_parses();
            }
            note_chosen_hold(self.hold);
            note_rung(self.narrow);
            return Ok(());
        }
        let Some(limit) = self.unnamed_small_limit() else {
            return Ok(());
        };
        if self.options.stored() {
            // A storing level has no encoder to admit.
            return Ok(());
        }
        if self.options.solid {
            // A SOLID run keeps the default's path at every limit, as it
            // had: its finder is sized from the carried history, which the
            // member terms of `Run::alone_bytes` do not see
            // (`Run::chosen_hold`), so no sum here can say whether its
            // unheld run fits. Counted 2 Oct 2026 under real cgroup limits:
            // holding one window regardless ran 5,000 small members solid
            // at 0.35x to 0.8x of the wall in cells where the unheld run
            // completes, and a sum built from the engine's own terms
            // overstated a level 5 run by 80 MiB and understated a set
            // with one 226 MiB member. Its hold under a small unnamed
            // limit is not done yet: it needs an honest sum for it.
            return Ok(());
        }
        // Rung 1, as the default's own choosers leave it.
        self.choose_lead_depth();
        self.choose_team_most();
        self.choose_large_lane();
        let wide_team = self.team_width();
        // A team of two and more was fitted to the limit by its own
        // choosers (`Run::team_width`'s share, `Run::fit_large_lane`), the
        // lead's sum inside it; a lead alone fits where its sum does.
        let alone = self.alone_bytes(None, None);
        let wide_fits = wide_team >= 2 || alone <= team_ceiling(limit);
        note_plan(alone);
        // Rung 2.
        self.narrow = true;
        self.hold = self.chosen_hold();
        self.parses = self.chosen_parses();
        let narrow_team = self.team_width();
        let narrow_fits = if narrow_team >= 2 {
            self.beside_team_bytes(self.hold.filter(|_| self.hold_widens_team())) <= limit
        } else {
            self.alone_bytes(self.hold, self.parses) <= limit
        };
        // Where both fit, the team decides only where the team's members
        // are most of the run: a set of large members is the lead's, and
        // there the default's staged flush is the faster wall (counted: a
        // 4 GiB set of binaries under 384 MiB, 23 s on the default's
        // admission with no team against 31 s narrow with one).
        let narrow = !wide_fits
            || (narrow_fits && narrow_team >= 2 && wide_team < 2 && self.team_has_most_bytes());
        if !narrow {
            self.narrow = false;
            self.hold = None;
            self.parses = None;
        }
        note_chosen_hold(self.hold);
        note_rung(self.narrow);
        // Rung 3: no plan fits the ENVIRONMENT's cap itself. Refused here,
        // before a byte, in the caller's terms; past the cap the kernel
        // kills the process, or refuses its memory, with the archive part
        // written. What is weighed is only what the lead CERTAINLY holds
        // (`Run::lead_one_finder_bytes`), so that nothing which could have
        // completed is refused: between `working_limit` and the cap the
        // narrowest plan RUNS, since completing beats refusing.
        let cap = self.options.memory.environment_cap;
        if self.narrow && !narrow_fits && cap > 0 {
            // One finder, the larger: the member's class is not read yet,
            // and the run builds only the one it takes
            // (`Run::lead_one_finder_bytes`).
            let needed = self
                .lead_one_finder_bytes(self.hold, self.parses)
                .saturating_add(PROCESS_ROOM_BYTES);
            note_needed(needed);
            if needed > cap {
                return Err(Error::new(ErrorKind::LimitExceeded {
                    resource: crate::error::Resource::WorkingMemory,
                    needed,
                    limit: cap,
                }));
            }
            // Admitted with no plan that fits: the chains' parses in
            // flight are held, so the run stands inside the cap with room
            // rather than on its edge (`Run::parses_under_cap`).
            self.chain_width = self.parses_under_cap(cap);
            note_cap_wave(self.chain_width, self.capped_flight(self.chain_width));
        }
        Ok(())
    }

    /// Refuses, before a byte is written, a run that cannot keep a ceiling
    /// the caller NAMED, where the caller asked for that
    /// (`WriteOptions::refuse_over_ceiling`); otherwise it does nothing,
    /// and a named ceiling the run passes is reported as before
    /// (`WriteReport::ceiling_exceeded_by`).
    ///
    /// **The figure** is [`Run::named_most_bytes`]: every term the run's
    /// stated working memory (`Run::working_now`) holds, each at the most it
    /// reaches for this member table at the hold and parses the run already
    /// chose under the ceiling. Until 25 Oct 2026 it was rung 3's figure,
    /// what the lead CERTAINLY holds (`Run::lead_one_finder_bytes`), and the
    /// run then held past it by what that leaves out: counted on macOS (M5
    /// Max, 18 threads) at the least `-mm` each named, the write's stated
    /// peak passed `working_limit` by 80 MiB over 13,477 text files at `-m5
    /// -md32m` (both level 5 finders live at once, where one was charged),
    /// by 145 over 118 MB of text at `-md128m -s` (a solid run's history is
    /// the stream's, not the largest member's), and by 58 over one 2 GiB
    /// member (parses in flight, the store rule's judges, the stream's
    /// buffers), and the process passed the named `-mm` by 52, 114 and 6
    /// MiB (the chain 40 cause count). The
    /// figure moves no byte: it decides only whether the run is refused.
    ///
    /// **Why it exists.** Under a named ceiling the dictionary is capped at
    /// the ceiling's own figure and no lower, while one member's window
    /// costs the encoder several times the dictionary: counted 23 Oct 2026
    /// on macOS (M5 Ultra, 82 MiB of text, `-m5`, release build), the
    /// write's own stated peak under a 256 MiB ceiling was 133 MiB at
    /// `-md8m`, 236 at `-md16m`, 363 at `-md32m`, 618 at `-md64m` and 1,130
    /// at `-md128m`, at one thread as at thirty-six and at level 1 as at 5,
    /// and every one of them finished with nothing said.
    ///
    /// The ceiling compared is `working_limit`, the engine's own figure
    /// under the named ceiling, and that is what `limit` names. A storing
    /// level has no encoder and is never refused. A function of the
    /// options and the member table.
    pub(super) fn refuse_over_named_ceiling(&mut self) -> Result<()> {
        if !self.options.refuse_over_ceiling || self.options.stored() {
            return Ok(());
        }
        let Some(ceiling) = self.caller_ceiling() else {
            return Ok(());
        };
        self.read_lone_head();
        let held = self.named_most_bytes();
        if held > ceiling {
            let needed = self.needed_where_it_runs(held);
            return Err(Error::new(ErrorKind::LimitExceeded {
                resource: crate::error::Resource::WorkingMemory,
                needed,
                limit: ceiling,
            }));
        }
        Ok(())
    }

    /// Read the ONE member's head before the refusal, so that it is charged
    /// the finder its own class builds (`Run::lone_head`, FROM-STUDIO 841)
    /// and not the larger of level 5's two. A reader's
    /// [`class::HEAD_BYTES`] are pulled into the store rule's prefix by the
    /// very call the encode makes for its class (`store::Prefix::head`,
    /// `Run::start_member_run`) and HELD there: the samples and the encode
    /// read them back (`store::Prefix::keeps`), so the reader is read once,
    /// in order, nothing is sought, and no byte moves. Bytes in memory need
    /// no read. Only where the member's own path reads it back: not a solid
    /// run (whose charge reads no class), and a member the store rule
    /// samples (`Run::may_sample`), which is where a failed pull is
    /// reported (`Run::head_failed`). A pull that fails holds no head, so
    /// the member is charged the larger finder, and its error is the
    /// write's where the member is reached, as it would have been.
    fn read_lone_head(&mut self) {
        if self.options.solid || !self.reads_class() {
            return;
        }
        let Some(index) = self.lone_lead() else {
            return;
        };
        let size = self.members[index].size;
        if size < class::HEAD_BYTES as u64 || !self.may_sample(index) {
            return;
        }
        let span = usize::try_from(size.min(store::PREFIX_BYTES as u64))
            .expect("the prefix is at most 32 MiB");
        let Run {
            members, prefix, ..
        } = self;
        let failed = match &mut members[index].payload {
            Payload::Reader { reader, .. } => {
                let pulled = prefix
                    .head(index, &mut **reader, class::HEAD_BYTES, span)
                    .map(|_| ());
                if pulled.is_ok() {
                    prefix.keep();
                }
                pulled.err()
            }
            Payload::Bytes(_) => None,
        };
        if let Some(error) = failed {
            self.head_failed = Some((index, error));
        }
    }

    /// The least `working_limit`, from `held` up, under which this run's
    /// own dials, chosen again for that limit ([`Run::choose_rung`]), hold
    /// no more than it: what a refusal NAMES, so that the figure it names
    /// runs. A larger ceiling can take wider dials (no hold, the default's
    /// plan, the kept judges), so the sum at the dials chosen under the
    /// refused ceiling named a figure that was refused again: counted 25 Oct
    /// 2026, a 34 MiB text member at `-m5 -md32m` named `-mm837m` under
    /// `-mm256m` and was refused at 837 as needing 894. At most eight rounds;
    /// the run's own limit and dials are put back after.
    fn needed_where_it_runs(&mut self, held: u64) -> u64 {
        let kept = (
            self.options.memory.working_limit,
            self.narrow,
            self.hold,
            self.parses,
            self.chain_width,
        );
        let mut needed = held;
        for _ in 0..8 {
            self.options.memory.working_limit = needed;
            // As `Run::new` chooses them, then the rung, as `Run::walk` does.
            self.hold = self.chosen_hold();
            self.parses = self.chosen_parses();
            if self.choose_rung().is_err() {
                break;
            }
            let again = self.named_most_bytes();
            if again <= needed {
                break;
            }
            needed = again;
        }
        (
            self.options.memory.working_limit,
            self.narrow,
            self.hold,
            self.parses,
            self.chain_width,
        ) = kept;
        needed
    }

    /// The lead's CHAINS' wave, in blocks, where an ENVIRONMENT'S cap binds
    /// and no plan fits the limit under it (`Run::choose_rung`, a run
    /// admitted past its narrow rung), or `None` for the wave's own width.
    /// The tree's parses are not moved: the hold of its hints to the least
    /// already leaves it one walk group in flight.
    ///
    /// **The rule is the cap's**: the widest wave at which what the chains
    /// hold (`Run::lead_chain_bytes`), one window read, the wave's parses
    /// (`Run::capped_flight`), the process's room and what stands beside
    /// them ([`CAP_WAVE_BESIDE`]) come to NINE TENTHS of the cap; `None`
    /// where the unheld wave does; and where not even
    /// [`PARSES_UNDER_CAP_LEAST`] blocks do, that many. Nothing where no
    /// class of the level gives a member to the chains.
    ///
    /// **Why.** `Run::chosen_parses` narrows nothing where not even one
    /// parse fits its sum, and nothing at the chains' levels; and a held
    /// wave (`Engine::hold_wave`) does not bound the chains' parses at a
    /// long dictionary. At 32 MiB on 96 threads they are 69 to 72 MiB, and
    /// counted 3 Oct 2026 under real cgroup limits (x86-64,
    /// `MemoryMax=512M`) levels
    /// 3, 4 and 5 at `-md32m` stood at 475 to 484 MiB of process with the
    /// cgroup at its cap, and were killed by the kernel on a busy box, a
    /// partial archive left: the refusal this run was admitted past must
    /// not become that.
    ///
    /// **What the width costs and buys**, the same count on a quiet box
    /// (one 1 GiB member, K=3, the cgroup's own peak): 8 blocks 445 MiB
    /// and 2.4x the unheld wall, 16 blocks 465 to 471 and 1.5x, 24 blocks
    /// 488 to 493 and 1.3 to 1.4x, unheld 511 to 512.
    ///
    /// Nothing here runs with no environment's cap, at a budget of 512 MiB
    /// and above, in a solid run or under a caller's named ceiling (the
    /// named path's own dial is not counted yet).
    pub(super) fn parses_under_cap(&self, cap: u64) -> Option<usize> {
        if let Some(blocks) = knob_cap_wave() {
            return Some(blocks);
        }
        let chains = self.lead_chain_bytes(self.hold, self.parses);
        if chains == 0 {
            return None;
        }
        let held = chains
            .saturating_add(self.window_bytes() as u64)
            .saturating_add(PROCESS_ROOM_BYTES)
            .saturating_add(CAP_WAVE_BESIDE);
        let most = cap / 10 * 9;
        let fits = |blocks: Option<usize>| held.saturating_add(self.capped_flight(blocks)) <= most;
        if fits(None) {
            return None;
        }
        let window_blocks = self
            .window_bytes()
            .div_ceil(crate::encode::drive::PARSE_BLOCK_BYTES);
        Some(
            (PARSES_UNDER_CAP_LEAST..window_blocks.max(PARSES_UNDER_CAP_LEAST))
                .rev()
                .find(|&blocks| fits(Some(blocks)))
                .unwrap_or(PARSES_UNDER_CAP_LEAST),
        )
    }

    /// What one window's parses in flight are charged
    /// (`Encoder::flight_term_over`) at this run's hold with the chains'
    /// wave held to `blocks`, or not held.
    pub(super) fn capped_flight(&self, blocks: Option<usize>) -> u64 {
        let window = self.window_bytes();
        let span = usize::try_from(self.dictionary)
            .unwrap_or(usize::MAX)
            .saturating_add(window);
        let mut probe = self.encoder_capped(self.hold, self.parses);
        if let Some(blocks) = blocks {
            probe.hold_chain_width(blocks);
        }
        probe.flight_term_over(window, span)
    }

    /// What the HELD-WHOLE write of member `index` would hold, in bytes.
    ///
    /// Spec G 3.5 names the terms and these are them: the dictionary the
    /// member's options choose, the FINDER TERM (restated 28 Sep 2026:
    /// what the level's finder allocates over the member held whole,
    /// `Engine::finder_term`, computed by the functions that size the
    /// finder so the two cannot drift; it was ten bytes per byte of
    /// dictionary, which at `-m1` and 128 KiB charged 1.25 MiB for chains
    /// of 8 MiB), one window, and the member's packed bytes held whole -
    /// which the writer cannot know before it encodes and therefore bounds
    /// by the UNPACKED size, which it does know, plus the room a block
    /// that will not compress spends on being stored instead. A storing
    /// level has no finder.
    ///
    /// **The packed bytes are COUNTED TWICE** (spec G 3.5's held-member
    /// rule of 30 Sep 2026): the buffer they grow in
    /// and the one beside it. Two held members of 356 and 287 MB were
    /// counted at 746 to 826 MiB of process peak where the first rule had
    /// charged the bound once and held them under 512 MiB. The writer now
    /// reserves the held buffer to its bound rather than growing it
    /// (`Run::reserve_held`) and appends into it (`flush_windows`), so it
    /// holds less than this; the spec's sum is kept as the one both a
    /// named ceiling and the default policy's `working_limit` are met
    /// with.
    ///
    /// **It is a function of the POLICY and the MEMBER and of nothing
    /// else**, which is what makes the mode it chooses the same on every
    /// run (spec G 3.5's acceptance test 3). No clock, no measured
    /// resident size, no count of what is in flight, and in particular
    /// not [`Run::packed_estimate`], whose ratio follows the members
    /// already written and would make one member's mode depend on
    /// another's bytes.
    pub(super) fn held_whole_bytes(&self, index: usize) -> u64 {
        let size = self.members[index].size;
        let finder = if self.options.stored() {
            0
        } else {
            // At the finder's own geometry: the term is the spec's, and a
            // hold (`Run::chosen_hold`) only ever takes less.
            self.encoder_held(None)
                .finder_term(usize::try_from(size).unwrap_or(usize::MAX))
        };
        self.dictionary
            .saturating_add(finder)
            .saturating_add(self.window_bytes() as u64)
            .saturating_add(self.packed_bound(index).saturating_mul(2))
    }

    /// The limit a member's held-whole write must fit where no caller
    /// named a ceiling: the policy's `working_limit`, but never more than
    /// the FLOOR's figure, `MemoryPolicy::DEFAULT_LIMIT` less the process's
    /// overhead, whatever the machine's memory.
    ///
    /// The default `working_limit` scales with physical memory;
    /// this threshold does not follow it (decided 1 Oct 2026):
    /// holding and streaming differ in a member's packed size field, and
    /// the same input must write the same archive on a 16 GB laptop and a
    /// 376 GB server, nor should a default create hold a member of many
    /// GiB in memory. Only the WIDTH scales. Under a NAMED ceiling the
    /// threshold is the named figure (`Run::over_ceiling`), as it was.
    pub(super) fn held_member_limit(&self) -> u64 {
        let memory = &self.options.memory;
        memory
            .working_limit
            .min(MemoryPolicy::DEFAULT_LIMIT.saturating_sub(memory.process_overhead))
    }

    /// By how many bytes holding member `index` whole would pass the
    /// caller's ceiling, or `None` where it would not, or where the
    /// caller named no ceiling at all.
    ///
    /// **This is the switch between spec G 3.5 case (b)'s two modes**,
    /// and the whole of what was narrowed on 20 Sep 2026. Case (b) is a member of
    /// a NON-SOLID volume set larger than one window, and it has two:
    ///
    /// 1. **Held whole, the DEFAULT**, which this answering `None`
    ///    selects. The member keeps `Run::compress`'s one-region
    ///    shortcut and the minimum-width packed size vint of 3.5 rule 2,
    ///    and its bytes are the bytes this writer wrote before the
    ///    exception existed. It has the lowest wall, and "otherwise,
    ///    use as much as we need to" is why it is the default.
    /// 2. **Streamed**, which this answering `Some` selects where the
    ///    output can also take the correction. The member goes out as
    ///    the encoder produces it, at the reserved width, and the
    ///    shortcut stands aside, because a caller who named a hard
    ///    ceiling has asked for memory over wall.
    ///
    /// **A ceiling that cannot be kept is not an error** (decided 20
    /// Sep 2026; the principle is that a job reference `rar` and
    /// `unrar` would complete is not one this engine fails on a policy of
    /// its own). Where this answers
    /// `Some` but the member cannot stream anyway - the output cannot
    /// patch, the member is encrypted, the reservation would not cover
    /// the volume's cap - `Run::streams_packed` answers false, the member
    /// is held whole in mode 1 with mode 1's bytes, the archive is
    /// finished and valid, and `WriteReport::ceiling_exceeded_by` carries
    /// the excess.
    ///
    /// A SOLID member is not case (b) at all: the writer reserves and
    /// streams it whatever the policy says, and both callers check
    /// `solid` before they reach here.
    pub(super) fn over_ceiling(&self, index: usize) -> Option<u64> {
        let ceiling = self.caller_ceiling()?;
        let over = self.held_whole_bytes(index).saturating_sub(ceiling);
        (over > 0).then_some(over)
    }
}
