//! The tape's width: how many lanes decode a member's blocks, the rule a
//! host takes, the gate that moves it, and what a working limit leaves.

use super::*;

/// How many workers this member gets, or zero for the serial path.
///
/// The carried policy asks the host how many cores it has, which is a
/// system call; section 7.3 item 9 keeps those off the decode path, so the
/// host is asked once for the process and the member loop only compares
/// numbers. The size floor and the worker ceiling are both carried.
///
/// **The host's figure depends on whether the caller STATED the width.**
/// A stated width (`ReadOptions::workers`, `-mt<n>`) meets the carried
/// figure, the hardware threads less one, exactly as it always did. The
/// engine's own default counts PHYSICAL cores instead ([`physical_host`]):
/// the apply stage is serial (SPEC-H2 3.8), so the member's wall is one
/// thread's, and a lane scheduled on that thread's SMT sibling takes the
/// core's execution units from it. On a machine without SMT the two figures
/// are the same number and nothing changes.
// `MT_MIN_OUTPUT` is deliberately zero under `cfg(test)`, so the suite
// forces every decode down the tape path; the comparison is then trivially
// false, which is correct and not a mistake.
#[allow(clippy::absurd_extreme_comparisons)]
pub(crate) fn workers(unpacked: u64, policy_max: usize, stated: bool) -> usize {
    static STATED: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    static DEFAULT: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let size = usize::try_from(unpacked).unwrap_or(usize::MAX);
    if size < MT_MIN_OUTPUT {
        return 0;
    }
    let host = if stated {
        *STATED.get_or_init(|| host_knob().unwrap_or_else(|| mt_worker_count(usize::MAX)))
    } else {
        *DEFAULT.get_or_init(|| host_knob().unwrap_or_else(physical_host))
    };
    host.min(policy_max)
}

/// The host's lane figure counted in PHYSICAL cores: one lane a core less
/// the core the apply stage runs on, at most `MT_MAX_WORKERS`.
pub(super) fn physical_host() -> usize {
    crate::cores::physical()
        .saturating_sub(1)
        .min(MT_MAX_WORKERS)
}

/// THE FEWEST LANES THE DEFAULT WIDTH FALLS TO ([`Width`]). It
/// OPENS at its ceiling, the physical cores less one, and falls from
/// there, a lane a chunk, while the apply stage never waits.
///
/// **Why it falls, measured**
/// (30 Sep 2026). The apply stage is the
/// member's wall (SPEC-H2 3.8) and a lane past the few that keep it fed
/// makes it SLOWER, not idle: on a quiet 8 core Zen 4 its own cycles rose
/// by about a third from four lanes to eight, cache misses rose with the
/// lanes, and the clock did not move, so a lone 1 GiB `-m3` member read
/// 0.650 s at two lanes against 0.730 at eight. The same held with the machine
/// pinned to one thread a core, so it is not the SMT pair alone.
///
/// **It falls like this only on a machine under its system's line**
/// ([`SYSTEM_LINE`]: 18 physical cores on Apple silicon, 48 on x86-64
/// Linux). From there up Apple silicon holds the width at its ceiling and
/// x86-64 Linux gates the fall ([`default_rule`], [`WidthRule`]). A system
/// with no line falls at any core count, as before.
///
/// **Why it OPENS wide, also measured.** A width that opened here and grew
/// a lane a chunk lost the class legs of one 32 to 64 MiB member to the
/// old default on a 32 core M3 Ultra: `rar5_incompressible_64m` 0.384x,
/// `rar5_text_64m_m3` 0.778x. A member of a few chunks never reached the
/// width its decode needed, and a decode-bound member (incompressible, a
/// small dictionary) starved its apply. And a FIXED narrow width loses 1.3
/// to 1.6 times on a machine full of other work. So the default starts
/// where the old one did, less the SMT siblings, and gives lanes back only
/// once the apply has shown, chunk after chunk, that it does not need them.
pub(crate) const LEAST_LANES: usize = 2;

/// The default width grows by a lane when MORE than one unit in this many
/// found its lane not done ([`Width`]).
pub(super) const GROW_EVERY: usize = 8;

/// THE FEWEST PHYSICAL CORES AT WHICH THE DEFAULT WIDTH STAYS AT ITS
/// CEILING and does not move ([`Width`]), ON APPLE SILICON: twice the lanes
/// and the apply, so every lane and the apply thread can have a core with
/// as many again left over. Below a system's line ([`SYSTEM_LINE`]), and on
/// a system with no line at any core count, the width falls and grows
/// exactly as before.
///
/// **Why the fall is not for every machine, measured**
/// (1 Oct 2026). Binary data needs its
/// lanes in some stretches of an archive and not in others; the moving
/// width gives lanes back in the calm stretches, and the wall is lost in
/// the chunks it then runs narrow. Held at eight lanes against moving:
/// a 32 core M3 Ultra read one 4 GiB binary member 1.030x to 1.044x, a
/// solid binary archive 1.022x to 1.056x and a 1 GiB text member 1.016x
/// and 1.094x (K=5, for 1 to 3 percent more CPU); a 20 core M1 Ultra read
/// 0.999x to 1.049x on every row; an 18 core laptop 1.023x to 1.099x.
///
/// **What was tried in its place and did not recover it** on that M3
/// Ultra: a grow bound of one unit in 16, 32 or 64 instead of one in
/// eight (0.999x to 1.019x), and a ceiling of 12 or 16 lanes, moving
/// (1.000x to 1.018x) or held (1.003x to 1.048x, under eight held). The
/// apply's waits fell with every one of them and the wall did not follow,
/// so the waits are what the width MOVES on and not a measure of what a
/// width costs.
pub(crate) const STEADY_CORES: usize = 2 * (MT_MAX_WORKERS + 1);

/// THE FEWEST PHYSICAL CORES AT WHICH x86-64 LINUX LEAVES THE MOVING WIDTH:
/// the smaller of the two machines it has rows on (a 48 core Xeon, a 96
/// core Zen 5). Under it, and on Windows at any core count, the width
/// moves as before: 9 to 47 cores have no row and so no rule, and on an 8
/// core Zen 4 binary data gained nothing from more lanes.
pub(crate) const STEADY_CORES_X86_LINUX: usize = 48;

/// What the default width does on a machine ([`default_rule`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WidthRule {
    /// Falls a lane after a calm chunk and grows on the apply's waits: the
    /// rule every machine had, and every machine under its line has.
    Moves,
    /// Stays at its ceiling, as a stated width does.
    Holds,
    /// Stays at its ceiling until [`GATE_CALM`] chunks in a row are calm,
    /// then falls a lane a calm chunk; goes back to the ceiling at once
    /// when the apply waits on more than one unit in [`GATE_JUMP`], and a
    /// lane back, below the ceiling, on more than one in [`GATE_BACK`].
    Gated,
}

/// THE RULE ON WIDE x86-64 LINUX, AND IT IS ONE CONSTANT: `Gated` as
/// landed; `Holds` is the ungated hold, `Moves` the rule before this.
///
/// **Why a gate, measured**
/// (1 Oct 2026; a 96 core Zen 5, quiet,
/// against the moving width). On x86-64 the two shapes pull apart, as they
/// do not on Apple silicon: HELD, one large binary member read 1.060x to
/// 1.073x, a solid binary archive 1.062x to 1.066x and many members
/// 1.037x, and a 1 GiB text member 0.927x to 0.943x (a 48 core Xeon: 1.034x
/// to 1.054x, 1.004x to 1.013x, and text 0.953x). GATED (K=3), the large
/// member keeps 1.052x, text comes back to 0.983x and 0.995x, and the solid
/// archive keeps 1.031x. The large member is the shape this engine is for,
/// so the gate lands: it gives up half the solid archive's gain to give
/// the text member back all but 2 percent.
///
/// **What the gate reads**: nothing but the apply's own waits. A text
/// member never makes the apply wait at any width, so a run of calm chunks
/// at the ceiling is the sign of it; binary data has calm stretches too,
/// which is why the fall waits for a run and why a real wait sends the
/// width straight back up instead of a lane a chunk.
pub(super) const WIDE_X86_LINUX_RULE: WidthRule = WidthRule::Gated;

/// The calm chunks in a row a [`WidthRule::Gated`] width waits for at its
/// ceiling before its first fall (6, 12 and 16 were screened beside it).
pub(super) const GATE_CALM: u32 = 8;

/// A [`WidthRule::Gated`] width goes back to its ceiling when the apply
/// waited on more than one unit in this many (any grow, and one in 6, were
/// screened beside it: both cost the text member more).
pub(super) const GATE_JUMP: usize = 4;

/// A [`WidthRule::Gated`] width BELOW its ceiling takes one lane back when
/// the apply waited on more than one unit in this many, a wait too light
/// to be a grow ([`GROW_EVERY`]).
///
/// **Why, measured**
/// (3 Oct 2026; a 48 core Xeon,
/// quiet). Without it a light wait only started the calm
/// run again, so the fall stopped wherever the first light wait met it
/// and the width stayed there for the rest of the member: a media-like 4
/// GiB member settled at 6, 7 or 8 lanes from run to run and read 2.39 s
/// at the median where the width held at its ceiling read 2.32 (held at
/// 7, 6 and 5 lanes: 2.40, 2.47, 2.57). One lane under the ceiling that
/// member's apply waits in 95 chunks in 100, on 3.8 units in 100; a text
/// member at its floor of two lanes waits in 13 chunks in 100, on 0.3
/// units in 100, and almost never on more than two units of a chunk. So
/// one unit in 32 takes that member back to its ceiling within a chunk or
/// two and leaves the text member at its floor (bounds of 24 and 16 read
/// the same; any wait at all put text at three lanes).
pub(super) const GATE_BACK: usize = 32;

/// This build's system: the physical cores from which it leaves the moving
/// width, and what it does from there; `None` for a system with no row
/// behind such a line ([`STEADY_CORES`], [`STEADY_CORES_X86_LINUX`]).
pub(super) const SYSTEM_LINE: Option<(usize, WidthRule)> =
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some((STEADY_CORES, WidthRule::Holds))
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some((STEADY_CORES_X86_LINUX, WIDE_X86_LINUX_RULE))
    } else {
        None
    };

/// The default width's rule on a machine with `cores` physical cores, of a
/// system with this `line`.
pub(super) const fn rule_on(cores: usize, line: Option<(usize, WidthRule)>) -> WidthRule {
    match line {
        Some((from, rule)) if cores >= from => rule,
        _ => WidthRule::Moves,
    }
}

/// What the default width does on THIS machine: its system's rule from its
/// line up ([`SYSTEM_LINE`]) and [`WidthRule::Moves`] under it or with no
/// line, unless a bench knob fixed the host figure ([`TAPE_HOST_ENV`]),
/// whose widths are the figure itself, or named the answer
/// ([`TAPE_MOVES_ENV`]). A property of the machine and never of the
/// archive, and it moves no byte of output: a width decides which thread
/// decodes a block, not what the block decodes to.
pub(crate) fn default_rule() -> WidthRule {
    static RULE: std::sync::OnceLock<WidthRule> = std::sync::OnceLock::new();
    if host_knob().is_some() {
        return WidthRule::Holds;
    }
    *RULE.get_or_init(|| match count_knob(TAPE_MOVES_ENV) {
        Some(0) => WidthRule::Holds,
        Some(1) => WidthRule::Moves,
        Some(_) => WidthRule::Gated,
        None => rule_on(crate::cores::physical(), SYSTEM_LINE),
    })
}

/// A decoder's default width: `None` where it holds at its ceiling.
pub(crate) fn default_width() -> Option<Width> {
    match default_rule() {
        WidthRule::Holds => None,
        WidthRule::Moves => Some(Width::open()),
        WidthRule::Gated => Some(Width::open_gated()),
    }
}

/// COUNT KNOB:
/// `1` makes the default width move on any machine (the old path), `0`
/// holds it at its ceiling and `2` gates it, so one binary carries every
/// arm of the rule on one machine. Nothing ships setting it.
pub(crate) const TAPE_MOVES_ENV: &str = "RARKIT_TAPE_MOVES";

/// The most calm chunks a fall may be made to wait for ([`Width`]).
pub(super) const PATIENCE_MAX: u32 = 64;

/// THE DEFAULT WIDTH of one decoder: its lanes for the next chunk, and
/// how long it waits before giving one back.
///
/// **Why a fall has to earn its keep, measured.** A rule that fell a lane
/// on any chunk with no wait flipped for the whole of a 1 GiB member
/// between three lanes, where the apply almost never waited (7 units in
/// 1,000), and two, where it waited on half its units, on a 16 core EPYC
/// 9R14: half the chunks paid the starved width and the member read 1.070
/// s against 0.921 at a fixed four. So a fall that is followed by a grow
/// (a BOUNCE) doubles the calm chunks the next fall needs, up to
/// [`PATIENCE_MAX`]. A machine whose floor is enough (the quiet Zen 4, where
/// two lanes waited on 14 units in 1,000) never bounces and falls a lane
/// a chunk from the ceiling to it; a machine that bounces settles above.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Width {
    /// The target, `usize::MAX` until a chunk has run (read as the ceiling).
    pub(super) now: usize,
    /// The calm chunks in a row a fall needs.
    pub(super) patience: u32,
    /// The calm chunks in a row so far.
    pub(super) calm: u32,
    /// Whether the last move was a fall, so a grow after it is a bounce.
    pub(super) fell: bool,
    /// Whether this is a [`WidthRule::Gated`] width.
    pub(super) gated: bool,
}

impl Width {
    /// A decoder's first width: the ceiling, falling after one calm chunk.
    pub(crate) const fn open() -> Width {
        Width {
            now: usize::MAX,
            patience: 1,
            calm: 0,
            fell: false,
            gated: false,
        }
    }

    /// A [`WidthRule::Gated`] decoder's first width: the ceiling, falling
    /// only after [`GATE_CALM`] calm chunks in a row.
    pub(crate) const fn open_gated() -> Width {
        Width {
            now: usize::MAX,
            patience: GATE_CALM,
            calm: 0,
            fell: false,
            gated: true,
        }
    }

    /// The lanes the next chunk may open under a ceiling of `most`.
    pub(crate) fn lanes(&self, most: usize) -> usize {
        self.now.min(most.max(1))
    }

    /// Move the target on one chunk's count: it ran `lanes`, the apply
    /// found `waited` of `counted` units not done, under a ceiling of
    /// `most` (the physical cores less one, a budget, `MT_MAX_WORKERS`).
    /// GROWS a lane when the apply waited on more than one unit in
    /// [`GROW_EVERY`] and the chunk ran the whole target (a chunk held
    /// narrow by its own size or by the budget says nothing about the
    /// target); FALLS a lane after `patience` chunks in a row with no wait
    /// at all; holds otherwise. Never below [`LEAST_LANES`] (or `most`
    /// where that is lower), never above `most`. A GATED width differs in
    /// three things: a grow goes to `most` at once when the apply waited on
    /// more than one unit in [`GATE_JUMP`], a calm run that has earned
    /// its first fall keeps falling a lane a calm chunk, and below `most`
    /// a wait on more than one unit in [`GATE_BACK`] takes a lane back.
    #[cfg(test)]
    pub(crate) fn after_chunk(&mut self, lanes: usize, waited: usize, counted: usize, most: usize) {
        self.after_chunk_beside(lanes, waited, counted, most, 1);
    }

    /// [`Width::after_chunk`] for a member decoded with `members` of them
    /// in flight, itself among them. The lane back of [`GATE_BACK`] is for
    /// a member decoded ALONE: with two or more abreast a gated width does
    /// what it did before that rule, because members decoded at once read
    /// faster with fewer lanes each (eight 512 MiB members on 48 cores:
    /// 0.965x and 0.992x with the lane back, K=9).
    pub(crate) fn after_chunk_beside(
        &mut self,
        lanes: usize,
        waited: usize,
        counted: usize,
        most: usize,
        members: usize,
    ) {
        let most = most.max(1);
        let floor = LEAST_LANES.min(most);
        let now = self.now.min(most);
        if counted == 0 {
            return;
        }
        if waited * GROW_EVERY > counted && lanes >= now {
            if self.fell {
                self.patience = (self.patience * 2).min(PATIENCE_MAX);
            }
            self.now = if self.gated && waited * GATE_JUMP > counted {
                most
            } else {
                (now + 1).min(most)
            };
            self.calm = 0;
            self.fell = false;
        } else if waited == 0 {
            self.calm += 1;
            self.now = now;
            if self.calm >= self.patience && now > floor {
                self.now = now - 1;
                if !self.gated {
                    self.calm = 0;
                }
                self.fell = true;
            }
        } else if self.gated
            && members <= 1
            && now < most
            && lanes >= now
            && waited * GATE_BACK > counted
        {
            // A gated width below its ceiling takes a lane back on a wait
            // too light to be a grow ([`GATE_BACK`]). Not a bounce: the
            // next fall waits no longer for it.
            self.now = now + 1;
            self.calm = 0;
            self.fell = false;
        } else {
            self.now = now;
            self.calm = 0;
            self.fell = false;
        }
    }
}

/// [`TAPE_HOST_ENV`] as a host figure: `logical` is the carried figure
/// (the default before physical cores were counted, the control arm),
/// `physical` is [`physical_host`], and a number is itself. Anything else,
/// `grow` by convention (`gate.py --knob RARKIT_TAPE_HOST=logical:grow`
/// wants two named values), is no figure at all: the shipped default.
pub(super) fn host_knob() -> Option<usize> {
    static KNOB: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *KNOB.get_or_init(|| {
        match crate::knob::reader_var(TAPE_HOST_ENV)
            .ok()
            .as_deref()
            .map(str::trim)
        {
            Some("logical") => Some(mt_worker_count(usize::MAX)),
            Some("physical") => Some(physical_host()),
            _ => count_knob(TAPE_HOST_ENV),
        }
    })
}

/// BENCH KNOB:
/// replaces the host's lane figure in [`workers`] for a stated width and
/// the default alike ([`host_knob`] reads it), so a timed run can hold the
/// pool and the decode-ahead where they are and move only the tape's
/// lanes, and `logical` is the old default in the same binary. Nothing
/// ships setting it.
pub(crate) const TAPE_HOST_ENV: &str = "RARKIT_TAPE_HOST";

/// COUNT KNOB: replaces [`RESOLVE_MIN_LANES`], so a timed run can take the
/// repeat pass off a width that would have it, or put it on one that would
/// not. Nothing ships setting it.
pub(crate) const RESOLVE_MIN_LANES_ENV: &str = "RARKIT_RESOLVE_MIN_LANES";

/// The fewest lanes the repeat pass needs, from [`RESOLVE_MIN_LANES_ENV`]
/// or [`RESOLVE_MIN_LANES`].
pub(crate) fn resolve_min_lanes() -> usize {
    static MIN: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *MIN.get_or_init(|| count_knob(RESOLVE_MIN_LANES_ENV).unwrap_or(RESOLVE_MIN_LANES))
}

/// COUNT KNOB: `RARKIT_TAPE_TRACE=1` prints each piped chunk's lanes and
/// the apply stage's waits to stderr, so a timed run can read the wait rate
/// a width gives on its machine. Nothing ships setting it.
pub(crate) const TAPE_TRACE_ENV: &str = "RARKIT_TAPE_TRACE";

/// Whether [`TAPE_TRACE_ENV`] is on.
pub(crate) fn trace() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| crate::knob::reader_var(TAPE_TRACE_ENV).is_ok_and(|v| v.trim() == "1"))
}

pub(super) fn count_knob(name: &str) -> Option<usize> {
    crate::knob::reader_var(name)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
}

/// The most this stage may RETAIN per lane between blocks, in bytes.
///
/// `member_piped`'s own bound, stated in its doc comment and enforced by
/// the channel of one it hands tapes down: lane `k` holds at most the tape
/// it is filling and the tape it has handed over, so `2 * lanes` tapes are
/// alive, inside API 8.2's `4 * W`. A tape survives into the next block
/// only if `BlockTape::worth_recycling` says so, and that is the carried
/// `TAPE_RECYCLE_BYTES_MAX` on the literal buffer and the same figure on
/// the operation buffer. Two buffers at that bound, two tapes per lane.
///
/// A tape can exceed this WHILE a hostile block is being decoded, up to
/// `TAPE_OPS_CAP` and `TAPE_LITS_CAP`, at which point the lane parks the
/// block and the serial path finishes it (spec H2 section 4.2). That is a
/// transient the park bound already governs and it is not what a width is
/// priced against: this is the steady state, which is the term that grows
/// with the lanes.
#[cfg(feature = "parallel")]
pub(crate) const TAPE_BYTES_PER_LANE: u64 = 2 * 2 * TAPE_RECYCLE_BYTES_MAX as u64;

/// Bytes CHARGED per packed byte of a tape unit a lane holds: every RAR 5
/// symbol takes at least one bit, so a packed byte decodes to at most eight
/// literal bytes and eight operations of eight bytes each.
#[cfg(feature = "parallel")]
pub(crate) const UNIT_CHARGE_PER_PACKED_BYTE: u64 = 8 * (1 + std::mem::size_of::<TapeOp>() as u64);

/// The units one lane may hold at once: the one it decodes, the one queued
/// in its channel and the one the apply stage holds (`member_piped`).
#[cfg(feature = "parallel")]
pub(crate) const UNITS_IN_FLIGHT_PER_LANE: u64 = 3;

/// The packed bytes a tape unit may span at `lanes` lanes inside
/// `working_limit`, CHARGED as admission charges the per-block form.
///
/// Each lane is already priced at [`TAPE_BYTES_PER_LANE`] for the two tapes
/// it keeps from its pool, which may hold the capacity of earlier big
/// blocks. A unit adds its own tapes on top, three units a lane in flight,
/// each charged at its worst case ([`UNIT_CHARGE_PER_PACKED_BYTE`] per
/// packed byte). So a lane's share of the limit, less that, bounds what a
/// unit may span, and the unit SHRINKS to fit; when nothing is left the
/// answer is 0 and the chain decodes one block a unit, which is the
/// per-block form exactly. At the default 512 MiB this allows the full
/// 64 KiB unit up to 17 lanes, about 46 KiB at 20 and none at 32; a stated
/// `-mm` lowers it further (SPEC-API 8.2).
#[cfg(feature = "parallel")]
pub(crate) fn unit_bytes_within_budget(working_limit: u64, lanes: usize) -> usize {
    let per_lane = working_limit / lanes.max(1) as u64;
    let spare = per_lane.saturating_sub(TAPE_BYTES_PER_LANE);
    usize::try_from(spare / (UNITS_IN_FLIGHT_PER_LANE * UNIT_CHARGE_PER_PACKED_BYTE))
        .unwrap_or(usize::MAX)
}

/// Whether a member of `unpacked` bytes is shared out across lanes at all,
/// whatever the budget: under the size floor it is decoded on one thread.
// `MT_MIN_OUTPUT` is zero under `cfg(test)`, as `workers` says above.
#[allow(clippy::absurd_extreme_comparisons)]
pub(crate) fn shared_out(unpacked: u64) -> bool {
    usize::try_from(unpacked).unwrap_or(usize::MAX) >= MT_MIN_OUTPUT
}

/// The lanes one member's tape decode may open inside `working_limit`.
///
/// API 8.4.1 keeps `MemoryPolicy::working_limit` a HARD ceiling and says
/// the engine lowers the members in flight, and then the width inside
/// them, until the sum fits. The members in flight are lowered by the
/// terms section 5.2 counts and charges - one window per member, the
/// read-ahead, the member tables - and this is the other half: the tape
/// buffers, which are the only term that grows with the WIDTH.
///
/// It is priced against the whole budget rather than against what the
/// windows leave, and that is deliberate. API 8.4.4 test 2 requires the
/// reported peak to be FLAT in the width at a fixed breadth, so the tape
/// buffers are deliberately not charged into `memory::current`; composing
/// them with the charged terms here would price the width twice, once
/// through this and once through the members in flight the charged terms
/// have already lowered.
///
/// At the default 512 MiB budget this is 32 lanes, which is the top of
/// 8.4.3's own ladder and therefore does not bind on any shape that
/// ladder measures. A caller who asks for 64 MiB gets 4, which is the
/// direction 8.4.1 requires: a budget that genuinely binds narrows the
/// width, and running narrower is never an error (8.2).
#[cfg(feature = "parallel")]
pub(crate) fn lanes_within_budget(working_limit: u64) -> usize {
    usize::try_from(working_limit / TAPE_BYTES_PER_LANE)
        .unwrap_or(usize::MAX)
        .max(1)
}
