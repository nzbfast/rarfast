//! The segment team: a member longer than one stretch of its streamed
//! encode cut into stretches, each on an engine of its own, and the windows
//! read ahead of a member's one engine.

use super::*;

/// The most engines the segment team runs at `level` on `cores` physical
/// cores of the pool; one is no team.
///
/// **Measured, not reasoned** (the width sweep;
/// decided 1 Oct 2026).
/// Several engines each keep their own heads, links and history hot
/// where the one engine's threads shared one set, so on few cores the
/// team costs more cache than it frees serial work: on eight cores it was
/// never faster at levels 2 and 3 (down to 0.63x of the one engine) and
/// at level 1 only where four engines stood for eight cores. So:
///
/// - **level 1** from [`SEGMENT_CORES_LEAST`]`[0]` cores, the level whose
///   wall is its serial linking pass: 1.4x on sixteen cores of an M5
///   Ultra, 2.2x on sixteen of an EPYC 9R14, 4.2x on forty-eight;
/// - **levels 2 and 3** from [`SEGMENT_CORES_LEAST`]`[1]` cores: on
///   sixteen the gain was thin where it was one (1.04x and 1.13x on the
///   M5 Ultra, 1.22x on the EPYC) and no sixteen-core machine of two
///   memory channels was swept, which is the machine it would most
///   likely lose on; from thirty-two the wins are clear (1.7x to 2.3x).
///   Twenty, lowered from thirty-two on 18 Oct 2026: on the twenty cores
///   of an M1 Ultra (16 performance and 4 efficiency) 1 GiB of a big member at
///   `-m3` took 2.70 s on one engine and 1.67, 1.61, 1.60 and 1.66 s on
///   teams of 4, 6, 8 and 10 engines, the same archive at every width,
///   about 455 MiB an engine (a count, one binary for every width). Sixteen
///   stays under the bar, for the reason above;
/// - one engine to [`SEGMENT_CORES_AN_ENGINE`] cores, and never more than
///   [`SEGMENT_ENGINES_MOST`]: the engine count that was fastest, or
///   within its null of the fastest, on every box.
///
/// The thresholds move on a sixteen-core two-channel desktop's row, which
/// is not measured yet.
#[cfg(feature = "parallel")]
pub(super) fn segment_engines(level: u8, cores: usize) -> usize {
    let least = match level {
        1 => SEGMENT_CORES_LEAST[0],
        2 | 3 => SEGMENT_CORES_LEAST[1],
        // A member that walks the chains at levels 4 and 5 (the caller's
        // test): levels 2 and 3's row. On 96 cores of an EPYC 9R45 a 4 GiB
        // binary member at level 5 went 20.3 s to 9.9 on 32 threads and to
        // 6.9 at the default width; a forced team gained on 16 threads too
        // (1.21x to 1.45x), which a machine of 16 cores and two memory
        // channels has yet to confirm
        // (measured 2 Oct 2026).
        4 | 5 => SEGMENT_CORES_LEAST[1],
        _ => return 1,
    };
    if cores < least {
        1
    } else {
        (cores / SEGMENT_CORES_AN_ENGINE).clamp(1, SEGMENT_ENGINES_MOST)
    }
}

/// Whether a member of FEWER stretches than the rule's engines takes the
/// segment team above level 1 (`Run::segment_width`): `stretches` of
/// the member, `blocks` of one window, `pool` threads, and a team of
/// `afforded` engines (the stretches themselves before the memory is
/// asked, the afforded width after).
///
/// Two things, both counted on a quiet 64-core box at 64 and at 36
/// threads (measured 2 Oct 2026):
///
/// - **the member's windows must be able to fill the pool**: stretches
///   times the blocks of a window at least the pool's threads. An engine
///   beside the run's own parses one window at a time, so four stretches
///   of 2 MiB windows are 32 blocks in flight where the one engine's wave
///   keeps a 36 or 64 thread pool busy: a 64 MiB member there is the one
///   engine's (the team was 0.76x on a 64 MiB text member at level 3),
///   and a 128 MiB member's eight stretches are the team's (1.36x to
///   1.70x);
/// - **the team as afforded is no smaller than its window asks**
///   ([`segment_few_engines_least`]): under a working limit, or on a
///   member of four to seven stretches, a team of a few engines of
///   narrow windows is slower than the one engine.
#[cfg(feature = "parallel")]
pub(super) fn few_stretches_take_the_team(
    level: u8,
    stretches: usize,
    blocks: usize,
    pool: usize,
    afforded: usize,
) -> bool {
    stretches.saturating_mul(blocks) >= pool && afforded >= segment_few_engines_least(level, blocks)
}

/// The fewest engines a team of a member of few stretches runs on, by
/// the blocks of its window ([`few_stretches_take_the_team`]): four at
/// 2 MiB windows, three at 4 MiB, two at 8 MiB, and none under 2 MiB.
///
/// **Measured** with the engine count forced, on members of 256 and 512
/// MiB at level 3, the same on 64 and 36 threads of a Graviton3 box and
/// on 96 threads of a quiet Sapphire Rapids box
/// (2 Oct 2026, the `few` rows), the one
/// engine's wall over the team's: at 2 MiB windows two engines 0.73x to
/// 0.79x, three 0.92x to 1.08x, four 1.07x to 1.16x; at 4 MiB two 0.95x
/// to 1.00x, three 1.04x to 1.15x; at 8 MiB two 1.06x to 1.25x. It is a
/// count of engines and not of blocks in flight, and not of the pool's
/// width: four engines of 2 MiB windows and two of 4 MiB both hold 32,
/// and the first gains where the second loses, on 36, 64 and 96 threads
/// alike. A window under 2 MiB has no row, so there the member of few
/// stretches stays the one engine's, as it was before this bar.
///
/// At levels 4 and 5, where a member that walks the chains takes the
/// team, the same sweep reads one engine more at 2 MiB windows: on 64
/// and 36 threads of the Graviton3 box four engines 0.91x to 0.96x and
/// five 1.01x to 1.08x (on 96 threads of the x86-64 box four 0.98x to
/// 1.08x, five 1.08x to 1.18x); three at 4 MiB 1.03x to 1.13x and two
/// at 8 MiB 1.11x to 1.29x as at level 3.
/// (`segment_team` holds a team of those levels to four engines or
/// none, whatever its window: that floor is its own and is asked after
/// this one.)
#[cfg(feature = "parallel")]
pub(super) const fn segment_few_engines_least(level: u8, blocks: usize) -> usize {
    match blocks {
        0..=7 => usize::MAX,
        8..=15 if level > 3 => 5,
        8..=15 => 4,
        16..=31 => 3,
        _ => 2,
    }
}

/// The fewest physical cores of the pool the segment team runs on, at
/// level 1 and at levels 2 to 5 (`segment_engines`).
#[cfg(feature = "parallel")]
pub(super) const SEGMENT_CORES_LEAST: [usize; 2] = [16, 20];

/// The cores of the pool an engine of the segment team stands for.
#[cfg(feature = "parallel")]
pub(super) const SEGMENT_CORES_AN_ENGINE: usize = 2;

/// The most engines the segment team runs, however wide the pool: no row
/// gained past it. On 48 cores of an EPYC 9R14, 24 engines were at or
/// within their null of the fastest count at levels 1 and 3 and 48 were
/// slower at level 1 (4.14x against 3.77x); on 36 cores of an M5 Ultra 16
/// were as fast as 36; and at the default width of 192 cores, 96 engines
/// took 7.7 s and 14.7 GiB where 24 at `-mt48` took 5.8 s and 4.3 GiB
/// (measured 1 Oct 2026).
#[cfg(feature = "parallel")]
pub(super) const SEGMENT_ENGINES_MOST: usize = 24;

/// The fewest engines the segment team runs at levels 4 and 5: a team the
/// memory left holds under it is the one engine's walk instead
/// (`Run::segment_width`).
///
/// **Measured** (a Zen 5 rental, 2 Oct 2026, hold 2,
/// one 4 GiB binary member at `-m5`, the default width of 96 cores, the
/// engine count forced): the one engine 20.2 s; two engines 27.3 s, four
/// 17.5, eight 11.0, twenty-four 6.8. An engine beside the run's own
/// parses one window at a time, so two or three of them keep fewer
/// threads busy than the one engine's wave (9.6 against 12.9), and under
/// a named `-mm512m` or `-mm1g`, which afford three, the team was 0.98x.
/// Four is the first count that gains (1.16x).
#[cfg(feature = "parallel")]
pub(super) const SEGMENT_TREE_ENGINES_LEAST: usize = 4;

/// The fewest engines the WORKING LIMIT must afford the segment team at
/// levels 2 and 3 for a window of `blocks` parse blocks: under it the
/// member is the one engine's walk (`Run::segment_width`). Three, or two
/// at a window of 8 MiB and more. Level 1 keeps every engine it is
/// afforded, since there each one gains.
///
/// **Measured, a member of MANY stretches at 2 MiB windows**
/// (2 Oct 2026; a 96 thread
/// Xeon 8488C, one 4 GiB binary member, no cap, the engine count forced,
/// two reps; wall s and process MiB):
///
/// | engines | `-m2` | `-m3` | `-m1` |
/// |---|---|---|---|
/// | 1 | 19.1, 18.5 at 224 | 20.3, 21.2 at 251 | 11.8, 12.4 at 170 |
/// | 2 | 22.8, 23.0 at 356 | 26.8, 27.3 at 372 | 7.4, 7.4 at 403 |
/// | 3 | 17.7, 17.9 at 468 | 20.8, 20.9 at 491 | 5.4, 5.4 at 562 |
/// | 4 | 15.5, 15.6 at 570 | 18.0, 18.4 at 588 | 4.4, 4.7 at 720 |
///
/// An engine beside the run's own parses one window at a time, so the
/// second engine takes the pool's wave from the first and gives less
/// back; the third makes it up at level 2 (1.06x of one) and at level 3
/// draws level with it.
///
/// **By the window**, as the bar for a member of few stretches reads it
/// ([`segment_few_engines_least`], whose sweep found two engines 0.73x to
/// 0.79x of one at 2 MiB windows, 0.95x to 1.00x at 4 MiB, and 1.06x to
/// 1.25x at 8 MiB): where that bar asks two, two are kept here too. Where
/// it asks four (2 MiB), three are kept here: a member of many stretches
/// gains with three at level 2 and loses nothing at level 3, and the earlier
/// code ran three there.
///
/// It reads what the MEMORY affords and nothing else: a team that the
/// pool, the member's stretches or the rule by cores holds under it is
/// that bar's to judge.
#[cfg(feature = "parallel")]
pub(crate) const fn segment_afforded_least(level: u8, blocks: usize) -> usize {
    let few = segment_few_engines_least(level, blocks);
    if few < SEGMENT_CHAIN_ENGINES_LEAST {
        few
    } else {
        SEGMENT_CHAIN_ENGINES_LEAST
    }
}

/// The most [`segment_afforded_least`] asks.
#[cfg(feature = "parallel")]
pub(super) const SEGMENT_CHAIN_ENGINES_LEAST: usize = 3;

/// The segment team's width at `level` from its four bounds: the pool's
/// width, the member's stretches, the engines the working limit affords
/// and the engines the rule by cores gives. At levels 4 and 5 a team held
/// under [`SEGMENT_TREE_ENGINES_LEAST`] is the one engine's walk.
#[cfg(feature = "parallel")]
pub(crate) fn segment_team(
    level: u8,
    pool: usize,
    stretches: usize,
    afford: usize,
    engines: usize,
) -> usize {
    let team = pool.min(stretches).min(afford).min(engines).max(1);
    if level > 3 && team < SEGMENT_TREE_ENGINES_LEAST {
        1
    } else {
        team
    }
}

/// One STRETCH of a streamed member handed to one engine of the segment
/// team: where the kept dictionary ends in its input buffer, the member
/// offset of its first byte, and whether the member ends with it.
#[derive(Clone, Copy)]
pub(super) struct Stretch {
    pub(super) kept: usize,
    pub(super) base: u64,
    pub(super) last: bool,
    /// The effort the member is encoded by, read off its head by the run's
    /// own encoder (`Encoder::member_effort`), for a stretch of a member of
    /// several; none for a whole member, whose engine reads the head
    /// itself.
    pub(super) effort: Option<crate::encode::drive::Plan>,
}

/// The SEGMENT TEAM: several engines for ONE member longer than a stretch
/// (built to answer a
/// question of 1 Oct 2026: "if you have more than 8 cores, is there even
/// faster we can go with more cores thrown at the problem?").
///
/// **What was serial.** A member longer than one window is encoded a
/// window at a time by ONE engine: the read, the chains' insert pass on
/// one thread, the parses across the pool, the append. At level 1 the
/// insert pass and the read are about a fifth of the CPU, so a member of
/// any length kept four to five cores busy at any width: counted on a 192
/// core box, the single 4 GiB file took 13.4 s at `-mt8` and 19.4 s at
/// `-mt48` (measured 1 Oct 2026).
///
/// **What the team is.** The one engine's history slides every slack's
/// worth of input, and what it writes between two slides is a function of
/// the dictionary the first slide kept and of the bytes since
/// (`Engine::resume_slid`). So the member is a row of STRETCHES, each
/// from one slide to the next, and a stretch goes to an engine of its own,
/// resumed from the dictionary before it. The writing thread reads the
/// stretches in order, checksums them in order, hands each to an engine,
/// and appends their packed bytes in order.
///
/// **Why it moves no byte.** Each engine is handed the windows the one
/// engine staged, in the order it staged them, from the history it held
/// when it staged the first: the batches, the flushes and the slides fall
/// where they fell (`stage_window`), so each stretch's packed bytes are
/// the ones the one engine appended there. How many engines run is a
/// width, chosen from the pool and from the memory left
/// (`Run::segment_width`), and never reaches the archive:
/// `tests/segment_team.rs` compares every width's archive with one
/// engine's.
///
/// **Where it runs.** A NON-SOLID run with no ceiling named by the caller,
/// on a member of more stretches than one that walks the chains: levels 1
/// to 3, and at levels 4 and 5 a member whose own effort is the lazy
/// parse over the chains (level 4's plan, level 5 by the member's class),
/// each stretch walked by that effort (`Stretch::effort`). A solid run's
/// index crosses its slides; a member that keeps the tree is not claimed
/// here; under a caller's ceiling a flush is one window and the writer
/// keeps one engine.
#[derive(Default)]
pub(super) struct Segments {
    /// The engines beside the run's own, kept between members.
    pub(super) crews: Vec<Encoder>,
    /// Each engine's input for the round in flight: the kept dictionary
    /// and then its stretch.
    pub(super) inputs: Vec<Vec<u8>>,
    /// Each engine's packed bytes for the round in flight.
    pub(super) outs: Vec<Vec<u8>>,
    /// The dictionary the last stretch read leaves for the next one.
    pub(super) kept: Vec<u8>,
    /// How many engines the member in flight runs on; under two, the
    /// walk is the one engine's.
    pub(super) width: usize,
    /// The rolling hand-off of the member in flight, where it runs
    /// ([`Roll`]).
    #[cfg(feature = "parallel")]
    pub(super) roll: Option<Roll>,
    /// The rolling hand-off's input buffers between members, each kept at
    /// the length it has been written to, so that a later member's
    /// stretches are read over bytes already touched and nothing is
    /// zero-filled twice. Not stated while idle, as the rounds' buffers
    /// are not (`inputs`, cleared and kept at their capacity).
    #[cfg(feature = "parallel")]
    pub(super) idle_inputs: Vec<Vec<u8>>,
}

impl Segments {
    /// What the team holds now beside the run's own encoder: its engines'
    /// histories, finders and parses, and the rounds' buffers.
    pub(super) fn held(&self) -> u64 {
        let engines = self.crews.iter().fold(0u64, |sum, crew| {
            sum.saturating_add(crew.held_bytes())
                .saturating_add(crew.structure_bytes())
                .saturating_add(crew.flight_bytes())
        });
        let buffers = self
            .inputs
            .iter()
            .chain(&self.outs)
            .map(|buffer| buffer.len() as u64)
            .sum::<u64>();
        #[cfg(feature = "parallel")]
        let rolling = self.roll.as_ref().map_or(0, Roll::held);
        #[cfg(not(feature = "parallel"))]
        let rolling = 0u64;
        engines
            .saturating_add(buffers)
            .saturating_add(self.kept.len() as u64)
            .saturating_add(rolling)
    }
}

/// The windows of a member read AHEAD of the one engine that encodes it.
///
/// **What was serial.** A member encoded a window at a time by ONE engine
/// (no segment team: few cores, the tree's levels) was read, checksummed
/// and staged window by window on the writing thread, and each batch of
/// staged windows then parsed in a flush that thread waited for. Counted
/// 2 Oct 2026 on eight threads of a Xeon 8488C, one 4 GiB member at level
/// 1: of a 14.3 s wall, 0.75 s was the read, 0.26 the CRC32 and 0.21 the
/// zero fill of the window's buffer before each read, all with nothing
/// else running.
///
/// **What is read ahead.** While a flush runs on the pool, the writing
/// thread reads the next windows, as many as `Run::scratch` takes (two:
/// a whole flush at the shipped dictionary), behind the ones not yet
/// staged, and takes their checksum. They are staged from there when the flush has ended. The
/// windows, their order, and the flushes are the ones the walk had: a
/// flush still falls where the batch is full or `Engine::may_stage` ends
/// it, before the same window, so no byte moves; the payload is read once,
/// in order, by the writing thread.
///
/// **A failing reader** is met where the walk needs the window it failed
/// on, with every flush before that window run and handed on as it was:
/// its error waits here until then.
///
/// **What it holds.** `Run::scratch` at two windows (`Run::ahead_bytes`),
/// where it was one; the lead is charged for it where its depth is chosen
/// (`Run::alone_bytes`).
#[derive(Default)]
pub(super) struct WindowsAhead {
    /// The windows read and not yet staged are `scratch[head..tail]`.
    pub(super) head: usize,
    pub(super) tail: usize,
    /// How far the member has been read.
    pub(super) read_to: u64,
    /// The error the reader ended in, returned when the walk reaches the
    /// window it struck.
    pub(super) failed: Option<Error>,
    /// The filter plans (`filters::detect`) of windows read ahead, taken
    /// beside the flush before them ([`plan_ahead`]), each by the
    /// window's offset in the member, in member order.
    pub(super) plans: std::collections::VecDeque<(u64, Vec<FilterSpan>)>,
    /// Plan buffers the stage has finished with, for the next windows.
    pub(super) spare_plans: Vec<Vec<FilterSpan>>,
}

impl WindowsAhead {
    /// The plan taken ahead for the window at offset `base`, if one was.
    pub(super) fn take_plan(&mut self, base: u64) -> Option<Vec<FilterSpan>> {
        while let Some(&(at, _)) = self.plans.front() {
            if at >= base {
                break;
            }
            let (_, stale) = self.plans.pop_front().expect("a plan in front");
            self.spare_plans.push(stale);
        }
        match self.plans.front() {
            Some(&(at, _)) if at == base => self.plans.pop_front().map(|(_, plan)| plan),
            _ => None,
        }
    }
}

/// Takes the filter plan of every window read ahead in `scratch` that has
/// none yet, `next` being the member offset of the window at `at.head`.
///
/// **Beside the flush, not after it.** The plan of a window is
/// `filters::detect` over that window's bytes at its offset and nothing
/// else, so it can be taken as soon as the window is read, while the pool
/// parses the batch before it; staged later, the window takes the same
/// plan it would have taken there (`Encoder::stage_window_planned`), and
/// the archive is the same. Counted on the big member at `-m3` (an 18 core Apple
/// M5 Max, 15 Oct 2026): the main thread spent about 0.11 s of a 3.6 s
/// create in `detect` between flushes, with the pool otherwise idle.
pub(super) fn plan_ahead(
    scratch: &[u8],
    at: &mut WindowsAhead,
    next: u64,
    want: u64,
    window: usize,
) {
    let mut base = next;
    let mut from = at.head;
    while from < at.tail && base < want {
        let room = (want - base).min(window as u64) as usize;
        if from + room > at.tail {
            break;
        }
        if !at.plans.iter().any(|&(planned, _)| planned == base) {
            let mut plan = at.spare_plans.pop().unwrap_or_default();
            let bytes = &scratch[from..from + room];
            width::on_pool(|| filters::detect(bytes, base, &mut plan));
            at.plans.push_back((base, plan));
        }
        from += room;
        base += room as u64;
    }
}

/// Reads up to `most` of member `index`'s next windows into `scratch`
/// behind the ones `at` holds, as far as they fit, and takes their
/// checksum. A reader's failure is left in `at`.
#[allow(clippy::too_many_arguments)]
pub(super) fn read_windows(
    member: &mut Planned<'_>,
    prefix: &mut Prefix,
    index: usize,
    scratch: &mut [u8],
    at: &mut WindowsAhead,
    want: u64,
    window: usize,
    most: usize,
    digest: &mut Running,
) {
    if at.failed.is_some() {
        return;
    }
    if at.head == at.tail {
        at.head = 0;
        at.tail = 0;
    }
    for _ in 0..most {
        if at.read_to >= want {
            break;
        }
        let room = (want - at.read_to).min(window as u64) as usize;
        if at.tail + room > scratch.len() {
            if at.head == 0 {
                break;
            }
            scratch.copy_within(at.head..at.tail, 0);
            at.tail -= at.head;
            at.head = 0;
            if at.tail + room > scratch.len() {
                break;
            }
        }
        let target = &mut scratch[at.tail..at.tail + room];
        match &mut member.payload {
            Payload::Bytes(data) => {
                let from = at.read_to as usize;
                target.copy_from_slice(&data[from..from + room]);
            }
            Payload::Reader { reader, .. } => {
                let mut filled = 0;
                while filled < room {
                    match prefix.read(index, &mut **reader, &mut target[filled..]) {
                        Ok(0) => {
                            at.failed = Some(Error::new(ErrorKind::Truncated));
                            return;
                        }
                        Ok(read) => filled += read,
                        Err(error) => {
                            at.failed = Some(Error::from(error));
                            return;
                        }
                    }
                }
            }
        }
        digest.update(&scratch[at.tail..at.tail + room]);
        at.tail += room;
        at.read_to += room as u64;
    }
}

/// Whether a member's windows are read AHEAD of its one engine
/// ([`WindowsAhead`]). ON, on the rows
/// measured 1 Oct 2026; the knob below
/// turns it off for a count, and a test sets it for its own thread.
pub(super) const WINDOWS_AHEAD: bool = true;

/// Under the COUNT-ONLY feature `wave-knob`, `RARKIT_WINDOW_AHEAD=0` turns
/// the windows' read-ahead off and `=1` on, read once. Never a byte.
#[cfg(feature = "wave-knob")]
pub(super) fn knob_windows_ahead() -> Option<bool> {
    static AHEAD: std::sync::OnceLock<Option<bool>> = std::sync::OnceLock::new();
    *AHEAD.get_or_init(|| match std::env::var("RARKIT_WINDOW_AHEAD").ok()?.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    })
}

#[cfg(not(feature = "wave-knob"))]
#[inline(always)]
pub(super) fn knob_windows_ahead() -> Option<bool> {
    None
}

#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static WINDOW_AHEAD: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    pub(super) static WINDOW_AHEAD_MEMBERS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Runs `work` with the windows' read-ahead on, or off, on this thread.
/// This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn with_window_ahead<T>(ahead: bool, work: impl FnOnce() -> T) -> T {
    let was = WINDOW_AHEAD.with(|cell| cell.replace(Some(ahead)));
    let result = work();
    WINDOW_AHEAD.with(|cell| cell.set(was));
    result
}

/// How many members this thread's writes have read ahead of their one
/// engine. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn window_ahead_members() -> usize {
    WINDOW_AHEAD_MEMBERS.with(std::cell::Cell::get)
}

pub(super) fn note_window_ahead() {
    #[cfg(feature = "bench-internals")]
    WINDOW_AHEAD_MEMBERS.with(|cell| cell.set(cell.get() + 1));
}

/// Whether the form is on ([`WindowsAhead`]).
pub(super) fn windows_ahead_on() -> bool {
    #[cfg(feature = "bench-internals")]
    if let Some(ahead) = WINDOW_AHEAD.with(std::cell::Cell::get) {
        return ahead;
    }
    knob_windows_ahead().unwrap_or(WINDOWS_AHEAD)
}

// How many engines the segment team runs, where a test says: `None`, and
// always without `bench-internals`, is `Run::segment_width`'s own choice.
// A width and never a byte, which is what the tests that set it compare.
#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static SEGMENT_WIDTH: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    pub(super) static SEGMENT_ROUNDS: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

/// Under the COUNT-ONLY feature `wave-knob`, `RARKIT_SEGMENT_WIDTH=N`
/// holds the segment team to `N` engines (one is the walk without a
/// team), read once, so the widths are counted inside one binary. A
/// width and never a byte.
#[cfg(all(feature = "parallel", feature = "wave-knob"))]
pub(super) fn knob_segment_width() -> Option<usize> {
    static WIDTH: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *WIDTH.get_or_init(|| {
        std::env::var("RARKIT_SEGMENT_WIDTH")
            .ok()
            .and_then(|width| width.trim().parse::<usize>().ok())
            .filter(|&width| width > 0)
    })
}

#[cfg(all(feature = "parallel", not(feature = "wave-knob")))]
#[inline(always)]
pub(super) fn knob_segment_width() -> Option<usize> {
    None
}

/// Runs `work` with the segment team held to `width` engines on this
/// thread (one is the walk without a team). This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn with_segment_width<T>(width: usize, work: impl FnOnce() -> T) -> T {
    let was = SEGMENT_WIDTH.with(|cell| cell.replace(Some(width.max(1))));
    let result = work();
    SEGMENT_WIDTH.with(|cell| cell.set(was));
    result
}

/// How many rounds the segment team has run on this thread, and the most
/// engines one of them ran, since [`reset_segment_rounds`]. This
/// repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn segment_rounds() -> (usize, usize) {
    SEGMENT_ROUNDS.with(std::cell::Cell::get)
}

/// Starts [`segment_rounds`] again from zero.
#[cfg(feature = "bench-internals")]
pub(crate) fn reset_segment_rounds() {
    SEGMENT_ROUNDS.with(|cell| cell.set((0, 0)));
}

/// One round of the segment team ran on `engines` engines.
#[cfg(feature = "parallel")]
pub(super) fn note_segment_round(_engines: usize) {
    #[cfg(feature = "bench-internals")]
    SEGMENT_ROUNDS.with(|cell| {
        let (rounds, most) = cell.get();
        cell.set((rounds + 1, most.max(_engines)));
    });
}

/// One engine of the segment team over one stretch: `input` is the kept
/// dictionary and then the stretch's bytes, and `out` takes its packed
/// bytes. The windows are staged and flushed exactly as the one engine
/// stages and flushes them ([`stage_window`]), and the stretch's end is
/// where that engine's next window would have slid its history, which it
/// does with nothing staged.
pub(super) fn encode_stretch(
    encoder: &mut Encoder,
    input: &[u8],
    stretch: Stretch,
    window: usize,
    depth: usize,
    slack: usize,
    out: &mut Vec<u8>,
) {
    out.clear();
    if stretch.base == 0 && stretch.last {
        // The stretch is one WHOLE member from no history: its class is
        // read from its own head (`Encoder::start_member`, SPEC-H3 8.1).
        encoder.start_member(&input[stretch.kept..], (input.len() - stretch.kept) as u64);
    } else {
        if stretch.base == 0 {
            // A member's first stretch of several: the segment team's.
            encoder.reset_history();
        } else {
            encoder.resume_slid(
                &input[..stretch.kept],
                window,
                stretch.base - stretch.kept as u64,
            );
        }
        // Both put the level's own plan back. A member of a level with
        // two efforts (level 5 by class) is walked by the one its head
        // chose, on every engine and at every stretch.
        if let Some(effort) = stretch.effort {
            encoder.walk_member_by(effort);
        }
    }
    encoder.set_slack_multiple(slack);
    let data = &input[stretch.kept..];
    let count = data.len().div_ceil(window);
    let mut staged = 0usize;
    for (index, chunk) in data.chunks(window).enumerate() {
        stage_window(
            encoder,
            chunk,
            stretch.last && index + 1 == count,
            stretch.base + (index * window) as u64,
            out,
            false,
            depth,
            &mut staged,
        );
    }
    if staged > 0 {
        flush_windows(encoder, out, false, &mut staged);
    }
}

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    /// One window of a member, which is the most the writer hands the
    /// encoder at a time (spec G 3.7.3). A window is a working buffer and
    /// not a promise, and the dictionary is already the ceiling on what a
    /// match can reach.
    pub(super) fn window_bytes(&self) -> usize {
        (self.dictionary as usize).clamp(crate::encode::drive::PARSE_BLOCK_BYTES, MAX_WINDOW_BYTES)
    }

    /// The windowed encode of spec G 3.7.3, which is also spec G 3.9's
    /// solid walk: the same loop, differing only in whether the history
    /// it starts from is this member's own earlier windows or the member
    /// before it.
    ///
    /// The writer pulls one window, hands it to the encoder with the
    /// history in front of it, appends the blocks that come back, keeps
    /// the last dictionary's worth as the next window's history, and
    /// repeats. The member's INPUT is never held: what this holds is one
    /// window and one dictionary, both sized from the options and not
    /// from the member. The unpacked digest is taken as the windows pass,
    /// because a reader is pulled exactly once and there is no second
    /// look at those bytes.
    ///
    /// What is NOT removed here is the packed output buffer;
    /// `Run::packed` says why and what closing it needs.
    pub(super) fn compress_streaming(&mut self, index: usize) -> Result<()> {
        let want = self.members[index].size;
        let window = self.window_bytes();
        let continues = self.options.solid && self.solid_run;
        let reader_payload = matches!(self.members[index].payload, Payload::Reader { .. });
        let mut digest = self.new_digest();

        // A history is only ever the bytes the DECODER will have in its
        // window when it reaches this member: this member's own earlier
        // windows, or, in a solid set, the member before it. A member
        // that starts a run starts from nothing.
        if !continues {
            self.start_member_run(index)?;
        }
        self.scratch.reserve(window);
        self.packed.clear();
        // Windows are STAGED and parsed several at once unless the caller
        // set a ceiling; `stage_window` says why that is sound.
        // The held buffer `Run::reserve_held` reserved for the member is
        // appended to, never swapped away (`flush_windows`).
        let kept = self.held_kept(index);
        let depth = self.staged_depth();
        let mut staged = 0usize;
        // A NON-SOLID member streamed with no ceiling runs its history
        // further before it slides, and puts the shipped slack back when
        // it is done, so no other member and no solid run sees it
        // (`encode::drive::STREAMED_SLACK_MULTIPLE`, which says what that
        // costs and moves).
        let wide_slack = !self.options.solid
            && self.small_ceiling().is_none()
            && self.dictionary >= crate::encode::drive::STREAMED_SLACK_LEAST_DICTIONARY as u64;
        if wide_slack {
            self.encoder
                .as_mut()
                .expect("the encoder was built by compress")
                .set_slack_multiple(streamed_slack());
        }
        #[cfg(feature = "bench-internals")]
        LAST_SLACK.with(|cell| {
            cell.set(if wide_slack {
                streamed_slack()
            } else {
                crate::encode::drive::HISTORY_SLACK_MULTIPLE
            })
        });

        // What this thread pulls and judges beside the member's last
        // flush (`Run::ahead_plan`): only where spec G 3.8.3 judges solid
        // members, so that with `solid_store` off every reader is pulled
        // when it was.
        let mut after = if self.options.solid
            && self.options.solid_store
            && self.pull_failed.is_none()
            && self.prefetched.is_empty()
        {
            self.ahead_plan(index + 1)
        } else {
            Ahead::default()
        };
        let checksum = self.options.checksum;
        let mut after_kept = None;

        let mut pulled = 0u64;
        // A member of several stretches goes to the segment team where the
        // run affords one ([`Segments`]): the same packed bytes, appended
        // a round at a time.
        #[cfg(feature = "parallel")]
        {
            self.segments.width = self.segment_width(index);
            if self.segments.width >= 2 {
                let slack = if wide_slack {
                    streamed_slack()
                } else {
                    crate::encode::drive::HISTORY_SLACK_MULTIPLE
                };
                let mut packed = std::mem::take(&mut self.packed);
                let mut outcome = Ok(());
                if self.rolls() {
                    // The checksum is taken while the engines run, so by
                    // this thread alone (`Run::digest_threads`' rule for a
                    // pool that is lent).
                    digest = new_running(self.options.checksum, 1);
                    self.roll_start(want, window, depth, slack);
                    outcome = self.roll_on(index, &mut digest, &mut packed, false);
                    self.roll_end();
                } else {
                    while pulled < want {
                        match self.segment_round(
                            index,
                            want,
                            window,
                            pulled,
                            &mut digest,
                            depth,
                            slack,
                            &mut packed,
                        ) {
                            Ok(now) => pulled = now,
                            Err(error) => {
                                outcome = Err(error);
                                break;
                            }
                        }
                    }
                }
                self.packed = packed;
                self.segments.width = 0;
                self.note_peak();
                if wide_slack {
                    self.encoder
                        .as_mut()
                        .expect("the encoder was built by compress")
                        .set_slack_multiple(crate::encode::drive::HISTORY_SLACK_MULTIPLE);
                }
                outcome?;
                if reader_payload {
                    self.unpacked_digest = Some(digest.finish());
                }
                return Ok(());
            }
        }
        if depth > 1 && self.windows_ahead() {
            // The windows read ahead of the one engine ([`WindowsAhead`]):
            // `stage_window`'s own steps, the flush before a window run
            // beside the read of the windows after it. The checksum is
            // taken while the flush runs, so by this thread alone.
            note_window_ahead();
            digest = new_running(self.options.checksum, 1);
            self.size_scratch_ahead(want);
            let mut ahead = WindowsAhead::default();
            let outcome = loop {
                let room = (want - pulled).min(window as u64) as usize;
                let last = pulled + room as u64 == want;
                let Run {
                    members,
                    scratch,
                    encoder,
                    packed,
                    prefix,
                    ..
                } = self;
                let encoder = encoder.as_mut().expect("the encoder was built by compress");
                let before = packed.capacity();
                if staged >= depth || (staged > 0 && !encoder.may_stage(room)) {
                    let was = staged;
                    beside_with(
                        || flush_windows(encoder, packed, kept, &mut staged),
                        |_| {
                            read_windows(
                                &mut members[index],
                                prefix,
                                index,
                                scratch,
                                &mut ahead,
                                want,
                                window,
                                depth,
                                &mut digest,
                            );
                        },
                    );
                    note_flush_width(was);
                }
                if ahead.tail - ahead.head < room {
                    // Nothing read ahead: read as it is staged.
                    read_windows(
                        &mut members[index],
                        prefix,
                        index,
                        scratch,
                        &mut ahead,
                        want,
                        window,
                        1,
                        &mut digest,
                    );
                    if ahead.tail - ahead.head < room {
                        break Err(ahead
                            .failed
                            .take()
                            .unwrap_or_else(|| refuse("a window read ahead came short")));
                    }
                }
                encoder.stage_window(&scratch[ahead.head..ahead.head + room], last, pulled);
                ahead.head += room;
                staged += 1;
                if last {
                    flush_windows(encoder, packed, kept, &mut staged);
                }
                note_packed_capacity(before, packed.capacity());
                pulled += room as u64;
                self.note_peak();
                if last {
                    break Ok(());
                }
            };
            if wide_slack {
                self.encoder
                    .as_mut()
                    .expect("the encoder was built by compress")
                    .set_slack_multiple(crate::encode::drive::HISTORY_SLACK_MULTIPLE);
            }
            outcome?;
            if reader_payload {
                self.unpacked_digest = Some(digest.finish());
            }
            return Ok(());
        }
        loop {
            let room = (want - pulled).min(window as u64) as usize;
            let last = pulled + room as u64 == want;
            {
                let Run {
                    members,
                    scratch,
                    encoder,
                    packed,
                    prefix,
                    prefetched,
                    prefetch_buf,
                    judges,
                    ..
                } = self;
                let encoder = encoder.as_mut().expect("the encoder was built by compress");
                scratch.clear();
                match &mut members[index].payload {
                    Payload::Bytes(data) => {
                        let at = pulled as usize;
                        scratch.extend_from_slice(&data[at..at + room]);
                    }
                    Payload::Reader { reader, .. } => {
                        scratch.resize(room, 0);
                        let mut filled = 0;
                        while filled < room {
                            let read = prefix
                                .read(index, &mut **reader, &mut scratch[filled..room])
                                .map_err(Error::from)?;
                            if read == 0 {
                                return Err(Error::new(ErrorKind::Truncated));
                            }
                            filled += read;
                        }
                    }
                }
                digest.update(scratch);
                // The encoder keeps the history and the index over it, so
                // this window pays only for its own bytes.
                let before = packed.capacity();
                if depth > 1 && last && !after.is_empty() {
                    // The member's LAST flush, with the readers after the
                    // member pulled and judged by this thread beside it
                    // (`pull_ahead`): `stage_window`'s own steps, the
                    // flush that ends them run on the pool.
                    if staged >= depth || (staged > 0 && !encoder.may_stage(scratch.len())) {
                        flush_windows(encoder, packed, kept, &mut staged);
                    }
                    encoder.stage_window(scratch, last, pulled);
                    staged += 1;
                    let plan = std::mem::take(&mut after);
                    after_kept = Some(flush_beside(
                        || flush_windows(encoder, packed, kept, &mut staged),
                        plan,
                        members,
                        prefetched,
                        prefetch_buf,
                        judges,
                        checksum,
                    ));
                } else if depth > 1 {
                    stage_window(
                        encoder,
                        scratch,
                        last,
                        pulled,
                        packed,
                        kept,
                        depth,
                        &mut staged,
                    );
                } else {
                    encoder.chunk(scratch, last, packed, pulled);
                }
                note_packed_capacity(before, packed.capacity());
            }
            if let Some(kept) = after_kept.take() {
                self.keep_ahead(kept);
            }
            pulled += room as u64;
            // Sampled EVERY window and not once at the end: `packed`
            // grows window by window while `scratch` holds this window,
            // and the last window may be a short one, so the largest
            // total is not always the final state.
            self.note_peak();
            if last {
                break;
            }
        }
        if wide_slack {
            self.encoder
                .as_mut()
                .expect("the encoder was built by compress")
                .set_slack_multiple(crate::encode::drive::HISTORY_SLACK_MULTIPLE);
        }
        if reader_payload {
            self.unpacked_digest = Some(digest.finish());
        }
        Ok(())
    }

    /// How many engines member `index`, about to be encoded a window at a
    /// time by the run's own encoder (already built, its slack already
    /// set), runs on: the segment team's width ([`Segments`]), or one for
    /// the walk as it was.
    ///
    /// More than one only in a NON-SOLID run with no ceiling named by the
    /// caller, at a chain level, with windows staged, on a member of more
    /// stretches than one; and above level 1 only on a member of at least
    /// as many stretches as the rule's engines, or one whose team holds at
    /// least a block in flight for every thread of the pool (its
    /// stretches times the blocks of a window). Then the least of three
    /// figures:
    ///
    /// - the pool's width held to `WriteOptions::workers`, since an engine
    ///   beyond the threads there are has nobody to run its insert pass;
    /// - the member's stretches;
    /// - what the policy's `working_limit` still affords, less what a
    ///   process holds beside the writer's charged memory
    ///   ([`TEAM_BESIDE_WRITER`]), over what one more engine holds
    ///   ([`Run::segment_charge`]): the run's own encoder is one engine
    ///   whatever is left.
    ///
    /// Read from what the run holds NOW, so it follows the member's place
    /// in the run. That is sound because the width cannot reach a byte
    /// ([`Segments`]).
    pub(super) fn segment_width(&self, index: usize) -> usize {
        #[cfg(not(feature = "parallel"))]
        {
            let _ = index;
            1
        }
        #[cfg(feature = "parallel")]
        {
            if self.options.solid || self.dial_ceiling().is_some() || window_depth() <= 1 {
                return 1;
            }
            let Some(encoder) = &self.encoder else {
                return 1;
            };
            // The team is the chains' (spec G 3.7.3). At levels 1 to 3 that
            // is the level. At levels 4 and 5 it is the MEMBER: one whose
            // own effort is the lazy parse over the chains (level 4's
            // plan; at level 5 the member's class, which
            // `start_member_run` has read by now) takes the team, and one
            // that keeps the tree, or an optimal parse, is one engine's.
            if self.options.method > 3 {
                if !encoder.member_walks_lazy_chains() {
                    return 1;
                }
            } else if encoder.walks_tree() {
                return 1;
            }
            let window = self.window_bytes();
            let size = self.members[index].size;
            // A slide must keep whole windows, and no more than a stretch
            // holds: the next engine is handed them as the member's own
            // bytes and judges each for filters as the one engine did. So
            // the dictionary is a whole number of windows (it is one, up
            // to 8 MiB) and no longer than the slack (it is not, up to 64
            // MiB).
            let dictionary = self.dictionary as usize;
            if !dictionary.is_multiple_of(window)
                || encoder.streamed_period(window, dictionary, u64::MAX / 2) < dictionary as u64
            {
                return 1;
            }
            // The stretches, counted no further than the pool could use.
            let pool = self.pool_width().min(self.options.encoder_width());
            let mut stretches = 0usize;
            let mut at = 0u64;
            let mut history = 0usize;
            while at < size && stretches < pool {
                let period = encoder.streamed_period(window, history, size - at);
                history = encoder.kept_by_slide(history.saturating_add(period as usize));
                at += period;
                stretches += 1;
            }
            #[cfg(feature = "bench-internals")]
            if let Some(width) = SEGMENT_WIDTH.with(std::cell::Cell::get) {
                if std::env::var_os("RARKIT_TEAM_SAY").is_some() {
                    let (lead, each) = self.segment_charge(window);
                    eprintln!(
                        "rarkit team: forced {width}: held now {} MiB, lead {} MiB, each {} MiB, stretches {stretches}, window {} MiB, dictionary {} MiB",
                        self.working_now() >> 20,
                        lead >> 20,
                        each >> 20,
                        window >> 20,
                        dictionary >> 20,
                    );
                }
                return width.min(stretches).max(1);
            }
            if let Some(width) = knob_segment_width() {
                return width.min(stretches).max(1);
            }
            // The rule by cores and level, which the sweep drew. Above
            // level 1 a member of fewer stretches than the rule's engines
            // is the one engine's too, UNLESS its team's windows fill the
            // pool: an engine beside the run's own is held to one window
            // in flight, so a few of them parse fewer blocks at once than
            // the one engine's wave on the same pool (a 64 MiB text at
            // level 3 on 36 cores, four stretches of 2 MiB windows: 0.75x
            // to 0.84x at every engine count). That is a count of BLOCKS,
            // and a window is the dictionary: at 8 MiB four engines hold
            // 128 blocks in flight where at 2 MiB they hold 32. A stretch
            // grows with the dictionary too, so a member of 1 GiB has
            // sixteen stretches at 8 MiB and above, fewer than the 18 or
            // 24 engines of a wide pool, and by the count of stretches
            // alone it fell to one engine there: 0.40x to 0.75x of its
            // wall at 2 MiB on 64 and on 36 cores
            // (measured 1 Oct 2026).
            // Level 1's wall is its linking pass, so there every stretch
            // another engine takes is a gain.
            let engines = segment_engines(self.options.method, self.pool_cores());
            if pool < 2 || stretches < 2 || engines < 2 {
                return 1;
            }
            // `few`: the member the count of stretches alone refused.
            let few = self.options.method > 1 && stretches < engines.min(pool);
            let blocks = (window / crate::encode::drive::PARSE_BLOCK_BYTES).max(1);
            let level = self.options.method;
            if few && !few_stretches_take_the_team(level, stretches, blocks, pool, stretches) {
                return 1;
            }
            // The worker team's ceiling, by its own function, so the
            // bench knob that puts a run at the 512 MiB floor reaches
            // both.
            let limit = team_ceiling(self.options.memory.working_limit);
            let (lead, each) = self.segment_charge(window);
            // The worker team's crews grow into their charge while this
            // member is encoded: what they do not hold yet is not room.
            let owed = self.team_charged.saturating_sub(self.team_now());
            // The run's OWN encoder is one of the team's engines, and the
            // one that is not held to a window: its finder is the unheld
            // one and its parses are the pool's wave. It has built neither
            // when a member begins, so what it holds now says nothing of
            // what it will: reserved here at its own sum
            // (`Run::own_engine_bytes`), less what it does hold.
            //
            // From level 3, where it was counted and where the team it
            // costs is no loss (three engines draw level with one there).
            // At levels 1 and 2 the run's own engine is as unreserved, but
            // the engines the limits read afforded stated 365 to 380 MiB
            // inside limits of 379 to 467, and each is a gain there (at
            // level 2 three are 1.06x of one): reserving it with this
            // sum, which stands about 30 MiB above what those levels
            // hold, would take them. Left as they were, until a sum is
            // exact enough to say.
            let own = if self.options.method > 2 {
                self.own_engine_bytes(index, window).saturating_sub(
                    encoder
                        .held_bytes()
                        .saturating_add(encoder.structure_bytes())
                        .saturating_add(encoder.flight_bytes()),
                )
            } else {
                0
            };
            let room = limit
                .saturating_sub(self.working_now())
                .saturating_sub(owed)
                .saturating_sub(lead)
                .saturating_sub(own);
            let afford = 1 + usize::try_from(room / each.max(1)).unwrap_or(usize::MAX);
            #[cfg(feature = "bench-internals")]
            if std::env::var_os("RARKIT_TEAM_SAY").is_some() {
                eprintln!(
                    "rarkit team: limit {} MiB, held now {} MiB, owed {} MiB, lead {} MiB, own engine {} MiB, each {} MiB, afford {afford}, engines {engines}, stretches {stretches}, pool {pool}",
                    limit >> 20,
                    self.working_now() >> 20,
                    owed >> 20,
                    lead >> 20,
                    own >> 20,
                    each >> 20,
                );
            }
            // A team the MEMORY affords under the count that gains at this
            // window is the one engine's walk (`segment_afforded_least`).
            if matches!(level, 2 | 3) && afford < segment_afforded_least(level, blocks) {
                return 1;
            }
            let team = segment_team(self.options.method, pool, stretches, afford, engines);
            // The same member again with the team as the memory affords
            // it: two engines of narrow windows are slower than the one.
            if few && !few_stretches_take_the_team(level, stretches, blocks, pool, team) {
                return 1;
            }
            team
        }
    }

    /// What the run's OWN encoder holds while it encodes member `index` as
    /// one of the segment team's engines: its carried history, its finder
    /// and hints (`Encoder::member_held_bytes`, at the streamed slack) and
    /// its parses in flight over one flush (`Encoder::flight_term_over`),
    /// the terms [`Run::alone_bytes`] charges a windowed member's lead.
    ///
    /// **Why it is reserved.** `Run::segment_width` sized the team from
    /// what the run held when the member began, and the run's own encoder
    /// has built nothing then. Counted 2 Oct 2026 on a 96 thread box:
    /// one 4
    /// GiB member at level 3 under a cgroup cap of 512 MiB to 1 GiB, a
    /// working limit of 379 to 467 MiB: the team was afforded three
    /// engines from 3 MiB held, its plan 229 MiB, and at the write's high
    /// point the run's own encoder stood at 183 MiB (history 18, finder
    /// 68, parses in flight 97) beside the two others' 199: 385 to 392
    /// MiB stated, and a process of 485 to 503 MiB that the kernel killed
    /// under 512 MiB.
    #[cfg(feature = "parallel")]
    pub(super) fn own_engine_bytes(&self, index: usize, window: usize) -> u64 {
        let probe = self.encoder_capped(self.hold, self.parses);
        let mut slid = self.encoder_capped(self.hold, self.parses);
        slid.set_slack_multiple(self.streamed_slack_multiple());
        let len = usize::try_from(self.members[index].size).unwrap_or(usize::MAX);
        let flush = self.lead_window_flush().min(len);
        let span = usize::try_from(self.dictionary)
            .unwrap_or(usize::MAX)
            .saturating_add(flush);
        slid.member_held_bytes(len, Some(window))
            .saturating_add(probe.flight_term_over(flush, span))
    }

    /// What the segment team adds to the run's working memory: for the
    /// run's own encoder, which becomes one of its engines, the round's
    /// input buffer and packed bytes; and for each engine beside it, those
    /// and the engine itself, held to one window in flight
    /// (`Engine::hold_wave`), its finder, its history at the cap and its
    /// parses. Each term is what is held, not an allowance.
    #[cfg(feature = "parallel")]
    pub(super) fn segment_charge(&self, window: usize) -> (u64, u64) {
        // Under the slack the walk runs the member at: the stretch and the
        // history's cap both follow it.
        let mut probe = self.encoder_held(Some(window));
        probe.set_slack_multiple(self.streamed_slack_multiple());
        // A stretch at its longest, the member's first, and the dictionary
        // in front of every later one.
        let stretch =
            usize::try_from(probe.streamed_period(window, 0, u64::MAX / 2)).unwrap_or(usize::MAX);
        let input = (self.dictionary as usize).saturating_add(stretch) as u64;
        let packed = crate::encode::drive::packed_most(stretch) as u64;
        let buffers = input.saturating_add(packed);
        let engine = probe
            .member_held_bytes(usize::MAX / 2, Some(window))
            .saturating_add(probe.flight_term(window));
        (buffers, buffers.saturating_add(engine))
    }

    /// Whether a member encoded a window at a time by the run's one
    /// engine has its windows read ahead ([`WindowsAhead`]): where the
    /// form is on, outside a solid run (whose last flush pulls the readers
    /// after the member instead, `flush_beside`), where a flush stages
    /// more windows than one (never under a caller's ceiling), and where
    /// the pool has two threads at least, so that one thread's walk is
    /// the walk it was.
    ///
    /// **Levels 1 to 3, by the rows.** At the tree's levels the read and
    /// the checksum were two to four thousandths of the wall, and reading
    /// ahead read 0.985x on two rows of three there (one 1 GiB member on
    /// an M1 Ultra at 2 and 8 threads), so levels 4 and 5 keep the walk
    /// they had (measured 1 Oct 2026).
    pub(super) fn windows_ahead(&self) -> bool {
        windows_ahead_on()
            && !self.options.solid
            && self.options.method <= 3
            && self.staged_depth() > 1
            && self.helpers() >= 2
    }

    /// How many bytes of a member are read ahead of its one engine
    /// ([`WindowsAhead`]): TWO WINDOWS, or a flush's worth where that is
    /// less. At the shipped dictionary a window is 8 MiB and a flush is
    /// two of them, so the whole of the next flush is read beside this
    /// one. At a small dictionary a flush stages many windows and two of
    /// them are read ahead, the rest as they are staged: what the walk
    /// holds of a member follows the DICTIONARY and never the member
    /// (`tests/writers.rs`, which held a flush's worth to be too much at
    /// 128 KiB and 256 KiB: the first two gates of this land were red on
    /// it).
    pub(super) fn ahead_bytes(&self) -> usize {
        let window = self.window_bytes();
        self.lead_window_flush()
            .min(window.saturating_mul(2))
            .max(window)
    }

    /// `Run::scratch` at what a member of `want` bytes is read ahead
    /// through (`Run::ahead_bytes`, or the member where it is shorter),
    /// which is what `Run::alone_bytes` charges the lead for it.
    /// Zero-filled where it grows, once, and read over from then on.
    pub(super) fn size_scratch_ahead(&mut self, want: u64) {
        let need = usize::try_from(want)
            .unwrap_or(usize::MAX)
            .min(self.ahead_bytes())
            .max(1);
        if self.scratch.len() < need {
            self.scratch.resize(need, 0);
        } else {
            self.scratch.truncate(need);
        }
    }

    /// The bound on one stretch's packed bytes, at its longest
    /// (`Run::segment_charge`'s packed term).
    #[cfg(feature = "parallel")]
    pub(super) fn segment_packed(&self, window: usize) -> u64 {
        let mut probe = self.encoder_held(Some(window));
        probe.set_slack_multiple(self.streamed_slack_multiple());
        let stretch =
            usize::try_from(probe.streamed_period(window, 0, u64::MAX / 2)).unwrap_or(usize::MAX);
        crate::encode::drive::packed_most(stretch) as u64
    }

    /// One ROUND of the segment team for member `index`, `pulled` bytes of
    /// whose `want` have been read: the next stretches, one an engine,
    /// read and checksummed here in order, encoded at once, and their
    /// packed bytes appended to `sink` in order. Answers how far the
    /// member has now been read.
    ///
    /// The run's own encoder is the first engine and runs its stretch on
    /// this thread; the others run on the pool. `depth` and `slack` are
    /// this thread's test dials, read here because the engines' threads
    /// have their own.
    #[cfg(feature = "parallel")]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn segment_round(
        &mut self,
        index: usize,
        want: u64,
        window: usize,
        mut pulled: u64,
        digest: &mut Running,
        depth: usize,
        slack: usize,
        sink: &mut Vec<u8>,
    ) -> Result<u64> {
        let width = self.segments.width;
        while self.segments.crews.len() + 1 < width {
            let crew = self.encoder_held(Some(window));
            self.segments.crews.push(crew);
        }
        let mut stretches: Vec<Stretch> = Vec::with_capacity(width);
        {
            let Run {
                members,
                prefix,
                segments,
                encoder,
                ..
            } = self;
            let lead = encoder
                .as_ref()
                .expect("the encoder was built before the walk");
            // The member's effort, which the run's own encoder read off
            // its head and every stretch puts back (`encode_stretch`).
            let effort = lead.member_effort();
            if segments.inputs.len() < width {
                segments.inputs.resize_with(width, Vec::new);
                segments.outs.resize_with(width, Vec::new);
            }
            if pulled == 0 {
                segments.kept.clear();
            }
            while stretches.len() < width && pulled < want {
                let period =
                    lead.streamed_period(window, segments.kept.len(), want - pulled) as usize;
                let input = &mut segments.inputs[stretches.len()];
                input.clear();
                input.reserve_exact(segments.kept.len() + period);
                input.extend_from_slice(&segments.kept);
                let kept = input.len();
                match &mut members[index].payload {
                    Payload::Bytes(data) => {
                        let at = pulled as usize;
                        input.extend_from_slice(&data[at..at + period]);
                    }
                    Payload::Reader { reader, .. } => {
                        input.resize(kept + period, 0);
                        let mut filled = kept;
                        while filled < kept + period {
                            let read = prefix
                                .read(index, &mut **reader, &mut input[filled..])
                                .map_err(Error::from)?;
                            if read == 0 {
                                return Err(Error::new(ErrorKind::Truncated));
                            }
                            filled += read;
                        }
                    }
                }
                digest.update(&input[kept..]);
                stretches.push(Stretch {
                    kept,
                    base: pulled,
                    last: pulled + period as u64 == want,
                    effort: Some(effort),
                });
                pulled += period as u64;
                // What a slide keeps of this stretch's history is the
                // next stretch's.
                let keep = lead.kept_by_slide(input.len());
                segments.kept.clear();
                segments
                    .kept
                    .extend_from_slice(&input[input.len() - keep..]);
            }
        }
        let count = stretches.len();
        note_segment_round(count);
        {
            let Run {
                segments, encoder, ..
            } = self;
            let lead = encoder
                .as_mut()
                .expect("the encoder was built before the walk");
            // Every engine of the round shares the pool with the others,
            // the run's own for the round only: outside it, it is alone.
            lead.share_pool(count);
            for crew in segments.crews.iter_mut() {
                crew.share_pool(count);
            }
            let Segments {
                crews,
                inputs,
                outs,
                ..
            } = segments;
            let (first_in, rest_in) = inputs[..count].split_first().expect("a stretch");
            let (first_out, rest_out) = outs[..count].split_first_mut().expect("a stretch");
            width::scope_here(|scope| {
                for (((crew, input), out), stretch) in crews
                    .iter_mut()
                    .zip(rest_in)
                    .zip(rest_out)
                    .zip(&stretches[1..])
                {
                    let stretch = *stretch;
                    scope.spawn(move |_| {
                        encode_stretch(crew, input, stretch, window, depth, slack, out);
                    });
                }
                encode_stretch(
                    lead,
                    first_in,
                    stretches[0],
                    window,
                    depth,
                    slack,
                    first_out,
                );
            });
            lead.share_pool(0);
        }
        // The round's high point: every engine's structures built, its
        // input still held and its packed bytes whole.
        self.note_peak();
        for (input, out) in self.segments.inputs[..count]
            .iter_mut()
            .zip(&mut self.segments.outs[..count])
        {
            sink.extend_from_slice(out);
            out.clear();
            input.clear();
        }
        if pulled == want {
            self.segments.kept.clear();
        }
        Ok(pulled)
    }
}

#[cfg(test)]
mod plan_ahead_tests {
    use super::*;

    /// Bytes a filter pays in (x86 near calls) beside bytes none does, so
    /// the plans are not all empty.
    fn mixed(len: usize) -> Vec<u8> {
        let mut state = 0x9e37_79b9_u32;
        (0..len)
            .map(|i| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                if (i / 70_000) % 2 == 0 && i % 5 == 0 {
                    0xe8
                } else if (i / 70_000) % 2 == 0 && i % 5 == 4 {
                    0x00
                } else {
                    state as u8
                }
            })
            .collect()
    }

    /// **A plan taken ahead is the plan the stage would take**: every
    /// window read ahead, the last one short, gets `filters::detect` over
    /// its own bytes at its own offset, and `take_plan` hands each to its
    /// own window only, a window it never planned getting none. On the
    /// caller's thread: `width::on_pool` runs here when no pool is lent.
    #[test]
    fn plans_taken_ahead_are_the_stage_s_own() {
        let window = 100_000;
        let want = 360_000u64;
        let start = 50_000u64;
        let bytes = mixed((want - start) as usize);
        let mut scratch = vec![0u8; 8];
        scratch.extend_from_slice(&bytes);
        let mut ahead = WindowsAhead {
            head: 8,
            tail: scratch.len(),
            read_to: want,
            ..WindowsAhead::default()
        };
        plan_ahead(&scratch, &mut ahead, start, want, window);
        // Again: nothing is planned twice.
        plan_ahead(&scratch, &mut ahead, start, want, window);
        assert_eq!(ahead.plans.len(), 4, "three whole windows and a short one");
        assert_eq!(ahead.take_plan(start - 1), None, "an offset never planned");
        let mut base = start;
        let mut from = 8;
        let mut any = false;
        while base < want {
            let room = (want - base).min(window as u64) as usize;
            let mut fresh = Vec::new();
            filters::detect(&scratch[from..from + room], base, &mut fresh);
            any |= !fresh.is_empty();
            let taken = ahead.take_plan(base).expect("a plan for every window read");
            assert_eq!(taken, fresh, "the window at {base}");
            base += room as u64;
            from += room;
        }
        assert!(any, "no window was given a filter: the test sees nothing");
        assert!(ahead.plans.is_empty());
    }
}
