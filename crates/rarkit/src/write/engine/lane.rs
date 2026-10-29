//! The worker team's size: how many crews, the largest member they take,
//! and the large-member lane.

use super::*;

/// The largest member the worker team takes (`Run::team_takes`) under a
/// caller's memory ceiling: one parse block. It is what bounds a crew's
/// encoder, whose finder and hints are sized from the member (spec H3
/// section 8.3), and it is what that ceiling's share was measured with.
/// Where no ceiling was named the team may take members of several
/// blocks ([`TEAM_MEMBER_BLOCKS_MOST`], `Run::choose_team_most`).
pub(super) const TEAM_MEMBER_MOST: u64 = crate::encode::drive::PARSE_BLOCK_BYTES as u64;

/// The most parse blocks a member the worker team takes may be, where no
/// caller named a memory ceiling (`Run::choose_team_most`).
///
/// **Why a member of several blocks is the team's.** A member is a wave of
/// its own blocks and no more: one of three blocks, encoded by the
/// writing thread, runs three wide however wide the box is, and the team
/// waits on it. Counted 28 Sep 2026 on tree5k (5,000 members, 50 of them
/// above one block, about 640 KiB each), an Apple M1 Mac, 20 cores: the team of
/// one-block members ran about six cores wide where the old engine ran
/// about seventeen, at LESS CPU; on a local set of that shape, members of
/// up to 1 MiB taken by the team made `-m1` 0.24 s to 0.13 s, the same
/// bytes. Past
/// sixteen blocks (4 MiB) a member is wide enough on its own to be the
/// writing thread's, and a crew sized for it costs more than it buys.
pub(super) const TEAM_MEMBER_BLOCKS_MOST: u64 = 16;

/// What a LARGE crew's encoder holds in flight (`Engine::hold_wave`): one
/// walk group of the tree, four parse blocks. The crews are the team's
/// width, so a crew needs none inside its member; held, a tree crew for a
/// member of eight blocks keeps four blocks of hints and parses rather
/// than eight, which is what lets the memory ceiling fit more large
/// crews at levels 4 and 5. A held wave moves no byte (`Engine::hold_wave`
/// says why).
pub(super) const LARGE_CREW_HOLD: usize =
    crate::encode::drive::WALK_BLOCKS * crate::encode::drive::PARSE_BLOCK_BYTES;

/// How far past one window the large-member lane reaches where its charge
/// costs the team no crew (`Run::choose_large_lane`): a reader member of
/// up to this many bytes is pulled whole and encoded by a crew of its own
/// while others encode its neighbours. Halved down to the window until it
/// fits.
///
/// 64 MiB: on the 4 GiB set of real binaries (9,516 members), 76 percent
/// of the bytes are in members of up to 64 MiB and 33 percent in members
/// between one window and 18 MiB, which the writing thread encoded one at
/// a time. A member above the reach is the writing thread's, on the
/// segment team where it is long enough ([`Segments`]).
pub(super) const LANE_REACH: u64 = 64 << 20;

// A test's reach for the large-member lane on this thread; unset, and
// always without `bench-internals`, it is [`LANE_REACH`]. A width and
// never a byte, which is what the tests that set it compare.
#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static LANE_REACH_SET: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Runs `work` with the large-member lane's reach set to `bytes` on this
/// thread (zero is the lane inside one window, as it was before it
/// reached). This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn with_lane_reach<T>(bytes: u64, work: impl FnOnce() -> T) -> T {
    let was = LANE_REACH_SET.with(|cell| cell.replace(Some(bytes)));
    let result = work();
    LANE_REACH_SET.with(|cell| cell.set(was));
    result
}

/// [`LANE_REACH`] and `false`, or the reach a test set and `true`: a
/// test's reach is taken as it is wherever it fits at all, not compared.
/// So is the count-only `wave-knob`'s `RARKIT_LANE_REACH` bytes (0 for no
/// reach past a window), read once.
pub(super) fn lane_reach() -> (u64, bool) {
    #[cfg(feature = "bench-internals")]
    if let Some(bytes) = LANE_REACH_SET.with(std::cell::Cell::get) {
        return (bytes, true);
    }
    #[cfg(feature = "wave-knob")]
    {
        static REACH: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
        let knob = *REACH.get_or_init(|| {
            std::env::var("RARKIT_LANE_REACH")
                .ok()
                .and_then(|bytes| bytes.trim().parse::<u64>().ok())
        });
        if let Some(bytes) = knob {
            return (bytes, true);
        }
    }
    (LANE_REACH, false)
}

// A test's figure for the physical cores a write's pool runs on, on this
// thread; unset, and always without `bench-internals`, it is
// `Run::pool_cores`' own. What a rule by cores chooses is a width and
// never a byte.
#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static TEAM_CORES_SET: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// Runs `work` with the rules by cores (`segment_engines`, `lane_reach_on`)
/// reading `cores` physical cores, whatever the pool and the machine. This
/// repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn with_team_cores<T>(cores: usize, work: impl FnOnce() -> T) -> T {
    let was = TEAM_CORES_SET.with(|cell| cell.replace(Some(cores.max(1))));
    let result = work();
    TEAM_CORES_SET.with(|cell| cell.set(was));
    result
}

/// A test's figure for [`Run::pool_cores`], where one is set.
pub(super) fn cores_set() -> Option<usize> {
    #[cfg(feature = "bench-internals")]
    {
        TEAM_CORES_SET.with(std::cell::Cell::get)
    }
    #[cfg(not(feature = "bench-internals"))]
    {
        None
    }
}

/// How far the large-member lane reaches at `level` on `cores` physical
/// cores of the pool (`Run::choose_large_lane`), zero for no reach past
/// one window: [`LANE_REACH`] from [`LANE_CORES_LEAST`] of them, by level;
/// under that, at levels 2 and 3, the narrow pool's reach
/// (`lane_reach_narrow`) from [`LANE_NARROW_CORES_LEAST`]; and never at
/// the tree's levels, which no row of the sweep covers.
pub(super) fn lane_reach_on(level: u8, cores: usize) -> u64 {
    match level {
        1..=3 if cores >= LANE_CORES_LEAST[usize::from(level) - 1] => LANE_REACH,
        2 | 3 if cores >= LANE_NARROW_CORES_LEAST => lane_reach_narrow(cores),
        _ => 0,
    }
}

/// The fewest physical cores of the pool the lane reaches [`LANE_REACH`]
/// on, at levels 1, 2 and 3 (`lane_reach_on`).
pub(super) const LANE_CORES_LEAST: [usize; 3] = [4, 16, 16];

/// The lane's reach at levels 2 and 3 on a pool of `cores` physical cores
/// too narrow for [`LANE_REACH`]: [`LANE_REACH_NARROW`], or where
/// [`LANE_NARROW_BY_CORES`] a MiB a core up to it.
///
/// **Why a short reach where the long one loses.** A member past one
/// window was the writing thread's on such a pool, its parse blocks a
/// wave over the pool; a crew encodes a member alone, on one thread,
/// beside its fellows. Which is faster turns on the member's LENGTH: a
/// wave over a short member leaves cores idle, a wave over a long one
/// fills the pool, and several crews each with tables of their own cost
/// more cache than one wave does. Timed on eight cores of a Zen 4 at
/// level 3, each class of a 4 GiB set of binaries as a set of its own
/// (measured 1 Oct 2026): members of 2 to 4
/// MiB on crews 1.58x of the earlier code, 4 to 8 MiB 1.12x to 1.15x, 8 to 16 MiB
/// 0.90x to 0.93x. So the reach stops under the class that loses. The
/// whole set at a reach of 4, 8, 16 and 64 MiB read 1.06x, 1.09x, 1.09x
/// and 1.02x, the last being the reach the segment team's sweep read
/// under the earlier code there.
///
/// The reach is a WIDTH and never a byte: every reach writes the archive
/// no reach writes, so a rule by cores or by architecture moves nothing
/// in any archive (API promise 2.6).
pub(super) fn lane_reach_narrow(cores: usize) -> u64 {
    if LANE_NARROW_BY_CORES {
        (cores as u64)
            .saturating_mul(1 << 20)
            .min(LANE_REACH_NARROW)
    } else {
        LANE_REACH_NARROW
    }
}

/// The most a narrow pool reaches (`lane_reach_narrow`): the longest
/// class of members that gained as a set of its own on eight cores, on
/// both architectures timed.
pub(super) const LANE_REACH_NARROW: u64 = 8 << 20;

/// Whether a pool of fewer than eight cores reaches a MiB a core in place
/// of [`LANE_REACH_NARROW`] (`lane_reach_narrow`): everywhere but x86-64.
///
/// **Measured on four threads, and the two architectures disagree**
/// (measured 1 Oct 2026). On x86-64 (a Zen 4)
/// a reach of 8 MiB was ahead of 4 MiB there (a 1 GiB set of binaries
/// 1.07x of the earlier code against 1.04x; members of 4 to 8 MiB alone 1.06x). On
/// aarch64 (an M1 Ultra) members of 4 to 8 MiB alone read 0.87x and 0.94x
/// of the earlier code on crews, and at 4 MiB the whole set was ahead (1.01x) where
/// at 8 MiB it was level. Both were a four-thread pool on a wider box; a
/// true four-core machine's row is not measured yet on each. An architecture with no
/// row takes the cautious form.
pub(super) const LANE_NARROW_BY_CORES: bool = !cfg!(target_arch = "x86_64");

/// The fewest physical cores of the pool the narrow reach is on at
/// levels 2 and 3 (`lane_reach_on`).
pub(super) const LANE_NARROW_CORES_LEAST: usize = 4;

/// One fit of the large-member lane (`Run::fit_large_lane`).
pub(super) struct LaneFit {
    /// The reach: the largest member the lane takes.
    pub(super) most: u64,
    /// The large crews and the small ones beside them.
    pub(super) crews: usize,
    pub(super) smalls: usize,
    /// The largest member the lane really takes where that is past one
    /// window, else zero.
    pub(super) past: u64,
    /// What the crews of both kinds are charged.
    pub(super) charged: u64,
    /// What the walk costs with the large lane, in bytes one crew encodes: the
    /// longer of the two kinds' bytes over their crews, since they run at
    /// once, and the members no crew takes at the writing thread's pace
    /// ([`LEAD_PACE`]). An estimate that orders the reaches; it is not a
    /// time, and no byte follows it.
    pub(super) cost: u64,
}

/// The writing thread's pace over a member no crew takes, in crews, for
/// [`LaneFit::cost`]: its wave is the pool's width where a crew's is held
/// to four blocks, so its member goes faster than a crew's, and a reach
/// that leaves one large crew is no gain over it. Two is an estimate (the
/// one engine kept about four cores busy at level 1 on a 4 GiB set of
/// binaries, a crew one or two); a tie keeps the lane it had.
pub(super) const LEAD_PACE: u64 = 2;

/// The buffers of its largest member a large crew is charged past one
/// window (`Run::fit_large_lane`): the member pulled whole, its packed
/// bytes in the batch being encoded and in the batch being written, and
/// the pulled and packed buffers the team keeps for the next batch
/// (`Run::team_spare_most`, `Run::packed_pool_most`). The batch planned
/// ahead is not among them: it is planned only where the room for it is
/// left over (`Run::walk_team`).
pub(super) const LANE_BUFFERS: u64 = 5;

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    /// How many crews the worker team runs, or less than two where the
    /// walk is a member at a time.
    ///
    /// **The team is for a NON-SOLID, COMPRESSED run.** Each such member
    /// is encoded from nothing (spec H3 section 4), so members are
    /// independent and several can be encoded at once. A member of one
    /// parse block is one wave of width one, which is the whole set's
    /// width when the members go one at a time: 9,681 small members of
    /// the rivals round's set ran on about one core (27 Sep 2026). A
    /// solid set is one carried run and is batched as one instead
    /// (`Run::batch_solid`); a stored one has nothing to encode.
    ///
    /// Under a caller's ceiling the width is the least of four figures,
    /// each a bound somebody set:
    ///
    /// - the pool's width, which is what the crews run on;
    /// - `WriteOptions::workers`, the ENCODER'S width (API 7.2 and
    ///   8.2), which is what a crew is;
    /// - `MemoryPolicy::max_workers`, the memory ceiling on threads;
    /// - what the memory policy leaves the crews, over what one crew
    ///   costs. Under a CALLER'S ceiling (`Run::caller_ceiling`) that is
    ///   the ceiling less what the run holds beside the team
    ///   (`Run::beside_team_bytes`), over what a crew's finder really
    ///   takes (`Run::crew_bytes`): a budget the user set is hard, and
    ///   inside it the widest team is the fastest wall. A
    ///   fixed quarter of the ceiling was the rule before 28 Sep 2026, and
    ///   at `-mm256` it held small9k and one 20 MiB member to two crews
    ///   where four fitted, 0.674x the wall. At
    ///   the default policy it was a quarter of `working_limit` over
    ///   [`CREW_BYTES`], 128 MiB over 16, eight crews.
    ///
    /// **Where no ceiling was named the width is the pool's, held to
    /// `WriteOptions::workers` and to what the DEFAULT policy's
    /// `working_limit` affords at what a crew really holds**
    /// (`Run::crew_charge`), and `max_workers` is not in it. A default is
    /// not a budget anybody set, the fastest wall is the default's aim,
    /// and API 8.2 leaves `max_workers` the read and
    /// repair sides' dial; the eight crews both default
    /// figures came to held a non-solid set of 5,000 small members to
    /// about seven cores of eighteen, where the old engine ran about
    /// fifteen (counted 28 Sep 2026). The team's
    /// charged memory still stays inside the default's `working_limit`,
    /// which was the condition for widening it: a crew
    /// is a few MiB at levels 1 to 3 and about 15 MiB at the tree's, so
    /// on the widest box measured the pool binds first.
    pub(super) fn team_width(&self) -> usize {
        if self.options.solid || self.options.stored() {
            return 1;
        }
        let share = match self.dial_ceiling() {
            Some(limit) => {
                // At the tree's levels the hold does not widen the team
                // (`Run::chosen_hold`).
                let lead = self.hold.filter(|_| self.hold_widens_team());
                limit.saturating_sub(self.beside_team_bytes(lead)) / self.crew_bytes()
            }
            None => {
                // The large-member lane's width was fitted to the ceiling
                // when it was chosen (`Run::choose_large_lane`).
                if self.large_crews > 0 {
                    return self.large_crews + self.small_crews;
                }
                // No ceiling was named, so `max_workers` is not in this
                // expression either (see above).
                let limit = team_ceiling(self.options.memory.working_limit);
                let afford =
                    limit.saturating_sub(self.beside_team_bytes(None)) / self.crew_charge().max(1);
                return self
                    .pool_width()
                    .min(self.options.encoder_width())
                    .min(usize::try_from(afford).unwrap_or(usize::MAX));
            }
        };
        self.team_share(share)
    }

    /// The pool's width, which is what the crews run on: the write's own
    /// (`width::pool_width`), no wider than `workers`.
    pub(super) fn pool_width(&self) -> usize {
        width::pool_width()
    }

    /// The physical cores this write's encoders run on: the pool's width
    /// held to the encoder's and to the machine's physical cores
    /// (`cores::physical`: SMT siblings counted once, within the process's
    /// affinity mask), which is what the rules by cores read
    /// (`segment_engines`, `lane_reach_on`). A pool of sixteen threads on
    /// eight cores of two threads each is eight.
    pub(super) fn pool_cores(&self) -> usize {
        // Without the pool there is one thread and neither form runs.
        #[cfg(feature = "parallel")]
        let machine = crate::cores::physical();
        #[cfg(not(feature = "parallel"))]
        let machine = 1;
        cores_set().unwrap_or_else(|| {
            self.pool_width()
                .min(self.options.encoder_width())
                .min(machine)
        })
    }

    /// Chooses `Run::team_most`, the largest member the worker team takes.
    ///
    /// [`TEAM_MEMBER_MOST`], one parse block, under a caller's ceiling and
    /// wherever the team does not run. Where no ceiling was named: the
    /// fewest of 2, 4, 8 and [`TEAM_MEMBER_BLOCKS_MOST`] blocks that holds
    /// every member of that many blocks or fewer, stepped down while the
    /// crew it charges (`Run::crew_charge`, sized from the largest member
    /// taken) would narrow the team below the pool's width held to the
    /// encoder's: a wide team of one-block members is worth more than a
    /// narrower one that also takes the few larger members. A function of
    /// the options, the pool and the member table, so the choice is the
    /// same on every run of the same inputs, and it cannot move a byte:
    /// a crew encodes a member with the call the member-at-a-time walk
    /// makes for it (`pack_member`), whatever its size.
    pub(super) fn choose_team_most(&mut self) {
        self.team_most = TEAM_MEMBER_MOST;
        if self.options.solid || self.options.stored() || self.dial_ceiling().is_some() {
            return;
        }
        let want = self.pool_width().min(self.options.encoder_width());
        if want < 2 {
            return;
        }
        self.team_most = TEAM_MEMBER_BLOCKS_MOST * TEAM_MEMBER_MOST;
        let largest = (0..self.members.len())
            .filter(|&index| self.team_takes(index))
            .map(|index| self.members[index].size)
            .max()
            .unwrap_or(0);
        let mut blocks = 2;
        while blocks < TEAM_MEMBER_BLOCKS_MOST && blocks * TEAM_MEMBER_MOST < largest {
            blocks *= 2;
        }
        while blocks >= 2 {
            self.team_most = blocks * TEAM_MEMBER_MOST;
            if largest <= TEAM_MEMBER_MOST || self.team_width() >= want {
                return;
            }
            blocks /= 2;
        }
        self.team_most = TEAM_MEMBER_MOST;
    }

    /// Chooses the LARGE-MEMBER LANE: `Run::large_most` and
    /// `Run::large_crews`.
    ///
    /// **Why.** A member above `Run::team_most` was the writing thread's,
    /// one at a time, each a wave of its own few blocks. Measured black
    /// box, untimed on an Apple M3 Mac (32 cores), on tree5k's 50 members above
    /// one parse block (31 MB) written as a set of their own: the old
    /// engine ran them 18 to 20 wide at every level, rarkit 1.8 to 5.1
    /// wide; at level 1 rarkit spent LESS CPU (0.25 s against 0.40 at one
    /// thread) and was 4.3x the wall.
    ///
    /// **What.** Where no ceiling was named, members above `Run::team_most`
    /// and up to the lane's reach are taken by `K` crews of their own, the
    /// LARGE crews, and the rest by small crews. The reach is one window
    /// (`Run::window_bytes`), or past it as far as the rule by cores
    /// allows (`lane_reach_on`: [`LANE_REACH`], or the narrow pool's at
    /// levels 2 and 3, `lane_reach_narrow`) where the members held whole
    /// cost the team no crew (`Run::fit_large_lane`). A crew keeps the
    /// structures of the largest member it has encoded, so the two kinds
    /// are charged apart: large crews at the largest such member's real
    /// charge and small ones at theirs, inside the memory ceiling less
    /// what the run holds beside the team (`Run::beside_team_bytes`, which
    /// the lane shrinks, since those members leave the writing thread).
    /// The pool is split between the kinds by their input bytes, at least
    /// one crew of each and no more large crews than large members, and
    /// both are scaled down together until the charge fits, so the team
    /// may run narrower than the pool: on a 32 core box the small crews
    /// alone could spend the room and leave no large crew at all (counted
    /// on tree5k over the -m4 and -m5 memory lane's charges). Neither kind
    /// left, no lane. The bytes are the member-at-a-time walk's by
    /// `pack_member`'s argument, whatever the member's size.
    pub(super) fn choose_large_lane(&mut self) {
        self.large_most = 0;
        self.large_crews = 0;
        self.small_crews = 0;
        self.large_largest = 0;
        self.lane_charged = 0;
        if self.options.solid || self.options.stored() || self.dial_ceiling().is_some() {
            return;
        }
        let want = self.pool_width().min(self.options.encoder_width());
        let window = self.window_bytes() as u64;
        if want < 3 {
            return;
        }
        // One window, fitted as it always was, where the small crews do
        // not already take a window; and each reach PAST one window, from
        // [`LANE_REACH`] halved down to it, of which the one that costs
        // least is taken where it costs less than the lane without it.
        let inside = if window > self.team_most {
            self.fit_large_lane(window, want)
        } else {
            None
        };
        let mut past: Option<LaneFit> = None;
        let (mut reach, set) = lane_reach();
        // The rule by cores and level, which the sweep drew (the long
        // reach, or the narrow pool's short one at levels 2 and 3); a
        // test's reach is taken as it is.
        if !set {
            reach = lane_reach_on(self.options.method, self.pool_cores());
        }
        // Nor under a NAMED ceiling of any size (spec G 3.7.3): the lane
        // stays inside one window there. With the reach on, a process held
        // to `-mm2048m` at `-m1 -mt16` stood at 2,074 to 2,104 MiB of
        // footprint on macOS, the freed 64 MiB buffers of the reach staying
        // in it, where the writer stated 1,793 to 1,818 (counted 1 Oct
        // 2026); without it,
        // 1,665 to 1,718.
        if !set && self.caller_ceiling().is_some() {
            reach = 0;
        }
        while reach > window.max(self.team_most) {
            if let Some(fit) = self.fit_large_lane(reach, want) {
                if fit.past > 0 && past.as_ref().is_none_or(|best| fit.cost < best.cost) {
                    past = Some(fit);
                }
            }
            if set {
                break;
            }
            reach /= 2;
        }
        self.large_most = 0;
        let without = match &inside {
            Some(fit) => fit.cost,
            None => self.no_lane_cost(),
        };
        let Some(fit) = past.filter(|fit| set || fit.cost < without).or(inside) else {
            return;
        };
        self.large_most = fit.most;
        self.large_crews = fit.crews;
        self.small_crews = fit.smalls;
        self.large_largest = fit.past;
        self.lane_charged = fit.charged;
    }

    /// The walk's cost, in [`LaneFit::cost`]'s unit, with a worker team
    /// and no large-member lane: the members the small crews take over
    /// the team's width, and every other member at the writing thread's
    /// pace.
    pub(super) fn no_lane_cost(&self) -> u64 {
        let limit = team_ceiling(self.options.memory.working_limit);
        let afford = limit.saturating_sub(self.beside_team_bytes(None)) / self.crew_charge().max(1);
        let width = self
            .pool_width()
            .min(self.options.encoder_width())
            .min(usize::try_from(afford).unwrap_or(usize::MAX))
            .max(1) as u64;
        let (mut taken, mut rest) = (0u64, 0u64);
        for (index, member) in self.members.iter().enumerate() {
            if member.is_directory {
                continue;
            }
            if self.team_takes(index) {
                taken = taken.saturating_add(member.size);
            } else {
                rest = rest.saturating_add(member.size);
            }
        }
        (taken / width).saturating_add(rest / LEAD_PACE)
    }

    /// Fits the large-member lane at a reach of `most` bytes: the crews of
    /// each kind, what they are charged, and what the walk then costs; or
    /// nothing where no member is the lane's or memory leaves no crew of
    /// either kind. Leaves `Run::large_most` at `most`, which is what
    /// [`Run::team_takes`] reads while it fits.
    ///
    /// **Past one window** a crew's reader member is pulled whole, as it
    /// is inside one, and encoded with the held walk's own calls
    /// (`pack_member`), so the lane's bytes are still the member-at-a-time
    /// walk's. What it holds more is stated and charged: the member, its
    /// packed bytes in the batch being encoded and the batch being
    /// written, and the buffers kept between batches, five of the lane's
    /// largest member a crew ([`LANE_BUFFERS`]), beside the crew's own
    /// structures for a member that long. So the further the reach, the
    /// fewer crews the same memory affords, and [`LaneFit::cost`] is what
    /// the reaches are compared by.
    pub(super) fn fit_large_lane(&mut self, most: u64, want: usize) -> Option<LaneFit> {
        let window = self.window_bytes() as u64;
        self.large_most = most;
        // The team's members by kind: how many large ones, and the input
        // bytes of each kind, which is what the width is split by.
        let (mut large, mut large_bytes, mut small_bytes) = (0usize, 0u64, 0u64);
        let (mut largest, mut rest) = (0u64, 0u64);
        for index in 0..self.members.len() {
            let size = self.members[index].size;
            if self.team_takes(index) {
                if size > self.team_most {
                    large += 1;
                    large_bytes = large_bytes.saturating_add(size);
                    largest = largest.max(size);
                } else {
                    small_bytes = small_bytes.saturating_add(size);
                }
            } else if !self.members[index].is_directory {
                rest = rest.saturating_add(size);
            }
        }
        if large == 0 {
            return None;
        }
        let past = if largest > window { largest } else { 0 };
        let small = self.crew_charge_upto(self.team_most, None);
        let each = self
            .crew_charge_upto(most, Some(LARGE_CREW_HOLD))
            .saturating_add(LANE_BUFFERS.saturating_mul(past));
        let room = team_ceiling(self.options.memory.working_limit)
            .saturating_sub(self.beside_team_bytes(None));
        // The pool split between the two kinds by their bytes, at least
        // one crew each and no more large crews than large members; then
        // both scaled down together, the one further over its share first,
        // until the crews' charge fits the room. The team may so run
        // NARROWER than the pool: a few large crews beside fewer small
        // ones beat a full width of small ones that leaves the large
        // members to the writing thread one at a time.
        let total = large_bytes.saturating_add(small_bytes).max(1);
        let share = ((want as u64).saturating_mul(large_bytes) + total / 2) / total;
        let large0 = usize::try_from(share)
            .unwrap_or(usize::MAX)
            .clamp(1, (want - 1).min(large));
        let small0 = want - large0;
        let (mut crews, mut smalls) = (large0, small0);
        let held = |crews: usize, smalls: usize| {
            (smalls as u64)
                .saturating_mul(small)
                .saturating_add((crews as u64).saturating_mul(each))
        };
        while crews > 0 && held(crews, smalls) > room {
            // Cut whichever kind is further above its share of the split.
            if crews * small0 > smalls * large0 || smalls <= 1 {
                crews -= 1;
            } else {
                smalls -= 1;
            }
        }
        if crews == 0 || smalls == 0 {
            return None;
        }
        Some(LaneFit {
            most,
            crews,
            smalls,
            past,
            charged: held(crews, smalls),
            cost: (large_bytes / crews as u64)
                .max(small_bytes / smalls as u64)
                .saturating_add(rest / LEAD_PACE),
        })
    }

    /// The team's width where the memory policy affords `share` crews:
    /// that, held to the pool's, the encoder's width and the policy's
    /// thread ceiling. `Run::team_width` less its solid and stored rule.
    pub(super) fn team_share(&self, share: u64) -> usize {
        let afford = usize::try_from(share).unwrap_or(usize::MAX);
        self.pool_width()
            .min(self.options.encoder_width())
            .min(self.options.memory.max_workers)
            .min(afford)
    }

    /// Whether the members the worker team takes are at least half of the
    /// run's bytes, at the team's members as they are chosen now
    /// (`Run::team_takes`): what `Run::hold_widens_team` asks at the
    /// tree's levels, asked at every level for `Run::choose_rung`.
    pub(super) fn team_has_most_bytes(&self) -> bool {
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

    /// Whether the worker team encodes member `index`.
    ///
    /// A member of at most `Run::team_most` bytes (`Run::choose_team_most`):
    /// a larger one is the writing thread's, a wave of its own width. Not
    /// a member the streamed walk takes, whose packed bytes
    /// are never held whole (a small member never is one). And either
    /// bytes in memory, or a READER of at most one window: a reader is
    /// pulled ahead of where the writer is writing, by the writing
    /// thread and in `add` order ([`Run::pull_whole`]). In a VOLUME SET
    /// too, since 1 Oct 2026: a caller that reported volume boundaries
    /// against the member it last pulled from (the CLI's progress lines
    /// did) saw a boundary land on the wrong member, which kept a
    /// reader out, and 5,000 members of a set in volumes went a member at
    /// a time at 3x to 6x the wall of the same set in one archive; the
    /// writer now says which member it has taken up
    /// (`Progress::member_started`, `Run::announce`). Nothing is
    /// discarded at a boundary here: a non-solid member is encoded from
    /// nothing, so its packed bytes are the same wherever it lands.
    pub(super) fn team_takes(&self, index: usize) -> bool {
        self.team_takes_upto(index, self.team_most.max(self.large_most))
    }

    /// Whether a worker team MAY run beside the lead in this write: what a
    /// caller's named ceiling charges the team's terms by
    /// (`Run::named_most_bytes`, FROM-STUDIO 840). A set neither solid nor
    /// stored, a pool and an encoder two threads wide or more, and a member
    /// the team would take at the largest it can be given to take: up to
    /// [`TEAM_MEMBER_BLOCKS_MOST`] parse blocks (`Run::choose_team_most`),
    /// and up to one window by the large-member lane, whose reach stays
    /// inside one window under a named ceiling (`Run::choose_large_lane`).
    /// Asked before either is chosen, so it errs towards yes.
    pub(super) fn team_may_run(&self) -> bool {
        if self.options.solid
            || self.options.stored()
            || self.pool_width().min(self.options.encoder_width()) < 2
        {
            return false;
        }
        let most = (TEAM_MEMBER_BLOCKS_MOST * TEAM_MEMBER_MOST)
            .max(self.window_bytes() as u64)
            .max(self.team_most)
            .max(self.large_most);
        (0..self.members.len()).any(|index| self.team_takes_upto(index, most))
    }

    /// [`Run::team_takes`] for a team given members of up to `most` bytes.
    fn team_takes_upto(&self, index: usize, most: u64) -> bool {
        let member = &self.members[index];
        if member.is_directory || member.size == 0 || member.size > most {
            return false;
        }
        if self.streams_packed(index) {
            return false;
        }
        // A member spec G 3.8.3's samples STORE is the writing thread's: no
        // crew encodes what is written stored (`Run::plan_batch` takes the
        // verdict as it plans).
        if self.stored_by_sample[index] {
            return false;
        }
        match member.payload {
            Payload::Bytes(_) => true,
            // A reader is pulled whole (`Run::pull_whole`), so it is the
            // team's only where it is one window, which the windowed
            // encode holds of it anyway: spec G 3.7.3's input is never
            // held past a window.
            // Past a window only where the large-member lane reaches
            // (`Run::choose_large_lane`), whose charge counts the member
            // held whole.
            // In a VOLUME SET only up to a window: a longer reader there
            // keeps the walk it had (held, or streamed across the
            // boundary), which this change neither counted nor altered.
            Payload::Reader { .. } => {
                let window = self.window_bytes() as u64;
                if self.options.volume_set() {
                    member.size <= window
                } else {
                    member.size <= window.max(self.large_most)
                }
            }
        }
    }
}
