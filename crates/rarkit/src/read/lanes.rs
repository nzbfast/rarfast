//! The tape lanes every member decoding at once may open BETWEEN them.
//!
//! SPEC-API 8.2's table gives the row for 8.3 as "at most `max_workers`
//! decode units over all members together", and 8.3 as the PRODUCT of the
//! members decoded at once and the width inside each of them. A driver
//! that budgets only the breadth multiplies instead: on 20 Sep 2026 eight
//! members at a ceiling of eight ran sixty four lanes, measured.
//!
//! **Why a reservation and not a division.** Dividing the ceiling by the
//! pool's width is sound and is what shipped first, but it spends the
//! ceiling on slots rather than on work: a caller that asks for a breadth
//! of eight on a two member archive gets two members at a width of one
//! and leaves six units unspent, which measured 0.86 s against 0.35 s on
//! two 256 MiB members. Dividing by the members in FLIGHT is what that
//! wants and is unsound on its own, because a grant made while the pool
//! was quiet is still outstanding when the pool fills.
//!
//! A reservation is both: a member takes its share of what is free, and
//! GIVES IT BACK at the end of every chunk, so a grant made when the pool
//! was quiet lasts one chunk and no longer.
//!
//! **The ceiling is HARD, at every instant, and that includes a member's
//! own unit.** This header used to say the reservation alone made it so.
//! It did not: a member was ADMITTED unconditionally, so a member that
//! arrived while another held the whole ceiling for its chunk made the
//! units in flight the ceiling plus one until that chunk ended. Found 29
//! Sep 2026 by `tests/thread_width.rs` failing under load ("a read width
//! of 2 and the decode ran 3 blocks at once"), named by an instrument that
//! recorded every holder: a member's lanes at the full width, and a second
//! member decoding at a width of one on its own thread. A user's width,
//! like their memory budget, is never exceeded even for a moment (SPEC-API
//! 8.4.2 bounds the members and the lanes together), so now the member's
//! unit is part of the reservation: [`LaneBudget::member_in`] admits a
//! member only when its unit fits beside every member and every lane
//! already out, and a member that finds the ceiling spent WAITS until a
//! grant or a member gives units back. The members and the lanes are one
//! word, so an admission and a grant can never both pass on a reading
//! that the other has already spent.
//!
//! **Why the wait cannot deadlock.** A member waits holding nothing. A
//! member holding units holds them only inside its own decode, and that
//! decode never waits on another member while a member waits for a unit:
//! its bytes go to the caller's writer, to a look-ahead slot, or to a ring
//! a thread that holds no unit drains, and a member that spans a volume
//! (the one decode that reports `volume_done` from inside itself) runs
//! only once the look-ahead has drained. So every holder finishes its
//! chunk or its member on its own, and every wait ends.
//!
//! **The look-ahead slot is the one place that takes care.** It was
//! unbounded when the paragraph above was first written, and since
//! 7 Oct 2026 a worker filling one is held back while the look-ahead holds
//! a window of bytes its caller has not taken (`sequential::Gate`). A
//! worker held there is a holder waiting on the walking thread, and the
//! walking thread decodes members of its own, each of which takes a unit
//! here: with the ceiling's units all in held workers' hands, the walk
//! waited for a unit, delivered nothing, and nothing moved again
//! (`rarfast p -mt4` on five large members that barely pack and a
//! directory entry, 8 Oct 2026). So a holder that waits for anything
//! outside its decode waits in [`Yield::park_while`], which lets it go for
//! as long as any member waits for a unit, and [`LaneBudget::member_in`]
//! wakes whoever is parked there before it waits. That is the premise
//! above made a rule instead of an observation: no holder is parked while
//! a member waits FOR WHAT THAT HOLDER HAS.
//!
//! **What a waiting member may ask of a parked holder** (10 Oct 2026).
//! The rule was first "no holder is parked while a member waits", every
//! holder and for as long as the wait: and a worker let go passes the
//! gate, so for that long the look-ahead had no window. Four stored
//! members of a gibibyte, each behind a small one, read by the walk in
//! order at a width of three to eight: 150 MB in one run and one, two or
//! three whole members more in the next, by whether a member happened to
//! wait while a stored one sat at the gate with the ceiling's lanes. A
//! member waits for one of two things, and each has its own holders:
//!
//! - a LANE: the members out are fewer than the ceiling, so what is in the
//!   way is the lanes of somebody's chunk. Only a parked holder of lanes
//!   is let go, and only to the end of the chunk it holds them for. At its
//!   next chunk it takes none while the gate would hold it
//!   ([`Yield::park_while`] remembers, [`LaneBudget::take`] asks), so it
//!   parks again holding its own unit and nothing a member can wait for.
//!   A holder parked with its own unit alone stays parked.
//! - a MEMBER'S OWN UNIT: the members out are the whole ceiling, so no
//!   chunk's end helps and one of them has to finish. Every parked holder
//!   is let go, as before. The look-ahead runs one worker fewer than its
//!   width beside the walk, so there this is a width of one.
//!
//! And the wait itself is short, WHERE HOLDERS WAIT AT A GATE: there a
//! member waiting is counted as a member where a chunk's share is worked
//! out ([`LaneBudget::take`]), so the members decoding leave it a unit at
//! their next chunk. Before, the share was of the members ADMITTED, and a
//! member alone took every lane again a chunk after giving them back,
//! with a member waiting 80 to 370 ms beside it (counted). A budget with
//! no gate, the parallel pool's, shares exactly as it did: no holder of
//! its units is ever parked, so a long wait there holds no bytes, and
//! counting the waiting there moved one of its rows (extraction of a
//! set of four at a width of 8 on a 20 thread Apple machine, 0.985 and
//! 0.981 of the parent in two sittings of fifteen, the same row level on
//! x86-64).
//!
//! **And a chunk is short where its holder can be held.** A coded member's
//! chunk is a few blocks. A STORED member's was a gibibyte
//! (`concurrent::GRANT_SLICE`), which for a like member is the member: let go
//! "to the end of its chunk", it was let go whole. So a budget whose
//! holders wait at a gate grants a stored member's lanes a quarter of the
//! gate's window at a time ([`LaneBudget::held_at`]). The lanes
//! themselves stay: sent at a width of one instead, a stored set of
//! many members printed to nowhere read 0.59 to 0.91 of its wall on an 8 core Zen 4
//! (K=15), the walking thread folding every checksum the lanes had
//! folded abreast.
//!
//! **What makes it cheap.** `Rar5Lz::member_planned` already runs once per
//! chunk and `member_piped` already creates its lanes inside a
//! `std::thread::scope` that joins them before it returns, so the release
//! point exists in the shape of the code and nothing about the hand-over
//! changes. The shrink is therefore one chunk late, which on a 256 MiB
//! member is a few percent of its decode and on a member of one chunk is
//! nothing at all.
//!
//! **The accounting, in units.** A member decoding at a width of one is
//! ONE unit: it opens no lane, `member_piped` is not entered, and the
//! member's own thread does the decoding. A member at a width above one
//! is `w` units: `w` lane threads decode and its own thread becomes the
//! apply stage, which decodes nothing. So the units are the sum of the
//! widths, and every member needs at least one. The breadth is at most the
//! ceiling (`extract_parallel_with` mins the caller's request against it),
//! so every member's floor is affordable EVENTUALLY; it is not affordable
//! at the moment another member's chunk holds the extras, and that moment
//! is what the admission waits out.

use std::cell::Cell;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

/// WHERE A HOLDER OF UNITS WAITS FOR SOMETHING OUTSIDE ITS DECODE, and the
/// count of members waiting for a unit, which lets it go (this module's
/// header, "the look-ahead slot is the one place that takes care").
///
/// One a budget, shared with whatever parks that budget's holders: the
/// look-ahead's gate. The two counts are read and written in the opposite
/// order by the two sides, each under or behind the one lock, so a member
/// that begins to wait and a holder that begins to park cannot both miss
/// the other: the member counts itself and then looks for parked holders,
/// the holder counts itself and then looks for waiting members.
#[derive(Debug, Default)]
pub(crate) struct Yield {
    /// Members parked in [`LaneBudget::member_in`].
    wanting: AtomicUsize,
    /// Those of them that wait for a member's own unit: the members out
    /// are the whole ceiling, and no chunk's end admits them.
    starving: AtomicUsize,
    /// Holders parked in [`Yield::park_while`].
    parked: AtomicUsize,
    lock: Mutex<()>,
    moved: Condvar,
}

thread_local! {
    /// The lanes the calling thread holds beyond its member's own unit
    /// ([`LaneGrant`], taken and given back on the one thread).
    static LANES_HERE: Cell<usize> = const { Cell::new(0) };
    /// The gate had the calling thread wait, or would have, the last time
    /// it came to it ([`Yield::park_while`]); cleared when it passes
    /// unasked ([`Yield::passed`]) and at each member's start.
    static HELD_BACK: Cell<bool> = const { Cell::new(false) };
}

impl Yield {
    /// Whether a member is waiting for a unit.
    fn wanted(&self) -> bool {
        self.wanting.load(Ordering::SeqCst) > 0
    }

    /// Whether a parked holder is let go: a member waits for a member's
    /// own unit, or it waits for a lane and this holder has lanes (this
    /// module's header, "what a waiting member may ask of a parked
    /// holder").
    fn gives_way(&self, lanes: bool) -> bool {
        self.starving.load(Ordering::SeqCst) > 0 || (lanes && self.wanted())
    }

    /// The calling thread came to what holds it back and was let through
    /// unasked: its next chunk takes its share of the lanes again.
    #[inline(always)]
    pub(crate) fn passed() {
        HELD_BACK.with(|held| {
            if held.get() {
                held.set(false);
            }
        });
    }

    /// The holders parked here.
    #[inline(always)]
    pub(crate) fn parked(&self) -> usize {
        self.parked.load(Ordering::SeqCst)
    }

    /// Wake every holder parked here, to look again. The lock is taken
    /// only when one is parked, and taken at all so that a holder between
    /// its test and its wait cannot miss this.
    #[inline(always)]
    pub(crate) fn wake(&self) {
        if self.parked() > 0 {
            drop(self.lock.lock().unwrap_or_else(|e| e.into_inner()));
            self.moved.notify_all();
        }
    }

    /// Park the calling thread, which may hold units, for as long as
    /// `held` answers true AND no member waits for what it holds
    /// ([`Yield::gives_way`]). `held` is asked again after every
    /// [`Yield::wake`].
    pub(crate) fn park_while(&self, mut held: impl FnMut() -> bool) {
        let lanes = LANES_HERE.with(Cell::get) > 0;
        let mut guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        // Counted under the lock, so a `wake` that reads the count after
        // changing what `held` or `gives_way` reads either sees this
        // holder and takes the lock behind it, or changed it before the
        // test below.
        self.parked.fetch_add(1, Ordering::SeqCst);
        let mut asked = false;
        while held() {
            // Held back, whether or not a waiting member lets it go: its
            // next chunk takes no lane to sit on ([`LaneBudget::take`]).
            asked = true;
            HELD_BACK.with(|back| back.set(true));
            if self.gives_way(lanes) {
                break;
            }
            guard = self.moved.wait(guard).unwrap_or_else(|e| e.into_inner());
        }
        self.parked.fetch_sub(1, Ordering::SeqCst);
        drop(guard);
        if !asked {
            // Nothing held it after all (the front member with its slot
            // near empty): through unasked.
            Self::passed();
        }
    }
}

/// The members in flight and the extra lanes out, as ONE word: members in
/// the high half, extras in the low. One word so that `member_in` and
/// `take` read the same state and move it by one compare and swap.
const MEMBER: u64 = 1 << 32;

/// The members and the extras in a units word.
fn split(units: u64) -> (usize, usize) {
    ((units >> 32) as usize, (units & (MEMBER - 1)) as usize)
}

/// The fewest lanes at which opening the tape path buys anything.
///
/// **This is a fact about the code and not a figure from a
/// specification, and a reader should not go looking for the spec line.**
/// `Rar5Lz::member_planned` enters `member_piped` on `self.overlap &&
/// lanes > 1` and on nothing else, so a member granted one lane decodes
/// wave at a time on its own thread whatever else is true of it. SPEC-H2
/// states no lane floor: its section 7.3 lists ten structural
/// requirements and none of them is one, and its only lane arithmetic is
/// section 0's descriptive "up to eight worker threads", which is an
/// 18 Sep 2026 snapshot of the carried policy. SPEC-API 8.2's "a stage
/// that runs narrower, or that never threads at all, is in contract" is
/// the nearest rule, and it permits one lane rather than recommending it.
///
/// So two is the smallest width that is WORTH GRANTING. Granting one is
/// not wrong; it is simply indistinguishable from granting none, which is
/// what makes a division that hands out ones a division that has spent
/// nothing.
pub(crate) const MIN_USEFUL_LANES: usize = 2;

/// The breadth a ceiling can actually afford a useful width inside.
///
/// **The zero-lane floor, stated as the rule the code follows** (SPEC-API
/// 8.3, which makes the breadth and the width one product against one
/// ceiling, and the goal, which is the lowest wall inside the memory
/// budget). A ceiling divided by a breadth larger than half of
/// it leaves every member below [`MIN_USEFUL_LANES`], so the product
/// buys breadth and nothing else, and the remainder of the division is
/// spent by nobody. Found at a read width of six over four 20 MiB `-m1`
/// members: six divided by four is one, no member entered the tape path,
/// and two units of the six were never spent.
///
/// This narrows the BREADTH so that every member in flight has a width
/// worth having. It is one of the two arrangements SPEC-API 8.3 leaves to
/// measurement, the other being to spend the remainder and keep the
/// breadth ([`LaneBudget`]'s spill), and the arms of
/// the breadth driver script are what choose between them.
///
/// Never below one, and never above what was asked: widening a caller's
/// breadth request is not this function's to do.
pub(crate) fn useful_breadth(ceiling: usize, asked: usize) -> usize {
    let ceiling = ceiling.max(1);
    let asked = asked.max(1);
    if ceiling / asked >= MIN_USEFUL_LANES {
        return asked;
    }
    (ceiling / MIN_USEFUL_LANES).max(1).min(asked)
}

/// THE CORES ARE SHARED TOO, between members decoded abreast at the
/// default width: the most lanes each of `members` decoded at once may open
/// on `cores` physical cores, so that every member's lanes AND its apply
/// thread have a core. The cores less one a member, divided between the
/// members, and never under [`MIN_USEFUL_LANES`].
///
/// **Why, measured** (3 Oct 2026; a 48 core Xeon
/// with two threads a core, quiet). The default width's
/// ceiling is the pool's width, which counts hardware THREADS, and a
/// member's unit in the budget is its lanes and not its apply thread. So
/// eight 512 MiB members abreast were each offered twelve lanes, took the
/// eight a member may open, and ran 64 lanes and eight applies on 48
/// cores: 0.539 s, where five lanes a member read 0.489, four 0.499 and
/// six 0.505. Twelve, sixteen and twenty four 256 MiB members read lowest
/// at three or four, three, and two lanes a member (0.311 against 0.431 at
/// eight; 0.355 against 0.493; 0.468 against 0.607, where one lane read
/// 0.505). Two and four members abreast read lowest at the eight lanes
/// they already had, which this share leaves them.
pub(crate) fn abreast_lanes(cores: usize, members: usize) -> usize {
    let members = members.max(1);
    (cores.saturating_sub(members) / members).max(MIN_USEFUL_LANES)
}

/// COUNT KNOB: the cores members abreast share ([`abreast_cores`]) on any
/// machine, `0` for none (the budget before this rule), so one binary
/// carries both arms on one box. Nothing ships setting it.
pub(crate) const ABREAST_CORES_ENV: &str = "RARKIT_ABREAST_CORES";

/// The physical cores that members decoded abreast share, for a read whose
/// width the caller did or did not state: `None` for a stated width (the
/// dial is the caller's, and its ceiling already divides between the
/// members) and on a machine with no row behind such a share.
pub(crate) fn abreast_cores(stated: bool) -> Option<usize> {
    static CORES: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    if stated {
        return None;
    }
    *CORES.get_or_init(|| {
        let knob = crate::knob::reader_var(ABREAST_CORES_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok());
        match knob {
            Some(0) => None,
            Some(n) => Some(n),
            None => abreast_cores_on(
                crate::cores::physical(),
                cfg!(all(target_os = "linux", target_arch = "x86_64")),
            ),
        }
    })
}

/// [`abreast_cores`] on a machine of `cores` physical cores that is, or is
/// not, x86-64 Linux: the cores from that system's line up
/// (`tape::STEADY_CORES_X86_LINUX`, the 48 core Xeon the rows are from)
/// and `None` under it and on every other system. An 8 core Zen 4 has rows
/// and no rule: its two and four members abreast read lowest with the
/// lanes they have, and its eight read 0.588 s at one lane a member
/// against 0.609 at the two the budget gives, which is the breadth's
/// question and not this share's. Apple silicon has no row yet.
const fn abreast_cores_on(cores: usize, x86_linux: bool) -> Option<usize> {
    if x86_linux && cores >= crate::rar5_lz::tape::STEADY_CORES_X86_LINUX {
        Some(cores)
    } else {
        None
    }
}

/// What the members decoding at once may spend between them.
#[derive(Debug)]
pub(crate) struct LaneBudget {
    /// The read's width (`ReadOptions::workers` as 8.4.2 resolves it),
    /// the whole of what may be in flight.
    ceiling: usize,
    /// Members being decoded right now, each holding one unit, and the
    /// units reserved BEYOND the one each of them holds, in one word
    /// ([`MEMBER`]). Together they never pass `ceiling`.
    units: AtomicU64,
    /// The members parked in [`LaneBudget::member_in`], counted where a
    /// holder parked outside its decode reads them ([`Yield`]), so a unit
    /// given back takes the lock below only when somebody is waiting for
    /// it.
    place: Arc<Yield>,
    /// What a waiting member parks on.
    gate: Mutex<()>,
    freed: Condvar,
    /// Whether the REMAINDER of the fair share is handed out.
    spill: bool,
    /// Remainder units out, so the remainder is spread one member at a
    /// time instead of piling on whoever asks first. Zero unless
    /// `spill`.
    spilled: AtomicUsize,
    /// The members the pool was asked to keep in flight
    /// ([`LaneBudget::asked`]); one where nobody said.
    breadth: usize,
    /// The physical cores members decoded ABREAST share at the default
    /// width ([`abreast_cores`]); `None` where the share is the ceiling's
    /// alone, which is every stated width and every machine under its
    /// system's line.
    cores: Option<usize>,
    /// The most bytes of a stored member read under ONE grant of lanes
    /// ([`LaneBudget::held_at`]); no bound of this budget's own where its
    /// holders are never held.
    grant_bytes: u64,
    /// Whether this budget's holders wait at a gate
    /// ([`LaneBudget::held_at`]): where they do, a member waiting is
    /// counted in a chunk's share.
    gated: bool,
}

impl LaneBudget {
    /// The budget with the remainder FLOORED away, which is the
    /// arrangement before the zero-lane floor was found. Kept for the
    /// unit tests that pin the defect and the fix against each other.
    #[cfg(test)]
    pub(crate) fn new(ceiling: usize) -> LaneBudget {
        LaneBudget::with_spill(ceiling, false)
    }

    /// The budget with the remainder of the fair share spendable.
    pub(crate) fn with_spill(ceiling: usize, spill: bool) -> LaneBudget {
        LaneBudget {
            ceiling: ceiling.max(1),
            units: AtomicU64::new(0),
            place: Arc::default(),
            gate: Mutex::new(()),
            freed: Condvar::new(),
            spill,
            spilled: AtomicUsize::new(0),
            breadth: 1,
            cores: None,
            grant_bytes: u64::MAX,
            gated: false,
        }
    }

    /// The same budget, for holders that wait at a gate of `window` bytes
    /// (the look-ahead's; zero is no gate and changes nothing): a stored
    /// member's lanes are granted a quarter of the window at a time, a
    /// mebibyte at least, so a holder held with lanes has them for that
    /// much and no more; and a member waiting is counted in a chunk's
    /// share.
    pub(crate) fn held_at(mut self, window: u64) -> LaneBudget {
        if window > 0 {
            self.grant_bytes = (window / 4).max(1 << 20);
            self.gated = true;
        }
        self
    }

    /// The most bytes of a stored member one grant of this budget's lanes
    /// covers.
    pub(crate) fn grant_bytes(&self) -> u64 {
        self.grant_bytes
    }

    /// The same budget, sharing `cores` physical cores between the members
    /// decoded abreast ([`abreast_lanes`]); `None` changes nothing.
    pub(crate) fn abreast_on(mut self, cores: Option<usize>) -> LaneBudget {
        self.cores = cores;
        self
    }

    /// The most lanes one of `members` decoded at once may open: the whole
    /// of `share` for a member alone or with no core count to share.
    fn abreast(&self, share: usize, members: usize) -> usize {
        match self.cores {
            Some(cores) if members > 1 => share.min(abreast_lanes(cores, members)),
            _ => share,
        }
    }

    /// The same budget, told the breadth its pool was asked for: the
    /// members that WILL be in flight, which [`LaneBudget::take`]'s fair
    /// share cannot see (it divides by the members admitted so far).
    pub(crate) fn asked(mut self, breadth: usize) -> LaneBudget {
        self.breadth = breadth.max(1);
        self
    }

    /// The units one member may hold, its own among them, if every member
    /// of the breadth asked for is to fit beside it: the whole ceiling for
    /// a pool of one, never under one.
    pub(crate) fn share_of_breadth(&self) -> usize {
        self.abreast((self.ceiling / self.breadth).max(1), self.breadth)
    }

    /// Where a holder of this budget's units parks when it waits for
    /// something outside its decode ([`Yield`]).
    pub(crate) fn place(&self) -> Arc<Yield> {
        Arc::clone(&self.place)
    }

    /// Count one member in for as long as the returned slot lives,
    /// WAITING first while its unit does not fit beside the members and
    /// the lanes already out (this module's header says why the ceiling
    /// is hard and why the wait ends).
    pub(crate) fn member_in(&self) -> MemberSlot<'_> {
        // A new member on this thread: what the gate asked of the last
        // one is not asked of this one.
        Yield::passed();
        if !self.admit() {
            #[cfg(feature = "wait-census")]
            let _census = crate::probe::census::at(crate::probe::census::ADMIT_WAIT);
            let mut gate = self.gate.lock().unwrap_or_else(|e| e.into_inner());
            self.place.wanting.fetch_add(1, Ordering::SeqCst);
            // The units this member waits for may be in the hands of
            // holders parked outside their decode: those that hold what it
            // waits for go on from here until it is admitted ([`Yield`]).
            self.place.wake();
            // Whether it waits for a member's own unit is read again at
            // every wake: the lanes it waited for may have come back and
            // gone to a member admitted ahead of it. A unit given back
            // takes the lock this thread holds until it waits, so no such
            // change is missed.
            let mut starving = false;
            while !self.admit() {
                if !starving && self.members() >= self.ceiling {
                    starving = true;
                    self.place.starving.fetch_add(1, Ordering::SeqCst);
                    self.place.wake();
                }
                gate = self.freed.wait(gate).unwrap_or_else(|e| e.into_inner());
            }
            if starving {
                self.place.starving.fetch_sub(1, Ordering::SeqCst);
            }
            self.place.wanting.fetch_sub(1, Ordering::SeqCst);
        }
        MemberSlot {
            budget: self,
            #[cfg(feature = "wait-census")]
            _census: crate::probe::census::at(crate::probe::census::MEMBERS),
        }
    }

    /// Take one member's unit if it fits. A member ALONE always fits: the
    /// ceiling is at least one and no grant outlives the member holding it.
    fn admit(&self) -> bool {
        let mut now = self.units.load(Ordering::SeqCst);
        loop {
            let (live, extra) = split(now);
            if live > 0 && live + extra >= self.ceiling {
                return false;
            }
            match self.units.compare_exchange_weak(
                now,
                now + MEMBER,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(seen) => now = seen,
            }
        }
    }

    /// Give `units` back and wake whoever waits for them. The lock is
    /// taken only when a member is parked, and taken at all so that a
    /// member between its last `admit` and its `wait` cannot miss this.
    fn give_back(&self, units: u64) {
        self.units.fetch_sub(units, Ordering::SeqCst);
        if self.place.wanted() {
            drop(self.gate.lock().unwrap_or_else(|e| e.into_inner()));
            self.freed.notify_all();
        }
    }

    /// The members being decoded right now, this caller's own among them
    /// where it holds a slot.
    pub(crate) fn members(&self) -> usize {
        split(self.units.load(Ordering::SeqCst)).0
    }

    /// The units in flight, members and lanes together, for the tests.
    #[cfg(test)]
    fn in_flight(&self) -> usize {
        let (live, extra) = split(self.units.load(Ordering::SeqCst));
        live + extra
    }

    /// The lanes one member may open NOW, wanting `want` of them.
    ///
    /// Never fewer than one, and never so many that the units in flight
    /// pass the ceiling. `want` is already the size floor's and the
    /// engine's own answer; this only says how much of it the budget can
    /// afford beside the other members.
    pub(crate) fn take(&self, want: usize) -> LaneGrant<'_> {
        // A thread the gate is holding back takes no lane to sit on: it
        // decodes this chunk on its own unit, which no member waits for
        // while the members out are under the ceiling (this module's
        // header).
        let want = if HELD_BACK.with(Cell::get) { 1 } else { want };
        // A MEMBER WAITING IS A MEMBER, where holders wait at a gate: the
        // share is of the members out and the members waiting to be, and
        // each of those is left its unit below, so a wait ends with the
        // chunk it began in. A budget with no gate shares as it always
        // has (this module's header).
        let waiting = if self.gated {
            self.place.wanting.load(Ordering::SeqCst)
        } else {
            0
        };
        let live = (split(self.units.load(Ordering::Acquire)).0 + waiting).max(1);
        // The FAIR share, so two members do not settle into a lopsided
        // seven and one that then swaps every chunk. A member alone in
        // the pool gets the whole ceiling by the same line.
        let share = (self.ceiling / live).max(1);
        // THE REMAINDER, AND THE WHOLE OF THE ZERO-LANE FLOOR. The line
        // above FLOORS, so at a ceiling of six over four members every
        // member is offered one lane and two units of the six are
        // offered to nobody at all. One lane is not a narrow tape
        // decode, it is no tape decode: `member_planned` enters
        // `member_piped` on `lanes > 1` (see `MIN_USEFUL_LANES`), so the
        // floor does not merely waste the remainder, it costs every
        // member in flight its overlap.
        //
        // The remainder is handed out ONE UNIT PER MEMBER, to the first
        // members that ask, so that it is spread rather than piled on
        // whoever asks first: a ceiling of twelve over five members
        // becomes three, three, two, two, two and never three, three,
        // three, two, ONE, which would leave the last member below the
        // floor this exists to lift it off.
        let spare = if self.spill {
            self.ceiling.saturating_sub(share.saturating_mul(live))
        } else {
            0
        };
        let mut spilled = false;
        let mut cap = share;
        if spare > 0 && want > share {
            let mut out = self.spilled.load(Ordering::Acquire);
            while out < spare {
                match self.spilled.compare_exchange_weak(
                    out,
                    out + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        spilled = true;
                        cap = share + 1;
                        break;
                    }
                    Err(now) => out = now,
                }
            }
        }
        // Members abreast at the default width share the CORES too, each
        // with its apply thread counted ([`abreast_lanes`]).
        let cap = self.abreast(cap, live);
        let wanted_extra = want.min(cap).saturating_sub(1);
        let mut extra = 0;
        if wanted_extra > 0 {
            let mut now = self.units.load(Ordering::SeqCst);
            loop {
                // What is free is the ceiling less the unit every live
                // member holds and the extras already out, read from the
                // one word an admission moves too.
                let (members, held) = split(now);
                let free = self
                    .ceiling
                    .saturating_sub((members + waiting).max(1))
                    .saturating_sub(held);
                let grant = wanted_extra.min(free);
                if grant == 0 {
                    break;
                }
                match self.units.compare_exchange_weak(
                    now,
                    now + grant as u64,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => {
                        extra = grant;
                        break;
                    }
                    Err(seen) => now = seen,
                }
            }
        }
        if spilled && extra == 0 {
            // The remainder unit was reserved and then the general pot
            // had nothing free to spend it on. Give it back NOW rather
            // than at the end of the chunk, so the next member to ask
            // sees a remainder that is honestly there.
            self.spilled.fetch_sub(1, Ordering::AcqRel);
            spilled = false;
        }
        // The instrument, and it is the whole of what this work added to
        // the shipped path: without `test-support` the module that reads
        // it does not exist and this line is not compiled.
        #[cfg(feature = "test-support")]
        crate::probe::note_lane_grant(extra + 1, live);
        LANES_HERE.with(|here| here.set(here.get() + extra));
        LaneGrant {
            budget: self,
            extra,
            spilled,
            _here: PhantomData,
        }
    }
}

/// One member's place in the budget, given back when it finishes.
pub(crate) struct MemberSlot<'a> {
    budget: &'a LaneBudget,
    #[cfg(feature = "wait-census")]
    _census: crate::probe::census::At,
}

impl Drop for MemberSlot<'_> {
    fn drop(&mut self) {
        self.budget.give_back(MEMBER);
    }
}

/// One chunk's lanes, given back when the chunk's scope joins.
pub(crate) struct LaneGrant<'a> {
    budget: &'a LaneBudget,
    extra: usize,
    /// Whether one of this chunk's units came out of the remainder pot.
    spilled: bool,
    /// Given back on the thread that took it, which is where its lanes
    /// are counted for [`Yield::park_while`].
    _here: PhantomData<*const ()>,
}

impl LaneGrant<'_> {
    /// The width this chunk may run at, its own unit included.
    pub(crate) fn lanes(&self) -> usize {
        self.extra + 1
    }
}

impl Drop for LaneGrant<'_> {
    fn drop(&mut self) {
        if self.extra > 0 {
            LANES_HERE.with(|here| here.set(here.get().saturating_sub(self.extra)));
            self.budget.give_back(self.extra as u64);
        }
        if self.spilled {
            self.budget.spilled.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// The decode-ahead's lanes when the caller states no width.
///
/// **Measured, not derived** (SPEC-API 8.4.3 asks every default to be the
/// figure that measures the lowest wall; the 22 Sep
/// 2026 width curve of `f/extract-solid290-m3` and its pricing on two
/// archives). The decode-ahead (`rar5_lz::ahead`) feeds ONE serial apply
/// stage, so what a solid chain can use is the ratio of a member's decode
/// to its apply and not the box's width. On that leg one lane left the
/// apply waiting on 235 of 289 members, and every lane past a few made the
/// wall WORSE, monotonically, to 5.92 ms at thirty two on a 32 core box
/// against 4.22 at two: a lane past what the chain needs costs its own
/// thread start and join, and it parks between members, so nearly every
/// offer has to wake a thread on the thread that is the wall.
///
/// Why THREE and not one, two or four. One cannot keep up (a member's
/// decode costs about 1.8 times its apply). With the queue sized for the
/// width (`Ahead::set_lanes`), two keep up with about 13 to 37 waits an
/// extraction, and three with about one, and three read the lowest wall on
/// `f/extract-solid290-m3` in all three runs that priced them against
/// two and four (an Apple M3 Mac twice, the 18 core laptop once); on the 20,000
/// member `rar5_small_solid_20k` chain two, three and four read level with
/// thirty two once the queue is deep. The stage still GROWS past this when
/// the apply keeps waiting, so a chain whose decode is dearer than these
/// gets the lanes it needs.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
pub(crate) const AHEAD_DEFAULT_LANES: usize = 3;

/// How many lanes a solid chain's decode-ahead opens.
///
/// `workers` is `ReadOptions::workers` as the caller gave it and `width`
/// is the read width it resolved to (API 8.4.2). A caller who STATED a
/// width gets that width here untouched: the dial is theirs. A caller who
/// stated nothing gets [`AHEAD_DEFAULT_LANES`], never above the resolved
/// width, which is the policy 8.4.2 allows ("a ceiling and never a
/// demand") and 8.2 puts in contract ("a stage that runs narrower ... is
/// in contract").
#[cfg(feature = "test-support")]
fn default_ahead_lanes() -> usize {
    crate::probe::ahead_grow_start().unwrap_or(AHEAD_DEFAULT_LANES)
}

#[cfg(not(feature = "test-support"))]
fn default_ahead_lanes() -> usize {
    AHEAD_DEFAULT_LANES
}

#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
pub(crate) fn ahead_lanes(workers: Option<usize>, width: usize) -> usize {
    match workers {
        Some(_) => width.max(1),
        None => width.clamp(1, default_ahead_lanes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stated_width_reaches_the_decode_ahead_untouched() {
        for width in [1usize, 2, 3, 4, 10, 20, 32, 64] {
            assert_eq!(ahead_lanes(Some(width), width), width);
        }
        // A stated width below two stays below two: the dial is the
        // caller's in both directions.
        assert_eq!(ahead_lanes(Some(1), 1), 1);
    }

    #[test]
    fn the_default_opens_the_chains_own_lanes_whatever_the_box() {
        for width in [3usize, 10, 18, 20, 32, 64] {
            assert_eq!(ahead_lanes(None, width), AHEAD_DEFAULT_LANES);
        }
    }

    #[test]
    fn the_default_never_opens_more_lanes_than_the_width_it_resolved_to() {
        assert_eq!(ahead_lanes(None, 1), 1);
        assert_eq!(ahead_lanes(None, 0), 1);
        assert_eq!(ahead_lanes(None, 2), 2);
    }

    /// The share over the breadth asked for: the ceiling divided by the
    /// members the pool will run, whoever has been admitted so far.
    #[test]
    fn the_share_of_the_breadth_does_not_wait_for_admissions() {
        assert_eq!(LaneBudget::with_spill(96, true).share_of_breadth(), 96);
        assert_eq!(
            LaneBudget::with_spill(96, true).asked(4).share_of_breadth(),
            24
        );
        assert_eq!(
            LaneBudget::with_spill(16, true).asked(8).share_of_breadth(),
            2
        );
        assert_eq!(
            LaneBudget::with_spill(8, true).asked(16).share_of_breadth(),
            1
        );
        assert_eq!(
            LaneBudget::with_spill(8, true).asked(0).share_of_breadth(),
            8
        );
        // Four members that each take that share fit at once, where the
        // first two taking the fair share of those admitted leave the
        // third no unit to be admitted on.
        let budget = LaneBudget::with_spill(16, true).asked(4);
        let slots: Vec<_> = (0..2).map(|_| budget.member_in()).collect();
        let grants: Vec<_> = (0..2)
            .map(|_| budget.take(budget.share_of_breadth()))
            .collect();
        assert_eq!(grants.iter().map(|g| g.lanes()).sum::<usize>(), 8);
        assert!(budget.admit());
        assert!(budget.admit());
        drop((slots, grants));
        let greedy = LaneBudget::with_spill(16, true);
        let slots: Vec<_> = (0..2).map(|_| greedy.member_in()).collect();
        let grants: Vec<_> = (0..2).map(|_| greedy.take(16)).collect();
        assert_eq!(grants.iter().map(|g| g.lanes()).sum::<usize>(), 16);
        assert!(!greedy.admit());
        drop((slots, grants));
    }

    #[test]
    fn one_member_alone_gets_the_whole_ceiling() {
        let budget = LaneBudget::new(8);
        let _slot = budget.member_in();
        assert_eq!(budget.take(8).lanes(), 8);
    }

    /// THE CEILING PLUS ONE, forced rather than waited for under load.
    ///
    /// Member A arrives alone and takes the whole ceiling for its chunk;
    /// member B arrives while that chunk runs. Admitting B at once put the
    /// units at three against a ceiling of two until A's chunk ended, which
    /// is what `tests/thread_width.rs` read as "a read width of 2 and the
    /// decode ran 3 blocks at once". B must wait for A's grant instead, and
    /// be admitted as soon as it comes back.
    #[test]
    fn a_member_arriving_mid_chunk_waits_for_the_grant_it_would_exceed() {
        use std::sync::mpsc;
        use std::time::Duration;
        let budget = LaneBudget::with_spill(2, true);
        let a = budget.member_in();
        let grant = budget.take(2);
        assert_eq!(grant.lanes(), 2, "a member alone takes the whole ceiling");
        std::thread::scope(|scope| {
            let (admitted, told) = mpsc::channel();
            let budget = &budget;
            scope.spawn(move || {
                let b = budget.member_in();
                admitted
                    .send(budget.in_flight())
                    .expect("the test is listening");
                drop(b);
            });
            assert!(
                told.recv_timeout(Duration::from_millis(200)).is_err(),
                "member B was admitted while A's chunk held the whole ceiling, \
                 which puts {} units in flight against a ceiling of 2",
                budget.in_flight() + 1
            );
            assert_eq!(budget.in_flight(), 2);
            drop(grant);
            let units = told
                .recv_timeout(Duration::from_secs(10))
                .expect("member B is admitted once A's grant comes back");
            assert_eq!(
                units, 2,
                "A's own unit and B's, and nothing past the ceiling"
            );
        });
        drop(a);
        assert_eq!(budget.in_flight(), 0);
    }

    /// A HOLDER PARKED OUTSIDE ITS DECODE GIVES WAY TO A MEMBER THAT WAITS.
    ///
    /// Member A holds the whole ceiling, its own unit and its chunk's lane,
    /// and parks for something that never comes (a look-ahead worker held
    /// at the gate with the walking thread not delivering). Member B then
    /// waits for a unit. A is let go for as long as B waits, ends its
    /// chunk, and B is admitted. Ordered, not timed: B asks only once A is
    /// parked. Two threads beside the test's own, no memory to speak of.
    #[test]
    fn a_holder_parked_outside_its_decode_gives_way_to_a_waiting_member() {
        use std::sync::mpsc;
        use std::time::Duration;
        let budget = LaneBudget::with_spill(2, true);
        let place = budget.place();
        std::thread::scope(|scope| {
            let (admitted, told) = mpsc::channel();
            let budget = &budget;
            let holder = Arc::clone(&place);
            scope.spawn(move || {
                let a = budget.member_in();
                let grant = budget.take(2);
                assert_eq!(grant.lanes(), 2, "a member alone takes the whole ceiling");
                // Held for ever by its own account: only a waiting member
                // lets it go.
                holder.park_while(|| true);
                drop(grant);
                drop(a);
            });
            while place.parked() == 0 {
                std::thread::yield_now();
            }
            assert_eq!(budget.in_flight(), 2, "the parked holder has the ceiling");
            scope.spawn(move || {
                let b = budget.member_in();
                admitted.send(()).expect("the test is listening");
                drop(b);
            });
            told.recv_timeout(Duration::from_secs(60)).expect(
                "member B was never admitted: the holder of every unit stayed \
                 parked while B waited for one",
            );
        });
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(place.parked(), 0);
    }

    /// A MEMBER WAITING FOR A LANE LETS GO ONLY A HOLDER OF LANES.
    ///
    /// A ceiling of three. Member A holds its own unit and nothing else and
    /// parks for something that never comes (a stored member at the gate).
    /// Member B, on the test's thread, holds its unit and the one lane the
    /// ceiling leaves. Member C then waits: the members out are two of
    /// three, so what it waits for is B's lane, and B is not parked. A is
    /// asked nothing: it is still parked when B's chunk ends and C is
    /// admitted. Before 10 Oct 2026 C's wait let A go, and a worker let go
    /// passes the gate for as long as the wait lasts. Ordered, not timed:
    /// each step waits for the one before. Two threads beside the test's
    /// own, no memory to speak of.
    #[test]
    fn a_member_waiting_for_a_lane_leaves_a_parked_member_parked() {
        use std::sync::atomic::AtomicBool;
        use std::sync::mpsc;
        use std::time::Duration;
        let budget = LaneBudget::with_spill(3, true);
        let place = budget.place();
        let release = AtomicBool::new(false);
        let left = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let (admitted, told) = mpsc::channel();
            let budget = &budget;
            let (release, left) = (&release, &left);
            let holder = Arc::clone(&place);
            scope.spawn(move || {
                let a = budget.member_in();
                holder.park_while(|| !release.load(Ordering::SeqCst));
                left.store(true, Ordering::SeqCst);
                drop(a);
            });
            while place.parked() == 0 {
                std::thread::yield_now();
            }
            let b = budget.member_in();
            let chunk = budget.take(3);
            assert_eq!(chunk.lanes(), 2, "the one lane two members leave of three");
            assert_eq!(budget.in_flight(), 3, "the ceiling is spent");
            scope.spawn(move || {
                let c = budget.member_in();
                admitted.send(()).expect("the test is listening");
                drop(c);
            });
            while !place.wanted() {
                std::thread::yield_now();
            }
            assert!(
                told.recv_timeout(Duration::from_millis(100)).is_err(),
                "member C was admitted past the ceiling"
            );
            assert!(
                !left.load(Ordering::SeqCst),
                "the parked member was let go by a member waiting for a lane it does not hold"
            );
            drop(chunk);
            told.recv_timeout(Duration::from_secs(60))
                .expect("member C is admitted once the lane comes back");
            assert!(
                !left.load(Ordering::SeqCst),
                "the parked member left with its own wait unmet"
            );
            release.store(true, Ordering::SeqCst);
            place.wake();
            drop(b);
        });
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(place.parked(), 0);
    }

    /// AND A MEMBER WAITING FOR A MEMBER'S OWN UNIT LETS EVERY HOLDER GO:
    /// the 8 Oct rule where it is still the only way on. A ceiling of one
    /// (the look-ahead at a width of one: its worker and the walk). Member
    /// A holds the one unit, no lane, and parks for something that never
    /// comes. Member B waits, and no chunk's end can admit it: A is let
    /// go, ends, and B is in. Ordered, not timed. Two threads beside the
    /// test's own.
    #[test]
    fn a_member_waiting_for_a_members_unit_lets_a_parked_member_go() {
        use std::sync::mpsc;
        use std::time::Duration;
        let budget = LaneBudget::with_spill(1, true);
        let place = budget.place();
        std::thread::scope(|scope| {
            let (admitted, told) = mpsc::channel();
            let budget = &budget;
            let holder = Arc::clone(&place);
            scope.spawn(move || {
                let a = budget.member_in();
                assert_eq!(budget.take(8).lanes(), 1, "a ceiling of one has no lane");
                holder.park_while(|| true);
                drop(a);
            });
            while place.parked() == 0 {
                std::thread::yield_now();
            }
            scope.spawn(move || {
                let b = budget.member_in();
                admitted.send(()).expect("the test is listening");
                drop(b);
            });
            told.recv_timeout(Duration::from_secs(60)).expect(
                "member B was never admitted: the holder of the only unit stayed \
                 parked while B waited for it",
            );
        });
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(place.parked(), 0);
    }

    /// A MEMBER WAITING IS LEFT ITS UNIT AT THE NEXT CHUNK, where holders
    /// wait at a gate, and nowhere else. A member alone
    /// takes the whole ceiling for a chunk; with a member counted as
    /// waiting, its next chunk takes the share of two members and leaves
    /// the waiting one's unit free, where before it took the whole ceiling
    /// again and the member waited on. The waiting member is counted by
    /// hand, so the take is read with it waiting and not yet admitted:
    /// with a thread for it the two would race. No thread beside the
    /// test's own.
    #[test]
    fn a_chunk_taken_beside_a_waiting_member_leaves_it_a_unit() {
        let budget = LaneBudget::with_spill(4, true).held_at(1 << 20);
        let a = budget.member_in();
        assert_eq!(
            budget.take(4).lanes(),
            4,
            "a member alone, the whole ceiling"
        );
        budget.place.wanting.fetch_add(1, Ordering::SeqCst);
        let chunk = budget.take(4);
        assert_eq!(
            chunk.lanes(),
            2,
            "the share of the member out and the one waiting"
        );
        assert!(budget.admit(), "the waiting member's unit was left free");
        budget.place.wanting.fetch_sub(1, Ordering::SeqCst);
        assert_eq!(budget.in_flight(), 3);
        drop(chunk);
        budget.give_back(MEMBER);
        // Five members' worth of want at a ceiling of three: one out and
        // two waiting leave the chunk its own unit and nothing more.
        let narrow = LaneBudget::with_spill(3, true).held_at(1 << 20);
        let b = narrow.member_in();
        narrow.place.wanting.fetch_add(2, Ordering::SeqCst);
        assert_eq!(narrow.take(3).lanes(), 1);
        narrow.place.wanting.fetch_sub(2, Ordering::SeqCst);
        assert_eq!(
            narrow.take(3).lanes(),
            3,
            "and the ceiling again with none waiting"
        );
        drop((a, b));
        assert_eq!(budget.in_flight(), 0);
        // A budget with NO gate, the pool's, shares exactly as it did: a
        // member alone takes the whole ceiling with a member waiting too.
        let pool = LaneBudget::with_spill(4, true);
        let c = pool.member_in();
        pool.place.wanting.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            pool.take(4).lanes(),
            4,
            "the pool's share is of the members admitted"
        );
        pool.place.wanting.fetch_sub(1, Ordering::SeqCst);
        drop(c);
    }

    /// A THREAD THE GATE HOLDS BACK TAKES NO LANE TO SIT ON, and takes its
    /// share again once it has passed unasked. The record is the thread's,
    /// so the budget's member runs on a thread of its own; a second thread
    /// wakes it each time it parks. Ordered, not timed. No memory to speak
    /// of.
    #[test]
    fn a_thread_held_back_takes_one_lane_until_it_passes_unasked() {
        use std::sync::atomic::AtomicBool;
        let budget = LaneBudget::with_spill(4, true);
        let place = budget.place();
        let done = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let (budget, place, done) = (&budget, &place, &done);
            // Whoever parks is woken to ask again.
            scope.spawn(move || {
                while !done.load(Ordering::SeqCst) {
                    place.wake();
                    std::thread::yield_now();
                }
            });
            scope
                .spawn(move || {
                    let _a = budget.member_in();
                    assert_eq!(budget.take(4).lanes(), 4);
                    // Asked to wait once, then let on by its own answer.
                    let mut asks = 0;
                    place.park_while(|| {
                        asks += 1;
                        asks == 1
                    });
                    assert_eq!(budget.take(4).lanes(), 1, "held back: its own unit alone");
                    // Not held this time: through unasked.
                    place.park_while(|| false);
                    assert_eq!(budget.take(4).lanes(), 4, "its share again");
                    asks = 0;
                    place.park_while(|| {
                        asks += 1;
                        asks == 1
                    });
                    assert_eq!(budget.take(4).lanes(), 1);
                    Yield::passed();
                    assert_eq!(
                        budget.take(4).lanes(),
                        4,
                        "the gate's own quick way through"
                    );
                })
                .join()
                .expect("the member's thread ran");
            done.store(true, Ordering::SeqCst);
        });
        assert_eq!(budget.in_flight(), 0);
    }

    /// With no member waiting, a parked holder stays parked until what it
    /// waits for says otherwise and it is woken: the waiting place adds a
    /// way out and takes none away.
    #[test]
    fn a_parked_holder_stays_until_its_own_wait_ends() {
        use std::sync::atomic::AtomicBool;
        use std::time::Duration;
        let place = Yield::default();
        let done = AtomicBool::new(false);
        let left = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                place.park_while(|| !done.load(Ordering::SeqCst));
                left.store(true, Ordering::SeqCst);
            });
            while place.parked() == 0 {
                std::thread::yield_now();
            }
            // A wake with nothing changed is not a release.
            place.wake();
            std::thread::sleep(Duration::from_millis(50));
            assert!(!left.load(Ordering::SeqCst), "let go with its wait unmet");
            done.store(true, Ordering::SeqCst);
            place.wake();
        });
        assert!(left.load(Ordering::SeqCst));
    }

    /// And the admission and the grant share one word, so a member being
    /// admitted and a member taking lanes AT THE SAME MOMENT cannot both
    /// pass on one reading. Many threads, one ceiling, every instant
    /// checked by the only party that can see it: the units themselves.
    #[test]
    fn members_and_lanes_racing_never_pass_the_ceiling() {
        let budget = LaneBudget::with_spill(3, true);
        let peak = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..500 {
                        let _slot = budget.member_in();
                        let _grant = budget.take(3);
                        peak.fetch_max(budget.in_flight(), Ordering::SeqCst);
                    }
                });
            }
        });
        assert!(
            peak.load(Ordering::SeqCst) <= 3,
            "{} units in flight against a ceiling of 3",
            peak.load(Ordering::SeqCst)
        );
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn two_members_split_it_evenly_rather_than_lopsidedly() {
        let budget = LaneBudget::new(8);
        let _a = budget.member_in();
        let _b = budget.member_in();
        let first = budget.take(8);
        let second = budget.take(8);
        assert_eq!((first.lanes(), second.lanes()), (4, 4));
    }

    /// THE ZERO-LANE FLOOR, pinned as the defect it is.
    ///
    /// A ceiling of six over four members: the floored share is one, no
    /// member reaches `MIN_USEFUL_LANES`, and two of the six units are
    /// spent by nobody. This is what was measured on four 20 MiB `-m1`
    /// members at a read width of six.
    #[test]
    fn the_floored_share_leaves_a_remainder_nobody_spends() {
        let budget = LaneBudget::new(6);
        let _slots: Vec<_> = (0..4).map(|_| budget.member_in()).collect();
        let grants: Vec<_> = (0..4).map(|_| budget.take(6)).collect();
        let widths: Vec<_> = grants.iter().map(|g| g.lanes()).collect();
        assert_eq!(widths, vec![1, 1, 1, 1]);
        let spent: usize = widths.iter().sum();
        assert_eq!(spent, 4, "two of the six units went to nobody");
        assert!(
            widths.iter().all(|&w| w < MIN_USEFUL_LANES),
            "and no member reached the tape path at all"
        );
    }

    /// The same cell with the remainder spendable: the ceiling is spent
    /// EXACTLY, the breadth is untouched, and the members that get the
    /// remainder reach the tape path.
    #[test]
    fn spilling_the_remainder_spends_the_ceiling_exactly() {
        let budget = LaneBudget::with_spill(6, true);
        let _slots: Vec<_> = (0..4).map(|_| budget.member_in()).collect();
        let grants: Vec<_> = (0..4).map(|_| budget.take(6)).collect();
        let mut widths: Vec<_> = grants.iter().map(|g| g.lanes()).collect();
        widths.sort_unstable();
        assert_eq!(widths, vec![1, 1, 2, 2]);
        assert_eq!(widths.iter().sum::<usize>(), 6, "the ceiling, exactly");
        assert_eq!(
            widths.iter().filter(|&&w| w >= MIN_USEFUL_LANES).count(),
            2,
            "the remainder bought two members a tape decode"
        );
    }

    /// The remainder is SPREAD, not piled on whoever asks first. Twelve
    /// over five is three, three, two, two, two: piling would read
    /// three, three, three, two, one and leave the last member under the
    /// floor this exists to lift it off.
    #[test]
    fn the_remainder_is_spread_rather_than_piled() {
        let budget = LaneBudget::with_spill(12, true);
        let _slots: Vec<_> = (0..5).map(|_| budget.member_in()).collect();
        let grants: Vec<_> = (0..5).map(|_| budget.take(12)).collect();
        let mut widths: Vec<_> = grants.iter().map(|g| g.lanes()).collect();
        widths.sort_unstable();
        assert_eq!(widths, vec![2, 2, 2, 3, 3]);
        assert_eq!(widths.iter().sum::<usize>(), 12);
    }

    /// Spilling changes nothing when the share divides exactly: there is
    /// no remainder to spend and the two arrangements are one.
    #[test]
    fn spilling_is_a_no_op_when_the_ceiling_divides() {
        for (ceiling, members) in [(8usize, 4usize), (4, 4), (12, 4), (8, 2)] {
            let floored = LaneBudget::new(ceiling);
            let spilt = LaneBudget::with_spill(ceiling, true);
            let mut got = Vec::new();
            for budget in [&floored, &spilt] {
                let _slots: Vec<_> = (0..members).map(|_| budget.member_in()).collect();
                let grants: Vec<_> = (0..members).map(|_| budget.take(ceiling)).collect();
                let mut widths: Vec<_> = grants.iter().map(|g| g.lanes()).collect();
                widths.sort_unstable();
                got.push(widths);
            }
            assert_eq!(got[0], got[1], "ceiling {ceiling} over {members} members");
        }
    }

    /// Narrowing the breadth is the other arrangement: fewer members in
    /// flight, each with a width worth having, and never wider than the
    /// caller asked for.
    #[test]
    fn narrowing_the_breadth_buys_every_member_a_useful_width() {
        assert_eq!(useful_breadth(6, 4), 3, "three members at two lanes each");
        assert_eq!(useful_breadth(4, 4), 2);
        assert_eq!(useful_breadth(12, 4), 4, "three lanes each already");
        assert_eq!(useful_breadth(8, 4), 4, "two lanes each already");
        assert_eq!(useful_breadth(1, 4), 1, "a ceiling of one buys nothing");
        assert_eq!(useful_breadth(2, 1), 1, "never widened past the request");
        assert_eq!(useful_breadth(32, 2), 2);
        for ceiling in 1usize..=32 {
            for asked in 1usize..=32 {
                let got = useful_breadth(ceiling, asked);
                assert!((1..=asked).contains(&got), "{ceiling}/{asked} gave {got}");
                // Either it was not narrowed, or it was narrowed to a
                // width worth having, or the ceiling is too small to buy
                // one at any breadth, which a breadth of one says
                // honestly rather than pretending otherwise.
                assert!(
                    got == asked || got == 1 || ceiling / got >= MIN_USEFUL_LANES,
                    "{ceiling}/{asked} narrowed to {got} and still starves"
                );
            }
        }
    }

    #[test]
    fn the_units_never_pass_the_ceiling_however_many_members_ask() {
        for spill in [false, true] {
            for ceiling in [1usize, 2, 4, 8, 16] {
                for members in 1..=ceiling {
                    let budget = LaneBudget::with_spill(ceiling, spill);
                    let slots: Vec<_> = (0..members).map(|_| budget.member_in()).collect();
                    let grants: Vec<_> = (0..members).map(|_| budget.take(ceiling)).collect();
                    let units: usize = grants.iter().map(|g| g.lanes()).sum();
                    assert!(
                        units <= ceiling,
                        "spill {spill}, ceiling {ceiling}, {members} members: {units} units"
                    );
                    assert!(grants.iter().all(|g| g.lanes() >= 1));
                    drop(grants);
                    drop(slots);
                    assert_eq!(budget.in_flight(), 0);
                    assert_eq!(budget.spilled.load(Ordering::Acquire), 0);
                }
            }
        }
    }

    #[test]
    fn the_units_never_pass_the_ceiling_under_the_floored_share() {
        for ceiling in [1usize, 2, 4, 8, 16] {
            for members in 1..=ceiling {
                let budget = LaneBudget::new(ceiling);
                let slots: Vec<_> = (0..members).map(|_| budget.member_in()).collect();
                let grants: Vec<_> = (0..members).map(|_| budget.take(ceiling)).collect();
                let units: usize = grants.iter().map(|g| g.lanes()).sum();
                assert!(
                    units <= ceiling,
                    "ceiling {ceiling}, {members} members: {units} units"
                );
                // And every member decodes: a grant of zero is a member
                // that never runs.
                assert!(grants.iter().all(|g| g.lanes() >= 1));
                drop(grants);
                drop(slots);
                assert_eq!(budget.in_flight(), 0);
            }
        }
    }

    /// A member arriving while a wide grant is outstanding WAITS for it,
    /// and the wide member narrows at its next chunk.
    ///
    /// SPEC-API 8.3: "the product of the members decoded at once and the
    /// width inside each of them stays at or below `max_workers`", each
    /// member's floor of one INSIDE that bound (8.2's row: "at most
    /// `max_workers` decode units over all members together"). This test
    /// used to let the late member in at once at a width of one and
    /// assert `wide + late <= 8 + 1`, the one line that recorded the
    /// ceiling plus one; its own comment said the width of one was chosen
    /// so as not to breach the ceiling, and nothing in SPEC-API grants a
    /// floor above it. Decided 29 Sep 2026 that the ceiling is hard, so the
    /// late member is admitted only once the wide chunk gives its lanes
    /// back, and then the two split the ceiling as two members always
    /// have.
    #[test]
    fn a_late_member_never_pushes_the_units_over() {
        use std::sync::mpsc;
        use std::time::Duration;
        let budget = LaneBudget::new(8);
        let _a = budget.member_in();
        let wide = budget.take(8);
        assert_eq!(wide.lanes(), 8);
        std::thread::scope(|scope| {
            let (admitted, told) = mpsc::channel();
            let (go, hold) = mpsc::channel::<()>();
            let budget = &budget;
            scope.spawn(move || {
                let _b = budget.member_in();
                let late = budget.take(8);
                admitted.send(late.lanes()).expect("the test is listening");
                hold.recv().expect("the test says when");
            });
            assert!(
                told.recv_timeout(Duration::from_millis(200)).is_err(),
                "the late member was admitted beside a grant of the whole ceiling"
            );
            // The wide member's chunk ends, and the late member is in.
            drop(wide);
            let late = told
                .recv_timeout(Duration::from_secs(10))
                .expect("the late member is admitted once the wide grant is back");
            assert_eq!(late, 4, "two members in flight, so the fair share");
            let narrowed = budget.take(8);
            assert_eq!(narrowed.lanes(), 4);
            assert!(narrowed.lanes() + late <= 8, "SPEC-API 8.3's product");
            assert_eq!(
                budget.in_flight(),
                8,
                "the ceiling, exactly, and never past it"
            );
            drop(narrowed);
            go.send(()).expect("the late member is waiting");
        });
    }

    /// A budget whose holders wait at a gate grants a stored member's
    /// lanes a quarter of the window at a time; any other budget, and a
    /// gate of no window, bounds nothing.
    #[test]
    fn a_held_budget_grants_a_stored_members_lanes_a_quarter_window_at_a_time() {
        assert_eq!(LaneBudget::with_spill(8, true).grant_bytes(), u64::MAX);
        assert_eq!(
            LaneBudget::with_spill(8, true).held_at(0).grant_bytes(),
            u64::MAX
        );
        assert_eq!(
            LaneBudget::with_spill(8, true)
                .held_at(128 << 20)
                .grant_bytes(),
            32 << 20
        );
        assert_eq!(
            LaneBudget::with_spill(8, true)
                .held_at(1 << 20)
                .grant_bytes(),
            1 << 20,
            "a mebibyte at least"
        );
    }

    /// The share of the cores for members abreast: each member's lanes and
    /// its apply thread fit, never under the fewest lanes worth granting.
    #[test]
    fn members_abreast_share_the_cores_with_their_applies() {
        assert_eq!(abreast_lanes(48, 8), 5);
        assert_eq!(abreast_lanes(48, 12), 3);
        assert_eq!(abreast_lanes(48, 16), 2);
        assert_eq!(abreast_lanes(48, 24), MIN_USEFUL_LANES);
        assert_eq!(abreast_lanes(48, 96), MIN_USEFUL_LANES);
        // Two and four members keep more than a member may open anyway.
        assert_eq!(abreast_lanes(48, 4), 11);
        assert_eq!(abreast_lanes(48, 2), 23);
        assert_eq!(abreast_lanes(96, 8), 11);
        assert_eq!(abreast_lanes(0, 0), MIN_USEFUL_LANES);
    }

    /// Only wide x86-64 Linux has rows behind the share.
    #[test]
    fn the_share_of_the_cores_is_for_wide_x86_linux_alone() {
        assert_eq!(abreast_cores_on(48, true), Some(48));
        assert_eq!(abreast_cores_on(96, true), Some(96));
        assert_eq!(abreast_cores_on(47, true), None);
        assert_eq!(abreast_cores_on(8, true), None);
        assert_eq!(abreast_cores_on(48, false), None);
        assert_eq!(abreast_cores_on(20, false), None);
        // A stated width never takes it, whatever the machine.
        assert_eq!(abreast_cores(true), None);
    }

    /// Eight members abreast at a ceiling of 96 threads on 48 cores take
    /// five lanes each and not the twelve the ceiling alone offers; a
    /// member alone, and a budget told no core count, take what they did.
    #[test]
    fn a_budget_told_its_cores_caps_members_abreast_and_no_one_else() {
        let budget = LaneBudget::with_spill(96, true)
            .asked(8)
            .abreast_on(Some(48));
        assert_eq!(budget.share_of_breadth(), 5);
        {
            let _alone = budget.member_in();
            assert_eq!(budget.take(8).lanes(), 8, "a member alone");
        }
        let slots: Vec<_> = (0..8).map(|_| budget.member_in()).collect();
        let grants: Vec<_> = (0..8).map(|_| budget.take(8)).collect();
        assert!(grants.iter().all(|g| g.lanes() == 5));
        assert_eq!(budget.in_flight(), 40);
        drop(grants);
        drop(slots);
        // Four abreast: the eight a member asks for, as before.
        let slots: Vec<_> = (0..4).map(|_| budget.member_in()).collect();
        let grants: Vec<_> = (0..4).map(|_| budget.take(8)).collect();
        assert!(grants.iter().all(|g| g.lanes() == 8));
        drop(grants);
        drop(slots);
        // No core count: the ceiling's share alone.
        let plain = LaneBudget::with_spill(96, true).asked(8);
        assert_eq!(plain.share_of_breadth(), 12);
        let slots: Vec<_> = (0..8).map(|_| plain.member_in()).collect();
        let grants: Vec<_> = (0..8).map(|_| plain.take(8)).collect();
        assert!(grants.iter().all(|g| g.lanes() == 8));
        drop(grants);
        drop(slots);
        // The share never raises what the ceiling allows: 16 threads over
        // eight members is two lanes each with or without it.
        let narrow = LaneBudget::with_spill(16, true)
            .asked(8)
            .abreast_on(Some(48));
        assert_eq!(narrow.share_of_breadth(), 2);
    }
}
